//! Ownership is verifier-produced state, never a client session/header selector.
use std::sync::Arc;

use http_body_util::{BodyExt, StreamBody};
use serde::{Deserialize, Serialize};

use crate::http::jwt::VerifiedMcpIdentity;
use crate::http::sessionpersistence::{Encoder, MCPSessionState};
use crate::mcp::upstream::{IncomingRequestContext, UpstreamError};
use crate::store::{ConfigurationGeneration, Stores};
use crate::types::agent::ResourceName;
use crate::{http, mcp};

const PREFIX: &str = "agw-mcp-owned-v1.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
	owner: [u8; 32],
	backend: ResourceName,
	generation: ConfigurationGeneration,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeState {
	binding: Binding,
	state: MCPSessionState,
}

#[derive(Clone, Debug)]
pub(super) struct Guard {
	binding: Arc<Binding>,
	expires_at: u64,
	stores: Stores,
}

impl Binding {
	pub(super) fn current(
		ctx: &IncomingRequestContext,
		backend: &ResourceName,
		stores: &Stores,
	) -> Result<Option<Arc<Self>>, mcp::Error> {
		let Some(identity) = ctx.extensions().get::<VerifiedMcpIdentity>() else {
			return Ok(None);
		};
		let owner = identity.owner().ok_or(mcp::Error::UnknownSession)?;
		let generation = *ctx
			.extensions()
			.get::<ConfigurationGeneration>()
			.ok_or(mcp::Error::UnknownSession)?;
		if identity.expires_at() <= jsonwebtoken::get_current_timestamp()
			|| generation != stores.configuration_generation()
		{
			return Err(mcp::Error::UnknownSession);
		}
		Ok(Some(Arc::new(Self {
			owner,
			backend: backend.clone(),
			generation,
		})))
	}

	pub(super) fn guard(
		binding: &Option<Arc<Self>>,
		ctx: &IncomingRequestContext,
		backend: &ResourceName,
		stores: &Stores,
	) -> Result<Option<Guard>, mcp::Error> {
		let current = Self::current(ctx, backend, stores)?;
		if &current != binding {
			return Err(mcp::Error::UnknownSession);
		}
		Ok(current.map(|binding| {
			Guard {
				binding,
				expires_at: ctx
					.extensions()
					.get::<VerifiedMcpIdentity>()
					.expect("current verified identity")
					.expires_at(),
				stores: stores.clone(),
			}
		}))
	}
}

impl Guard {
	pub(super) fn validate(&self) -> Result<(), UpstreamError> {
		if self.expires_at <= jsonwebtoken::get_current_timestamp()
			|| self.binding.generation != self.stores.configuration_generation()
		{
			return Err(UpstreamError::Unavailable(
				"MCP session authorization expired or changed".into(),
			));
		}
		Ok(())
	}

	pub(super) fn response(&self, response: http::Response) -> Result<http::Response, UpstreamError> {
		self.validate()?;
		let guard = self.clone();
		Ok(response.map(|body| {
			let stream =
				futures_util::stream::try_unfold((body, guard), |(mut body, guard)| async move {
					loop {
						guard.validate().map_err(|_| std::io::Error::other("MCP session authorization expired or changed"))?;
						tokio::select! {
							frame = body.frame() => {
								// Recheck after asynchronous body production and before delivery.
								guard.validate().map_err(|_| std::io::Error::other("MCP session authorization expired or changed"))?;
								return match frame {
									Some(Ok(frame)) => Ok(Some((frame, (body, guard)))),
									Some(Err(_)) => Err(std::io::Error::other("MCP response stream failed")),
									None => Ok(None),
								};
							},
							// An idle stream must also release its upstream at expiry/update.
							_ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
						}
					}
				});
			http::Body::new(StreamBody::new(stream))
		}))
	}
}

pub(super) fn validate_context(ctx: &IncomingRequestContext) -> Result<(), UpstreamError> {
	if let Some(guard) = ctx.extensions().get::<Guard>() {
		guard.validate()?;
	}
	Ok(())
}

pub(super) fn encode(
	state: MCPSessionState,
	binding: &Binding,
	encoder: &Encoder,
) -> Result<String, http::sessionpersistence::Error> {
	let bytes = serde_json::to_vec(&ResumeState {
		binding: binding.clone(),
		state,
	})?;
	let id = format!("{PREFIX}{}", encoder.encrypt_bytes(&bytes)?);
	if id.len() > 16 * 1024 {
		return Err(http::sessionpersistence::Error::InvalidSessionEncoding);
	}
	Ok(id)
}

pub(super) fn is_owned(id: &str) -> bool {
	id.starts_with(PREFIX)
}

pub(super) fn decode(
	id: &str,
	expected: &Binding,
	encoder: &Encoder,
) -> Result<MCPSessionState, mcp::Error> {
	// Bound work before decryption/allocation. Ordinary HTTP header limits also apply.
	if id.len() > 16 * 1024 {
		return Err(mcp::Error::InvalidSessionIdHeader);
	}
	let encrypted = id
		.strip_prefix(PREFIX)
		.ok_or(mcp::Error::InvalidSessionIdHeader)?;
	let bytes = encoder
		.decrypt(encrypted)
		.map_err(|_| mcp::Error::InvalidSessionIdHeader)?;
	let state: ResumeState =
		serde_json::from_slice(&bytes).map_err(|_| mcp::Error::InvalidSessionIdHeader)?;
	if &state.binding != expected {
		return Err(mcp::Error::UnknownSession);
	}
	Ok(state.state)
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use bytes::Bytes;
	use http_body::Frame;

	use super::*;

	fn guard(stores: &Stores, expires_at: u64) -> Guard {
		Guard {
			binding: Arc::new(Binding {
				owner: [7; 32],
				backend: ResourceName::new("test".into(), "ns".into()),
				generation: stores.configuration_generation(),
			}),
			expires_at,
			stores: stores.clone(),
		}
	}

	#[tokio::test]
	async fn mcp_owned_response_withholds_frames_after_configuration_change() {
		let stores = Stores::default();
		let guard = guard(&stores, jsonwebtoken::get_current_timestamp() + 60);
		let response = http::Response::new(http::Body::from("synthetic-private-result"));
		let mut body = guard.response(response).unwrap().into_body();
		drop(stores.binds.write());
		assert!(body.frame().await.unwrap().is_err());
		assert!(body.frame().await.is_none());
		let ctx = IncomingRequestContext::empty();
		let mut ctx = ctx;
		ctx.extensions_mut().insert(guard);
		assert!(validate_context(&ctx).is_err());
	}

	#[tokio::test]
	async fn mcp_owned_idle_response_terminates_at_credential_expiry() {
		let stores = Stores::default();
		let guard = guard(&stores, jsonwebtoken::get_current_timestamp() + 1);
		let pending = futures_util::stream::pending::<Result<Frame<Bytes>, std::io::Error>>();
		let response = http::Response::new(http::Body::new(StreamBody::new(pending)));
		let mut body = guard.response(response).unwrap().into_body();
		let frame = tokio::time::timeout(Duration::from_secs(3), body.frame())
			.await
			.unwrap();
		assert!(frame.unwrap().is_err());
	}

	#[tokio::test]
	async fn mcp_owned_async_response_rechecks_before_delivery() {
		let stores = Stores::default();
		let guard = guard(&stores, jsonwebtoken::get_current_timestamp() + 60);
		let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(1);
		let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
		let response = http::Response::new(http::Body::new(StreamBody::new(stream)));
		let mut body = guard.response(response).unwrap().into_body();
		let task = tokio::spawn(async move { body.frame().await.unwrap() });
		tokio::task::yield_now().await;
		drop(stores.discovery.write());
		tx.send(Ok(Frame::data(Bytes::from_static(
			b"synthetic-private-result",
		))))
		.await
		.unwrap();
		assert!(task.await.unwrap().is_err());
	}
}
