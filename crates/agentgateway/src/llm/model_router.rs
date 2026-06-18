use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use agent_core::prelude::Strng;
use agent_core::strng;
use bytes::Bytes;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use rand::seq::IndexedRandom;
use serde_json::Value;

use crate::http::transformation_cel::TransformationMetadata;
use crate::http::{self, Request, Response};
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{
	BackendReference, BackendTrafficPolicy, HeaderMatch, HeaderValueMatch, RouteBackendReference,
	TrafficPolicy,
};
use crate::{apply, cel, schema_enum};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRoute {
	pub name: String,
	pub visibility: ModelVisibility,
	pub header_matches: Vec<Vec<HeaderMatch>>,
	pub backend_key: Strng,
	pub route_policies: Vec<TrafficPolicy>,
	pub backend_policies: Vec<BackendTrafficPolicy>,
}

#[apply(schema_enum!)]
#[derive(Default)]
pub enum ModelVisibility {
	/// Public models can be requested directly by clients and are included in the model list.
	#[default]
	Public,
	/// Internal models can be targeted by virtual models but cannot be requested directly.
	Internal,
}

impl ModelVisibility {
	pub fn is_public(&self) -> bool {
		matches!(self, Self::Public)
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualModelRoute {
	pub name: String,
	pub route_policies: Vec<TrafficPolicy>,
	pub routing: VirtualModelRouting,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VirtualModelRouting {
	Weighted(Vec<WeightedTarget>),
	Failover { backend_key: Strng },
	Conditional(Vec<ConditionalTarget>),
	Semantic(SemanticRouting),
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WeightedTarget {
	pub model: String,
	pub weight: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalTarget {
	pub model: String,
	pub when: Option<Arc<cel::Expression>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticRouting {
	pub embedding_model: String,
	pub default_model: String,
	pub targets: Vec<SemanticTarget>,
	#[serde(skip_serializing)]
	state: Arc<SemanticIndexState>,
}

impl SemanticRouting {
	pub fn new(embedding_model: String, default_model: String, targets: Vec<SemanticTarget>) -> Self {
		Self {
			embedding_model,
			default_model,
			targets,
			state: Arc::new(SemanticIndexState::default()),
		}
	}
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticTarget {
	pub model: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub description: Option<String>,
	pub phrases: Vec<String>,
	pub score_threshold: f32,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub min_input_tokens: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_input_tokens: Option<u64>,
}

#[derive(Default)]
struct SemanticIndexState {
	index: tokio::sync::RwLock<Option<Arc<SemanticIndex>>>,
	warmup_started: AtomicBool,
}

impl std::fmt::Debug for SemanticIndexState {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SemanticIndexState")
			.field(
				"warmup_started",
				&self.warmup_started.load(Ordering::Relaxed),
			)
			.finish_non_exhaustive()
	}
}

#[derive(Debug)]
struct SemanticIndex {
	entries: Vec<SemanticIndexEntry>,
}

#[derive(Debug)]
struct SemanticIndexEntry {
	model: String,
	phrase: String,
	score_threshold: f32,
	min_input_tokens: Option<u64>,
	max_input_tokens: Option<u64>,
	embedding: Vec<f32>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelRouter {
	models: Vec<ModelRoute>,
	virtual_models: Vec<VirtualModelRoute>,
	created: u64,
}

#[derive(Debug, Clone)]
pub struct ResolvedBackend {
	pub backend: RouteBackendReference,
	pub route_policies: Vec<TrafficPolicy>,
}

pub enum ResolveResult {
	DirectResponse(Response),
	Backend(ResolvedBackend),
}

type RouterResult<T> = Result<T, Box<Response>>;

struct RequestedModel {
	model: String,
	location: RequestedModelLocation,
}

enum RequestedModelLocation {
	Body(Value),
	Path,
}

struct SemanticRequest {
	query_text: String,
	messages: Vec<super::SimpleChatCompletionMessage>,
}

impl ModelRouter {
	pub fn new(
		models: Vec<ModelRoute>,
		virtual_models: Vec<VirtualModelRoute>,
		created: u64,
	) -> Self {
		Self {
			models,
			virtual_models,
			created,
		}
	}

	pub fn warm_semantic_routes(&self, client: PolicyClient) {
		let req = ::http::Request::builder()
			.uri("http://agentgateway.internal/v1/chat/completions")
			.body(http::Body::empty())
			.expect("synthetic warmup request is valid");
		for virtual_model in &self.virtual_models {
			let VirtualModelRouting::Semantic(semantic) = &virtual_model.routing else {
				continue;
			};
			let Some(embedding_backend) =
				self.resolve_concrete_model(&semantic.embedding_model, true, &req)
			else {
				tracing::warn!(
					virtual_model = %virtual_model.name,
					embedding_model = %semantic.embedding_model,
					default_model = %semantic.default_model,
					"semantic virtual model embedding model could not be resolved; skipping eager warmup",
				);
				continue;
			};
			semantic.maybe_start_warmup(
				virtual_model.name.clone(),
				client.clone(),
				embedding_backend,
			);
		}
	}

	pub async fn resolve(&self, req: &mut Request, client: &PolicyClient) -> ResolveResult {
		if is_model_list_request(req) {
			return ResolveResult::DirectResponse(self.model_list_response(req));
		}
		let requested_model = match requested_model(req).await {
			Ok(requested_model) => requested_model,
			Err(resp) => return ResolveResult::DirectResponse(*resp),
		};
		req
			.extensions_mut()
			.get_or_insert_with(TransformationMetadata::default)
			.0
			.insert(
				"agentgateway_user_model".to_string(),
				Value::String(requested_model.model.clone()),
			);
		if let Some(virtual_model) = self
			.virtual_models
			.iter()
			.find(|model| model.name == requested_model.model)
		{
			return self
				.resolve_virtual_model(virtual_model, req, requested_model.location, client)
				.await;
		}
		tracing::trace!(
			requested_model = %requested_model.model,
			virtual_model_count = self.virtual_models.len(),
			"unable to find declared virtual model; trying concrete model routes",
		);

		match self.resolve_concrete_model(&requested_model.model, false, req) {
			Some(route) => ResolveResult::Backend(route),
			None => ResolveResult::DirectResponse(model_not_found_response()),
		}
	}

	fn model_list_response(&self, req: &Request) -> Response {
		let data = self
			.models
			.iter()
			.filter(|model| model.visibility == ModelVisibility::Public)
			.filter(|model| model_authorized(model, req))
			.map(|model| model_list_entry(&model.name, self.created))
			.chain(
				self
					.virtual_models
					.iter()
					.map(|model| model_list_entry(&model.name, self.created)),
			)
			.collect::<Vec<_>>();
		let body = serde_json::json!({
			"data": data,
			"object": "list",
		})
		.to_string();
		::http::Response::builder()
			.status(::http::StatusCode::OK)
			.header(::http::header::CONTENT_TYPE, "application/json")
			.body(http::Body::from(body))
			.expect("LLM model list response is valid")
	}

	async fn resolve_virtual_model(
		&self,
		virtual_model: &VirtualModelRoute,
		req: &mut Request,
		location: RequestedModelLocation,
		client: &PolicyClient,
	) -> ResolveResult {
		let target = match &virtual_model.routing {
			VirtualModelRouting::Weighted(targets) => {
				match targets.choose_weighted(&mut rand::rng(), |target| target.weight) {
					Ok(target) => target.model.clone(),
					Err(err) => {
						tracing::debug!(%err, "failed to select weighted virtual model target");
						return ResolveResult::DirectResponse(llm_error_response(
							::http::StatusCode::NOT_FOUND,
							&format!("Virtual model {} could not be resolved", virtual_model.name),
							"virtual_model_not_resolved",
						));
					},
				}
			},
			VirtualModelRouting::Failover { backend_key } => {
				return ResolveResult::Backend(ResolvedBackend {
					backend: RouteBackendReference {
						weight: 1,
						target: BackendReference::Backend(strng::format!("/{}", backend_key)).into(),
						inline_policies: vec![],
					},
					route_policies: virtual_model.route_policies.clone(),
				});
			},
			VirtualModelRouting::Conditional(targets) => {
				let exec = cel::Executor::new_request(req);
				match targets.iter().find(|target| {
					target
						.when
						.as_ref()
						.map(|expr| exec.eval_bool(expr))
						.unwrap_or(true)
				}) {
					Some(target) => target.model.clone(),
					None => {
						return ResolveResult::DirectResponse(llm_error_response(
							::http::StatusCode::BAD_REQUEST,
							&format!(
								"Virtual model {} did not match any conditional target",
								virtual_model.name
							),
							"virtual_model_no_matching_target",
						));
					},
				}
			},
			VirtualModelRouting::Semantic(semantic) => {
				let embedding_backend = self.resolve_concrete_model(&semantic.embedding_model, true, req);
				let semantic_request = semantic_request(req, &location);
				self
					.resolve_semantic_model(
						virtual_model,
						semantic,
						embedding_backend,
						semantic_request,
						client,
					)
					.await
			},
		};
		if let Err(resp) = rewrite_request_model(req, location, &target) {
			return ResolveResult::DirectResponse(*resp);
		}
		match self.resolve_concrete_model(&target, true, req) {
			Some(route) => ResolveResult::Backend(route),
			None => {
				tracing::debug!(
					virtual_model = %virtual_model.name,
					target_model = %target,
					"virtual model selected target with no declared concrete model",
				);
				ResolveResult::DirectResponse(llm_error_response(
					::http::StatusCode::NOT_FOUND,
					&format!(
						"Virtual model {} selected target {target}, but no matching model was found",
						virtual_model.name
					),
					"virtual_model_target_not_found",
				))
			},
		}
	}

	fn resolve_concrete_model(
		&self,
		requested_model: &str,
		allow_internal: bool,
		req: &Request,
	) -> Option<ResolvedBackend> {
		// `models` can store things like `provider/*`. The concrete `requested_model` will be like `provider/real-model`.
		let model = self.models.iter().find(|model| {
			(allow_internal || model.visibility == ModelVisibility::Public)
				&& model_name_matches(&model.name, requested_model)
				&& header_matches(&model.header_matches, req)
		})?;
		Some(ResolvedBackend {
			backend: RouteBackendReference {
				weight: 1,
				target: BackendReference::Backend(strng::format!("/{}", model.backend_key)).into(),
				inline_policies: model.backend_policies.clone(),
			},
			route_policies: model.route_policies.clone(),
		})
	}

	async fn resolve_semantic_model(
		&self,
		virtual_model: &VirtualModelRoute,
		semantic: &SemanticRouting,
		embedding_backend: Option<ResolvedBackend>,
		semantic_request: Option<SemanticRequest>,
		client: &PolicyClient,
	) -> String {
		let Some(embedding_backend) = embedding_backend else {
			tracing::warn!(
				virtual_model = %virtual_model.name,
				embedding_model = %semantic.embedding_model,
				default_model = %semantic.default_model,
				"semantic virtual model embedding model could not be resolved; using default model",
			);
			return semantic.default_model.clone();
		};
		semantic.maybe_start_warmup(
			virtual_model.name.clone(),
			client.clone(),
			embedding_backend.clone(),
		);

		let Some(semantic_request) = semantic_request else {
			tracing::debug!(
				virtual_model = %virtual_model.name,
				default_model = %semantic.default_model,
				"semantic routing supports only chat completions requests with user text; using default model",
			);
			return semantic.default_model.clone();
		};
		let Some(index) = semantic.ready_index().await else {
			tracing::debug!(
				virtual_model = %virtual_model.name,
				default_model = %semantic.default_model,
				"semantic route index not ready; using default model",
			);
			return semantic.default_model.clone();
		};
		let query_embedding = match client
			.call_llm_embeddings(
				embedding_backend.backend.clone(),
				embedding_backend.route_policies.clone(),
				&semantic.embedding_model,
				vec![semantic_request.query_text],
			)
			.await
		{
			Ok(mut embeddings) if !embeddings.is_empty() => embeddings.remove(0),
			Ok(_) => {
				tracing::warn!(
					virtual_model = %virtual_model.name,
					embedding_model = %semantic.embedding_model,
					default_model = %semantic.default_model,
					"semantic routing query embedding response was empty; using default model",
				);
				return semantic.default_model.clone();
			},
			Err(err) => {
				tracing::warn!(
					virtual_model = %virtual_model.name,
					embedding_model = %semantic.embedding_model,
					default_model = %semantic.default_model,
					%err,
					"semantic routing query embedding failed; using default model",
				);
				return semantic.default_model.clone();
			},
		};
		match semantic_decision(&index, &query_embedding, Some(&semantic_request.messages)) {
			SemanticDecision::Selected(selection) => {
				tracing::debug!(
					virtual_model = %virtual_model.name,
					target_model = %selection.model,
					score = selection.score,
					score_threshold = selection.score_threshold,
					input_tokens = selection.input_tokens,
					min_input_tokens = selection.min_input_tokens,
					max_input_tokens = selection.max_input_tokens,
					phrase = %selection.phrase,
					"semantic virtual model selected target",
				);
				selection.model
			},
			SemanticDecision::TokenLimitExceeded(selection) => {
				tracing::debug!(
					virtual_model = %virtual_model.name,
					default_model = %semantic.default_model,
					best_target_model = %selection.model,
					best_score = selection.score,
					score_threshold = selection.score_threshold,
					input_tokens = selection.input_tokens,
					min_input_tokens = selection.min_input_tokens,
					max_input_tokens = selection.max_input_tokens,
					best_phrase = %selection.phrase,
					"semantic virtual model target exceeded max input tokens; using default model",
				);
				semantic.default_model.clone()
			},
			SemanticDecision::TokenMinimumNotMet(selection) => {
				tracing::debug!(
					virtual_model = %virtual_model.name,
					default_model = %semantic.default_model,
					best_target_model = %selection.model,
					best_score = selection.score,
					score_threshold = selection.score_threshold,
					input_tokens = selection.input_tokens,
					min_input_tokens = selection.min_input_tokens,
					max_input_tokens = selection.max_input_tokens,
					best_phrase = %selection.phrase,
					"semantic virtual model target below min input tokens; using default model",
				);
				semantic.default_model.clone()
			},
			SemanticDecision::TokenEstimateFailed(selection) => {
				tracing::debug!(
					virtual_model = %virtual_model.name,
					default_model = %semantic.default_model,
					best_target_model = %selection.model,
					best_score = selection.score,
					score_threshold = selection.score_threshold,
					min_input_tokens = selection.min_input_tokens,
					max_input_tokens = selection.max_input_tokens,
					token_error = ?selection.token_error,
					best_phrase = %selection.phrase,
					"semantic virtual model could not estimate input tokens for token-bounded target; using default model",
				);
				semantic.default_model.clone()
			},
			SemanticDecision::BelowThreshold(selection) => {
				tracing::debug!(
					virtual_model = %virtual_model.name,
					default_model = %semantic.default_model,
					best_target_model = %selection.model,
					best_score = selection.score,
					score_threshold = selection.score_threshold,
					best_phrase = %selection.phrase,
					"semantic virtual model found no target above threshold; using default model",
				);
				semantic.default_model.clone()
			},
			SemanticDecision::NoCandidates => {
				tracing::debug!(
					virtual_model = %virtual_model.name,
					default_model = %semantic.default_model,
					"semantic virtual model found no target above threshold; using default model",
				);
				semantic.default_model.clone()
			},
		}
	}
}

impl SemanticRouting {
	async fn ready_index(&self) -> Option<Arc<SemanticIndex>> {
		self.state.index.read().await.clone()
	}

	fn maybe_start_warmup(
		&self,
		virtual_model: String,
		client: PolicyClient,
		embedding_backend: ResolvedBackend,
	) {
		if self.state.warmup_started.swap(true, Ordering::AcqRel) {
			return;
		}

		let phrase_count = self.phrase_count();
		tracing::info!(
			virtual_model = %virtual_model,
			embedding_model = %self.embedding_model,
			default_model = %self.default_model,
			phrase_count,
			"semantic route index warmup started",
		);

		let semantic = self.clone();
		tokio::spawn(async move {
			let mut backoff = Duration::from_secs(1);
			loop {
				match build_semantic_index(&semantic, &client, &embedding_backend).await {
					Ok(index) => {
						let entry_count = index.entries.len();
						*semantic.state.index.write().await = Some(Arc::new(index));
						tracing::info!(
							virtual_model = %virtual_model,
							embedding_model = %semantic.embedding_model,
							entry_count,
							"semantic route index warmup complete",
						);
						return;
					},
					Err(err) => {
						tracing::warn!(
							virtual_model = %virtual_model,
							embedding_model = %semantic.embedding_model,
							default_model = %semantic.default_model,
							%err,
							retry_after = ?backoff,
							"semantic route index warmup failed; retrying",
						);
						tokio::time::sleep(backoff).await;
						backoff = std::cmp::min(backoff * 2, Duration::from_secs(30));
					},
				}
			}
		});
	}

	fn phrase_count(&self) -> usize {
		self.targets.iter().map(|target| target.phrases.len()).sum()
	}
}

async fn build_semantic_index(
	semantic: &SemanticRouting,
	client: &PolicyClient,
	embedding_backend: &ResolvedBackend,
) -> anyhow::Result<SemanticIndex> {
	let mut inputs = Vec::new();
	let mut entries = Vec::new();
	for target in &semantic.targets {
		for phrase in &target.phrases {
			inputs.push(phrase.clone());
			entries.push(SemanticIndexEntry {
				model: target.model.clone(),
				phrase: phrase.clone(),
				score_threshold: target.score_threshold,
				min_input_tokens: target.min_input_tokens,
				max_input_tokens: target.max_input_tokens,
				embedding: Vec::new(),
			});
		}
	}
	let embeddings = client
		.call_llm_embeddings(
			embedding_backend.backend.clone(),
			embedding_backend.route_policies.clone(),
			&semantic.embedding_model,
			inputs,
		)
		.await
		.map_err(|err| anyhow::anyhow!("{err}"))?;
	if embeddings.len() != entries.len() {
		anyhow::bail!(
			"semantic route embedding response count {} did not match phrase count {}",
			embeddings.len(),
			entries.len()
		);
	}
	for (entry, embedding) in entries.iter_mut().zip(embeddings) {
		entry.embedding = embedding;
	}
	Ok(SemanticIndex { entries })
}

#[derive(Debug, Clone, PartialEq)]
struct SemanticSelection {
	model: String,
	phrase: String,
	score: f32,
	score_threshold: f32,
	input_tokens: Option<u64>,
	min_input_tokens: Option<u64>,
	max_input_tokens: Option<u64>,
	token_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum SemanticDecision {
	Selected(SemanticSelection),
	TokenLimitExceeded(SemanticSelection),
	TokenMinimumNotMet(SemanticSelection),
	TokenEstimateFailed(SemanticSelection),
	BelowThreshold(SemanticSelection),
	NoCandidates,
}

#[cfg(test)]
fn select_semantic_target(
	index: &SemanticIndex,
	query_embedding: &[f32],
	messages: Option<&[super::SimpleChatCompletionMessage]>,
) -> Option<SemanticSelection> {
	match semantic_decision(index, query_embedding, messages) {
		SemanticDecision::Selected(selection) => Some(selection),
		_ => None,
	}
}

fn semantic_decision(
	index: &SemanticIndex,
	query_embedding: &[f32],
	messages: Option<&[super::SimpleChatCompletionMessage]>,
) -> SemanticDecision {
	let mut input_tokens_by_model = HashMap::new();
	let mut best_candidate = None;
	let mut best_token_limited = None;
	let mut best_token_minimum = None;
	let mut best_token_error = None;
	let mut best_selected = None;

	for entry in &index.entries {
		let Some(mut selection) = semantic_selection(entry, query_embedding) else {
			continue;
		};
		replace_if_better(&mut best_candidate, selection.clone());
		if selection.score < selection.score_threshold {
			continue;
		}

		if selection.min_input_tokens.is_some() || selection.max_input_tokens.is_some() {
			match semantic_input_tokens(&mut input_tokens_by_model, &entry.model, messages) {
				Ok(input_tokens) => {
					selection.input_tokens = Some(input_tokens);
					if let Some(min_input_tokens) = selection.min_input_tokens
						&& input_tokens < min_input_tokens
					{
						replace_if_better(&mut best_token_minimum, selection);
						continue;
					}
					if let Some(max_input_tokens) = selection.max_input_tokens
						&& input_tokens > max_input_tokens
					{
						replace_if_better(&mut best_token_limited, selection);
						continue;
					}
				},
				Err(err) => {
					selection.token_error = Some(err);
					replace_if_better(&mut best_token_error, selection);
					continue;
				},
			}
		}
		replace_if_better(&mut best_selected, selection);
	}

	if let Some(selection) = best_selected {
		SemanticDecision::Selected(selection)
	} else if let Some(selection) = best_token_limited {
		SemanticDecision::TokenLimitExceeded(selection)
	} else if let Some(selection) = best_token_minimum {
		SemanticDecision::TokenMinimumNotMet(selection)
	} else if let Some(selection) = best_token_error {
		SemanticDecision::TokenEstimateFailed(selection)
	} else if let Some(selection) = best_candidate {
		SemanticDecision::BelowThreshold(selection)
	} else {
		SemanticDecision::NoCandidates
	}
}

fn semantic_selection(
	entry: &SemanticIndexEntry,
	query_embedding: &[f32],
) -> Option<SemanticSelection> {
	let score = cosine_similarity(query_embedding, &entry.embedding)?;
	Some(SemanticSelection {
		model: entry.model.clone(),
		phrase: entry.phrase.clone(),
		score,
		score_threshold: entry.score_threshold,
		input_tokens: None,
		min_input_tokens: entry.min_input_tokens,
		max_input_tokens: entry.max_input_tokens,
		token_error: None,
	})
}

fn semantic_input_tokens(
	input_tokens_by_model: &mut HashMap<String, Result<u64, String>>,
	model: &str,
	messages: Option<&[super::SimpleChatCompletionMessage]>,
) -> Result<u64, String> {
	let Some(messages) = messages else {
		return Err("request messages were unavailable".to_string());
	};
	input_tokens_by_model
		.entry(model.to_string())
		.or_insert_with(|| {
			super::num_tokens_from_messages(model, messages).map_err(|err| err.to_string())
		})
		.clone()
}

fn replace_if_better(best: &mut Option<SemanticSelection>, selection: SemanticSelection) {
	if best
		.as_ref()
		.is_none_or(|current| selection.score > current.score)
	{
		*best = Some(selection);
	}
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f32> {
	if a.len() != b.len() || a.is_empty() {
		return None;
	}
	let mut dot = 0.0_f32;
	let mut a_norm = 0.0_f32;
	let mut b_norm = 0.0_f32;
	for (a, b) in a.iter().zip(b.iter()) {
		dot += a * b;
		a_norm += a * a;
		b_norm += b * b;
	}
	if a_norm <= f32::EPSILON || b_norm <= f32::EPSILON {
		return None;
	}
	Some(dot / (a_norm.sqrt() * b_norm.sqrt()))
}

fn model_not_found_response() -> Response {
	llm_error_response(
		::http::StatusCode::NOT_FOUND,
		"Model not found",
		"model_not_found",
	)
}

fn llm_error_response(status: ::http::StatusCode, message: &str, code: &str) -> Response {
	::http::Response::builder()
		.status(status)
		.header(::http::header::CONTENT_TYPE, "application/json")
		.body(http::Body::from(
			serde_json::json!({
				"error": {
					"message": message,
					"type": "invalid_request_error",
					"code": code,
				}
			})
			.to_string(),
		))
		.expect("LLM error response is valid")
}

fn model_authorized(model: &ModelRoute, req: &Request) -> bool {
	let rules = model
		.route_policies
		.iter()
		.filter_map(|policy| match policy {
			TrafficPolicy::Authorization(authorization) => Some(authorization.0.clone()),
			_ => None,
		})
		.collect::<Vec<_>>();
	if rules.is_empty() {
		return true;
	}
	crate::http::authorization::HTTPAuthorizationSet::new(
		crate::http::authorization::RuleSets::from_arcs(rules),
	)
	.apply(req)
	.is_ok()
}

fn model_list_entry(id: &str, created: u64) -> serde_json::Value {
	serde_json::json!({
		"id": id,
		"object": "model",
		"created": created,
		// TODO: this matches some other gateways but seems odd. Should we use the real provide here?
		"owned_by": "openai",
	})
}

fn is_model_list_request(req: &Request) -> bool {
	let path = req.uri().path().trim_end_matches('/');
	path == "/v1/models"
		|| path
			.strip_prefix("/v1/models")
			.is_some_and(|suffix| suffix.starts_with('/'))
		|| path == "/models"
		|| path
			.strip_prefix("/models")
			.is_some_and(|suffix| suffix.starts_with('/'))
}

fn header_matches(matches: &[Vec<HeaderMatch>], req: &Request) -> bool {
	if matches.is_empty() {
		return true;
	}
	matches.iter().any(|headers| headers_match(headers, req))
}

fn headers_match(headers: &[HeaderMatch], req: &Request) -> bool {
	for HeaderMatch { name, value } in headers {
		let Some(have) = http::get_pseudo_or_header_value(name, req) else {
			return false;
		};
		match value {
			HeaderValueMatch::Exact(want) => {
				if have.as_ref() != *want {
					return false;
				}
			},
			HeaderValueMatch::Regex(want) => {
				let Some(have_str) = have.to_str().ok() else {
					return false;
				};
				let Some(m) = want.find(have_str) else {
					return false;
				};
				if !(m.start() == 0 && m.end() == have_str.len()) {
					return false;
				}
			},
			HeaderValueMatch::Invalid => return false,
		}
	}
	true
}

fn model_name_matches(pattern: &str, model: &str) -> bool {
	if pattern == "*" {
		return true;
	}
	if let Some(prefix) = pattern.strip_suffix('*') {
		return model.starts_with(prefix);
	}
	if let Some(suffix) = pattern.strip_prefix('*') {
		return model.ends_with(suffix);
	}
	pattern == model
}

async fn requested_model(req: &mut Request) -> RouterResult<RequestedModel> {
	let path = req.uri().path();
	if let Some(model) = crate::llm::types::detect::extract_model_from_path(path) {
		return Ok(RequestedModel {
			model: model.to_string(),
			location: RequestedModelLocation::Path,
		});
	}

	let body = body_bytes(req).await?;
	let body: Value = serde_json::from_slice(&body).map_err(|err| {
		tracing::debug!(%err, "failed to parse LLM request body");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"LLM request body must be valid JSON",
			"invalid_request_body",
		))
	})?;
	let model = body
		.get("model")
		.and_then(Value::as_str)
		.map(ToString::to_string)
		.ok_or_else(|| {
			Box::new(llm_error_response(
				::http::StatusCode::BAD_REQUEST,
				"LLM request body is missing string field 'model'",
				"missing_model",
			))
		})?;
	Ok(RequestedModel {
		model,
		location: RequestedModelLocation::Body(body),
	})
}

fn semantic_request(req: &Request, location: &RequestedModelLocation) -> Option<SemanticRequest> {
	if req.uri().path().trim_end_matches('/') != "/v1/chat/completions" {
		return None;
	}
	let RequestedModelLocation::Body(body) = location else {
		return None;
	};
	let messages = semantic_chat_messages(body)?;
	let query_text = messages
		.iter()
		.rev()
		.find(|message| message.role.as_str() == "user")
		.map(|message| message.content.to_string())
		.filter(|text| !text.is_empty())?;
	Some(SemanticRequest {
		query_text,
		messages,
	})
}

#[cfg(test)]
fn semantic_query_text(req: &Request, location: &RequestedModelLocation) -> Option<String> {
	semantic_request(req, location).map(|request| request.query_text)
}

fn semantic_chat_messages(body: &Value) -> Option<Vec<super::SimpleChatCompletionMessage>> {
	let messages = body.get("messages")?.as_array()?;
	let messages = messages
		.iter()
		.filter_map(|message| {
			let role = message.get("role").and_then(Value::as_str)?;
			let content = message
				.get("content")
				.and_then(message_content_text)
				.unwrap_or_default();
			Some(super::SimpleChatCompletionMessage {
				role: strng::new(role),
				content: strng::new(&content),
			})
		})
		.collect::<Vec<_>>();
	(!messages.is_empty()).then_some(messages)
}

fn message_content_text(content: &Value) -> Option<String> {
	match content {
		Value::String(text) => Some(text.clone()),
		Value::Array(parts) => {
			let text = parts
				.iter()
				.filter_map(|part| {
					if part.get("type").and_then(Value::as_str) != Some("text") {
						return None;
					}
					part.get("text").and_then(Value::as_str)
				})
				.collect::<Vec<_>>()
				.join(" ");
			(!text.is_empty()).then_some(text)
		},
		_ => None,
	}
}

fn rewrite_request_model(
	req: &mut Request,
	location: RequestedModelLocation,
	target: &str,
) -> RouterResult<()> {
	match location {
		RequestedModelLocation::Body(body) => rewrite_body_model(req, body, target),
		RequestedModelLocation::Path => rewrite_uri_model(req, target),
	}
}

fn rewrite_body_model(req: &mut Request, mut body: Value, target: &str) -> RouterResult<()> {
	let Some(obj) = body.as_object_mut() else {
		return Ok(());
	};
	obj.insert("model".to_string(), Value::String(target.to_string()));
	let body = serde_json::to_vec(&body).map_err(|err| {
		tracing::debug!(%err, "failed to serialize rewritten LLM request body");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"Failed to rewrite LLM request body model",
			"request_body_rewrite_failed",
		))
	})?;
	*req.body_mut() = http::Body::from(body);
	req.headers_mut().remove(::http::header::CONTENT_LENGTH);
	req.extensions_mut().remove::<cel::BufferedBody>();
	Ok(())
}

fn rewrite_uri_model(req: &mut Request, target: &str) -> RouterResult<()> {
	let Some(path_and_query) = req.uri().path_and_query() else {
		return Ok(());
	};
	let Some(path) = rewrite_path_model(path_and_query.path(), target) else {
		return Ok(());
	};
	let path_and_query = if let Some(query) = path_and_query.query() {
		format!("{path}?{query}")
	} else {
		path
	};
	let path_and_query = path_and_query.parse().map_err(|err| {
		tracing::debug!(%err, "failed to rewrite LLM request URI model");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"Failed to rewrite LLM request URI model",
			"request_uri_rewrite_failed",
		))
	})?;
	let mut parts = req.uri().clone().into_parts();
	parts.path_and_query = Some(path_and_query);
	*req.uri_mut() = ::http::Uri::from_parts(parts).map_err(|err| {
		tracing::debug!(%err, "failed to rebuild LLM request URI");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"Failed to rewrite LLM request URI model",
			"request_uri_rewrite_failed",
		))
	})?;
	Ok(())
}

fn rewrite_path_model(path: &str, target: &str) -> Option<String> {
	if path.ends_with(":streamRawPredict") || path.ends_with(":rawPredict") {
		let (prefix, rest) = path.split_once("/publishers/anthropic/models/")?;
		let (_, suffix) = rest.split_once(':')?;
		return Some(format!(
			"{prefix}/publishers/anthropic/models/{}:{suffix}",
			encode_model_path_segment(target)
		));
	}
	for suffix in [
		"/invoke-with-response-stream",
		"/invoke",
		"/converse-stream",
		"/converse",
	] {
		if let Some(before_suffix) = path.strip_suffix(suffix)
			&& let Some((prefix, _)) = before_suffix.split_once("/model/")
		{
			return Some(format!(
				"{prefix}/model/{}{suffix}",
				encode_model_path_segment(target)
			));
		}
	}
	None
}

fn encode_model_path_segment(model: &str) -> String {
	const MODEL_SEGMENT: &AsciiSet = &CONTROLS.add(b'/').add(b'%');
	utf8_percent_encode(model, MODEL_SEGMENT).to_string()
}

async fn body_bytes(req: &mut Request) -> RouterResult<Bytes> {
	if let Some(body) = req.extensions().get::<cel::BufferedBody>() {
		return Ok(body.0.clone());
	}
	let body = http::inspect_body(req).await.map_err(|err| {
		tracing::debug!(%err, "failed to read LLM request body");
		Box::new(llm_error_response(
			::http::StatusCode::BAD_REQUEST,
			"Failed to read LLM request body",
			"request_body_read_failed",
		))
	})?;
	req.extensions_mut().insert(cel::BufferedBody(body.clone()));
	Ok(body)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn semantic_query_text_extracts_last_user_string_message() {
		let req = ::http::Request::builder()
			.uri("/v1/chat/completions")
			.body(http::Body::empty())
			.unwrap();
		let body = serde_json::json!({
			"messages": [
				{"role": "user", "content": "first question"},
				{"role": "assistant", "content": "first answer"},
				{"role": "user", "content": "second question"}
			]
		});

		assert_eq!(
			semantic_query_text(&req, &RequestedModelLocation::Body(body)).as_deref(),
			Some("second question")
		);
	}

	#[test]
	fn semantic_query_text_extracts_text_blocks_from_multimodal_message() {
		let req = ::http::Request::builder()
			.uri("/v1/chat/completions")
			.body(http::Body::empty())
			.unwrap();
		let body = serde_json::json!({
			"messages": [
				{
					"role": "user",
					"content": [
						{"type": "image_url", "image_url": {"url": "https://example.test/image.png"}},
						{"type": "text", "text": "find ski resorts"},
						{"type": "text", "text": "near fresh snow"}
					]
				}
			]
		});

		assert_eq!(
			semantic_query_text(&req, &RequestedModelLocation::Body(body)).as_deref(),
			Some("find ski resorts near fresh snow")
		);
	}

	#[test]
	fn semantic_query_text_ignores_non_chat_completion_routes() {
		let req = ::http::Request::builder()
			.uri("/v1/responses")
			.body(http::Body::empty())
			.unwrap();
		let body = serde_json::json!({
			"messages": [{"role": "user", "content": "hello"}]
		});

		assert!(semantic_query_text(&req, &RequestedModelLocation::Body(body)).is_none());
	}

	#[test]
	fn select_semantic_target_picks_highest_score_above_threshold() {
		let index = SemanticIndex {
			entries: vec![
				SemanticIndexEntry {
					model: "coding".to_string(),
					phrase: "write python".to_string(),
					score_threshold: 0.5,
					min_input_tokens: None,
					max_input_tokens: None,
					embedding: vec![1.0, 0.0],
				},
				SemanticIndexEntry {
					model: "travel".to_string(),
					phrase: "plan a vacation".to_string(),
					score_threshold: 0.5,
					min_input_tokens: None,
					max_input_tokens: None,
					embedding: vec![0.0, 1.0],
				},
			],
		};

		let selection = select_semantic_target(&index, &[0.9, 0.1], None).expect("semantic match");

		assert_eq!(selection.model, "coding");
		assert_eq!(selection.phrase, "write python");
		assert!(selection.score > 0.9);
	}

	#[test]
	fn select_semantic_target_falls_back_when_score_is_below_threshold() {
		let index = SemanticIndex {
			entries: vec![SemanticIndexEntry {
				model: "coding".to_string(),
				phrase: "write python".to_string(),
				score_threshold: 0.9,
				min_input_tokens: None,
				max_input_tokens: None,
				embedding: vec![1.0, 0.0],
			}],
		};

		assert!(select_semantic_target(&index, &[0.5, 0.5], None).is_none());
	}

	#[test]
	fn select_semantic_target_skips_target_exceeding_max_input_tokens() {
		let index = SemanticIndex {
			entries: vec![
				SemanticIndexEntry {
					model: "gpt-4o-mini".to_string(),
					phrase: "write python".to_string(),
					score_threshold: 0.5,
					min_input_tokens: None,
					max_input_tokens: Some(1),
					embedding: vec![1.0, 0.0],
				},
				SemanticIndexEntry {
					model: "gpt-4.1-mini".to_string(),
					phrase: "design a distributed system".to_string(),
					score_threshold: 0.5,
					min_input_tokens: None,
					max_input_tokens: None,
					embedding: vec![0.9, 0.1],
				},
			],
		};
		let messages = vec![crate::llm::SimpleChatCompletionMessage {
			role: strng::new("user"),
			content: strng::new("write python code with enough words to exceed one token"),
		}];

		let selection =
			select_semantic_target(&index, &[1.0, 0.0], Some(&messages)).expect("semantic match");

		assert_eq!(selection.model, "gpt-4.1-mini");
	}

	#[test]
	fn select_semantic_target_skips_target_below_min_input_tokens() {
		let index = SemanticIndex {
			entries: vec![
				SemanticIndexEntry {
					model: "analysis".to_string(),
					phrase: "deep architecture analysis".to_string(),
					score_threshold: 0.5,
					min_input_tokens: Some(1_000),
					max_input_tokens: None,
					embedding: vec![1.0, 0.0],
				},
				SemanticIndexEntry {
					model: "general".to_string(),
					phrase: "general question".to_string(),
					score_threshold: 0.5,
					min_input_tokens: None,
					max_input_tokens: None,
					embedding: vec![0.9, 0.1],
				},
			],
		};
		let messages = vec![crate::llm::SimpleChatCompletionMessage {
			role: strng::new("user"),
			content: strng::new("short question"),
		}];

		let selection =
			select_semantic_target(&index, &[1.0, 0.0], Some(&messages)).expect("semantic match");

		assert_eq!(selection.model, "general");
	}

	#[test]
	fn rewrite_path_model_rewrites_bedrock_converse_and_preserves_suffix() {
		assert_eq!(
			rewrite_path_model(
				"/model/anthropic.claude-3-5-sonnet-20241022-v2:0/converse",
				"anthropic.claude-3-haiku-20240307-v1:0",
			)
			.as_deref(),
			Some("/model/anthropic.claude-3-haiku-20240307-v1:0/converse")
		);
	}

	#[test]
	fn rewrite_path_model_rewrites_bedrock_invoke_and_encodes_slashes() {
		assert_eq!(
			rewrite_path_model(
				"/model/virtual/invoke-with-response-stream",
				"arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/my-profile",
			)
			.as_deref(),
			Some(
				"/model/arn:aws:bedrock:us-east-1:123456789012:application-inference-profile%2Fmy-profile/invoke-with-response-stream"
			)
		);
	}

	#[test]
	fn rewrite_path_model_rewrites_vertex_raw_predict() {
		assert_eq!(
			rewrite_path_model(
				"/v1/projects/p/locations/us/publishers/anthropic/models/virtual:rawPredict",
				"claude-sonnet",
			)
			.as_deref(),
			Some("/v1/projects/p/locations/us/publishers/anthropic/models/claude-sonnet:rawPredict")
		);
	}

	#[test]
	fn rewrite_uri_model_preserves_query() {
		let mut req = ::http::Request::builder()
			.uri("http://example.com/model/virtual/converse?trace=true")
			.body(http::Body::empty())
			.unwrap();
		rewrite_uri_model(&mut req, "real/model").expect("URI rewrites");
		assert_eq!(
			req.uri().to_string(),
			"http://example.com/model/real%2Fmodel/converse?trace=true"
		);
	}
}
