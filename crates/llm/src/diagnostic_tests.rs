use std::fmt::Write;
use std::sync::{Arc, Barrier, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use crate::{AIError, InputFormat, JsonErrorDiagnostic, logged_response_parsing};

const SECRET: &str = "openshield-private-diagnostic-sentinel";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<String>>);

struct Fields<'a>(&'a mut String);

impl Visit for Fields<'_> {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		write!(self.0, "{}={value:?} ", field.name()).unwrap();
	}
}

impl Subscriber for Capture {
	fn enabled(&self, _: &Metadata<'_>) -> bool {
		true
	}

	fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
		Some(tracing::metadata::LevelFilter::TRACE)
	}

	fn new_span(&self, _: &Attributes<'_>) -> Id {
		Id::from_u64(1)
	}

	fn record(&self, _: &Id, _: &Record<'_>) {}
	fn record_follows_from(&self, _: &Id, _: &Id) {}
	fn enter(&self, _: &Id) {}
	fn exit(&self, _: &Id) {}

	fn event(&self, event: &Event<'_>) {
		let mut events = self.0.lock().unwrap();
		event.record(&mut Fields(&mut events));
		events.push('\n');
	}
}

pub(crate) fn capture_diagnostics<T>(run: impl FnOnce() -> T) -> (T, String) {
	// With only one registered dispatcher, tracing initializes a new callsite
	// using the current thread's default. A parallel test without a subscriber
	// can then cache Interest::never for a site our capture needs. Retain an
	// unused dispatcher so registration consults both subscribers. Events still
	// go only to this invocation's thread-scoped capture, never a global buffer.
	static REGISTRATION_ANCHOR: OnceLock<tracing::Dispatch> = OnceLock::new();
	REGISTRATION_ANCHOR.get_or_init(|| tracing::Dispatch::new(Capture::default()));
	let capture = Capture::default();
	let result = tracing::subscriber::with_default(capture.clone(), run);
	let events = capture.0.lock().unwrap().clone();
	(result, events)
}

#[test]
fn diagnostic_capture_handles_first_callsite_registration_on_another_thread() {
	fn emit() {
		tracing::debug!("parallel diagnostic registration probe");
	}
	let barrier = Arc::new(Barrier::new(2));
	let other_barrier = barrier.clone();
	let other = std::thread::spawn(move || {
		other_barrier.wait();
		emit();
		other_barrier.wait();
	});
	let (_, events) = capture_diagnostics(|| {
		barrier.wait();
		barrier.wait();
		emit();
	});
	other.join().unwrap();
	assert!(events.contains("parallel diagnostic registration probe"));
}

fn assert_private(error: AIError) {
	let display = error.to_string();
	let debug = format!("{error:?}");
	assert!(!display.contains(SECRET));
	assert!(!debug.contains(SECRET));
	assert!(display.len() < 160);
	assert!(std::error::Error::source(&error).is_none());
	let error = anyhow::Error::new(error);
	assert!(!format!("{error:#}").contains(SECRET));
	assert!(!format!("{error:?}").contains(SECRET));
	for source in error.chain() {
		assert!(!source.to_string().contains(SECRET));
	}
}

#[test]
fn diagnostic_discards_custom_error_messages_in_every_json_error_variant() {
	for constructor in [
		AIError::request_marshal,
		AIError::response_parsing,
		AIError::response_marshal,
	] {
		let raw: serde_json::Error = serde::de::Error::custom(SECRET.repeat(4096));
		assert!(raw.to_string().contains(SECRET));
		assert_private(constructor(raw));
	}
	assert_private(AIError::request_parsing(
		InputFormat::Messages,
		serde::de::Error::custom(SECRET),
	));
}

#[test]
fn logged_parser_never_retains_body_or_content_derived_error() {
	#[derive(Debug, Deserialize)]
	enum Choice {
		Allowed,
	}
	let body = serde_json::to_vec(SECRET).unwrap();
	let raw = serde_json::from_slice::<Choice>(&body).unwrap_err();
	assert!(raw.to_string().contains(SECRET));
	let (error, events) = capture_diagnostics(|| logged_response_parsing(&body)(raw));
	assert!(events.contains("failed to parse response"));
	assert!(events.contains("category=\"data\""));
	assert!(events.contains(&format!("response_bytes={}", body.len())));
	assert!(!events.contains(SECRET));
	assert!(!events.contains("body="));
	assert_private(error);
}

#[test]
fn logged_parser_withholds_non_utf8_and_body_prefixes() {
	let mut body = SECRET.as_bytes().repeat(128);
	body.insert(0, 0xff);
	let raw = serde_json::from_slice::<serde_json::Value>(&body).unwrap_err();
	let (error, events) = capture_diagnostics(|| logged_response_parsing(&body)(raw));
	assert!(events.contains("failed to parse response"));
	assert!(events.contains("category=\"syntax\""));
	assert!(!events.contains(SECRET));
	assert_private(error);
}

#[test]
fn diagnostic_stream_parser_drops_values_before_anyhow_and_debug_logs() {
	use http_body_util::BodyExt;

	let runtime = tokio::runtime::Builder::new_current_thread()
		.build()
		.unwrap();
	let data = serde_json::json!({
		"choices": [{"index": SECRET, "delta": {"content": SECRET}}]
	});
	let frame = format!("data: {data}\n\ndata: [DONE]\n\n");
	let (_, events) = capture_diagnostics(|| {
		runtime.block_on(async {
			let response = agent_http::Response::new(agent_http::Body::from(frame));
			let response = crate::conversion::completions::passthrough_stream(
				crate::StreamingUsageGuard::default(),
				crate::LogContentFields::default(),
				response,
			);
			let _ = response.into_body().collect().await.unwrap();
		})
	});
	assert!(events.contains("failed to parse streaming response"));
	assert!(events.contains("data at line"));
	assert!(!events.contains(SECRET));
}

#[test]
fn serializer_custom_error_is_not_retained() {
	struct PrivateSerializer;
	impl Serialize for PrivateSerializer {
		fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
			Err(serde::ser::Error::custom(SECRET))
		}
	}
	let raw = serde_json::to_vec(&PrivateSerializer).unwrap_err();
	assert!(raw.to_string().contains(SECRET));
	assert_private(AIError::request_marshal(raw));
	assert_private(AIError::response_marshal(
		serde_json::to_vec(&PrivateSerializer).unwrap_err(),
	));
}

#[test]
fn diagnostic_keeps_category_and_location_without_error_sources() {
	for (body, category) in [(b"{".as_slice(), "eof"), (b"!".as_slice(), "syntax")] {
		let raw = serde_json::from_slice::<serde_json::Value>(body).unwrap_err();
		let location = (raw.line(), raw.column());
		let diagnostic = JsonErrorDiagnostic::from(raw);
		assert_eq!(diagnostic.category, category);
		assert_eq!((diagnostic.line, diagnostic.column), location);
		assert!(std::error::Error::source(&diagnostic).is_none());
	}
	struct PrivateReader;
	impl std::io::Read for PrivateReader {
		fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
			Err(std::io::Error::other(SECRET))
		}
	}
	let raw = serde_json::from_reader::<_, serde_json::Value>(PrivateReader).unwrap_err();
	assert!(raw.to_string().contains(SECRET));
	let diagnostic = JsonErrorDiagnostic::from(raw);
	assert_eq!(diagnostic.category, "io");
	assert!(!format!("{diagnostic:?} {diagnostic}").contains(SECRET));
	assert!(std::error::Error::source(&diagnostic).is_none());
}
