//! Continuing authorization belongs to a gateway replica, never to the worker.
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use protos::ateapi::Actor;
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::proxy::ProxyError;

const INTERVAL: Duration = Duration::from_secs(5);
const RPC_DEADLINE: Duration = Duration::from_secs(2);

type Binding = (String, Option<String>);
type Validate = dyn Fn(&Actor) -> Result<(), ProxyError> + Send + Sync;

pub(crate) struct Lease {
	pub(crate) cancelled: CancellationToken,
	pub(crate) reason: Mutex<&'static str>,
	metrics: Option<Arc<crate::telemetry::metrics::Metrics>>,
	// Polling stops when the last live binding releases its group.
	_group: Arc<ActorGroup>,
	validate: Box<Validate>,
}
impl std::fmt::Debug for Lease {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Lease")
			.field("cancelled", &self.cancelled)
			.finish_non_exhaustive()
	}
}
impl Drop for Lease {
	fn drop(&mut self) {
		self.cancelled.cancel();
		if let Some(metrics) = &self.metrics {
			metrics.substrate_revocation_actors_active.dec();
		}
	}
}

#[derive(Debug, Default)]
struct ActorGroup {
	bindings: Mutex<HashMap<Binding, Weak<Lease>>>,
	cancelled: CancellationToken,
}
impl Drop for ActorGroup {
	fn drop(&mut self) {
		self.cancelled.cancel();
	}
}

#[derive(Clone, Debug)]
pub(crate) struct Registry {
	actors: Arc<Mutex<HashMap<String, Weak<ActorGroup>>>>,
	permits: Arc<Semaphore>,
}
impl Default for Registry {
	fn default() -> Self {
		Self {
			actors: Default::default(),
			permits: Arc::new(Semaphore::new(64)),
		}
	}
}
impl Registry {
	pub(crate) fn register<F, Fut, V>(
		&self,
		key: String,
		binding: Binding,
		metrics: Option<Arc<crate::telemetry::metrics::Metrics>>,
		check: F,
		validate: V,
	) -> Arc<Lease>
	where
		F: Fn() -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<Actor, ProxyError>> + Send + 'static,
		V: Fn(&Actor) -> Result<(), ProxyError> + Send + Sync + 'static,
	{
		let mut actors = self.actors.lock().expect("revocation registry poisoned");
		let (group, start) = match actors
			.get(&key)
			.and_then(Weak::upgrade)
			.filter(|group| !group.cancelled.is_cancelled())
		{
			Some(group) => (group, false),
			None => (Arc::new(ActorGroup::default()), true),
		};
		let mut bindings = group.bindings.lock().expect("actor group poisoned");
		if let Some(lease) = bindings.get(&binding).and_then(Weak::upgrade)
			&& !lease.cancelled.is_cancelled()
		{
			return lease;
		}
		if let Some(metrics) = &metrics {
			metrics.substrate_revocation_actors_active.inc();
		}
		let lease = Arc::new(Lease {
			cancelled: CancellationToken::new(),
			reason: Mutex::new("actor-check-failed"),
			metrics: metrics.clone(),
			_group: group.clone(),
			validate: Box::new(validate),
		});
		bindings.insert(binding, Arc::downgrade(&lease));
		if !start {
			return lease;
		}
		let weak = Arc::downgrade(&group);
		actors.insert(key.clone(), weak.clone());
		let actors = self.actors.clone();
		let permits = self.permits.clone();
		let cancelled = group.cancelled.clone();
		// Jitter only shortens the interval; it never extends authorization.
		let mut due = Instant::now() + Duration::from_millis(rand::random_range(4000..=5000));
		tokio::spawn(async move {
			loop {
				tokio::select! { biased;
					_ = cancelled.cancelled() => break,
					_ = sleep_until(due) => {}
				}
				let deadline = due + RPC_DEADLINE;
				let result = timeout_at(deadline, async {
					let _permit = permits.acquire().await.expect("semaphore remains open");
					if Instant::now() >= deadline {
						return Err(ProxyError::SubstrateEgressConnectDenied(
							"actor-check-overdue",
						));
					}
					if let Some(metrics) = &metrics {
						metrics.substrate_revocation_lookups.inc();
					}
					check().await
				})
				.await;
				// Serialize cancellation with registration so a new binding cannot
				// join a group after its poller decides to stop.
				let _actors = actors.lock().expect("revocation registry poisoned");
				let Some(group) = weak.upgrade() else { break };
				let mut bindings = group.bindings.lock().expect("actor group poisoned");
				let mut failed = false;
				bindings.retain(|_, weak| {
					let Some(lease) = weak.upgrade() else {
						return false;
					};
					if lease.cancelled.is_cancelled() {
						return false;
					}
					let validation = match &result {
						Ok(Ok(actor)) if Instant::now() < deadline => (lease.validate)(actor),
						Ok(Err(ProxyError::SubstrateEgressConnectDenied(reason))) => {
							Err(ProxyError::SubstrateEgressConnectDenied(reason))
						},
						_ => Err(ProxyError::SubstrateEgressConnectDenied(
							"actor-check-failed",
						)),
					};
					if let Err(error) = validation {
						failed = true;
						*lease.reason.lock().expect("reason poisoned") = match error {
							ProxyError::SubstrateEgressConnectDenied(reason) => reason,
							_ => "actor-check-failed",
						};
						lease.cancelled.cancel();
						return false;
					}
					true
				});
				if failed && let Some(metrics) = &metrics {
					metrics.substrate_revocation_failed_checks.inc();
					if Instant::now() >= deadline {
						metrics.substrate_revocation_overdue_checks.inc();
					}
				}
				if bindings.is_empty() {
					cancelled.cancel();
					break;
				}
				due += INTERVAL;
			}
			let mut actors = actors.lock().expect("revocation registry poisoned");
			if actors
				.get(&key)
				.is_some_and(|current| current.ptr_eq(&weak))
			{
				actors.remove(&key);
			}
		});
		lease
	}
	#[cfg(test)]
	fn register_test<F, Fut>(
		&self,
		key: String,
		metrics: Option<Arc<crate::telemetry::metrics::Metrics>>,
		check: F,
	) -> Arc<Lease>
	where
		F: Fn() -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<(), ProxyError>> + Send + 'static,
	{
		self.register(
			key,
			(String::new(), None),
			metrics,
			move || {
				let check = check();
				async move { check.await.map(|()| Actor::default()) }
			},
			|_| Ok(()),
		)
	}
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};

	use super::*;

	#[derive(Clone)]
	struct LogWriter(Arc<Mutex<Vec<u8>>>);
	impl std::io::Write for LogWriter {
		fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
			self.0.lock().unwrap().extend_from_slice(bytes);
			Ok(bytes.len())
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}

	#[derive(Clone)]
	struct ActorView {
		actor: Arc<Mutex<protos::ateapi::Actor>>,
		calls: Arc<AtomicUsize>,
		error: Option<tonic::Code>,
		delay: Duration,
	}
	#[async_trait::async_trait]
	impl crate::test_helpers::ateapimock::Handler for ActorView {
		async fn get_actor(
			&mut self,
			_: &protos::ateapi::GetActorRequest,
		) -> Result<protos::ateapi::Actor, tonic::Status> {
			self.calls.fetch_add(1, Ordering::Relaxed);
			tokio::time::sleep(self.delay).await;
			if let Some(error) = self.error {
				return Err(tonic::Status::new(error, "test failure"));
			}
			Ok(self.actor.lock().unwrap().clone())
		}
	}

	#[rstest::rstest]
	#[case::quarantine("quarantine", true, true, "actor-quarantined")]
	#[case::uid("uid", true, true, "actor-uid-mismatch")]
	#[case::deleted("deleted", true, true, "actor-check-failed")]
	#[case::hold("hold", false, false, "")]
	#[case::activation("activation", false, true, "activation-mismatch")]
	#[case::outage("outage", true, true, "actor-check-failed")]
	#[case::slow("slow", true, true, "actor-check-failed")]
	#[case::overdue("overdue", true, true, "actor-check-failed")]
	#[tokio::test]
	async fn mixed_certificate_registry_shares_lookup_and_validates_frozen_bindings(
		#[case] trigger: &str,
		#[case] uid_only_closed: bool,
		#[case] activation_closed: bool,
		#[case] reason: &str,
	) {
		use super::super::egress_actor_resolution::{ActorIdentity, EgressActorResolution};
		use crate::test_helpers::ateapimock;
		use crate::test_helpers::proxymock::setup_proxy_test;
		let actor = Arc::new(Mutex::new(protos::ateapi::Actor {
			metadata: Some(protos::ateapi::ResourceMetadata {
				uid: "uid-1".into(),
				..Default::default()
			}),
			status: Some(protos::ateapi::ActorStatus {
				state: protos::ateapi::ActorState::Running as i32,
				activation_id: "run-1".into(),
				..Default::default()
			}),
		}));
		let calls = Arc::new(AtomicUsize::new(0));
		let handler = ActorView {
			actor: actor.clone(),
			calls: calls.clone(),
			error: match trigger {
				"deleted" => Some(tonic::Code::NotFound),
				"outage" => Some(tonic::Code::Unavailable),
				_ => None,
			},
			delay: if trigger == "slow" {
				Duration::from_secs(3)
			} else {
				Duration::ZERO
			},
		};
		let api = ateapimock::AteApiMock::new(move || handler.clone())
			.spawn()
			.await;
		let gateway = setup_proxy_test("{}").unwrap();
		let inputs = gateway.inputs();
		let policy: EgressActorResolution =
			serde_json::from_value(serde_json::json!({"host": api.address.to_string()})).unwrap();
		let mut identity = ActorIdentity {
			atespace: "demo".into(),
			actor_name: "my-actor".into(),
			actor_uid: Some("uid-1".into()),
			activation_id: Some("run-1".into()),
		};
		let bound = policy.monitor(&inputs, &identity, "192.0.2.1:443");
		identity.activation_id = None;
		let uid_only = policy.monitor(&inputs, &identity, "192.0.2.2:443");
		let another = policy.monitor(&inputs, &identity, "192.0.2.3:443");
		assert!(Arc::ptr_eq(&uid_only, &another));
		assert_eq!(
			inputs.substrate_revocations.actors.lock().unwrap().len(),
			1,
			"one actor poll group for mixed certificates"
		);
		{
			let mut actor = actor.lock().unwrap();
			let status = actor.status.as_mut().unwrap();
			match trigger {
				"quarantine" => status.quarantine = Some(protos::ateapi::ActorQuarantine {}),
				"uid" => {
					status.quarantine = Some(protos::ateapi::ActorQuarantine {});
					actor.metadata.as_mut().unwrap().uid = "uid-2".into();
				},
				"hold" => status.holds.push(protos::ateapi::ActorHold {}),
				"activation" => status.activation_id = "run-2".into(),
				_ => {},
			}
		}
		let _permits = if trigger == "overdue" {
			Some(
				inputs
					.substrate_revocations
					.permits
					.clone()
					.acquire_many_owned(64)
					.await
					.unwrap(),
			)
		} else {
			None
		};
		tokio::time::sleep(Duration::from_millis(7200)).await;
		assert_eq!(
			calls.load(Ordering::Relaxed),
			usize::from(trigger != "overdue"),
			"one GetActor per poll"
		);
		assert_eq!(uid_only.cancelled.is_cancelled(), uid_only_closed);
		assert_eq!(bound.cancelled.is_cancelled(), activation_closed);
		if activation_closed {
			assert_eq!(*bound.reason.lock().unwrap(), reason);
		}
		if uid_only_closed {
			assert_eq!(*uid_only.reason.lock().unwrap(), reason);
		}
		let logs = Arc::new(Mutex::new(Vec::new()));
		let writer = LogWriter(logs.clone());
		let subscriber = tracing_subscriber::fmt()
			.json()
			.with_env_filter("off,agentgateway::substrate::connect_revocation=warn")
			.with_writer(move || writer.clone())
			.finish();
		if uid_only_closed {
			tracing::subscriber::with_default(subscriber, || {
				crate::proxy::log_revocation(
					&uid_only,
					Some(&identity),
					&"192.0.2.2:443".parse().unwrap(),
				);
			});
			let bytes = logs.lock().unwrap();
			let event: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
			assert_eq!(
				event["target"],
				"agentgateway::substrate::connect_revocation"
			);
			assert_eq!(event["fields"]["reason_code"], reason);
			assert_eq!(event["fields"]["activation_id"], "");
			assert_eq!(event["fields"]["actor_uid"], "uid-1");
		}
	}

	#[tokio::test(start_paused = true)]
	async fn tunnels_share_one_check_and_last_drop_stops_polling() {
		let registry = Registry::default();
		let calls = Arc::new(AtomicUsize::new(0));
		let count = calls.clone();
		let a = registry.register_test("actor/run".into(), None, move || {
			count.fetch_add(1, Ordering::Relaxed);
			async { Ok(()) }
		});
		let b = registry.register_test("actor/run".into(), None, || async {
			panic!("per-tunnel lookup")
		});
		assert!(Arc::ptr_eq(&a, &b));
		tokio::time::sleep(Duration::from_millis(5100)).await;
		assert_eq!(calls.load(Ordering::Relaxed), 1);
		drop(a);
		drop(b);
		tokio::task::yield_now().await;
		tokio::time::sleep(INTERVAL * 2).await;
		assert_eq!(calls.load(Ordering::Relaxed), 1);
		assert!(registry.actors.lock().unwrap().is_empty());
	}

	#[tokio::test(start_paused = true)]
	async fn slow_rpc_and_backlog_fail_closed_without_late_lookup() {
		for backlog in [false, true] {
			let registry = Registry::default();
			let permit = if backlog {
				Some(
					registry
						.permits
						.clone()
						.acquire_many_owned(64)
						.await
						.unwrap(),
				)
			} else {
				None
			};
			let calls = Arc::new(AtomicUsize::new(0));
			let count = calls.clone();
			let lease = registry.register_test("actor/run".into(), None, move || {
				count.fetch_add(1, Ordering::Relaxed);
				async { std::future::pending().await }
			});
			tokio::time::sleep(Duration::from_millis(7100)).await;
			assert!(lease.cancelled.is_cancelled());
			assert_eq!(calls.load(Ordering::Relaxed), usize::from(!backlog));
			drop(permit);
			tokio::task::yield_now().await;
			assert_eq!(calls.load(Ordering::Relaxed), usize::from(!backlog));
		}
	}

	#[tokio::test(start_paused = true)]
	async fn missed_schedule_closes_without_starting_a_stale_lookup() {
		let registry = Registry::default();
		let lease = registry.register_test("actor/run".into(), None, || async {
			panic!("overdue schedule must not start RPC")
		});
		tokio::time::advance(Duration::from_secs(10)).await;
		tokio::task::yield_now().await;
		assert!(lease.cancelled.is_cancelled());
	}

	#[tokio::test(start_paused = true)]
	async fn replicas_have_independent_checks() {
		let calls = Arc::new(AtomicUsize::new(0));
		let mut leases = Vec::new();
		for _ in 0..3 {
			let registry = Registry::default();
			let calls = calls.clone();
			leases.push(registry.register_test("actor/run".into(), None, move || {
				calls.fetch_add(1, Ordering::Relaxed);
				async { Ok(()) }
			}));
		}
		tokio::time::sleep(Duration::from_millis(5100)).await;
		assert_eq!(calls.load(Ordering::Relaxed), 3);
	}

	#[tokio::test(start_paused = true)]
	async fn actor_batched_scale_measurement() {
		let started = std::time::Instant::now();
		let calls = Arc::new(AtomicUsize::new(0));
		let mut leases = Vec::new();
		for _ in 0..3 {
			let registry = Registry::default();
			for actor in 0..1000 {
				for _ in 0..10 {
					let calls = calls.clone();
					leases.push(
						registry.register_test(format!("actor-{actor}/run"), None, move || {
							calls.fetch_add(1, Ordering::Relaxed);
							async { Ok(()) }
						}),
					);
				}
			}
		}
		tokio::time::sleep(Duration::from_millis(5200)).await;
		assert_eq!(calls.load(Ordering::Relaxed), 3000);
		let before = calls.load(Ordering::Relaxed);
		tokio::time::sleep(Duration::from_secs(50)).await;
		let lookups = calls.load(Ordering::Relaxed) - before;
		assert_eq!(lookups, 30000);
		assert!(leases.iter().all(|lease| !lease.cancelled.is_cancelled()));
		println!(
			"Q6 SIMULATION A=1000 T=10 R=3 lookups={lookups} logical_seconds=50 lookups_per_logical_second=600 wall_seconds={:.6}; no network or deployment latency qualification",
			started.elapsed().as_secs_f64()
		);
	}

	#[tokio::test(start_paused = true)]
	async fn failures_keep_reason_and_reconnect_gets_new_execution_lease() {
		for reason in [
			"actor-quarantined",
			"actor-uid-mismatch",
			"activation-mismatch",
			"actor-check-failed",
		] {
			let registry = Registry::default();
			let old = registry.register_test("actor/run".into(), None, move || async move {
				Err(ProxyError::SubstrateEgressConnectDenied(reason))
			});
			tokio::time::sleep(Duration::from_millis(5100)).await;
			assert!(old.cancelled.is_cancelled());
			assert_eq!(*old.reason.lock().unwrap(), reason);
			let new = registry.register_test("actor/run".into(), None, || async { Ok(()) });
			assert!(!new.cancelled.is_cancelled());
			assert!(!Arc::ptr_eq(&old, &new));
			let replacement = registry.register_test("actor/new-run".into(), None, || async { Ok(()) });
			assert!(!Arc::ptr_eq(&replacement, &new));
		}
	}
}

/// Hyper spawns HTTP/2 request futures independently of the connection future.
/// Bind those tasks to the same execution, including pending upstream requests.
#[derive(Clone, Default)]
pub(crate) struct Executor(pub(crate) Option<CancellationToken>);
impl<F> hyper::rt::Executor<F> for Executor
where
	F: Future + Send + 'static,
	F::Output: Send + 'static,
{
	fn execute(&self, future: F) {
		let cancelled = self.0.clone();
		tokio::spawn(async move {
			if let Some(cancelled) = cancelled {
				tokio::select! { biased; _ = cancelled.cancelled() => {}, _ = future => {} }
			} else {
				future.await;
			}
		});
	}
}

pub(crate) struct AbortOnDrop(pub(crate) tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}

pub(crate) struct TunnelMetrics(pub(crate) Arc<crate::telemetry::metrics::Metrics>);
impl TunnelMetrics {
	pub(crate) fn new(metrics: Arc<crate::telemetry::metrics::Metrics>) -> Self {
		metrics.substrate_revocation_tunnels_active.inc();
		Self(metrics)
	}
	pub(crate) fn closed(&self) {
		self.0.substrate_revocation_closed_tunnels.inc();
	}
}
impl Drop for TunnelMetrics {
	fn drop(&mut self) {
		self.0.substrate_revocation_tunnels_active.dec();
	}
}

#[cfg(test)]
mod executor_tests {
	use std::sync::atomic::{AtomicBool, Ordering};

	use hyper::rt::Executor as _;

	use super::*;
	struct Dropped(Arc<AtomicBool>);
	impl Drop for Dropped {
		fn drop(&mut self) {
			self.0.store(true, Ordering::SeqCst);
		}
	}
	#[tokio::test]
	async fn cancelling_connection_drops_spawned_pending_stream() {
		let cancelled = CancellationToken::new();
		let dropped = Arc::new(AtomicBool::new(false));
		let guard = Dropped(dropped.clone());
		Executor(Some(cancelled.clone())).execute(async move {
			let _guard = guard;
			std::future::pending::<()>().await;
		});
		tokio::task::yield_now().await;
		cancelled.cancel();
		tokio::task::yield_now().await;
		assert!(dropped.load(Ordering::SeqCst));
	}
}
