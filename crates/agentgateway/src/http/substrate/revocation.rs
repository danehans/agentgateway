//! Continuing authorization belongs to a gateway replica, never to the worker.
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::proxy::ProxyError;

const INTERVAL: Duration = Duration::from_secs(5);
const RPC_DEADLINE: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(crate) struct Lease {
	pub(crate) cancelled: CancellationToken,
	pub(crate) reason: Mutex<&'static str>,
	metrics: Option<Arc<crate::telemetry::metrics::Metrics>>,
}
impl Drop for Lease {
	fn drop(&mut self) {
		self.cancelled.cancel();
		if let Some(metrics) = &self.metrics {
			metrics.substrate_revocation_actors_active.dec();
		}
	}
}

#[derive(Clone, Debug)]
pub(crate) struct Registry {
	actors: Arc<Mutex<HashMap<String, Weak<Lease>>>>,
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
	pub(crate) fn register<F, Fut>(
		&self,
		key: String,
		metrics: Option<Arc<crate::telemetry::metrics::Metrics>>,
		check: F,
	) -> Arc<Lease>
	where
		F: Fn() -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<(), ProxyError>> + Send + 'static,
	{
		let mut actors = self.actors.lock().expect("revocation registry poisoned");
		if let Some(lease) = actors.get(&key).and_then(Weak::upgrade)
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
		});
		let weak = Arc::downgrade(&lease);
		actors.insert(key.clone(), weak.clone());
		let actors = self.actors.clone();
		let permits = self.permits.clone();
		let cancelled = lease.cancelled.clone();
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
				if !matches!(result, Ok(Ok(()))) || Instant::now() >= deadline {
					if let Some(metrics) = &metrics {
						metrics.substrate_revocation_failed_checks.inc();
						if Instant::now() >= deadline {
							metrics.substrate_revocation_overdue_checks.inc();
						}
					}
					if let Some(lease) = weak.upgrade() {
						*lease.reason.lock().expect("reason poisoned") = match result {
							Ok(Err(ProxyError::SubstrateEgressConnectDenied(reason))) => reason,
							_ => "actor-check-failed",
						};
					}
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
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::atomic::{AtomicUsize, Ordering};

	#[tokio::test(start_paused = true)]
	async fn tunnels_share_one_check_and_last_drop_stops_polling() {
		let registry = Registry::default();
		let calls = Arc::new(AtomicUsize::new(0));
		let count = calls.clone();
		let a = registry.register("actor/run".into(), None, move || {
			count.fetch_add(1, Ordering::Relaxed);
			async { Ok(()) }
		});
		let b = registry.register("actor/run".into(), None, || async {
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
			let lease = registry.register("actor/run".into(), None, move || {
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
		let lease = registry.register("actor/run".into(), None, || async {
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
			leases.push(registry.register("actor/run".into(), None, move || {
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
						registry.register(format!("actor-{actor}/run"), None, move || {
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
			let old = registry.register("actor/run".into(), None, move || async move {
				Err(ProxyError::SubstrateEgressConnectDenied(reason))
			});
			tokio::time::sleep(Duration::from_millis(5100)).await;
			assert!(old.cancelled.is_cancelled());
			assert_eq!(*old.reason.lock().unwrap(), reason);
			let new = registry.register("actor/run".into(), None, || async { Ok(()) });
			assert!(!new.cancelled.is_cancelled());
			assert!(!Arc::ptr_eq(&old, &new));
			let replacement = registry.register("actor/new-run".into(), None, || async { Ok(()) });
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
	use super::*;
	use hyper::rt::Executor as _;
	use std::sync::atomic::{AtomicBool, Ordering};
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
