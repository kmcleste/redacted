/*!
Observability helpers — thin wrappers over the `metrics` crate (D17, §12).

The `metrics` crate is a facade: no concrete backend is needed here.
engine-grpc installs the Prometheus recorder; callers in other environments
install their own or leave it as a no-op.

All labels use static strings to avoid per-call allocation on the hot path.

Online metrics recorded:
  engine_detect_duration_us      histogram   detection latency
  engine_mask_duration_us        histogram   full mask (detect + replace) latency
  engine_rehydrate_duration_us   histogram   batch rehydration latency
  engine_entities_detected_total counter     per entity type
  engine_vault_ops_total         counter     per operation (store/get/delete/purge)
  engine_rehydrate_mismatches_total counter  placeholder in response, absent from vault
  engine_fail_open_total         counter     detectors failing silently under load
  engine_canary_pii_found_total  counter     egress canary false-negative hits per type
*/

use std::time::Instant;

// ---------------------------------------------------------------------------
// Timing guard
// ---------------------------------------------------------------------------

/// RAII timer: records elapsed time to a histogram on drop.
pub struct Timer {
    start: Instant,
    histogram: &'static str,
}

impl Timer {
    pub fn new(histogram: &'static str) -> Self {
        Self {
            start: Instant::now(),
            histogram,
        }
    }

    pub fn elapsed_us(&self) -> f64 {
        self.start.elapsed().as_micros() as f64
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        metrics::histogram!(self.histogram).record(self.elapsed_us());
    }
}

// ---------------------------------------------------------------------------
// Recording helpers
// ---------------------------------------------------------------------------

/// Record that `count` entities of `entity_type` were detected.
#[inline]
pub fn record_entities_detected(entity_type: &'static str, count: u64) {
    if count > 0 {
        metrics::counter!("engine_entities_detected_total", "entity_type" => entity_type)
            .increment(count);
    }
}

/// Record a vault operation.
#[inline]
pub fn record_vault_op(operation: &'static str) {
    metrics::counter!("engine_vault_ops_total", "operation" => operation).increment(1);
}

/// Record rehydration mismatches (placeholder in response absent from vault).
#[inline]
pub fn record_rehydrate_mismatches(count: u64) {
    if count > 0 {
        metrics::counter!("engine_rehydrate_mismatches_total").increment(count);
    }
}

/// Record a fail-open event (detector silently dropped under load).
#[inline]
pub fn record_fail_open() {
    metrics::counter!("engine_fail_open_total").increment(1);
}

/// Record an egress-canary hit (residual PII found in the masked payload).
#[inline]
pub fn record_canary_hit(entity_type: &'static str) {
    metrics::counter!("engine_canary_pii_found_total", "entity_type" => entity_type).increment(1);
}

/// Start a detect-latency timer.
pub fn detect_timer() -> Timer {
    Timer::new("engine_detect_duration_us")
}
/// Start a mask-latency timer.
pub fn mask_timer() -> Timer {
    Timer::new("engine_mask_duration_us")
}
/// Start a rehydrate-latency timer.
pub fn rehydrate_timer() -> Timer {
    Timer::new("engine_rehydrate_duration_us")
}
