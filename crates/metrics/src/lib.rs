//! In-memory metrics counters.
//!
//! Mirrors `app/services/metrics_service.py`. Tracks total/allowed/
//! blocked/redacted requests, plus per-content-type and per-detector
//! breakdowns, ready for a future dashboard to poll.
//!
//! STATUS: skeleton with the same counters as the Python MVP. Will need
//! to become thread-safe (atomics or a mutex) once the interceptor crate
//! starts calling it from multiple concurrent connection handlers.

use common::Decision;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct MetricsCounters {
    pub total_requests: AtomicU64,
    pub allowed_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    pub redacted_requests: AtomicU64,
    pub warned_requests: AtomicU64,
}

impl MetricsCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, decision: Decision) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        match decision {
            Decision::Allow => self.allowed_requests.fetch_add(1, Ordering::Relaxed),
            Decision::Block => self.blocked_requests.fetch_add(1, Ordering::Relaxed),
            Decision::Redact => self.redacted_requests.fetch_add(1, Ordering::Relaxed),
            Decision::Warn => self.warned_requests.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            allowed_requests: self.allowed_requests.load(Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
            redacted_requests: self.redacted_requests.load(Ordering::Relaxed),
            warned_requests: self.warned_requests.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub blocked_requests: u64,
    pub redacted_requests: u64,
    pub warned_requests: u64,
}
use std::sync::{Arc, OnceLock};

static GLOBAL_METRICS: OnceLock<Arc<MetricsCounters>> = OnceLock::new();

pub fn global() -> Arc<MetricsCounters> {
    GLOBAL_METRICS
        .get_or_init(|| Arc::new(MetricsCounters::new()))
        .clone()
}

pub fn record_global(decision: Decision) {
    global().record(decision);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_zero() {
        let m = MetricsCounters::new();
        let s = m.snapshot();
        assert_eq!(s.total_requests, 0);
    }

    #[test]
    fn records_block_correctly() {
        let m = MetricsCounters::new();
        m.record(Decision::Block);
        let s = m.snapshot();
        assert_eq!(s.total_requests, 1);
        assert_eq!(s.blocked_requests, 1);
        assert_eq!(s.allowed_requests, 0);
    }

    #[test]
    fn accumulates_across_multiple_records() {
        let m = MetricsCounters::new();
        m.record(Decision::Allow);
        m.record(Decision::Allow);
        m.record(Decision::Block);
        let s = m.snapshot();
        assert_eq!(s.total_requests, 3);
        assert_eq!(s.allowed_requests, 2);
        assert_eq!(s.blocked_requests, 1);
    }
}
