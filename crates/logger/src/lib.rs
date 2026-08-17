//! Structured audit logging.
//!
//! Every inspected request produces one JSON audit event written to stdout.
//! Fields match what the PDF architecture specifies:
//! timestamp, request_id, destination, policy decision, detector results,
//! risk score, latency.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use logger::{AuditEvent, AuditLogger};
//! let event = AuditEvent::new("example.com")
//!     .decision("BLOCK")
//!     .risk_score(100)
//!     .detectors(vec!["regex".into()])
//!     .latency_ms(3);
//! AuditLogger::log(&event);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

static RECENT_EVENTS: OnceLock<Mutex<VecDeque<AuditEvent>>> = OnceLock::new();

fn event_store() -> &'static Mutex<VecDeque<AuditEvent>> {
    RECENT_EVENTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(500)))
}

pub fn recent_events() -> Vec<AuditEvent> {
    event_store()
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .rev()
        .collect()
}

// ─── Init ─────────────────────────────────────────────────────────────────────

/// Initialise global structured JSON logging. Call exactly once at startup.
/// Subsequent calls are silently ignored (OnceLock guarantees this).
pub fn init_logging() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();
    });
}

// ─── Audit event ──────────────────────────────────────────────────────────────

/// One structured audit record per inspected request.
/// Serialises to a single-line JSON object — pipe to `jq` for pretty-print.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ISO-8601 UTC timestamp of when the request was inspected.
    pub timestamp: String,
    /// UUID v4 — unique per connection.
    pub request_id: String,
    /// Target hostname extracted from the CONNECT line (e.g. "api.openai.com").
    pub destination: String,
    /// ALLOW / REDACT / BLOCK / WARN
    pub decision: String,
    /// Aggregated risk score from all detectors.
    pub risk_score: u32,
    /// Names of detectors that produced at least one finding.
    pub detectors_triggered: Vec<String>,
    /// Number of individual findings (secrets / keywords) found.
    pub finding_count: usize,
    /// Wall-clock milliseconds from connection accept to decision.
    pub latency_ms: u64,
    /// Optional: HTTP method if visible (populated for plain HTTP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Optional: top-level path / URL fragment if visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl AuditEvent {
    /// Minimal constructor — use builder methods to fill additional fields.
    pub fn new(destination: impl Into<String>) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: uuid::Uuid::new_v4().to_string(),
            destination: destination.into(),
            decision: "ALLOW".into(),
            risk_score: 0,
            detectors_triggered: Vec::new(),
            finding_count: 0,
            latency_ms: 0,
            method: None,
            path: None,
        }
    }

    pub fn decision(mut self, d: impl Into<String>) -> Self {
        self.decision = d.into(); self
    }
    pub fn risk_score(mut self, s: u32) -> Self {
        self.risk_score = s; self
    }
    pub fn detectors(mut self, d: Vec<String>) -> Self {
        self.detectors_triggered = d; self
    }
    pub fn finding_count(mut self, n: usize) -> Self {
        self.finding_count = n; self
    }
    pub fn latency_ms(mut self, ms: u64) -> Self {
        self.latency_ms = ms; self
    }
    pub fn method(mut self, m: impl Into<String>) -> Self {
        self.method = Some(m.into()); self
    }
    pub fn path(mut self, p: impl Into<String>) -> Self {
        self.path = Some(p.into()); self
    }
}

// ─── Logger ───────────────────────────────────────────────────────────────────

pub struct AuditLogger;

impl AuditLogger {
    /// Emit one audit event as a JSON line to stdout via `tracing`.
    /// The `tracing` subscriber (initialised by `init_logging`) formats
    /// the event; on production we pipe this to a log aggregator
    /// (Splunk, ELK, Datadog) which parses the JSON natively.
    pub fn log(event: &AuditEvent) {
    {
        let mut store = event_store().lock().unwrap();

        store.push_back(event.clone());

        if store.len() > 500 {
            store.pop_front();
        }
    }

    let json = serde_json::to_string(event)
        .unwrap_or_else(|_| r#"{"error":"audit serialise failed"}"#.into());

    tracing::info!(audit_event = %json, "audit");
}

    /// Convenience: emit directly from components.
    pub fn emit(
        destination: &str,
        decision: &str,
        risk_score: u32,
        detectors: Vec<String>,
        finding_count: usize,
        latency_ms: u64,
    ) {
        let event = AuditEvent::new(destination)
            .decision(decision)
            .risk_score(risk_score)
            .detectors(detectors)
            .finding_count(finding_count)
            .latency_ms(latency_ms);
        Self::log(&event);
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serialises_required_fields() {
        let event = AuditEvent::new("api.openai.com")
            .decision("BLOCK")
            .risk_score(100)
            .detectors(vec!["regex".into()])
            .finding_count(1)
            .latency_ms(5);

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"destination\":\"api.openai.com\""));
        assert!(json.contains("\"decision\":\"BLOCK\""));
        assert!(json.contains("\"risk_score\":100"));
        assert!(json.contains("\"regex\""));
        assert!(json.contains("\"latency_ms\":5"));
    }

    #[test]
    fn optional_fields_omitted_when_absent() {
        let event = AuditEvent::new("example.com");
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("\"method\""));
        assert!(!json.contains("\"path\""));
    }

    #[test]
    fn optional_fields_present_when_set() {
        let event = AuditEvent::new("example.com")
            .method("GET")
            .path("/api/v1/query");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"method\":\"GET\""));
        assert!(json.contains("/api/v1/query"));
    }

    #[test]
    fn audit_event_has_uuid_request_id() {
        let event = AuditEvent::new("example.com");
        // UUIDs are 36 characters: 8-4-4-4-12
        assert_eq!(event.request_id.len(), 36);
        assert_eq!(event.request_id.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn audit_event_has_iso8601_timestamp() {
        let event = AuditEvent::new("example.com");
        // Basic structural check — contains T separator and +/Z timezone marker
        assert!(event.timestamp.contains('T'));
        assert!(event.timestamp.contains('+') || event.timestamp.ends_with('Z'));
    }

    #[test]
    fn two_events_have_different_request_ids() {
        let a = AuditEvent::new("a.com");
        let b = AuditEvent::new("b.com");
        assert_ne!(a.request_id, b.request_id);
    }

    #[test]
    fn audit_logger_emit_does_not_panic() {
        // Just confirms the emit path doesn't panic without a subscriber.
        AuditLogger::emit("test.com", "ALLOW", 0, vec![], 0, 1);
    }
}
