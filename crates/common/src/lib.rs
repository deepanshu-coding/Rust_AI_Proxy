//! Shared types used across every crate in the workspace.
//!
//! This mirrors `app/models/schemas.py` from the original Python proxy —
//! same concepts (Decision, Finding, ContentType), now as Rust types with
//! compile-time guarantees instead of runtime Pydantic validation.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Final enforcement decision made by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Redact,
    Block,
    /// Non-blocking decision: content passes through, but an alert is raised.
    /// (New in the Rust version — the Python MVP only had Allow/Redact/Block.)
    Warn,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Decision::Allow => "ALLOW",
            Decision::Redact => "REDACT",
            Decision::Block => "BLOCK",
            Decision::Warn => "WARN",
        };
        write!(f, "{s}")
    }
}

/// What kind of content this request body represents, after extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Text,
    Code,
    Document,
    Image,
    Json,
    Xml,
    Html,
    Zip,
}

/// A single thing a detector found (a secret, a keyword hit, etc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which detector produced this (e.g. "regex", "keyword").
    pub detector: String,
    /// Specific type within that detector (e.g. "aws_access_key").
    pub finding_type: String,
    /// Risk contribution of this single finding.
    pub risk: u32,
    /// Masked/partial match — never the full secret, for safe logging.
    pub masked_match: String,
}

/// Aggregated result of running all detectors on a piece of content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub request_id: String,
    pub decision: Decision,
    pub risk_score: u32,
    pub findings: Vec<Finding>,
}

/// Errors that can occur anywhere in the pipeline.
/// Every crate's fallible functions should return `Result<T, CdpError>`
/// (or a crate-local error that converts into this one) — no `unwrap()`
/// in request-handling paths, ever. A panic here takes down the proxy,
/// which means the user's entire internet connection drops.
#[derive(Debug, thiserror::Error)]
pub enum CdpError {
    #[error("extraction failed: {0}")]
    Extraction(String),

    #[error("detection failed: {0}")]
    Detection(String),

    #[error("policy evaluation failed: {0}")]
    Policy(String),

    #[error("interception/TLS error: {0}")]
    Interception(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type CdpResult<T> = Result<T, CdpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_displays_uppercase() {
        assert_eq!(Decision::Block.to_string(), "BLOCK");
        assert_eq!(Decision::Allow.to_string(), "ALLOW");
        assert_eq!(Decision::Redact.to_string(), "REDACT");
        assert_eq!(Decision::Warn.to_string(), "WARN");
    }

    #[test]
    fn decision_serializes_uppercase_json() {
        let json = serde_json::to_string(&Decision::Block).unwrap();
        assert_eq!(json, "\"BLOCK\"");
    }

    #[test]
    fn finding_serializes_round_trip() {
        let f = Finding {
            detector: "regex".into(),
            finding_type: "aws_access_key".into(),
            risk: 100,
            masked_match: "AKIA12...".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.risk, 100);
        assert_eq!(back.detector, "regex");
    }
}
