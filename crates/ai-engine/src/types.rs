//! Core types and trait for the AI analysis layer.
//!
//! ## Design principle
//!
//! `AiAnalyzer` is the single seam between "business logic that uses AI"
//! and "whatever model is actually running". Swap the implementation
//! (stub → local SLM → cloud LLM) by changing one line in the wiring
//! code — zero changes to the proxy, policy engine, or detectors.
//!
//! SLM is an *advisor*, never a *decision-maker*. `AnalysisResult`
//! contains a `recommended_action` field, but the Policy Engine is the
//! only component allowed to call `.evaluate()` and produce a final
//! `Decision`. The SLM result is fed in as one more input alongside
//! regex findings and keyword findings.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ─── Input ────────────────────────────────────────────────────────────────────

/// Everything the SLM needs to produce a useful analysis. Constructed by
/// the proxy for each inspected request and passed to `AiAnalyzer::analyze`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    /// Plain text extracted from the request body (post-extractor pipeline).
    pub extracted_text: String,

    /// Destination host (e.g. "api.openai.com") — gives the SLM context
    /// about where the data is going, which matters for DLP policy.
    pub destination: String,

    /// HTTP method if known ("GET", "POST", etc.).
    pub method: Option<String>,

    /// Findings already produced by the regex + keyword detectors.
    /// The SLM can use these to avoid re-doing obvious detection and
    /// instead focus on context, obfuscation, and business-logic leakage
    /// that rules-based detectors miss.
    pub prior_findings: Vec<PriorFinding>,

    /// Total risk score from rule-based detectors alone (before SLM).
    /// Lets the SLM calibrate — if rules already scored 100, focus on
    /// explaining why rather than re-detecting.
    pub rule_based_risk: u32,
}

/// A single finding from the regex or keyword detector, included in the
/// request so the SLM has full context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorFinding {
    pub detector: String,
    pub finding_type: String,
    pub risk: u32,
    pub masked_match: String,
}

impl PriorFinding {
    pub fn from_common(f: &common::Finding) -> Self {
        Self {
            detector: f.detector.clone(),
            finding_type: f.finding_type.clone(),
            risk: f.risk,
            masked_match: f.masked_match.clone(),
        }
    }
}

// ─── Output ───────────────────────────────────────────────────────────────────

/// Structured response from the SLM. This is advisory only — the Policy
/// Engine reads it alongside rule-based findings but is the sole authority
/// on the final `Decision`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Human-readable category: "credential_leak", "pii_exposure",
    /// "source_code_exfiltration", "safe", "unknown", etc.
    pub classification: String,

    /// SLM's own risk estimate, 0–100. Combined with rule-based score
    /// by the risk scorer, not used directly.
    pub risk_score: u8,

    /// How confident the SLM is in its analysis, 0–100.
    /// Low confidence → policy engine may discount the SLM's risk_score.
    pub confidence: u8,

    /// Entities the SLM identified: ["AWS_KEY", "PII:EMAIL", "SECRET"].
    pub detected_entities: Vec<String>,

    /// Human-readable explanation for why this classification was given.
    /// Shown in audit logs and (future) dashboard alerts.
    pub reason: String,

    /// The SLM's non-binding suggestion. Policy Engine decides whether
    /// to follow it, override it, or combine it with rule-based findings.
    pub recommended_action: RecommendedAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecommendedAction {
    Allow,
    Redact,
    Block,
    Warn,
}

impl std::fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow  => write!(f, "allow"),
            Self::Redact => write!(f, "redact"),
            Self::Block  => write!(f, "block"),
            Self::Warn   => write!(f, "warn"),
        }
    }
}

impl AnalysisResult {
    /// Safe default used when the SLM is unavailable or times out.
    /// Returns zero risk and "allow" so the proxy falls back to
    /// rule-based detection only — never crashes, never over-blocks.
    pub fn unavailable() -> Self {
        Self {
            classification:    "unavailable".into(),
            risk_score:        0,
            confidence:        0,
            detected_entities: Vec::new(),
            reason:            "SLM unavailable — rule-based detection only".into(),
            recommended_action: RecommendedAction::Allow,
        }
    }

    /// True when the SLM produced a meaningful result (not a fallback).
    pub fn is_meaningful(&self) -> bool {
        self.classification != "unavailable" && self.confidence > 0
    }
}

// ─── Trait ───────────────────────────────────────────────────────────────────

/// The single interface between the proxy and any AI model.
///
/// Implement this trait to plug in:
/// - `StubAnalyzer`      — always returns safe/zero (current)
/// - `LocalSlmAnalyzer`  — Phi-3 / Mistral / Llama via Candle (next)
/// - `CloudLlmAnalyzer`  — OpenAI / Anthropic API (future)
///
/// The proxy holds an `Arc<dyn AiAnalyzer>` — swap the implementation
/// at startup without touching any other code.
#[async_trait]
pub trait AiAnalyzer: Send + Sync {
    /// Analyse a request and return structured intelligence.
    /// Must NEVER panic — return `AnalysisResult::unavailable()` on any
    /// internal failure so the proxy can continue with rule-based detection.
    async fn analyze(&self, request: AnalysisRequest) -> AnalysisResult;

    /// Human-readable name of this analyser implementation, used in logs.
    fn name(&self) -> &'static str;

    /// Whether this analyser is currently healthy / available.
    /// Called at startup and periodically — lets the proxy log a clear
    /// warning if the SLM failed to load instead of silently degrading.
    fn is_available(&self) -> bool;
}
