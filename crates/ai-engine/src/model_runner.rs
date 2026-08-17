//! Model runner — the layer that actually invokes an AI model.
//!
//! ## Separation from `AiAnalyzer`
//!
//! `AiAnalyzer` is the high-level trait the proxy calls. `ModelRunner`
//! is the lower-level trait that does the raw inference call. This two-
//! layer design means:
//!
//! - `StubAnalyzer` and `LocalSlmAnalyzer` both use `AiAnalyzer` as
//!   their interface, regardless of how they call the model underneath.
//! - Swapping from a local model to a cloud API only requires a new
//!   `ModelRunner` implementation — the prompt builder, response parser,
//!   and risk scorer are all reused unchanged.
//!
//! ## Current implementations
//!
//! `StubModelRunner` — always returns a safe/zero JSON response.
//!   Used in tests and when no model is configured.
//!
//! ## Future implementations (not yet built)
//!
//! `CandleModelRunner` — runs a quantized GGUF model (Phi-3 Mini,
//!   Mistral 7B, Llama 3.1 8B) locally via the `candle` crate.
//!   Will be added as an optional feature flag so the binary compiles
//!   without ML deps when not needed.
//!
//! `HttpModelRunner` — calls an OpenAI-compatible API endpoint
//!   (Ollama running locally, LM Studio, or a cloud LLM). No model
//!   weights needed on disk — just a URL and API key.

use crate::prompt_builder::BuiltPrompt;
use crate::response_parser::ResponseParser;
use crate::types::{AiAnalyzer, AnalysisRequest, AnalysisResult, PriorFinding, RecommendedAction};
use async_trait::async_trait;

// ─── ModelRunner trait ────────────────────────────────────────────────────────

/// Low-level inference interface. Receives a built prompt, returns raw
/// model output as a string (which the response parser then validates).
#[async_trait]
pub trait ModelRunner: Send + Sync {
    async fn run(&self, prompt: &BuiltPrompt) -> Result<String, String>;
    fn name(&self) -> &'static str;
    fn is_ready(&self) -> bool;
}

// ─── StubModelRunner ─────────────────────────────────────────────────────────

/// Returns a configurable canned response. Used in tests and as the
/// default when no real model is configured — lets the proxy run fully
/// without any AI infrastructure.
pub struct StubModelRunner {
    response: String,
}

impl StubModelRunner {
    /// Default stub: always returns "safe" with zero risk.
    pub fn new() -> Self {
        Self {
            response: serde_json::json!({
                "classification": "safe",
                "risk_score": 0,
                "confidence": 0,
                "detected_entities": [],
                "reason": "Stub model runner — no inference performed",
                "recommended_action": "allow"
            })
            .to_string(),
        }
    }

    /// Test helper: returns a specific canned JSON response.
    #[cfg(test)]
    pub fn with_response(response: impl Into<String>) -> Self {
        Self { response: response.into() }
    }
}

impl Default for StubModelRunner {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl ModelRunner for StubModelRunner {
    async fn run(&self, _prompt: &BuiltPrompt) -> Result<String, String> {
        Ok(self.response.clone())
    }
    fn name(&self) -> &'static str { "stub" }
    fn is_ready(&self) -> bool { true }
}

// ─── GenericAnalyzer ─────────────────────────────────────────────────────────

/// A complete `AiAnalyzer` implementation that wires together:
/// `PromptBuilder` → `ModelRunner` → `ResponseParser`.
///
/// Instantiate with any `ModelRunner` implementation:
/// ```ignore
/// let analyzer = GenericAnalyzer::new(StubModelRunner::new());
/// let analyzer = GenericAnalyzer::new(CandleModelRunner::load("phi3.gguf")?);
/// let analyzer = GenericAnalyzer::new(HttpModelRunner::new("http://localhost:11434"));
/// ```
pub struct GenericAnalyzer<R: ModelRunner> {
    runner: R,
}

impl<R: ModelRunner> GenericAnalyzer<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

#[async_trait]
impl<R: ModelRunner + Send + Sync> AiAnalyzer for GenericAnalyzer<R> {
    async fn analyze(&self, request: AnalysisRequest) -> AnalysisResult {
        if !self.runner.is_ready() {
            tracing::warn!(runner = %self.runner.name(), "model runner not ready, returning unavailable");
            return AnalysisResult::unavailable();
        }

        let prompt = crate::prompt_builder::PromptBuilder::build(&request);

        match self.runner.run(&prompt).await {
            Ok(raw) => {
                let result = ResponseParser::parse(&raw);
                tracing::debug!(
                    runner       = %self.runner.name(),
                    classification = %result.classification,
                    risk_score   = result.risk_score,
                    confidence   = result.confidence,
                    "SLM analysis complete"
                );
                result
            }
            Err(e) => {
                tracing::warn!(
                    runner = %self.runner.name(),
                    error  = %e,
                    "model runner error, returning unavailable"
                );
                AnalysisResult::unavailable()
            }
        }
    }

    fn name(&self) -> &'static str { self.runner.name() }

    fn is_available(&self) -> bool { self.runner.is_ready() }
}

// ─── StubAnalyzer convenience alias ──────────────────────────────────────────

/// Ready-to-use stub analyzer — drop-in for tests and default config.
pub type StubAnalyzer = GenericAnalyzer<StubModelRunner>;

impl StubAnalyzer {
    pub fn stub() -> Self {
        Self::new(StubModelRunner::new())
    }
}

// ─── Future runner stubs (documented, not implemented) ───────────────────────

/// Placeholder for local GGUF model runner via `candle`.
/// When implemented:
/// - `cargo add candle-core candle-transformers --optional`
/// - feature flag: `[features] local-slm = ["candle-core", ...]`
/// - Load model: `CandleModelRunner::load(path, device)`
/// - Inference: tokenize prompt, run forward pass, decode tokens
pub struct CandleModelRunner;
// Implementation tracked as a future milestone — see README Phase 5.

/// Placeholder for HTTP-based model runner (Ollama / LM Studio / cloud).
/// When implemented:
/// - `cargo add reqwest --optional`
/// - POST to OpenAI-compatible `/v1/chat/completions` endpoint
/// - Configurable: base_url, model_id, api_key, timeout_ms
pub struct HttpModelRunner;
// Implementation tracked as a future milestone — see README Phase 5.

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_analyzer_returns_safe_result() {
        let analyzer = StubAnalyzer::stub();
        let req = AnalysisRequest {
            extracted_text:  "normal text".into(),
            destination:     "example.com".into(),
            method:          None,
            prior_findings:  vec![],
            rule_based_risk: 0,
        };
        let result = analyzer.analyze(req).await;
        assert_eq!(result.classification, "safe");
        assert_eq!(result.risk_score, 0);
        assert_eq!(result.recommended_action, RecommendedAction::Allow);
    }

    #[tokio::test]
    async fn stub_analyzer_is_available() {
        let analyzer = StubAnalyzer::stub();
        assert!(analyzer.is_available());
        assert_eq!(analyzer.name(), "stub");
    }

    #[tokio::test]
    async fn generic_analyzer_parses_custom_stub_response() {
        let runner = StubModelRunner::with_response(r#"{
            "classification": "credential_leak",
            "risk_score": 90,
            "confidence": 85,
            "detected_entities": ["API_KEY"],
            "reason": "API key found",
            "recommended_action": "block"
        }"#);
        let analyzer = GenericAnalyzer::new(runner);

        let req = AnalysisRequest {
            extracted_text:  "sk-secret123".into(),
            destination:     "api.openai.com".into(),
            method:          Some("POST".into()),
            prior_findings:  vec![PriorFinding {
                detector:     "regex".into(),
                finding_type: "openai_api_key".into(),
                risk:         100,
                masked_match: "sk-sec...".into(),
            }],
            rule_based_risk: 100,
        };

        let result = analyzer.analyze(req).await;
        assert_eq!(result.classification, "credential_leak");
        assert_eq!(result.risk_score, 90);
        assert_eq!(result.recommended_action, RecommendedAction::Block);
        assert!(result.is_meaningful());
    }

    #[tokio::test]
    async fn generic_analyzer_returns_unavailable_on_bad_json() {
        let runner = StubModelRunner::with_response("this is not json at all");
        let analyzer = GenericAnalyzer::new(runner);

        let req = AnalysisRequest {
            extracted_text:  "text".into(),
            destination:     "example.com".into(),
            method:          None,
            prior_findings:  vec![],
            rule_based_risk: 0,
        };

        let result = analyzer.analyze(req).await;
        assert_eq!(result.classification, "unavailable");
        assert!(!result.is_meaningful());
    }

    #[tokio::test]
    async fn analyzer_name_matches_runner_name() {
        let analyzer = StubAnalyzer::stub();
        assert_eq!(analyzer.name(), "stub");
    }
}
