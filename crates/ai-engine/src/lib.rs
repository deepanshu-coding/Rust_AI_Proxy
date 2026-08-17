#![allow(unused_imports)]
//! AI Engine — SLM integration layer for CDP Proxy.
//!
//! ## Architecture
//!
//! ```text
//! Proxy (inspect_and_relay)
//!     │
//!     ▼
//! AiLayer::analyse_with_findings(text, findings)
//!     │
//!     ├── PromptBuilder::build(request)
//!     │       → BuiltPrompt { system, user, combined }
//!     │
//!     ├── AiAnalyzer::analyze(request)     ← trait, any impl
//!     │       → AnalysisResult { classification, risk_score, confidence, ... }
//!     │
//!     ├── ResponseParser::parse(raw_text)
//!     │       → validated AnalysisResult (never panics)
//!     │
//!     ├── RiskScorer::combine(rule_based, slm_result)
//!     │       → CombinedRisk { rule_based, slm_weighted, combined }
//!     │
//!     └── Returns (CombinedRisk, AnalysisResult) to proxy
//!             → proxy passes combined_risk.combined to PolicyEngine
//!             → PolicyEngine makes final Decision (ALLOW/REDACT/BLOCK)
//! ```
//!
//! ## Proxy never crashes due to SLM
//!
//! Every failure path (model unavailable, timeout, bad JSON) returns
//! AnalysisResult::unavailable() with risk_score=0. The policy engine
//! then makes its decision based solely on rule-based scores.

pub mod model_runner;
pub mod prompt_builder;
pub mod response_parser;
pub mod risk_scorer;
pub mod types;

pub use model_runner::{GenericAnalyzer, ModelRunner, StubAnalyzer, StubModelRunner};
pub use prompt_builder::PromptBuilder;
pub use response_parser::ResponseParser;
pub use risk_scorer::{CombinedRisk, RiskScorer};
pub use types::{AiAnalyzer, AnalysisRequest, AnalysisResult};
pub use types::{PriorFinding, RecommendedAction};

use std::sync::Arc;

/// High-level facade used by inspect_and_relay in the interceptor.
/// Holds an Arc<dyn AiAnalyzer> so any implementation can be injected.
pub struct AiLayer {
    analyzer:    Arc<dyn AiAnalyzer>,
    risk_scorer: RiskScorer,
}

impl AiLayer {
    pub fn new(analyzer: Arc<dyn AiAnalyzer>, slm_blend_factor: f64) -> Self {
        Self {
            analyzer,
            risk_scorer: RiskScorer::new(slm_blend_factor),
        }
    }

    /// Default: stub analyzer (zero inference), default blend factor 0.5.
    pub fn stub() -> Self {
        Self::new(Arc::new(StubAnalyzer::stub()), 0.5)
    }

    pub fn is_available(&self) -> bool { self.analyzer.is_available() }
    pub fn analyzer_name(&self) -> &'static str { self.analyzer.name() }

    /// Main entry point called by inspect_and_relay after rule-based detection.
    /// Never panics — returns (combined_risk, unavailable_result) on any failure.
    pub async fn analyse_with_findings(
        &self,
        text: &str,
        destination: &str,
        method: Option<&str>,
        findings: &[common::Finding],
        rule_based_risk: u32,
    ) -> (CombinedRisk, AnalysisResult) {
        let prior_findings: Vec<PriorFinding> = findings
            .iter()
            .map(PriorFinding::from_common)
            .collect();

        let request = AnalysisRequest {
            extracted_text:  text.to_string(),
            destination:     destination.to_string(),
            method:          method.map(String::from),
            prior_findings,
            rule_based_risk,
        };

        let slm_result = self.analyzer.analyze(request).await;

        tracing::info!(
            analyzer       = %self.analyzer_name(),
            classification = %slm_result.classification,
            slm_risk       = slm_result.risk_score,
            confidence     = slm_result.confidence,
            meaningful     = slm_result.is_meaningful(),
            "SLM analysis"
        );

        let combined = self.risk_scorer.combine(rule_based_risk, &slm_result);

        tracing::info!(summary = %combined.summary(), "risk combination");

        (combined, slm_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_layer_returns_rule_based_score_unchanged() {
        let layer    = AiLayer::stub();
        let findings = vec![common::Finding {
            detector:     "regex".into(),
            finding_type: "aws_access_key".into(),
            risk:         100,
            masked_match: "AKIA12...".into(),
        }];
        let (combined, slm) = layer
            .analyse_with_findings(
                "AKIAIOSFODNN7EXAMPLE",
                "s3.amazonaws.com",
                None,
                &findings,
                100,
            )
            .await;
        assert_eq!(combined.rule_based, 100);
        assert_eq!(combined.combined, 100);
        assert_eq!(slm.classification, "safe");
        assert!(!slm.is_meaningful());
    }

    #[tokio::test]
    async fn stub_layer_is_available() {
        let layer = AiLayer::stub();
        assert!(layer.is_available());
        assert_eq!(layer.analyzer_name(), "stub");
    }

    #[tokio::test]
    async fn custom_analyzer_raises_combined_score() {
        let runner = StubModelRunner::with_response(r#"{
            "classification": "credential_leak",
            "risk_score": 80,
            "confidence": 100,
            "detected_entities": ["SECRET"],
            "reason": "Obfuscated credential detected",
            "recommended_action": "block"
        }"#);
        let analyzer = Arc::new(GenericAnalyzer::new(runner));
        let layer    = AiLayer::new(analyzer, 0.5);

        let (combined, slm) = layer
            .analyse_with_findings("obfuscated text", "evil.com", Some("POST"), &[], 10)
            .await;

        assert!(combined.combined > 10);
        assert!(slm.is_meaningful());
        assert_eq!(slm.recommended_action, RecommendedAction::Block);
    }

    #[tokio::test]
    async fn slm_cannot_reduce_rule_based_score() {
        let runner = StubModelRunner::with_response(r#"{
            "classification": "safe",
            "risk_score": 0,
            "confidence": 99,
            "detected_entities": [],
            "reason": "looks fine",
            "recommended_action": "allow"
        }"#);
        let analyzer = Arc::new(GenericAnalyzer::new(runner));
        let layer    = AiLayer::new(analyzer, 1.0);

        let (combined, _) = layer
            .analyse_with_findings("AKIAIOSFODNN7EXAMPLE", "s3.amazonaws.com", None, &[], 100)
            .await;

        assert_eq!(combined.combined, 100, "SLM must not reduce rule-based score");
    }

    #[tokio::test]
    async fn layer_works_with_no_prior_findings() {
        let layer = AiLayer::stub();
        let (combined, _) = layer
            .analyse_with_findings("normal text", "example.com", Some("GET"), &[], 0)
            .await;
        assert_eq!(combined.combined, 0);
    }
}
