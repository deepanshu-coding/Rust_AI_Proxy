//! Combined risk scoring — merges rule-based detector scores with the
//! SLM's advisory risk estimate into a single score for the Policy Engine.
//!
//! ## Design principle
//!
//! The SLM never has final say. This module produces a `CombinedRisk`
//! that the Policy Engine reads alongside the raw findings — the engine
//! still calls `.evaluate(&findings)` with full control. The combined
//! score is an *input* to that evaluation, not a bypass of it.
//!
//! ## Combination strategy
//!
//! We use a **weighted ceiling** approach:
//!
//! - Rule-based score is authoritative for known patterns (AWS key = 100,
//!   always blocks regardless of what the SLM says).
//! - SLM score is weighted by its confidence: a 90% confident SLM saying
//!   risk=80 contributes more than a 10% confident SLM saying risk=80.
//! - The combined score is max(rule_based, weighted_slm) — we never
//!   *reduce* the rule-based score because the SLM said "safe". A regex
//!   match on an AWS key is not overridable by model output.
//! - If SLM is unavailable (confidence=0), combined == rule_based exactly.

use crate::types::AnalysisResult;

/// Output of combining rule-based and SLM risk estimates.
#[derive(Debug, Clone)]
pub struct CombinedRisk {
    /// Rule-based score (from regex + keyword detectors). Immutable —
    /// the SLM cannot lower this.
    pub rule_based:  u32,

    /// SLM's weighted risk contribution (risk_score × confidence / 100).
    pub slm_weighted: u32,

    /// Final combined score passed to the Policy Engine.
    /// = max(rule_based, rule_based + slm_weighted * blend_factor)
    pub combined:    u32,

    /// Whether the SLM was actually available and contributed.
    pub slm_active:  bool,
}

pub struct RiskScorer {
    /// How much the SLM can raise the score above the rule-based baseline.
    /// Default 0.5 → SLM can add at most 50% of its weighted score on top.
    /// Range 0.0–1.0. Configurable so orgs can tune SLM influence.
    slm_blend_factor: f64,
}

impl Default for RiskScorer {
    fn default() -> Self {
        Self { slm_blend_factor: 0.5 }
    }
}

impl RiskScorer {
    pub fn new(slm_blend_factor: f64) -> Self {
        let factor = slm_blend_factor.clamp(0.0, 1.0);
        Self { slm_blend_factor: factor }
    }

    /// Combine rule-based score with SLM result into a `CombinedRisk`.
    pub fn combine(&self, rule_based: u32, slm: &AnalysisResult) -> CombinedRisk {
        let slm_active = slm.is_meaningful();

        let slm_weighted = if slm_active {
            // Weight the SLM's risk score by its confidence.
            // confidence=100 → full SLM risk score
            // confidence=50  → half SLM risk score
            // confidence=0   → zero contribution
            let weighted = (slm.risk_score as f64) * (slm.confidence as f64) / 100.0;
            weighted.round() as u32
        } else {
            0
        };

        // SLM can only ADD to the rule-based score, never reduce it.
        // The blend factor controls how much SLM can add.
        let slm_contribution = ((slm_weighted as f64) * self.slm_blend_factor).round() as u32;
        let combined = rule_based.saturating_add(slm_contribution).min(200);
        // Cap at 200 so aggregated scores don't overflow policy thresholds
        // in unexpected ways — the policy engine's block_at is typically 100.

        CombinedRisk {
            rule_based,
            slm_weighted,
            combined,
            slm_active,
        }
    }
}

impl CombinedRisk {
    /// Human-readable summary for audit logs.
    pub fn summary(&self) -> String {
        if self.slm_active {
            format!(
                "combined={} (rule={} + slm_weighted={})",
                self.combined, self.rule_based, self.slm_weighted
            )
        } else {
            format!(
                "combined={} (rule={}, slm unavailable)",
                self.combined, self.rule_based
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RecommendedAction;

    fn slm_result(risk: u8, confidence: u8) -> AnalysisResult {
        AnalysisResult {
            classification:    "credential_leak".into(),
            risk_score:        risk,
            confidence,
            detected_entities: vec![],
            reason:            "test".into(),
            recommended_action: RecommendedAction::Block,
        }
    }

    #[test]
    fn slm_unavailable_combined_equals_rule_based() {
        let scorer = RiskScorer::default();
        let slm    = AnalysisResult::unavailable();
        let result = scorer.combine(80, &slm);
        assert_eq!(result.combined, 80);
        assert_eq!(result.rule_based, 80);
        assert!(!result.slm_active);
    }

    #[test]
    fn slm_adds_to_rule_based_never_reduces() {
        let scorer = RiskScorer::default();
        // Rule says 80, SLM says risk=0 with high confidence
        let low_risk_slm = slm_result(0, 100);
        let result = scorer.combine(80, &low_risk_slm);
        // SLM saying risk=0 should NOT lower the rule-based 80
        assert_eq!(result.combined, 80, "SLM must not reduce rule-based score");
    }

    #[test]
    fn high_confidence_slm_raises_combined_score() {
        let scorer = RiskScorer::default();
        // Rule=50, SLM=risk 80 confidence 100 → weighted=80, blend=0.5 → +40
        let result = scorer.combine(50, &slm_result(80, 100));
        assert!(result.combined > 50, "high confidence SLM should raise score");
        assert_eq!(result.slm_weighted, 80);
    }

    #[test]
    fn low_confidence_slm_contributes_little() {
        let scorer = RiskScorer::default();
        // SLM=risk 100 confidence 10 → weighted=10, blend=0.5 → +5
        let result = scorer.combine(50, &slm_result(100, 10));
        assert!(result.combined <= 60, "low confidence SLM should contribute little: {}", result.combined);
    }

    #[test]
    fn combined_score_never_exceeds_200() {
        let scorer = RiskScorer::new(1.0); // max blend
        let result = scorer.combine(200, &slm_result(100, 100));
        assert!(result.combined <= 200);
    }

    #[test]
    fn zero_blend_factor_slm_has_no_effect() {
        let scorer = RiskScorer::new(0.0);
        let result = scorer.combine(50, &slm_result(100, 100));
        assert_eq!(result.combined, 50, "zero blend → SLM has no effect");
    }

    #[test]
    fn full_blend_factor_slm_fully_contributes() {
        let scorer = RiskScorer::new(1.0);
        // rule=30, SLM=risk 60 confidence 100 → weighted=60, +60 = 90
        let result = scorer.combine(30, &slm_result(60, 100));
        assert_eq!(result.combined, 90);
    }

    #[test]
    fn summary_mentions_slm_unavailable_when_inactive() {
        let scorer = RiskScorer::default();
        let result = scorer.combine(50, &AnalysisResult::unavailable());
        assert!(result.summary().contains("unavailable"), "{}", result.summary());
    }

    #[test]
    fn summary_shows_all_three_scores_when_slm_active() {
        let scorer = RiskScorer::default();
        let result = scorer.combine(50, &slm_result(80, 100));
        let s = result.summary();
        assert!(s.contains("combined="), "{s}");
        assert!(s.contains("rule="),     "{s}");
        assert!(s.contains("slm_weighted="), "{s}");
    }
}
