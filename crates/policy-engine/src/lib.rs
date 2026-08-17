//! Policy engine — turns an aggregated risk score into a Decision.
//!
//! Mirrors `app/engine/policy_engine.py` and `app/engine/risk_engine.py`
//! from the Python MVP, but thresholds will be loaded from `policies/*.toml`
//! (via the `config` crate) instead of being hardcoded — the spec requires
//! policy to live in configuration files, not Rust code.
//!
//! STATUS: skeleton with the same default thresholds as the Python MVP
//! (>=100 BLOCK, >=50 REDACT, else ALLOW), hardcoded for now. Config-file
//! loading lands when the `config` crate is built.

use common::{Decision, Finding};

pub struct PolicyThresholds {
    pub block_at: u32,
    pub redact_at: u32,
}

impl Default for PolicyThresholds {
    fn default() -> Self {
        Self {
            block_at: 100,
            redact_at: 50,
        }
    }
}

pub struct PolicyEngine {
    thresholds: PolicyThresholds,
}

impl PolicyEngine {
    pub fn new(thresholds: PolicyThresholds) -> Self {
        Self { thresholds }
    }

    /// Sum every finding's risk, then map the total to a Decision.
    pub fn evaluate(&self, findings: &[Finding]) -> (u32, Decision) {
        let total_risk: u32 = findings.iter().map(|f| f.risk).sum();
        self.evaluate_score(total_risk)
    }
    /// Evaluate a pre-computed risk score (e.g. after SLM combination)
    /// directly, bypassing the per-finding aggregation. Used when the
    /// AI layer has already combined rule-based + SLM scores.
    pub fn evaluate_score(&self, risk_score: u32) -> (u32, Decision) {
        let decision = if risk_score >= self.thresholds.block_at {
            Decision::Block
        } else if risk_score >= self.thresholds.redact_at {
            Decision::Redact
        } else {
            Decision::Allow
        };
        (risk_score, decision)
    }

}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyThresholds::default())
    }
}

impl PolicyEngine {
    /// Build from a `LoadedPolicy` produced by the `config` crate — this
    /// is how the policy engine gets its thresholds from `policies/*.toml`
    /// instead of compiled-in defaults.
    pub fn from_config(policy: &config::LoadedPolicy) -> Self {
        Self::new(PolicyThresholds {
            block_at:  policy.block_at,
            redact_at: policy.redact_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(risk: u32) -> Finding {
        Finding {
            detector: "test".into(),
            finding_type: "test_type".into(),
            risk,
            masked_match: "xxx".into(),
        }
    }

    #[test]
    fn no_findings_means_allow() {
        let engine = PolicyEngine::default();
        let (risk, decision) = engine.evaluate(&[]);
        assert_eq!(risk, 0);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn risk_100_blocks() {
        let engine = PolicyEngine::default();
        let (risk, decision) = engine.evaluate(&[finding(100)]);
        assert_eq!(risk, 100);
        assert_eq!(decision, Decision::Block);
    }

    #[test]
    fn risk_50_redacts() {
        let engine = PolicyEngine::default();
        let (_, decision) = engine.evaluate(&[finding(50)]);
        assert_eq!(decision, Decision::Redact);
    }

    #[test]
    fn risk_49_allows() {
        let engine = PolicyEngine::default();
        let (_, decision) = engine.evaluate(&[finding(49)]);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn multiple_findings_aggregate() {
        let engine = PolicyEngine::default();
        let (risk, decision) = engine.evaluate(&[finding(30), finding(30)]);
        assert_eq!(risk, 60);
        assert_eq!(decision, Decision::Redact);
    }

    #[test]
    fn custom_thresholds_respected() {
        let engine = PolicyEngine::new(PolicyThresholds {
            block_at: 200,
            redact_at: 80,
        });
        let (_, decision) = engine.evaluate(&[finding(100)]);
        assert_eq!(decision, Decision::Redact);
    }
}
