//! Prompt construction for the AI analysis layer.
//!
//! ## Why a separate module
//!
//! The prompt is the most volatile part of SLM integration — it changes
//! when you switch models (Phi-3 vs Mistral vs GPT-4 have different
//! optimal prompt formats), when you tune for accuracy, or when you add
//! new detection categories. Keeping it isolated here means:
//!
//! - Model runner and response parser never need to change for prompt tweaks
//! - Prompts can be unit-tested without running inference
//! - Future: load prompt templates from config files instead of hardcode
//!
//! ## Format
//!
//! We use a structured system + user message format compatible with all
//! major chat-format models (ChatML, Llama-3 instruct, Phi-3, Mistral).
//! The prompt explicitly instructs the model to return JSON only — no
//! prose preamble — so the response parser has a clean input.

use crate::types::{AnalysisRequest, PriorFinding};

/// A ready-to-send prompt pair for chat-format models.
#[derive(Debug, Clone)]
pub struct BuiltPrompt {
    /// System message — defines the model's role and output contract.
    pub system: String,
    /// User message — the actual request to analyse.
    pub user: String,
    /// Full prompt as a single string for models that don't support
    /// separate system/user roles (e.g. completion-only APIs).
    pub combined: String,
}

pub struct PromptBuilder;

impl PromptBuilder {
    /// Build a prompt from an `AnalysisRequest`.
    /// The output instructs the model to return a specific JSON schema —
    /// the response parser expects exactly this schema.
    pub fn build(request: &AnalysisRequest) -> BuiltPrompt {
        let system = Self::system_prompt();
        let user   = Self::user_prompt(request);
        let combined = format!("{system}\n\n{user}");
        BuiltPrompt { system, user, combined }
    }

    fn system_prompt() -> String {
        r#"You are a Data Loss Prevention (DLP) analyst embedded in an enterprise
Secure Web Gateway. Your job is to analyse outgoing network requests and
identify confidential information leakage.

You will receive:
1. Extracted text from the request body
2. The destination host
3. Findings already detected by rule-based detectors (regex + keywords)

Your task:
- Identify any confidential information that rule-based detectors may have MISSED
- Consider context: is this data sensitive given WHERE it is going?
- Look for obfuscated, encoded, or indirect leakage
- Assess business risk, not just technical pattern matches

CRITICAL RULES:
- You are an ADVISOR only. You never make the final decision.
- Return ONLY valid JSON. No prose, no markdown, no explanation outside the JSON.
- If you are uncertain, lower your confidence score — do not guess.
- Never fabricate findings that are not in the text.

Return exactly this JSON schema:
{
  "classification": "<string: credential_leak|pii_exposure|source_code_exfiltration|business_data|safe|unknown>",
  "risk_score": <integer 0-100>,
  "confidence": <integer 0-100>,
  "detected_entities": [<string>, ...],
  "reason": "<string: one sentence explanation>",
  "recommended_action": "<string: allow|redact|block|warn>"
}"#.to_string()
    }

    fn user_prompt(req: &AnalysisRequest) -> String {
        let prior = Self::format_prior_findings(&req.prior_findings);
        let method = req.method.as_deref().unwrap_or("UNKNOWN");

        // Truncate very long bodies — SLMs have context limits.
        // 2000 chars covers the vast majority of API request bodies.
        let text_preview = if req.extracted_text.len() > 2000 {
            format!(
                "{}... [truncated, total {} chars]",
                &req.extracted_text[..2000],
                req.extracted_text.len()
            )
        } else {
            req.extracted_text.clone()
        };

        format!(
            r#"=== REQUEST TO ANALYSE ===
Destination: {destination}
Method: {method}
Rule-based risk score so far: {rule_risk}/100

=== PRIOR DETECTOR FINDINGS ===
{prior}

=== EXTRACTED REQUEST BODY ===
{text}

=== YOUR ANALYSIS (JSON only) ==="#,
            destination = req.destination,
            rule_risk   = req.rule_based_risk,
            prior       = prior,
            text        = text_preview,
        )
    }

    fn format_prior_findings(findings: &[PriorFinding]) -> String {
        if findings.is_empty() {
            return "None — rule-based detectors found nothing. Look carefully.".to_string();
        }
        findings
            .iter()
            .map(|f| {
                format!(
                    "  - [{}] type={} risk={} match={}",
                    f.detector, f.finding_type, f.risk, f.masked_match
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PriorFinding;

    fn sample_request() -> AnalysisRequest {
        AnalysisRequest {
            extracted_text:  "api_key=sk-test123".into(),
            destination:     "api.openai.com".into(),
            method:          Some("POST".into()),
            prior_findings:  vec![PriorFinding {
                detector:     "regex".into(),
                finding_type: "openai_api_key".into(),
                risk:         100,
                masked_match: "sk-tes...".into(),
            }],
            rule_based_risk: 100,
        }
    }

    #[test]
    fn prompt_contains_destination() {
        let p = PromptBuilder::build(&sample_request());
        assert!(p.user.contains("api.openai.com"), "user: {}", p.user);
        assert!(p.combined.contains("api.openai.com"));
    }

    #[test]
    fn prompt_contains_prior_findings() {
        let p = PromptBuilder::build(&sample_request());
        assert!(p.user.contains("openai_api_key"), "user: {}", p.user);
        assert!(p.user.contains("risk=100"));
    }

    #[test]
    fn prompt_contains_extracted_text() {
        let p = PromptBuilder::build(&sample_request());
        assert!(p.user.contains("api_key=sk-test123"), "user: {}", p.user);
    }

    #[test]
    fn prompt_instructs_json_only_output() {
        let p = PromptBuilder::build(&sample_request());
        assert!(p.system.contains("ONLY valid JSON"));
        assert!(p.system.contains("\"classification\""));
    }

    #[test]
    fn long_text_is_truncated() {
        let mut req = sample_request();
        req.extracted_text = "x".repeat(5000);
        let p = PromptBuilder::build(&req);
        assert!(p.user.contains("truncated"));
        assert!(p.user.contains("5000 chars"));
    }

    #[test]
    fn no_prior_findings_shows_clear_message() {
        let mut req = sample_request();
        req.prior_findings = vec![];
        let p = PromptBuilder::build(&req);
        assert!(p.user.contains("found nothing"), "user: {}", p.user);
    }

    #[test]
    fn system_prompt_emphasises_advisor_role() {
        let p = PromptBuilder::build(&sample_request());
        assert!(p.system.contains("ADVISOR"));
        assert!(p.system.contains("never make the final decision"));
    }

    #[test]
    fn combined_contains_both_system_and_user() {
        let p = PromptBuilder::build(&sample_request());
        assert!(p.combined.contains("Data Loss Prevention"));
        assert!(p.combined.contains("api.openai.com"));
    }
}
