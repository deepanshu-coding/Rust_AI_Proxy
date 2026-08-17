//! Parse and validate raw SLM text output into `AnalysisResult`.
//!
//! ## Why a separate module
//!
//! Models are unreliable narrators — they can:
//! - Wrap JSON in markdown code fences (```json ... ```)
//! - Add a prose preamble before the JSON
//! - Emit invalid JSON on unusual inputs
//! - Return out-of-range values (risk_score: 150)
//! - Use unexpected classification strings
//!
//! This module handles all of that defensively. The proxy must never
//! crash because a model returned malformed output — we always return
//! *something* meaningful, even if it's just `AnalysisResult::unavailable()`.

use crate::types::{AnalysisResult, RecommendedAction};

#[derive(Debug)]
pub enum ParseError {
    EmptyResponse,
    NoJsonFound,
    InvalidJson(String),
    MissingField(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyResponse      => write!(f, "SLM returned empty response"),
            Self::NoJsonFound        => write!(f, "no JSON object found in response"),
            Self::InvalidJson(e)     => write!(f, "JSON parse error: {e}"),
            Self::MissingField(name) => write!(f, "required field missing: {name}"),
        }
    }
}

pub struct ResponseParser;

impl ResponseParser {
    /// Parse raw model output into `AnalysisResult`.
    /// On any parse failure, returns `AnalysisResult::unavailable()` and
    /// logs the error — never propagates a parse error to the proxy.
    pub fn parse(raw: &str) -> AnalysisResult {
        match Self::try_parse(raw) {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(error = %e, raw_response = %&raw[..raw.len().min(200)],
                    "SLM response parse failed, using unavailable fallback");
                AnalysisResult::unavailable()
            }
        }
    }

    fn try_parse(raw: &str) -> Result<AnalysisResult, ParseError> {
        if raw.trim().is_empty() {
            return Err(ParseError::EmptyResponse);
        }

        // Extract JSON from the raw text — handles markdown fences,
        // prose preambles, and trailing text after the JSON object.
        let json_str = Self::extract_json(raw).ok_or(ParseError::NoJsonFound)?;

        let value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| ParseError::InvalidJson(e.to_string()))?;

        let classification = value["classification"]
            .as_str()
            .ok_or_else(|| ParseError::MissingField("classification".into()))?
            .to_string();

        let reason = value["reason"]
            .as_str()
            .ok_or_else(|| ParseError::MissingField("reason".into()))?
            .to_string();

        // Numeric fields: clamp to valid range, default to 0 if missing/invalid
        let risk_score = Self::clamp_u8(value["risk_score"].as_u64());
        let confidence = Self::clamp_u8(value["confidence"].as_u64());

        // detected_entities: array of strings, empty if missing/wrong type
        let detected_entities = value["detected_entities"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // recommended_action: parse permissively, default to warn on unknown
        let recommended_action = value["recommended_action"]
            .as_str()
            .map(Self::parse_action)
            .unwrap_or(RecommendedAction::Warn);

        // Validate classification string — normalise unknown values
        let classification = Self::normalise_classification(&classification);

        Ok(AnalysisResult {
            classification,
            risk_score,
            confidence,
            detected_entities,
            reason,
            recommended_action,
        })
    }

    /// Find the first `{...}` JSON object in arbitrary text.
    /// Handles markdown fences, prose preambles, trailing content.
    fn extract_json(text: &str) -> Option<&str> {
        // Strip common markdown fence patterns first
        let text = text
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        // Find first { and its matching }
        let start = text.find('{')?;
        let mut depth = 0usize;
        let mut end   = start;

        for (i, ch) in text[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = start + i;
                        break;
                    }
                }
                _ => {}
            }
        }

        if depth == 0 && end >= start {
            Some(&text[start..=end])
        } else {
            None
        }
    }

    fn clamp_u8(v: Option<u64>) -> u8 {
        v.unwrap_or(0).min(100) as u8
    }

    fn parse_action(s: &str) -> RecommendedAction {
        match s.to_lowercase().as_str() {
            "allow"  => RecommendedAction::Allow,
            "redact" => RecommendedAction::Redact,
            "block"  => RecommendedAction::Block,
            "warn"   => RecommendedAction::Warn,
            _        => RecommendedAction::Warn, // unknown → conservative
        }
    }

    fn normalise_classification(s: &str) -> String {
        const KNOWN: &[&str] = &[
            "credential_leak",
            "pii_exposure",
            "source_code_exfiltration",
            "business_data",
            "safe",
            "unknown",
            "unavailable",
        ];
        let lower = s.to_lowercase();
        if KNOWN.contains(&lower.as_str()) {
            lower
        } else {
            // Unknown classification → treat as unknown rather than
            // silently accepting a model hallucination
            tracing::debug!(classification = %s, "normalised unknown SLM classification to 'unknown'");
            "unknown".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JSON: &str = r#"{
        "classification": "credential_leak",
        "risk_score": 95,
        "confidence": 88,
        "detected_entities": ["AWS_KEY", "SECRET"],
        "reason": "AWS access key detected in request body",
        "recommended_action": "block"
    }"#;

    #[test]
    fn parses_valid_json_correctly() {
        let result = ResponseParser::parse(VALID_JSON);
        assert_eq!(result.classification, "credential_leak");
        assert_eq!(result.risk_score, 95);
        assert_eq!(result.confidence, 88);
        assert_eq!(result.detected_entities, vec!["AWS_KEY", "SECRET"]);
        assert_eq!(result.recommended_action, RecommendedAction::Block);
        assert!(result.is_meaningful());
    }

    #[test]
    fn handles_markdown_fence() {
        let fenced = format!("```json\n{VALID_JSON}\n```");
        let result = ResponseParser::parse(&fenced);
        assert_eq!(result.classification, "credential_leak");
        assert_eq!(result.risk_score, 95);
    }

    #[test]
    fn handles_prose_preamble() {
        let with_preamble = format!("Sure, here is my analysis:\n{VALID_JSON}");
        let result = ResponseParser::parse(&with_preamble);
        assert_eq!(result.classification, "credential_leak");
    }

    #[test]
    fn empty_response_returns_unavailable() {
        let result = ResponseParser::parse("   ");
        assert_eq!(result.classification, "unavailable");
        assert_eq!(result.risk_score, 0);
        assert!(!result.is_meaningful());
    }

    #[test]
    fn invalid_json_returns_unavailable() {
        let result = ResponseParser::parse("{ not valid json }}}");
        assert_eq!(result.classification, "unavailable");
    }

    #[test]
    fn missing_classification_returns_unavailable() {
        let json = r#"{"risk_score": 50, "confidence": 70, "reason": "x", "recommended_action": "allow", "detected_entities": []}"#;
        let result = ResponseParser::parse(json);
        assert_eq!(result.classification, "unavailable");
    }

    #[test]
    fn risk_score_clamped_to_100() {
        let json = r#"{"classification": "safe", "risk_score": 999, "confidence": 50, "reason": "x", "recommended_action": "allow", "detected_entities": []}"#;
        let result = ResponseParser::parse(json);
        assert_eq!(result.risk_score, 100);
    }

    #[test]
    fn unknown_action_defaults_to_warn() {
        let json = r#"{"classification": "safe", "risk_score": 0, "confidence": 50, "reason": "x", "recommended_action": "explode", "detected_entities": []}"#;
        let result = ResponseParser::parse(json);
        assert_eq!(result.recommended_action, RecommendedAction::Warn);
    }

    #[test]
    fn unknown_classification_normalised_to_unknown() {
        let json = r#"{"classification": "SUPER_SECRET_THING", "risk_score": 50, "confidence": 50, "reason": "x", "recommended_action": "warn", "detected_entities": []}"#;
        let result = ResponseParser::parse(json);
        assert_eq!(result.classification, "unknown");
    }

    #[test]
    fn empty_detected_entities_allowed() {
        let json = r#"{"classification": "safe", "risk_score": 0, "confidence": 90, "reason": "clean", "recommended_action": "allow", "detected_entities": []}"#;
        let result = ResponseParser::parse(json);
        assert!(result.detected_entities.is_empty());
    }

    #[test]
    fn all_recommended_actions_parse_correctly() {
        for (action_str, expected) in [
            ("allow",  RecommendedAction::Allow),
            ("redact", RecommendedAction::Redact),
            ("block",  RecommendedAction::Block),
            ("warn",   RecommendedAction::Warn),
        ] {
            let json = format!(
                r#"{{"classification":"safe","risk_score":0,"confidence":50,"reason":"x","recommended_action":"{action_str}","detected_entities":[]}}"#
            );
            let result = ResponseParser::parse(&json);
            assert_eq!(result.recommended_action, expected, "failed for {action_str}");
        }
    }
}
