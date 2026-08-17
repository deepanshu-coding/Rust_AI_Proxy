//! Detection engine — pluggable, trait-based detectors.
//!
//! ## Detectors
//!
//! - `RegexDetector`  — 8 patterns: AWS/OpenAI/GitHub keys, JWT, private
//!   keys, DB connection strings, Bearer tokens. Uses `fancy-regex` for
//!   lookaround support (Rust's `regex` crate does not support lookbehind,
//!   which several Python-ported patterns require).
//! - `KeywordDetector` — credential keyword k=v / JSON / YAML / ENV patterns.
//! - `ScanPipeline`   — orchestrates all detectors; new detectors just need
//!   to implement `Detector` — zero changes to the pipeline.

use common::Finding;
use fancy_regex::Regex;
use once_cell::sync::Lazy;

// ─── Core trait ──────────────────────────────────────────────────────────────

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, text: &str) -> Vec<Finding>;
}

// ─── RegexDetector ───────────────────────────────────────────────────────────

struct RegexPattern {
    name: &'static str,
    regex: Regex,
    risk: u32,
    placeholder: &'static str,
}

macro_rules! pat {
    ($name:expr, $re:expr, $risk:expr, $ph:expr) => {
        RegexPattern {
            name: $name,
            regex: Regex::new($re).expect(concat!("bad regex: ", $name)),
            risk: $risk,
            placeholder: $ph,
        }
    };
}

static PATTERNS: Lazy<Vec<RegexPattern>> = Lazy::new(|| {
    vec![
        pat!(
            "aws_access_key",
            r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
            100,
            "[AWS_ACCESS_KEY]"
        ),
        pat!(
            "aws_secret_key",
            r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            100,
            "[AWS_SECRET_KEY]"
        ),
        pat!(
            "openai_api_key",
            r"sk-[A-Za-z0-9]{32,64}",
            100,
            "[OPENAI_API_KEY]"
        ),
        pat!(
            "github_token",
            r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}",
            100,
            "[GITHUB_TOKEN]"
        ),
        pat!(
            "jwt_token",
            r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
            80,
            "[JWT_TOKEN]"
        ),
        pat!(
            "private_key",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            100,
            "[PRIVATE_KEY]"
        ),
        pat!(
            "db_connection_string",
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlserver)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
            100,
            "[DB_CONNECTION_STRING]"
        ),
        pat!(
            "bearer_token",
            r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*",
            80,
            "[BEARER_TOKEN]"
        ),
    ]
});

pub struct RegexDetector;

impl Detector for RegexDetector {
    fn name(&self) -> &'static str {
        "regex"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for p in PATTERNS.iter() {
            // fancy_regex returns Result per match; skip errors (shouldn't
            // happen with pre-validated patterns, but never panic in hot path)
            for m in p.regex.find_iter(text).flatten() {
                let raw = m.as_str();
                let masked = if raw.len() > 6 {
                    format!("{}...", &raw[..6])
                } else {
                    format!("{}...", &raw[..raw.len().min(3)])
                };
                findings.push(Finding {
                    detector: "regex".into(),
                    finding_type: p.name.into(),
                    risk: p.risk,
                    masked_match: masked,
                });
            }
        }
        findings
    }
}

impl RegexDetector {
    /// Replace all detected secrets with placeholder strings.
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_string();
        for p in PATTERNS.iter() {
            result = p.regex.replace_all(&result, p.placeholder).into_owned();
        }
        result
    }
}

// ─── KeywordDetector ─────────────────────────────────────────────────────────

const CREDENTIAL_KEYWORDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
];

/// Matches: key=value, key: value, JSON "key": "value", YAML key: val,
/// ENV KEY=VALUE — all case-insensitive, multi-line.
static KV_PATTERN: Lazy<Regex> = Lazy::new(|| {
    let kws = CREDENTIAL_KEYWORDS.join("|");
    Regex::new(&format!(
        r#"(?im)(?:^|["'\s{{,])(?:{kws})\s*[=:]\s*["']?([^\s"'}}\n,;]{{3,}})["']?"#
    ))
    .expect("bad KV_PATTERN regex")
});

/// Standalone keyword anywhere in text.
static STANDALONE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    let kws = CREDENTIAL_KEYWORDS.join("|");
    Regex::new(&format!(r"(?i)\b(?:{kws})\b")).expect("bad STANDALONE_PATTERN regex")
});

pub struct KeywordDetector;

impl Detector for KeywordDetector {
    fn name(&self) -> &'static str {
        "keyword"
    }

    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // First pass: k=v matches (have an associated value — higher signal)
        for m in KV_PATTERN.find_iter(text).flatten() {
            let matched = m.as_str().trim();
            let keyword = CREDENTIAL_KEYWORDS
                .iter()
                .find(|&&kw| matched.to_lowercase().contains(kw))
                .copied()
                .unwrap_or("credential");

            if seen.insert(format!("kv:{keyword}")) {
                let masked = if matched.len() > 12 {
                    format!("{}...", &matched[..12])
                } else {
                    matched.to_string()
                };
                findings.push(Finding {
                    detector: "keyword".into(),
                    finding_type: format!("credential_keyword:{keyword}"),
                    risk: 50,
                    masked_match: masked,
                });
            }
        }

        // Second pass: standalone keywords not already caught via k=v
        for m in STANDALONE_PATTERN.find_iter(text).flatten() {
            let keyword = m.as_str().to_lowercase();
            let kv_key = format!("kv:{keyword}");
            let sa_key = format!("standalone:{keyword}");
            if !seen.contains(&kv_key) && seen.insert(sa_key) {
                findings.push(Finding {
                    detector: "keyword".into(),
                    finding_type: format!("credential_keyword:{keyword}"),
                    risk: 50,
                    masked_match: keyword,
                });
            }
        }

        findings
    }
}

impl KeywordDetector {
    pub fn redact(&self, text: &str) -> String {
        KV_PATTERN
            .replace_all(text, "[SECRET_REDACTED]")
            .into_owned()
    }
}

// ─── ScanPipeline ─────────────────────────────────────────────────────────────

/// Runs all detectors, aggregates findings. Wrap in `Arc` for sharing
/// across connection-handler tasks.
pub struct ScanPipeline {
    detectors: Vec<Box<dyn Detector>>,
}

impl ScanPipeline {
    pub fn default_pipeline() -> Self {
        Self {
            detectors: vec![Box::new(RegexDetector), Box::new(KeywordDetector)],
        }
    }

    pub fn with_detectors(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        self.detectors
            .iter()
            .flat_map(|d| d.detect(text))
            .collect()
    }

    pub fn triggered_names<'a>(&'a self, findings: &[Finding]) -> Vec<&'a str> {
        let fired: std::collections::HashSet<&str> =
            findings.iter().map(|f| f.detector.as_str()).collect();
        self.detectors
            .iter()
            .map(|d| d.name())
            .filter(|n| fired.contains(n))
            .collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RegexDetector ──

    #[test]
    fn detects_aws_access_key() {
        let d = RegexDetector;
        let f = d.detect("export AWS_KEY=AKIAIOSFODNN7EXAMPLE rest");
        assert!(f.iter().any(|f| f.finding_type == "aws_access_key"),
            "findings: {f:?}");
    }

    #[test]
    fn detects_openai_key() {
        let d = RegexDetector;
        let f = d.detect("sk-abcdefghijklmnopqrstuvwxyz123456ABCDEFGHIJKLMNOP");
        assert!(f.iter().any(|f| f.finding_type == "openai_api_key"),
            "findings: {f:?}");
    }

    #[test]
    fn detects_github_token() {
        let d = RegexDetector;
        let f = d.detect("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcde12345");
        assert!(f.iter().any(|f| f.finding_type == "github_token"),
            "findings: {f:?}");
    }

    #[test]
    fn detects_jwt() {
        let d = RegexDetector;
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                   .eyJzdWIiOiIxMjM0NTY3ODkwIn0\
                   .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let f = d.detect(jwt);
        assert!(f.iter().any(|f| f.finding_type == "jwt_token"),
            "findings: {f:?}");
    }

    #[test]
    fn detects_private_key_header() {
        let d = RegexDetector;
        let f = d.detect("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...");
        assert!(f.iter().any(|f| f.finding_type == "private_key"),
            "findings: {f:?}");
    }

    #[test]
    fn detects_db_connection_string() {
        let d = RegexDetector;
        let f = d.detect("postgresql://user:pass@localhost:5432/mydb");
        assert!(f.iter().any(|f| f.finding_type == "db_connection_string"),
            "findings: {f:?}");
    }

    #[test]
    fn detects_bearer_token() {
        let d = RegexDetector;
        let f = d.detect("Authorization: Bearer sometoken123==");
        assert!(f.iter().any(|f| f.finding_type == "bearer_token"),
            "findings: {f:?}");
    }

    #[test]
    fn clean_text_no_findings() {
        let d = RegexDetector;
        assert!(d.detect("Hello, normal sentence with no secrets.").is_empty());
    }

    #[test]
    fn masked_match_shorter_than_original_and_has_ellipsis() {
        let d = RegexDetector;
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let f = d.detect(secret);
        assert!(!f.is_empty());
        for finding in &f {
            assert!(finding.masked_match.len() < secret.len());
            assert!(finding.masked_match.contains("..."));
        }
    }

    #[test]
    fn redact_replaces_aws_key_with_placeholder() {
        let d = RegexDetector;
        let r = d.redact("key=AKIAIOSFODNN7EXAMPLE");
        assert!(!r.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(r.contains("[AWS_ACCESS_KEY]"));
    }

    #[test]
    fn redact_replaces_private_key_header() {
        let d = RegexDetector;
        let r = d.redact("-----BEGIN RSA PRIVATE KEY-----\ndata");
        assert!(r.contains("[PRIVATE_KEY]"));
    }

    #[test]
    fn aws_key_not_detected_when_surrounded_by_other_alphanum() {
        // Lookbehind ensures partial matches inside longer strings don't fire
        let d = RegexDetector;
        let f = d.detect("XAKIAIOSFODNN7EXAMPLEX");
        assert!(!f.iter().any(|f| f.finding_type == "aws_access_key"),
            "should NOT detect AWS key surrounded by other alpha: {f:?}");
    }

    // ── KeywordDetector ──

    #[test]
    fn detects_password_equals() {
        let d = KeywordDetector;
        let f = d.detect("password=supersecret123");
        assert!(f.iter().any(|f| f.finding_type.contains("password")));
    }

    #[test]
    fn detects_api_key_colon() {
        let d = KeywordDetector;
        let f = d.detect("api_key: my-secret-value-here");
        assert!(!f.is_empty(), "findings: {f:?}");
    }

    #[test]
    fn detects_json_secret_field() {
        let d = KeywordDetector;
        let f = d.detect(r#"{"secret": "my-secret-value-here"}"#);
        assert!(!f.is_empty(), "findings: {f:?}");
    }

    #[test]
    fn clean_text_no_keyword_findings() {
        let d = KeywordDetector;
        assert!(d.detect("The weather is sunny today.").is_empty());
    }

    #[test]
    fn no_duplicate_findings_for_same_keyword() {
        let d = KeywordDetector;
        let f = d.detect("password=myval123");
        let pw: Vec<_> = f.iter().filter(|f| f.finding_type.contains("password")).collect();
        assert_eq!(pw.len(), 1, "duplicate password findings: {pw:?}");
    }

    #[test]
    fn keyword_risk_is_50() {
        let d = KeywordDetector;
        let f = d.detect("passwd=myval123");
        assert!(f.iter().all(|f| f.risk == 50), "all keyword risks should be 50");
    }

    // ── ScanPipeline ──

    #[test]
    fn pipeline_fires_both_regex_and_keyword_detectors() {
        let p = ScanPipeline::default_pipeline();
        let f = p.scan("AKIAIOSFODNN7EXAMPLE\npasswd=myval123");
        let detectors: std::collections::HashSet<_> =
            f.iter().map(|f| f.detector.as_str()).collect();
        assert!(detectors.contains("regex"));
        assert!(detectors.contains("keyword"));
    }

    #[test]
    fn pipeline_empty_for_clean_content() {
        let p = ScanPipeline::default_pipeline();
        assert!(p.scan("This is a completely normal sentence.").is_empty());
    }

    #[test]
    fn triggered_names_includes_fired_detectors() {
        let p = ScanPipeline::default_pipeline();
        let f = p.scan("passwd=myval123");
        let names = p.triggered_names(&f);
        assert!(names.contains(&"keyword"));
    }
}
