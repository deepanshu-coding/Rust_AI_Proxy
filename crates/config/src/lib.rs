//! Configuration loading — policies live in `policies/*.toml`, not Rust code.
//!
//! Per the architecture spec: *"Policies should come from configuration
//! files instead of hardcoded Rust code."* This crate owns the loading
//! and validation of those files and exposes a `LoadedPolicy` that
//! `policy-engine` can consume directly — the policy engine itself
//! never touches file I/O.
//!
//! ## File format (`policies/default.toml`)
//!
//! ```toml
//! [thresholds]
//! block_at  = 100
//! redact_at = 50
//!
//! [rules.aws_access_key]
//! risk   = 100
//! action = "block"
//!
//! [rules.credential_keyword]
//! risk   = 50
//! action = "redact"
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read policy file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse policy file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid action '{action}' in rule '{rule}': must be allow, redact, block, or warn")]
    InvalidAction { rule: String, action: String },
}

pub type ConfigResult<T> = Result<T, ConfigError>;

// ─── Raw TOML structures ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThresholdsConfig {
    pub block_at:  Option<u32>,
    pub redact_at: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub risk:   u32,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyFileConfig {
    #[serde(default)]
    pub thresholds: ThresholdsConfig,
    #[serde(default)]
    pub rules: HashMap<String, RuleConfig>,
}

// ─── Validated output ─────────────────────────────────────────────────────────

/// A fully-loaded and validated policy, ready for the policy engine to use.
/// Produced by `PolicyLoader::load` — never constructed directly.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub block_at:  u32,
    pub redact_at: u32,
    pub rules:     HashMap<String, RuleConfig>,
}

impl LoadedPolicy {
    /// Defaults matching what the policy engine hardcoded before this crate.
    pub fn default_thresholds() -> Self {
        Self {
            block_at:  100,
            redact_at: 50,
            rules:     HashMap::new(),
        }
    }
}

// ─── Loader ───────────────────────────────────────────────────────────────────

pub struct PolicyLoader;

impl PolicyLoader {
    /// Load a policy file from `path`. Validates all rule actions.
    pub fn load(path: &Path) -> ConfigResult<LoadedPolicy> {
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::parse(&raw, &path.display().to_string())
    }

    /// Load from `policies/default.toml` relative to `base_dir`.
    /// Falls back to hardcoded defaults if the file does not exist —
    /// so the proxy works out-of-the-box without requiring a config file.
    pub fn load_or_default(base_dir: &Path) -> LoadedPolicy {
        let path = base_dir.join("policies").join("default.toml");
        if !path.exists() {
            tracing::info!(
                "no policy file found at {}, using built-in defaults",
                path.display()
            );
            return LoadedPolicy::default_thresholds();
        }
        match Self::load(&path) {
            Ok(policy) => {
                tracing::info!("loaded policy from {}", path.display());
                policy
            }
            Err(e) => {
                tracing::warn!("failed to load policy ({}), using defaults", e);
                LoadedPolicy::default_thresholds()
            }
        }
    }

    /// Parse TOML string into a `LoadedPolicy`. Separated from `load`
    /// so tests can exercise parsing without touching the filesystem.
    pub fn parse(toml_str: &str, source: &str) -> ConfigResult<LoadedPolicy> {
        let file: PolicyFileConfig =
            toml::from_str(toml_str).map_err(|e| ConfigError::Parse {
                path: source.to_string(),
                source: e,
            })?;

        // Validate all action strings before we hand the config to the engine.
        const VALID_ACTIONS: &[&str] = &["allow", "redact", "block", "warn"];
        for (name, rule) in &file.rules {
            if !VALID_ACTIONS.contains(&rule.action.to_lowercase().as_str()) {
                return Err(ConfigError::InvalidAction {
                    rule: name.clone(),
                    action: rule.action.clone(),
                });
            }
        }

        Ok(LoadedPolicy {
            block_at:  file.thresholds.block_at.unwrap_or(100),
            redact_at: file.thresholds.redact_at.unwrap_or(50),
            rules:     file.rules,
        })
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOML: &str = r#"
        [thresholds]
        block_at  = 100
        redact_at = 50

        [rules.aws_access_key]
        risk   = 100
        action = "block"

        [rules.credential_keyword]
        risk   = 50
        action = "redact"

        [rules.bearer_token]
        risk   = 80
        action = "block"
    "#;

    #[test]
    fn parses_thresholds_correctly() {
        let p = PolicyLoader::parse(SAMPLE_TOML, "test").unwrap();
        assert_eq!(p.block_at,  100);
        assert_eq!(p.redact_at, 50);
    }

    #[test]
    fn parses_rules_correctly() {
        let p = PolicyLoader::parse(SAMPLE_TOML, "test").unwrap();
        assert_eq!(p.rules.len(), 3);

        let aws = p.rules.get("aws_access_key").unwrap();
        assert_eq!(aws.risk,   100);
        assert_eq!(aws.action, "block");

        let kw = p.rules.get("credential_keyword").unwrap();
        assert_eq!(kw.risk,   50);
        assert_eq!(kw.action, "redact");
    }

    #[test]
    fn defaults_when_thresholds_omitted() {
        let toml = r#"
            [rules.some_rule]
            risk   = 30
            action = "allow"
        "#;
        let p = PolicyLoader::parse(toml, "test").unwrap();
        assert_eq!(p.block_at,  100);
        assert_eq!(p.redact_at, 50);
    }

    #[test]
    fn empty_toml_produces_default_thresholds_and_empty_rules() {
        let p = PolicyLoader::parse("", "test").unwrap();
        assert_eq!(p.block_at,  100);
        assert_eq!(p.redact_at, 50);
        assert!(p.rules.is_empty());
    }

    #[test]
    fn rejects_invalid_action() {
        let bad = r#"
            [rules.bad_rule]
            risk   = 50
            action = "explode"
        "#;
        let result = PolicyLoader::parse(bad, "test");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("explode"), "error should name the bad action: {msg}");
    }

    #[test]
    fn load_or_default_returns_defaults_when_file_missing() {
        let dir = std::path::PathBuf::from("/nonexistent/path/that/does/not/exist");
        let p = PolicyLoader::load_or_default(&dir);
        assert_eq!(p.block_at,  100);
        assert_eq!(p.redact_at, 50);
    }

    #[test]
    fn load_from_real_file_round_trips() {
        // Write a temp file, load it, verify round-trip.
        let dir = std::env::temp_dir().join(format!(
            "cdp-config-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.toml");
        std::fs::write(&file, SAMPLE_TOML).unwrap();

        let p = PolicyLoader::load(&file).unwrap();
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.block_at, 100);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_default_with_real_policies_dir() {
        // Use the actual policies/default.toml in the repo if it exists.
        // This test passes whether or not the file is present — it exercises
        // both code paths (file present → parse, file absent → defaults).
        let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()  // crates/config → crates
            .unwrap()
            .parent()  // crates → workspace root
            .unwrap()
            .to_path_buf();
        let p = PolicyLoader::load_or_default(&workspace_root);
        // Either way, thresholds must be sane positive numbers.
        assert!(p.block_at  > 0);
        assert!(p.redact_at > 0);
        assert!(p.block_at  >= p.redact_at);
    }
}
