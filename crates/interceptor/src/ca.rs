//! Root CA generation + per-domain leaf certificate signing.
//!
//! ## How this fits into Phase 3 (TLS termination, not yet built)
//!
//! This module produces two things:
//! 1. A long-lived root CA (private key + self-signed cert) — generated
//!    once, installed into the Windows Trust Store, reused forever
//!    (or until rotated).
//! 2. Short-lived "leaf" certificates for individual domains
//!    (e.g. `accounts.google.com`), signed by that root CA on demand
//!    when the proxy intercepts a CONNECT for that domain. The browser
//!    sees a cert for the domain it asked for, signed by something it
//!    already trusts — so no warning, no broken padlock.
//!
//! This module does NOT yet wire into the actual TLS handshake
//! (`tokio-rustls` server-side termination) — that's the next piece
//! built on top of this. This module's job is just: can we correctly
//! generate a CA and have it produce valid, verifiable leaf certs.
//!
//! ## Security note
//! The root CA private key is the single most sensitive artifact in this
//! entire project. Anyone who has it can mint trusted certificates for
//! ANY domain on a machine where it's installed. It must never be
//! committed to version control, must be generated locally per-install,
//! and the `certs/` directory is already in `.gitignore` for this reason.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa,
    ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use std::path::Path;
use time::{Duration, OffsetDateTime};

use common::{CdpError, CdpResult};

/// A generated (or loaded) root CA, ready to sign leaf certificates.
pub struct RootCa {
    pub key_pair: KeyPair,
    /// The CA's own self-signed certificate object — needed as the
    /// `issuer` argument when signing leaf certs (rcgen's API wants the
    /// full Certificate, not just raw DER bytes).
    pub certificate: Certificate,
    pub cert_pem: String,
    pub key_pem: String,
}

impl RootCa {
    /// Generate a brand-new root CA, valid for ~10 years.
    /// `common_name` shows up in Windows' cert manager UI — make it
    /// identifiable so a user/admin reviewing trusted roots can tell
    /// it's this proxy and not something suspicious.
    pub fn generate(common_name: &str) -> CdpResult<Self> {
        let key_pair = KeyPair::generate()
            .map_err(|e| CdpError::Interception(format!("key generation failed: {e}")))?;

        let params = Self::ca_params(common_name)?;

        let certificate = params
            .clone()
            .self_signed(&key_pair)
            .map_err(|e| CdpError::Interception(format!("CA self-sign failed: {e}")))?;

        let cert_pem = certificate.pem();
        let key_pem = key_pair.serialize_pem();

        Ok(Self {
            key_pair,
            certificate,
            cert_pem,
            key_pem,
        })
    }

    fn ca_params(common_name: &str) -> CdpResult<CertificateParams> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        dn.push(DnType::OrganizationName, "EnaLisis CDP Proxy");
        params.distinguished_name = dn;

        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(365 * 10);

        Ok(params)
    }

    /// Save the root CA's cert + key to disk as PEM files.
    /// The cert PEM is what gets installed into Windows' Trust Store.
    /// The key PEM must stay private — never share, never commit.
    pub fn save_to_dir(&self, dir: &Path) -> CdpResult<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca-cert.pem"), &self.cert_pem)?;
        std::fs::write(dir.join("ca-key.pem"), &self.key_pem)?;
        Ok(())
    }

    /// Load a previously-generated root CA from disk, if present.
    /// `common_name` must match what the CA was originally generated
    /// with (re-derives the same DistinguishedName so the reconstructed
    /// Certificate object is consistent — the key material is what
    /// actually matters for trust, this just keeps metadata sane).
    pub fn load_from_dir(dir: &Path, common_name: &str) -> CdpResult<Option<Self>> {
        let cert_path = dir.join("ca-cert.pem");
        let key_path = dir.join("ca-key.pem");

        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }

        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;

        let key_pair = KeyPair::from_pem(&key_pem)
            .map_err(|e| CdpError::Interception(format!("failed to load CA key: {e}")))?;

        let params = Self::ca_params(common_name)?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|e| CdpError::Interception(format!("failed to rebuild CA cert: {e}")))?;

        Ok(Some(Self {
            key_pair,
            certificate,
            cert_pem,
            key_pem,
        }))
    }

    /// Load the CA from `dir` if it exists, otherwise generate a new one
    /// and persist it. This is what startup code calls — idempotent
    /// across restarts, generates exactly once per machine/install.
    pub fn load_or_generate(dir: &Path, common_name: &str) -> CdpResult<Self> {
        if let Some(existing) = Self::load_from_dir(dir, common_name)? {
            tracing::info!(path = %dir.display(), "loaded existing root CA");
            return Ok(existing);
        }
        tracing::info!(path = %dir.display(), "generating new root CA");
        let ca = Self::generate(common_name)?;
        ca.save_to_dir(dir)?;
        Ok(ca)
    }

    /// Sign a new leaf certificate for `domain`, valid for a short
    /// period (browsers/OSes increasingly reject very-long-lived leaf
    /// certs even from trusted CAs). This is generated fresh per domain
    /// the first time it's seen — Phase 3 will cache these in memory so
    /// we're not re-signing on every single connection to the same site.
    pub fn issue_leaf_cert(&self, domain: &str) -> CdpResult<LeafCert> {
        let leaf_key = KeyPair::generate()
            .map_err(|e| CdpError::Interception(format!("leaf key generation failed: {e}")))?;

        let mut params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| CdpError::Interception(format!("invalid domain for cert: {e}")))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        // Short-lived: 90 days, matching modern CA/Browser Forum guidance
        // direction. Safe here because we re-issue on demand anyway.
        params.not_after = now + Duration::days(90);

        let cert = params
            .signed_by(&leaf_key, &self.certificate, &self.key_pair)
            .map_err(|e| CdpError::Interception(format!("leaf cert signing failed: {e}")))?;

        Ok(LeafCert {
            domain: domain.to_string(),
            cert_der: cert.der().to_vec(),
            key_der: leaf_key.serialize_der(),
        })
    }
}

/// A signed certificate for one specific domain, ready to be used in a
/// TLS handshake with a client (Phase 3 territory — not used yet).
pub struct LeafCert {
    pub domain: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal stand-in for `tempfile::tempdir()` using only std — avoids
    /// pulling in an extra dev-dependency whose transitive deps require
    /// a newer Rust edition than this sandbox's toolchain supports.
    /// Cleans itself up on Drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "cdp-proxy-test-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> TempDir {
        TempDir::new("ca")
    }

    #[test]
    fn generates_a_valid_root_ca() {
        let ca = RootCa::generate("Test CDP Proxy CA").unwrap();
        assert!(!ca.certificate.der().is_empty());
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn issues_a_leaf_cert_for_a_domain() {
        let ca = RootCa::generate("Test CDP Proxy CA").unwrap();
        let leaf = ca.issue_leaf_cert("example.com").unwrap();
        assert_eq!(leaf.domain, "example.com");
        assert!(!leaf.cert_der.is_empty());
        assert!(!leaf.key_der.is_empty());
    }

    #[test]
    fn issues_distinct_leaf_certs_for_different_domains() {
        let ca = RootCa::generate("Test CDP Proxy CA").unwrap();
        let leaf_a = ca.issue_leaf_cert("a.com").unwrap();
        let leaf_b = ca.issue_leaf_cert("b.com").unwrap();
        assert_ne!(leaf_a.cert_der, leaf_b.cert_der);
    }

    #[test]
    fn save_and_load_round_trip_preserves_ca() {
        let dir = tempdir();
        let original = RootCa::generate("Test CDP Proxy CA").unwrap();
        original.save_to_dir(dir.path()).unwrap();

        let loaded = RootCa::load_from_dir(dir.path(), "Test CDP Proxy CA")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.cert_pem, original.cert_pem);
        assert_eq!(loaded.key_pem, original.key_pem);
    }

    #[test]
    fn load_from_empty_dir_returns_none() {
        let dir = tempdir();
        let result = RootCa::load_from_dir(dir.path(), "Test CA").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_or_generate_creates_once_then_reuses() {
        let dir = tempdir();

        let first = RootCa::load_or_generate(dir.path(), "Test CA").unwrap();
        let second = RootCa::load_or_generate(dir.path(), "Test CA").unwrap();

        // Second call should have LOADED the first one, not generated a
        // new one — same key material proves that.
        assert_eq!(first.cert_pem, second.cert_pem);
    }

    #[test]
    fn loaded_ca_can_still_issue_leaf_certs() {
        let dir = tempdir();
        let original = RootCa::generate("Test CDP Proxy CA").unwrap();
        original.save_to_dir(dir.path()).unwrap();

        let loaded = RootCa::load_from_dir(dir.path(), "Test CDP Proxy CA")
            .unwrap()
            .unwrap();
        let leaf = loaded.issue_leaf_cert("loaded-test.com").unwrap();
        assert_eq!(leaf.domain, "loaded-test.com");
    }
}
