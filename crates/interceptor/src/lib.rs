//! Traffic interception — the highest-priority piece of this project.
//!
//! Responsible for transparently capturing outgoing HTTP/HTTPS traffic
//! from every application on the system (Chrome, Edge, Outlook, VS Code,
//! Slack, Teams, REST clients) before it reaches the network, decrypting
//! HTTPS via a locally-trusted root CA, and handing plaintext content to
//! the extractor/detector pipeline before deciding whether to forward it.
//!
//! ## Build phases (per the project's "verify after every step" policy)
//!
//! - ✅ **Phase 1**: `PlainHttpProxy` — a real TCP listener that accepts
//!   connections, parses HTTP request lines, and either forwards plain
//!   HTTP requests upstream or tunnels HTTPS via CONNECT (raw byte copy
//!   — **not decrypted yet**, just proven end-to-end connectivity).
//! - ✅ **Phase 2**: `ca` — root CA generation, persistence, and
//!   per-domain leaf certificate signing (openssl-verified valid X.509).
//! - ✅ **Phase 2b**: `cert_store` — install/uninstall the root CA into
//!   Windows' Trusted Root store via `certutil.exe`. Command logic
//!   unit-tested; actual Windows trust-store behavior still needs
//!   manual confirmation on a real Windows machine.
//! - ✅ **Phase 3a (this commit)**: `tls` — terminates a real TLS
//!   handshake using a per-domain leaf cert, verified end-to-end in this
//!   sandbox via an in-process rustls client that trusts our generated
//!   CA (the same mechanism Windows' Trust Store provides on a real
//!   machine, just exercised without needing one).
//! - ⬜ Phase 3b: wire `tls::terminate_client_tls` into
//!   `plain_proxy::handle_connect`, add an upstream TLS *client*
//!   connection to the real destination, and relay decrypted plaintext
//!   between the two — replacing the current raw `tunnel::relay` call
//!   for CONNECT requests
//! - ⬜ Phase 4: Windows system proxy registration (`InternetSetOption`)
//!   so OS-wide traffic actually routes here instead of needing manual
//!   browser proxy config
//! - ⬜ Phase 5 (future): WFP callout driver for bypass-resistant capture
//!
//! Everything above sits behind the `Interceptor` trait, so the capture
//! mechanism can evolve without extractor/detector/policy-engine ever
//! needing to change.

use common::CdpResult;

pub mod ca;
pub mod cert_store;
pub mod http_parser;
pub mod plain_proxy;
pub mod system_proxy;
pub mod tls;
pub mod tunnel;

/// One intercepted request, already decrypted if it was HTTPS.
pub struct InterceptedRequest {
    pub destination_host: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What the policy pipeline tells the interceptor to do with a request
/// after inspection.
pub enum InterceptAction {
    Forward(InterceptedRequest),
    ForwardModified(InterceptedRequest),
    Block,
}

#[async_trait::async_trait]
pub trait Interceptor: Send + Sync {
    /// Start listening for traffic. Implementations decide how
    /// (userland proxy port + system proxy registration, or later,
    /// a WFP callout) — callers only depend on this trait.
    async fn start(&self) -> CdpResult<()>;
}

pub use plain_proxy::PlainHttpProxy;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intercepted_request_holds_expected_fields() {
        let req = InterceptedRequest {
            destination_host: "example.com".into(),
            method: "GET".into(),
            headers: vec![("User-Agent".into(), "test".into())],
            body: vec![],
        };
        assert_eq!(req.destination_host, "example.com");
        assert_eq!(req.method, "GET");
    }
}
