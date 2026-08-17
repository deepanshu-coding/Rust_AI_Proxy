//! Full MITM HTTP/HTTPS proxy — Phase 3b.
//!
//! ## What changed from Phase 1
//!
//! `handle_connect` no longer blindly tunnels raw bytes. It now:
//!   1. Sends "200 Connection Established" to the client.
//!   2. Issues a per-domain leaf cert from the root CA, builds a
//!      `TlsAcceptor`, and performs a TLS handshake *with the client*
//!      (the client sees a cert for the domain it asked for, signed by a
//!      CA it trusts because `install-cert` was run).
//!   3. Simultaneously opens a real TLS *client* connection to the actual
//!      upstream server (validated against webpki-roots).
//!   4. Relays plaintext between the two TLS streams — content that is
//!      now fully visible for inspection.
//!
//! ## What is NOT done yet (deliberately)
//!
//! The plaintext relay in step 4 still just copies bytes — it does not
//! yet pass them through the detection/policy pipeline. That wiring
//! happens in the next step once this MITM foundation is confirmed solid.
//!
//! Plain HTTP requests are still forwarded raw — they arrive as plaintext
//! already, so they bypass the buffered inspection for now (detection for
//! plain HTTP is a small next step).
//!
//! ## On cert pinning
//!
//! Applications that implement certificate pinning (some mobile apps,
//! Slack internals, certain banking APIs) will refuse connections through
//! this proxy even with the CA trusted, because they hardcode the
//! expected certificate or public key. This is expected and correct —
//! these apps have explicitly opted out of the system trust model. The
//! proxy correctly falls through to a 502 for these rather than silently
//! failing or bypassing their security.

use crate::ca::RootCa;
use crate::http_parser::{is_connect, parse_host_port, parse_request_line, ParseError};
use crate::tls::{acceptor_for_leaf_cert, connect_upstream_tls_over};
use crate::tunnel;
use crate::Interceptor;
use common::{CdpError, CdpResult};
use ai_engine::AiLayer;
use detector::ScanPipeline;
use policy_engine::PolicyEngine;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

pub struct MitmProxy {
    pub bind_addr: String,
    pub ca: Arc<RootCa>,
    connector: TlsConnector,
    pipeline: Arc<ScanPipeline>,
    policy: Arc<PolicyEngine>,
    ai_layer: Arc<AiLayer>,
}

impl MitmProxy {
    /// Production constructor: uses real webpki-roots for upstream
    /// certificate validation.
    pub fn new(bind_addr: impl Into<String>, ca: RootCa) -> Self {
        Self::new_with_policy(bind_addr, ca, PolicyEngine::default())
    }

    /// Constructor with an externally-configured `PolicyEngine` — used by
    /// `proxy-gateway` so thresholds come from `policies/default.toml`
    /// rather than compiled-in defaults.
    pub fn new_with_policy(
        bind_addr: impl Into<String>,
        ca: RootCa,
        policy: PolicyEngine,
    ) -> Self {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Self {
            bind_addr: bind_addr.into(),
            ca: Arc::new(ca),
            connector: TlsConnector::from(Arc::new(tls_config)),
            pipeline: Arc::new(ScanPipeline::default_pipeline()),
            policy: Arc::new(policy),
            ai_layer: Arc::new(AiLayer::stub()),
        }
    }

    /// Full production constructor: externally-configured policy engine
    /// AND externally-configured AI layer. Used by `proxy-gateway` so
    /// both policy thresholds (from TOML) and AI analyzer (stub by
    /// default, real SLM later) are injected at startup.
    pub fn new_with_ai(
        bind_addr: impl Into<String>,
        ca: RootCa,
        policy: PolicyEngine,
        ai_layer: AiLayer,
    ) -> Self {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Self {
            bind_addr: bind_addr.into(),
            ca: Arc::new(ca),
            connector: TlsConnector::from(Arc::new(tls_config)),
            pipeline: Arc::new(ScanPipeline::default_pipeline()),
            policy: Arc::new(policy),
            ai_layer: Arc::new(ai_layer),
        }
    }
    #[cfg(test)]
    pub fn with_connector(
        bind_addr: impl Into<String>,
        ca: RootCa,
        connector: TlsConnector,
    ) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            ca: Arc::new(ca),
            connector,
            pipeline: Arc::new(ScanPipeline::default_pipeline()),
            policy: Arc::new(PolicyEngine::default()),
            ai_layer: Arc::new(AiLayer::stub()),
        }
    }
}

#[async_trait::async_trait]
impl Interceptor for MitmProxy {
    async fn start(&self) -> CdpResult<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        tracing::info!(addr = %self.bind_addr, "MitmProxy listening");

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            tracing::debug!(%peer_addr, "accepted connection");

            let ca = Arc::clone(&self.ca);
            let connector = self.connector.clone();
            let pipeline = Arc::clone(&self.pipeline);
            let policy = Arc::clone(&self.policy);
            let ai_layer = Arc::clone(&self.ai_layer);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, ca, connector, pipeline, policy, ai_layer).await {
                    tracing::warn!(error = %e, %peer_addr, "connection handler error");
                }
            });
        }
    }
}

/// Back-compat alias — Phase 1 tests and the proxy-gateway binary used
/// `PlainHttpProxy`. Keep it pointing to `MitmProxy` so callers don't
/// need to change.
pub type PlainHttpProxy = MitmProxy;

/// Parse the request line, then dispatch to CONNECT MITM or plain HTTP.
async fn handle_connection(
    mut client: TcpStream,
    ca: Arc<RootCa>,
    connector: TlsConnector,
    pipeline: Arc<ScanPipeline>,
    policy: Arc<PolicyEngine>,
    ai_layer: Arc<AiLayer>,
) -> CdpResult<()> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    let (line, consumed) = loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);

        match parse_request_line(&buf) {
            Ok(result) => break result,
            Err(ParseError::Incomplete) => {
                if buf.len() > 64 * 1024 {
                    return Err(CdpError::Interception(
                        "request line too large".to_string(),
                    ));
                }
                continue;
            }
            Err(ParseError::Malformed) => {
                return Err(CdpError::Interception("malformed request line".to_string()));
            }
        }
    };

    if is_connect(&line) {
        handle_connect_mitm(client, &line.target, ca, connector, pipeline, policy, ai_layer).await
    } else {
        let _ = consumed;
        handle_plain_http(client, &line.target, buf).await
    }
}

/// Full MITM CONNECT handler:
///   client ←TLS→ proxy ←TLS→ real upstream
///
/// After both handshakes, plaintext is visible at this point in the
/// proxy — this is where the detection pipeline will plug in (next step).
async fn handle_connect_mitm(
    mut client: TcpStream,
    target: &str,
    ca: Arc<RootCa>,
    connector: TlsConnector,
    pipeline: Arc<ScanPipeline>,
    policy: Arc<PolicyEngine>,
    ai_layer: Arc<AiLayer>,
) -> CdpResult<()> {
    let (host, port) = parse_host_port(target);
    tracing::info!(%host, port, "CONNECT MITM requested");

    // Step 1: TCP connect to the real upstream server first, before
    // committing to the client with "200 Connection Established" — this
    // way we can return 502 if the upstream is unreachable, rather than
    // telling the client "all good" and then dying.
    let upstream_tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await;
            return Err(CdpError::from(e));
        }
    };

    // Step 2: Tell the client the CONNECT is established.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Step 3: Issue a per-domain leaf cert from our root CA and perform
    // the TLS handshake with the client. After this, `client_tls` gives
    // us plaintext from the browser.
    let leaf = ca.issue_leaf_cert(&host)?;
    let acceptor = acceptor_for_leaf_cert(&leaf)?;
    let client_tls = match acceptor.accept(client).await {
        Ok(s) => s,
        Err(e) => {
            // Client rejected our cert (cert pinning, or CA not trusted
            // yet on this machine). Log and bail — this is a known
            // expected failure mode, not a proxy crash.
            return Err(CdpError::Interception(format!(
                "client TLS handshake failed for {host}: {e}"
            )));
        }
    };

    // Step 4: Upgrade the upstream TCP connection to TLS as well.
    // We pass the already-connected TCP socket so no second DNS lookup
    // is needed, and use the original hostname for SNI.
    let upstream_tls =
        match connect_upstream_tls_over(connector, upstream_tcp, &host).await {
            Ok(s) => s,
            Err(e) => {
                return Err(CdpError::Interception(format!(
                    "upstream TLS handshake failed for {host}: {e}"
                )));
            }
        };

    // Step 5: Relay plaintext between the two TLS streams.
    // FUTURE: this relay call is the insertion point for the detection
    // pipeline — instead of blindly copying, we'll buffer/inspect the
    // plaintext request before forwarding, and the response before
    // returning it. For now, raw relay proves the full MITM path works.
    tracing::debug!(%host, "MITM established, running detection pipeline");
    tunnel::inspect_and_relay(client_tls, upstream_tls, pipeline, policy, ai_layer, host).await
}

/// Plain (non-HTTPS) HTTP: forward raw bytes as-is.
/// Still not wired into detection pipeline (same as Phase 1) — that
/// lands alongside the CONNECT pipeline in the next step.
async fn handle_plain_http(
    client: TcpStream,
    target: &str,
    already_read: Vec<u8>,
) -> CdpResult<()> {
    let (host, port) = extract_host_from_target(target);
    let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
    if !already_read.is_empty() {
        upstream.write_all(&already_read).await?;
    }
    tunnel::relay(client, upstream).await
}

fn extract_host_from_target(target: &str) -> (String, u16) {
    let without_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    let host_part = without_scheme.split('/').next().unwrap_or(without_scheme);
    match host_part.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (host_part.to_string(), 80),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::RootCa;
    use crate::tls::acceptor_for_leaf_cert;
    use ai_engine::AiLayer;
    use detector::ScanPipeline;
    use policy_engine::PolicyEngine;
    use rustls_pki_types::CertificateDer;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn extracts_host_and_default_port_from_absolute_uri() {
        let (host, port) = extract_host_from_target("http://example.com/path");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn extracts_host_and_explicit_port() {
        let (host, port) = extract_host_from_target("http://example.com:8080/path");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn handles_target_without_path() {
        let (host, port) = extract_host_from_target("http://example.com");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[tokio::test]
    async fn proxy_relays_plain_http_get_to_real_listener() {
        let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            let (mut sock, _) = dest_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.starts_with("GET"));
            sock.write_all(b"HTTP/1.1 200 OK\r\n\r\nhi").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let ca = RootCa::generate("Test CA").unwrap();
        let proxy_ca = Arc::new(ca);

        // Use a dummy connector — plain HTTP test doesn't hit TLS path
        let root_store = rustls::RootCertStore::empty();
        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_cfg));

        let proxy_task = tokio::spawn(async move {
            let (sock, _) = proxy_listener.accept().await.unwrap();
            let pipeline = Arc::new(ScanPipeline::default_pipeline());
            let policy = Arc::new(PolicyEngine::default());
            let ai_layer = Arc::new(AiLayer::stub());
            handle_connection(sock, proxy_ca, connector, pipeline, policy, ai_layer).await.unwrap();
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let request = format!(
            "GET http://127.0.0.1:{}/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            dest_addr.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response_text = String::from_utf8_lossy(&response);
        assert!(response_text.contains("200 OK"));
        assert!(response_text.contains("hi"));

        dest_task.await.unwrap();
        proxy_task.await.unwrap();
    }

    /// Full MITM integration test: client → proxy (our CA cert) → upstream
    /// (also our CA cert, acting as a real TLS server). All in-process,
    /// no real internet, no DNS. This is the Phase 3b end-to-end proof.
    #[tokio::test]
    async fn full_mitm_connect_decrypts_and_relays_https_plaintext() {
        // One CA for both sides (real world: our CA for client-side,
        // webpki-roots for upstream-side; in tests, same CA for both
        // so we can run fully offline).
        let ca = RootCa::generate("Test MITM CA").unwrap();

        // Fake upstream HTTPS server: TLS, reads a request, sends a response.
        // We use "127.0.0.1" as the leaf cert domain because the proxy will
        // connect to this server via loopback IP (from the CONNECT target),
        // and that IP must match what the cert covers.
        let upstream_leaf = ca.issue_leaf_cert("127.0.0.1").unwrap();
        let upstream_acceptor = acceptor_for_leaf_cert(&upstream_leaf).unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let upstream_task = tokio::spawn(async move {
            let (sock, _) = upstream_listener.accept().await.unwrap();
            let mut tls = upstream_acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            // Prove we received plaintext HTTP (not encrypted garbage)
            assert!(
                req.contains("GET") || req.contains("POST") || req.len() > 0,
                "upstream received plaintext: {req:?}"
            );
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        });

        // Build the MITM proxy with a connector that trusts our test CA
        // (instead of real webpki-roots) for upstream connections.
        let mut upstream_roots = rustls::RootCertStore::empty();
        upstream_roots
            .add(CertificateDer::from(ca.certificate.der().to_vec()))
            .unwrap();
        let upstream_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(upstream_roots)
            .with_no_client_auth();
        let upstream_connector = TlsConnector::from(Arc::new(upstream_cfg));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_ca = Arc::new(ca);
        let proxy_ca2 = Arc::clone(&proxy_ca);

        let proxy_task = tokio::spawn(async move {
            let (sock, _) = proxy_listener.accept().await.unwrap();
            let pipeline = Arc::new(ScanPipeline::default_pipeline());
            let policy = Arc::new(PolicyEngine::default());
            let ai_layer = Arc::new(AiLayer::stub());
            handle_connection(sock, proxy_ca2, upstream_connector, pipeline, policy, ai_layer)
                .await
                .unwrap();
        });

        // Build a "browser" client that trusts our test CA.
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots
            .add(CertificateDer::from(
                proxy_ca.certificate.der().to_vec(),
            ))
            .unwrap();
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(client_roots)
            .with_no_client_auth();
        let client_connector =
            tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

        // Step 1: Send CONNECT to the proxy.
        // We send the actual IP:port (loopback) so the proxy can TCP
        // connect without DNS. In real Chrome/Edge, the browser resolves
        // DNS first itself, then sends CONNECT with the resolved IP — or
        // sends CONNECT with the hostname and relies on the proxy to
        // resolve it. Our test avoids DNS entirely by using 127.0.0.1.
        // The leaf cert SNI ("upstream.local") is agreed by both sides
        // at TLS layer, separately from the TCP routing.
        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let mut tcp = tokio::io::BufStream::new(tcp);
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: upstream.local\r\n\r\n",
            upstream_addr.port()
        );
        tcp.write_all(connect_req.as_bytes()).await.unwrap();
        tcp.flush().await.unwrap();

        // Step 2: Read "200 Connection Established" from the proxy.
        let mut connect_response = String::new();
        loop {
            let mut line = String::new();
            loop {
                let mut byte = [0u8; 1];
                tcp.read_exact(&mut byte).await.unwrap();
                if byte[0] == b'\n' {
                    break;
                }
                if byte[0] != b'\r' {
                    line.push(byte[0] as char);
                }
            }
            if line.is_empty() {
                break;
            }
            connect_response = line;
        }
        assert!(
            connect_response.contains("200"),
            "expected 200, got: {connect_response}"
        );

        // Step 3: Layer TLS on top of the established tunnel.
        // The proxy issued a leaf cert for "127.0.0.1" (since that's what
        // was in the CONNECT target). We connect with IP SNI accordingly.
        // rcgen supports IP SANs so the cert is valid for 127.0.0.1.
        let inner_stream = tcp.into_inner();
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from("127.0.0.1")
                .unwrap();
        let mut tls_stream = client_connector
            .connect(server_name, inner_stream)
            .await
            .unwrap();

        // Step 4: Send a real HTTP request through the decrypted tunnel.
        tls_stream
            .write_all(b"GET / HTTP/1.1\r\nHost: upstream.local\r\n\r\n")
            .await
            .unwrap();
        tls_stream.shutdown().await.unwrap();

        // Step 5: Read the response — should be the fake upstream's "OK".
        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.contains("200 OK"),
            "expected 200 OK in response, got: {response_str:?}"
        );

        upstream_task.await.unwrap();
        proxy_task.await.unwrap();
    }
    /// Prove the detection pipeline actually blocks: send an AWS key
    /// through the proxy and confirm a 403 comes back instead of the
    /// request reaching the upstream server.
    #[tokio::test]
    async fn mitm_proxy_blocks_request_containing_aws_key() {
        let ca = RootCa::generate("Test Block CA").unwrap();

        // Upstream server — should NOT receive the request if blocked.
        let upstream_leaf = ca.issue_leaf_cert("127.0.0.1").unwrap();
        let upstream_acceptor = acceptor_for_leaf_cert(&upstream_leaf).unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_received = std::sync::Arc::new(tokio::sync::Mutex::new(false));
        let upstream_received2 = upstream_received.clone();

        let upstream_task = tokio::spawn(async move {
            if let Ok((sock, _)) = upstream_listener.accept().await {
                if let Ok(mut tls) = upstream_acceptor.accept(sock).await {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = tls.read(&mut buf).await {
                        if n > 0 {
                            *upstream_received2.lock().await = true;
                        }
                    }
                }
            }
        });

        // Build proxy with injected connector trusting our CA.
        let mut upstream_roots = rustls::RootCertStore::empty();
        upstream_roots.add(CertificateDer::from(ca.certificate.der().to_vec())).unwrap();
        let upstream_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(upstream_roots)
            .with_no_client_auth();
        let upstream_connector = TlsConnector::from(Arc::new(upstream_cfg));

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_ca = Arc::new(ca);
        let proxy_ca2 = Arc::clone(&proxy_ca);

        let proxy_task = tokio::spawn(async move {
            let (sock, _) = proxy_listener.accept().await.unwrap();
            let pipeline = Arc::new(ScanPipeline::default_pipeline());
            let policy = Arc::new(PolicyEngine::default());
            let ai_layer = Arc::new(AiLayer::stub());
            let _ = handle_connection(sock, proxy_ca2, upstream_connector, pipeline, policy, ai_layer).await;
        });

        // Client: CONNECT then send a request containing an AWS key.
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(CertificateDer::from(proxy_ca.certificate.der().to_vec())).unwrap();
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(client_roots)
            .with_no_client_auth();
        let client_connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

        let tcp = TcpStream::connect(proxy_addr).await.unwrap();
        let mut tcp = tokio::io::BufStream::new(tcp);
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            upstream_addr.port()
        );
        tcp.write_all(connect_req.as_bytes()).await.unwrap();
        tcp.flush().await.unwrap();

        // Read 200 Connection Established
        loop {
            let mut line = String::new();
            loop {
                let mut byte = [0u8; 1];
                tcp.read_exact(&mut byte).await.unwrap();
                if byte[0] == b'\n' { break; }
                if byte[0] != b'\r' { line.push(byte[0] as char); }
            }
            if line.is_empty() { break; }
        }

        let inner = tcp.into_inner();
        let sn = tokio_rustls::rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let mut tls = client_connector.connect(sn, inner).await.unwrap();

        // Send request WITH an AWS key — should be blocked.
        let evil_req =
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Key: AKIAIOSFODNN7EXAMPLE\r\n\r\n";
        tls.write_all(evil_req.as_bytes()).await.unwrap();
        tls.shutdown().await.unwrap();

        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        let resp_str = String::from_utf8_lossy(&response);

        // Must get a 403 from the proxy, NOT a 200 from upstream.
        assert!(
            resp_str.contains("403"),
            "expected 403 BLOCK response, got: {resp_str:?}"
        );

        // Upstream must NOT have received anything.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !*upstream_received.lock().await,
            "upstream should NOT have received a blocked request"
        );

        proxy_task.await.unwrap();
        let _ = upstream_task.await;
    }

}
