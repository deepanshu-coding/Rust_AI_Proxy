//! TLS termination — the core of "decrypting HTTPS to inspect it".
//!
//! ## How this fits with `ca.rs`
//!
//! `ca::RootCa::issue_leaf_cert(domain)` already produces a signed
//! certificate + private key for any domain, in DER form. This module's
//! job is purely mechanical: take that DER cert/key pair, build a
//! `rustls::ServerConfig` from it, and use that config to perform an
//! actual TLS server-side handshake with the connecting client (the
//! browser). Once that handshake completes, we have a `TlsStream` we can
//! read/write plaintext through — which is the entire point of this
//! whole project.
//!
//! ## What this module does NOT do
//!
//! It does not yet connect to the real upstream server as a TLS
//! *client* (that's the other half of full MITM — needed so the proxy
//! can actually forward the now-visible plaintext request onward over a
//! real HTTPS connection). That upstream-client half, plus wiring this
//! into `plain_proxy::handle_connect` to replace the raw `tunnel::relay`
//! call, is the next piece of work after this module is verified in
//! isolation.
//!
//! ## Honest verification boundary
//!
//! Everything in this module is testable with real (if synthetic)
//! certs, entirely within this sandbox — a TLS handshake between two
//! local Tokio tasks doesn't need Windows or a real browser. What
//! still can't be verified here: how an actual Chrome/Edge/Firefox
//! reacts to certs from a CA it was told to trust via `certutil`. That
//! remains a Windows-side check.

use crate::ca::LeafCert;
use common::{CdpError, CdpResult};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Build a `rustls::ServerConfig` (wrapped in a Tokio `TlsAcceptor`) from
/// a single leaf certificate. One of these is built per-domain, since
/// each domain gets its own cert/key pair from `ca::issue_leaf_cert`.
pub fn acceptor_for_leaf_cert(leaf: &LeafCert) -> CdpResult<TlsAcceptor> {
    let cert_der = CertificateDer::from(leaf.cert_der.clone());
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_der.clone()));

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| {
            CdpError::Interception(format!("failed to build TLS server config: {e}"))
        })?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Perform the actual TLS handshake with a connected client, using a
/// per-domain acceptor. Returns a `TlsStream` that can be read/written
/// as plaintext once the handshake completes.
pub async fn terminate_client_tls(
    acceptor: &TlsAcceptor,
    client_socket: TcpStream,
) -> CdpResult<ServerTlsStream<TcpStream>> {
    acceptor.accept(client_socket).await.map_err(|e| {
        CdpError::Interception(format!("TLS handshake with client failed: {e}"))
    })
}

/// Shared connector for talking to *real* upstream HTTPS servers (the
/// other half of MITM — once we've decrypted the client's request, we
/// need to forward it onward over a genuine, properly-validated HTTPS
/// connection to whatever the client originally asked for).
///
/// Uses Mozilla's curated root CA list (`webpki-roots`) — the same trust
/// basis real browsers use — NOT our own proxy CA, since upstream
/// servers present their own real certificates, not ones we generated.
/// This is built once and reused across every connection (building a
/// fresh `ClientConfig` per-connection is wasteful and unnecessary; the
/// trust roots never change at runtime).
fn upstream_connector() -> &'static TlsConnector {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    CONNECTOR.get_or_init(|| {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    })
}

/// Open a real, validated TLS connection to the actual destination
/// server (e.g. the real `example.com:443`), as a TLS *client* — the
/// proxy acting like a normal browser would toward the real internet.
pub async fn connect_upstream_tls(
    host: &str,
    port: u16,
) -> CdpResult<ClientTlsStream<TcpStream>> {
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| CdpError::Interception(format!("upstream TCP connect failed: {e}")))?;

    connect_upstream_tls_over(upstream_connector().clone(), tcp, host).await
}

/// Same as `connect_upstream_tls`, but with an injectable connector —
/// lets tests substitute a connector that trusts a locally-generated
/// test CA instead of the real public webpki-roots, so the connection
/// logic can be verified against a real (if synthetic) TLS server
/// without depending on outbound internet access or a specific
/// real-world certificate being valid at test-run time.
pub async fn connect_upstream_tls_with(
    connector: TlsConnector,
    host: &str,
    port: u16,
) -> CdpResult<ClientTlsStream<TcpStream>> {
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| CdpError::Interception(format!("upstream TCP connect failed: {e}")))?;

    connect_upstream_tls_over(connector, tcp, host).await
}

/// Core TLS upgrade function — wraps an already-connected `TcpStream`
/// in TLS using the given connector and SNI hostname. Called by both
/// `connect_upstream_tls` and `connect_upstream_tls_with`. Also usable
/// directly in tests that need to control both the TCP connection and
/// the trust store independently.
pub async fn connect_upstream_tls_over(
    connector: TlsConnector,
    tcp: TcpStream,
    server_name_for_sni: &str,
) -> CdpResult<ClientTlsStream<TcpStream>> {
    let server_name = ServerName::try_from(server_name_for_sni.to_string())
        .map_err(|e| CdpError::Interception(format!("invalid upstream hostname: {e}")))?;

    connector.connect(server_name, tcp).await.map_err(|e| {
        CdpError::Interception(format!("upstream TLS handshake failed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::RootCa;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    /// Builds a rustls ClientConfig that trusts our test root CA — the
    /// equivalent of what Windows' Trust Store does after `install-cert`,
    /// but entirely in-process so this test needs no OS-level trust
    /// store and no real Windows machine.
    fn client_config_trusting(ca: &RootCa) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        let ca_cert_der = CertificateDer::from(ca.certificate.der().to_vec());
        roots.add(ca_cert_der).unwrap();

        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    #[tokio::test]
    async fn full_tls_handshake_succeeds_with_leaf_cert_trusted_via_our_ca() {
        // 1. Generate a root CA (same mechanism as `cli generate-ca`).
        let ca = RootCa::generate("Test CDP Proxy CA").unwrap();

        // 2. Issue a leaf cert for a fake domain (same mechanism the
        //    proxy will use per-CONNECT once wired into plain_proxy).
        let leaf = ca.issue_leaf_cert("test.local").unwrap();

        // 3. Build a TLS acceptor (the "server side" — what our proxy
        //    presents to the real browser) from that leaf cert.
        let acceptor = acceptor_for_leaf_cert(&leaf).unwrap();

        // 4. Build a TLS connector (the "client side" — standing in for
        //    a real browser) that trusts our root CA, exactly like a
        //    Windows browser would after `install-cert`.
        let client_config = client_config_trusting(&ca);
        let connector = TlsConnector::from(Arc::new(client_config));

        // 5. Real TCP listener + real TCP connection between two local
        //    Tokio tasks, then layer TLS on top of that real socket.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls_stream = terminate_client_tls(&acceptor, socket).await.unwrap();

            // Prove plaintext is visible post-handshake: read a request,
            // write back a response, just like the proxy will eventually
            // do with the detection pipeline in between.
            let mut buf = [0u8; 1024];
            let n = tls_stream.read(&mut buf).await.unwrap();
            let received = String::from_utf8_lossy(&buf[..n]).to_string();
            assert_eq!(received, "hello from client");

            tls_stream
                .write_all(b"hello from server")
                .await
                .unwrap();
            tls_stream.shutdown().await.unwrap();
        });

        let client_task = tokio::spawn(async move {
            let tcp_stream = TcpStream::connect(addr).await.unwrap();
            let domain = ServerName::try_from("test.local").unwrap();
            let mut tls_stream = connector.connect(domain, tcp_stream).await.unwrap();

            tls_stream.write_all(b"hello from client").await.unwrap();

            let mut buf = Vec::new();
            tls_stream.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, b"hello from server");
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        client_result.unwrap();
    }

    #[tokio::test]
    async fn handshake_fails_when_client_does_not_trust_the_ca() {
        // Same setup, but the "client" trusts a DIFFERENT root CA than
        // the one that signed the leaf cert — this must fail, proving
        // our TLS termination doesn't silently accept untrusted certs.
        let real_ca = RootCa::generate("Real CA").unwrap();
        let leaf = real_ca.issue_leaf_cert("test.local").unwrap();
        let acceptor = acceptor_for_leaf_cert(&leaf).unwrap();

        let wrong_ca = RootCa::generate("Wrong CA").unwrap();
        let client_config = client_config_trusting(&wrong_ca);
        let connector = TlsConnector::from(Arc::new(client_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            // We expect this to fail (client will abort the handshake
            // because it doesn't trust our cert's issuer).
            let result = terminate_client_tls(&acceptor, socket).await;
            assert!(result.is_err());
        });

        let client_task = tokio::spawn(async move {
            let tcp_stream = TcpStream::connect(addr).await.unwrap();
            let domain = ServerName::try_from("test.local").unwrap();
            let result = connector.connect(domain, tcp_stream).await;
            assert!(result.is_err());
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        server_result.unwrap();
        client_result.unwrap();
    }

    #[tokio::test]
    async fn upstream_tls_connect_and_relay_with_injected_trust_store() {
        // Generate a test CA and issue a leaf cert for "upstream.local".
        let ca = RootCa::generate("Test Upstream CA").unwrap();
        let leaf = ca.issue_leaf_cert("upstream.local").unwrap();
        let server_acceptor = acceptor_for_leaf_cert(&leaf).unwrap();

        // Build a client-side connector that trusts ONLY our test CA —
        // same code path as the real upstream_connector() with
        // webpki-roots, just a different (injected) root store.
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca.certificate.der().to_vec()))
            .unwrap();
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        // Fake upstream server: TLS, echoes data back.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = terminate_client_tls(&server_acceptor, socket)
                .await
                .unwrap();
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            tls.shutdown().await.unwrap();
        });

        // Connect to the real (loopback) IP directly via TcpStream —
        // no DNS needed — then layer TLS on top using our injected
        // connector with "upstream.local" as the SNI name.
        // This is exactly how plain_proxy.rs will call it: it will
        // have already resolved host:port via the CONNECT request line,
        // TCP-connect there, then call connect_upstream_tls_over.
        let tcp = TcpStream::connect(server_addr).await.unwrap();
        let mut upstream =
            connect_upstream_tls_over(connector, tcp, "upstream.local")
                .await
                .unwrap();

        // Prove decrypted plaintext flows both ways.
        upstream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        upstream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        upstream.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[test]
    fn acceptor_builds_successfully_from_valid_leaf_cert() {
        let ca = RootCa::generate("Test CA").unwrap();
        let leaf = ca.issue_leaf_cert("example.com").unwrap();
        let result = acceptor_for_leaf_cert(&leaf);
        assert!(result.is_ok());
    }
}
