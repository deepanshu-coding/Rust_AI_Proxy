//! Bidirectional byte tunnel — used after a CONNECT handshake.
//!
//! Phase 1 honesty check: this does NOT decrypt or inspect HTTPS traffic.
//! It proves the proxy can sit in the middle of a real TLS handshake
//! between client and server and pass bytes through correctly (the
//! browser will see a valid TLS connection end-to-end). Actual
//! inspection of this traffic requires TLS termination, which is
//! Phase 3 — replacing this raw copy with a real MITM handshake.

use common::{CdpError, CdpResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Copy bytes in both directions between `client` and `upstream` until
/// either side closes. Used for plain CONNECT tunneling.
pub async fn relay(mut client: TcpStream, mut upstream: TcpStream) -> CdpResult<()> {
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let client_to_upstream = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = client_read
                .read(&mut buf)
                .await
                .map_err(CdpError::from)?;
            if n == 0 {
                break;
            }
            upstream_write
                .write_all(&buf[..n])
                .await
                .map_err(CdpError::from)?;
        }
        upstream_write.shutdown().await.map_err(CdpError::from)
    };

    let upstream_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = upstream_read
                .read(&mut buf)
                .await
                .map_err(CdpError::from)?;
            if n == 0 {
                break;
            }
            client_write
                .write_all(&buf[..n])
                .await
                .map_err(CdpError::from)?;
        }
        client_write.shutdown().await.map_err(CdpError::from)
    };

    // Run both directions concurrently; if either errors, we still let
    // the other finish gracefully rather than panicking the connection.
    let (a, b) = tokio::join!(client_to_upstream, upstream_to_client);
    a.and(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn relay_copies_bytes_both_directions() {
        // Set up a fake "upstream" server that echoes back uppercase.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap();
            let reply = String::from_utf8_lossy(&buf[..n]).to_uppercase();
            sock.write_all(reply.as_bytes()).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        // Set up a "client-facing" listener that our relay will sit behind.
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        let relay_task = tokio::spawn(async move {
            let (client_sock, _) = client_listener.accept().await.unwrap();
            let upstream_sock = TcpStream::connect(upstream_addr).await.unwrap();
            relay(client_sock, upstream_sock).await.unwrap();
        });

        // Act as the "client".
        let mut client = TcpStream::connect(client_addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert_eq!(response, b"HELLO");

        upstream_task.await.unwrap();
        relay_task.await.unwrap();
    }
}

/// Relay bytes between two TLS streams (one client-facing ServerTlsStream,
/// one upstream-facing ClientTlsStream). Conceptually identical to
/// `relay()` but operates on the decrypted plaintext layer — this is
/// where the detection pipeline will be inserted next.
pub async fn relay_tls(
    client: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    upstream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> CdpResult<()> {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    let client_to_upstream = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = cr.read(&mut buf).await.map_err(CdpError::from)?;
            if n == 0 { break; }
            uw.write_all(&buf[..n]).await.map_err(CdpError::from)?;
        }
        uw.shutdown().await.map_err(CdpError::from)
    };

    let upstream_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = ur.read(&mut buf).await.map_err(CdpError::from)?;
            if n == 0 { break; }
            cw.write_all(&buf[..n]).await.map_err(CdpError::from)?;
        }
        cw.shutdown().await.map_err(CdpError::from)
    };

    let (a, b) = tokio::join!(client_to_upstream, upstream_to_client);
    a.and(b)
}

/// Inspection-aware relay: reads the full client request, runs the
/// detection + policy pipeline, then either forwards (Allow/Redact) or
/// drops the connection (Block). The response from upstream is relayed
/// back to the client as-is (response inspection is a future extension).
///
/// This replaces the raw `relay_tls` call for CONNECT tunnels — this is
/// the point where the proxy becomes an actual DLP system, not just a
/// transparent pass-through.
pub async fn inspect_and_relay(
    mut client: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    mut upstream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    pipeline: std::sync::Arc<detector::ScanPipeline>,
    policy: std::sync::Arc<policy_engine::PolicyEngine>,
    ai_layer: std::sync::Arc<ai_engine::AiLayer>,
    host: String,
) -> CdpResult<()> {
    use common::Decision;

    let start = std::time::Instant::now();

    // Step 1: Buffer the request until headers complete or size limit.
    let mut req_buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    loop {
        let n = client.read(&mut tmp).await?;
        req_buf.extend_from_slice(&tmp[..n]);
        if n == 0 || req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if req_buf.len() > 2 * 1024 * 1024 {
            tracing::warn!(%host, "request too large to buffer, forwarding raw");
            upstream.write_all(&req_buf).await?;
            return relay_tls(client, upstream).await;
        }
    }

    if req_buf.is_empty() {
        return Ok(());
    }

    // Step 2: Rule-based detection pipeline.
    let text = String::from_utf8_lossy(&req_buf);
    let findings = pipeline.scan(&text);
    let triggered = pipeline.triggered_names(&findings);
    let rule_based_risk: u32 = findings.iter().map(|f| f.risk).sum();

    // Step 2.5: SLM advisory analysis — runs AFTER rule-based detectors,
    // feeds them their findings as context. SLM is advisor only: it cannot
    // lower the rule-based score, and the Policy Engine (Step 3) makes
    // the final decision — not the SLM.
    let (combined_risk, slm_result) = ai_layer
        .analyse_with_findings(&text, &host, None, &findings, rule_based_risk)
        .await;

    tracing::info!(
        %host,
        rule_based_risk,
        combined_risk    = combined_risk.combined,
        slm_class        = %slm_result.classification,
        slm_confidence   = slm_result.confidence,
        slm_recommended  = %slm_result.recommended_action,
        "combined risk after SLM advisory"
    );

    // Step 3: Policy Engine makes the FINAL decision using the combined score.
    // The SLM's recommended_action is logged but never directly acted upon —
    // the Policy Engine is the sole decision-making authority.
    let (risk_score, decision) = policy.evaluate_score(combined_risk.combined);
    let latency_ms = start.elapsed().as_millis() as u64;

    // Audit log includes both rule-based and combined scores for transparency.
    logger::AuditLogger::emit(
        &host,
        &decision.to_string(),
        risk_score,
        triggered.iter().map(|s| s.to_string()).collect(),
        findings.len(),
        latency_ms,
    );
    
    metrics::record_global(decision);

    tracing::info!(
        %host, risk_score, decision = %decision,
        finding_count = findings.len(), latency_ms,
        "inspection result"
    );

    match decision {
        Decision::Block => {
            tracing::warn!(%host, risk_score, "request BLOCKED by policy");
            let block_response = format!(
                "HTTP/1.1 403 Forbidden\r\n\
                 Content-Type: text/plain\r\n\
                 X-CDP-Decision: BLOCK\r\n\
                 X-CDP-Risk-Score: {risk_score}\r\n\
                 Content-Length: 47\r\n\r\n\
                 Request blocked: confidential data detected by CDP."
            );
            let _ = client.write_all(block_response.as_bytes()).await;
            let _ = client.shutdown().await;
            let _ = upstream.shutdown().await;
            Ok(())
        }

        Decision::Redact => {
            tracing::info!(%host, risk_score, "request REDACTED before forwarding");
            let regex_d = detector::RegexDetector;
            let kw_d = detector::KeywordDetector;
            let redacted = kw_d.redact(&regex_d.redact(&text));
            upstream.write_all(redacted.as_bytes()).await?;
            relay_tls(client, upstream).await
        }

        Decision::Allow | Decision::Warn => {
            // Forward the original request unchanged.
            upstream.write_all(&req_buf).await?;
            relay_tls(client, upstream).await
        }
    }
}
