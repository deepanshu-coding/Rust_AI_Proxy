use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const API_ADDR: &str = "127.0.0.1:8080";

pub async fn start() -> io::Result<()> {
    let listener = TcpListener::bind(API_ADDR).await?;

    println!("REST API          : http://{API_ADDR}");
    println!("GET /api/stats    : live metrics");
    println!("GET /api/events   : recent audit events");

    loop {
        let (stream, _) = listener.accept().await?;

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("REST API error: {e}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0u8; 8192];

    let n = stream.read(&mut buffer).await?;

    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..n]);

    let first_line = request.lines().next().unwrap_or("");

    let mut parts = first_line.split_whitespace();

    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    // CORS preflight
    if method == "OPTIONS" {
        write_response(
            &mut stream,
            204,
            "text/plain",
            "",
        )
        .await?;

        return Ok(());
    }

    match (method, path) {
        ("GET", "/api/stats") => {
            let snapshot = metrics::global().snapshot();

            let body = serde_json::json!({
                "total": snapshot.total_requests,
                "allowed": snapshot.allowed_requests,
                "blocked": snapshot.blocked_requests,
                "redacted": snapshot.redacted_requests,
                "warned": snapshot.warned_requests,
                "avg_risk": 0
            })
            .to_string();

            write_response(
                &mut stream,
                200,
                "application/json",
                &body,
            )
            .await?;
        }

        ("GET", "/api/events") => {
            let events = logger::recent_events();

            let body = serde_json::to_string(&events)
                .unwrap_or_else(|_| "[]".to_string());

            write_response(
                &mut stream,
                200,
                "application/json",
                &body,
            )
            .await?;
        }

        ("GET", "/") => {
            write_response(
                &mut stream,
                200,
                "text/plain",
                "D.P Sharma Security Proxy REST API",
            )
            .await?;
        }

        _ => {
            write_response(
                &mut stream,
                404,
                "application/json",
                r#"{"error":"Not found"}"#,
            )
            .await?;
        }
    }

    Ok(())
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    let status_text = match status {
        200 => "OK",
        204 => "No Content",
        404 => "Not Found",
        _ => "OK",
    };

    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.as_bytes().len()
    );

    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;

    Ok(())
}