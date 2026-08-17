//! Minimal HTTP/1.x request-line parsing.
//!
//! Only does enough to figure out: is this a CONNECT (HTTPS tunnel setup)
//! or a plain HTTP request, and where does it need to go. Full header
//! parsing for the plaintext inspection pipeline (extractor/detector) is
//! a Phase 3 concern, once we're actually decrypting HTTPS — for plain
//! HTTP, headers are forwarded as-is for now.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    pub method: String,
    /// For CONNECT: "host:port". For plain HTTP: the request target
    /// (may be an absolute URI or a path, depending on the client).
    pub target: String,
    pub version: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("incomplete request — need more bytes")]
    Incomplete,
    #[error("malformed request line")]
    Malformed,
}

/// Parse just the first line of an HTTP request out of a raw byte buffer.
/// Returns the request line plus how many bytes it consumed (so the
/// caller can find where headers/body start).
pub fn parse_request_line(buf: &[u8]) -> Result<(RequestLine, usize), ParseError> {
    let text = std::str::from_utf8(buf).map_err(|_| ParseError::Malformed)?;

    let line_end = text.find("\r\n").ok_or(ParseError::Incomplete)?;
    let line = &text[..line_end];

    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or(ParseError::Malformed)?;
    let target = parts.next().ok_or(ParseError::Malformed)?;
    let version = parts.next().ok_or(ParseError::Malformed)?;

    Ok((
        RequestLine {
            method: method.to_string(),
            target: target.to_string(),
            version: version.to_string(),
        },
        line_end + 2, // include the \r\n
    ))
}

/// True if this request line is a CONNECT (the method browsers use to
/// set up an HTTPS tunnel through a proxy).
pub fn is_connect(line: &RequestLine) -> bool {
    line.method.eq_ignore_ascii_case("CONNECT")
}

/// Extract host and port from a CONNECT target like "example.com:443".
/// Defaults to port 443 if no port is present (shouldn't normally happen
/// for CONNECT, but we don't want to panic on a malformed client).
pub fn parse_host_port(target: &str) -> (String, u16) {
    match target.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse().unwrap_or(443);
            (host.to_string(), port)
        }
        None => (target.to_string(), 443),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_request_line() {
        let raw = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (line, consumed) = parse_request_line(raw).unwrap();
        assert_eq!(line.method, "CONNECT");
        assert_eq!(line.target, "example.com:443");
        assert_eq!(line.version, "HTTP/1.1");
        assert_eq!(consumed, "CONNECT example.com:443 HTTP/1.1\r\n".len());
    }

    #[test]
    fn parses_plain_get_request_line() {
        let raw = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (line, _) = parse_request_line(raw).unwrap();
        assert_eq!(line.method, "GET");
        assert_eq!(line.target, "http://example.com/");
    }

    #[test]
    fn incomplete_request_returns_incomplete_error() {
        let raw = b"GET http://exam";
        let result = parse_request_line(raw);
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn malformed_request_line_returns_error() {
        let raw = b"NOTHTTPATALL\r\n\r\n";
        let result = parse_request_line(raw);
        assert!(matches!(result, Err(ParseError::Malformed)));
    }

    #[test]
    fn is_connect_detects_connect_method() {
        let line = RequestLine {
            method: "CONNECT".into(),
            target: "example.com:443".into(),
            version: "HTTP/1.1".into(),
        };
        assert!(is_connect(&line));
    }

    #[test]
    fn is_connect_rejects_get_method() {
        let line = RequestLine {
            method: "GET".into(),
            target: "/".into(),
            version: "HTTP/1.1".into(),
        };
        assert!(!is_connect(&line));
    }

    #[test]
    fn parse_host_port_splits_correctly() {
        let (host, port) = parse_host_port("example.com:443");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_host_port_defaults_to_443_without_port() {
        let (host, port) = parse_host_port("example.com");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn is_connect_case_insensitive() {
        let line = RequestLine {
            method: "connect".into(),
            target: "example.com:443".into(),
            version: "HTTP/1.1".into(),
        };
        assert!(is_connect(&line));
    }
}
