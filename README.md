# Rust based AI-Proxy (UI + Secure Web Gateway + DLP)

This is the **enterprise evolution** of the original Python/FastAPI `cdp-proxy`
content scanner - same detection philosophy (Regex + Keyword + future SLM,
Allow/Redact/Block policy), rebuilt as a **transparent, system-wide Windows
network interceptor** instead of an API endpoint clients call manually.

---

## Current Status: Phase 4 - Windows System Proxy Registration 

As of this commit:

  -  Full Cargo workspace compiles cleanly (`cargo build`)
  -  All 81 unit + integration tests pass (`cargo test`)
  -  Full MITM pipeline verified in-process:
  - TLS termination (client ↔ proxy)
  - Upstream TLS client (proxy ↔ server)
  - Detection: RegexDetector + KeywordDetector (8 regex patterns + credential keywords)
  - Policy: BLOCK → 403 (upstream never reached), REDACT → sanitised forward, ALLOW → passthrough
  - Integration test: AWS key in HTTPS request → 403, upstream received nothing ✓
  -  `interceptor::system_proxy` - WinINet registry + `InternetSetOption` notification.
  Windows deps are `cfg`-gated so Linux build is clean. Returns clear error on non-Windows.
  -  Complete CLI: `generate-ca`, `install-cert`, `uninstall-cert`, `enable-proxy`,
  `disable-proxy`, `status`, `start`, `stop`
  -  **Pending your Windows confirmation (cannot verify from this sandbox):**
  - `install-cert` → "EnaLisis CDP Proxy Root CA" appears in `certmgr.msc`
  - `enable-proxy` → Windows Settings → Network → Proxy shows `127.0.0.1:8888`
  - Browser HTTPS → no cert warning, green padlock, traffic flows through proxy

## Build, Test & Run

```powershell
cargo build
cargo test
```

### Complete Windows setup

```powershell
# Step 1 (as Administrator) — generates CA, installs cert, enables proxy:
cargo run --bin cli -- start

# Step 2 (any terminal) — starts the MITM proxy:
cargo run --bin proxy-gateway
```

Then open Chrome/Edge → any HTTPS site. You should see a green padlock with
no certificate warning. Check `certmgr.msc` → Trusted Root CAs for
"EnaLisis CDP Proxy Root CA" and Windows Settings → Network → Proxy for
`127.0.0.1:8888`.

### Manual step-by-step (if `start` fails at any point)

```powershell
cargo run --bin cli -- generate-ca
cargo run --bin cli -- install-cert     # must be Administrator
cargo run --bin cli -- enable-proxy
cargo run --bin proxy-gateway
```

### Status / teardown

```powershell
cargo run --bin cli -- status           # show CA / proxy / trust store state
cargo run --bin cli -- stop             # disable system proxy
cargo run --bin cli -- uninstall-cert   # remove CA from Trust Store
```

Requires Rust stable — install via `rustup` from https://rustup.rs


## Roadmap

1.  Phase 1 — plain HTTP proxy (TCP listener, CONNECT tunneling)
2.  Phase 2 — root CA generation + per-domain leaf cert signing (openssl-verified)
3.  Phase 2b — `install-cert` / `uninstall-cert` CLI (logic verified; Windows confirmation pending)
4.  Phase 3a — TLS termination module (`tls.rs`), full handshake test in-process
5.  Phase 3b — MITM wired into live proxy (`handle_connect_mitm`)
6.  Phase 3c — Detection pipeline wired: RegexDetector + KeywordDetector + PolicyEngine
   inline in HTTPS stream; BLOCK test verified end-to-end
7.  Phase 4 — Windows system proxy: `enable-proxy` / `disable-proxy` CLI; `start` / `stop`
   one-shot commands; `status` dashboard (Windows behavior pending your confirmation)
8.  Phase 5 (future) — WFP kernel callout driver for bypass-resistant capture
9.  Response body inspection (currently only request is inspected)
10.  Structured audit log events per request (tracing logs exist; structured JSON per-request pending)
11.  `extractor` crate — PDF, DOCX, image OCR for file-upload inspection
12.  `config` crate — load `policies/*.toml` into PolicyEngine (thresholds currently hardcoded)
13.  Dashboard — web UI for live traffic / metrics / alerts


## Why Rust, Why Not Reuse the Python Proxy Directly

The Python FastAPI proxy is an **API-level scanner**: a client explicitly
sends content to `POST /scan`. It has no way to see traffic that isn't
deliberately routed to it.

This project's top requirement is **transparent, system-wide interception** —
every app's outgoing HTTP/HTTPS traffic must be inspected automatically,
without any app being aware the proxy exists. That requires OS-level traffic
redirection (system proxy settings or WFP) and inline TLS termination —
capabilities a Python REST API does not have and was never designed for.
Rust was chosen for performance (sub-millisecond inline traffic inspection),
memory safety in a security-critical path, and first-class Windows
system-level API bindings.
