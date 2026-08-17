//! CDP Proxy Gateway — startup, wiring, and run loop.
//!
//! Startup sequence:
//!   1. Load policy from `policies/default.toml` (fallback to defaults)
//!   2. Load or generate root CA from `certs/`
//!   3. Initialise AI layer (stub by default — swap for real SLM here)
//!   4. Start MitmProxy with all three components injected
//!
//! ## Swapping the AI analyser
//!
//! To replace the stub with a real local SLM or cloud LLM, change the
//! ONE line marked "AI LAYER CONFIGURATION" below. Everything else —
//! the proxy, detectors, policy engine — remains completely unchanged.
//!
//! Example (local SLM via HTTP/Ollama):
//! ```ignore
//! use ai_engine::{AiLayer, GenericAnalyzer, HttpModelRunner};
//! let ai = AiLayer::new(
//!     Arc::new(GenericAnalyzer::new(HttpModelRunner::new("http://localhost:11434"))),
//!     0.5,  // blend factor: SLM can raise score by up to 50% of its weighted contribution
//! );
//! ```
mod api;
use ai_engine::AiLayer;
use config::PolicyLoader;
use interceptor::ca::RootCa;
use interceptor::plain_proxy::MitmProxy;
use interceptor::Interceptor;
use std::path::PathBuf;


const BIND_ADDR: &str = "127.0.0.1:8888";
const CA_COMMON_NAME: &str = "EnaLisis CDP Proxy Root CA";

#[tokio::main]
async fn main() {
    logger::init_logging();
    tracing::info!("cdp-proxy-gateway starting");

    let workspace_root = PathBuf::from(
        std::env::current_dir().expect("cannot read current dir"),
    );

    // ── 1. Policy ──────────────────────────────────────────────────────────
    let loaded_policy = PolicyLoader::load_or_default(&workspace_root);
    tracing::info!(
        block_at  = loaded_policy.block_at,
        redact_at = loaded_policy.redact_at,
        rules     = loaded_policy.rules.len(),
        "policy loaded"
    );
    let policy_engine = policy_engine::PolicyEngine::from_config(&loaded_policy);

    // ── 2. Root CA ─────────────────────────────────────────────────────────
    let certs_dir = workspace_root.join("certs");
    let ca = match RootCa::load_or_generate(&certs_dir, CA_COMMON_NAME) {
        Ok(ca) => ca,
        Err(e) => {
            eprintln!("Fatal: could not load/generate root CA: {e}");
            std::process::exit(1);
        }
    };

    // ── 3. AI LAYER CONFIGURATION ──────────────────────────────────────────
    // Default: stub analyser — zero inference, proxy behaves exactly as
    // it did before SLM integration (rule-based detection only).
    //
    // To enable a real SLM: replace AiLayer::stub() with:
    //   AiLayer::new(Arc::new(GenericAnalyzer::new(YourModelRunner)), blend)
    //
    // blend_factor controls how much the SLM can raise the combined score:
    //   0.0 = SLM has no effect (safe default during evaluation)
    //   0.5 = SLM can add up to 50% of its weighted score (recommended)
    //   1.0 = SLM fully contributes (use only after tuning)
    let ai_layer = AiLayer::stub();

    tracing::info!(
        analyzer  = %ai_layer.analyzer_name(),
        available = ai_layer.is_available(),
        "AI layer initialised"
    );
    // ── 4. Start REST API ─────────────────────────────────────────────────
    tokio::spawn(async {
        if let Err(e) = api::start().await {
            eprintln!("REST API stopped: {e}");
        }
    });

    // ── 4. Start proxy ─────────────────────────────────────────────────────
    println!("CDP Proxy Gateway — listening on {BIND_ADDR}");
    println!(
        "Policy  : block≥{} | redact≥{} | rules: {}",
        loaded_policy.block_at,
        loaded_policy.redact_at,
        loaded_policy.rules.len()
    );
    println!("AI layer: {} ({})",
        ai_layer.analyzer_name(),
        if ai_layer.is_available() { "available" } else { "unavailable — rule-based only" }
    );
    println!("Root CA : {}", certs_dir.join("ca-cert.pem").display());
    println!();
    println!("Ensure root CA is trusted : cargo run --bin cli -- install-cert");
    println!("Enable system proxy       : cargo run --bin cli -- enable-proxy");

    let proxy = MitmProxy::new_with_ai(BIND_ADDR, ca, policy_engine, ai_layer);
    if let Err(e) = proxy.start().await {
        tracing::error!(error = %e, "proxy-gateway exited with error");
        eprintln!("Fatal: {e}");
        std::process::exit(1);
    }
}
