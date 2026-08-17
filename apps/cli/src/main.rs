//! CLI for managing the CDP proxy.
//!
//! Commands:
//!   generate-ca     — generate root CA into ./certs/
//!   install-cert    — install root CA into Windows Trust Store (requires Admin)
//!   uninstall-cert  — remove root CA from Windows Trust Store
//!   enable-proxy    — register 127.0.0.1:8888 as Windows system proxy
//!   disable-proxy   — remove the system proxy setting
//!   status          — show current proxy and cert state
//!   start           — generate CA, install cert, enable proxy, start gateway
//!   stop            — disable proxy (gateway itself stopped via Ctrl-C)

use interceptor::ca::RootCa;
use interceptor::cert_store;
use interceptor::system_proxy;
use std::path::PathBuf;

const CA_COMMON_NAME: &str = "EnaLisis CDP Proxy Root CA";
const PROXY_HOST: &str = "127.0.0.1";
const PROXY_PORT: u16 = 8888;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");

    match command {
        "generate-ca"   => generate_ca(),
        "install-cert"  => install_cert(),
        "uninstall-cert"=> uninstall_cert(),
        "enable-proxy"  => cmd_enable_proxy(),
        "disable-proxy" => cmd_disable_proxy(),
        "status"        => cmd_status(),
        "start"         => cmd_start(),
        "stop"          => cmd_stop(),
        _               => print_help(),
    }
}

fn certs_dir() -> PathBuf { PathBuf::from("certs") }

// ─── CA management ───────────────────────────────────────────────────────────

fn generate_ca() {
    let dir = certs_dir();
    match RootCa::load_or_generate(&dir, CA_COMMON_NAME) {
        Ok(_) => {
            println!("Root CA ready at: {}", dir.display());
            println!("  ca-cert.pem  — install this into Windows Trust Store");
            println!("  ca-key.pem   — KEEP PRIVATE, never share or commit");
        }
        Err(e) => { eprintln!("Failed: {e}"); std::process::exit(1); }
    }
}

fn install_cert() {
    let cert_path = certs_dir().join("ca-cert.pem");
    if !cert_path.exists() {
        eprintln!("No CA found at {}. Run `cli generate-ca` first.", cert_path.display());
        std::process::exit(1);
    }
    println!("Installing {} into Windows Trusted Root store...", cert_path.display());
    println!("(Requires Administrator privileges)");
    match cert_store::install_root_ca(&cert_path) {
        Ok(()) => println!("Success. Root CA is now trusted on this machine."),
        Err(e) => { eprintln!("Failed: {e}"); std::process::exit(1); }
    }
}

fn uninstall_cert() {
    println!("Removing '{}' from Windows Trusted Root store...", CA_COMMON_NAME);
    match cert_store::uninstall_root_ca(CA_COMMON_NAME) {
        Ok(()) => println!("Success. Root CA removed."),
        Err(e) => { eprintln!("Failed: {e}"); std::process::exit(1); }
    }
}

// ─── Proxy registration ───────────────────────────────────────────────────────

fn cmd_enable_proxy() {
    println!("Enabling system proxy → {PROXY_HOST}:{PROXY_PORT} ...");
    match system_proxy::enable(PROXY_HOST, PROXY_PORT) {
        Ok(()) => {
            println!("Done. All WinINet apps (Chrome, Edge, Outlook, etc.) now");
            println!("route traffic through {PROXY_HOST}:{PROXY_PORT}.");
            println!();
            println!("Next: make sure `proxy-gateway` is running, and that the root");
            println!("CA is installed (`cli install-cert`), otherwise HTTPS will fail.");
        }
        Err(e) => { eprintln!("Failed: {e}"); std::process::exit(1); }
    }
}

fn cmd_disable_proxy() {
    println!("Disabling system proxy...");
    match system_proxy::disable() {
        Ok(()) => println!("Done. System proxy removed; traffic routes directly."),
        Err(e) => { eprintln!("Failed: {e}"); std::process::exit(1); }
    }
}

// ─── Status ───────────────────────────────────────────────────────────────────

fn cmd_status() {
    println!("=== CDP Proxy Status ===");
    println!();

    // CA files
    let cert = certs_dir().join("ca-cert.pem");
    let key  = certs_dir().join("ca-key.pem");
    println!("Root CA:");
    println!("  ca-cert.pem : {}", if cert.exists() { "✓ present" } else { "✗ missing (run generate-ca)" });
    println!("  ca-key.pem  : {}", if key.exists()  { "✓ present" } else { "✗ missing" });
    println!();

    // System proxy
    println!("System proxy:");
    match system_proxy::current() {
        Some(addr) => println!("  ✓ enabled → {addr}"),
        None       => println!("  ✗ not set (run enable-proxy)"),
    }
    println!();
    println!("Trust store: verify manually in certmgr.msc");
    println!("  (Trusted Root Certification Authorities → look for '{CA_COMMON_NAME}')");
    println!();
    println!("Gateway: check if `proxy-gateway` process is running");
}

// ─── start / stop helpers ─────────────────────────────────────────────────────

fn cmd_start() {
    println!("=== CDP Proxy Full Setup ===");
    println!();

    // 1. CA
    print!("[1/3] Root CA... ");
    let dir = certs_dir();
    match RootCa::load_or_generate(&dir, CA_COMMON_NAME) {
        Ok(_)  => println!("OK"),
        Err(e) => { println!("FAILED: {e}"); std::process::exit(1); }
    }

    // 2. Trust Store
    let cert_path = dir.join("ca-cert.pem");
    print!("[2/3] Trust Store... ");
    match cert_store::install_root_ca(&cert_path) {
        Ok(())  => println!("OK"),
        Err(e)  => {
            println!("FAILED: {e}");
            println!("       → Re-run as Administrator for Trust Store install.");
            std::process::exit(1);
        }
    }

    // 3. System proxy
    print!("[3/3] System proxy... ");
    match system_proxy::enable(PROXY_HOST, PROXY_PORT) {
        Ok(())  => println!("OK"),
        Err(e)  => { println!("FAILED: {e}"); std::process::exit(1); }
    }

    println!();
    println!("Setup complete. Now run:");
    println!("  cargo run --bin proxy-gateway");
    println!();
    println!("All traffic from Chrome, Edge, Outlook, etc. will be inspected.");
}

fn cmd_stop() {
    println!("Stopping CDP Proxy...");
    println!();
    print!("Disabling system proxy... ");
    match system_proxy::disable() {
        Ok(())  => println!("OK"),
        Err(e)  => println!("FAILED: {e}"),
    }
    println!();
    println!("System proxy removed. Stop the `proxy-gateway` process manually (Ctrl-C).");
    println!("To also remove the root CA: run `cli uninstall-cert`");
}

// ─── Help ─────────────────────────────────────────────────────────────────────

fn print_help() {
    println!("cdp-proxy CLI");
    println!();
    println!("SETUP (run once, in order):");
    println!("  generate-ca     Generate root CA into ./certs/");
    println!("  install-cert    Install root CA into Windows Trust Store (run as Admin)");
    println!("  enable-proxy    Set 127.0.0.1:{PROXY_PORT} as Windows system proxy");
    println!();
    println!("RUNTIME:");
    println!("  start           Run all 3 setup steps then print gateway start command");
    println!("  stop            Remove system proxy (stop gateway with Ctrl-C separately)");
    println!("  status          Show current CA / proxy / trust store state");
    println!();
    println!("TEARDOWN:");
    println!("  disable-proxy   Remove system proxy setting");
    println!("  uninstall-cert  Remove root CA from Windows Trust Store");
    println!("  generate-ca     (safe to re-run — reuses existing CA)");
}
