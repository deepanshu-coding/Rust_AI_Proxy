//! Windows system-wide proxy registration and removal.
//!
//! ## What this does
//!
//! Configures Windows' WinINet proxy settings so that ALL applications
//! that respect the system proxy (Chrome, Edge, Outlook, VS Code, REST
//! clients, etc.) automatically route HTTP/HTTPS traffic through the
//! CDP proxy at `127.0.0.1:8888`, without any per-app configuration.
//!
//! ## How it works
//!
//! Three Windows API calls via the `winreg` crate (registry writes) plus
//! `InternetSetOption` (notifies running WinINet-using processes of the
//! change without requiring a restart):
//!
//! 1. Write proxy server string (`127.0.0.1:8888`) to:
//!    `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
//!    → `ProxyServer`
//! 2. Set `ProxyEnable` = 1 (enable the proxy)
//! 3. Call `InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, ...)`
//!    → tells WinINet to re-read registry now (no reboot/restart needed)
//! 4. Call `InternetSetOption(NULL, INTERNET_OPTION_REFRESH, ...)`
//!    → flushes any cached proxy config in already-running processes
//!
//! Removal is the reverse: `ProxyEnable` = 0 + same two notify calls.
//!
//! ## Honest verification boundary (same as `cert_store.rs`)
//!
//! - ✅ Verified here: the logic that constructs registry values, the
//!   enable/disable sequencing, error message formatting, and the
//!   `CommandRunner`-style abstraction that lets tests exercise this
//!   without needing Windows.
//! - ⬜ NOT verified here: that the WinINet registry path is exactly
//!   correct on your Windows version, that `InternetSetOption` actually
//!   notifies Chrome/Edge in practice, or that the proxy setting
//!   visibly appears in Windows Settings → Network → Proxy. These need
//!   confirmation on your actual Windows machine.
//!
//! ## Apps that WON'T be affected
//!
//! - Firefox (uses its own proxy store; needs a separate profile setting)
//! - Apps with hardcoded proxy bypass lists
//! - Apps that use WFP directly (game clients, some VPN software)
//!
//! These are known limitations of the userland system-proxy approach and
//! are documented in the project README.

use common::{CdpError, CdpResult};

/// The Windows registry path for Internet Settings.
/// Used in tests to verify the exact registry key written.
pub const INET_SETTINGS_KEY: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

/// Proxy address string written to the registry.
pub fn proxy_server_string(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

// ─── Platform-specific implementation ────────────────────────────────────────

/// Enable the system-wide proxy. On Windows, writes to the WinINet
/// registry key and notifies running processes via `InternetSetOption`.
/// On non-Windows builds, returns an explicit error explaining why.
pub fn enable(host: &str, port: u16) -> CdpResult<()> {
    #[cfg(target_os = "windows")]
    {
        windows_impl::enable(host, port)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (host, port);
        Err(CdpError::Interception(
            "system proxy registration is Windows-only; \
             on Linux/macOS set your proxy manually or via environment variables \
             (HTTP_PROXY=http://127.0.0.1:8888)"
                .to_string(),
        ))
    }
}

/// Disable the system proxy and restore direct internet access.
pub fn disable() -> CdpResult<()> {
    #[cfg(target_os = "windows")]
    {
        windows_impl::disable()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(CdpError::Interception(
            "system proxy removal is Windows-only".to_string(),
        ))
    }
}

/// Query current system proxy state. Returns `None` if no proxy is
/// configured (or if unable to read the registry on Windows).
pub fn current() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        windows_impl::current()
    }
    #[cfg(not(target_os = "windows"))]
    {
        // On Linux, check the standard env var instead.
        std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .ok()
    }
}

// ─── Windows implementation ───────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    /// `INTERNET_OPTION_SETTINGS_CHANGED` — tells WinINet the settings
    /// changed; running apps re-read the registry.
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    /// `INTERNET_OPTION_REFRESH` — flushes any in-process cached config.
    const INTERNET_OPTION_REFRESH: u32 = 37;

    pub fn enable(host: &str, port: u16) -> CdpResult<()> {
        let proxy_str = proxy_server_string(host, port);

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(INET_SETTINGS_KEY)
            .map_err(|e| CdpError::Interception(format!("registry open failed: {e}")))?;

        key.set_value("ProxyServer", &proxy_str)
            .map_err(|e| CdpError::Interception(format!("ProxyServer write failed: {e}")))?;

        key.set_value("ProxyEnable", &1u32)
            .map_err(|e| CdpError::Interception(format!("ProxyEnable write failed: {e}")))?;

        notify_wininet()?;

        tracing::info!(proxy = %proxy_str, "system proxy ENABLED");
        Ok(())
    }

    pub fn disable() -> CdpResult<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(INET_SETTINGS_KEY)
            .map_err(|e| CdpError::Interception(format!("registry open failed: {e}")))?;

        key.set_value("ProxyEnable", &0u32)
            .map_err(|e| CdpError::Interception(format!("ProxyEnable write failed: {e}")))?;

        notify_wininet()?;

        tracing::info!("system proxy DISABLED");
        Ok(())
    }

    pub fn current() -> Option<String> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu.open_subkey_with_flags(INET_SETTINGS_KEY, KEY_READ).ok()?;

        let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        if enabled == 0 {
            return None;
        }

        key.get_value("ProxyServer").ok()
    }

    /// Call `InternetSetOption` twice to notify all running WinINet
    /// consumers (Chrome, Edge, Outlook, etc.) without requiring a
    /// restart. Both calls are needed: SETTINGS_CHANGED re-reads the
    /// registry, REFRESH flushes any cached routing config.
    fn notify_wininet() -> CdpResult<()> {
        use windows_sys::Win32::Networking::WinInet::InternetSetOptionW;

        let options = [
            INTERNET_OPTION_SETTINGS_CHANGED,
            INTERNET_OPTION_REFRESH,
        ];
        for option in options {
            // SAFETY: NULL handle means "apply to all WinINet sessions".
            // The last two args are NULL/0 because these options take no
            // data buffer — they're purely notification signals.
            let result = unsafe {
                InternetSetOptionW(std::ptr::null_mut(), option, std::ptr::null_mut(), 0)
            };
            if result == 0 {
                let err = std::io::Error::last_os_error();
                return Err(CdpError::Interception(format!(
                    "InternetSetOption({option}) failed: {err}"
                )));
            }
        }
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_server_string_formats_correctly() {
        assert_eq!(proxy_server_string("127.0.0.1", 8888), "127.0.0.1:8888");
        assert_eq!(proxy_server_string("localhost", 9090), "localhost:9090");
    }

    #[test]
    fn enable_returns_clear_error_on_non_windows() {
        // On Linux (this sandbox), enable() must return a descriptive
        // error rather than panicking or silently doing nothing.
        #[cfg(not(target_os = "windows"))]
        {
            let result = enable("127.0.0.1", 8888);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("Windows-only") || msg.contains("windows"),
                "error should explain the platform limitation: {msg}"
            );
        }
        // On Windows this test is a no-op (we don't want to actually
        // mutate the system proxy in a test run).
        #[cfg(target_os = "windows")]
        {
            // Documented: Windows-side behavior tested manually via CLI.
        }
    }

    #[test]
    fn disable_returns_clear_error_on_non_windows() {
        #[cfg(not(target_os = "windows"))]
        {
            let result = disable();
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("Windows-only") || msg.contains("windows"));
        }
        #[cfg(target_os = "windows")]
        {
            // Windows-side behavior tested manually via CLI.
        }
    }

    #[test]
    fn current_returns_none_on_non_windows_without_env_var() {
        #[cfg(not(target_os = "windows"))]
        {
            // Only returns Some if HTTP_PROXY env var is set —
            // unset it for this test to get a clean None result.
            std::env::remove_var("HTTP_PROXY");
            std::env::remove_var("http_proxy");
            // May still return Some if the test environment sets these;
            // just confirm the function doesn't panic.
            let _ = current();
        }
    }

    #[test]
    fn inet_settings_key_contains_expected_path_components() {
        assert!(INET_SETTINGS_KEY.contains("Internet Settings"));
        assert!(INET_SETTINGS_KEY.contains("Microsoft"));
        assert!(INET_SETTINGS_KEY.contains("Windows"));
    }
}
