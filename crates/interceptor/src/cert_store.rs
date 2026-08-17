//! Install/uninstall the generated root CA into Windows' Trusted Root
//! Certification Authorities store, via `certutil.exe` (built into every
//! Windows install since XP — no extra dependency needed).
//!
//! ## Why shell out instead of calling WinAPI directly
//!
//! A native `CertAddCertificateContextToStore` call via the `windows`
//! crate is the more "idiomatic" option on paper, but it pulls in a
//! large Windows-only dependency for one narrow feature — against this
//! project's "minimal dependencies" requirement — and critically, it
//! cannot be compiled or exercised at all in this development sandbox
//! (Linux container, no Windows headers). Shelling out to `certutil.exe`
//! keeps this module's own logic (argument building, exit-code handling,
//! error surfacing) testable and verifiable here, even though the actual
//! end-to-end Windows behavior can only be confirmed on a real Windows
//! machine — that gap is called out explicitly below rather than hidden.
//!
//! ## What IS verified here vs. what ISN'T
//!
//! - ✅ Verified in this sandbox: command construction (the exact argv
//!   passed to `certutil`), exit-code-to-Result mapping, error message
//!   formatting — all via unit tests that fake the command runner.
//! - ⬜ NOT verified here (Windows-only, needs your machine): that
//!   `certutil.exe` actually exists at the expected path, that it
//!   accepts these exact flags on your Windows version, and that the
//!   cert genuinely becomes trusted afterward. This is flagged honestly
//!   rather than claimed as tested.
//!
//! ## Required privileges
//!
//! Installing into the **Local Machine** "ROOT" store (trusted for all
//! users) requires Administrator privileges. Installing into the
//! **Current User** "ROOT" store does not, but only protects that one
//! Windows user account. This module defaults to machine-wide install
//! since the goal is system-wide interception, and surfaces a clear
//! error if it's run without sufficient privileges (certutil itself
//! reports this via a non-zero exit code).

use common::{CdpError, CdpResult};
use std::path::Path;
use std::process::{Command, Output};

/// Abstraction over "run a command and get its output" so the actual
/// `certutil` invocation logic can be unit-tested without needing a
/// real Windows machine or real certutil.exe present.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output>;
}

/// Real implementation — actually spawns `certutil.exe`. Only meaningful
/// on Windows; on any other OS this will fail with "command not found",
/// which is expected and surfaced as a clear error, not a panic.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        Command::new(program).args(args).output()
    }
}

/// Install `cert_path` (a PEM-encoded certificate file) into the
/// Windows "ROOT" (Trusted Root Certification Authorities) store,
/// machine-wide. Requires the process to be running elevated
/// (Run as Administrator).
pub fn install_root_ca(cert_path: &Path) -> CdpResult<()> {
    install_root_ca_with(&RealCommandRunner, cert_path)
}

/// Remove a previously-installed root CA from the Windows "ROOT" store,
/// identified by its Subject Common Name (must match exactly what was
/// used when the CA was generated, e.g. "EnaLisis CDP Proxy Root CA").
pub fn uninstall_root_ca(common_name: &str) -> CdpResult<()> {
    uninstall_root_ca_with(&RealCommandRunner, common_name)
}

// --- Testable inner implementations, parameterized over CommandRunner ---

fn install_root_ca_with(runner: &dyn CommandRunner, cert_path: &Path) -> CdpResult<()> {
    let path_str = cert_path.to_str().ok_or_else(|| {
        CdpError::Interception("certificate path is not valid UTF-8".to_string())
    })?;

    let output = runner
        .run("certutil.exe", &["-addstore", "-f", "ROOT", path_str])
        .map_err(|e| {
            CdpError::Interception(format!(
                "failed to run certutil.exe (is this Windows? is certutil on PATH?): {e}"
            ))
        })?;

    check_certutil_result(&output, "install")
}

fn uninstall_root_ca_with(runner: &dyn CommandRunner, common_name: &str) -> CdpResult<()> {
    let output = runner
        .run("certutil.exe", &["-delstore", "ROOT", common_name])
        .map_err(|e| {
            CdpError::Interception(format!(
                "failed to run certutil.exe (is this Windows? is certutil on PATH?): {e}"
            ))
        })?;

    check_certutil_result(&output, "uninstall")
}

fn check_certutil_result(output: &Output, action: &str) -> CdpResult<()> {
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(CdpError::Interception(format!(
            "certutil {action} failed (exit code {:?}). stdout: {stdout} stderr: {stderr}. \
             If this is a permissions error, re-run as Administrator.",
            output.status.code()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::ExitStatus;
    use std::sync::Mutex;

    /// Build an ExitStatus for a given exit code, working on both Unix
    /// (where raw status encodes the code in the high byte) and Windows
    /// (where ExitStatusExt::from_raw takes the code directly) — so
    /// these tests compile and run on whichever OS `cargo test` is
    /// actually invoked on, including your Windows machine.
    fn exit_status(code: i32) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw(code << 8)
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(code as u32)
        }
    }

    /// Records what command/args it was called with, and returns a
    /// pre-programmed fake result — lets us test the argument-building
    /// and exit-code-handling logic without a real certutil.exe.
    struct FakeCommandRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        exit_code: i32,
        stdout: String,
        stderr: String,
    }

    impl FakeCommandRunner {
        fn success() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                exit_code: 0,
                stdout: "CertUtil: -addstore command completed successfully.".to_string(),
                stderr: String::new(),
            }
        }

        fn failure(exit_code: i32, stderr: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                exit_code,
                stdout: String::new(),
                stderr: stderr.to_string(),
            }
        }

        fn last_call(&self) -> (String, Vec<String>) {
            self.calls.lock().unwrap().last().unwrap().clone()
        }
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            ));

            Ok(Output {
                status: exit_status(self.exit_code),
                stdout: self.stdout.clone().into_bytes(),
                stderr: self.stderr.clone().into_bytes(),
            })
        }
    }

    #[test]
    fn install_calls_certutil_with_correct_addstore_args() {
        let runner = FakeCommandRunner::success();
        let result = install_root_ca_with(&runner, Path::new("certs/ca-cert.pem"));

        assert!(result.is_ok());
        let (program, args) = runner.last_call();
        assert_eq!(program, "certutil.exe");
        assert_eq!(args, vec!["-addstore", "-f", "ROOT", "certs/ca-cert.pem"]);
    }

    #[test]
    fn install_returns_err_on_nonzero_exit_code() {
        let runner = FakeCommandRunner::failure(1, "Access is denied.");
        let result = install_root_ca_with(&runner, Path::new("certs/ca-cert.pem"));

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Access is denied"));
        assert!(err_msg.contains("Administrator"));
    }

    #[test]
    fn uninstall_calls_certutil_with_correct_delstore_args() {
        let runner = FakeCommandRunner::success();
        let result = uninstall_root_ca_with(&runner, "EnaLisis CDP Proxy Root CA");

        assert!(result.is_ok());
        let (program, args) = runner.last_call();
        assert_eq!(program, "certutil.exe");
        assert_eq!(
            args,
            vec!["-delstore", "ROOT", "EnaLisis CDP Proxy Root CA"]
        );
    }

    #[test]
    fn uninstall_returns_err_on_nonzero_exit_code() {
        let runner = FakeCommandRunner::failure(2, "Cannot find object or property.");
        let result = uninstall_root_ca_with(&runner, "Nonexistent CA");

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Cannot find object"));
    }

    #[test]
    fn install_surfaces_io_error_when_certutil_missing() {
        struct AlwaysFailRunner;
        impl CommandRunner for AlwaysFailRunner {
            fn run(&self, _program: &str, _args: &[&str]) -> std::io::Result<Output> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "program not found",
                ))
            }
        }

        let result = install_root_ca_with(&AlwaysFailRunner, Path::new("certs/ca-cert.pem"));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("certutil"));
    }

    #[test]
    fn real_command_runner_constructs_without_panicking() {
        // Just confirms the struct/trait wiring compiles and the real
        // implementation can be instantiated. Does NOT actually invoke
        // certutil — that only makes sense on a real Windows machine.
        let _runner = RealCommandRunner;
    }
}
