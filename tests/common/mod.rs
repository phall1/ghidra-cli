//! Common test utilities for E2E tests.
//!
//! This module provides:
//! - `schemas`: Typed data structures for JSON output validation
//! - `helpers`: Fluent test helpers and utilities
//! - `DaemonTestHarness`: Daemon lifecycle management for tests

pub mod helpers;
pub mod schemas;

// Re-export commonly used items
pub use helpers::{ghidra, get_function_address, normalize_json, normalize_output, GhidraCommand, GhidraResult};
pub use schemas::Validate;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Once;
use std::time::Duration;

/// Get path to the sample_binary test fixture.
pub fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sample_binary")
}

/// Ensure test project exists with analyzed sample binary.
/// Uses Once::call_once for idempotent setup across multiple tests.
pub fn ensure_test_project(project: &str, program: &str) {
    static SETUP: Once = Once::new();
    SETUP.call_once(|| {
        let binary = fixture_binary();
        if !binary.exists() {
            panic!(
                "Test fixture not found: {:?}\nRun: rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs",
                binary
            );
        }

        eprintln!("=== Setting up test project (import + analyze) ===");

        // Step 1: Import the binary
        let mut cmd = assert_cmd::Command::cargo_bin("ghidra").expect("Failed to find ghidra binary");
        let result = cmd
            .arg("import")
            .arg(binary.to_str().unwrap())
            .arg("--project")
            .arg(project)
            .arg("--program")
            .arg(program)
            .timeout(std::time::Duration::from_secs(300))
            .output()
            .expect("Failed to run import command");

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);
            eprintln!("Import stdout: {}", stdout);
            eprintln!("Import stderr: {}", stderr);
            if !stderr.contains("already exists") && !stdout.contains("already exists") {
                eprintln!("Warning: Import may have failed, but continuing...");
            }
        } else {
            eprintln!("Binary imported successfully");
        }

        // Step 2: Analyze the binary (creates code units needed for comments)
        eprintln!("Running analysis...");
        let mut analyze_cmd = assert_cmd::Command::cargo_bin("ghidra").expect("Failed to find ghidra binary");
        let analyze_result = analyze_cmd
            .arg("analyze")
            .arg("--project")
            .arg(project)
            .arg("--program")
            .arg(program)
            .timeout(std::time::Duration::from_secs(600))
            .output()
            .expect("Failed to run analyze command");

        if !analyze_result.status.success() {
            let stderr = String::from_utf8_lossy(&analyze_result.stderr);
            let stdout = String::from_utf8_lossy(&analyze_result.stdout);
            eprintln!("Analyze stdout: {}", stdout);
            eprintln!("Analyze stderr: {}", stderr);
            eprintln!("Warning: Analyze may have failed, but continuing...");
        } else {
            eprintln!("Analysis complete");
        }

        eprintln!("=== Test project setup complete ===");
    });
}

/// Test harness that manages daemon lifecycle for a test suite.
pub struct DaemonTestHarness {
    child: Child,
    socket_path: PathBuf,
    data_dir: PathBuf,
    project: String,
    // Runtime field prevents panic-during-panic in Drop (cannot create Runtime during panic unwinding)
    // and amortizes Runtime creation overhead across all async operations in this harness.
    runtime: tokio::runtime::Runtime,
}

impl DaemonTestHarness {
    /// Start daemon for testing. Blocks until daemon is ready or timeout.
    pub fn new(project: &str, program: &str) -> Result<Self> {
        let socket_path = get_unique_socket_path();
        let data_dir = get_unique_data_dir();

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ghidra"));
        cmd.env("GHIDRA_CLI_SOCKET", &socket_path)
            .env("GHIDRA_CLI_DATA_DIR", &data_dir)
            .arg("daemon")
            .arg("start")
            .arg("--foreground")
            .arg("--project")
            .arg(project)
            .arg("--program")
            .arg(program);

        let child = cmd.spawn().context("Failed to spawn daemon")?;

        // ChildGuard ensures daemon process is killed if wait_for_ready() returns early due to error.
        // Without this, failed initialization would leak daemon processes.
        struct ChildGuard(Option<Child>);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                }
            }
        }
        let mut guard = ChildGuard(Some(child));

        let runtime = tokio::runtime::Runtime::new()
            .context("Failed to create tokio runtime")?;

        let mut harness = Self {
            child: guard.0.take().unwrap(),
            socket_path,
            data_dir,
            project: project.to_string(),
            runtime,
        };

        // 120s timeout: Ghidra cold start can be slow on constrained CI environments.
        // Covers worst case without causing flaky tests.
        harness.wait_for_ready(Duration::from_secs(120))?;

        Ok(harness)
    }

    /// Wait for daemon to be ready using exponential backoff.
    fn wait_for_ready(&mut self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        // Exponential backoff: 100ms initial (responsive for fast starts), 2x multiplier, 12 max attempts.
        // Covers 100ms to ~200s range; total max wait ~409s but typical fast start exits in <5s.
        let mut delay = Duration::from_millis(100);
        let max_attempts = 12;

        for attempt in 0..max_attempts {
            if start.elapsed() > timeout {
                anyhow::bail!("Daemon failed to start within {}s timeout", timeout.as_secs());
            }

            std::thread::sleep(delay);

            if let Ok(mut client) = self.client() {
                match self.runtime.block_on(client.ping()) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {},
                    Err(e) => {
                        if attempt == max_attempts - 1 {
                            anyhow::bail!("Connection error during ping: {}", e);
                        }
                    }
                }
            }

            delay = delay.saturating_mul(2);
        }

        anyhow::bail!("Daemon failed to respond after {} attempts", max_attempts)
    }

    /// Get async IPC client connected to daemon.
    pub fn client(&self) -> Result<ghidra_cli::ipc::client::DaemonClient> {
        // Set GHIDRA_CLI_SOCKET for this process so client connects to the right socket
        // SAFETY: Tests run single-threaded (--test-threads=1), so no data race.
        unsafe { std::env::set_var("GHIDRA_CLI_SOCKET", &self.socket_path); }
        // When GHIDRA_CLI_SOCKET is set, the project path is ignored
        // but we still need to pass one for the function signature
        let project_path = std::path::Path::new(&self.project);
        self.runtime.block_on(async {
            ghidra_cli::ipc::client::DaemonClient::connect(project_path).await
        })
    }

    /// Get socket path for this daemon instance.
    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Get data directory for this daemon instance.
    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Get project name.
    pub fn project(&self) -> &str {
        &self.project
    }
}

impl Drop for DaemonTestHarness {
    fn drop(&mut self) {
        if let Ok(mut client) = self.client() {
            let _ = self.runtime.block_on(client.shutdown());
        }

        // 5s wait before kill: allows graceful shutdown to complete.
        // Most daemons shut down in <1s; 5s handles slow cleanup without blocking tests indefinitely.
        let timeout = Duration::from_secs(5);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = self.child.kill();
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Generate unique socket path for test isolation.
///
/// UUID guarantees uniqueness across parallel test suites and long-running CI (PID can wrap).
fn get_unique_socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("ghidra-test-{}.sock", uuid::Uuid::new_v4()))
}

/// Generate unique data directory for test isolation.
///
/// Prevents lock file conflicts between parallel daemon tests.
fn get_unique_data_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ghidra-data-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("Failed to create test data dir");
    dir
}

/// Require Ghidra to be available for tests to proceed.
#[macro_export]
macro_rules! require_ghidra {
    () => {
        let doctor = assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .arg("doctor")
            .output()
            .expect("Failed to run `ghidra doctor`");
        assert!(
            doctor.status.success(),
            "Ghidra is not available for tests.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&doctor.stdout),
            String::from_utf8_lossy(&doctor.stderr)
        );
    };
}
