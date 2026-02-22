//! Common test utilities for E2E tests.
//!
//! This module provides:
//! - `schemas`: Typed data structures for JSON output validation
//! - `helpers`: Fluent test helpers and utilities
//! - `DaemonTestHarness`: Bridge lifecycle management for tests

pub mod helpers;
pub mod schemas;

// Re-export commonly used items
pub use helpers::{
    get_function_address, get_function_addresses, ghidra, normalize_json, normalize_output,
    GhidraCommand, GhidraResult,
};
pub use schemas::Validate;

use anyhow::{Context, Result};
use std::path::PathBuf;
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
/// Skips import+analyze if the project already exists (supports CI caching).
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

        // Check if project already exists with program data (supports CI caching).
        // Verify both .gpr (project descriptor) and .rep (repository data) exist
        // to avoid using incomplete cached projects.
        let project_dir = dirs::cache_dir()
            .expect("Could not determine cache directory")
            .join("ghidra-cli")
            .join("projects")
            .join(project);
        let gpr_file = project_dir.join(format!("{}.gpr", project));
        let rep_dir = project_dir.join(format!("{}.rep", project));

        if gpr_file.exists() && rep_dir.exists() && rep_dir.is_dir() {
            eprintln!("=== Using cached test project: {:?} ===", gpr_file);
            return;
        }

        if gpr_file.exists() {
            eprintln!("=== Project .gpr exists but .rep missing, re-importing ===");
        }

        eprintln!("=== Setting up test project (import + analyze) ===");
        eprintln!("Project dir: {:?}", project_dir);

        // Step 1: Import the binary
        //
        // IMPORTANT: We use Stdio::null() instead of piped stdout/stderr.
        // On Windows, `ghidra import` spawns analyzeHeadless.bat → cmd.exe → java.exe.
        // If we use piped I/O, the grandchild JVM inherits the pipe handles.
        // When ghidra.exe exits, the pipe stays open (JVM holds inherited handles),
        // so output()/wait_with_output() blocks forever. Using null avoids this.
        eprintln!("Step 1: Importing binary {:?} ...", binary);
        let ghidra_bin = assert_cmd::cargo::cargo_bin("ghidra");
        let import_status = run_cli_with_timeout(
            &ghidra_bin,
            &[
                "import",
                binary.to_str().unwrap(),
                "--project",
                project,
                "--program",
                program,
            ],
            Duration::from_secs(300),
        );
        match import_status {
            Ok(status) => {
                eprintln!("Import finished with status: {}", status);
                if !status.success() {
                    eprintln!("Warning: Import may have failed, but continuing...");
                } else {
                    eprintln!("Binary imported successfully");
                }
            }
            Err(e) => eprintln!("Import error: {}", e),
        }

        // Step 2: Analyze the binary (creates code units needed for comments)
        eprintln!("Step 2: Running analysis...");
        let analyze_status = run_cli_with_timeout(
            &ghidra_bin,
            &[
                "analyze",
                "--project",
                project,
                "--program",
                program,
            ],
            Duration::from_secs(600),
        );
        match analyze_status {
            Ok(status) => {
                eprintln!("Analyze finished with status: {}", status);
                if !status.success() {
                    eprintln!("Warning: Analyze may have failed, but continuing...");
                } else {
                    eprintln!("Analysis complete");
                }
            }
            Err(e) => eprintln!("Analyze error: {}", e),
        }

        // Step 3: Stop the bridge that import/analyze left running.
        // Without this, the first test reuses the leftover bridge (free pass),
        // but when it stops the bridge, subsequent tests must start fresh ones.
        // This inconsistency causes the first test to pass while others fail.
        eprintln!("Step 3: Stopping leftover bridge...");
        let stop_status = run_cli_with_timeout(
            &ghidra_bin,
            &["stop", "--project", project],
            Duration::from_secs(60),
        );
        match stop_status {
            Ok(status) => eprintln!("Bridge stop finished with status: {}", status),
            Err(e) => eprintln!("Bridge stop error (may be expected): {}", e),
        }

        eprintln!("=== Test project setup complete ===");
    });
}

/// Test harness that manages bridge lifecycle for a test suite.
///
/// The bridge is the Ghidra Java process running GhidraCliBridge.
/// Tests connect to it via TCP using BridgeClient.
pub struct DaemonTestHarness {
    port: u16,
    pid: Option<u32>,
    data_dir: PathBuf,
    project: String,
    project_path: PathBuf,
}

impl DaemonTestHarness {
    /// Start bridge for testing. Blocks until bridge is ready or timeout.
    pub fn new(project: &str, program: &str) -> Result<Self> {
        let data_dir = get_unique_data_dir();

        // Resolve the project path (must match CLI's default: cache_dir/ghidra-cli/projects)
        let project_path = dirs::cache_dir()
            .context("Could not determine cache directory")?
            .join("ghidra-cli")
            .join("projects")
            .join(project);

        // Start the bridge using the CLI command (which starts Ghidra headless).
        // Uses Stdio::null() to avoid Windows pipe handle inheritance (see ensure_test_project).
        let ghidra_bin = assert_cmd::cargo::cargo_bin("ghidra");
        let status = run_cli_with_timeout(
            &ghidra_bin,
            &["start", "--project", project, "--program", program],
            Duration::from_secs(300),
        )?;

        if !status.success() {
            anyhow::bail!("Failed to start bridge (exit status: {})", status);
        }

        // Read port from port file
        let port = Self::wait_for_port(&project_path, Duration::from_secs(120))?;

        // Store PID now so Drop can wait for it even if restart deletes the PID file
        let pid = ghidra_cli::ghidra::bridge::read_pid_file(&project_path)
            .ok()
            .flatten();

        Ok(Self {
            port,
            pid,
            data_dir,
            project: project.to_string(),
            project_path,
        })
    }

    /// Wait for the bridge to become available by polling the port file.
    fn wait_for_port(project_path: &std::path::Path, timeout: Duration) -> Result<u16> {
        let start = std::time::Instant::now();
        let mut delay = Duration::from_millis(100);

        // Compute port file path (same logic as bridge.rs)
        let data_dir = dirs::data_local_dir()
            .context("Could not determine data directory")?
            .join("ghidra-cli");
        let hash = format!(
            "{:x}",
            md5::compute(project_path.to_string_lossy().as_bytes())
        );
        let port_file = data_dir.join(format!("bridge-{}.port", hash));

        while start.elapsed() < timeout {
            std::thread::sleep(delay);

            // Try to read port file
            if port_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&port_file) {
                    if let Ok(port) = content.trim().parse::<u16>() {
                        // Verify we can connect
                        let client = ghidra_cli::ipc::client::BridgeClient::new(port);
                        if client.ping().unwrap_or(false) {
                            return Ok(port);
                        }
                    }
                }
            }

            delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(5));
        }

        anyhow::bail!("Bridge failed to start within {}s", timeout.as_secs())
    }

    /// Get a BridgeClient connected to the test bridge.
    pub fn client(&self) -> Result<ghidra_cli::ipc::client::BridgeClient> {
        Ok(ghidra_cli::ipc::client::BridgeClient::new(self.port))
    }

    /// Get data directory for this daemon instance.
    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Get project name.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Get bridge port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for DaemonTestHarness {
    fn drop(&mut self) {
        // Read current PID from file (may differ from self.pid if restart changed it)
        let file_pid = ghidra_cli::ghidra::bridge::read_pid_file(&self.project_path)
            .ok()
            .flatten();

        // Use stop_bridge for proper graceful shutdown + force-kill
        let _ = ghidra_cli::ghidra::bridge::stop_bridge(&self.project_path);

        // Collect all PIDs we need to wait for (original + current, deduplicated)
        let mut pids_to_wait: Vec<u32> = Vec::new();
        if let Some(pid) = file_pid {
            pids_to_wait.push(pid);
        }
        if let Some(pid) = self.pid {
            if !pids_to_wait.contains(&pid) {
                pids_to_wait.push(pid);
            }
        }

        // Wait for ALL known processes to fully exit and release project lock.
        let max_wait = if cfg!(windows) {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(15)
        };
        for pid in &pids_to_wait {
            let start = std::time::Instant::now();
            while start.elapsed() < max_wait {
                if !ghidra_cli::ghidra::bridge::is_pid_alive(*pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        // Final cleanup of any remaining stale files
        let _ = ghidra_cli::ghidra::bridge::cleanup_stale_files(&self.project_path);
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Generate unique data directory for test isolation.
fn get_unique_data_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ghidra-data-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("Failed to create test data dir");
    dir
}

/// Run a CLI command with timeout.
///
/// Stdout uses Stdio::null() to avoid pipe handle inheritance on Windows, where
/// grandchild JVM processes inherit pipe handles and block wait_with_output() forever.
/// Stderr uses Stdio::inherit() so errors are visible in CI logs (inheriting the parent
/// fd doesn't create a pipe, so there's no blocking issue).
pub fn run_cli_with_timeout(
    bin: &std::path::Path,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to spawn CLI command")?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    eprintln!("Command timed out after {}s, killing...", timeout.as_secs());
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!("Command timed out after {}s", timeout.as_secs());
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => anyhow::bail!("Error waiting for command: {}", e),
        }
    }
}

/// Require Ghidra to be available for tests to proceed.
#[macro_export]
macro_rules! require_ghidra {
    () => {
        let doctor = assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .arg("doctor")
            .output()
            .expect("Failed to run ghidra doctor");

        let output = String::from_utf8_lossy(&doctor.stdout);

        if !output.contains("OK") || output.contains("NOT FOUND") || output.contains("FAILED") {
            panic!(
                "Ghidra not properly installed — tests MUST fail without Ghidra.\n\
                 Doctor output: {}",
                output
            );
        }
    };
}
