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
    get_function_address, ghidra, normalize_json, normalize_output, GhidraCommand, GhidraResult,
};
pub use schemas::Validate;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;
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

/// Test harness that manages bridge lifecycle for a test suite.
///
/// The bridge is the Ghidra Java process running GhidraCliBridge.
/// Tests connect to it via TCP using BridgeClient.
pub struct DaemonTestHarness {
    port: u16,
    data_dir: PathBuf,
    project: String,
    project_path: PathBuf,
}

impl DaemonTestHarness {
    /// Start bridge for testing. Blocks until bridge is ready or timeout.
    pub fn new(project: &str, program: &str) -> Result<Self> {
        let data_dir = get_unique_data_dir();

        // Resolve the project path
        let project_path = dirs::data_local_dir()
            .context("Could not determine data directory")?
            .join("ghidra-cli")
            .join("projects")
            .join(project);

        // Start the bridge using the CLI command (which starts Ghidra headless)
        let mut cmd = assert_cmd::Command::cargo_bin("ghidra").expect("Failed to find ghidra binary");
        let result = cmd
            .arg("daemon")
            .arg("start")
            .arg("--project")
            .arg(project)
            .arg("--program")
            .arg(program)
            .timeout(std::time::Duration::from_secs(300))
            .output()
            .expect("Failed to start bridge");

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);
            anyhow::bail!("Failed to start bridge:\nstdout: {}\nstderr: {}", stdout, stderr);
        }

        // Read port from port file
        let port = Self::wait_for_port(&project_path, Duration::from_secs(120))?;

        Ok(Self {
            port,
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
        let hash = format!("{:x}", md5::compute(project_path.to_string_lossy().as_bytes()));
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
        // Send shutdown command to bridge
        let client = ghidra_cli::ipc::client::BridgeClient::new(self.port);
        let _ = client.shutdown();

        // Wait for process to exit
        std::thread::sleep(Duration::from_secs(2));

        // Clean up
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Generate unique data directory for test isolation.
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
            .expect("Failed to run ghidra doctor");

        let output = String::from_utf8_lossy(&doctor.stdout);

        if !output.contains("OK") || output.contains("NOT FOUND") || output.contains("FAILED") {
            eprintln!("Ghidra not properly installed, skipping test");
            eprintln!("Doctor output: {}", output);
            return;
        }
    };
}
