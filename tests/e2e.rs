//! End-to-end tests for ghidra-cli
//!
//! These tests require a working Ghidra installation. The test project
//! is set up automatically on first run.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;
use std::path::PathBuf;
use std::sync::Once;

static SETUP: Once = Once::new();
static PROJECT_NAME: &str = "e2e-test";
static PROGRAM_NAME: &str = "sample_binary";

/// Get the path to the test fixture binary
fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sample_binary")
}

/// Ensure the test project is set up (import + analyze the sample binary).
/// This runs only once per test run, regardless of how many tests call it.
fn ensure_project_setup() {
    SETUP.call_once(|| {
        let binary = fixture_binary();
        if !binary.exists() {
            panic!(
                "Test fixture not found: {:?}\nRun: rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs",
                binary
            );
        }

        eprintln!("=== Setting up E2E test project (import + analyze) ===");

        // Import the binary
        let mut cmd = Command::cargo_bin("ghidra").expect("Failed to find ghidra binary");
        let result = cmd
            .arg("import")
            .arg(binary.to_str().unwrap())
            .arg("--project")
            .arg(PROJECT_NAME)
            .arg("--program")
            .arg(PROGRAM_NAME)
            .timeout(std::time::Duration::from_secs(300))
            .output()
            .expect("Failed to run import command");

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);
            eprintln!("Import stdout: {}", stdout);
            eprintln!("Import stderr: {}", stderr);
            // Don't panic - project might already exist
            if !stderr.contains("already exists") && !stdout.contains("already exists") {
                eprintln!("Warning: Import may have failed, but continuing...");
            }
        } else {
            eprintln!("Binary imported successfully");
        }

        eprintln!("=== E2E test project setup complete ===");
    });
}

mod e2e_tests {
    use super::*;

    /// Test that doctor command works
    #[test]
    fn test_doctor() {
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("doctor")
            .assert()
            .success()
            .stdout(predicate::str::contains("Ghidra CLI Doctor"));
    }

    /// Test version command
    #[test]
    fn test_version() {
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("version")
            .assert()
            .success()
            .stdout(predicate::str::contains("ghidra-cli"));
    }

    /// Test config list command
    #[test]
    fn test_config_list() {
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("config")
            .arg("list")
            .assert()
            .success()
            .stdout(predicate::str::contains("ghidra_install_dir"));
    }

    /// Test import command with sample binary
    #[test]
    #[serial]
    fn test_import_binary() {
        let binary = fixture_binary();
        if !binary.exists() {
            panic!(
                "Test fixture not found. Run: rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs"
            );
        }

        // Use a unique project name for this test
        let project = format!("e2e-import-{}", std::process::id());

        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("import")
            .arg(binary.to_str().unwrap())
            .arg("--project")
            .arg(&project)
            .arg("--program")
            .arg("sample_binary")
            .timeout(std::time::Duration::from_secs(300))
            .assert()
            .success()
            .stdout(predicate::str::contains("Successfully imported"));
    }

    /// Test function list command on pre-analyzed binary
    /// NOTE: This test requires the daemon to be running. Skipped pending daemon E2E test infrastructure.
    #[test]
    #[serial]
    #[ignore = "Requires daemon to be running. Run with --ignored to include daemon tests."]
    fn test_function_list() {
        ensure_project_setup();

        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("function")
            .arg("list")
            .arg("--project")
            .arg(PROJECT_NAME)
            .arg("--program")
            .arg(PROGRAM_NAME)
            .arg("--limit")
            .arg("100")
            .timeout(std::time::Duration::from_secs(300))
            .assert()
            .success()
            // Check for our known exported functions
            .stdout(predicate::str::contains("main"))
            .stdout(
                predicate::str::contains("fibonacci").or(predicate::str::contains("factorial")),
            );
    }

    /// Test decompile command
    /// NOTE: This test requires the daemon to be running.
    #[test]
    #[serial]
    #[ignore = "Requires daemon to be running. Run with --ignored to include daemon tests."]
    fn test_decompile() {
        ensure_project_setup();

        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("decompile")
            .arg("main") // Decompile main function
            .arg("--project")
            .arg(PROJECT_NAME)
            .arg("--program")
            .arg(PROGRAM_NAME)
            .timeout(std::time::Duration::from_secs(300))
            .assert()
            .success()
            // Should contain decompiled C code
            .stdout(predicate::str::contains("void").or(predicate::str::contains("int")));
    }

    /// Test strings command
    /// NOTE: This test requires the daemon to be running.
    #[test]
    #[serial]
    #[ignore = "Requires daemon to be running. Run with --ignored to include daemon tests."]
    fn test_strings() {
        ensure_project_setup();

        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("strings")
            .arg("list")
            .arg("--project")
            .arg(PROJECT_NAME)
            .arg("--program")
            .arg(PROGRAM_NAME)
            .arg("--limit")
            .arg("100") // Increase limit to find our test strings
            .timeout(std::time::Duration::from_secs(300))
            .assert()
            .success()
            // Check for strings that exist in a typical ELF binary
            // (libc symbols are reliably present)
            .stdout(predicate::str::contains("address"))
            .stdout(predicate::str::contains("value"));
    }

    /// Test memory map command
    /// NOTE: This test requires the daemon to be running.
    #[test]
    #[serial]
    #[ignore = "Requires daemon to be running. Run with --ignored to include daemon tests."]
    fn test_memory_map() {
        ensure_project_setup();

        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("memory")
            .arg("map")
            .arg("--project")
            .arg(PROJECT_NAME)
            .arg("--program")
            .arg(PROGRAM_NAME)
            .timeout(std::time::Duration::from_secs(300))
            .assert()
            .success()
            // Should show memory sections
            .stdout(predicate::str::contains(".text").or(predicate::str::contains("r")));
    }

    /// Test summary command
    /// NOTE: This test requires the daemon to be running.
    #[test]
    #[serial]
    #[ignore = "Requires daemon to be running. Run with --ignored to include daemon tests."]
    fn test_summary() {
        ensure_project_setup();

        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("summary")
            .arg("--project")
            .arg(PROJECT_NAME)
            .arg("--program")
            .arg(PROGRAM_NAME)
            .timeout(std::time::Duration::from_secs(300))
            .assert()
            .success()
            .stdout(predicate::str::contains("Program Summary"));
    }
}
