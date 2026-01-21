//! End-to-end tests for ghidra-cli
//!
//! These tests require a working Ghidra installation and test the full CLI workflow.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

/// Get the path to the test fixture binary
fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sample_binary")
}

/// Get a unique project name for each test to avoid conflicts
fn test_project_name(test_name: &str) -> String {
    format!("e2e-{}-{}", test_name, std::process::id())
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
    /// This test requires Ghidra to be installed
    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_import_binary() {
        let binary = fixture_binary();
        if !binary.exists() {
            panic!("Test fixture not found. Run: rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs");
        }

        let project = test_project_name("import");
        
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("import")
            .arg(binary.to_str().unwrap())
            .arg("--project")
            .arg(&project)
            .arg("--program")
            .arg("sample_binary")
            .timeout(std::time::Duration::from_secs(120))
            .assert()
            .success()
            .stdout(predicate::str::contains("Successfully imported"));
    }

    /// Test function list command on pre-analyzed binary
    /// Requires the e2e-test project to exist with sample_binary
    #[test]
    #[ignore]
    fn test_function_list() {
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("function")
            .arg("list")
            .arg("--project")
            .arg("e2e-test")
            .arg("--program")
            .arg("sample_binary")
            .arg("--limit")
            .arg("100")
            .timeout(std::time::Duration::from_secs(120))
            .assert()
            .success()
            // Check for our known exported functions
            .stdout(predicate::str::contains("main"))
            .stdout(predicate::str::contains("fibonacci").or(predicate::str::contains("factorial")));
    }

    /// Test decompile command
    #[test]
    #[ignore]
    fn test_decompile() {
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("decompile")
            .arg("main") // Decompile main function
            .arg("--project")
            .arg("e2e-test")
            .arg("--program")
            .arg("sample_binary")
            .timeout(std::time::Duration::from_secs(120))
            .assert()
            .success()
            // Should contain decompiled C code
            .stdout(predicate::str::contains("void").or(predicate::str::contains("int")));
    }

    /// Test strings command
    #[test]
    #[ignore]
    fn test_strings() {
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("strings")
            .arg("list")
            .arg("--project")
            .arg("e2e-test")
            .arg("--program")
            .arg("sample_binary")
            .arg("--limit")
            .arg("50")
            .timeout(std::time::Duration::from_secs(120))
            .assert()
            .success()
            // Check for our known strings
            .stdout(predicate::str::contains("Hello").or(predicate::str::contains("Ghidra")));
    }

    /// Test memory map command
    #[test]
    #[ignore]
    fn test_memory_map() {
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("memory")
            .arg("map")
            .arg("--project")
            .arg("e2e-test")
            .arg("--program")
            .arg("sample_binary")
            .timeout(std::time::Duration::from_secs(120))
            .assert()
            .success()
            // Should show memory sections
            .stdout(predicate::str::contains(".text").or(predicate::str::contains("r")));
    }

    /// Test summary command
    #[test]
    #[ignore]
    fn test_summary() {
        let mut cmd = Command::cargo_bin("ghidra").unwrap();
        cmd.arg("summary")
            .arg("--project")
            .arg("e2e-test")
            .arg("--program")
            .arg("sample_binary")
            .timeout(std::time::Duration::from_secs(120))
            .assert()
            .success()
            .stdout(predicate::str::contains("Program Summary"));
    }
}
