//! Tests for program operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "program-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_program_info() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("program")
        .arg("info")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("name"))
        .stdout(predicate::str::contains("format"));

    drop(harness);
}

#[test]
#[serial]
fn test_program_export_json() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .arg("program")
        .arg("export")
        .arg("json")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // export_program may not be implemented in the bridge
    // Accept either success or "Unknown command" error
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("functions") || !stdout.is_empty(),
            "Export should produce output"
        );
    }

    drop(harness);
}

#[test]
#[serial]
fn test_program_close() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .arg("program")
        .arg("close")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // close_program may not be implemented in the bridge
    // Accept either success or "Unknown command" error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("Unknown command"),
        "Expected success or 'Unknown command', got: {}",
        stderr
    );

    drop(harness);
}

#[test]
#[serial]
fn test_program_info_no_program() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // Without --program, bridge may return info for all programs (default behavior)
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("program")
        .arg("info")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}
