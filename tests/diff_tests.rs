//! Tests for diff operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "diff-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_diff_programs() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("diff")
        .arg("programs")
        .arg(TEST_PROGRAM)
        .arg(TEST_PROGRAM)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("program1"));

    drop(harness);
}

#[test]
#[serial]
#[ignore]
fn test_diff_functions() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("diff")
        .arg("functions")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure()
        .stderr(predicate::str::contains("CLI update"));

    drop(harness);
}
