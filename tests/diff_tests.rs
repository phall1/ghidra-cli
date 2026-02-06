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
fn test_diff_programs() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // diff programs compares two programs by name (no --program flag needed)
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("diff")
        .arg("programs")
        .arg(TEST_PROGRAM)
        .arg(TEST_PROGRAM)
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_diff_functions() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // diff functions requires two function names/addresses
    // Using main for both since we just want to verify command works
    // (note: _start doesn't exist on macOS Mach-O binaries)
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("diff")
        .arg("functions")
        .arg("main")
        .arg("main")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}
