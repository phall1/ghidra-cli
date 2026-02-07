//! Tests for symbol operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, DaemonTestHarness,
};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_symbol_list() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .arg("symbol")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(output.status.success(), "symbol list should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Known functions should appear as symbols
    // On macOS, names may have underscore prefix
    assert!(
        stdout.contains("main") || stdout.contains("_main"),
        "symbol list should contain main. Output: {}",
        stdout
    );

    drop(harness);
}

#[test]
#[serial]
fn test_symbol_create_and_get() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("symbol")
        .arg("create")
        .arg(&addr)
        .arg("test_symbol")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("symbol")
        .arg("get")
        .arg("test_symbol")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test_symbol"));

    drop(harness);
}

#[test]
#[serial]
fn test_symbol_rename() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let addrs = get_function_addresses(&harness, TEST_PROJECT, TEST_PROGRAM, 2);
    let addr = &addrs[1];

    // Use unique names to avoid collisions with cached project state
    let old_name = format!("old_sym_{}", std::process::id());
    let new_name = format!("new_sym_{}", std::process::id());

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("symbol")
        .arg("create")
        .arg(addr)
        .arg(&old_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("symbol")
        .arg("rename")
        .arg(&old_name)
        .arg(&new_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify new symbol exists
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("symbol")
        .arg("get")
        .arg(&new_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains(&*new_name));

    drop(harness);
}

#[test]
#[serial]
fn test_symbol_get_nonexistent() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("symbol")
        .arg("get")
        .arg("nonexistent_symbol_12345")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();

    drop(harness);
}
