//! Tests for symbol operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "symbol-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_symbol_list() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("symbol")
        .arg("list")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("symbols"));

    drop(harness);
}

#[test]
#[serial]
fn test_symbol_create_and_get() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("symbol")
        .arg("create")
        .arg("0x1000")
        .arg("test_symbol")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("symbol")
        .arg("get")
        .arg("test_symbol")
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
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("symbol")
        .arg("create")
        .arg("0x2000")
        .arg("old_symbol")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("symbol")
        .arg("rename")
        .arg("old_symbol")
        .arg("new_symbol")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_symbol_get_nonexistent() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("symbol")
        .arg("get")
        .arg("nonexistent_symbol_12345")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();

    drop(harness);
}
