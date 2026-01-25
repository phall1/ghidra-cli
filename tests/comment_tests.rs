//! Tests for comment operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "comment-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_comment_set_and_get() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("set")
        .arg("0x1000")
        .arg("test comment")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("get")
        .arg("0x1000")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test comment"));

    drop(harness);
}

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_comment_list() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("set")
        .arg("0x2000")
        .arg("another comment")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("list")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("comments"));

    drop(harness);
}

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_comment_delete() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("set")
        .arg("0x3000")
        .arg("to be deleted")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("delete")
        .arg("0x3000")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}
