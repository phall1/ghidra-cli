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
fn test_comment_set_and_get() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // Set a comment at the entry point (0x118910 in Ghidra's address space)
    // Note: ELF entry is 0x18910, but Ghidra loads with base 0x100000
    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("set")
        .arg("0x00118910")
        .arg("test comment from integration test")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get the comment back
    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("get")
        .arg("0x00118910")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test comment"));

    drop(harness);
}

#[test]
#[serial]
fn test_comment_list() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("set")
        .arg("0x00118920") // Within executable range (Ghidra address space)
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
fn test_comment_delete() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("comment")
        .arg("set")
        .arg("0x00118930") // Within executable range (Ghidra address space)
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
        .arg("0x00118930") // Within executable range (Ghidra address space)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}
