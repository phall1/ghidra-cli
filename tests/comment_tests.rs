//! Tests for comment operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, DaemonTestHarness,
};

const TEST_PROJECT: &str = "comment-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_comment_set_and_get() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // Dynamically resolve an address with a code unit
    let addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("comment")
        .arg("set")
        .arg(&addr)
        .arg("test comment from integration test")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get the comment back
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("comment")
        .arg("get")
        .arg(&addr)
        .arg("--project")
        .arg(TEST_PROJECT)
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
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(&harness, TEST_PROJECT, TEST_PROGRAM, 2);
    let addr = &addrs[0];

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("comment")
        .arg("set")
        .arg(addr)
        .arg("another comment")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("comment")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("another comment"));

    drop(harness);
}

#[test]
#[serial]
fn test_comment_delete() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(&harness, TEST_PROJECT, TEST_PROGRAM, 3);
    let addr = &addrs[addrs.len() - 1];

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("comment")
        .arg("set")
        .arg(addr)
        .arg("to be deleted")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("comment")
        .arg("delete")
        .arg(addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}
