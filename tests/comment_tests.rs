//! Tests for comment operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, DaemonTestHarness,
};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

#[test]
#[serial]
fn test_comment_set_and_get() {
    require_ghidra!();
    let harness = harness();

    // Dynamically resolve an address with a code unit
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

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
}

#[test]
#[serial]
fn test_comment_list() {
    require_ghidra!();
    let harness = harness();

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(harness, TEST_PROJECT, TEST_PROGRAM, 2);
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
}

#[test]
#[serial]
fn test_comment_delete() {
    require_ghidra!();
    let harness = harness();

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(harness, TEST_PROJECT, TEST_PROGRAM, 3);
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

    // Verify comment is actually gone
    let get_result = Command::cargo_bin("ghidra")
        .unwrap()
        .arg("comment")
        .arg("get")
        .arg(addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    let stdout = String::from_utf8_lossy(&get_result.stdout);
    assert!(
        !get_result.status.success() || !stdout.contains("to be deleted"),
        "Comment should be deleted but was still found: {}",
        stdout
    );
}
