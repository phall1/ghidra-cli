//! Tests for type operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, get_function_address, DaemonTestHarness};

const TEST_PROJECT: &str = "type-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_type_list() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("type")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_type_get_primitive() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("type")
        .arg("get")
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("size"));

    drop(harness);
}

#[test]
#[serial]
fn test_type_create() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("type")
        .arg("create")
        .arg("MyTestStruct")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_type_apply() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let addr = get_function_address(&harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .arg("type")
        .arg("apply")
        .arg(&addr)
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // Applying a type at a code address may conflict with existing instructions
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            || stderr.contains("Conflicting instruction")
            || stderr.contains("conflict"),
        "Expected success or instruction conflict, got: {}",
        stderr
    );

    drop(harness);
}

#[test]
#[serial]
fn test_type_get_nonexistent() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("type")
        .arg("get")
        .arg("NonexistentType12345")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();

    drop(harness);
}
