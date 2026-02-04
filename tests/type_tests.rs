//! Tests for type operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "type-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_type_list() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project").arg(TEST_PROJECT)
        .arg("type")
        .arg("list")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("types"));

    drop(harness);
}

#[test]
#[serial]
fn test_type_get_primitive() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project").arg(TEST_PROJECT)
        .arg("type")
        .arg("get")
        .arg("int")
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
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project").arg(TEST_PROJECT)
        .arg("type")
        .arg("create")
        .arg("MyTestStruct")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_type_apply() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project").arg(TEST_PROJECT)
        .arg("type")
        .arg("apply")
        .arg("0x1000")
        .arg("int")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_type_get_nonexistent() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project").arg(TEST_PROJECT)
        .arg("type")
        .arg("get")
        .arg("NonexistentType12345")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();

    drop(harness);
}
