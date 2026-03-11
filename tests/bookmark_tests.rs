use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, get_function_address, DaemonTestHarness};

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
fn test_bookmark_add() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("bookmark")
        .arg("add")
        .arg(&addr)
        .arg("--comment")
        .arg("test bookmark")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("added"));
}

#[test]
#[serial]
fn test_bookmark_list() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("bookmark")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_bookmark_delete() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("bookmark")
        .arg("add")
        .arg(&addr)
        .arg("--type")
        .arg("Warning")
        .arg("--comment")
        .arg("to delete")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("bookmark")
        .arg("delete")
        .arg(&addr)
        .arg("--type")
        .arg("Warning")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("deleted"));
}
