//! Tests for function management operations (create, delete, signature, return type).

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

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
fn test_set_return_type() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("set-return-type")
        .arg("add")
        .arg("long")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("return_type_set"));
}

#[test]
#[serial]
fn test_set_return_type_void() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("set-return-type")
        .arg("multiply")
        .arg("void")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("return_type_set"));
}

#[test]
#[serial]
fn test_set_return_type_bad_type() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("set-return-type")
        .arg("add")
        .arg("FakeTypeXYZ999")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("Unknown")
            || combined.contains("error")
            || combined.contains("Error")
            || !output.status.success(),
        "Setting bad return type should fail. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
#[serial]
fn test_set_function_signature() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("set-signature")
        .arg("add")
        .arg("long add(long a, long b)")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("signature_set"));
}

#[test]
#[serial]
fn test_set_function_signature_bad() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("set-signature")
        .arg("add")
        .arg("this is not a valid signature!!!")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("Invalid")
            || combined.contains("error")
            || combined.contains("Error")
            || combined.contains("parse")
            || !output.status.success(),
        "Setting bad signature should fail. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}
