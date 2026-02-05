//! Tests for stats command.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "stats-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_stats_normal() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("stats")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("stats"))
        .stdout(predicate::str::contains("functions"))
        .stdout(predicate::str::contains("symbols"));

    drop(harness);
}

#[test]
#[serial]
fn test_stats_has_all_fields() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("stats")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("functions"))
        .stdout(predicate::str::contains("symbols"))
        .stdout(predicate::str::contains("strings"))
        .stdout(predicate::str::contains("imports"))
        .stdout(predicate::str::contains("exports"))
        .stdout(predicate::str::contains("memory_size"))
        .stdout(predicate::str::contains("sections"))
        .stdout(predicate::str::contains("data_types"));

    drop(harness);
}

#[test]
#[serial]
fn test_stats_json_format() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .arg("stats")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    assert!(
        serde_json::from_str::<serde_json::Value>(&output_str).is_ok(),
        "Output should be valid JSON"
    );

    drop(harness);
}
