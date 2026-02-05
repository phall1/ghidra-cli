//! Tests for batch operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;
use std::fs;
use std::path::PathBuf;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "batch-test";
const TEST_PROGRAM: &str = "sample_binary";

fn create_batch_file(content: &str) -> PathBuf {
    let temp_dir = std::env::temp_dir();
    let batch_file = temp_dir.join(format!("ghidra_batch_{}.txt", std::process::id()));
    fs::write(&batch_file, content).expect("Failed to write batch file");
    batch_file
}

#[test]
#[serial]
fn test_batch_multiple_queries() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let batch_content = r#"
# Test batch file
query --address 0x100000
query --function main
"#;

    let batch_file = create_batch_file(batch_content);

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("commands_parsed"))
        .stdout(predicate::str::contains("results"));

    fs::remove_file(batch_file).ok();
    drop(harness);
}

#[test]
#[serial]
fn test_batch_empty_file() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let batch_content = r#"
# Only comments


# More comments
"#;

    let batch_file = create_batch_file(batch_content);

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("commands_parsed"));

    fs::remove_file(batch_file).ok();
    drop(harness);
}

#[test]
#[serial]
fn test_batch_with_comments() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let batch_content = r#"
# Query main function
query --function main
# Query by address
query --address 0x100000
# Another comment
"#;

    let batch_file = create_batch_file(batch_content);

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("commands_parsed"))
        .stdout(predicate::str::contains("2"));

    fs::remove_file(batch_file).ok();
    drop(harness);
}

#[test]
#[serial]
fn test_batch_invalid_file() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("/nonexistent/batch/file.txt")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("No such file")));

    drop(harness);
}

#[test]
#[serial]
fn test_batch_with_invalid_command() {
    require_ghidra!();
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    let batch_content = r#"
query --function main
invalid-command --arg value
query --address 0x100000
"#;

    let batch_file = create_batch_file(batch_content);

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("batch")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg(batch_file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("commands_parsed"))
        .stdout(predicate::str::contains("3"));

    fs::remove_file(batch_file).ok();
    drop(harness);
}
