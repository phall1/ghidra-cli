//! Tests for project management commands.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

mod common;

/// Generate unique project name for test isolation.
/// UUID prevents collisions in parallel CI runs.
fn unique_project_name(prefix: &str) -> String {
    format!("test-{}-{}", prefix, uuid::Uuid::new_v4())
}

#[test]
#[ignore] // Requires Ghidra installation
fn test_project_create() {
    let project = unique_project_name("create");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Created project"));

    // Cleanup
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[ignore] // Requires Ghidra installation
fn test_project_list() {
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("list")
        .assert()
        .success();
}

#[test]
#[ignore] // Requires Ghidra installation
fn test_project_info() {
    let project = unique_project_name("info");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("info")
        .arg(&project)
        .assert()
        .success();

    // Cleanup
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[ignore] // Requires Ghidra installation
fn test_project_lifecycle() {
    let project = unique_project_name("lifecycle");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(&project));

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_import_binary() {
    let project = unique_project_name("import");
    let binary = common::fixture_binary();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("import")
        .arg(binary.to_str().unwrap())
        .arg("--project")
        .arg(&project)
        .arg("--program")
        .arg("sample_binary")
        .timeout(std::time::Duration::from_secs(300))
        .assert()
        .success()
        .stdout(predicate::str::contains("Successfully imported"));

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_analyze_program() {
    let project = unique_project_name("analyze");
    let binary = common::fixture_binary();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("import")
        .arg(binary.to_str().unwrap())
        .arg("--project")
        .arg(&project)
        .arg("--program")
        .arg("sample_binary")
        .timeout(std::time::Duration::from_secs(300))
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("analyze")
        .arg("--project")
        .arg(&project)
        .arg("--program")
        .arg("sample_binary")
        .timeout(std::time::Duration::from_secs(300))
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}
