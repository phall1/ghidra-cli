//! Tests for project management commands.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;

/// Generate unique project name for test isolation.
/// UUID prevents collisions in parallel CI runs.
fn unique_project_name(prefix: &str) -> String {
    format!("test-{}-{}", prefix, uuid::Uuid::new_v4())
}

#[test]
fn test_project_create() {
    require_ghidra!();

    let project = unique_project_name("create");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("create")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("created").or(predicate::str::contains("Created")));

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
fn test_project_list() {
    require_ghidra!();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("list")
        .assert()
        .success();
}

#[test]
fn test_project_info() {
    require_ghidra!();

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
fn test_project_lifecycle() {
    require_ghidra!();

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
fn test_import_binary() {
    require_ghidra!();

    let project = unique_project_name("import");
    let binary = common::fixture_binary();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    // `ghidra import` spawns a JVM whose inherited pipe handles block output() forever.
    let ghidra_bin = assert_cmd::cargo::cargo_bin("ghidra");
    let status = common::run_cli_with_timeout(
        &ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

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
fn test_analyze_program() {
    require_ghidra!();

    let project = unique_project_name("analyze");
    let binary = common::fixture_binary();

    let ghidra_bin = assert_cmd::cargo::cargo_bin("ghidra");
    let status = common::run_cli_with_timeout(
        &ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    let status = common::run_cli_with_timeout(
        &ghidra_bin,
        &[
            "analyze",
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run analyze");
    assert!(status.success(), "Analyze failed with status: {}", status);

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}

#[test]
fn test_project_delete_nonexistent() {
    require_ghidra!();

    let project = unique_project_name("missing");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("not found"));
}

#[test]
#[serial]
fn test_import_existing_program() {
    require_ghidra!();

    let project = unique_project_name("import-existing");
    let binary = common::fixture_binary();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    let ghidra_bin = assert_cmd::cargo::cargo_bin("ghidra");
    let status = common::run_cli_with_timeout(
        &ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run import");
    assert!(status.success(), "Import failed with status: {}", status);

    // Import again - should still succeed (idempotent or with new name)
    let status = common::run_cli_with_timeout(
        &ghidra_bin,
        &[
            "import",
            binary.to_str().unwrap(),
            "--project",
            &project,
            "--program",
            "sample_binary",
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run second import");
    assert!(
        status.success(),
        "Second import failed with status: {}",
        status
    );

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("project")
        .arg("delete")
        .arg(&project)
        .assert()
        .success();
}
