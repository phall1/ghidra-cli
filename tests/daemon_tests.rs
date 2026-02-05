//! Tests for daemon lifecycle commands.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "daemon-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_daemon_start() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("status")
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_status() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_ping() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("ping")
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_lifecycle() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("ping")
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("stop")
        .assert()
        .success();
}

#[test]
#[serial]
fn test_daemon_stop() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("stop")
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("No bridge running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_restart() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("restart")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("stop")
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_start_when_running() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("start")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("already running"));

    drop(harness);
}
