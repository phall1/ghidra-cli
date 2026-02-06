//! Tests for daemon lifecycle commands.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "daemon-test";
const TEST_PROGRAM: &str = "sample_binary";

/// Try to create a DaemonTestHarness. Returns None (and skips the test) if
/// the bridge fails to start due to "program file(s) not found" - a known
/// macOS issue where Ghidra can't find the imported program.
fn try_start_daemon() -> Option<DaemonTestHarness> {
    match DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM) {
        Ok(h) => Some(h),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("program file(s) not found") {
                eprintln!(
                    "Skipping test: bridge can't find program (known macOS issue): {}",
                    msg
                );
                None
            } else {
                panic!("Failed to start daemon: {}", e);
            }
        }
    }
}

#[test]
#[serial]
fn test_daemon_start() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("status")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_status() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("status")
        .arg("--project")
        .arg(TEST_PROJECT)
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

    let Some(harness) = try_start_daemon() else {
        return;
    };

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("ping")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_lifecycle() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(_harness) = try_start_daemon() else {
        return;
    };

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("status")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("ping")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("stop")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_daemon_stop() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("stop")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("status")
        .arg("--project")
        .arg(TEST_PROJECT)
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

    let Some(harness) = try_start_daemon() else {
        return;
    };

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("restart")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("stop")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_start_when_running() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("start")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("already running"));

    drop(harness);
}
