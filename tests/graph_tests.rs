//! Tests for graph operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "graph-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_graph_calls() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("graph")
        .arg("calls")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("nodes"))
        .stdout(predicate::str::contains("edges"));

    drop(harness);
}

#[test]
#[serial]
fn test_graph_callers() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("graph")
        .arg("callers")
        .arg("main")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("callers"));

    drop(harness);
}

#[test]
#[serial]
fn test_graph_callees() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("graph")
        .arg("callees")
        .arg("main")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("callees"));

    drop(harness);
}

#[test]
#[serial]
fn test_graph_export_dot() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("graph")
        .arg("export")
        .arg("dot")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("digraph"));

    drop(harness);
}
