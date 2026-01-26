//! Tests for query commands that require daemon.

use assert_cmd::Command;
use once_cell::sync::Lazy;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "query-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: Lazy<DaemonTestHarness> = Lazy::new(|| {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
    DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
});

#[test]
#[serial]
fn test_function_list() {
    let harness = &*HARNESS;

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("function")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    assert!(stdout.contains("main"));
    assert!(stdout.contains("fibonacci") || stdout.contains("factorial"));
}

#[test]
#[serial]
fn test_function_list_limit() {
    let harness = &*HARNESS;

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("function")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--limit")
        .arg("5")
        .assert()
        .success();
}

#[test]
#[serial]
fn test_function_list_filter() {
    let harness = &*HARNESS;

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("function")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--filter")
        .arg("main")
        .assert()
        .success()
        .stdout(predicate::str::contains("main"));
}

#[test]
#[serial]
fn test_strings_list() {
    let harness = &*HARNESS;

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("strings")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--limit")
        .arg("100")
        .assert()
        .success()
        .stdout(predicate::str::contains("address"));
}

#[test]
#[serial]
fn test_memory_map() {
    let harness = &*HARNESS;

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("memory")
        .arg("map")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains(".text").or(predicate::str::contains("r")));
}

#[test]
#[serial]
fn test_summary() {
    let harness = &*HARNESS;

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("summary")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("Program Summary"));
}

#[test]
#[serial]
fn test_decompile_by_name() {
    let harness = &*HARNESS;

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("decompile")
        .arg("main")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("void").or(predicate::str::contains("int")));
}

#[test]
#[serial]
fn test_decompile_by_address() {
    let harness = &*HARNESS;

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("function")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    let functions: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let main_addr = functions
        .as_array()
        .and_then(|arr| arr.iter().find(|f| f["name"].as_str() == Some("main")))
        .and_then(|f| f["address"].as_str())
        .expect("Could not find main function address");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("decompile")
        .arg(main_addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_xref_to() {
    let harness = &*HARNESS;

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("function")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    let functions: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let main_addr = functions
        .as_array()
        .and_then(|arr| arr.iter().find(|f| f["name"].as_str() == Some("main")))
        .and_then(|f| f["address"].as_str())
        .expect("Could not find main function address");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("xref")
        .arg("to")
        .arg(main_addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_xref_from() {
    let harness = &*HARNESS;

    let output = Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("function")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    let functions: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let main_addr = functions
        .as_array()
        .and_then(|arr| arr.iter().find(|f| f["name"].as_str() == Some("main")))
        .and_then(|f| f["address"].as_str())
        .expect("Could not find main function address");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("xref")
        .arg("from")
        .arg(main_addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}
