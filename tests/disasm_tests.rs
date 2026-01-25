//! Tests for disassembly operations.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "disasm-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_disasm_at_main() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("disasm")
        .arg("0x101040")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("results"));

    drop(harness);
}

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_disasm_with_instruction_limit() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("disasm")
        .arg("0x101040")
        .arg("--instructions")
        .arg("10")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("results"))
        .stdout(predicate::str::contains("mnemonic"));

    drop(harness);
}

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_disasm_at_data_section() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("disasm")
        .arg("0x104000")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert();

    drop(harness);
}

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_disasm_invalid_address() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("disasm")
        .arg("0xFFFFFFFFFFFF")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert();

    drop(harness);
}

#[test]
#[serial]
#[ignore] // Requires Ghidra installation
fn test_disasm_small_count() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("disasm")
        .arg("0x101040")
        .arg("--instructions")
        .arg("3")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("results"));

    drop(harness);
}
