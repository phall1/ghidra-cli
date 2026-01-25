//! Tests for basic CLI commands that don't require daemon.

use assert_cmd::Command;
use predicates::prelude::*;

mod common;

#[test]
fn test_version() {
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ghidra-cli"));
}

#[test]
fn test_doctor() {
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("Ghidra CLI Doctor"));
}

#[test]
fn test_config_list() {
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("config")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("ghidra_install_dir"));
}

#[test]
fn test_config_get() {
    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("config")
        .arg("get")
        .arg("ghidra_install_dir")
        .assert()
        .success();
}

#[test]
fn test_config_set() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("set")
        .arg("default_output_format")
        .arg("json")
        .assert()
        .success();
}

#[test]
fn test_config_reset() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("reset")
        .assert()
        .success();
}
