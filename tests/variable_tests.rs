//! Tests for variable operations (list, rename, retype).

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

fn unique_name(prefix: &str) -> String {
    format!("{}_{}", prefix, std::process::id())
}

#[test]
#[serial]
fn test_variable_list() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("list")
        .arg("main")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(
        output.status.success(),
        "variable list should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("main") || stdout.contains("_main"),
        "variable list output should contain function name. Output: {}",
        stdout
    );
}

#[test]
#[serial]
fn test_variable_list_json() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("list")
        .arg("main")
        .arg("--json")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(
        output.status.success(),
        "variable list --json should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("variable list --json should return valid JSON");
    assert!(
        parsed.get("variables").is_some()
            || parsed
                .get("data")
                .and_then(|d| d.get("variables"))
                .is_some(),
        "JSON should contain variables array. Output: {}",
        stdout
    );
}

#[test]
#[serial]
fn test_variable_rename() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("list")
        .arg("add")
        .arg("--json")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(
        output.status.success(),
        "variable list should succeed for add function. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("Failed to parse JSON: {}", stdout));

    let variables = parsed
        .get("variables")
        .or_else(|| parsed.get("data").and_then(|d| d.get("variables")))
        .and_then(|v| v.as_array())
        .expect("Should have variables array");

    assert!(
        !variables.is_empty(),
        "add function should have at least one variable"
    );

    let first_var_name = variables[0]["name"]
        .as_str()
        .expect("Variable should have a name");

    let new_name = unique_name("renamed_var");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("rename")
        .arg("add")
        .arg(first_var_name)
        .arg(&new_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("renamed"));
}

#[test]
#[serial]
fn test_variable_retype() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("list")
        .arg("multiply")
        .arg("--json")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(
        output.status.success(),
        "variable list should succeed for multiply. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("Failed to parse JSON: {}", stdout));

    let variables = parsed
        .get("variables")
        .or_else(|| parsed.get("data").and_then(|d| d.get("variables")))
        .and_then(|v| v.as_array())
        .expect("Should have variables array");

    assert!(
        !variables.is_empty(),
        "multiply function should have at least one variable"
    );

    let var_name = variables[0]["name"]
        .as_str()
        .expect("Variable should have a name");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("retype")
        .arg("multiply")
        .arg(var_name)
        .arg("long")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("retyped"));
}

#[test]
#[serial]
fn test_variable_rename_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("rename")
        .arg("main")
        .arg("nonexistent_var_xyz")
        .arg("new_name")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("not found")
            || combined.contains("error")
            || combined.contains("Error")
            || !output.status.success(),
        "Renaming nonexistent variable should fail. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
#[serial]
fn test_variable_retype_bad_type() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("list")
        .arg("main")
        .arg("--json")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("Failed to parse JSON: {}", stdout));

    let variables = parsed
        .get("variables")
        .or_else(|| parsed.get("data").and_then(|d| d.get("variables")))
        .and_then(|v| v.as_array());

    if let Some(vars) = variables {
        if let Some(var_name) = vars.first().and_then(|v| v["name"].as_str()) {
            let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
                .arg("variable")
                .arg("retype")
                .arg("main")
                .arg(var_name)
                .arg("FakeNonExistentType123")
                .arg("--project")
                .arg(TEST_PROJECT)
                .arg("--program")
                .arg(TEST_PROGRAM)
                .output()
                .expect("Failed to run command");

            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout_err = String::from_utf8_lossy(&output.stdout);
            let combined = format!("{}{}", stdout_err, stderr);
            assert!(
                combined.contains("Unknown")
                    || combined.contains("error")
                    || combined.contains("Error")
                    || !output.status.success(),
                "Retyping with bad type should fail. stdout: {}, stderr: {}",
                stdout_err,
                stderr
            );
        }
    }
}
