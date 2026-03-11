//! Tests for struct/structure operations.

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
fn test_struct_create() {
    require_ghidra!();
    let _harness = harness();

    let name = unique_name("TestStructCreate");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_struct_get() {
    require_ghidra!();
    let _harness = harness();

    let name = unique_name("TestStructGet");

    // Create
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("get")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains(&name));
}

#[test]
#[serial]
fn test_struct_list() {
    require_ghidra!();
    let _harness = harness();

    let name = unique_name("TestStructList");

    // Create a struct first
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // List structs
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains(&name));
}

#[test]
#[serial]
fn test_struct_add_field() {
    require_ghidra!();
    let _harness = harness();

    let name = unique_name("TestStructAddField");

    // Create
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Add field
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("add-field")
        .arg(&name)
        .arg("field1")
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get and verify field
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("get")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("field1"));
}

#[test]
#[serial]
fn test_struct_add_multiple_fields() {
    require_ghidra!();
    let _harness = harness();

    let name = unique_name("TestStructMultiField");

    // Create
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Add fields
    for (field_name, field_type) in &[("value", "int"), ("flag", "byte"), ("ptr", "pointer")] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("struct")
            .arg("add-field")
            .arg(&name)
            .arg(field_name)
            .arg(field_type)
            .arg("--project")
            .arg(TEST_PROJECT)
            .arg("--program")
            .arg(TEST_PROGRAM)
            .assert()
            .success();
    }

    // Get and verify all fields
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("get")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("value"),
        "should contain field 'value': {}",
        stdout
    );
    assert!(
        stdout.contains("flag"),
        "should contain field 'flag': {}",
        stdout
    );
    assert!(
        stdout.contains("ptr"),
        "should contain field 'ptr': {}",
        stdout
    );
}

#[test]
#[serial]
fn test_struct_rename_field() {
    require_ghidra!();
    let _harness = harness();

    let name = unique_name("TestStructRenameField");

    // Create struct with a field
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("add-field")
        .arg(&name)
        .arg("old_field")
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Rename field
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("rename-field")
        .arg(&name)
        .arg("old_field")
        .arg("new_field")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get and verify renamed field
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("get")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("new_field"));
}

#[test]
#[serial]
fn test_struct_delete() {
    require_ghidra!();
    let _harness = harness();

    let name = unique_name("TestStructDelete");

    // Create
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Delete
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("delete")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify gone
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("get")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}

#[test]
#[serial]
fn test_struct_get_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("get")
        .arg("NonexistentStruct_99999")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}

#[test]
#[serial]
fn test_struct_full_lifecycle() {
    require_ghidra!();
    let _harness = harness();

    let name = unique_name("TestStructLifecycle");

    // Create
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Add fields
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("add-field")
        .arg(&name)
        .arg("x")
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("add-field")
        .arg(&name)
        .arg("y")
        .arg("byte")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Rename field
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("rename-field")
        .arg(&name)
        .arg("x")
        .arg("x_renamed")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get and verify
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("get")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("x_renamed"),
        "should contain renamed field: {}",
        stdout
    );
    assert!(stdout.contains("y"), "should contain field y: {}", stdout);

    // Delete
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("delete")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify gone
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("get")
        .arg(&name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}
