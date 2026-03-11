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
fn test_enum_create() {
    require_ghidra!();
    let _harness = harness();
    let name = unique_name("TestEnum");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("enum")
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
fn test_enum_create_with_members() {
    require_ghidra!();
    let _harness = harness();
    let name = unique_name("TestEnumMembers");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("enum")
        .arg("create")
        .arg(&name)
        .arg("--members")
        .arg(r#"[{"name":"RED","value":0},{"name":"GREEN","value":1},{"name":"BLUE","value":2}]"#)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_typedef_create() {
    require_ghidra!();
    let _harness = harness();
    let name = unique_name("MYINT");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("typedef")
        .arg("create")
        .arg(&name)
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_parse_c_type() {
    require_ghidra!();
    let _harness = harness();
    let name = unique_name("parsed_struct");
    let c_def = format!("struct {} {{ int x; int y; }};", name);

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("parse-c")
        .arg(&c_def)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}
