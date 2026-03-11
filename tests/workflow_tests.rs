use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, get_function_address, DaemonTestHarness};

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
fn test_workflow_discover_analyze_annotate() {
    require_ghidra!();
    let _h = harness();

    let list_out = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("list")
        .arg("--json")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to list functions");
    assert!(list_out.status.success(), "function list should succeed");

    let decomp_out = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("decompile")
        .arg("main")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to decompile main");
    assert!(decomp_out.status.success(), "decompile main should succeed");

    let main_addr = get_function_address(harness(), TEST_PROJECT, TEST_PROGRAM, "main");
    let comment_text = unique_name("workflow_note");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("set")
        .arg(&main_addr)
        .arg(&comment_text)
        .arg("--comment-type")
        .arg("PRE")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    let get_comment = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("get")
        .arg(&main_addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to get comment");
    assert!(get_comment.status.success(), "comment get should succeed");
    let comment_stdout = String::from_utf8_lossy(&get_comment.stdout);
    assert!(
        comment_stdout.contains(&comment_text),
        "comment text should persist. output: {}",
        comment_stdout
    );

    let var_out = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("variable")
        .arg("list")
        .arg("main")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to list variables");
    assert!(var_out.status.success(), "variable list should succeed");
}

#[test]
#[serial]
fn test_workflow_type_and_bookmark_cycle() {
    require_ghidra!();
    let _h = harness();

    let struct_name = unique_name("WorkflowStruct");
    let enum_name = unique_name("WorkflowEnum");
    let typedef_name = unique_name("WorkflowTypedef");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("create")
        .arg(&struct_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("struct")
        .arg("add-field")
        .arg(&struct_name)
        .arg("field_a")
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("enum")
        .arg("create")
        .arg(&enum_name)
        .arg("--members")
        .arg(r#"[{"name":"ZERO","value":0},{"name":"ONE","value":1}]"#)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("typedef")
        .arg("create")
        .arg(&typedef_name)
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    let main_addr = get_function_address(harness(), TEST_PROJECT, TEST_PROGRAM, "main");
    let bm_comment = unique_name("workflow_bm");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("bookmark")
        .arg("add")
        .arg(&main_addr)
        .arg("--type")
        .arg("Note")
        .arg("--comment")
        .arg(&bm_comment)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    let list_bm = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("bookmark")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to list bookmarks");
    assert!(list_bm.status.success(), "bookmark list should succeed");
    let bm_stdout = String::from_utf8_lossy(&list_bm.stdout);
    assert!(
        bm_stdout.contains(&bm_comment) || bm_stdout.contains(&main_addr),
        "bookmark should be visible in list. output: {}",
        bm_stdout
    );
}
