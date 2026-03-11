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

#[test]
#[serial]
fn test_analyzer_list() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("analyzer")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(
        output.status.success(),
        "analyzer list should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "analyzer list should return output");
}

#[test]
#[serial]
fn test_analyzer_set() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("analyzer")
        .arg("list")
        .arg("--json")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let analyzers = parsed
                .get("analyzers")
                .or_else(|| parsed.get("data").and_then(|d| d.get("analyzers")))
                .and_then(|a| a.as_array());

            if let Some(list) = analyzers {
                if let Some(first) = list.first() {
                    if let Some(name) = first.get("name").and_then(|n| n.as_str()) {
                        assert_cmd::cargo::cargo_bin_cmd!("ghidra")
                            .arg("analyzer")
                            .arg("set")
                            .arg(name)
                            .arg("false")
                            .arg("--project")
                            .arg(TEST_PROJECT)
                            .arg("--program")
                            .arg(TEST_PROGRAM)
                            .assert()
                            .success();
                    }
                }
            }
        }
    }
}
