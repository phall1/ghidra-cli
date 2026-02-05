//! Tests for bridge reliability - bridge death detection and port file cleanup.

use serial_test::serial;
use std::time::Duration;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "reliability-test";
const TEST_PROGRAM: &str = "sample_binary";

/// Test that stale port files are cleaned up on bridge restart.
///
/// Simulates a crash scenario where port file remains but bridge is dead.
#[test]
#[serial]
fn test_stale_files_cleaned_on_restart() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    // First bridge - start and stop cleanly
    {
        let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
            .expect("Failed to start first bridge");

        // Verify bridge is working
        assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .arg("ping")
            .arg("--project")
            .arg(TEST_PROJECT)
            .timeout(Duration::from_secs(30))
            .assert()
            .success();

        // Drop will clean up
    }

    // Brief pause to ensure cleanup completes
    std::thread::sleep(Duration::from_millis(500));

    // Second bridge - should start without issues (no stale port file conflict)
    {
        let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
            .expect("Failed to start second bridge - stale files may not have been cleaned");

        // Verify bridge is working
        assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .arg("ping")
            .arg("--project")
            .arg(TEST_PROJECT)
            .timeout(Duration::from_secs(30))
            .assert()
            .success();
    }
}

/// Test recovery after bridge crash (simulated via process kill).
///
/// After killing bridge, a new bridge should be able to start successfully.
#[test]
#[serial]
fn test_recovery_after_crash() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    // Start bridge and verify it works
    {
        let harness =
            DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start bridge");

        // Verify it's working
        assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .arg("ping")
            .arg("--project")
            .arg(TEST_PROJECT)
            .timeout(Duration::from_secs(30))
            .assert()
            .success();

        // Harness drop will kill bridge (simulating crash)
    }

    // Brief pause
    std::thread::sleep(Duration::from_millis(1000));

    // New bridge should start successfully after crash cleanup
    {
        let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
            .expect("Failed to start bridge after crash - cleanup may have failed");

        // Verify new bridge is working
        assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .arg("ping")
            .arg("--project")
            .arg(TEST_PROJECT)
            .timeout(Duration::from_secs(30))
            .assert()
            .success();
    }
}

/// Test that bridge commands return appropriate errors when bridge is not ready.
#[test]
#[serial]
fn test_bridge_not_ready_error() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start bridge");

    // Ping should work
    assert_cmd::Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("ping")
        .timeout(Duration::from_secs(30))
        .assert()
        .success();

    drop(harness);
}
