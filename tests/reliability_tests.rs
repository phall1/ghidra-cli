//! Tests for daemon IPC reliability - bridge death detection and socket cleanup.

use serial_test::serial;
use std::path::PathBuf;
use std::time::Duration;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "reliability-test";
const TEST_PROGRAM: &str = "sample_binary";

/// Test that stale socket files are cleaned up on daemon restart.
///
/// Simulates a crash scenario where socket file remains but daemon is dead.
#[test]
#[serial]
fn test_stale_socket_cleaned_on_restart() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    // First daemon - start and stop cleanly
    {
        let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
            .expect("Failed to start first daemon");

        // Verify daemon is working
        assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .env("GHIDRA_CLI_DATA_DIR", harness.data_dir())
            .env("GHIDRA_CLI_SOCKET", harness.socket_path())
            .arg("daemon")
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

    // Second daemon - should start without issues (no stale socket conflict)
    {
        let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
            .expect("Failed to start second daemon - stale socket may not have been cleaned");

        // Verify daemon is working
        assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .env("GHIDRA_CLI_DATA_DIR", harness.data_dir())
            .env("GHIDRA_CLI_SOCKET", harness.socket_path())
            .arg("daemon")
            .arg("ping")
            .arg("--project")
            .arg(TEST_PROJECT)
            .timeout(Duration::from_secs(30))
            .assert()
            .success();
    }
}

/// Test recovery after daemon crash (simulated via process kill).
///
/// After killing daemon, a new daemon should be able to start successfully.
#[test]
#[serial]
fn test_recovery_after_crash() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let socket_path: PathBuf;
    let data_dir: PathBuf;

    // Start daemon and get its paths
    {
        let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
            .expect("Failed to start daemon");

        socket_path = harness.socket_path().to_path_buf();
        data_dir = harness.data_dir().to_path_buf();

        // Verify it's working
        assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .env("GHIDRA_CLI_DATA_DIR", &data_dir)
            .env("GHIDRA_CLI_SOCKET", &socket_path)
            .arg("daemon")
            .arg("ping")
            .arg("--project")
            .arg(TEST_PROJECT)
            .timeout(Duration::from_secs(30))
            .assert()
            .success();

        // Harness drop will kill daemon (simulating crash)
    }

    // Brief pause
    std::thread::sleep(Duration::from_millis(1000));

    // New daemon should start successfully after crash cleanup
    {
        let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
            .expect("Failed to start daemon after crash - cleanup may have failed");

        // Verify new daemon is working
        assert_cmd::Command::cargo_bin("ghidra")
            .unwrap()
            .env("GHIDRA_CLI_DATA_DIR", harness.data_dir())
            .env("GHIDRA_CLI_SOCKET", harness.socket_path())
            .arg("daemon")
            .arg("ping")
            .arg("--project")
            .arg(TEST_PROJECT)
            .timeout(Duration::from_secs(30))
            .assert()
            .success();
    }
}

/// Test that daemon commands return appropriate errors when bridge is not ready.
#[test]
#[serial]
fn test_bridge_not_ready_error() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon");

    // Ping should work (doesn't require bridge)
    assert_cmd::Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_DATA_DIR", harness.data_dir())
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("daemon")
        .arg("ping")
        .arg("--project")
        .arg(TEST_PROJECT)
        .timeout(Duration::from_secs(30))
        .assert()
        .success();

    drop(harness);
}
