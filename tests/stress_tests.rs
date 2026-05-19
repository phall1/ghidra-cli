//! Stress tests for warm-bridge resource stability (E3.4 / ghidra-cli-ajr).
//!
//! Single-call E2E tests are blind to slow leaks: a handler that drops a
//! file descriptor or accumulates objects every call only shows up after
//! hundreds of round trips. This test fires 1000 sequential `ping` /
//! `bridge_info` calls at a warm bridge and asserts that:
//!
//!   - the JVM heap doesn't grow more than `HEAP_GROWTH_BUDGET_BYTES`
//!   - the bridge process's open-file-descriptor count is stable
//!     (delta within `FD_DELTA_BUDGET`)
//!
//! Bridge heap is read from the `bridge_info` JSON (extended in this PR to
//! carry `heap_used_bytes`). FD counts come from `lsof -p <pid>` on
//! Linux/macOS; the FD check is skipped on platforms where `lsof` isn't
//! available (notably Windows runners).

use serial_test::serial;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

/// How many round-trips to fire. Issue spec: 1000.
const STRESS_CALLS: usize = 1000;

/// Per-issue acceptance: heap growth < 50 MB.
const HEAP_GROWTH_BUDGET_BYTES: i64 = 50 * 1024 * 1024;

/// FD count is allowed a small jitter — the JVM may open a few backing files
/// for class loading on first-touch handlers. The point of the gate is to
/// catch *unbounded* growth (e.g. a leaked socket per call), not chase
/// every +/- 5 fluctuation.
const FD_DELTA_BUDGET: i64 = 20;

#[test]
#[serial]
fn warm_bridge_1000_calls_keeps_resources_bounded() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = match DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM) {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("program file(s) not found") {
                eprintln!("Skipping: bridge can't find program (known macOS issue)");
                return;
            }
            panic!("Failed to start bridge: {}", e);
        }
    };

    let client = harness.client().expect("client");

    // Warm up: the very first call after import can pay a one-shot
    // class-loading + decompiler-init tax. Burn that cost outside the
    // measurement so it doesn't bias the heap baseline.
    for _ in 0..10 {
        let _ = client.ping().expect("warmup ping");
    }
    let _ = client.bridge_info().expect("warmup bridge_info");

    let baseline = capture_snapshot(&harness, &client);
    eprintln!(
        "baseline: heap_used={} bytes  fd_count={:?}",
        baseline.heap_used_bytes, baseline.fd_count
    );

    let started = std::time::Instant::now();
    for i in 0..STRESS_CALLS {
        client
            .ping()
            .unwrap_or_else(|e| panic!("ping #{} failed: {}", i, e));
    }
    let elapsed = started.elapsed();
    eprintln!(
        "fired {} pings in {:.2}s ({:.0}/s)",
        STRESS_CALLS,
        elapsed.as_secs_f64(),
        STRESS_CALLS as f64 / elapsed.as_secs_f64()
    );

    let after = capture_snapshot(&harness, &client);
    eprintln!(
        "after:    heap_used={} bytes  fd_count={:?}",
        after.heap_used_bytes, after.fd_count
    );

    // Heap delta gate. The JVM may also *shrink* (GC), which is fine; only
    // unbounded growth is a regression signal.
    let heap_delta = after.heap_used_bytes as i64 - baseline.heap_used_bytes as i64;
    assert!(
        heap_delta < HEAP_GROWTH_BUDGET_BYTES,
        "JVM heap grew {} bytes over {} calls (budget {} bytes). \
         Baseline {} -> after {}.",
        heap_delta,
        STRESS_CALLS,
        HEAP_GROWTH_BUDGET_BYTES,
        baseline.heap_used_bytes,
        after.heap_used_bytes,
    );

    // FD gate. Only enforced when we could get a reading on both ends —
    // on macOS/Linux `lsof` is universally present; on Windows we skip.
    if let (Some(b), Some(a)) = (baseline.fd_count, after.fd_count) {
        let fd_delta = a as i64 - b as i64;
        assert!(
            fd_delta.abs() < FD_DELTA_BUDGET,
            "bridge FD count drifted by {} over {} calls (budget +/-{}). \
             Baseline {} -> after {}.",
            fd_delta,
            STRESS_CALLS,
            FD_DELTA_BUDGET,
            b,
            a,
        );
    } else {
        eprintln!("FD-count gate skipped (lsof not available or pid missing)");
    }
}

/// One sampled view of bridge-side resource usage.
struct ResourceSnapshot {
    heap_used_bytes: u64,
    fd_count: Option<u32>,
}

fn capture_snapshot(
    harness: &DaemonTestHarness,
    client: &ghidra_cli::ipc::client::BridgeClient,
) -> ResourceSnapshot {
    let info = client.bridge_info().expect("bridge_info");
    let heap_used_bytes = info
        .get("heap_used_bytes")
        .and_then(|v| v.as_u64())
        .expect("bridge_info should expose heap_used_bytes (Java side)");

    // Mirror DaemonTestHarness::new's project-path construction so we look
    // up the PID file in the same place the harness wrote it.
    let project_path = dirs::cache_dir()
        .expect("cache dir")
        .join("ghidra-cli")
        .join("projects")
        .join(harness.project());
    let pid = ghidra_cli::ghidra::bridge::read_pid_file(&project_path)
        .ok()
        .flatten();

    let fd_count = pid.and_then(open_fd_count);

    ResourceSnapshot {
        heap_used_bytes,
        fd_count,
    }
}

/// Count open file descriptors for `pid`. Returns `None` if the platform
/// doesn't support it or the underlying probe fails — callers treat that
/// as "skip the FD gate", not as a test failure.
fn open_fd_count(pid: u32) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        // /proc is authoritative and cheap. Don't shell out to lsof if we
        // can read directly.
        let entries = std::fs::read_dir(format!("/proc/{}/fd", pid)).ok()?;
        Some(entries.filter_map(|e| e.ok()).count() as u32)
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("lsof")
            .args(["-p", &pid.to_string(), "-n", "-P"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        // First line is the header from lsof; subtract it.
        let line_count = out.stdout.iter().filter(|b| **b == b'\n').count() as u32;
        Some(line_count.saturating_sub(1))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

