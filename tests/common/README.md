# Common Test Utilities

Shared infrastructure for E2E tests.

## DaemonTestHarness

Manages daemon lifecycle for test suites requiring Ghidra daemon interaction.

### Usage

```rust
use common::{DaemonTestHarness, ensure_test_project};

const TEST_PROJECT: &str = "my-test";
const TEST_PROGRAM: &str = "sample_binary";

#[test]
#[serial]
fn test_with_daemon() {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness = DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon");

    let mut client = harness.client().unwrap();
    // Use client for IPC calls

    // Daemon automatically shuts down when harness drops
}
```

### Shared Daemon Pattern

For multiple tests in same suite:

```rust
use once_cell::sync::Lazy;

static HARNESS: Lazy<DaemonTestHarness> = Lazy::new(|| {
    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
    DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM)
        .expect("Failed to start daemon")
});

#[test]
#[serial]
fn test_one() {
    let harness = &*HARNESS;
    // Use harness
}

#[test]
#[serial]
fn test_two() {
    let harness = &*HARNESS;
    // Same daemon instance
}
```

All tests using shared daemon must be marked `#[serial]` to prevent state races.

### Why Runtime Field Exists

`DaemonTestHarness` contains a `tokio::runtime::Runtime` field to:

1. **Prevent panic-during-panic**: Creating Runtime during Drop panic unwinding causes abort. Pre-created runtime allows safe cleanup.
2. **Amortize overhead**: Runtime creation takes ~10ms. Reusing across all async operations saves time.

### Socket Path Isolation

Each harness instance generates UUID-based Unix socket path:
```
/tmp/ghidra-test-<uuid>.sock
```

UUID prevents collisions:
- Between parallel test suites
- Across test runs on long-running CI (PID can wrap)

### Cleanup Guarantees

Drop implementation ensures best-effort cleanup:
1. Send shutdown via IPC (ignores errors)
2. Wait up to 5s for graceful exit
3. Kill process if still running
4. Remove socket file

Accepts minor leak risk on panic-during-panic (rare edge case).

## Fixtures

### fixture_binary()

Returns path to compiled sample_binary fixture.

```rust
let binary = fixture_binary();
assert!(binary.exists());
```

Binary must be compiled before tests:
```bash
rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs
```

### ensure_test_project()

Idempotent project setup using `Once::call_once`. Imports and analyzes sample_binary if needed.

```rust
ensure_test_project("my-project", "sample_binary");
// Second call does nothing - project already exists
```

Handles "already exists" errors gracefully. Safe to call from multiple tests.

## require_ghidra! Macro

Tests should call this macro to assert Ghidra availability up front:

```rust
#[test]
fn test_something() {
    require_ghidra!();

    // Test code runs only if ghidra doctor succeeds
}
```

Runs `ghidra doctor` and fails the test if Ghidra is unavailable, including doctor output.

## Design Decisions

### Exponential Backoff Parameters

`wait_for_ready()` uses:
- Initial delay: 100ms (responsive for fast starts)
- Multiplier: 2x
- Max attempts: 12
- Total timeout: 120s

Covers 100ms to ~200s range. Typical fast start exits in <5s.

### ChildGuard Pattern

`DaemonTestHarness::new()` uses ChildGuard to prevent daemon process leaks:

```rust
struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
        }
    }
}
```

If `wait_for_ready()` returns early due to error, ChildGuard ensures daemon process is killed. Without this, failed initialization leaks processes.

### Why 5s Shutdown Timeout

Most daemons shut down in <1s. 5s allows graceful cleanup without blocking tests indefinitely. If daemon hangs, hard kill prevents test suite deadlock.
