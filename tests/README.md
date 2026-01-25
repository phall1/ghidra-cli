# E2E Test Suite

Comprehensive end-to-end test coverage for ghidra-cli commands.

## Architecture

Tests are organized by functional area into separate files:

```
tests/
├── common/
│   └── mod.rs           # DaemonTestHarness, fixtures, helpers
├── daemon_tests.rs      # Daemon lifecycle: start/stop/restart/status/ping
├── project_tests.rs     # Project: create/list/delete/info
├── query_tests.rs       # Function/strings/memory/xref/dump queries
├── command_tests.rs     # Basic commands: version/doctor/config/init
├── unimplemented_tests.rs  # Graceful error tests for stub commands
└── e2e.rs               # Lightweight smoke test
```

## Per-Suite Daemon Lifecycle

Tests requiring daemon interaction use `DaemonTestHarness` from `common/mod.rs`. Each test suite starts its own daemon instance to amortize 5-30s startup overhead across all tests in that file.

**Why per-suite instead of per-test**: Starting a daemon for every test would add 5-30 minutes to CI time for 60+ tests. Per-suite daemons run tests serially within the suite but allow parallel execution across different test files.

**Why not shared global daemon**: State leakage between suites causes flaky tests and debugging nightmares. Each suite gets isolation.

## Data Flow

```
Test Suite Start
      |
      v
DaemonTestHarness::new()
      |
      +---> Start daemon process
      +---> Wait for IPC socket
      +---> Verify with ping
      |
      v
Run tests (serial within suite)
      |
      v
DaemonTestHarness::drop()
      |
      +---> Send shutdown command
      +---> Wait for process exit
      +---> Cleanup socket file
```

## Running Tests

Run all tests:
```bash
cargo test
```

Run specific test suite:
```bash
cargo test --test daemon_tests
cargo test --test query_tests
cargo test --test command_tests
```

Run single test:
```bash
cargo test --test query_tests test_function_list
```

Skip daemon tests (faster):
```bash
cargo test --test command_tests
cargo test --test project_tests --lib
```

## Test Requirements

### Ghidra Installation

Tests check for Ghidra availability using `skip_if_no_ghidra!()` macro. Tests skip with clear message if `ghidra doctor` fails.

### Test Fixtures

Sample binary fixture required: `tests/fixtures/sample_binary`

Build fixture:
```bash
rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs
```

Fixture contains functions: add, multiply, factorial, fibonacci, process_string, xor_encrypt, simple_hash, init_data, main

## Adding New Tests

### Non-Daemon Tests

Add to appropriate file (`command_tests.rs`, `project_tests.rs`):

```rust
#[test]
fn test_my_command() {
    skip_if_no_ghidra!();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("my-command")
        .assert()
        .success();
}
```

### Daemon-Dependent Tests

Add to `daemon_tests.rs` or `query_tests.rs`:

```rust
#[test]
#[serial]
fn test_my_query() {
    skip_if_no_ghidra!();

    let harness = &*HARNESS;  // Shared daemon instance

    Command::cargo_bin("ghidra")
        .unwrap()
        .env("GHIDRA_CLI_SOCKET", harness.socket_path())
        .arg("my-query")
        .arg("--project").arg(TEST_PROJECT)
        .arg("--program").arg(TEST_PROGRAM)
        .assert()
        .success();
}
```

Mark with `#[serial]` to prevent daemon state races within suite.

## Invariants

- Daemon must be fully started before any query test runs
- Each test suite gets its own daemon instance (no sharing)
- Socket files must be cleaned up even on test failure (Drop impl)
- Tests must not assume specific function addresses (use name-based lookups)

## Troubleshooting

### "Daemon failed to start within 120s timeout"

Ghidra cold start can be slow. Ensure:
- Ghidra installation is valid (`ghidra doctor`)
- Sufficient disk space for temporary Ghidra project
- Not running on extremely constrained CI resources

### "Test fixture not found"

Compile sample_binary:
```bash
rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs
```

### "Socket already in use" / "Address in use"

Each test suite generates UUID-based socket path to prevent collisions. This error suggests:
- Previous test run leaked daemon process (kill manually)
- Filesystem issue preventing socket cleanup

Find leaked processes:
```bash
ps aux | grep ghidra
kill <pid>
```

### Tests hang or timeout

- Check if Ghidra daemon is stuck (check process list)
- Verify network/IPC permissions for Unix sockets
- Increase timeout in test (daemon startup can vary)

### Import/analysis takes too long

Tests use 300s timeout for import/analyze operations. On slow systems:
- Run fewer parallel test suites
- Ensure Ghidra has adequate heap memory
- Check disk I/O performance

## Tradeoffs

**Per-suite vs per-test daemon**: Chose speed over maximum isolation. Tests within suite are serial, but suite-to-suite parallelism maintained.

**UUID socket paths vs fixed paths**: Chose reliability over simplicity. Guarantees uniqueness even with PID wrap on long-running CI.

**Testing unimplemented commands**: Adds maintenance burden but documents gaps and ensures graceful failures for stub commands.
