# Bridge Management Module (`src/daemon/`)

Thin compatibility wrapper over `src/ghidra/bridge.rs`. All logic lives in `bridge.rs`; this module re-exports functions for callers that still reference `daemon::*`.

## Why This Module Exists

Historical: the original architecture had a separate Rust daemon process. Now the "daemon" is just the long-running Java bridge process. This module was kept to avoid breaking the `daemon::` import paths used by some callers and tests.

## API Surface

| Function | Delegates To |
|----------|-------------|
| `ensure_bridge(config, mode)` | `bridge::ensure_bridge_running()` |
| `start_bridge(config, mode)` | `bridge::start_bridge()` |
| `stop_bridge(project_path)` | `bridge::stop_bridge()` |
| `get_bridge_status(project_path)` | `bridge::bridge_status()` |
| `is_bridge_running(project_path) -> Option<u16>` | `bridge::is_bridge_running()` |

`is_bridge_running` returns `Option<u16>` (the port) instead of `bool`. Callers use the returned port directly, eliminating TOCTOU races between liveness checks and port file reads.

## Architecture

See `src/ghidra/README.md` for the canonical bridge architecture documentation, including:

- Bridge lifecycle (spawn, PID write, ready signal, port file)
- Liveness detection (port file + PID alive + BridgeClient ping)
- Auto-start behavior for Import, Quick, and Analyze commands
- TOCTOU elimination via `is_bridge_running() -> Option<u16>`

## Liveness Detection

Bridge liveness is verified in `bridge::is_bridge_running()` and `bridge::bridge_status()`:

1. **Port file exists** -- `bridge-{hash}.port` in `~/.local/share/ghidra-cli/`
2. **PID alive** -- `kill(pid, 0)` succeeds on Unix
3. **TCP reachable** -- `TcpStream::connect("127.0.0.1:{port}")` succeeds (in `is_bridge_running`)
4. **Ping verified** -- `BridgeClient::new(port).ping()` returns true (in `bridge_status` and `verify_bridge`)

`is_bridge_running` uses a raw TCP probe (step 3) for speed. `bridge_status` uses BridgeClient ping (step 4) for stronger verification. The `verify_bridge()` helper in `main.rs` is called after connecting to an existing bridge to confirm it responds to commands.

## Command Flow

All commands flow through the OutputFormat formatter in `main.rs`:

1. Import/Quick produce structured `serde_json::Value` directly
2. Analyze and query commands go through `execute_via_bridge()` which returns `serde_json::Value`
3. The formatter at the end of `run_with_bridge()` applies Table, JSON, or JsonCompact formatting
4. Progress messages use `eprintln!()` (stderr), structured output uses `println!()` (stdout)

## Auto-Start Behavior

| Command | Bridge Not Running | Bridge Running |
|---------|-------------------|----------------|
| Import | Start bridge in Import mode | Import via `client.import_binary()`, switch program |
| Quick | Start bridge in Import mode, analyze | Import via running bridge, switch program, analyze |
| Analyze | Start bridge in Process mode, analyze via `execute_via_bridge` | Analyze via `execute_via_bridge` |
| Query commands | Start bridge in Process mode | Connect and query |

Quick reuses a running bridge by importing through the bridge's `import` command and switching to the new program, rather than starting a fresh bridge in Import mode.

Analyze has no special-case handler. It falls through to the generic dispatch path in `execute_via_bridge()`.

## Key Differences from Original Architecture

- No separate Rust daemon process; the Java bridge IS the persistent server
- `BridgeClient` (in `src/ipc/client.rs`) is the single TCP command implementation; bridge.rs uses raw `TcpStream` only for lightweight connect probes, not for sending commands
- `is_bridge_running()` returns `Option<u16>` (port), not `bool`
- `bridge_status()` uses `BridgeClient.ping()` instead of raw `TcpStream::connect`
- `stop_bridge()` uses `BridgeClient.shutdown()` for graceful shutdown
- Rust writes PID file immediately after spawn (before Java ready signal)
- Failed starts kill orphaned child processes and clean up stale files
