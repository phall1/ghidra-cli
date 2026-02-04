# Bridge Architecture

The bridge is the central execution layer for ghidra-cli. All commands route through a Java bridge running inside Ghidra's JVM, which maintains persistent access to the loaded program.

## Architecture

```
┌─────────────┐         ┌──────────────────────────────────────┐
│ CLI Client  │──TCP──▶ │ GhidraCliBridge.java                 │
│ (ghidra)    │         │ (GhidraScript in analyzeHeadless JVM)│
│ --project X │         │ ServerSocket on localhost:dynamic     │
└─────────────┘         └──────────────────────────────────────┘
```

### Per-Project Bridge Isolation

Each project gets its own bridge process with unique port/PID files:

- **Port file**: `~/.local/share/ghidra-cli/bridge-{hash}.port` — contains the TCP port number
- **PID file**: `~/.local/share/ghidra-cli/bridge-{hash}.pid` — contains the JVM process ID
- **Hash**: MD5 of the canonical project path

This allows multiple agents or terminals to work on different projects without conflicts.

## Key Components

| File | Purpose |
|------|---------|
| `src/ghidra/bridge.rs` | Bridge process management (start, stop, status, connect) |
| `src/ghidra/scripts/GhidraCliBridge.java` | Java bridge server (TCP, 17+ command handlers) |
| `src/ipc/client.rs` | BridgeClient — TCP connection, all command methods |
| `src/ipc/protocol.rs` | BridgeRequest/BridgeResponse structs (JSON wire format) |
| `src/ipc/transport.rs` | TCP transport helpers (port reachability check) |
| `src/daemon/mod.rs` | Thin wrapper over bridge.rs (kept for API compatibility) |

## Command Flow

1. **CLI parses command** and resolves project path
2. **Bridge discovery**: read port file, verify PID alive, verify TCP connect
3. **Auto-start**: if bridge not running, spawn `analyzeHeadless -postScript GhidraCliBridge.java`
4. **Send command**: TCP connect to localhost:port, send `{"command":"...","args":{...}}\n`
5. **Receive response**: read `{"status":"success|error","data":{...},"message":"..."}\n`
6. **Format output**: CLI applies format transformation (human-readable, JSON, pretty)

## Auto-Start Behavior

Import, Analyze, and Quick commands auto-start the bridge:

1. CLI reads port file for the project
2. If missing or stale (dead PID, TCP connect fails): launch `analyzeHeadless` with Java bridge
3. Bridge binds `ServerSocket(0)`, writes port + PID files, prints ready signal
4. CLI reads port from file, connects, sends command

## Lifecycle

- **One bridge per project** — port file path includes project hash
- **Sequential command processing** — single accept loop, one connection at a time (Ghidra Program objects are not thread-safe)
- **Graceful shutdown** — `shutdown` command breaks accept loop, deletes port/PID files, `run()` returns, `analyzeHeadless` exits
- **Forced shutdown** — read PID file, kill process
- **Stale file cleanup** — on startup, detect dead PID + unreachable port → clean up files and start fresh

The `{hash}` is computed as `MD5(project_path_string)` ensuring each project has unique port and PID file names.

## Bridge Commands

Commands handled by GhidraCliBridge.java:

| Category | Commands |
|----------|----------|
| Core | `ping`, `shutdown`, `status` |
| Program | `program_info`, `list_programs`, `open_program`, `program_close`, `program_delete`, `program_export` |
| Import/Analysis | `import`, `analyze` |
| Functions | `list_functions`, `decompile` |
| Data | `list_strings`, `list_imports`, `list_exports`, `memory_map` |
| Xrefs | `xrefs_to`, `xrefs_from` |
| Symbols | `symbol_list`, `symbol_get`, `symbol_create`, `symbol_delete`, `symbol_rename` |
| Types | `type_list`, `type_get`, `type_create`, `type_apply` |
| Comments | `comment_list`, `comment_get`, `comment_set`, `comment_delete` |
| Search | `find_string`, `find_bytes`, `find_function`, `find_calls`, `find_crypto`, `find_interesting` |
| Graph | `graph_calls`, `graph_callers`, `graph_callees`, `graph_export` |
| Diff | `diff_programs`, `diff_functions` |
| Patch | `patch_bytes`, `patch_nop`, `patch_export` |
| Disasm | `disasm` |
| Stats | `stats` |
| Scripts | `script_run`, `script_python`, `script_java`, `script_list` |
| Batch | `batch` |

## Reliability

### Bridge Liveness Detection

Bridge liveness is checked via three steps:

1. **Port file exists** — `bridge-{hash}.port` present in data directory
2. **PID alive** — `kill(pid, 0)` succeeds (Unix) for the PID in `bridge-{hash}.pid`
3. **TCP reachable** — `TcpStream::connect(("127.0.0.1", port))` succeeds

If any check fails, stale files are cleaned up and a fresh bridge is started.

### Stale File Cleanup

On bridge startup, stale files from previous crashes are detected and removed:

- **Port file** — removed if PID is dead or TCP unreachable
- **PID file** — removed alongside stale port file

This handles crash scenarios where the bridge died without proper cleanup.

### Startup Logging

During bridge startup, all Ghidra stdout and stderr is captured and logged:

```
[Ghidra stdout] INFO  ANALYZING all memory and code: ...
[Ghidra stderr] java.lang.UnsatisfiedLinkError: libXtst.so.6 ...
```

This aids in diagnosing issues like:
- Missing system libraries (X11 libs on Linux/WSL)
- Java version mismatches
- GhidraScript compilation failures
