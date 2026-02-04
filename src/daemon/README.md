# Daemon Module

The daemon is the central execution authority for ghidra-cli. All commands route through the daemon, which maintains a persistent connection to Ghidra via the bridge.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ CLI Client  │────▶│ IPC Server  │────▶│   Handler   │────▶│ GhidraBridge│
│ (DaemonCli) │     │ Per-project │     │  (Routing)  │     │ (TCP→Ghidra)│
│             │     │ Unix socket │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                    │
                                                                    ▼
                                                            ┌─────────────┐
                                                            │  bridge.py  │
                                                            │ (In Ghidra) │
                                                            └─────────────┘
```

### Per-Project Socket Isolation

Each project gets its own Unix socket to enable concurrent daemon operation:

- **Socket naming**: `ghidra-cli-{hash}.sock` where `{hash}` is MD5 of project path
- **Socket location**: `$XDG_RUNTIME_DIR/ghidra-cli/` or `/tmp/ghidra-cli/`
- **Lock file naming**: `daemon-{hash}.lock` (same hash for consistency)

This allows multiple agents or terminals to work on different projects without conflicts.

## Key Components

| File | Purpose |
|------|---------|
| `mod.rs` | Daemon main loop, startup, shutdown |
| `ipc_server.rs` | Unix socket server, accepts client connections |
| `handler.rs` | Routes IPC commands to bridge or specialized handlers |
| `process.rs` | Daemon lifecycle, lock files, process management |
| `queue.rs` | Command queue execution |
| `cache.rs` | Result caching |
| `state.rs` | Daemon state management |
| `handlers/` | Specialized command handlers |

## Command Flow

1. **CLI sends command** via IPC (Unix socket)
2. **IPC server** receives request, parses JSON
3. **Handler** routes to appropriate processor:
   - Direct bridge commands (decompile, function list, etc.)
   - Import/Analyze commands (via bridge.py handlers)
   - ExecuteCli for generic CLI command forwarding
4. **Bridge** sends to Ghidra via TCP, receives response
5. **Response** flows back through IPC to CLI

## Auto-Start Behavior

Import, Analyze, and Quick commands auto-start the daemon:

1. CLI checks if daemon is running for project
2. If not, starts daemon in background (`daemonize_unix` / `daemonize_windows`)
3. Waits briefly for daemon to initialize
4. Connects and sends command

## Lifecycle

- **One daemon per project** - Lock file prevents duplicates
- **One program per daemon** - Daemon loads a single program
- **Graceful shutdown** - Handles SIGTERM, SIGINT, IPC shutdown command
- **Lock files** - Located at `~/.local/share/ghidra-cli/daemon-{hash}.lock`
- **Socket files** - Located at `$XDG_RUNTIME_DIR/ghidra-cli/ghidra-cli-{hash}.sock`
- **Logs** - Located at `~/.local/share/ghidra-cli/daemon.log`

The `{hash}` is computed as `MD5(project_path_string)` ensuring each project has unique socket and lock file names.

## Handlers

Specialized handlers in `handlers/` directory:

| Handler | Commands |
|---------|----------|
| `program.rs` | Program info, memory, imports, exports |
| `symbols.rs` | Symbol operations |
| `types.rs` | Data type operations |
| `comments.rs` | Comment operations |
| `graph.rs` | Call graph operations |
| `find.rs` | Search operations |
| `diff.rs` | Program diff operations |
| `patch.rs` | Binary patching |
| `script.rs` | Script execution |
| `disasm.rs` | Disassembly |
| `stats.rs` | Statistics |
| `batch.rs` | Batch command execution |

## Bridge Commands

Commands sent to bridge.py in Ghidra:

- `import` - Import binary using AutoImporter
- `analyze` - Trigger analysis using AutoAnalysisManager
- `list_functions`, `decompile`, `list_strings`, etc.

See `src/ghidra/scripts/bridge.py` for the full command reference.

## Reliability

### Bridge Health Monitoring

The bridge (`GhidraBridge`) tracks whether the Ghidra JVM process is alive:

- **`check_health()`** - Uses `try_wait()` on the child process to detect if Ghidra has exited
- **`send_command()`** - On I/O errors, calls `check_health()` to distinguish process death from network timeouts
- **State update** - When process death is detected, `running` flag is set to false and daemon initiates shutdown

### Daemon Termination on Bridge Death

When the bridge process dies (Ghidra JVM crash, OOM, etc.):

1. Handler detects "process died" error from bridge
2. Handler signals daemon shutdown via `shutdown_tx.send()`
3. Daemon performs graceful cleanup (socket, lock, info files)
4. Next CLI command auto-starts a fresh daemon

This ensures clean state recovery without manual intervention.

### Stale File Cleanup

On daemon startup, `get_running_daemon_info()` detects and cleans stale files:

- **Lock file** - If acquirable, previous daemon is dead; file removed
- **Info file** - Removed alongside stale lock file
- **Socket file** - Removed to prevent "address in use" errors

This handles crash scenarios where daemon died without proper cleanup.

### Startup Logging

During bridge startup, all Ghidra stdout and stderr is captured and logged at `info` level:

```
[Ghidra stdout] INFO  ANALYZING all memory and code: ...
[Ghidra stderr] java.lang.UnsatisfiedLinkError: libXtst.so.6 ...
```

This aids in diagnosing issues like:
- Missing system libraries (X11 libs on Linux/WSL)
- Java version mismatches
- PyGhidra initialization failures

Logs are written to: `~/.local/share/ghidra-cli/daemon.log`
