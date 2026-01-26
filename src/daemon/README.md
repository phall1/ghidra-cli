# Daemon Module

The daemon is the central execution authority for ghidra-cli. All commands route through the daemon, which maintains a persistent connection to Ghidra via the bridge.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ CLI Client  │────▶│ IPC Server  │────▶│   Handler   │────▶│ GhidraBridge│
│ (DaemonCli) │     │ (Unix sock) │     │  (Routing)  │     │ (TCP→Ghidra)│
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                    │
                                                                    ▼
                                                            ┌─────────────┐
                                                            │  bridge.py  │
                                                            │ (In Ghidra) │
                                                            └─────────────┘
```

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
- **Logs** - Located at `~/.local/share/ghidra-cli/daemon.log`

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
