# Agent Instructions

## Critical Rules

1. **NEVER SKIP TESTS!** If Ghidra is not installed, the tests MUST fail.
2. **DEFAULT OUTPUT FORMAT** should be human and agent readable, NOT JSON. Use `--json` and `--pretty` for JSON output.

## Architecture

ghidra-cli uses a **daemon-only architecture**:
- All commands route through a daemon process
- Daemon manages a persistent Ghidra bridge connection
- Import/Analyze/Quick commands auto-start the daemon
- One daemon per project, one program per daemon

## Key Patterns

### Starting Analysis
```bash
# Quickest path - auto-starts daemon
ghidra quick ./binary

# Or explicit steps (daemon auto-starts on import)
ghidra import ./binary --project myproj --program prog
ghidra analyze --project myproj --program prog
```

### Daemon is Always Running
After import/analyze/quick, the daemon is running. All query commands use it automatically:
```bash
ghidra function list      # Uses daemon
ghidra decompile main     # Uses daemon
ghidra find crypto        # Uses daemon
```

### Manual Daemon Control
```bash
ghidra daemon status      # Check if running
ghidra daemon stop        # Stop daemon
ghidra daemon restart --project p --program new_prog  # Switch program
```

## Code Organization

- `src/main.rs` - CLI entry point, command routing
- `src/daemon/` - Daemon process, IPC server, command handlers
- `src/ghidra/bridge.rs` - Ghidra bridge connection management
- `src/ghidra/scripts/bridge.py` - Python script running inside Ghidra
- `src/ipc/` - IPC protocol and client
