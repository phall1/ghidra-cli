# Refactoring Notes

## Architecture Reference: debugger-cli

The `debugger-cli` project at `~/git/debugger-cli` provides a good pattern for daemon-based CLIs:

### Key Patterns Used

1. **IPC via Local Sockets** (`src/ipc/`)
   - Uses `interprocess` crate for cross-platform Unix sockets / Windows named pipes
   - Length-prefixed JSON messages (4-byte little-endian length + payload)
   - Separate `protocol.rs`, `transport.rs`, and `client.rs` modules

2. **Daemon Architecture** (`src/daemon/`)
   - `server.rs` - Main event loop with IPC listener
   - `handler.rs` - Command routing and execution
   - `session.rs` - State management for debug sessions

3. **Clean Separation**
   - IPC protocol defines its own `Command` enum (not reusing CLI args)
   - Handler translates protocol commands to domain operations
   - Session holds the actual debug adapter connection

---

## Implementation Progress

### Phase 1: Bridge Script ✅
- Created `src/ghidra/scripts/bridge.py` - persistent TCP server inside Ghidra
- Implements handlers: `ping`, `program_info`, `list_functions`, `decompile`, `list_strings`, `list_imports`, `list_exports`, `memory_map`, `xrefs_to`, `xrefs_from`
- Uses `---GHIDRA_CLI_START---` / `---GHIDRA_CLI_END---` markers for ready signal

### Phase 2: Output Markers ✅
- Updated all 8 Python scripts in `scripts.rs` with delimiters
- Updated `headless.rs` to use marker-based extraction instead of fragile brace-counting

### Phase 3: IPC Layer ✅
- Added `interprocess` crate to `Cargo.toml`
- Created `src/ipc/mod.rs` with:
  - `protocol.rs` - Typed `Command` enum, `Request`, `Response` structures
  - `transport.rs` - Cross-platform socket wrapper with length-prefixed framing
  - `client.rs` - `DaemonClient` for CLI-to-daemon communication

### Phase 4: Bridge Manager ✅
- Created `src/ghidra/bridge.rs` with `GhidraBridge` struct
- Manages Ghidra process lifecycle (spawn, monitor, shutdown)
- TCP connection to Python bridge script
- `BridgeResponse<T>` typed response handling
- Embeds bridge.py via `include_str!` macro

### Phase 5: Daemon Update 🚧
- Status: Not yet wired up
- Remaining: Refactor daemon to use new IPC layer and bridge

### Phase 6: Typed Responses ⚙️
- `BridgeResponse<T>` created in `bridge.rs`
- Remaining: Update all response handling

### Phase 7: GUI Integration (Optional)
- Status: Not started
- Future work

---

## Files Created/Modified

### New Files
- `src/ghidra/scripts/bridge.py` - Persistent Python bridge server
- `src/ghidra/bridge.rs` - Rust bridge manager
- `src/ipc/mod.rs` - IPC module root
- `src/ipc/protocol.rs` - Typed protocol definitions
- `src/ipc/transport.rs` - Socket transport layer
- `src/ipc/client.rs` - Daemon client

### Modified Files
- `Cargo.toml` - Added `interprocess` crate
- `src/main.rs` - Added `mod ipc`
- `src/ghidra/mod.rs` - Added `mod bridge`, `#[derive(Debug)]` on `GhidraClient`
- `src/ghidra/scripts.rs` - All scripts now have output markers
- `src/ghidra/headless.rs` - Marker-based JSON extraction

---

## Remaining Work

To complete the refactoring:

1. **Wire up bridge to daemon** - Modify `daemon/mod.rs` to hold `GhidraBridge`
2. **Route commands through bridge** - Update `daemon/queue.rs` to use bridge instead of spawning headless
3. **Switch to IPC layer** - Replace TCP RPC with local socket IPC
4. **Remove one-shot execution** - Clean up legacy headless spawning code
5. **Manual testing** - Test with actual Ghidra installation

---

## Build Status

```
✅ cargo check - PASSED
✅ cargo test - 30 passed, 1 pre-existing failure (test_parse_hex)
```
