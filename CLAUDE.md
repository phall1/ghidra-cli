# ghidra-cli Navigation Index

See @AGENTS.md for agent-specific instructions.

## Key Files

| What | When |
|------|------|
| `src/main.rs` | Modifying CLI entry point, daemon lifecycle, or output format detection |
| `src/cli.rs` | Adding/modifying CLI arguments and subcommands |
| `src/format/mod.rs` | Implementing new output formats or changing format detection logic |
| `src/daemon/handlers/*.rs` | Implementing daemon command handlers |
| `PLAN.md` | Understanding current implementation plan or reviewing decision rationale |
| `README.md` | Understanding project architecture or user-facing command documentation |

## Modules

| What | When |
|------|------|
| `src/daemon/` | Working with persistent Ghidra daemon or IPC communication |
| `src/format/` | Handling output format conversion (Table, Compact, JSON, CSV, etc.) |
| `tests/` | Writing integration or unit tests |

## Documentation

| What | When |
|------|------|
| `src/daemon/README.md` | Understanding daemon architecture and IPC protocol |
| `tests/README.md` | Understanding test structure and conventions |
