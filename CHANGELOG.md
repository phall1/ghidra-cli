# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Fork takeover.** Beginning with **0.2.0**, this project is maintained at
> `phall1/ghidra-cli`. The `akiselev/ghidra-cli` upstream (through 0.1.9) is no
> longer the canonical source. Future releases tag from `phall1/ghidra-cli`.

## [Unreleased]

### Added

- MCP phase 1 follow-on work tracked via [beads](https://github.com/steveasd/beads); see `bd list --status=open` for the active issue tree. Epics: observability & SLOs, test rigor, MCP surface quality, Java bridge refactor, RE persistence (annotation DB), decompiler independence (Phase 3), release engineering.

## [0.2.0] - unreleased

### Changed

- **Fork takeover**: project maintenance moves from `akiselev/ghidra-cli` to `phall1/ghidra-cli`. Repository URL and `authors` updated in `Cargo.toml`. License remains GPL-3.0; original copyright preserved.

### Migrated from 0.1.x (pre-fork)

The following items were the in-flight Unreleased changes inherited from upstream
0.1.9 and ship as part of the 0.2.0 baseline:

- **BREAKING**: Replaced Python bridge (`bridge.py`) with Java bridge (`GhidraCliBridge.java`)
  - Architecture simplified from 3 layers (CLI → Rust daemon → Python bridge) to 2 layers (CLI → Java bridge)
  - No separate Rust daemon process — CLI connects directly to Java bridge via TCP
  - Bridge runs as a GhidraScript inside `analyzeHeadless` JVM
  - Dynamic port binding with port/PID file discovery (`~/.local/share/ghidra-cli/bridge-{hash}.port`)
- **BREAKING**: Removed Python/PyGhidra dependency — only Java 17+ and Ghidra are required
- `ghidra setup` no longer installs PyGhidra
- `ghidra doctor` no longer checks for Python/PyGhidra
- MCP server (`ghidra mcp`) with 80 tools across 13 categories for LLM-driven reverse engineering

### Removed

- All 13 Python scripts (`bridge.py`, `find.py`, `symbols.py`, `types.py`, `comments.py`, `graph.py`, `diff.py`, `patch.py`, `disasm.py`, `stats.py`, `program.py`, `script_runner.py`, `batch.py`)
- Rust daemon process and associated modules (`handler.rs`, `handlers/`, `ipc_server.rs`, `process.rs`, `queue.rs`, `state.rs`, `cache.rs`)
- Dependencies: `remoc`, `interprocess`, `fslock`
- Unix domain socket IPC — replaced with direct TCP to Java bridge

### Security

- Local TCP communication only (localhost binding, no external access)

## [0.1.0] - 2025-01-26

### Added

- Daemon-only architecture with persistent Ghidra connection
- Auto-start daemon on import/analyze/quick commands
- Comprehensive reverse engineering commands:
  - Function analysis (list, decompile, disassemble, calls, xrefs)
  - Symbol management (list, get, create, delete, rename)
  - String analysis and search
  - Type definitions and application
  - Comment management
  - Memory operations
  - Cross-reference analysis
- Search capabilities:
  - String patterns
  - Byte sequences
  - Function names
  - Crypto constants
  - Interesting patterns
- Call graph generation and export
- Binary patching (bytes, NOP, export)
- Script execution (Python and Java)
- Batch operations
- Flexible output formats:
  - Human-readable (default for TTY)
  - Compact JSON (default for pipes)
  - Pretty JSON (--pretty flag)
- Expression-based filtering
- AI agent integration support

### Security

- Local IPC communication only (Unix sockets / named pipes)

[unreleased]: https://github.com/phall1/ghidra-cli/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/phall1/ghidra-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/akiselev/ghidra-cli/releases/tag/v0.1.0
