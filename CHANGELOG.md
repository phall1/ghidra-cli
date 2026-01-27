# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[unreleased]: https://github.com/akiselev/ghidra-cli/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/akiselev/ghidra-cli/releases/tag/v0.1.0
