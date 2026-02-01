# Agent Instructions

## Critical Rules

1. **NEVER SKIP TESTS!** If Ghidra is not installed, the tests MUST fail.
2. **DEFAULT OUTPUT FORMAT** should be human and agent readable, NOT JSON. Use `--json` and `--pretty` for JSON output.

## Architecture

ghidra-cli uses a **daemon-only architecture**:
- All commands route through a daemon process
- Daemon manages a persistent Ghidra bridge connection
- Import/Analyze/Quick commands auto-start the daemon
- One daemon per project
