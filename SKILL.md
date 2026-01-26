---
name: ghidra-cli
description: >
    Use ghidra-cli for reverse engineering tasks: binary analysis, decompilation, function inspection, cross-reference analysis, pattern discovery, and binary patching.
    Activate when the user requests:
    - Binary analysis or reverse engineering
    - Decompilation or disassembly
    - Function listing, inspection, or renaming
    - Cross-reference or call graph analysis
    - String or byte pattern searches
    - Binary patching or modification
    - Ghidra project management
---

# ghidra-cli

A high-performance Rust CLI for automating Ghidra reverse engineering tasks. Designed for both direct usage and AI agent integration.

## Architecture Overview

ghidra-cli uses a **daemon-only architecture** with **per-project isolation**:

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   CLI Command   │────▶│  Daemon (IPC)    │────▶│  GhidraBridge   │
│  ghidra ...     │     │  Per-project     │     │  TCP to Ghidra  │
│  --project X    │     │  Unix socket     │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                          │
                                                          ▼
                                                 ┌─────────────────┐
                                                 │   bridge.py     │
                                                 │  (Ghidra Script)│
                                                 └─────────────────┘
```

**Key concepts:**
- **Daemon**: Background process managing IPC and Ghidra bridge
- **Bridge**: Python script running inside Ghidra, executing commands
- **Auto-start**: Daemon starts automatically when needed (import, analyze, quick)
- **Per-project sockets**: Each project gets its own socket at `~/.local/share/ghidra-cli/ghidra-cli-{hash}.sock`
- **One daemon per project**: Multiple agents can work on different projects concurrently without conflicts
- **One program per daemon**: Daemon loads a single program for queries

## When to Use

Activate when the user requests:
- Binary analysis or reverse engineering
- Decompilation or disassembly
- Function listing, inspection, or renaming
- Cross-reference or call graph analysis
- String or byte pattern searches
- Binary patching or modification
- Ghidra project management

## Quick Start

### Fastest Path (Auto-Start)

```bash
# Import and analyze - daemon starts automatically
ghidra quick ./binary

# Daemon is now running, queries are fast
ghidra function list
ghidra decompile main
```

### Full Project Setup

```bash
# Create project structure
ghidra project create myproject

# Import binary (auto-starts daemon)
ghidra import ./binary --project myproject --program mybinary

# Analyze (uses running daemon)
ghidra analyze --project myproject --program mybinary

# All subsequent queries use daemon
ghidra function list
ghidra decompile main
ghidra find string "password"
```

### Manual Daemon Control

```bash
# Start daemon explicitly
ghidra daemon start --project myproject --program mybinary

# Check status
ghidra daemon status --project myproject

# Stop daemon
ghidra daemon stop --project myproject

# Restart with different program
ghidra daemon restart --project myproject --program other_binary
```

## Command Reference

### Project Management

| Command | Description |
|---------|-------------|
| `ghidra project create <name>` | Create new project |
| `ghidra project list` | List all projects |
| `ghidra project info <name>` | Show project details |
| `ghidra project delete <name>` | Delete project and all programs |

### Import & Analysis

| Command | Description |
|---------|-------------|
| `ghidra import <binary> --project <p>` | Import binary (auto-starts daemon) |
| `ghidra analyze --project <p> --program <prog>` | Run Ghidra analysis |
| `ghidra quick <binary>` | Import + analyze in one step |

### Function Operations

```bash
# List functions
ghidra function list
ghidra function list --limit 50
ghidra function list --filter "size > 100"
ghidra function list --filter "name contains 'crypt'"

# Get function details
ghidra function get main
ghidra function get 0x401000

# Decompile to C-like pseudocode
ghidra decompile main
ghidra decompile 0x401000

# Disassemble
ghidra disasm main
ghidra disasm 0x401000 --count 50

# Rename function
ghidra function rename sub_401000 decrypt_key
```

### Search Operations

```bash
# Find functions by pattern (glob)
ghidra find function "*crypt*"
ghidra find function "str*"

# Find strings
ghidra find string "password"
ghidra find string "error" --case-insensitive

# Find byte patterns (hex, spaces optional)
ghidra find bytes "4883ec08"
ghidra find bytes "48 83 ec 08"

# Find function calls
ghidra find calls malloc

# Find crypto constants (AES, DES, RSA, etc.)
ghidra find crypto

# Find suspicious patterns (anti-debug, obfuscation, etc.)
ghidra find interesting
```

### Cross-References

```bash
# References TO an address (who calls/reads this)
ghidra x-ref to 0x401000
ghidra x-ref to main

# References FROM an address (what this calls/reads)
ghidra x-ref from 0x401000
ghidra x-ref from main
```

### Call Graphs

```bash
# Full call graph from function
ghidra graph calls main

# Callers only (who calls this function)
ghidra graph callers main --depth 3

# Callees only (what this function calls)
ghidra graph callees main --depth 3

# Export to DOT format for visualization
ghidra graph export dot --output callgraph.dot
```

### Symbols

```bash
# List all symbols
ghidra symbol list
ghidra symbol list --limit 100

# Get symbol at address
ghidra symbol get 0x401000

# Create new symbol
ghidra symbol create my_func 0x401000

# Rename symbol
ghidra symbol rename old_name new_name

# Delete symbol
ghidra symbol delete my_func
```

### Strings

```bash
# List strings
ghidra strings list
ghidra strings list --limit 100
ghidra strings list --filter "length > 20"

# Find string references
ghidra strings refs "error message"
```

### Data Types

```bash
# List data types
ghidra type list
ghidra type list --filter "name contains 'struct'"

# Get type details
ghidra type get "MyStruct"

# Create type
ghidra type create "typedef int HANDLE"

# Apply type to address
ghidra type apply 0x402000 "char[32]"
```

### Memory

```bash
# Show memory map
ghidra memory map

# Read bytes at address
ghidra memory read 0x401000 64

# Dump section
ghidra dump section .text
```

### Comments

```bash
# Get comment at address
ghidra comment get 0x401000

# Set comment
ghidra comment set 0x401000 "Entry point for decryption"

# List all comments
ghidra comment list

# Delete comment
ghidra comment delete 0x401000
```

### Binary Patching

```bash
# Patch bytes at address
ghidra patch bytes 0x401000 "90909090"

# NOP out instructions
ghidra patch nop 0x401000 --count 5

# Export patched binary
ghidra patch export --output patched.bin
```

### Scripting

```bash
# List available scripts
ghidra script list

# Run Python script
ghidra script run analysis.py

# Run with arguments
ghidra script run myscript.py --args "arg1 arg2"

# Inline Python (access currentProgram, state, etc.)
ghidra script python "print(currentProgram.getName())"

# Inline Java
ghidra script java "println(currentProgram.getName());"
```

### Batch Operations

```bash
# Run commands from file
ghidra batch commands.txt

# Commands file format (one per line):
# function list
# decompile main
# find string "password"
```

### Statistics

```bash
# Program statistics
ghidra stats

# Program summary
ghidra summary
```

### Daemon Management

```bash
# Start daemon for project
ghidra daemon start --project myproject --program mybinary

# Start in foreground (for debugging)
ghidra daemon start --project myproject --program mybinary --foreground

# Check if daemon is running
ghidra daemon status --project myproject

# Ping daemon (health check)
ghidra daemon ping --project myproject

# Clear result cache
ghidra daemon clear-cache --project myproject

# Stop daemon
ghidra daemon stop --project myproject

# Restart with new program
ghidra daemon restart --project myproject --program newbinary
```

## Output Formats

```bash
# Human-readable (default for terminal)
ghidra function list

# JSON output
ghidra function list --json

# Pretty JSON
ghidra function list --pretty

# Select specific fields
ghidra function list --fields "name,address,size"

# Count only
ghidra function list --format count
```

## Filtering

Use expressions to filter results:

```bash
# Numeric comparisons
ghidra function list --filter "size > 100"
ghidra function list --filter "size >= 50"
ghidra function list --filter "size < 1000"

# String matching
ghidra function list --filter "name contains 'crypt'"
ghidra function list --filter "name starts_with 'sub_'"
ghidra function list --filter "name ends_with '_init'"

# Combine with limit
ghidra function list --filter "size > 100" --limit 20
```

## Common Analysis Patterns

### Investigate a Suspicious Function

```bash
# Get overview
ghidra function get suspicious_func

# See the code
ghidra decompile suspicious_func

# What does it call?
ghidra graph callees suspicious_func --depth 2

# Who calls it?
ghidra graph callers suspicious_func --depth 3

# Check cross-references
ghidra x-ref to suspicious_func
```

### Find Crypto or Sensitive Code

```bash
# Find crypto constants
ghidra find crypto

# Find password-related strings
ghidra find string "password"
ghidra find string "key"
ghidra find string "secret"

# Find crypto function names
ghidra find function "*crypt*"
ghidra find function "*aes*"
ghidra find function "*sha*"
```

### Trace Data Flow

```bash
# Find where data is written
ghidra x-ref to 0x404000

# Find where data is read
ghidra x-ref from 0x404000

# Trace through call graph
ghidra graph callees source_func --depth 5
```

### Analyze Anti-Analysis Techniques

```bash
# Find interesting/suspicious patterns
ghidra find interesting

# Look for timing checks, debugger detection
ghidra find string "IsDebuggerPresent"
ghidra find function "*debug*"

# Find self-modifying code indicators
ghidra find bytes "e8 00 00 00 00"  # call $+5 pattern
```

### Patch and Export

```bash
# Identify patch location
ghidra disasm 0x401000 --count 10

# Apply patch
ghidra patch nop 0x401000 --count 2

# Verify
ghidra disasm 0x401000 --count 10

# Export
ghidra patch export --output patched.exe
```

## Error Recovery

| Situation | Resolution |
|-----------|------------|
| Daemon not running | Commands auto-start daemon; or `ghidra daemon start --project <p> --program <prog>` |
| No project exists | `ghidra project create <name>` or use `ghidra quick <binary>` |
| Function not found | Use `ghidra find function "*pattern*"` to search |
| Address format | Use hex with 0x prefix: `0x401000` |
| Slow queries | Daemon should be running; check with `ghidra daemon status` |
| Wrong program loaded | `ghidra daemon restart --project <p> --program <correct_prog>` |
| Daemon crashed | `ghidra daemon start --project <p> --program <prog>` |

## Global Options

All commands accept:

| Option | Description |
|--------|-------------|
| `--project <name>` | Target project (auto-detected if daemon running) |
| `--program <name>` | Target program within project |
| `--json` | JSON output |
| `--pretty` | Pretty-printed JSON output |
| `--filter <expr>` | Filter expression |
| `--limit <N>` | Maximum results to return |
| `--fields <list>` | Comma-separated fields to include |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra installation |
| `GHIDRA_PROJECT_DIR` | Default project directory |

## Troubleshooting

### Check Installation

```bash
ghidra doctor
```

### View Daemon Logs

```bash
# Logs are at ~/.local/share/ghidra-cli/daemon.log
tail -f ~/.local/share/ghidra-cli/daemon.log
```

### Debug Mode

```bash
# Run daemon in foreground to see output
ghidra daemon start --project myproject --program mybinary --foreground
```

### Reset State

```bash
# Stop daemon for a specific project
ghidra daemon stop --project myproject

# Remove lock files if needed (per-project, named by hash)
rm ~/.local/share/ghidra-cli/daemon-*.lock

# Remove sockets if needed (per-project, named by hash)
rm /run/user/$UID/ghidra-cli/ghidra-cli-*.sock
# Or on systems without XDG_RUNTIME_DIR:
rm /tmp/ghidra-cli/ghidra-cli-*.sock
```

## Multi-Project Support

ghidra-cli supports concurrent analysis of multiple projects. Each project gets:
- Its own daemon process (identified by lock file)
- Its own Unix socket (named by project path hash)

This allows multiple agents or terminals to work on different binaries without conflicts:

```bash
# Terminal 1: Work on project A
ghidra quick ./binary_a --project projectA
ghidra function list --project projectA

# Terminal 2: Work on project B (concurrently)
ghidra quick ./binary_b --project projectB
ghidra decompile main --project projectB
```

Both daemons run independently and don't interfere with each other.
