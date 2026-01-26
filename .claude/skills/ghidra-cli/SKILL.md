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

Use ghidra-cli for reverse engineering tasks: binary analysis, decompilation, function inspection, cross-reference analysis, pattern discovery, and binary patching.

## When to Use

Activate when the user requests:
- Binary analysis or reverse engineering
- Decompilation or disassembly
- Function listing, inspection, or renaming
- Cross-reference or call graph analysis
- String or byte pattern searches
- Binary patching or modification
- Ghidra project management

## Workflow

### Pre-flight Check

Before running queries, verify the environment:

```bash
# Check if daemon is running for fast queries
ghidra daemon status --project <project>

# If not running, start it
ghidra daemon start --project <project> --program <program>
```

### Quick Start (New Binary)

For one-off analysis, use quick mode:

```bash
ghidra quick ./binary
ghidra daemon start --project quick-analysis --program binary
```

### Full Project Setup

For sustained analysis:

```bash
ghidra project create myproject
ghidra import ./binary --project myproject
ghidra analyze --project myproject --program binary
ghidra daemon start --project myproject --program binary
```

## Command Reference

### Querying Functions

```bash
# List all functions
ghidra function list --project <p> --program <prog>

# Filter functions by size or name
ghidra function list --filter "size > 500"
ghidra function list --filter "name contains 'crypt'"

# Get function details
ghidra function get main

# Decompile to pseudocode
ghidra function decompile main

# Disassemble
ghidra function disasm main

# Cross-references
ghidra function xrefs main
ghidra function calls main
```

### Search Operations

```bash
# Find functions by pattern
ghidra find function "*crypt*"

# Find strings
ghidra find string "password"

# Find byte patterns (hex)
ghidra find bytes "4883ec08"

# Find crypto constants
ghidra find crypto

# Find suspicious patterns (anti-analysis, obfuscation)
ghidra find interesting
```

### Cross-References

```bash
# References TO an address
ghidra x-ref to 0x401000

# References FROM an address
ghidra x-ref from 0x401000
```

### Call Graphs

```bash
# Full call graph
ghidra graph calls

# Who calls this function (callers)
ghidra graph callers main --depth 3

# What does this function call (callees)
ghidra graph callees main --depth 3

# Export as DOT format
ghidra graph export dot
```

### Symbols and Strings

```bash
# List symbols
ghidra symbol list

# List strings
ghidra strings list --limit 100

# References to a string
ghidra strings refs "error"
```

### Memory and Types

```bash
# Memory map
ghidra memory map

# Read memory at address
ghidra memory read 0x401000 64

# List data types
ghidra type list

# Apply type to address
ghidra type apply 0x402000 "char[32]"
```

### Modifications

```bash
# Rename function
ghidra function rename sub_401000 decrypt_password

# Add comment
ghidra comment set 0x401000 "Key derivation starts here"

# Patch bytes
ghidra patch bytes 0x401000 "90909090"

# NOP instructions
ghidra patch nop 0x401010 --count 5

# Export patched binary
ghidra patch export --output patched.bin
```

### Scripting

```bash
# Run Python script
ghidra script run analysis.py

# Inline Python
ghidra script python "print(currentProgram.getName())"

# Batch commands from file
ghidra batch commands.txt
```

## Output Handling

ghidra-cli outputs JSON by default. Parse the structured data:

```bash
# JSON output (default)
ghidra function list

# Table format for display
ghidra function list --format table

# Count only
ghidra function list --format count
```

When processing results, extract relevant fields from JSON rather than displaying raw output.

## Common Patterns

### Investigate a Function

```bash
ghidra function get <name>           # Overview
ghidra function decompile <name>     # Pseudocode
ghidra function calls <name>         # What it calls
ghidra function xrefs <name>         # Who calls it
ghidra graph callers <name> --depth 2
```

### Find Interesting Code

```bash
ghidra find crypto                   # Crypto constants
ghidra find interesting              # Suspicious patterns
ghidra find function "*alloc*"       # Memory functions
ghidra strings list --filter "length > 50"
```

### Trace Data Flow

```bash
ghidra x-ref to <address>            # Who writes here
ghidra x-ref from <address>          # What this references
ghidra graph callees <func> --depth 3
```

## Error Recovery

| Situation          | Resolution                                                    |
| ------------------ | ------------------------------------------------------------- |
| Daemon not running | `ghidra daemon start --project <p> --program <prog>`          |
| No project exists  | `ghidra project create <name>` or use `ghidra quick <binary>` |
| Function not found | Use `ghidra find function "*pattern*"` to search              |
| Address format     | Use hex with 0x prefix: `0x401000`                            |
| Slow queries       | Start daemon for sub-second response times                    |

## Global Options

All commands accept:
- `--project <name>` - Target project
- `--program <name>` - Target program within project
- `--format json|table|count` - Output format
- `--filter <expr>` - Filter expression
- `--limit <N>` - Max results
