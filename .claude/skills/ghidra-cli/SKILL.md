----
name: ghidra-cli
description: >
    CLI for exploring binaries using Ghidra and a query language
----

## Overview

Ghidra CLI is a Rust-based command-line tool that provides programmatic access to Ghidra's reverse engineering capabilities. It's designed with AI agents in mind, featuring:

- **Daemon architecture** for fast, conflict-free operations
- **Universal query system** for consistent data extraction
- **Automatic caching** to minimize redundant operations
- **Token-efficient output formats** for LLM consumption

---

## Quick Reference

### Essential Commands

```bash
# Daemon management
ghidra daemon start --project <name>     # Start background daemon
ghidra daemon stop --project <name>      # Stop daemon
ghidra daemon status --project <name>    # Check status

# Project operations
ghidra project create <name>             # Create new project
ghidra import <binary> --project <name>  # Import binary
ghidra analyze --project <name>          # Run analysis

# Query data
ghidra query <type> --project <name> [--filter] [--limit]

# Decompilation
ghidra decompile <addr|name> --project <name>
```

### Common Data Types

`functions`, `strings`, `imports`, `exports`, `symbols`, `memory`, `xrefs`, `types`, `comments`

---

## Workflow Patterns

### Pattern 1: First-Time Binary Analysis

```bash
# 1. Create project and start daemon
ghidra project create analysis_2024
ghidra daemon start --project analysis_2024 --foreground

# 2. Import and analyze binary
ghidra import malware.exe --project analysis_2024
ghidra analyze --project analysis_2024

# 3. Get high-level summary
ghidra summary --project analysis_2024

# 4. Query specific data as needed
ghidra query functions --project analysis_2024 --filter "size>500"
```

### Pattern 2: Investigating Suspicious Behavior

```bash
# Find crypto-related functions
ghidra query functions --project analysis \
  --filter 'name contains "crypt" or name contains "encrypt"' \
  --fields name,address,size

# Check suspicious imports
ghidra query imports --project analysis \
  --filter 'name contains "Process" or name contains "Registry"'

# Find suspicious strings
ghidra query strings --project analysis \
  --filter 'value contains "http" or value contains "cmd.exe"' \
  --limit 50
```

### Pattern 3: Function Analysis Deep Dive

```bash
# List all functions (count first!)
ghidra query functions --project analysis --count

# Get top 20 largest functions
ghidra query functions --project analysis \
  --sort -size --limit 20 \
  --fields name,address,size

# Decompile specific function
ghidra decompile suspicious_func --project analysis

# Find what calls this function
ghidra function xrefs suspicious_func --project analysis

# Find what this function calls
ghidra function calls suspicious_func --project analysis
```

---

## Token Optimization Strategies

### 1. Always Count First

Before fetching data, check the result size:

```bash
# BAD: Might return 10,000 functions
ghidra query functions --project analysis

# GOOD: Check size first
ghidra query functions --project analysis --count
# Output: 10,247 functions

# Then refine with filter
ghidra query functions --project analysis \
  --filter 'not name starts_with "FUN_"' \
  --count
# Output: 156 functions
```

### 2. Use Field Selection

Only request fields you need:

```bash
# BAD: Returns all fields (name, address, size, body, callers, callees, etc.)
ghidra query functions --project analysis

# GOOD: Select minimal fields
ghidra query functions --project analysis \
  --fields name,address,size \
  --format json
```

### 3. Apply Filters Server-Side

Filter in Ghidra, not in your code:

```bash
# BAD: Fetch all 10K functions, filter in LLM
ghidra query functions --project analysis | grep crypto

# GOOD: Filter on server
ghidra query functions --project analysis \
  --filter 'name contains "crypto"'
```

### 4. Use Compact Formats

```bash
# For analysis/display
--format json         # Full JSON with all fields

# For LLM processing (RECOMMENDED)
--format minimal      # Just name/address, space-separated
--format ids          # Just addresses, one per line

# For counting
--count               # Just return the count
```

### 5. Paginate Large Results

```bash
# Get first 50 results
ghidra query functions --project analysis --limit 50

# Get next 50 results
ghidra query functions --project analysis --limit 50 --offset 50
```

---

## Filter Expression Reference

### Comparison Operators

```bash
field == value        # Exact match
field != value        # Not equal
field > value         # Greater than
field >= value        # Greater or equal
field < value         # Less than
field <= value        # Less or equal
```

### String Operators

```bash
field contains "text"       # Case-insensitive substring
field starts_with "text"    # Prefix match
field ends_with "text"      # Suffix match
field matches "regex"       # Regular expression
```

### Logical Operators

```bash
condition1 and condition2   # Both must be true
condition1 or condition2    # Either must be true
not condition               # Negation
```

### Special Operators

```bash
exists(field)              # Field exists and is not null
field in [val1,val2,val3]  # Field is one of values
```

### Example Filters

```bash
# Large named functions
'size > 1000 and not name starts_with "FUN_"'

# Crypto-related
'name contains "crypt" or name contains "hash" or name contains "encrypt"'

# Network-related strings
'value contains "http" or value contains "socket" or value contains "connect"'

# Public exported functions
'public == true and exists(export)'

# Complex condition
'(size > 500 or callees > 10) and not thunk and exists(callers)'
```

---

## Output Format Guide

### JSON (Default for Pipes)

```bash
ghidra query functions --project analysis --format json
```

```json
[
  {
    "name": "main",
    "address": "0x401000",
    "size": 1024,
    "body": "...",
    "callers": ["0x402000"],
    "callees": ["0x403000"]
  }
]
```

### Minimal (Best for LLMs)

```bash
ghidra query functions --project analysis --format minimal
```

```
main 0x401000
sub_401100 0x401100
FUN_401200 0x401200
```

### IDs Only

```bash
ghidra query functions --project analysis --format ids
```

```
0x401000
0x401100
0x401200
```

### Table (For Display)

```bash
ghidra query functions --project analysis --format table
```

```
┌────────────┬──────────┬──────┐
│ Name       │ Address  │ Size │
├────────────┼──────────┼──────┤
│ main       │ 0x401000 │ 1024 │
│ sub_401100 │ 0x401100 │ 256  │
└────────────┴──────────┴──────┘
```

---

## Common Tasks

### Task: Find Entry Point

```bash
# Method 1: Query for "entry" or "main"
ghidra query functions --project analysis \
  --filter 'name == "entry" or name == "main" or name == "_start"'

# Method 2: Get program info
ghidra summary --project analysis | grep -i "entry"
```

### Task: Find Suspicious API Calls

```bash
# Check imports
ghidra query imports --project analysis \
  --filter 'name contains "CreateProcess" or
            name contains "WinExec" or
            name contains "ShellExecute" or
            name contains "URLDownload"'
```

### Task: Extract All Strings

```bash
# Get count first
ghidra query strings --project analysis --count

# If reasonable size, fetch all
ghidra query strings --project analysis \
  --fields value,address \
  --format minimal > strings.txt

# If too large, filter
ghidra query strings --project analysis \
  --filter 'length > 10' \
  --limit 1000
```

### Task: Analyze Function Behavior

```bash
# 1. Get function info
ghidra function get suspicious_func --project analysis

# 2. Decompile
ghidra decompile suspicious_func --project analysis

# 3. See what it calls
ghidra function calls suspicious_func --project analysis

# 4. See where it's called from
ghidra function xrefs suspicious_func --project analysis

# 5. Check strings it references
ghidra query strings --project analysis \
  --filter 'xrefs contains "suspicious_func"'
```

### Task: Find Encrypted/Obfuscated Code

```bash
# High entropy strings (likely encrypted)
ghidra query strings --project analysis \
  --filter 'length > 50' \
  --format minimal

# Large functions (potential obfuscation)
ghidra query functions --project analysis \
  --filter 'size > 5000' \
  --sort -size

# Functions with unusual call patterns
ghidra query functions --project analysis \
  --filter 'callees > 50 or callers > 20'
```

---

## Daemon Best Practices

### When to Use Daemon

**Always use daemon for:**
- Multiple queries on the same project
- Interactive analysis sessions
- Repeated decompilation requests
- Any workflow with >3 commands

**Skip daemon for:**
- One-off quick analysis
- Different projects each time
- Simple import/analyze operations

### Daemon Lifecycle

```bash
# At session start
ghidra daemon start --project analysis

# During session: all commands auto-route to daemon
ghidra query functions --project analysis
# ↑ Automatically uses daemon if running

# At session end
ghidra daemon stop --project analysis
```

### Troubleshooting Daemon

```bash
# Check if daemon is running
ghidra daemon status --project analysis

# Test daemon responsiveness
ghidra daemon ping --project analysis

# Restart if stuck
ghidra daemon restart --project analysis

# Force stop (if needed)
pkill -f "ghidra daemon"
rm ~/.local/share/ghidra-cli/daemon-*.lock
```

---

## Error Handling

### Common Errors

**"Project not found"**
```bash
# List projects
ghidra project list

# Create if needed
ghidra project create analysis
```

**"Daemon not running"**
```bash
# Start daemon
ghidra daemon start --project analysis --foreground

# Check logs
tail -f ~/.local/share/ghidra-cli/daemon.log
```

**"Analysis incomplete"**
```bash
# Run analysis
ghidra analyze --project analysis

# Check if binary is imported
ghidra project info analysis
```

**"Timeout"**
```bash
# Increase timeout in config
echo "timeout: 600" >> ~/.config/ghidra-cli/config.yaml

# Or use environment variable
export GHIDRA_TIMEOUT=600
```

---

## Performance Tips

1. **Start with counts** - Always check result size before fetching
2. **Use daemon** - 100x faster for repeated operations
3. **Cache awareness** - Identical queries return instantly (5-min TTL)
4. **Filter aggressively** - Reduce data transfer
5. **Select minimal fields** - Less data = faster & fewer tokens
6. **Batch similar queries** - Group related operations together

---

## Integration Examples

### Example: Malware Analysis Report

```bash
#!/bin/bash
PROJECT="malware_analysis"
BINARY="suspicious.exe"

# Setup
ghidra project create $PROJECT
ghidra daemon start --project $PROJECT
ghidra import $BINARY --project $PROJECT
ghidra analyze --project $PROJECT

# Gather intelligence
echo "=== SUMMARY ==="
ghidra summary --project $PROJECT

echo -e "\n=== SUSPICIOUS IMPORTS ==="
ghidra query imports --project $PROJECT \
  --filter 'name contains "Process" or name contains "Registry"'

echo -e "\n=== CRYPTO FUNCTIONS ==="
ghidra query functions --project $PROJECT \
  --filter 'name contains "crypt" or name contains "encrypt"' \
  --fields name,address

echo -e "\n=== NETWORK STRINGS ==="
ghidra query strings --project $PROJECT \
  --filter 'value contains "http" or value contains "://"' \
  --limit 20

# Cleanup
ghidra daemon stop --project $PROJECT
```

### Example: Function Coverage Analysis

```bash
# Count total functions
TOTAL=$(ghidra query functions --project analysis --count)

# Count named functions
NAMED=$(ghidra query functions --project analysis \
  --filter 'not name starts_with "FUN_"' --count)

# Calculate percentage
echo "Coverage: $NAMED / $TOTAL functions named"
echo "Percentage: $(( NAMED * 100 / TOTAL ))%"
```

---

## Appendix: Complete Command Reference

### Daemon Commands

```bash
ghidra daemon start [--project] [--port] [--foreground]
ghidra daemon stop [--project]
ghidra daemon restart [--project] [--port]
ghidra daemon status [--project]
ghidra daemon ping [--project]
ghidra daemon clear-cache [--project]
```

### Project Commands

```bash
ghidra project create <name>
ghidra project list
ghidra project delete <name>
ghidra project info <name>
```

### Analysis Commands

```bash
ghidra import <binary> [--project]
ghidra analyze [--project]
ghidra summary [--project]
ghidra quick <binary>  # import + analyze + summary
```

### Query Commands

```bash
ghidra query <type> [options]
  --project <name>
  --filter <expression>
  --fields <list>
  --format <format>
  --limit <n>
  --offset <n>
  --sort <field>
  --count
```

### Function Commands

```bash
ghidra function list [options]
ghidra function get <name|addr> [options]
ghidra function decompile <name|addr> [options]
ghidra function calls <name|addr> [options]
ghidra function xrefs <name|addr> [options]
```

### Utility Commands

```bash
ghidra doctor           # Verify installation
ghidra init             # Initialize configuration
ghidra config get <key>
ghidra config set <key> <value>
ghidra version
```

---

## Tips for LLM Agents

1. **Always check daemon status** before starting analysis
2. **Use `--count` liberally** to avoid overwhelming responses
3. **Start broad, then narrow** with filters
4. **Leverage caching** by grouping similar queries
5. **Use `--format minimal`** for token efficiency
6. **Handle errors gracefully** - daemon issues are common
7. **Clean up after sessions** - stop daemons when done
8. **Document your queries** - future you will thank you

---

**Happy reverse engineering! 🔍**
