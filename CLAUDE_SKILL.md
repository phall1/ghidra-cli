# Ghidra CLI - Claude Code Skill

This skill enables Claude Code and other AI agents to efficiently reverse engineer binaries using Ghidra through a powerful CLI interface.

## Quick Reference

### Most Common Commands

```bash
# Count-first workflow (ALWAYS use this pattern)
ghidra query functions --program=<binary> --count
ghidra query functions --program=<binary> --filter="<expr>" --count
ghidra query functions --program=<binary> --filter="<expr>" --fields=name,address --format=json-compact

# Query data types
ghidra query functions|strings|imports|exports|memory --program=<binary> [options]

# Decompile
ghidra decompile <addr|name> --program=<binary>

# Dump data
ghidra dump imports|exports|functions|strings --program=<binary> [options]
```

## Setup & Initialization

```bash
# First time setup
ghidra init

# Check installation
ghidra doctor

# Import a binary
ghidra import <binary-path> --project=<project-name>

# Quick analysis (import + analyze + summary)
ghidra quick <binary-path>
```

## Universal Query Command

The `query` command is your primary tool. It supports filtering, field selection, and multiple output formats.

### Syntax

```bash
ghidra query <data-type> --program=<binary> [options]
```

### Data Types

- `functions` - All functions
- `strings` - String literals
- `imports` - Imported functions
- `exports` - Exported functions
- `memory` - Memory regions
- `symbols` - Symbol table
- `xrefs` - Cross-references

### Options

```bash
--filter="<expression>"     # Filter results
--fields=<list>             # Select specific fields (comma-separated)
--format=<format>           # Output format (json, json-compact, table, minimal, count)
--limit=<n>                 # Max results
--offset=<n>                # Skip first n results
--sort=<field>              # Sort by field (prefix with - for descending)
--count                     # Just return count
```

## Filter Language

### Comparison Operators

```bash
field=value          # Exact match
field!=value         # Not equal
field>value          # Greater than
field>=value         # Greater or equal
field<value          # Less than
field<=value         # Less or equal
```

### String Operators

```bash
field~pattern        # Contains (case-insensitive)
field^pattern        # Starts with
field$pattern        # Ends with
field=~regex         # Regex match
```

### Logical Operators

```bash
expr AND expr        # Both conditions
expr OR expr         # Either condition
NOT expr             # Negation
(expr)               # Grouping
```

### Special Operators

```bash
field EXISTS         # Field is present
field IN [val1,val2] # One of values
```

## Essential Workflows

### 1. Initial Binary Analysis

```bash
# Get summary
ghidra summary --program=<binary>

# Count functions
ghidra query functions --program=<binary> --count

# Count named functions
ghidra query functions --program=<binary> --filter="NOT name^FUN_" --count

# List named functions (minimal output)
ghidra query functions --program=<binary> \
  --filter="NOT name^FUN_" \
  --fields=name,address,size \
  --format=json-compact \
  --limit=50
```

### 2. Finding Interesting Functions

```bash
# Large functions
ghidra query functions --program=<binary> \
  --filter="size>1000" \
  --fields=name,address,size \
  --sort=-size \
  --limit=20

# Functions with specific keywords
ghidra query functions --program=<binary> \
  --filter="name~crypt OR name~encrypt OR name~password" \
  --fields=name,address \
  --format=json-compact

# Functions that call specific APIs
ghidra query functions --program=<binary> \
  --filter="calls~WinExec OR calls~CreateProcess" \
  --format=json-compact
```

### 3. String Analysis

```bash
# Count strings
ghidra query strings --program=<binary> --count

# Find URLs
ghidra query strings --program=<binary> \
  --filter="value~http" \
  --fields=value,address \
  --format=minimal

# Find long strings (potential paths/URLs)
ghidra query strings --program=<binary> \
  --filter="length>50" \
  --format=json-compact \
  --limit=20

# Find specific keywords
ghidra query strings --program=<binary> \
  --filter="value~password OR value~key OR value~token" \
  --format=json-compact
```

### 4. Import Analysis

```bash
# List all imports
ghidra dump imports --program=<binary> --format=json-compact

# Find suspicious imports
ghidra query imports --program=<binary> \
  --filter="name IN [CreateProcess,WinExec,ShellExecute,WriteFile,CreateRemoteThread]" \
  --format=json-compact

# Find crypto imports
ghidra query imports --program=<binary> \
  --filter="name~Crypt" \
  --format=json-compact
```

### 5. Decompilation

```bash
# Decompile by address
ghidra decompile 0x401000 --program=<binary>

# Decompile by name
ghidra decompile main --program=<binary>

# Decompile with minimal output
ghidra fn decompile 0x401000 --program=<binary> --format=compact
```

### 6. Cross-Reference Analysis

```bash
# Find what calls a function
ghidra query xrefs --program=<binary> \
  --filter="to~WinExec" \
  --fields=from,from_function \
  --format=json-compact

# Find all callers to an address
ghidra xref to 0x401000 --program=<binary> --format=json-compact
```

## Output Formats

Choose the right format for your use case:

- `count` - Just the number (best for checking result size)
- `json-compact` - Minimal JSON (best for LLMs)
- `minimal` - Just addresses/names (good for piping)
- `ids` - Just IDs (good for further queries)
- `table` - Human-readable table (good for display)
- `json` - Full JSON (when you need all data)

## Best Practices for LLMs

### 1. Always Count First

```bash
# BAD: Fetching all data without knowing size
ghidra query functions --program=<binary>

# GOOD: Count first, then filter
ghidra query functions --program=<binary> --count
ghidra query functions --program=<binary> --filter="size>1000" --count
ghidra query functions --program=<binary> --filter="size>1000" --format=json-compact
```

### 2. Use Aggressive Filtering

```bash
# BAD: Fetching then filtering in code
ghidra query functions --program=<binary> --format=json

# GOOD: Filter on Ghidra side
ghidra query functions --program=<binary> \
  --filter="size>1000 AND name~crypt" \
  --format=json-compact
```

### 3. Select Only Needed Fields

```bash
# BAD: Getting all fields
ghidra query functions --program=<binary>

# GOOD: Select only what you need
ghidra query functions --program=<binary> \
  --fields=name,address,size \
  --format=json-compact
```

### 4. Paginate Large Results

```bash
# Get first page
ghidra query functions --program=<binary> --limit=50

# Get next page
ghidra query functions --program=<binary> --limit=50 --offset=50
```

### 5. Use Appropriate Output Format

```bash
# For analysis: json-compact
ghidra query functions --program=<binary> --format=json-compact

# For display: table
ghidra query functions --program=<binary> --format=table

# For piping: minimal or ids
ghidra query functions --program=<binary> --format=ids
```

## Common Analysis Patterns

### Pattern 1: Find Entry Points

```bash
# Find main or WinMain
ghidra query functions --program=<binary> \
  --filter="name~main OR name~WinMain OR name~DllMain" \
  --format=json-compact
```

### Pattern 2: Find Crypto Functions

```bash
# By name
ghidra query functions --program=<binary> \
  --filter="name~crypt OR name~cipher OR name~hash OR name~aes OR name~rsa" \
  --format=json-compact

# By imports
ghidra query imports --program=<binary> \
  --filter="name~Crypt" \
  --format=json-compact
```

### Pattern 3: Find Network Functions

```bash
# By imports
ghidra query imports --program=<binary> \
  --filter="name~socket OR name~connect OR name~send OR name~recv OR name~http" \
  --format=json-compact
```

### Pattern 4: Find File Operations

```bash
ghidra query imports --program=<binary> \
  --filter="name~File OR name~Read OR name~Write OR name~Create" \
  --format=json-compact
```

### Pattern 5: Find Suspicious Strings

```bash
# Registry keys
ghidra query strings --program=<binary> \
  --filter="value~HKEY OR value~Software" \
  --format=json-compact

# URLs
ghidra query strings --program=<binary> \
  --filter="value~http" \
  --format=json-compact

# Credentials
ghidra query strings --program=<binary> \
  --filter="value~password OR value~username OR value~token" \
  --format=json-compact
```

## Error Handling

### Common Errors

1. **Program not specified**: Use `--program=<binary>` or set default with `ghidra set-default program <binary>`
2. **Ghidra not found**: Run `ghidra init` or set `GHIDRA_INSTALL_DIR`
3. **Analysis timeout**: Increase with `set GHIDRA_TIMEOUT=600`
4. **Project not found**: Create with `ghidra project create <name>`

### Troubleshooting

```bash
# Check installation
ghidra doctor

# List available projects
ghidra project list

# Show current configuration
ghidra config list
```

## Configuration

### Set Defaults

```bash
# Set default program (so you don't have to pass --program each time)
ghidra set-default program <binary>

# Set default project
ghidra set-default project <project-name>
```

### Environment Variables

```bash
# Windows
set GHIDRA_INSTALL_DIR=C:\ghidra\ghidra_11.0
set GHIDRA_DEFAULT_PROGRAM=malware.exe

# Unix
export GHIDRA_INSTALL_DIR=/opt/ghidra
export GHIDRA_DEFAULT_PROGRAM=malware.elf
```

## Example Workflow

Here's a complete analysis workflow:

```bash
# 1. Import and analyze
ghidra import suspicious.exe --project=analysis

# 2. Get overview
ghidra summary --program=suspicious.exe

# 3. Count functions
ghidra query functions --program=suspicious.exe --count
# Output: 1247

# 4. Count named functions
ghidra query functions --program=suspicious.exe --filter="NOT name^FUN_" --count
# Output: 89

# 5. Get named functions
ghidra query functions --program=suspicious.exe \
  --filter="NOT name^FUN_" \
  --fields=name,address,size \
  --format=json-compact

# 6. Find suspicious imports
ghidra dump imports --program=suspicious.exe \
  --filter="name~Exec OR name~Create OR name~Write" \
  --format=json-compact

# 7. Find interesting strings
ghidra query strings --program=suspicious.exe \
  --filter="value~http OR value~password" \
  --format=json-compact

# 8. Decompile interesting functions
ghidra decompile 0x401000 --program=suspicious.exe
```

## Tips

1. **Always count before fetching** - Prevents overwhelming your context
2. **Use filters aggressively** - Pre-filter on Ghidra side
3. **Select minimal fields** - Reduces token usage
4. **Use json-compact format** - Most efficient for LLMs
5. **Set defaults** - Avoids repeating `--program` and `--project`
6. **Paginate large results** - Use `--limit` and `--offset`
7. **Cache results** - Store commonly-used queries in variables

## Advanced: Chaining Commands

```bash
# Get list of function addresses, then decompile each
FUNCS=$(ghidra query functions --program=<binary> \
  --filter="name~suspicious" \
  --format=ids)

for addr in $FUNCS; do
  ghidra decompile $addr --program=<binary> --format=compact
done
```

## Daemon Mode

The daemon keeps Ghidra loaded in memory for fast, interactive analysis. This is recommended for most workflows.

### Starting the Daemon

```bash
# Start daemon for a specific program
ghidra daemon start --program=<binary>

# Check daemon status
ghidra daemon status

# Stop daemon
ghidra daemon stop

# Clear daemon cache
ghidra daemon clear-cache
```

### Daemon-Mode Commands

When the daemon is running, these commands execute instantly without reloading Ghidra:

## Symbol Operations

```bash
# List all symbols
ghidra symbol list

# List symbols with filter
ghidra symbol list --filter="main"

# Get symbol details
ghidra symbol get <name>

# Create a symbol at address
ghidra symbol create <address> <name>

# Delete a symbol
ghidra symbol delete <name>

# Rename a symbol
ghidra symbol rename <old_name> <new_name>
```

## Type Operations

```bash
# List all data types
ghidra type list

# Get type definition
ghidra type get <type_name>

# Create a new struct type
ghidra type create <type_name>

# Apply a type to an address
ghidra type apply <address> <type_name>
```

## Comment Operations

```bash
# List all comments
ghidra comment list

# Get comments at address
ghidra comment get <address>

# Set a comment at address
ghidra comment set <address> "<text>"

# Set a specific comment type (pre, post, eol, plate)
ghidra comment set <address> "<text>" --type=pre

# Delete comment at address
ghidra comment delete <address>
```

## Graph Operations

```bash
# Get call graph (with optional limit)
ghidra graph calls --limit=100

# Get callers of a function (with depth)
ghidra graph callers <function_name> --depth=2

# Get callees of a function
ghidra graph callees <function_name> --depth=2

# Export call graph (dot, json, gml)
ghidra graph export --format=dot
```

## Find/Search Operations

```bash
# Find strings matching pattern
ghidra find string "<pattern>"

# Find byte patterns (hex)
ghidra find bytes "90 90 90"

# Find functions by pattern
ghidra find function "<pattern>"

# Find calls to a function
ghidra find calls <function_name>

# Find crypto constants (AES, DES, etc.)
ghidra find crypto

# Find interesting functions (suspicious names)
ghidra find interesting
```

## Diff Operations

```bash
# Compare two programs
ghidra diff programs <program1> <program2>
```

## Patch Operations

```bash
# Patch bytes at address
ghidra patch bytes <address> <hex_bytes>

# NOP instruction at address
ghidra patch nop <address>

# Export patched binary
ghidra patch export <output_path>
```

## Script Execution

```bash
# Run a Python script file
ghidra script run <script_path> [args...]

# Execute inline Python code
ghidra script python "<code>"

# Execute inline Java code
ghidra script java "<code>"

# List available scripts
ghidra script list
```

## Disassembly

```bash
# Disassemble at address
ghidra disasm <address>

# Disassemble with instruction count
ghidra disasm <address> -n 20
```

## Batch Operations

```bash
# Run batch commands from file
ghidra batch <script_file>
```

Batch file format (one command per line):
```
query functions --count
decompile main
symbol list
```

## Statistics

```bash
# Get program statistics
ghidra stats
```

Returns: function count, instruction count, data count, memory usage, etc.

## Daemon-Mode Workflows

### Pattern 1: Interactive Analysis

```bash
# Start daemon
ghidra daemon start --program=suspicious.exe

# Run queries (fast, no reload)
ghidra stats
ghidra symbol list
ghidra find crypto
ghidra decompile main

# Stop when done
ghidra daemon stop
```

### Pattern 2: Symbol/Type Annotation

```bash
# Start daemon
ghidra daemon start --program=target.exe

# Add symbols
ghidra symbol create 0x401000 "decrypt_function"
ghidra symbol create 0x402000 "key_buffer"

# Add comments
ghidra comment set 0x401000 "Main decryption routine"

# Apply types
ghidra type apply 0x402000 "byte[32]"
```

### Pattern 3: Call Graph Analysis

```bash
# Get full call graph
ghidra graph calls --limit=1000

# Trace callers to interesting function
ghidra graph callers "WinExec" --depth=5

# Trace callees from main
ghidra graph callees "main" --depth=3
```

This skill gives you powerful, token-efficient access to Ghidra for binary analysis!
