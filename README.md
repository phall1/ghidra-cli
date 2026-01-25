# Ghidra CLI

A high-performance Rust CLI for automating Ghidra reverse engineering tasks, designed for both direct usage and AI agent integration (like Claude Code).

## Features

- **Fast daemon mode** - Keeps Ghidra loaded in memory for sub-second response times
- **Comprehensive analysis** - Functions, symbols, types, strings, cross-references
- **Binary patching** - Modify bytes, NOP instructions, export patches
- **Call graphs** - Generate caller/callee graphs, export to DOT format
- **Search capabilities** - Find strings, bytes, functions, crypto patterns
- **Script execution** - Run Python/Java scripts, inline or from files
- **Batch operations** - Execute multiple commands from a file
- **Flexible output** - JSON, table, or count formats with field selection
- **Filtering** - Powerful expression-based filtering (e.g., `size > 100`)

## Installation

### From Source

```bash
git clone https://github.com/akiselev/ghidra-cli
cd ghidra-cli
cargo install --path .
```

### Requirements

- **Ghidra 10.0+** - Download from [ghidra-sre.org](https://ghidra-sre.org)
- **Java 17+** - Required by Ghidra
- **Rust 1.70+** - For building from source

Set the Ghidra installation path:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Or configure via CLI:
ghidra config set ghidra_path /path/to/ghidra
```

## Quick Start

```bash
# Check installation
ghidra doctor

# Import and analyze a binary
ghidra import ./binary --project myproject --program mybinary
ghidra analyze --project myproject --program mybinary

# Start the daemon for fast repeated queries
ghidra daemon start --project myproject --program mybinary

# List functions
ghidra function list

# Decompile a function
ghidra decompile main

# Find interesting strings
ghidra find string "password"

# Get cross-references
ghidra x-ref to 0x401000

# Generate call graph
ghidra graph calls main --depth 3
```

## Commands

### Project & Program Management
```bash
ghidra project create <name>           # Create project
ghidra project list                    # List projects
ghidra project delete <name>           # Delete project
ghidra import <binary> --project <p>   # Import binary
ghidra analyze --project <p>           # Run analysis
```

### Function Analysis
```bash
ghidra function list                   # List all functions
ghidra function list --filter "size > 100"  # Filter by size
ghidra decompile <name-or-addr>        # Decompile function
ghidra disasm <address> --count 20     # Disassemble instructions
```

### Symbols & Types
```bash
ghidra symbol list                     # List symbols
ghidra symbol create <name> <addr>     # Create symbol
ghidra symbol rename <old> <new>       # Rename symbol
ghidra type list                       # List data types
ghidra type get <name>                 # Get type details
```

### Cross-References
```bash
ghidra x-ref to <address>              # References TO address
ghidra x-ref from <address>            # References FROM address
```

### Search
```bash
ghidra find string "pattern"           # Find strings
ghidra find bytes "90 90 90"           # Find byte patterns
ghidra find function "*crypt*"         # Find functions by name
ghidra find crypto                     # Find crypto constants
ghidra find interesting                # Find interesting patterns
```

### Call Graphs
```bash
ghidra graph calls <func>              # Full call graph
ghidra graph callers <func>            # Who calls this?
ghidra graph callees <func>            # What does this call?
ghidra graph export dot                # Export to DOT format
```

### Binary Patching
```bash
ghidra patch bytes <addr> "90 90"      # Patch bytes
ghidra patch nop <addr> --count 5      # NOP out instructions
ghidra patch export                    # Export as patch file
```

### Comments
```bash
ghidra comment get <address>           # Get comment
ghidra comment set <addr> "note"       # Set comment
ghidra comment list                    # List all comments
```

### Scripts
```bash
ghidra script list                     # List available scripts
ghidra script run myscript.py          # Run script file
ghidra script python "print(currentProgram)"  # Inline Python
```

### Batch Operations
```bash
ghidra batch commands.txt              # Run commands from file
```

### Statistics
```bash
ghidra stats                           # Program statistics
ghidra summary                         # Program summary
```

## Daemon Mode

The daemon keeps Ghidra loaded in memory for fast queries:

```bash
# Start daemon with a program loaded
ghidra daemon start --project myproject --program mybinary

# All subsequent commands use the daemon automatically
ghidra function list    # Fast!
ghidra decompile main   # Fast!

# Check daemon status
ghidra daemon status

# Stop daemon
ghidra daemon stop
```

## Output Formats

```bash
# JSON output (default)
ghidra function list --format json

# Table format
ghidra function list --format table

# Count only
ghidra function list --format count

# Select specific fields
ghidra function list --fields "name,address,size"
```

## Filtering

Use expressions to filter results:

```bash
ghidra function list --filter "size > 100"
ghidra function list --filter "name contains 'main'"
ghidra strings list --filter "length > 20"
```

## AI Agent Integration

Ghidra CLI is designed to work seamlessly with AI coding assistants like Claude Code. The structured JSON output and comprehensive command set make it ideal for automated reverse engineering workflows.

Example workflow with an AI agent:
1. `ghidra import suspicious.exe --project analysis --program suspicious`
2. `ghidra analyze --project analysis --program suspicious`
3. `ghidra daemon start --project analysis --program suspicious`
4. `ghidra find interesting` - AI analyzes suspicious patterns
5. `ghidra decompile <func>` - AI examines specific functions
6. `ghidra x-ref to <addr>` - AI traces data flow

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT License - See [LICENSE](LICENSE) for details.
