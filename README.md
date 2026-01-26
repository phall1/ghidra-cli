# Ghidra CLI

A high-performance Rust CLI for automating Ghidra reverse engineering tasks, designed for both direct usage and AI agent integration (like Claude Code).

## Features

- **Daemon-only architecture** - All operations route through a persistent daemon for consistency
- **Auto-start daemon** - Import/analyze commands automatically start the daemon
- **Fast queries** - Sub-second response times with Ghidra kept in memory
- **Comprehensive analysis** - Functions, symbols, types, strings, cross-references
- **Binary patching** - Modify bytes, NOP instructions, export patches
- **Call graphs** - Generate caller/callee graphs, export to DOT format
- **Search capabilities** - Find strings, bytes, functions, crypto patterns
- **Script execution** - Run Python/Java scripts, inline or from files
- **Batch operations** - Execute multiple commands from a file
- **Flexible output** - Human-readable, JSON, or pretty JSON formats
- **Filtering** - Powerful expression-based filtering (e.g., `size > 100`)

## Architecture

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

All commands go through the daemon, which maintains a persistent connection to Ghidra via the bridge script. This provides:
- **Consistent state** - Single Ghidra process for all operations
- **Fast queries** - No JVM startup overhead per command
- **Auto-start** - Daemon starts automatically when needed
- **Per-project isolation** - Each project gets its own daemon and socket, enabling concurrent analysis of multiple binaries

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

# Import and analyze a binary (daemon auto-starts)
ghidra quick ./binary

# Or step by step:
ghidra import ./binary --project myproject --program mybinary
ghidra analyze --project myproject --program mybinary

# Query functions (uses running daemon)
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
ghidra import <binary> --project <p>   # Import binary (auto-starts daemon)
ghidra analyze --project <p>           # Run analysis
ghidra quick <binary>                  # Import + analyze in one step
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

## Daemon Management

The daemon keeps Ghidra loaded in memory. It starts automatically when needed, but you can also control it manually:

```bash
# Start daemon with a program loaded
ghidra daemon start --project myproject --program mybinary

# Check daemon status
ghidra daemon status --project myproject

# All commands use the daemon automatically
ghidra function list --project myproject    # Fast!
ghidra decompile main --project myproject   # Fast!

# Stop daemon
ghidra daemon stop --project myproject

# Restart with different program
ghidra daemon restart --project myproject --program otherbinary
```

### Multi-Project Support

Each project gets its own daemon process and socket, allowing concurrent analysis:

```bash
# Work on multiple projects simultaneously
ghidra quick ./binary_a --project projA
ghidra quick ./binary_b --project projB

# Query each independently
ghidra function list --project projA
ghidra function list --project projB
```

## Output Formats

Default output is human-readable in all contexts. Use flags to request machine formats:

- **Default**: Compact human-readable format (designed for both humans and AI agents)
- **--json**: Compact JSON for machine parsing
- **--pretty**: Pretty-printed JSON (indented, multi-line)

Override with flags:
```bash
# Force JSON output (compact, single-line)
ghidra function list --json

# Force pretty JSON (indented, multi-line)
ghidra function list --pretty

# Select specific fields
ghidra function list --fields "name,address,size"
```

### Output Format Design

Format detection occurs at the CLI boundary rather than in daemon handlers. Handlers always return compact JSON for IPC efficiency and caching stability. The CLI applies format transformation (human-readable, pretty JSON) at the output boundary based on TTY detection or explicit flags. This design maintains a stable IPC protocol with a single format decision point, preventing daemon cache invalidation from format variations.

## Filtering

Use expressions to filter results:

```bash
ghidra function list --filter "size > 100"
ghidra function list --filter "name contains 'main'"
ghidra strings list --filter "length > 20"
```

## AI Agent Integration

Ghidra CLI is designed to work seamlessly with AI coding assistants like Claude Code. The structured output and comprehensive command set make it ideal for automated reverse engineering workflows.

Example workflow with an AI agent:
1. `ghidra quick suspicious.exe` - Import, analyze, start daemon
2. `ghidra find interesting` - AI analyzes suspicious patterns
3. `ghidra decompile <func>` - AI examines specific functions
4. `ghidra x-ref to <addr>` - AI traces data flow
5. `ghidra patch nop <addr>` - AI patches anti-debug code
6. `ghidra patch export` - Export patched binary

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT License - See [LICENSE](LICENSE) for details.
