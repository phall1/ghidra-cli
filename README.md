# Ghidra CLI

A high-performance Rust CLI for automating Ghidra reverse engineering tasks, designed for both direct usage and AI agent integration (like Claude Code).

## Features

- 🔥 **Daemon-Based Architecture** - Background daemon prevents conflicts and speeds up operations
- 📦 **Command Queuing** - Safe, serialized execution of Ghidra operations
- ⚡ **Automatic Caching** - Instant responses for repeated queries (5-minute TTL)
- 🚀 **Universal Query System** - Query any Ghidra data type with a single command
- 🔍 **Advanced Filtering** - Powerful filter language for precise data extraction
- 📊 **Multiple Output Formats** - JSON, CSV, TSV, Table, and more
- 🤖 **LLM-Optimized** - Designed for minimal token usage and maximum efficiency
- 🪟 **Cross-Platform** - Native Windows, Linux, and macOS support
- 📦 **Zero Configuration** - Auto-detection of Ghidra installation

## Installation

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) 10.0 or later
- Rust 1.70+ (for building from source)

### From Source

```bash
git clone https://github.com/yourusername/ghidra-cli
cd ghidra-cli
cargo build --release
```

The binary will be at `target/release/ghidra.exe` (Windows) or `target/release/ghidra` (Unix).

### Setup

1. Run the initialization wizard:
```bash
ghidra init
```

2. Set your Ghidra installation (if not auto-detected):
```bash
set GHIDRA_INSTALL_DIR=C:\ghidra\ghidra_11.0
```

3. Verify installation:
```bash
ghidra doctor
```

## Quick Start

### With Daemon (Recommended)

```bash
# Start the daemon for a project
ghidra daemon start --project analysis

# Now all commands are routed through the daemon automatically
ghidra query functions --project analysis --filter="size>1000"
ghidra decompile 0x401000 --project analysis

# Check daemon status
ghidra daemon status --project analysis

# Stop the daemon when done
ghidra daemon stop --project analysis
```

### Without Daemon (Direct Mode)

```bash
# Quick analysis of a binary
ghidra quick malware.exe

# Import a binary
ghidra import suspicious.exe --project=analysis

# Query functions
ghidra query functions --program=suspicious.exe --filter="size>1000"

# Decompile a function
ghidra decompile 0x401000 --program=suspicious.exe

# List suspicious imports
ghidra dump imports --program=suspicious.exe --filter="name~Crypt OR name~Process"
```

## Daemon Architecture

The daemon prevents Ghidra headless conflicts and dramatically improves performance:

```
┌──────────────┐                  ┌─────────────────────┐
│ CLI Client   │──JSON-over-TCP──▶│ Daemon              │
│ (Any Command)│                  │ ┌─────────────────┐ │
└──────────────┘                  │ │ Command Queue   │ │
                                  │ │ (Serialized)    │ │
                                  │ └────────┬────────┘ │
                                  │          ▼          │
                                  │ ┌─────────────────┐ │
                                  │ │ Cache (5min TTL)│ │
                                  │ └─────────────────┘ │
                                  │          ▼          │
                                  │ ┌─────────────────┐ │
                                  │ │ Ghidra Headless │ │
                                  │ └─────────────────┘ │
                                  └─────────────────────┘
```

### Daemon Commands

```bash
# Start daemon (foreground for debugging)
ghidra daemon start --project my_project --foreground

# Start daemon with custom port
ghidra daemon start --project my_project --port 17700

# Check status
ghidra daemon status --project my_project

# Restart daemon
ghidra daemon restart --project my_project

# Stop daemon
ghidra daemon stop --project my_project

# Ping daemon to check responsiveness
ghidra daemon ping --project my_project

# Clear result cache
ghidra daemon clear-cache --project my_project
```

### Why Use the Daemon?

**Without Daemon:**
- ❌ 3-5 second startup per command
- ❌ Cannot run concurrent operations
- ❌ No result caching
- ❌ Project lock conflicts

**With Daemon:**
- ✅ Instant responses (cache hits)
- ✅ Queued operations (no conflicts)
- ✅ Keep Ghidra loaded in memory
- ✅ Automatic cache management

## Universal Query Command

The `query` command is the primary interface for data extraction:

```bash
ghidra query <data-type> [options]
```

### Supported Data Types

- `functions` - All functions in the program
- `strings` - String data
- `imports` - Import table
- `exports` - Export table
- `memory` - Memory regions
- `symbols` - Symbol table
- `xrefs` - Cross-references
- `comments` - All comments
- `types` - Data types

### Query Options

```bash
--filter="<expression>"   # Filter results
--fields=<list>           # Select specific fields
--format=<format>         # Output format
--limit=<n>               # Max results
--offset=<n>              # Skip first n results
--sort=<field>            # Sort order
--count                   # Just return count
```

### Filter Language

```bash
# Comparison operators
name=malloc               # Exact match
size>1000                 # Greater than
address>=0x401000         # Greater or equal

# String operators
name~crypt                # Contains (case-insensitive)
name^sub_                 # Starts with
name$_exit                # Ends with
name=~"regex"             # Regex match

# Logical operators
name~crypt AND size>500   # AND
name~main OR name~start   # OR
NOT name^FUN_             # NOT

# Special operators
calls EXISTS              # Field exists
name IN [malloc,free]     # One of values
size>=100 AND size<=1000  # Range
```

## Examples

### Function Analysis

```bash
# List all functions
ghidra query functions --program=malware.exe

# Find large functions with crypto in the name
ghidra query functions --program=malware.exe \
  --filter="size>1000 AND name~crypt" \
  --format=json-compact

# Count unnamed functions
ghidra query functions --program=malware.exe \
  --filter="name^FUN_" \
  --count

# Get specific fields only
ghidra query functions --program=malware.exe \
  --fields=name,address,size \
  --limit=10
```

### String Analysis

```bash
# Find HTTP/HTTPS URLs
ghidra query strings --program=malware.exe \
  --filter="value~http"

# Find long strings (potential paths, URLs)
ghidra query strings --program=malware.exe \
  --filter="length>50" \
  --format=minimal
```

### Import Analysis

```bash
# Find suspicious imports
ghidra query imports --program=malware.exe \
  --filter="name IN [CreateProcess,WinExec,ShellExecute]"

# Find crypto imports
ghidra query imports --program=malware.exe \
  --filter="name~Crypt" \
  --format=table
```

### Memory Analysis

```bash
# List executable memory regions
ghidra query memory --program=malware.exe \
  --filter="permissions~x" \
  --format=table
```

### Decompilation

```bash
# Decompile a specific function
ghidra decompile 0x401000 --program=malware.exe

# Decompile by name
ghidra decompile main --program=malware.exe

# Get compact output
ghidra fn decompile suspicious_func --program=malware.exe \
  --format=compact
```

## Specialized Commands

### Function Commands

```bash
ghidra fn list [options]                    # List functions
ghidra fn get <addr|name> [options]         # Get function details
ghidra fn decompile <addr|name> [options]   # Decompile
ghidra fn calls <addr|name> [options]       # What it calls
ghidra fn xrefs <addr|name> [options]       # What calls it
```

### String Commands

```bash
ghidra strings [options]                    # List all strings
ghidra strings refs <string> [options]      # Get references
```

### Memory Commands

```bash
ghidra mem map [options]                    # Memory map
ghidra mem read <addr> <size> [options]     # Read memory
ghidra mem search <pattern> [options]       # Search for pattern
```

### Dump Commands

```bash
ghidra dump imports [options]               # All imports
ghidra dump exports [options]               # All exports
ghidra dump functions [options]             # All functions
ghidra dump strings [options]               # All strings
```

## Output Formats

```
full          - Full human-readable (default for TTY)
compact       - One-line summaries
minimal       - Just addresses/names
json          - Full JSON
json-compact  - Minimal JSON
json-stream   - NDJSON (one per line)
csv           - CSV format
tsv           - TSV format
table         - Pretty table
ids           - Just addresses/IDs
count         - Just count
```

## Configuration

### Environment Variables

```bash
GHIDRA_INSTALL_DIR       # Path to Ghidra installation
GHIDRA_PROJECT_DIR       # Project directory
GHIDRA_DEFAULT_PROGRAM   # Default program to analyze
GHIDRA_DEFAULT_PROJECT   # Default project name
GHIDRA_TIMEOUT           # Command timeout (seconds)
```

### Configuration File

Located at:
- Windows: `%APPDATA%\ghidra-cli\config.yaml`
- Linux/Mac: `~/.config/ghidra-cli/config.yaml`

```yaml
ghidra_install_dir: C:\ghidra\ghidra_11.0
ghidra_project_dir: C:\Users\username\.ghidra-projects
default_program: malware.exe
default_project: analysis
default_output_format: json-compact
default_limit: 1000
timeout: 300
```

### Set Defaults

```bash
# Set default program
ghidra set-default program malware.exe

# Set default project
ghidra set-default project analysis
```

## LLM-Optimized Workflow

For Claude Code and other agents:

```bash
# 1. Count first (check result size)
ghidra query functions --program=malware.exe --count
# → 1,247 functions

# 2. Refine filter and count
ghidra query functions --program=malware.exe \
  --filter="NOT name^FUN_" \
  --count
# → 89 named functions

# 3. Get minimal data
ghidra query functions --program=malware.exe \
  --filter="NOT name^FUN_" \
  --fields=name,address \
  --format=json-compact

# 4. Deep dive on specific items
ghidra fn decompile <address> --program=malware.exe \
  --format=compact
```

## Project Management

```bash
# Create project
ghidra project create myproject

# List projects
ghidra project list

# Delete project
ghidra project delete myproject
```

## Scripting

### Run Custom Scripts

```bash
# Run a Python script
ghidra script run my_analysis.py --program=malware.exe -- arg1 arg2

# Execute inline Python
ghidra script python "print(currentProgram.getName())" --program=malware.exe

# Execute inline Java
ghidra script java "println(currentProgram.getName());" --program=malware.exe
```

### Built-in Scripts

The CLI includes built-in scripts for:
- Function listing
- Decompilation
- String extraction
- Import/Export tables
- Memory map
- Cross-references
- Program information

## Windows-Specific Notes

### Path Handling

The CLI handles both Unix-style (`/`) and Windows-style (`\`) paths automatically.

### Ghidra Installation Detection

Auto-detection checks these locations:
- `C:\Program Files\Ghidra`
- `C:\Program Files (x86)\Ghidra`
- `C:\ghidra`
- Registry entries (if available)

### Executable Detection

Supports common Windows formats:
- `.exe` - Executables
- `.dll` - Dynamic libraries
- `.sys` - System drivers

## Performance Tips

1. **Use `--count` first** - Check result size before fetching data
2. **Filter aggressively** - Pre-filter on Ghidra side, not in your code
3. **Select minimal fields** - Use `--fields` to reduce data transfer
4. **Use compact formats** - `json-compact` or `minimal` for LLMs
5. **Paginate large results** - Use `--limit` and `--offset`

## Troubleshooting

### Ghidra Not Found

```bash
# Check doctor
ghidra doctor

# Set manually
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra

# Or in config
ghidra config set ghidra_install_dir C:\path\to\ghidra
```

### Analysis Timeout

```bash
# Increase timeout
set GHIDRA_TIMEOUT=600

# Or in config
ghidra config set timeout 600
```

### Project Issues

```bash
# List projects
ghidra project list

# Delete and recreate
ghidra project delete myproject
ghidra project create myproject
```

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE) for details.

## Credits

- [Ghidra](https://ghidra-sre.org/) - NSA's reverse engineering framework
- Built with ❤️ for Claude Code and the AI agent community
