# ilspy-cli

Agent-friendly .NET decompilation CLI using ILSpy (ICSharpCode.Decompiler).

## Why?

- **Ghidra produces poor output for .NET** — ILSpy gives clean C# source
- **Single-method decompilation** — `ilspycmd` can't do this
- **Structured JSON output** — no text parsing needed for agents
- **In-process execution** — no subprocess overhead
- **.NET detection** — classify .NET vs native without loading the runtime

## Requirements

- .NET 8 SDK (build time)
- .NET 8 runtime (run time)
- Rust toolchain

## Build

```bash
cargo build
```

The build script automatically runs `dotnet publish` on the C# bridge project.

## Usage

```bash
# Detect .NET vs native
ilspy detect MyApp.dll
ilspy detect "C:\Program Files\MyApp" --recursive

# List types
ilspy list types MyLib.dll
ilspy list types MyLib.dll --filter Controller --kind class

# List methods
ilspy list methods MyLib.dll --type MyNamespace.MyClass

# Decompile
ilspy decompile MyLib.dll                                    # Full assembly
ilspy decompile MyLib.dll --type MyNamespace.MyClass         # Single type
ilspy decompile MyLib.dll --type MyNamespace.MyClass --method DoWork  # Single method!

# Search decompiled source
ilspy search MyLib.dll "ConnectionString"

# Assembly metadata
ilspy info MyLib.dll

# Check setup
ilspy doctor
```

## Output Formats

| Flag | Format | Best for |
|------|--------|----------|
| (default) | Table/Compact | Humans and agents in TTY |
| `--json` | JSON (minified) | Piping to tools |
| `--pretty` | JSON (indented) | Reading JSON |
| `--compact` | One line per item | Agent parsing |

## Architecture

```
┌─────────────┐    netcorehost/hostfxr     ┌──────────────────────┐
│  Rust CLI    │ ◄────── FFI calls ──────► │  C# Bridge DLL       │
│  (clap)      │    [UnmanagedCallersOnly]  │  (IlSpyBridge.dll)   │
│              │                            │                      │
│  - cli.rs    │    JSON strings via        │  - ICSharpCode       │
│  - format/   │    IntPtr/len pairs        │    .Decompiler       │
│  - commands/ │                            │  - Wrapper methods   │
└─────────────┘                            └──────────────────────┘
```

## License

GPL-3.0
