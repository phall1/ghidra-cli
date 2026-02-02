# ilspy-cli Navigation Index

See @AGENTS.md for agent-specific instructions.

## Key Files

| What | When |
|------|------|
| `src/main.rs` | Modifying CLI entry point or output format detection |
| `src/cli.rs` | Adding/modifying CLI arguments and subcommands |
| `src/format/mod.rs` | Implementing new output formats or changing format logic |
| `src/bridge/mod.rs` | .NET runtime hosting and bridge function loading |
| `src/bridge/ffi.rs` | FFI marshalling between Rust and C# |
| `src/bridge/types.rs` | Serde structs matching C# JSON responses |
| `src/ilspy/detect.rs` | Pure-Rust .NET detection via PE headers |
| `bridge/IlSpyBridge.cs` | C# bridge with [UnmanagedCallersOnly] exports |
| `bridge/IlSpyBridge.csproj` | C# project and ICSharpCode.Decompiler dependency |
| `build.rs` | Build script that runs `dotnet publish` |

## Modules

| What | When |
|------|------|
| `src/bridge/` | FFI layer between Rust and .NET (netcorehost) |
| `src/commands/` | Command implementations (list, decompile, search, info, detect, doctor) |
| `src/format/` | Output formatting (Table, Compact, JSON) |
| `src/ilspy/` | Pure-Rust .NET detection (no runtime needed) |
| `bridge/` | C# project wrapping ICSharpCode.Decompiler |

## Architecture

```
Rust CLI (clap) → netcorehost FFI → C# Bridge DLL → ICSharpCode.Decompiler
```

Data flows as JSON strings over FFI function pointers with [UnmanagedCallersOnly].
C# allocates memory, Rust reads it, then calls FreeMem.
