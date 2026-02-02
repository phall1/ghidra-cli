# Agent Instructions

## Critical Rules

1. **NEVER SKIP TESTS!** If .NET SDK is not installed, the tests MUST fail.
2. **DEFAULT OUTPUT FORMAT** should be human and agent readable, NOT JSON. Use `--json` and `--pretty` for JSON output.
3. The `detect` command MUST work without .NET runtime (pure Rust PE parsing).

## Architecture

ilspy-cli uses an **in-process .NET hosting** architecture:
- Rust binary hosts the .NET runtime via `netcorehost` crate
- C# bridge DLL wraps ICSharpCode.Decompiler with `[UnmanagedCallersOnly]` exports
- Data exchange is JSON strings over FFI function pointers
- Memory: C# allocates with `Marshal.AllocHGlobal`, Rust calls `FreeMem` after reading
- Bridge DLL is built at compile time via `build.rs` → `dotnet publish`

## Key Capability

Single-method decompilation (`ilspy decompile --type T --method M`) is NOT possible with `ilspycmd`. This is a key differentiator.

## Build Requirements

- .NET 8 SDK (build time, for `dotnet publish`)
- .NET 8 runtime (run time, loaded by netcorehost)
- Rust toolchain
