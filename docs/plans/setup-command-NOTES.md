# Setup Command Implementation Notes

## Codebase Analysis

### Current Structure
- **Cargo.toml**: Already has tokio, clap, serde, dirs, anyhow dependencies
- **src/cli.rs**: Commands enum on line 20-127, need to add Setup variant
- **src/main.rs**: 
  - `run()` sync function handles most commands (line 49-72)
  - `run_async()` handles daemon commands (line 74-80)
  - `run_with_daemon_check()` routes commands through daemon if running (line 82-125)
- **src/ghidra/mod.rs**: GhidraClient with `verify_installation()` - can reuse for verification
- **src/config.rs**: Config struct with `save()` method and `ghidra_install_dir` field

### Key Insights
1. Setup command should be treated as async like daemon commands (uses reqwest for HTTP)
2. Need to route `Commands::Setup` through `run_async()` rather than sync `run()`
3. Can reuse existing `Config::save()` to persist ghidra_install_dir after installation
4. Can reuse `GhidraClient::verify_installation()` to verify the installation

### Dependencies Added
```toml
reqwest = { version = "0.11", features = ["json", "stream", "rustls-tls"] }
zip = "0.6"
futures-util = "0.3"
indicatif = "0.17"
```

## Implementation Progress

### Phase 1: Dependencies ✅
Added reqwest, zip, futures-util, and indicatif to Cargo.toml

### Phase 2: CLI Definition ✅
- Added `Setup(SetupArgs)` variant to Commands enum
- Added `SetupArgs` struct with version, dir, and force fields

### Phase 3: Setup Module ✅
Created `src/ghidra/setup.rs` with:
- `check_java_requirement()` - runs `java -version` and checks for JDK 17+
- `resolve_version_url()` - queries GitHub API for release URL
- `download_file()` - streams download with indicatif progress bar
- `extract_zip()` - extracts with progress bar, handles Unix permissions
- `install_ghidra()` - orchestrates the full installation flow

### Phase 4: Main Integration ✅
- Updated imports to include SetupArgs
- Modified main() to route Setup through run_async()
- Updated run_async() to handle Commands::Setup
- Added handle_setup() async function

## Testing Notes

### Build Verification
```
cargo build  # SUCCESS - only lint warnings
```

### Help Output
```
$ ghidra setup --help
Download and setup Ghidra automatically

Usage: ghidra setup [OPTIONS]

Options:
      --version <VERSION>  Specific Ghidra version to install (e.g., "11.0"). Defaults to latest
  -d, --dir <DIR>          Installation directory. Defaults to standard data directory
      --force              Skip Java check
  -v, --verbose            Enable verbose output
  -q, --quiet              Suppress non-essential output
  -h, --help               Print help
```

### Tests
All existing tests pass (cargo test).

## Files Modified
- `Cargo.toml` - Added 4 new dependencies
- `src/cli.rs` - Added SetupArgs struct and Setup variant
- `src/ghidra/mod.rs` - Added `pub mod setup;`
- `src/ghidra/setup.rs` - NEW FILE - 230 lines
- `src/main.rs` - Updated routing and added handle_setup function
