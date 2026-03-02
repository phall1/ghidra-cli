//! Embedded bridge DLLs — compiled into the binary via include_bytes!
//! and extracted to a cache directory at runtime.

use std::fs;
use std::path::PathBuf;

const BRIDGE_DLL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bridge/IlSpyBridge.dll"));
const RUNTIME_CONFIG: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/bridge/IlSpyBridge.runtimeconfig.json"));
const DEPS_JSON: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/bridge/IlSpyBridge.deps.json"));
const DECOMPILER_DLL: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/bridge/ICSharpCode.Decompiler.dll"));

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Extract embedded bridge DLLs to a cache directory.
/// Returns the path to the extracted bridge directory, or None on failure.
pub fn extract_bridge() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let cache_dir = PathBuf::from(home)
        .join(".cache")
        .join("ilspy-cli")
        .join("bridge")
        .join(VERSION);

    let stamp = cache_dir.join(".extracted");
    if stamp.exists() && cache_dir.join("IlSpyBridge.dll").exists() {
        return Some(cache_dir);
    }

    fs::create_dir_all(&cache_dir).ok()?;
    fs::write(cache_dir.join("IlSpyBridge.dll"), BRIDGE_DLL).ok()?;
    fs::write(
        cache_dir.join("IlSpyBridge.runtimeconfig.json"),
        RUNTIME_CONFIG,
    )
    .ok()?;
    fs::write(cache_dir.join("IlSpyBridge.deps.json"), DEPS_JSON).ok()?;
    fs::write(
        cache_dir.join("ICSharpCode.Decompiler.dll"),
        DECOMPILER_DLL,
    )
    .ok()?;
    fs::write(&stamp, VERSION).ok()?;

    Some(cache_dir)
}
