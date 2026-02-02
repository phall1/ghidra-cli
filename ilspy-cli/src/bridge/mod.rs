pub mod ffi;
pub mod types;

use std::path::{Path, PathBuf};

use netcorehost::pdcstr;

use crate::error::{IlSpyError, Result};
use self::ffi::*;
use self::types::*;

/// The ILSpy bridge — hosts the .NET runtime in-process and calls
/// ICSharpCode.Decompiler through [UnmanagedCallersOnly] C# exports.
pub struct IlSpyBridge {
    list_types_fn: FnOneArg,
    list_methods_fn: FnTwoArgs,
    decompile_type_fn: FnTwoArgs,
    decompile_method_fn: FnThreeArgs,
    decompile_full_fn: FnOneArg,
    assembly_info_fn: FnOneArg,
    search_fn: FnTwoArgs,
    free_fn: FnFreeMem,
}

impl IlSpyBridge {
    /// Initialize the .NET runtime and load all bridge function pointers.
    pub fn new() -> Result<Self> {
        let bridge_dir = Self::find_bridge_dir()?;
        let runtime_config = bridge_dir.join("IlSpyBridge.runtimeconfig.json");
        let bridge_dll = bridge_dir.join("IlSpyBridge.dll");

        if !runtime_config.exists() {
            return Err(IlSpyError::BridgeDllNotFound(
                runtime_config.display().to_string(),
            ));
        }
        if !bridge_dll.exists() {
            return Err(IlSpyError::BridgeDllNotFound(
                bridge_dll.display().to_string(),
            ));
        }

        let hostfxr = netcorehost::nethost::load_hostfxr()
            .map_err(|e| IlSpyError::RuntimeInitFailed(e.to_string()))?;

        let config_path = to_pdcstring(&runtime_config)?;
        let context = hostfxr
            .initialize_for_runtime_config(&config_path)
            .map_err(|e| IlSpyError::RuntimeInitFailed(e.to_string()))?;

        let dll_path = to_pdcstring(&bridge_dll)?;
        let loader = context
            .get_delegate_loader_for_assembly(dll_path)
            .map_err(|e| IlSpyError::RuntimeInitFailed(e.to_string()))?;

        let type_name = pdcstr!("IlSpyBridge, IlSpyBridge");

        macro_rules! load {
            ($name:expr, $ty:ty) => {{
                let managed = loader
                    .get_function_with_unmanaged_callers_only::<$ty>(
                        type_name,
                        &to_pdcstring_str($name)?,
                    )
                    .map_err(|e| IlSpyError::FunctionLoadFailed($name.to_string(), e.to_string()))?;
                *managed
            }};
        }

        Ok(Self {
            list_types_fn: load!("ListTypes", FnOneArg),
            list_methods_fn: load!("ListMethods", FnTwoArgs),
            decompile_type_fn: load!("DecompileType", FnTwoArgs),
            decompile_method_fn: load!("DecompileMethod", FnThreeArgs),
            decompile_full_fn: load!("DecompileFull", FnOneArg),
            assembly_info_fn: load!("GetAssemblyInfo", FnOneArg),
            search_fn: load!("SearchSource", FnTwoArgs),
            free_fn: load!("FreeMem", FnFreeMem),
        })
    }

    /// List all types in an assembly.
    pub fn list_types(&self, assembly: &str) -> Result<Vec<TypeInfo>> {
        let json = unsafe { call_one_arg(self.list_types_fn, self.free_fn, assembly) };
        Self::parse_result(&json)
    }

    /// List methods, optionally filtered by type.
    pub fn list_methods(&self, assembly: &str, type_name: &str) -> Result<Vec<MethodInfo>> {
        let json =
            unsafe { call_two_args(self.list_methods_fn, self.free_fn, assembly, type_name) };
        Self::parse_result(&json)
    }

    /// Decompile a single type.
    pub fn decompile_type(&self, assembly: &str, type_name: &str) -> Result<DecompileResult> {
        let json = unsafe {
            call_two_args(self.decompile_type_fn, self.free_fn, assembly, type_name)
        };
        Self::parse_result(&json)
    }

    /// Decompile a single method.
    pub fn decompile_method(
        &self,
        assembly: &str,
        type_name: &str,
        method_name: &str,
    ) -> Result<DecompileResult> {
        let json = unsafe {
            call_three_args(
                self.decompile_method_fn,
                self.free_fn,
                assembly,
                type_name,
                method_name,
            )
        };
        Self::parse_result(&json)
    }

    /// Decompile the full assembly.
    pub fn decompile_full(&self, assembly: &str) -> Result<DecompileResult> {
        let json = unsafe { call_one_arg(self.decompile_full_fn, self.free_fn, assembly) };
        Self::parse_result(&json)
    }

    /// Get assembly metadata.
    pub fn assembly_info(&self, assembly: &str) -> Result<AssemblyInfo> {
        let json = unsafe { call_one_arg(self.assembly_info_fn, self.free_fn, assembly) };
        Self::parse_result(&json)
    }

    /// Search decompiled source with a regex pattern.
    pub fn search_source(&self, assembly: &str, pattern: &str) -> Result<Vec<SearchResult>> {
        let json = unsafe { call_two_args(self.search_fn, self.free_fn, assembly, pattern) };
        Self::parse_result(&json)
    }

    // ── Internal helpers ─────────────────────────────────────────────

    fn parse_result<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
        // Check if it's an error response
        if let Ok(err) = serde_json::from_str::<BridgeError>(json) {
            return Err(IlSpyError::BridgeCallFailed(err.error));
        }
        serde_json::from_str(json).map_err(|e| {
            IlSpyError::BridgeCallFailed(format!("Failed to parse response: {e}\nJSON: {json}"))
        })
    }

    /// Find the directory containing the compiled bridge DLL.
    /// Checks: next to executable, then in the build output directory.
    fn find_bridge_dir() -> Result<PathBuf> {
        // 1. Next to the executable
        if let Ok(exe) = std::env::current_exe() {
            let exe_dir = exe.parent().unwrap_or(Path::new("."));
            let candidate = exe_dir.join("bridge");
            if candidate.join("IlSpyBridge.dll").exists() {
                return Ok(candidate);
            }
            // Also check directly alongside exe
            if exe_dir.join("IlSpyBridge.dll").exists() {
                return Ok(exe_dir.to_path_buf());
            }
        }

        // 2. ILSPY_BRIDGE_DIR environment variable
        if let Ok(dir) = std::env::var("ILSPY_BRIDGE_DIR") {
            let p = PathBuf::from(&dir);
            if p.join("IlSpyBridge.dll").exists() {
                return Ok(p);
            }
        }

        // 3. Relative to cargo manifest dir (development)
        if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
            let dev_path = PathBuf::from(&manifest)
                .join("target")
                .join("bridge");
            if dev_path.join("IlSpyBridge.dll").exists() {
                return Ok(dev_path);
            }
        }

        Err(IlSpyError::BridgeDllNotFound(
            "Could not find IlSpyBridge.dll. Set ILSPY_BRIDGE_DIR or ensure it's next to the executable.".to_string()
        ))
    }
}

/// Convert a Path to a PdCString for netcorehost APIs.
fn to_pdcstring(path: &Path) -> Result<netcorehost::pdcstring::PdCString> {
    let canonical = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    netcorehost::pdcstring::PdCString::from_os_str(canonical.as_os_str())
        .map_err(|e| IlSpyError::RuntimeInitFailed(format!("Invalid path encoding: {e}")))
}

/// Convert a &str to a PdCString for netcorehost APIs.
fn to_pdcstring_str(s: &str) -> Result<netcorehost::pdcstring::PdCString> {
    netcorehost::pdcstring::PdCString::from_os_str(std::ffi::OsStr::new(s))
        .map_err(|e| IlSpyError::RuntimeInitFailed(format!("Invalid string encoding: {e}")))
}
