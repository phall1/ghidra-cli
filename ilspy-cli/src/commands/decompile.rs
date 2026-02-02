use crate::bridge::IlSpyBridge;
use crate::cli::{DecompileArgs, OutputFormat};
use crate::error::Result;
use crate::format;

pub fn decompile(bridge: &IlSpyBridge, args: &DecompileArgs, fmt: OutputFormat) -> Result<String> {
    let assembly = dunce::canonicalize(&args.assembly)
        .unwrap_or_else(|_| args.assembly.clone());
    let path_str = assembly.to_string_lossy();

    let result = match (&args.r#type, &args.method) {
        (Some(type_name), Some(method_name)) => {
            // Single method decompilation
            bridge.decompile_method(&path_str, type_name, method_name)?
        }
        (Some(type_name), None) => {
            // Single type decompilation
            bridge.decompile_type(&path_str, type_name)?
        }
        (None, _) => {
            // Full assembly decompilation
            bridge.decompile_full(&path_str)?
        }
    };

    // For decompile, default to source output unless JSON requested
    let effective_fmt = match fmt {
        OutputFormat::Table | OutputFormat::Compact => OutputFormat::Source,
        other => other,
    };

    Ok(format::format_decompile(&result, effective_fmt))
}
