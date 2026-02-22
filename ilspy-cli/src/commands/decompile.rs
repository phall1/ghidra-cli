use crate::bridge::IlSpyBridge;
use crate::cli::{DecompileArgs, OutputFormat};
use crate::error::Result;
use crate::format;

pub fn decompile(bridge: &IlSpyBridge, args: &DecompileArgs, fmt: OutputFormat) -> Result<String> {
    let assembly = dunce::canonicalize(&args.assembly)
        .unwrap_or_else(|_| args.assembly.clone());
    let path_str = assembly.to_string_lossy();

    if let Some(output_dir) = &args.output_dir {
        if args.r#type.is_some() || args.method.is_some() {
            return Err(crate::error::IlSpyError::BridgeCallFailed(
                "--output-dir cannot be used with --type or --method".to_string()
            ));
        }

        let target_dir = dunce::canonicalize(output_dir)
            .unwrap_or_else(|_| output_dir.clone());
        let target_str = target_dir.to_string_lossy();

        let result = bridge.decompile_project(&path_str, &target_str)?;

        return Ok(match fmt {
            OutputFormat::Json => serde_json::to_string(&result).unwrap_or_default(),
            OutputFormat::JsonPretty => serde_json::to_string_pretty(&result).unwrap_or_default(),
            _ => {
                let files = result.get("files").and_then(|v| v.as_u64()).unwrap_or(0);
                let dir = result.get("directory").and_then(|v| v.as_str()).unwrap_or("");
                format!("Decompiled {} files to {}", files, dir)
            }
        });
    }

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
