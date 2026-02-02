use crate::bridge::IlSpyBridge;
use crate::cli::{ListMethodsArgs, ListTypesArgs, OutputFormat};
use crate::error::Result;
use crate::format;

pub fn list_types(bridge: &IlSpyBridge, args: &ListTypesArgs, fmt: OutputFormat) -> Result<String> {
    let assembly = dunce::canonicalize(&args.assembly)
        .unwrap_or_else(|_| args.assembly.clone());
    let path_str = assembly.to_string_lossy();

    let mut types = bridge.list_types(&path_str)?;

    // Apply filters
    if let Some(ref filter) = args.filter {
        let filter_lower = filter.to_lowercase();
        types.retain(|t| t.full_name.to_lowercase().contains(&filter_lower));
    }
    if let Some(ref kind) = args.kind {
        types.retain(|t| kind.matches(&t.kind));
    }

    Ok(format::format_types(&types, fmt))
}

pub fn list_methods(
    bridge: &IlSpyBridge,
    args: &ListMethodsArgs,
    fmt: OutputFormat,
) -> Result<String> {
    let assembly = dunce::canonicalize(&args.assembly)
        .unwrap_or_else(|_| args.assembly.clone());
    let path_str = assembly.to_string_lossy();
    let type_name = args.r#type.as_deref().unwrap_or("");

    let mut methods = bridge.list_methods(&path_str, type_name)?;

    // Apply filter
    if let Some(ref filter) = args.filter {
        let filter_lower = filter.to_lowercase();
        methods.retain(|m| m.name.to_lowercase().contains(&filter_lower));
    }

    Ok(format::format_methods(&methods, fmt))
}
