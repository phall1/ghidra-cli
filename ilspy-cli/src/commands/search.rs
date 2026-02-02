use crate::bridge::IlSpyBridge;
use crate::cli::{OutputFormat, SearchArgs};
use crate::error::Result;
use crate::format;

pub fn search(bridge: &IlSpyBridge, args: &SearchArgs, fmt: OutputFormat) -> Result<String> {
    let assembly = dunce::canonicalize(&args.assembly)
        .unwrap_or_else(|_| args.assembly.clone());
    let path_str = assembly.to_string_lossy();

    // Validate regex before sending to bridge
    regex::Regex::new(&args.pattern).map_err(|e| {
        crate::error::IlSpyError::Other(format!("Invalid regex pattern: {e}"))
    })?;

    let results = bridge.search_source(&path_str, &args.pattern)?;

    Ok(format::format_search(&results, fmt))
}
