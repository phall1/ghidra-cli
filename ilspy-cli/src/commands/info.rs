use crate::bridge::IlSpyBridge;
use crate::cli::{InfoArgs, OutputFormat};
use crate::error::Result;
use crate::format;

pub fn info(bridge: &IlSpyBridge, args: &InfoArgs, fmt: OutputFormat) -> Result<String> {
    let assembly = dunce::canonicalize(&args.assembly)
        .unwrap_or_else(|_| args.assembly.clone());
    let path_str = assembly.to_string_lossy();

    let info = bridge.assembly_info(&path_str)?;

    Ok(format::format_assembly_info(&info, fmt))
}
