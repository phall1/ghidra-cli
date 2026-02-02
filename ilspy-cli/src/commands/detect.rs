use std::path::Path;
use walkdir::WalkDir;

use crate::cli::{DetectArgs, OutputFormat};
use crate::error::Result;
use crate::format::{self, DetectResult};
use crate::ilspy::detect::detect_pe;

pub fn detect(args: &DetectArgs, fmt: OutputFormat) -> Result<String> {
    let path = &args.path;

    let mut results: Vec<DetectResult> = if path.is_dir() {
        if args.recursive {
            WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| is_pe_extension(e.path()))
                .map(|e| detect_pe(e.path()))
                .collect()
        } else {
            std::fs::read_dir(path)
                .map_err(crate::error::IlSpyError::Io)?
                .filter_map(|e| e.ok())
                .filter(|e| is_pe_extension(&e.path()))
                .map(|e| detect_pe(&e.path()))
                .collect()
        }
    } else {
        vec![detect_pe(path)]
    };

    // Apply filters
    if args.dotnet_only {
        results.retain(|r| r.is_dotnet);
    }
    if args.native_only {
        results.retain(|r| !r.is_dotnet);
    }

    // Sort: .NET first, then by name
    results.sort_by(|a, b| {
        b.is_dotnet
            .cmp(&a.is_dotnet)
            .then_with(|| a.path.cmp(&b.path))
    });

    Ok(format::format_detect(&results, fmt))
}

fn is_pe_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref(),
        Some("dll" | "exe")
    )
}
