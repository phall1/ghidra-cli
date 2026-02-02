use comfy_table::{Table, presets::UTF8_FULL, ContentArrangement};
use serde::Serialize;

use crate::bridge::types::*;
use crate::cli::OutputFormat;

/// Format types list for display.
pub fn format_types(types: &[TypeInfo], format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(types).unwrap_or_default(),
        OutputFormat::JsonPretty => serde_json::to_string_pretty(types).unwrap_or_default(),
        OutputFormat::Compact => types
            .iter()
            .map(|t| {
                format!(
                    "{} ({}) [{} methods, {} props, {} fields]",
                    t.full_name, t.kind, t.method_count, t.property_count, t.field_count
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        OutputFormat::Table => {
            let mut table = new_table();
            table.set_header(vec!["Type", "Kind", "Methods", "Props", "Fields", "Public"]);
            for t in types {
                table.add_row(vec![
                    t.full_name.clone(),
                    t.kind.clone(),
                    t.method_count.to_string(),
                    t.property_count.to_string(),
                    t.field_count.to_string(),
                    if t.is_public { "yes" } else { "no" }.to_string(),
                ]);
            }
            table.to_string()
        }
        OutputFormat::Source => format_types(types, OutputFormat::Compact),
    }
}

/// Format methods list for display.
pub fn format_methods(methods: &[MethodInfo], format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(methods).unwrap_or_default(),
        OutputFormat::JsonPretty => serde_json::to_string_pretty(methods).unwrap_or_default(),
        OutputFormat::Compact => methods
            .iter()
            .map(|m| {
                let params = m
                    .parameters
                    .iter()
                    .map(|p| format!("{} {}", p.param_type, p.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                let mods = build_modifiers(m);
                format!(
                    "{}::{} → {} {}({})",
                    m.type_name, m.name, m.return_type, mods, params
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        OutputFormat::Table => {
            let mut table = new_table();
            table.set_header(vec!["Type", "Method", "Return", "Parameters", "Modifiers"]);
            for m in methods {
                let params = m
                    .parameters
                    .iter()
                    .map(|p| format!("{} {}", p.param_type, p.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                table.add_row(vec![
                    m.type_name.clone(),
                    m.name.clone(),
                    m.return_type.clone(),
                    params,
                    build_modifiers(m),
                ]);
            }
            table.to_string()
        }
        OutputFormat::Source => format_methods(methods, OutputFormat::Compact),
    }
}

/// Format decompiled source for display.
pub fn format_decompile(result: &DecompileResult, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(result).unwrap_or_default(),
        OutputFormat::JsonPretty => serde_json::to_string_pretty(result).unwrap_or_default(),
        _ => result.source.clone(),
    }
}

/// Format assembly info for display.
pub fn format_assembly_info(info: &AssemblyInfo, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(info).unwrap_or_default(),
        OutputFormat::JsonPretty => serde_json::to_string_pretty(info).unwrap_or_default(),
        OutputFormat::Compact => {
            let mut lines = vec![
                format!("Assembly: {}", info.name),
                format!("Framework: {}", info.target_framework),
                format!("Types: {}", info.type_count),
                format!("References: {}", info.references.len()),
            ];
            for r in &info.references {
                lines.push(format!("  {} v{}", r.name, r.version));
            }
            lines.join("\n")
        }
        OutputFormat::Table => {
            let mut out = format!(
                "Assembly: {}\nFramework: {}\nTypes: {}\n\nReferences:\n",
                info.name, info.target_framework, info.type_count
            );
            let mut table = new_table();
            table.set_header(vec!["Reference", "Version"]);
            for r in &info.references {
                table.add_row(vec![r.name.clone(), r.version.clone()]);
            }
            out.push_str(&table.to_string());
            out
        }
        OutputFormat::Source => format_assembly_info(info, OutputFormat::Compact),
    }
}

/// Format search results for display.
pub fn format_search(results: &[SearchResult], format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(results).unwrap_or_default(),
        OutputFormat::JsonPretty => serde_json::to_string_pretty(results).unwrap_or_default(),
        OutputFormat::Compact | OutputFormat::Table | OutputFormat::Source => {
            let mut lines = Vec::new();
            for r in results {
                lines.push(format!("── {} ({} matches) ──", r.type_name, r.match_count));
                for m in &r.matches {
                    lines.push(format!("  Line {}: {}", m.line, m.matched));
                    for ctx_line in m.context.lines() {
                        lines.push(format!("    {}", ctx_line));
                    }
                }
            }
            if lines.is_empty() {
                "No matches found.".to_string()
            } else {
                lines.join("\n")
            }
        }
    }
}

/// Format detect results for display.
pub fn format_detect(
    results: &[DetectResult],
    format: OutputFormat,
) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string(results).unwrap_or_default(),
        OutputFormat::JsonPretty => serde_json::to_string_pretty(results).unwrap_or_default(),
        OutputFormat::Compact => results
            .iter()
            .map(|r| {
                format!(
                    "{}: {} [{}]",
                    r.path, r.framework, r.recommended_tool
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        OutputFormat::Table => {
            let mut table = new_table();
            table.set_header(vec!["File", "Type", "Framework", "Tool"]);
            for r in results {
                table.add_row(vec![
                    r.path.clone(),
                    if r.is_dotnet { ".NET" } else { "Native" }.to_string(),
                    r.framework.clone(),
                    r.recommended_tool.clone(),
                ]);
            }
            table.to_string()
        }
        OutputFormat::Source => format_detect(results, OutputFormat::Compact),
    }
}

/// Detection result (used by format but defined here for convenience).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectResult {
    pub path: String,
    pub is_dotnet: bool,
    pub framework: String,
    pub recommended_tool: String,
}

fn new_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

fn build_modifiers(m: &MethodInfo) -> String {
    let mut mods = Vec::new();
    mods.push(m.accessibility.to_lowercase());
    if m.is_static {
        mods.push("static".to_string());
    }
    if m.is_virtual {
        mods.push("virtual".to_string());
    }
    if m.is_abstract {
        mods.push("abstract".to_string());
    }
    mods.join(" ")
}
