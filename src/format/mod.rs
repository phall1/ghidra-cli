#![allow(dead_code)]

use serde::Serialize;
use serde_json::Value as JsonValue;
use crate::error::{GhidraError, Result};
use comfy_table::{Table, presets::UTF8_FULL};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Full,
    Compact,
    Minimal,
    Json,
    JsonCompact,
    JsonStream,
    Csv,
    Tsv,
    Table,
    Ids,
    Count,
    Tree,
    Hex,
    Asm,
    C,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "compact" => Ok(Self::Compact),
            "minimal" => Ok(Self::Minimal),
            "json" => Ok(Self::Json),
            "json-compact" => Ok(Self::JsonCompact),
            "json-stream" | "ndjson" => Ok(Self::JsonStream),
            "csv" => Ok(Self::Csv),
            "tsv" => Ok(Self::Tsv),
            "table" => Ok(Self::Table),
            "ids" => Ok(Self::Ids),
            "count" => Ok(Self::Count),
            "tree" => Ok(Self::Tree),
            "hex" => Ok(Self::Hex),
            "asm" => Ok(Self::Asm),
            "c" => Ok(Self::C),
            _ => Err(GhidraError::InvalidFormat(format!("Unknown format: {}", s))),
        }
    }

    pub fn is_human_friendly(&self) -> bool {
        matches!(self, Self::Full | Self::Compact | Self::Table | Self::Tree)
    }

    pub fn is_machine_friendly(&self) -> bool {
        matches!(self, Self::Json | Self::JsonCompact | Self::JsonStream | Self::Csv | Self::Tsv)
    }
}

pub trait Formatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String>;
}

pub struct DefaultFormatter;

impl Formatter for DefaultFormatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Json => {
                serde_json::to_string_pretty(data).map_err(|e| e.into())
            }
            OutputFormat::JsonCompact => {
                serde_json::to_string(data).map_err(|e| e.into())
            }
            OutputFormat::JsonStream => {
                let mut result = String::new();
                for item in data {
                    let json = serde_json::to_string(item)?;
                    result.push_str(&json);
                    result.push('\n');
                }
                Ok(result)
            }
            OutputFormat::Count => {
                Ok(format!("{}", data.len()))
            }
            OutputFormat::Table => {
                format_table(data)
            }
            OutputFormat::Csv => {
                format_csv(data, ',')
            }
            OutputFormat::Tsv => {
                format_csv(data, '\t')
            }
            OutputFormat::Minimal | OutputFormat::Ids => {
                format_minimal(data)
            }
            _ => {
                // For other formats, default to JSON
                serde_json::to_string_pretty(data).map_err(|e| e.into())
            }
        }
    }
}

fn format_table<T: Serialize>(data: &[T]) -> Result<String> {
    if data.is_empty() {
        return Ok("No results".to_string());
    }

    // Convert to JSON values to inspect structure
    let json_data: Vec<JsonValue> = data.iter()
        .map(|item| serde_json::to_value(item))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    // Get all keys from first object
    let keys = if let Some(JsonValue::Object(map)) = json_data.first() {
        map.keys().cloned().collect::<Vec<_>>()
    } else {
        return Ok(format!("{} results", data.len()));
    };

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);

    // Add header
    table.set_header(&keys);

    // Add rows
    for item in &json_data {
        if let JsonValue::Object(map) = item {
            let row: Vec<String> = keys.iter()
                .map(|k| {
                    map.get(k)
                        .map(|v| format_json_value(v))
                        .unwrap_or_else(|| "".to_string())
                })
                .collect();
            table.add_row(row);
        }
    }

    Ok(table.to_string())
}

fn format_csv<T: Serialize>(data: &[T], delimiter: char) -> Result<String> {
    if data.is_empty() {
        return Ok(String::new());
    }

    let json_data: Vec<JsonValue> = data.iter()
        .map(|item| serde_json::to_value(item))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok(String::new());
    }

    let keys = if let Some(JsonValue::Object(map)) = json_data.first() {
        map.keys().cloned().collect::<Vec<_>>()
    } else {
        return Ok(String::new());
    };

    let mut result = String::new();

    // Header
    result.push_str(&keys.join(&delimiter.to_string()));
    result.push('\n');

    // Rows
    for item in &json_data {
        if let JsonValue::Object(map) = item {
            let row: Vec<String> = keys.iter()
                .map(|k| {
                    map.get(k)
                        .map(|v| format_json_value(v))
                        .unwrap_or_else(|| "".to_string())
                })
                .collect();
            result.push_str(&row.join(&delimiter.to_string()));
            result.push('\n');
        }
    }

    Ok(result)
}

fn format_minimal<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data.iter()
        .map(|item| serde_json::to_value(item))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut result = String::new();

    for item in &json_data {
        if let JsonValue::Object(map) = item {
            // Try to get address or name or first field
            let value = map.get("address")
                .or_else(|| map.get("name"))
                .or_else(|| map.get("id"))
                .or_else(|| map.values().next())
                .map(|v| format_json_value(v))
                .unwrap_or_else(|| "".to_string());

            result.push_str(&value);
            result.push('\n');
        } else {
            result.push_str(&format_json_value(item));
            result.push('\n');
        }
    }

    Ok(result)
}

fn format_json_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => s.clone(),
        JsonValue::Array(arr) => {
            format!("[{}]", arr.iter().map(format_json_value).collect::<Vec<_>>().join(", "))
        }
        JsonValue::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()),
    }
}

pub fn auto_detect_format(is_tty: bool) -> OutputFormat {
    if is_tty {
        OutputFormat::Table
    } else {
        OutputFormat::JsonCompact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_format_json() {
        let data = vec![
            json!({"name": "test", "value": 123}),
        ];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Json).unwrap();
        assert!(result.contains("test"));
    }

    #[test]
    fn test_format_count() {
        let data = vec![
            json!({"name": "test1"}),
            json!({"name": "test2"}),
        ];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Count).unwrap();
        assert_eq!(result, "2");
    }
}
