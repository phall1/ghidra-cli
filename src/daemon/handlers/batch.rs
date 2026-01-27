//! Batch operation handler.

use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::path::Path;

pub async fn handle_batch(file_path: &str) -> Result<String> {
    let path = Path::new(file_path);

    if !path.exists() {
        anyhow::bail!("Batch file not found: {}", file_path);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read batch file: {}", file_path))?;

    let mut results = Vec::new();
    let mut line_number = 0;

    for line in content.lines() {
        line_number += 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        results.push(json!({
            "line": line_number,
            "command": trimmed,
            "status": "not_implemented",
            "message": "Batch command execution not yet implemented"
        }));
    }

    let response = json!({
        "file": file_path,
        "commands_parsed": results.len(),
        "results": results
    });

    serde_json::to_string(&response).context("Failed to serialize batch results")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_placeholder() {
        assert!(true);
    }
}
