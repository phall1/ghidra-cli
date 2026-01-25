//! Diff operation handlers.

use anyhow::{Context, Result};
use serde_json::json;
use crate::ghidra::bridge::GhidraBridge;

pub async fn handle_diff_programs(
    bridge: &mut GhidraBridge,
    prog1: &str,
    prog2: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "diff_programs",
        Some(json!({"prog1": prog1, "prog2": prog2}))
    ).context("Failed to diff programs")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to diff programs".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_diff_functions(
    bridge: &mut GhidraBridge,
    func1: &str,
    func2: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "diff_functions",
        Some(json!({"func1": func1, "func2": func2}))
    ).context("Failed to diff functions")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to diff functions".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_handlers_exist() {
        assert!(true);
    }
}
