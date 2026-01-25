//! Program operation handlers.

use anyhow::{Context, Result};
use serde_json::json;
use crate::ghidra::bridge::GhidraBridge;

pub async fn handle_program_close(bridge: &mut GhidraBridge) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "program_close",
        None
    ).context("Failed to close program")?;

    if response.status == "success" {
        Ok(json!({"status": "closed"}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to close program".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_program_delete(
    bridge: &mut GhidraBridge,
    program_name: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "program_delete",
        Some(json!({
            "program": program_name
        }))
    ).context("Failed to delete program")?;

    if response.status == "success" {
        Ok(json!({"status": "deleted", "program": program_name}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to delete program".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_program_info(bridge: &mut GhidraBridge) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "program_info",
        None
    ).context("Failed to get program info")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to get program info".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_program_export(
    bridge: &mut GhidraBridge,
    format: &str,
    output: Option<&str>
) -> Result<String> {
    let mut args = json!({
        "format": format
    });

    if let Some(output_path) = output {
        args["output"] = json!(output_path);
    }

    let response = bridge.send_command::<serde_json::Value>(
        "program_export",
        Some(args)
    ).context("Failed to export program")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to export program".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
