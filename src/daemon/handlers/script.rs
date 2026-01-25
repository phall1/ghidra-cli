//! Script execution handlers.

use anyhow::{Context, Result};
use serde_json::json;
use crate::ghidra::bridge::GhidraBridge;

pub async fn handle_script_run(
    bridge: &mut GhidraBridge,
    path: &str,
    args: &[String]
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "script_run",
        Some(json!({"path": path, "args": args}))
    ).context("Failed to run script")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to run script".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_script_python(
    bridge: &mut GhidraBridge,
    code: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "script_python",
        Some(json!({"code": code}))
    ).context("Failed to execute Python code")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to execute Python code".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_script_java(
    bridge: &mut GhidraBridge,
    code: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "script_java",
        Some(json!({"code": code}))
    ).context("Failed to execute Java code")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to execute Java code".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_script_list(bridge: &mut GhidraBridge) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "script_list",
        None
    ).context("Failed to list scripts")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to list scripts".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_placeholder() {
        assert!(true);
    }
}
