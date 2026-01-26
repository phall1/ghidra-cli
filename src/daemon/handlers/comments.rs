//! Comment operation handlers.

use anyhow::{Context, Result};
use serde_json::json;
use crate::ghidra::bridge::GhidraBridge;

pub async fn handle_comment_list(bridge: &mut GhidraBridge) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "comment_list",
        None
    ).context("Failed to list comments")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to list comments".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_comment_get(
    bridge: &mut GhidraBridge,
    address: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "comment_get",
        Some(json!({"address": address}))
    ).context("Failed to get comment")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to get comment".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_comment_set(
    bridge: &mut GhidraBridge,
    address: &str,
    text: &str,
    comment_type: Option<&str>
) -> Result<String> {
    let mut args = json!({
        "address": address,
        "text": text
    });

    if let Some(ctype) = comment_type {
        args["comment_type"] = json!(ctype);
    }

    let response = bridge.send_command::<serde_json::Value>(
        "comment_set",
        Some(args)
    ).context("Failed to set comment")?;

    if response.status == "success" {
        Ok(json!({"status": "set", "address": address}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to set comment".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_comment_delete(
    bridge: &mut GhidraBridge,
    address: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "comment_delete",
        Some(json!({"address": address}))
    ).context("Failed to delete comment")?;

    if response.status == "success" {
        Ok(json!({"status": "deleted", "address": address}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to delete comment".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
