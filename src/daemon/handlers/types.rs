//! Type operation handlers.

use anyhow::{Context, Result};
use serde_json::json;
use crate::ghidra::bridge::GhidraBridge;

pub async fn handle_type_list(bridge: &mut GhidraBridge) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "type_list",
        None
    ).context("Failed to list types")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to list types".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_type_get(
    bridge: &mut GhidraBridge,
    name: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "type_get",
        Some(json!({"name": name}))
    ).context("Failed to get type")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to get type".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_type_create(
    bridge: &mut GhidraBridge,
    name: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "type_create",
        Some(json!({"name": name}))
    ).context("Failed to create type")?;

    if response.status == "success" {
        Ok(json!({"status": "created", "name": name}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to create type".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_type_apply(
    bridge: &mut GhidraBridge,
    address: &str,
    type_name: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "type_apply",
        Some(json!({
            "address": address,
            "type_name": type_name
        }))
    ).context("Failed to apply type")?;

    if response.status == "success" {
        Ok(json!({"status": "applied", "address": address, "type": type_name}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to apply type".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
