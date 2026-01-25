//! Symbol operation handlers.

use anyhow::{Context, Result};
use serde_json::json;
use crate::ghidra::bridge::GhidraBridge;

pub async fn handle_symbol_list(
    bridge: &mut GhidraBridge,
    filter: Option<&str>
) -> Result<String> {
    let args = if let Some(f) = filter {
        Some(json!({"filter": f}))
    } else {
        None
    };

    let response = bridge.send_command::<serde_json::Value>(
        "symbol_list",
        args
    ).context("Failed to list symbols")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to list symbols".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_symbol_get(
    bridge: &mut GhidraBridge,
    address: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "symbol_get",
        Some(json!({"address": address}))
    ).context("Failed to get symbol")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to get symbol".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_symbol_create(
    bridge: &mut GhidraBridge,
    address: &str,
    name: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "symbol_create",
        Some(json!({
            "address": address,
            "name": name
        }))
    ).context("Failed to create symbol")?;

    if response.status == "success" {
        Ok(json!({"status": "created", "address": address, "name": name}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to create symbol".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_symbol_delete(
    bridge: &mut GhidraBridge,
    name: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "symbol_delete",
        Some(json!({"name": name}))
    ).context("Failed to delete symbol")?;

    if response.status == "success" {
        Ok(json!({"status": "deleted", "name": name}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to delete symbol".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_symbol_rename(
    bridge: &mut GhidraBridge,
    old_name: &str,
    new_name: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "symbol_rename",
        Some(json!({
            "old_name": old_name,
            "new_name": new_name
        }))
    ).context("Failed to rename symbol")?;

    if response.status == "success" {
        Ok(json!({"status": "renamed", "old_name": old_name, "new_name": new_name}).to_string())
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to rename symbol".to_string());
        anyhow::bail!("{}", message)
    }
}

/// Resolve address input - handles both hex addresses and symbol names.
/// The actual resolution is done on the Python side.
#[allow(dead_code)]
fn resolve_address(input: &str) -> Result<String> {
    // Pass-through to Python layer which handles both hex addresses and symbol name lookups
    if input.starts_with("0x") || input.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(input.to_string())
    } else {
        Ok(input.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_address_hex() {
        assert_eq!(resolve_address("0x1000").unwrap(), "0x1000");
    }

    #[test]
    fn test_resolve_address_name() {
        assert_eq!(resolve_address("main").unwrap(), "main");
    }
}
