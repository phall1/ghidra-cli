//! Patch operation handlers.

use crate::ghidra::bridge::GhidraBridge;
use anyhow::{Context, Result};
use serde_json::json;

pub async fn handle_patch_bytes(
    bridge: &mut GhidraBridge,
    address: &str,
    hex: &str,
) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>(
            "patch_bytes",
            Some(json!({
                "address": address,
                "hex": hex
            })),
        )
        .context("Failed to patch bytes")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to patch bytes".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_patch_nop(bridge: &mut GhidraBridge, address: &str) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("patch_nop", Some(json!({"address": address})))
        .context("Failed to patch NOP")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to patch NOP".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_patch_export(bridge: &mut GhidraBridge, output: &str) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("patch_export", Some(json!({"output": output})))
        .context("Failed to export patched binary")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to export patched binary".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder() {
        assert!(true);
    }
}
