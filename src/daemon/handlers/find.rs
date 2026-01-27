//! Find/search operation handlers.

use crate::ghidra::bridge::GhidraBridge;
use anyhow::{Context, Result};
use serde_json::json;

pub async fn handle_find_string(bridge: &mut GhidraBridge, pattern: &str) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("find_string", Some(json!({"pattern": pattern})))
        .context("Failed to find string")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to find string".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_find_bytes(bridge: &mut GhidraBridge, hex: &str) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("find_bytes", Some(json!({"hex": hex})))
        .context("Failed to find bytes")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to find bytes".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_find_function(bridge: &mut GhidraBridge, pattern: &str) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("find_function", Some(json!({"pattern": pattern})))
        .context("Failed to find function")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to find function".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_find_calls(bridge: &mut GhidraBridge, function: &str) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("find_calls", Some(json!({"function": function})))
        .context("Failed to find calls")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to find calls".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_find_crypto(bridge: &mut GhidraBridge) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("find_crypto", None)
        .context("Failed to find crypto constants")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to find crypto constants".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_find_interesting(bridge: &mut GhidraBridge) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("find_interesting", None)
        .context("Failed to find interesting functions")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to find interesting functions".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_placeholder() {
        assert!(true);
    }
}
