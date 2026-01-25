//! Disassembly operation handler.

use anyhow::{Context, Result};
use serde_json::json;
use crate::ghidra::bridge::GhidraBridge;

pub async fn handle_disasm(
    bridge: &mut GhidraBridge,
    address: &str,
    count: Option<usize>
) -> Result<String> {
    let mut args = json!({"address": address});

    if let Some(num) = count {
        args["count"] = json!(num);
    }

    let response = bridge.send_command::<serde_json::Value>(
        "disasm",
        Some(args)
    ).context("Failed to disassemble")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to disassemble".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_placeholder() {
        assert!(true);
    }
}
