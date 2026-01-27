//! Program statistics handler.

use crate::ghidra::bridge::GhidraBridge;
use anyhow::{Context, Result};

pub async fn handle_stats(bridge: &mut GhidraBridge) -> Result<String> {
    let response = bridge
        .send_command::<serde_json::Value>("stats", None)
        .context("Failed to get program statistics")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(serde_json::json!({}));
        serde_json::to_string(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Failed to get program statistics".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_placeholder() {
        assert!(true);
    }
}
