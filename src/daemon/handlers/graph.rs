//! Graph operation handlers.

use anyhow::{Context, Result};
use serde_json::json;
use crate::ghidra::bridge::GhidraBridge;

pub async fn handle_graph_calls(
    bridge: &mut GhidraBridge,
    limit: Option<usize>
) -> Result<String> {
    let args = if let Some(lim) = limit {
        Some(json!({"limit": lim}))
    } else {
        None
    };

    let response = bridge.send_command::<serde_json::Value>(
        "graph_calls",
        args
    ).context("Failed to get call graph")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to get call graph".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_graph_callers(
    bridge: &mut GhidraBridge,
    function: &str,
    depth: Option<usize>
) -> Result<String> {
    let mut args = json!({"function": function});
    if let Some(d) = depth {
        args["depth"] = json!(d);
    }

    let response = bridge.send_command::<serde_json::Value>(
        "graph_callers",
        Some(args)
    ).context("Failed to get callers")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to get callers".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_graph_callees(
    bridge: &mut GhidraBridge,
    function: &str,
    depth: Option<usize>
) -> Result<String> {
    let mut args = json!({"function": function});
    if let Some(d) = depth {
        args["depth"] = json!(d);
    }

    let response = bridge.send_command::<serde_json::Value>(
        "graph_callees",
        Some(args)
    ).context("Failed to get callees")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to get callees".to_string());
        anyhow::bail!("{}", message)
    }
}

pub async fn handle_graph_export(
    bridge: &mut GhidraBridge,
    format: &str
) -> Result<String> {
    let response = bridge.send_command::<serde_json::Value>(
        "graph_export",
        Some(json!({"format": format}))
    ).context("Failed to export graph")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Failed to export graph".to_string());
        anyhow::bail!("{}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
