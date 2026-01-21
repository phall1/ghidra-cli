//! Command handler for processing IPC requests.
//!
//! Translates IPC commands into Ghidra bridge operations.

use std::sync::Arc;

use serde_json::json;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::ghidra::bridge::GhidraBridge;
use crate::ipc::protocol::{Command, Response};

/// Handle an IPC command.
pub async fn handle_command(
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
    id: u64,
    command: Command,
) -> Response {
    match handle_command_inner(bridge, command).await {
        Ok(result) => Response::success(id, result),
        Err(e) => Response::error(id, e.to_string()),
    }
}

async fn handle_command_inner(
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
    command: Command,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Command::Ping => {
            Ok(json!({"status": "ok"}))
        }

        Command::Status => {
            let bridge_guard = bridge.lock().await;
            let bridge_running = bridge_guard.as_ref().map(|b| b.is_running()).unwrap_or(false);
            Ok(json!({
                "bridge_running": bridge_running,
            }))
        }

        Command::ClearCache => {
            // TODO: Implement cache clearing
            Ok(json!({"cleared": true}))
        }

        Command::Shutdown => {
            // Shutdown is handled at a higher level
            Ok(json!({"status": "shutting_down"}))
        }

        Command::ListFunctions { limit, filter } => {
            execute_bridge_command(bridge, "list_functions", Some(json!({
                "limit": limit,
                "filter": filter,
            }))).await
        }

        Command::Decompile { address } => {
            execute_bridge_command(bridge, "decompile", Some(json!({
                "address": address,
            }))).await
        }

        Command::ListStrings { limit } => {
            execute_bridge_command(bridge, "list_strings", Some(json!({
                "limit": limit,
            }))).await
        }

        Command::ListImports => {
            execute_bridge_command(bridge, "list_imports", None).await
        }

        Command::ListExports => {
            execute_bridge_command(bridge, "list_exports", None).await
        }

        Command::MemoryMap => {
            execute_bridge_command(bridge, "memory_map", None).await
        }

        Command::ProgramInfo => {
            execute_bridge_command(bridge, "program_info", None).await
        }

        Command::XRefsTo { address } => {
            execute_bridge_command(bridge, "xrefs_to", Some(json!({
                "address": address,
            }))).await
        }

        Command::XRefsFrom { address } => {
            execute_bridge_command(bridge, "xrefs_from", Some(json!({
                "address": address,
            }))).await
        }
    }
}

/// Execute a command on the Ghidra bridge.
async fn execute_bridge_command(
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
    command: &str,
    args: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let mut bridge_guard = bridge.lock().await;
    
    let bridge = bridge_guard.as_mut()
        .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;
    
    if !bridge.is_running() {
        anyhow::bail!("Bridge is not running");
    }

    debug!("Executing bridge command: {}", command);
    
    let response = bridge.send_command::<serde_json::Value>(command, args)?;
    
    if response.status == "success" {
        Ok(response.data.unwrap_or(json!({})))
    } else {
        let message = response.message.unwrap_or_else(|| "Unknown error".to_string());
        anyhow::bail!("{}", message)
    }
}
