//! Command handler for processing IPC requests.
//!
//! Translates IPC commands into Ghidra bridge operations.
//! Handles lazy bridge startup on Import/Analyze commands.

use std::sync::Arc;

use serde_json::json;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::ghidra::bridge::{BridgeStartMode, GhidraBridge};
use crate::ipc::protocol::{Command, Response};

use super::DaemonState;

/// Handle an IPC command.
pub async fn handle_command(
    state: &Arc<DaemonState>,
    id: u64,
    command: Command,
) -> Response {
    match handle_command_inner(state, command).await {
        Ok(result) => Response::success(id, result),
        Err(e) => Response::error(id, e.to_string()),
    }
}

/// Ensure the bridge is running, returning an error if not.
async fn require_bridge(
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
) -> anyhow::Result<()> {
    let bridge_guard = bridge.lock().await;
    let b = bridge_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No program loaded. Run 'ghidra import <binary>' first."))?;
    if !b.is_running() {
        anyhow::bail!("Bridge is not running. Try restarting the daemon.");
    }
    Ok(())
}

/// Start the bridge in import mode (lazy start).
async fn start_bridge_for_import(
    state: &Arc<DaemonState>,
    binary_path: &str,
    project: &str,
) -> anyhow::Result<()> {
    let ghidra_dir = state
        .ghidra_install_dir
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Ghidra installation directory not configured"))?;

    // Ensure project directory exists (Ghidra requires it)
    if !state.project_path.exists() {
        std::fs::create_dir_all(&state.project_path)
            .map_err(|e| anyhow::anyhow!("Failed to create project directory: {}", e))?;
    }

    // Stop existing bridge if any
    {
        let mut bridge_guard = state.bridge.lock().await;
        if let Some(mut b) = bridge_guard.take() {
            info!("Stopping existing bridge before import");
            b.stop().ok();
        }
    }

    let mut new_bridge = GhidraBridge::new(
        ghidra_dir.clone(),
        state.project_path.clone(),
        project.to_string(),
    );

    info!("Starting bridge in import mode for: {}", binary_path);
    new_bridge.start(BridgeStartMode::Import {
        binary_path: binary_path.to_string(),
    })?;

    let mut bridge_guard = state.bridge.lock().await;
    *bridge_guard = Some(new_bridge);

    Ok(())
}

/// Start the bridge in process mode (for analyze/query after import).
async fn start_bridge_for_process(
    state: &Arc<DaemonState>,
    project: &str,
    program: &str,
) -> anyhow::Result<()> {
    let ghidra_dir = state
        .ghidra_install_dir
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Ghidra installation directory not configured"))?;

    // Ensure project directory exists
    if !state.project_path.exists() {
        std::fs::create_dir_all(&state.project_path)
            .map_err(|e| anyhow::anyhow!("Failed to create project directory: {}", e))?;
    }

    // Stop existing bridge if any
    {
        let mut bridge_guard = state.bridge.lock().await;
        if let Some(mut b) = bridge_guard.take() {
            info!("Stopping existing bridge before starting process mode");
            b.stop().ok();
        }
    }

    let mut new_bridge = GhidraBridge::new(
        ghidra_dir.clone(),
        state.project_path.clone(),
        project.to_string(),
    );

    info!("Starting bridge in process mode for: {}", program);
    new_bridge.start(BridgeStartMode::Process {
        program_name: program.to_string(),
    })?;

    let mut bridge_guard = state.bridge.lock().await;
    *bridge_guard = Some(new_bridge);

    Ok(())
}

async fn handle_command_inner(
    state: &Arc<DaemonState>,
    command: Command,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Command::Ping => Ok(json!({"status": "ok"})),

        Command::Status => {
            let bridge_guard = state.bridge.lock().await;
            let bridge_running = bridge_guard
                .as_ref()
                .map(|b| b.is_running())
                .unwrap_or(false);
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

        // === Import: reuses running bridge if available, otherwise lazy-starts ===
        Command::Import {
            binary_path,
            project,
            program,
        } => {
            // Check if bridge is already running
            let bridge_running = {
                let bridge_guard = state.bridge.lock().await;
                bridge_guard.as_ref().map(|b| b.is_running()).unwrap_or(false)
            };

            if bridge_running {
                // Bridge already running — import via bridge command, no JVM restart
                let mut bridge_guard = state.bridge.lock().await;
                let bridge = bridge_guard.as_mut().unwrap();

                let import_response = bridge.send_command::<serde_json::Value>(
                    "import",
                    Some(json!({
                        "binary_path": binary_path,
                        "program": program,
                    })),
                )?;

                if import_response.status != "success" {
                    let msg = import_response.message.unwrap_or_else(|| "Import failed".to_string());
                    anyhow::bail!("{}", msg);
                }

                let program_name = program.unwrap_or_else(|| {
                    import_response
                        .data
                        .as_ref()
                        .and_then(|d| d.get("program"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown")
                        .to_string()
                });

                // Switch to the newly imported program
                let open_response = bridge.send_command::<serde_json::Value>(
                    "open_program",
                    Some(json!({"program": program_name})),
                )?;

                if open_response.status != "success" {
                    let msg = open_response.message.unwrap_or_else(|| "Failed to switch program".to_string());
                    anyhow::bail!("{}", msg);
                }

                Ok(json!({"program": program_name}))
            } else {
                // No bridge running — start one in import mode
                start_bridge_for_import(state, &binary_path, &project).await?;

                let mut bridge_guard = state.bridge.lock().await;
                let bridge = bridge_guard
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("Bridge failed to start"))?;

                let response = bridge.send_command::<serde_json::Value>(
                    "program_info",
                    None,
                )?;

                if response.status == "success" {
                    let program_name = program.unwrap_or_else(|| {
                        response
                            .data
                            .as_ref()
                            .and_then(|d| d.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown")
                            .to_string()
                    });
                    Ok(json!({"program": program_name}))
                } else {
                    let msg = response.message.unwrap_or_else(|| "Import failed".to_string());
                    anyhow::bail!("{}", msg)
                }
            }
        }

        // === Analyze: reuses running bridge, Python side handles program switching ===
        Command::Analyze { project, program } => {
            // Check if bridge is already running
            let bridge_running = {
                let bridge_guard = state.bridge.lock().await;
                bridge_guard.as_ref().map(|b| b.is_running()).unwrap_or(false)
            };

            if bridge_running {
                // Bridge already running — analyze command handles open_program internally
                let mut bridge_guard = state.bridge.lock().await;
                let bridge = bridge_guard.as_mut().unwrap();
                let response = bridge.send_command::<serde_json::Value>(
                    "analyze",
                    Some(json!({"project": project, "program": program})),
                )?;

                if response.status == "success" {
                    Ok(response.data.unwrap_or(json!({"status": "analysis_complete"})))
                } else {
                    let msg = response.message.unwrap_or_else(|| "Analysis failed".to_string());
                    anyhow::bail!("{}", msg)
                }
            } else {
                // Bridge not running, start it in process mode
                start_bridge_for_process(state, &project, &program).await?;
                Ok(json!({"status": "bridge_started", "program": program}))
            }
        }

        // === Program management commands ===
        Command::ListPrograms => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(state, "list_programs", None).await
        }

        Command::OpenProgram { program } => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(
                state,
                "open_program",
                Some(json!({"program": program})),
            )
            .await
        }

        // === All other commands require bridge to be running ===
        Command::ListFunctions { limit, filter } => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(
                state,
                "list_functions",
                Some(json!({
                    "limit": limit,
                    "filter": filter,
                })),
            )
            .await
        }

        Command::Decompile { address } => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(
                state,
                "decompile",
                Some(json!({
                    "address": address,
                })),
            )
            .await
        }

        Command::ListStrings { limit } => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(
                state,
                "list_strings",
                Some(json!({
                    "limit": limit,
                })),
            )
            .await
        }

        Command::ListImports => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(state, "list_imports", None).await
        }

        Command::ListExports => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(state, "list_exports", None).await
        }

        Command::MemoryMap => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(state, "memory_map", None).await
        }

        Command::ProgramInfo => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(state, "program_info", None).await
        }

        Command::XRefsTo { address } => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(
                state,
                "xrefs_to",
                Some(json!({
                    "address": address,
                })),
            )
            .await
        }

        Command::XRefsFrom { address } => {
            require_bridge(&state.bridge).await?;
            execute_bridge_command(
                state,
                "xrefs_from",
                Some(json!({
                    "address": address,
                })),
            )
            .await
        }

        Command::ExecuteCli { command_json } => {
            // Deserialize and execute CLI command through the queue handlers
            let cli_command: crate::cli::Commands = serde_json::from_str(&command_json)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize CLI command: {}", e))?;

            // Ensure bridge is running for ExecuteCli commands
            require_bridge(&state.bridge).await?;

            // Execute using the queue's command execution logic
            let result = crate::daemon::queue::execute_command_direct(&state.bridge, &cli_command).await?;

            // Parse the result as JSON (handlers return JSON strings)
            Ok(serde_json::from_str(&result).unwrap_or_else(|_| json!({"output": result})))
        }
    }
}

/// Execute a command on the Ghidra bridge.
///
/// If the bridge process dies during command execution, triggers daemon shutdown.
async fn execute_bridge_command(
    state: &Arc<DaemonState>,
    command: &str,
    args: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let mut bridge_guard = state.bridge.lock().await;

    let bridge = bridge_guard
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("No program loaded. Run 'ghidra import <binary>' first."))?;

    if !bridge.is_running() {
        anyhow::bail!("Bridge is not running");
    }

    debug!("Executing bridge command: {}", command);

    let response = match bridge.send_command::<serde_json::Value>(command, args) {
        Ok(resp) => resp,
        Err(e) => {
            // Check if bridge process died - trigger daemon shutdown
            let err_msg = e.to_string();
            if err_msg.contains("process died") || !bridge.is_running() {
                info!("Bridge process died, triggering daemon shutdown");
                let _ = state.shutdown_tx.send(());
            }
            return Err(e);
        }
    };

    if response.status == "success" {
        Ok(response.data.unwrap_or(json!({})))
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Unknown error".to_string());
        anyhow::bail!("{}", message)
    }
}
