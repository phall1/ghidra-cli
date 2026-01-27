//! Command queue for serializing Ghidra operations.
//!
//! Ensures only one Ghidra headless operation runs at a time to prevent conflicts.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{oneshot, Mutex, Semaphore};
use tracing::{info, warn};

use crate::cli::Commands;
use crate::daemon::cache::Cache;
use crate::daemon::handlers;
use crate::ghidra::bridge::GhidraBridge;

/// A queued command waiting to be executed.
struct QueuedCommand {
    command: Commands,
    response_tx: oneshot::Sender<Result<String>>,
}

/// Command queue for managing Ghidra operations.
pub struct CommandQueue {
    /// The project path being managed
    project_path: PathBuf,
    /// Queue of pending commands
    queue: Arc<Mutex<VecDeque<QueuedCommand>>>,
    /// Semaphore to ensure only one command executes at a time
    execution_lock: Arc<Semaphore>,
    /// Number of completed commands
    completed_count: Arc<Mutex<usize>>,
    /// Cache for common requests
    cache: Arc<Cache>,
    /// The Ghidra bridge instance
    bridge: Arc<Mutex<Option<GhidraBridge>>>,
}

impl CommandQueue {
    /// Create a new command queue.
    pub fn new(project_path: PathBuf, bridge: Arc<Mutex<Option<GhidraBridge>>>) -> Self {
        Self {
            project_path,
            queue: Arc::new(Mutex::new(VecDeque::new())),
            execution_lock: Arc::new(Semaphore::new(1)),
            completed_count: Arc::new(Mutex::new(0)),
            cache: Arc::new(Cache::new()),
            bridge,
        }
    }

    /// Submit a command for execution.
    pub async fn submit(&self, command: Commands) -> Result<String> {
        // Check cache first
        if let Some(cached) = self.cache.get(&command).await {
            info!("Cache hit for command");
            return Ok(cached);
        }

        let (response_tx, response_rx) = oneshot::channel();

        // Add to queue
        {
            let mut queue = self.queue.lock().await;
            queue.push_back(QueuedCommand {
                command: command.clone(),
                response_tx,
            });
            info!("Command queued (queue depth: {})", queue.len());
        }

        // Process queue
        self.process_queue().await;

        // Wait for response
        response_rx
            .await
            .context("Failed to receive command response")?
    }

    /// Process commands in the queue.
    async fn process_queue(&self) {
        let execution_lock = self.execution_lock.clone();
        let queue = self.queue.clone();
        let completed_count = self.completed_count.clone();
        let cache = self.cache.clone();
        let project_path = self.project_path.clone();
        let bridge = self.bridge.clone();

        tokio::spawn(async move {
            // Try to acquire execution lock (non-blocking)
            if let Ok(_permit) = execution_lock.try_acquire() {
                while let Some(queued_cmd) = {
                    let mut q = queue.lock().await;
                    q.pop_front()
                } {
                    info!("Executing command from queue");

                    // Execute the command
                    let result = execute_command(&project_path, &bridge, &queued_cmd.command).await;

                    // Cache successful results
                    if let Ok(ref output) = result {
                        cache.set(&queued_cmd.command, output.clone()).await;
                    }

                    // Send response
                    if queued_cmd.response_tx.send(result).is_err() {
                        warn!("Failed to send command response (receiver dropped)");
                    }

                    // Increment completed count
                    let mut count = completed_count.lock().await;
                    *count += 1;
                }
            }
        });
    }

    /// Get the current queue depth.
    pub fn queue_depth(&self) -> usize {
        // This is a synchronous method, so we can't await the lock
        // Return 0 as an estimate (actual depth available via async method)
        0
    }

    /// Get the current queue depth (async version).
    pub async fn queue_depth_async(&self) -> usize {
        let queue = self.queue.lock().await;
        queue.len()
    }

    /// Get the number of completed commands.
    pub fn completed_count(&self) -> usize {
        // This is a synchronous method, so we can't await the lock
        // Return 0 as an estimate (actual count available via async method)
        0
    }

    /// Get the number of completed commands (async version).
    pub async fn completed_count_async(&self) -> usize {
        let count = self.completed_count.lock().await;
        *count
    }

    /// Get the project path.
    pub fn project_path(&self) -> &Path {
        &self.project_path
    }
}

/// Execute a command against Ghidra via the bridge.
async fn execute_command(
    _project_path: &Path,
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
    command: &Commands,
) -> Result<String> {
    use serde_json::json;

    let (bridge_cmd, args) = match command {
        Commands::Query(query_args) => match query_args.data_type.as_str() {
            "functions" => (
                "list_functions",
                Some(json!({
                    "limit": query_args.limit,
                    "filter": query_args.filter,
                })),
            ),
            "strings" => (
                "list_strings",
                Some(json!({
                    "limit": query_args.limit,
                })),
            ),
            "imports" => ("list_imports", None),
            "exports" => ("list_exports", None),
            _ => anyhow::bail!("Unknown query type: {}", query_args.data_type),
        },
        Commands::Decompile(decompile_args) => (
            "decompile",
            Some(json!({
                "address": decompile_args.target,
            })),
        ),
        Commands::Memory(mem_cmd) => {
            use crate::cli::MemoryCommands;
            match mem_cmd {
                MemoryCommands::Map(_) => ("memory_map", None),
                _ => anyhow::bail!("Memory command not yet supported in daemon"),
            }
        }
        Commands::XRef(xref_cmd) => {
            use crate::cli::XRefCommands;
            match xref_cmd {
                XRefCommands::To(args) => (
                    "xrefs_to",
                    Some(json!({
                        "address": args.address,
                    })),
                ),
                XRefCommands::From(args) => (
                    "xrefs_from",
                    Some(json!({
                        "address": args.address,
                    })),
                ),
                XRefCommands::List(_) => anyhow::bail!("XRef List not yet supported"),
            }
        }
        Commands::Program(prog_cmd) => {
            use crate::cli::ProgramCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match prog_cmd {
                ProgramCommands::Close(_) => {
                    handlers::program::handle_program_close(bridge_ref).await
                }
                ProgramCommands::Delete(args) => {
                    let program = args
                        .program
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Program name required"))?;
                    handlers::program::handle_program_delete(bridge_ref, program).await
                }
                ProgramCommands::Info(_) => {
                    handlers::program::handle_program_info(bridge_ref).await
                }
                ProgramCommands::Export(args) => {
                    handlers::program::handle_program_export(
                        bridge_ref,
                        &args.format,
                        args.output.as_deref(),
                    )
                    .await
                }
            };
        }
        Commands::Symbol(sym_cmd) => {
            use crate::cli::SymbolCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match sym_cmd {
                SymbolCommands::List(opts) => {
                    handlers::symbols::handle_symbol_list(bridge_ref, opts.filter.as_deref()).await
                }
                SymbolCommands::Get(args) => {
                    handlers::symbols::handle_symbol_get(bridge_ref, &args.name).await
                }
                SymbolCommands::Create(args) => {
                    handlers::symbols::handle_symbol_create(bridge_ref, &args.address, &args.name)
                        .await
                }
                SymbolCommands::Delete(args) => {
                    handlers::symbols::handle_symbol_delete(bridge_ref, &args.name).await
                }
                SymbolCommands::Rename(args) => {
                    handlers::symbols::handle_symbol_rename(
                        bridge_ref,
                        &args.old_name,
                        &args.new_name,
                    )
                    .await
                }
            };
        }
        Commands::Type(type_cmd) => {
            use crate::cli::TypeCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match type_cmd {
                TypeCommands::List(_) => handlers::types::handle_type_list(bridge_ref).await,
                TypeCommands::Get(args) => {
                    handlers::types::handle_type_get(bridge_ref, &args.name).await
                }
                TypeCommands::Create(args) => {
                    handlers::types::handle_type_create(bridge_ref, &args.definition).await
                }
                TypeCommands::Apply(args) => {
                    handlers::types::handle_type_apply(bridge_ref, &args.address, &args.type_name)
                        .await
                }
            };
        }
        Commands::Comment(comment_cmd) => {
            use crate::cli::CommentCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match comment_cmd {
                CommentCommands::List(_) => {
                    handlers::comments::handle_comment_list(bridge_ref).await
                }
                CommentCommands::Get(args) => {
                    handlers::comments::handle_comment_get(bridge_ref, &args.address).await
                }
                CommentCommands::Set(args) => {
                    handlers::comments::handle_comment_set(
                        bridge_ref,
                        &args.address,
                        &args.text,
                        args.comment_type.as_deref(),
                    )
                    .await
                }
                CommentCommands::Delete(args) => {
                    handlers::comments::handle_comment_delete(bridge_ref, &args.address).await
                }
            };
        }
        Commands::Graph(graph_cmd) => {
            use crate::cli::GraphCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match graph_cmd {
                GraphCommands::Calls(opts) => {
                    handlers::graph::handle_graph_calls(bridge_ref, opts.limit).await
                }
                GraphCommands::Callers(args) => {
                    handlers::graph::handle_graph_callers(bridge_ref, &args.function, args.depth)
                        .await
                }
                GraphCommands::Callees(args) => {
                    handlers::graph::handle_graph_callees(bridge_ref, &args.function, args.depth)
                        .await
                }
                GraphCommands::Export(args) => {
                    handlers::graph::handle_graph_export(bridge_ref, &args.format).await
                }
            };
        }
        Commands::Find(find_cmd) => {
            use crate::cli::FindCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match find_cmd {
                FindCommands::String(args) => {
                    handlers::find::handle_find_string(bridge_ref, &args.pattern).await
                }
                FindCommands::Bytes(args) => {
                    handlers::find::handle_find_bytes(bridge_ref, &args.hex).await
                }
                FindCommands::Function(args) => {
                    handlers::find::handle_find_function(bridge_ref, &args.pattern).await
                }
                FindCommands::Calls(args) => {
                    handlers::find::handle_find_calls(bridge_ref, &args.function).await
                }
                FindCommands::Crypto(_) => handlers::find::handle_find_crypto(bridge_ref).await,
                FindCommands::Interesting(_) => {
                    handlers::find::handle_find_interesting(bridge_ref).await
                }
            };
        }
        Commands::Diff(diff_cmd) => {
            use crate::cli::DiffCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match diff_cmd {
                DiffCommands::Programs(args) => {
                    handlers::diff::handle_diff_programs(bridge_ref, &args.program1, &args.program2)
                        .await
                }
                DiffCommands::Functions(args) => {
                    handlers::diff::handle_diff_functions(bridge_ref, &args.func1, &args.func2)
                        .await
                }
            };
        }
        Commands::Patch(patch_cmd) => {
            use crate::cli::PatchCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match patch_cmd {
                PatchCommands::Bytes(args) => {
                    handlers::patch::handle_patch_bytes(bridge_ref, &args.address, &args.hex).await
                }
                PatchCommands::Nop(args) => {
                    handlers::patch::handle_patch_nop(bridge_ref, &args.address).await
                }
                PatchCommands::Export(args) => {
                    handlers::patch::handle_patch_export(bridge_ref, &args.output).await
                }
            };
        }
        Commands::Script(script_cmd) => {
            use crate::cli::ScriptCommands;
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return match script_cmd {
                ScriptCommands::Run(args) => {
                    handlers::script::handle_script_run(bridge_ref, &args.script_path, &args.args)
                        .await
                }
                ScriptCommands::Python(args) => {
                    handlers::script::handle_script_python(bridge_ref, &args.code).await
                }
                ScriptCommands::Java(args) => {
                    handlers::script::handle_script_java(bridge_ref, &args.code).await
                }
                ScriptCommands::List => handlers::script::handle_script_list(bridge_ref).await,
            };
        }
        Commands::Disasm(args) => {
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return handlers::disasm::handle_disasm(
                bridge_ref,
                &args.address,
                args.num_instructions,
            )
            .await;
        }
        Commands::Batch(args) => {
            return handlers::batch::handle_batch(&args.script_file).await;
        }
        Commands::Stats(_) => {
            let mut bridge_guard = bridge.lock().await;
            let bridge_ref = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge_ref.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            return handlers::stats::handle_stats(bridge_ref).await;
        }
        Commands::Summary(_) => ("program_info", None),
        _ => anyhow::bail!("Command not yet supported in daemon: {:?}", command),
    };

    let mut bridge_guard = bridge.lock().await;

    let bridge_ref = bridge_guard
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

    if !bridge_ref.is_running() {
        anyhow::bail!("Bridge is not running");
    }

    let response = bridge_ref
        .send_command::<serde_json::Value>(bridge_cmd, args)
        .context("Bridge command failed")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data).context("Failed to serialize response")
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Unknown error".to_string());
        anyhow::bail!("{}", message)
    }
}

/// Execute a CLI command directly (for IPC handler use).
/// This bypasses the queue and executes immediately.
pub async fn execute_command_direct(
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
    command: &Commands,
) -> Result<String> {
    execute_command(&PathBuf::new(), bridge, command).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_queue_creation() {
        let bridge = Arc::new(Mutex::new(None));
        let queue = CommandQueue::new(PathBuf::from("/test/project"), bridge);
        assert_eq!(queue.project_path(), Path::new("/test/project"));
        assert_eq!(queue.queue_depth_async().await, 0);
    }
}
