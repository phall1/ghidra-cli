//! Command queue for serializing Ghidra operations.
//!
//! Ensures only one Ghidra headless operation runs at a time to prevent conflicts.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, Semaphore, oneshot};
use tracing::{info, warn};

use crate::cli::Commands;
use crate::daemon::cache::Cache;
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
        response_rx.await
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
        Commands::Query(query_args) => {
            match query_args.data_type.as_str() {
                "functions" => (
                    "list_functions",
                    Some(json!({
                        "limit": query_args.limit,
                        "filter": query_args.filter,
                    }))
                ),
                "strings" => (
                    "list_strings",
                    Some(json!({
                        "limit": query_args.limit,
                    }))
                ),
                "imports" => ("list_imports", None),
                "exports" => ("list_exports", None),
                _ => anyhow::bail!("Unknown query type: {}", query_args.data_type),
            }
        },
        Commands::Decompile(decompile_args) => (
            "decompile",
            Some(json!({
                "address": decompile_args.target,
            }))
        ),
        Commands::Memory(mem_cmd) => {
            use crate::cli::MemoryCommands;
            match mem_cmd {
                MemoryCommands::Map(_) => ("memory_map", None),
                _ => anyhow::bail!("Memory command not yet supported in daemon"),
            }
        },
        Commands::XRef(xref_cmd) => {
            use crate::cli::XRefCommands;
            match xref_cmd {
                XRefCommands::To(args) => (
                    "xrefs_to",
                    Some(json!({
                        "address": args.address,
                    }))
                ),
                XRefCommands::From(args) => (
                    "xrefs_from",
                    Some(json!({
                        "address": args.address,
                    }))
                ),
                XRefCommands::List(_) => anyhow::bail!("XRef List not yet supported"),
            }
        },
        Commands::Summary(_) => ("program_info", None),
        _ => anyhow::bail!("Command not yet supported in daemon: {:?}", command),
    };

    let mut bridge_guard = bridge.lock().await;

    let bridge_ref = bridge_guard.as_mut()
        .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

    if !bridge_ref.is_running() {
        anyhow::bail!("Bridge is not running");
    }

    let response = bridge_ref.send_command::<serde_json::Value>(bridge_cmd, args)
        .context("Bridge command failed")?;

    if response.status == "success" {
        let data = response.data.unwrap_or(json!({}));
        serde_json::to_string_pretty(&data)
            .context("Failed to serialize response")
    } else {
        let message = response.message.unwrap_or_else(|| "Unknown error".to_string());
        anyhow::bail!("{}", message)
    }
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
