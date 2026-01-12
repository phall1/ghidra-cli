//! Daemon core logic.
//!
//! The daemon is the main runtime that:
//! - Loads and maintains project state in memory
//! - Queues commands to prevent Ghidra conflicts
//! - Serves RPC requests from clients
//! - Handles graceful shutdown

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::daemon::process::{write_daemon_info, remove_lock_file, DaemonInfo, get_data_dir};
use crate::daemon::queue::CommandQueue;
use crate::daemon::state::DaemonState;

pub mod cache;
pub mod process;
pub mod queue;
pub mod rpc;
pub mod state;

/// Daemon configuration.
pub struct DaemonConfig {
    /// Path to the project directory
    pub project_path: PathBuf,
    /// RPC port (None = auto-select)
    pub port: Option<u16>,
    /// Ghidra installation directory
    pub ghidra_install_dir: Option<PathBuf>,
    /// Log file path
    pub log_file: PathBuf,
}

/// Run the daemon.
pub async fn run(config: DaemonConfig) -> Result<()> {
    info!("Starting Ghidra daemon");
    info!("Project: {}", config.project_path.display());

    // Get data directory
    let data_dir = get_data_dir()
        .context("Failed to get data directory")?;

    // Load project state
    let _state = Arc::new(
        DaemonState::load(&config.project_path, config.ghidra_install_dir.as_deref())
            .context("Failed to load project state")?
    );

    info!("Project state loaded successfully");

    // Create command queue
    let queue = Arc::new(CommandQueue::new(config.project_path.clone()));

    // Create shutdown channel
    let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

    // Start RPC server
    let port = self::rpc::run_server(queue.clone(), config.port, shutdown_tx.clone()).await
        .context("Failed to start RPC server")?;

    info!("RPC server listening on port {}", port);

    // Write lock file
    let daemon_info = DaemonInfo::new(&config.project_path, port, &config.log_file);
    write_daemon_info(&data_dir, &config.project_path, &daemon_info)
        .context("Failed to write lock file")?;

    // Start cache cleanup task
    let cache_cleanup_handle = {
        let queue = queue.clone();
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_tx.subscribe();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(300)) => {
                        // Cleanup cache every 5 minutes
                        // Note: This would need access to the cache
                        // For now, we'll skip this as the cache is internal to the queue
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Cache cleanup task stopping");
                        break;
                    }
                }
            }
        })
    };

    // Wait for shutdown signal
    let shutdown_reason = wait_for_shutdown(shutdown_tx.clone()).await;

    info!("Shutdown initiated: {:?}", shutdown_reason);

    // Clean up
    shutdown_tx.send(()).ok(); // Signal all tasks to stop

    // Wait for cache cleanup to stop (with timeout)
    tokio::select! {
        _ = cache_cleanup_handle => {
            info!("Cache cleanup task stopped");
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
            warn!("Cache cleanup task did not stop in time");
        }
    }

    // Remove lock file
    remove_lock_file(&data_dir, &config.project_path)
        .context("Failed to remove lock file")?;

    info!("Daemon stopped");
    Ok(())
}

/// The reason for shutdown.
#[derive(Debug, Clone)]
pub enum ShutdownReason {
    /// SIGINT (Ctrl+C)
    Interrupt,
    /// SIGTERM
    Terminate,
    /// RPC shutdown request
    RpcRequest,
}

/// Wait for a shutdown signal.
async fn wait_for_shutdown(shutdown_tx: broadcast::Sender<()>) -> ShutdownReason {
    let mut shutdown_rx = shutdown_tx.subscribe();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT");
                ShutdownReason::Interrupt
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
                ShutdownReason::Terminate
            }
            _ = shutdown_rx.recv() => {
                info!("Received shutdown request via RPC");
                ShutdownReason::RpcRequest
            }
        }
    }

    #[cfg(windows)]
    {
        use tokio::signal;

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl+C");
                ShutdownReason::Interrupt
            }
            _ = shutdown_rx.recv() => {
                info!("Received shutdown request via RPC");
                ShutdownReason::RpcRequest
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config() {
        let config = DaemonConfig {
            project_path: PathBuf::from("/test/project"),
            port: Some(17700),
            ghidra_install_dir: None,
            log_file: PathBuf::from("/test/logs/daemon.log"),
        };

        assert_eq!(config.port, Some(17700));
    }
}
