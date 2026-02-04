//! Daemon core logic.
//!
//! The daemon is the main runtime that:
//! - Manages a persistent Ghidra bridge process
//! - Serves commands via local socket IPC
//! - Handles graceful shutdown

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

use crate::daemon::process::{acquire_daemon_lock, get_data_dir, remove_info_file, write_daemon_info, DaemonInfo};
use crate::ghidra::bridge::GhidraBridge;

pub mod cache;
pub mod handler;
pub mod handlers;
pub mod ipc_server;
pub mod process;
pub mod queue;
pub mod state;

/// Daemon configuration.
pub struct DaemonConfig {
    /// Path to the project directory
    pub project_path: PathBuf,
    /// Ghidra installation directory
    pub ghidra_install_dir: Option<PathBuf>,
    /// Log file path
    pub log_file: PathBuf,
}

/// Shared daemon state accessible by handlers.
pub struct DaemonState {
    /// The Ghidra bridge instance (None until first import/analyze)
    pub bridge: Arc<Mutex<Option<GhidraBridge>>>,
    /// Ghidra installation directory
    pub ghidra_install_dir: Option<PathBuf>,
    /// Project path on disk
    pub project_path: PathBuf,
    /// Shutdown signal sender - handlers can trigger daemon shutdown on bridge death
    pub shutdown_tx: broadcast::Sender<()>,
}

/// Run the daemon with the new bridge architecture.
pub async fn run(config: DaemonConfig) -> Result<()> {
    info!("Starting Ghidra daemon");
    info!("Project: {}", config.project_path.display());

    // Get data directory
    let data_dir = get_data_dir().context("Failed to get data directory")?;

    // Create shutdown channel
    let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

    // Initialize shared daemon state - bridge starts as None, lazy-started on first command
    let daemon_state = Arc::new(DaemonState {
        bridge: Arc::new(Mutex::new(None)),
        ghidra_install_dir: config.ghidra_install_dir.clone(),
        project_path: config.project_path.clone(),
        shutdown_tx: shutdown_tx.clone(),
    });

    info!("Bridge will be started on first import/analyze command");

    // Acquire OS-level lock (atomic liveness check)
    let _lock = acquire_daemon_lock(&data_dir, &config.project_path)
        .context("Failed to acquire daemon lock")?;

    // Write daemon info to separate file
    let daemon_info = DaemonInfo::new(&config.project_path, &config.log_file);
    write_daemon_info(&data_dir, &config.project_path, &daemon_info)
        .context("Failed to write daemon info")?;

    // Start IPC server task
    let ipc_state = daemon_state.clone();
    let ipc_shutdown_tx = shutdown_tx.clone();
    let ipc_project_path = config.project_path.clone();
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) =
            ipc_server::run_ipc_server(ipc_state, ipc_shutdown_tx, &ipc_project_path).await
        {
            error!("IPC server error: {}", e);
        }
    });

    // Wait for shutdown signal
    let shutdown_reason = wait_for_shutdown(shutdown_tx.clone()).await;

    info!("Shutdown initiated: {:?}", shutdown_reason);

    // Clean up
    shutdown_tx.send(()).ok(); // Signal all tasks to stop

    // Stop the bridge if it was started
    {
        let mut bridge_guard = daemon_state.bridge.lock().await;
        if let Some(mut b) = bridge_guard.take() {
            info!("Stopping Ghidra bridge...");
            if let Err(e) = b.stop() {
                error!("Error stopping bridge: {}", e);
            }
        }
    }

    // Wait for IPC server to stop (with timeout)
    tokio::select! {
        _ = ipc_handle => {
            info!("IPC server stopped");
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
            warn!("IPC server did not stop in time");
        }
    }

    // Remove info file; lock file is released when _lock drops at end of scope
    remove_info_file(&data_dir, &config.project_path).ok();

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

        let mut sigint =
            signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

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
            ghidra_install_dir: None,
            log_file: PathBuf::from("/test/logs/daemon.log"),
        };

        assert_eq!(config.project_path, PathBuf::from("/test/project"));
    }
}
