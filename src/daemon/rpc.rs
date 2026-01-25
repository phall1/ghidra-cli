//! RPC protocol for daemon communication using JSON over TCP.
//!
//! Defines the request/response types and RPC server/client implementations.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{info, error};

use crate::cli::Commands;
use crate::daemon::queue::CommandQueue;

/// RPC request from client to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Execute a CLI command
    Execute(Commands),
    /// Shutdown the daemon
    Shutdown,
    /// Get daemon status
    Status,
    /// Ping the daemon
    Ping,
}

/// RPC response from daemon to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    /// Command executed successfully with output
    Success(String),
    /// Command failed with error
    Error(String),
    /// Daemon status information
    Status(DaemonStatus),
    /// Pong response
    Pong,
}

/// Daemon status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Number of queued commands
    pub queue_depth: usize,
    /// Number of completed commands
    pub completed_commands: usize,
    /// Daemon uptime in seconds
    pub uptime_seconds: u64,
    /// Current project path
    pub project_path: String,
}

/// RPC server implementation.
pub struct DaemonServer {
    queue: Arc<CommandQueue>,
    shutdown_tx: broadcast::Sender<()>,
    started_at: std::time::Instant,
}

impl DaemonServer {
    /// Create a new RPC server.
    pub fn new(queue: Arc<CommandQueue>, shutdown_tx: broadcast::Sender<()>) -> Self {
        Self {
            queue,
            shutdown_tx,
            started_at: std::time::Instant::now(),
        }
    }

    /// Handle a request and return a response.
    async fn handle_request(&self, request: DaemonRequest) -> DaemonResponse {
        match request {
            DaemonRequest::Execute(command) => {
                match self.queue.submit(command).await {
                    Ok(result) => DaemonResponse::Success(result),
                    Err(e) => DaemonResponse::Error(e.to_string()),
                }
            }
            DaemonRequest::Shutdown => {
                info!("Received shutdown request via RPC");
                let _ = self.shutdown_tx.send(());
                DaemonResponse::Success("Daemon shutting down".to_string())
            }
            DaemonRequest::Status => {
                let status = DaemonStatus {
                    queue_depth: 0, // TODO: Get actual queue depth
                    completed_commands: 0, // TODO: Get actual completed count
                    uptime_seconds: self.started_at.elapsed().as_secs(),
                    project_path: self.queue.project_path().to_string_lossy().to_string(),
                };
                DaemonResponse::Status(status)
            }
            DaemonRequest::Ping => {
                DaemonResponse::Pong
            }
        }
    }
}

/// Run the RPC server.
pub async fn run_server(
    queue: Arc<CommandQueue>,
    port: Option<u16>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<u16> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port.unwrap_or(0)));
    let listener = TcpListener::bind(addr).await
        .context("Failed to bind TCP listener")?;

    let actual_port = listener.local_addr()
        .context("Failed to get local address")?
        .port();

    info!("RPC server listening on port {}", actual_port);

    let server = Arc::new(DaemonServer::new(queue, shutdown_tx.clone()));
    let mut shutdown_rx = shutdown_tx.subscribe();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            info!("Accepted connection from {}", addr);
                            let server = server.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, server).await {
                                    error!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("RPC server shutting down");
                    break;
                }
            }
        }
    });

    Ok(actual_port)
}

/// Handle a single client connection using JSON over TCP.
async fn handle_connection(
    stream: TcpStream,
    server: Arc<DaemonServer>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await
            .context("Failed to read from stream")?;

        if n == 0 {
            // Connection closed
            break;
        }

        // Parse request
        let request: DaemonRequest = serde_json::from_str(&line)
            .context("Failed to parse request")?;

        // Handle request
        let response = server.handle_request(request).await;

        // Serialize and send response
        let response_json = serde_json::to_string(&response)
            .context("Failed to serialize response")?;

        writer.write_all(response_json.as_bytes()).await
            .context("Failed to write response")?;
        writer.write_all(b"\n").await
            .context("Failed to write newline")?;
    }

    Ok(())
}

/// RPC client for connecting to the daemon.
pub struct DaemonClient {
    stream: TcpStream,
}

impl DaemonClient {
    /// Connect to the daemon at the given port.
    pub async fn connect(port: u16) -> Result<Self> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr).await
            .context("Failed to connect to daemon")?;

        Ok(Self { stream })
    }

    /// Send a request to the daemon.
    pub async fn request(&mut self, request: DaemonRequest) -> Result<DaemonResponse> {
        // Serialize and send request
        let request_json = serde_json::to_string(&request)
            .context("Failed to serialize request")?;

        self.stream.write_all(request_json.as_bytes()).await
            .context("Failed to write request")?;
        self.stream.write_all(b"\n").await
            .context("Failed to write newline")?;

        // Read response
        let (reader, _) = self.stream.split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await
            .context("Failed to read response")?;

        // Parse response
        let response: DaemonResponse = serde_json::from_str(&line)
            .context("Failed to parse response")?;

        Ok(response)
    }

    /// Execute a command on the daemon.
    pub async fn execute(&mut self, command: Commands) -> Result<String> {
        match self.request(DaemonRequest::Execute(command)).await? {
            DaemonResponse::Success(output) => Ok(output),
            DaemonResponse::Error(e) => Err(anyhow::anyhow!(e)),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }

    /// Get daemon status.
    pub async fn status(&mut self) -> Result<DaemonStatus> {
        match self.request(DaemonRequest::Status).await? {
            DaemonResponse::Status(status) => Ok(status),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }

    /// Shutdown the daemon.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.request(DaemonRequest::Shutdown).await?;
        Ok(())
    }

    /// Ping the daemon.
    pub async fn ping(&mut self) -> Result<()> {
        match self.request(DaemonRequest::Ping).await? {
            DaemonResponse::Pong => Ok(()),
            _ => Err(anyhow::anyhow!("Unexpected response")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = DaemonRequest::Ping;
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: DaemonRequest = serde_json::from_str(&json).unwrap();
        matches!(deserialized, DaemonRequest::Ping);
    }
}
