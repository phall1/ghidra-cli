//! Daemon state management.
//!
//! Manages the state of loaded Ghidra projects and maintains metadata.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tracing::info;

use crate::config::Config;
use crate::ghidra::GhidraClient;

/// Daemon state.
pub struct DaemonState {
    /// The Ghidra client
    client: Arc<RwLock<GhidraClient>>,
    /// Project path being managed
    project_path: PathBuf,
}

impl DaemonState {
    /// Load daemon state for a project.
    pub fn load(project_path: &Path, ghidra_install_dir: Option<&Path>) -> Result<Self> {
        info!("Loading daemon state for project: {}", project_path.display());

        // Load config
        let mut config = Config::load()
            .context("Failed to load config")?;

        // Override ghidra install dir if provided
        if let Some(dir) = ghidra_install_dir {
            config.ghidra_install_dir = Some(dir.to_path_buf());
        }

        // Create Ghidra client
        let client = GhidraClient::new(config)
            .context("Failed to create Ghidra client")?;

        // Verify the client installation is valid
        client.verify_installation()
            .context("Invalid Ghidra installation")?;

        info!("Daemon state loaded successfully");

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            project_path: project_path.to_path_buf(),
        })
    }

    /// Get a read lock on the Ghidra client.
    pub async fn client(&self) -> tokio::sync::RwLockReadGuard<'_, GhidraClient> {
        self.client.read().await
    }

    /// Get a write lock on the Ghidra client.
    pub async fn client_mut(&self) -> tokio::sync::RwLockWriteGuard<'_, GhidraClient> {
        self.client.write().await
    }

    /// Get the project path.
    pub fn project_path(&self) -> &Path {
        &self.project_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_creation() {
        // Note: This test would need a real Ghidra project to work
        // In a real test environment, you'd set up a test project first
    }
}
