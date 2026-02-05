//! Bridge management module.
//!
//! Manages the lifecycle of the Java GhidraCliBridge process.
//! The "daemon" is just the long-running Ghidra/Java bridge process -
//! there is no separate Rust daemon. The CLI connects directly to
//! the bridge via TCP.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::ghidra::bridge::{self, BridgeStartMode, BridgeStatus};

/// Bridge configuration (replaces old DaemonConfig).
#[allow(dead_code)]
pub struct BridgeConfig {
    /// Path to the Ghidra project directory
    pub project_path: PathBuf,
    /// Ghidra installation directory
    pub ghidra_install_dir: PathBuf,
}

/// Ensure a bridge is running for the given project.
/// If import mode, starts with the binary. If process mode, opens existing program.
/// Returns the port number for connecting.
#[allow(dead_code)]
pub fn ensure_bridge(config: &BridgeConfig, mode: BridgeStartMode) -> Result<u16> {
    bridge::ensure_bridge_running(&config.project_path, &config.ghidra_install_dir, mode)
}

/// Start a new bridge for the given project.
/// Returns the port number for connecting.
#[allow(dead_code)]
pub fn start_bridge(config: &BridgeConfig, mode: BridgeStartMode) -> Result<u16> {
    bridge::start_bridge(&config.project_path, &config.ghidra_install_dir, mode)
}

/// Stop the bridge for a project.
#[allow(dead_code)]
pub fn stop_bridge(project_path: &Path) -> Result<()> {
    bridge::stop_bridge(project_path)
}

/// Get bridge status for a project.
#[allow(dead_code)]
pub fn get_bridge_status(project_path: &Path) -> Result<BridgeStatus> {
    bridge::bridge_status(project_path)
}

/// Check if a bridge is running for a project.
/// Returns `Some(port)` if running, `None` otherwise.
#[allow(dead_code)]
pub fn is_bridge_running(project_path: &Path) -> Option<u16> {
    bridge::is_bridge_running(project_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_config() {
        let config = BridgeConfig {
            project_path: PathBuf::from("/test/project"),
            ghidra_install_dir: PathBuf::from("/opt/ghidra"),
        };

        assert_eq!(config.project_path, PathBuf::from("/test/project"));
        assert_eq!(config.ghidra_install_dir, PathBuf::from("/opt/ghidra"));
    }
}
