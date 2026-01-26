//! Process management for the daemon.
//!
//! Handles PID files, lock files, and daemon process information.

use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sysinfo::{System, Pid, ProcessRefreshKind};

/// Daemon information stored in the lock file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonInfo {
    /// Process ID of the daemon
    pub pid: u32,
    /// Project path being managed
    pub project_path: PathBuf,
    /// Log file path
    pub log_file: PathBuf,
    /// When the daemon was started
    pub started_at: DateTime<Utc>,
}

impl DaemonInfo {
    /// Create new daemon info.
    pub fn new(project_path: &Path, log_file: &Path) -> Self {
        Self {
            pid: std::process::id(),
            project_path: project_path.to_path_buf(),
            log_file: log_file.to_path_buf(),
            started_at: Utc::now(),
        }
    }
}

/// Get the data directory for daemon files.
///
/// Checks GHIDRA_CLI_DATA_DIR env var first (used for testing), then falls back to default.
pub fn get_data_dir() -> Result<PathBuf> {
    let data_dir = if let Ok(path) = std::env::var("GHIDRA_CLI_DATA_DIR") {
        PathBuf::from(path)
    } else {
        dirs::data_local_dir()
            .context("Failed to get local data directory")?
            .join("ghidra-cli")
    };

    fs::create_dir_all(&data_dir)
        .context("Failed to create data directory")?;

    Ok(data_dir)
}

/// Get the lock file path for a project.
fn get_lock_file_path(data_dir: &Path, project_path: &Path) -> PathBuf {
    let project_hash = format!("{:x}", md5::compute(project_path.to_string_lossy().as_bytes()));
    data_dir.join(format!("daemon-{}.lock", project_hash))
}

/// Write daemon info to a lock file.
pub fn write_daemon_info(data_dir: &Path, project_path: &Path, info: &DaemonInfo) -> Result<()> {
    let lock_file = get_lock_file_path(data_dir, project_path);
    let json = serde_json::to_string_pretty(info)
        .context("Failed to serialize daemon info")?;

    let mut file = fs::File::create(&lock_file)
        .context("Failed to create lock file")?;

    file.write_all(json.as_bytes())
        .context("Failed to write lock file")?;

    Ok(())
}

/// Read daemon info from a lock file.
pub fn read_daemon_info(data_dir: &Path, project_path: &Path) -> Result<Option<DaemonInfo>> {
    let lock_file = get_lock_file_path(data_dir, project_path);

    if !lock_file.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&lock_file)
        .context("Failed to read lock file")?;

    let info: DaemonInfo = serde_json::from_str(&contents)
        .context("Failed to parse lock file")?;

    Ok(Some(info))
}

/// Remove the lock file for a project.
pub fn remove_lock_file(data_dir: &Path, project_path: &Path) -> Result<()> {
    let lock_file = get_lock_file_path(data_dir, project_path);

    if lock_file.exists() {
        fs::remove_file(&lock_file)
            .context("Failed to remove lock file")?;
    }

    Ok(())
}

/// Check if a process with the given PID is running.
pub fn is_process_running(pid: u32) -> bool {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    sys.process(Pid::from_u32(pid)).is_some()
}

/// Get daemon info if running, or clean up stale lock file.
pub fn get_running_daemon_info(data_dir: &Path, project_path: &Path) -> Result<Option<DaemonInfo>> {
    if let Some(info) = read_daemon_info(data_dir, project_path)? {
        if is_process_running(info.pid) {
            Ok(Some(info))
        } else {
            // Process is dead, clean up stale lock file
            remove_lock_file(data_dir, project_path)?;
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// Ensure no daemon is currently running for this project.
pub fn ensure_not_running(data_dir: &Path, project_path: &Path) -> Result<()> {
    if let Some(info) = get_running_daemon_info(data_dir, project_path)? {
        bail!("Daemon is already running (PID: {})", info.pid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_daemon_info_creation() {
        let info = DaemonInfo::new(
            Path::new("/test/project"),
            Path::new("/test/logs/daemon.log"),
        );

        assert_eq!(info.project_path, PathBuf::from("/test/project"));
    }

    #[test]
    fn test_lock_file_operations() -> Result<()> {
        let temp_dir = tempdir()?;
        let data_dir = temp_dir.path();
        let project_path = PathBuf::from("/test/project");

        let info = DaemonInfo::new(&project_path, Path::new("/test/logs/daemon.log"));

        // Write
        write_daemon_info(data_dir, &project_path, &info)?;

        // Read
        let read_info = read_daemon_info(data_dir, &project_path)?;
        assert!(read_info.is_some());
        let read_info = read_info.unwrap();
        assert_eq!(read_info.pid, info.pid);

        // Remove
        remove_lock_file(data_dir, &project_path)?;
        let read_info = read_daemon_info(data_dir, &project_path)?;
        assert!(read_info.is_none());

        Ok(())
    }
}
