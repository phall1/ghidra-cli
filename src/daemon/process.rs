//! Process management for the daemon.
//!
//! Handles lock files and daemon process information using OS-level file locking
//! via `fslock` for atomic daemon liveness detection.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use fslock::LockFile;
use serde::{Deserialize, Serialize};

/// Daemon information stored in the info file.
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

    fs::create_dir_all(&data_dir).context("Failed to create data directory")?;

    Ok(data_dir)
}

/// Get the lock file path for a project (used for OS-level locking only).
fn get_lock_file_path(data_dir: &Path, project_path: &Path) -> PathBuf {
    let project_hash = format!(
        "{:x}",
        md5::compute(project_path.to_string_lossy().as_bytes())
    );
    data_dir.join(format!("daemon-{}.lock", project_hash))
}

/// Get the info file path for a project (stores DaemonInfo JSON).
fn get_info_file_path(data_dir: &Path, project_path: &Path) -> PathBuf {
    let project_hash = format!(
        "{:x}",
        md5::compute(project_path.to_string_lossy().as_bytes())
    );
    data_dir.join(format!("daemon-{}.info", project_hash))
}

/// Acquire an exclusive OS-level lock for the daemon.
///
/// Returns the held `LockFile` — the caller must keep it alive for the daemon's
/// entire lifetime. The lock is automatically released when the `LockFile` is dropped
/// (including on crash).
pub fn acquire_daemon_lock(
    data_dir: &Path,
    project_path: &Path,
) -> Result<LockFile> {
    let lock_path = get_lock_file_path(data_dir, project_path);
    let mut lock = LockFile::open(&lock_path)
        .context("Failed to open lock file")?;

    if !lock.try_lock_with_pid()
        .context("Failed to acquire lock")? {
        bail!("Daemon is already running for this project");
    }

    Ok(lock)
}

/// Write daemon info to the info file (separate from the lock file).
pub fn write_daemon_info(data_dir: &Path, project_path: &Path, info: &DaemonInfo) -> Result<()> {
    let info_path = get_info_file_path(data_dir, project_path);
    let json = serde_json::to_string_pretty(info).context("Failed to serialize daemon info")?;

    let mut file = fs::File::create(&info_path).context("Failed to create info file")?;
    file.write_all(json.as_bytes())
        .context("Failed to write info file")?;

    Ok(())
}

/// Remove the info file for a project.
///
/// The `.lock` file is released automatically when the daemon's `LockFile` handle drops.
/// Stale `.lock` files are harmless (empty, unlocked) and cleaned up by `get_running_daemon_info()`.
pub fn remove_info_file(data_dir: &Path, project_path: &Path) -> Result<()> {
    let info_path = get_info_file_path(data_dir, project_path);

    if info_path.exists() {
        fs::remove_file(&info_path).context("Failed to remove info file")?;
    }

    Ok(())
}

/// Get daemon info if running, or clean up stale files.
///
/// Uses OS-level locking for atomic liveness detection:
/// - If we can acquire the lock, no daemon holds it — clean up stale files.
/// - If we cannot acquire the lock, a daemon is alive — read the info file.
pub fn get_running_daemon_info(data_dir: &Path, project_path: &Path) -> Result<Option<DaemonInfo>> {
    let lock_path = get_lock_file_path(data_dir, project_path);
    if !lock_path.exists() {
        return Ok(None);
    }

    let mut lock = LockFile::open(&lock_path)
        .context("Failed to open lock file for status check")?;

    if lock.try_lock().context("Failed to check lock")? {
        // We got the lock — no daemon is holding it. Clean up stale files.
        lock.unlock().context("Failed to release lock")?;
        fs::remove_file(&lock_path).ok();
        let info_path = get_info_file_path(data_dir, project_path);
        fs::remove_file(&info_path).ok();
        // Also clean up stale socket file (daemon may have crashed without cleanup)
        crate::ipc::transport::remove_socket_for_project(project_path).ok();
        return Ok(None);
    }

    // Lock is held by another process — daemon is running. Read the info file.
    let info_path = get_info_file_path(data_dir, project_path);
    let contents = fs::read_to_string(&info_path)
        .context("Lock is held but info file is missing")?;
    let info: DaemonInfo = serde_json::from_str(&contents)
        .context("Failed to parse daemon info file")?;
    Ok(Some(info))
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
    fn test_lock_and_info_file_operations() -> Result<()> {
        let temp_dir = tempdir()?;
        let data_dir = temp_dir.path();
        let project_path = PathBuf::from("/test/project");

        // Acquire lock
        let _lock = acquire_daemon_lock(data_dir, &project_path)?;

        // Write info
        let info = DaemonInfo::new(&project_path, Path::new("/test/logs/daemon.log"));
        write_daemon_info(data_dir, &project_path, &info)?;

        // Info file should exist
        let info_path = get_info_file_path(data_dir, &project_path);
        assert!(info_path.exists());

        // Remove info file
        remove_info_file(data_dir, &project_path)?;
        assert!(!info_path.exists());

        Ok(())
    }

    #[test]
    fn test_cannot_acquire_lock_twice() -> Result<()> {
        let temp_dir = tempdir()?;
        let data_dir = temp_dir.path();
        let project_path = PathBuf::from("/test/project");

        // First lock succeeds
        let _lock = acquire_daemon_lock(data_dir, &project_path)?;

        // Second lock should fail
        let result = acquire_daemon_lock(data_dir, &project_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already running"));

        Ok(())
    }

    #[test]
    fn test_stale_lock_cleaned_up() -> Result<()> {
        let temp_dir = tempdir()?;
        let data_dir = temp_dir.path();
        let project_path = PathBuf::from("/test/project");

        // Create a lock file but don't hold the lock (simulates crashed daemon)
        let lock_path = get_lock_file_path(data_dir, &project_path);
        fs::File::create(&lock_path)?;

        // Also create a stale info file
        let info_path = get_info_file_path(data_dir, &project_path);
        let info = DaemonInfo::new(&project_path, Path::new("/test/logs/daemon.log"));
        let json = serde_json::to_string_pretty(&info)?;
        fs::write(&info_path, json)?;

        // get_running_daemon_info should detect no lock holder and clean up
        let result = get_running_daemon_info(data_dir, &project_path)?;
        assert!(result.is_none());

        // Stale files should be cleaned up
        assert!(!lock_path.exists());
        assert!(!info_path.exists());

        Ok(())
    }
}
