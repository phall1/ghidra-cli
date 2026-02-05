//! Ghidra Bridge - manages a persistent Ghidra Java bridge process.
//!
//! The bridge runs a GhidraCliBridge.java script via `analyzeHeadless` that
//! starts a TCP socket server. The CLI connects directly to this server
//! to execute commands. No intermediate daemon process is needed.

use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::ipc::client::BridgeClient;

/// How to start the bridge - import a new binary or open an existing program.
pub enum BridgeStartMode {
    /// Import a binary file into the project, then start bridge
    Import { binary_path: String },
    /// Open an existing program in the project
    Process { program_name: String },
}

/// Embedded Java bridge script
const JAVA_BRIDGE_SCRIPT: &str = include_str!("scripts/GhidraCliBridge.java");

/// Get the data directory for bridge port/PID files.
pub fn get_data_dir() -> Result<PathBuf> {
    let dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?
        .join("ghidra-cli");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Compute MD5 hash of project path for file naming.
fn project_hash(project_path: &Path) -> String {
    format!(
        "{:x}",
        md5::compute(project_path.to_string_lossy().as_bytes())
    )
}

/// Get the port file path for a project.
pub fn port_file_path(project_path: &Path) -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path);
    Ok(data_dir.join(format!("bridge-{}.port", hash)))
}

/// Get the PID file path for a project.
pub fn pid_file_path(project_path: &Path) -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path);
    Ok(data_dir.join(format!("bridge-{}.pid", hash)))
}

/// Read the port from the port file.
pub fn read_port_file(project_path: &Path) -> Result<Option<u16>> {
    let path = port_file_path(project_path)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let port: u16 = content
        .trim()
        .parse()
        .context("Invalid port in port file")?;
    Ok(Some(port))
}

/// Read the PID from the PID file.
pub fn read_pid_file(project_path: &Path) -> Result<Option<u32>> {
    let path = pid_file_path(project_path)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let pid: u32 = content.trim().parse().context("Invalid PID in PID file")?;
    Ok(Some(pid))
}

/// Check if a process with the given PID is alive.
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

/// Clean up stale port and PID files.
pub fn cleanup_stale_files(project_path: &Path) -> Result<()> {
    let port_path = port_file_path(project_path)?;
    let pid_path = pid_file_path(project_path)?;
    if port_path.exists() {
        std::fs::remove_file(&port_path).ok();
    }
    if pid_path.exists() {
        std::fs::remove_file(&pid_path).ok();
    }
    Ok(())
}

/// Check if a bridge is running for the given project.
///
/// Verifies: port file exists, PID is alive, TCP connect succeeds.
/// Returns `Some(port)` if running, `None` otherwise. Callers use the returned port
/// directly, avoiding a separate read_port_file call (TOCTOU elimination).
pub fn is_bridge_running(project_path: &Path) -> Option<u16> {
    let port = match read_port_file(project_path) {
        Ok(Some(p)) => p,
        _ => return None,
    };

    let pid = match read_pid_file(project_path) {
        Ok(Some(p)) => p,
        _ => return None,
    };

    if !is_pid_alive(pid) {
        return None;
    }

    // Verify TCP connect
    TcpStream::connect(format!("127.0.0.1:{}", port))
        .map(|_| Some(port))
        .unwrap_or(None)
}

/// Ensure a bridge is running for the given project.
/// Returns the port number to connect to.
pub fn ensure_bridge_running(
    project_path: &Path,
    ghidra_install_dir: &Path,
    mode: BridgeStartMode,
) -> Result<u16> {
    // Check if already running
    if let Ok(Some(port)) = read_port_file(project_path) {
        if let Ok(Some(pid)) = read_pid_file(project_path) {
            if is_pid_alive(pid) {
                // Verify TCP connect
                if TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
                    info!("Bridge already running on port {}", port);
                    return Ok(port);
                }
            }
        }
        // Stale files - clean up
        cleanup_stale_files(project_path)?;
    }

    // Start a new bridge
    start_bridge(project_path, ghidra_install_dir, mode)
}

/// Start a new bridge process.
/// Returns the port number once the bridge is ready.
pub fn start_bridge(
    project_path: &Path,
    ghidra_install_dir: &Path,
    mode: BridgeStartMode,
) -> Result<u16> {
    info!("Starting Ghidra bridge...");

    // Write the Java bridge script to disk
    let scripts_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
        .join("ghidra-cli")
        .join("scripts");
    std::fs::create_dir_all(&scripts_dir)?;
    let java_script_path = scripts_dir.join("GhidraCliBridge.java");
    std::fs::write(&java_script_path, JAVA_BRIDGE_SCRIPT)?;

    // Find analyzeHeadless
    let headless_script = find_headless_script(ghidra_install_dir)?;

    // Compute port file path
    let port_file = port_file_path(project_path)?;

    // Build command
    let mut cmd = Command::new(&headless_script);

    // analyzeHeadless expects: <parent_directory> <project_name>
    let ghidra_project_dir = project_path.parent().unwrap_or(project_path);
    let ghidra_project_name = project_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    cmd.arg(ghidra_project_dir).arg(&ghidra_project_name);

    // Add mode-specific args
    match &mode {
        BridgeStartMode::Import { binary_path } => {
            cmd.arg("-import").arg(binary_path);
        }
        BridgeStartMode::Process { program_name } => {
            cmd.arg("-process").arg(program_name).arg("-noanalysis");
        }
    }

    // Add Java bridge script args
    cmd.arg("-scriptPath")
        .arg(scripts_dir.to_str().unwrap())
        .arg("-postScript")
        .arg("GhidraCliBridge.java")
        .arg(port_file.to_str().unwrap());

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    info!("Ghidra command: {:?}", cmd);

    // Spawn the process
    let mut child = cmd.spawn().context("Failed to spawn Ghidra headless")?;
    info!("Ghidra process started with PID: {:?}", child.id());

    // Write PID file immediately so orphan cleanup is possible if Java crashes
    // before the ready signal (Java overwrites this once it binds the ServerSocket)
    write_pid_file(project_path, child.id()).ok();

    // Spawn a thread to capture stderr
    let stderr = child.stderr.take().expect("stderr should be piped");
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut stderr_output = Vec::new();
        for line in reader.lines().map_while(Result::ok) {
            info!("[Ghidra stderr] {}", line);
            stderr_output.push(line);
        }
        stderr_output
    });

    // Wait for ready signal from stdout
    let stdout = child.stdout.take().expect("stdout should be piped");
    let reader = BufReader::new(stdout);

    let mut ready = false;
    let mut last_error = String::new();
    let mut stdout_lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        info!("[Ghidra stdout] {}", line);
        stdout_lines.push(line.clone());

        if line.contains("ERROR") || line.contains("Exception") || line.contains("SEVERE") {
            last_error = line.clone();
        }

        if line.contains("---GHIDRA_CLI_START---") {
            continue;
        }
        if line.contains("\"status\"") && line.contains("\"ready\"") {
            info!("Bridge is ready");
            ready = true;
            break;
        }
        if line.contains("---GHIDRA_CLI_END---") && ready {
            break;
        }
    }

    if !ready {
        // Prevent orphaned JVM process: if child is still running but didn't
        // send the ready signal, kill it and clean up stale files
        if let Ok(None) = child.try_wait() {
            let _ = child.kill();
            let _ = child.wait();
        }
        cleanup_stale_files(project_path).ok();

        let stderr_output = stderr_handle.join().unwrap_or_default();
        let detail = if !last_error.is_empty() {
            format!(": {}", last_error)
        } else if !stderr_output.is_empty() {
            let last_stderr: Vec<_> = stderr_output.iter().rev().take(5).rev().cloned().collect();
            format!(": stderr: {}", last_stderr.join("\n"))
        } else {
            let last_stdout: Vec<_> = stdout_lines.iter().rev().take(10).rev().cloned().collect();
            format!("\nLast stdout:\n{}", last_stdout.join("\n"))
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                anyhow::bail!("Ghidra process exited with status: {}{}", status, detail);
            }
            Ok(None) => {
                anyhow::bail!("Ghidra bridge did not send ready signal{}", detail);
            }
            Err(e) => {
                anyhow::bail!("Error checking process status: {}", e);
            }
        }
    }

    // Read port from port file
    let port = read_port_file(project_path)?
        .ok_or_else(|| anyhow::anyhow!("Port file not created by bridge"))?;

    info!("Ghidra bridge started on port {}", port);
    Ok(port)
}

/// Stop the bridge for a project.
pub fn stop_bridge(project_path: &Path) -> Result<()> {
    // Try graceful shutdown via TCP using BridgeClient
    if let Ok(Some(port)) = read_port_file(project_path) {
        let client = BridgeClient::new(port);
        if let Ok(()) = client.shutdown() {
            debug!("Graceful shutdown sent");
        }
    }

    // If PID file exists, kill the process as fallback
    if let Ok(Some(pid)) = read_pid_file(project_path) {
        if is_pid_alive(pid) {
            warn!("Killing bridge process {} as fallback", pid);
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .output();
            }
        }
    }

    // Clean up files
    cleanup_stale_files(project_path)?;

    info!("Bridge stopped");
    Ok(())
}

/// Get bridge status for a project.
pub fn bridge_status(project_path: &Path) -> Result<BridgeStatus> {
    let port = read_port_file(project_path)?;
    let pid = read_pid_file(project_path)?;

    if let (Some(port), Some(pid)) = (port, pid) {
        if is_pid_alive(pid) {
            let client = BridgeClient::new(port);
            if client.ping().unwrap_or(false) {
                return Ok(BridgeStatus::Running { port, pid });
            }
        }
        // Stale files
        cleanup_stale_files(project_path).ok();
    }

    Ok(BridgeStatus::Stopped)
}

/// Write PID to the PID file for a project.
/// Enables orphan cleanup when Java crashes before writing its own PID file.
/// Java overwrites this value once it binds the ServerSocket.
fn write_pid_file(project_path: &Path, pid: u32) -> Result<()> {
    let path = pid_file_path(project_path)?;
    std::fs::write(&path, pid.to_string())?;
    debug!("Wrote PID {} to {}", pid, path.display());
    Ok(())
}

/// Bridge status
#[derive(Debug)]
pub enum BridgeStatus {
    Running { port: u16, pid: u32 },
    Stopped,
}

/// Find the analyzeHeadless script.
fn find_headless_script(ghidra_install_dir: &Path) -> Result<PathBuf> {
    let support_dir = ghidra_install_dir.join("support");

    #[cfg(unix)]
    let script_name = "analyzeHeadless";
    #[cfg(windows)]
    let script_name = "analyzeHeadless.bat";

    let script_path = support_dir.join(script_name);

    if script_path.exists() {
        Ok(script_path)
    } else {
        anyhow::bail!("analyzeHeadless not found at: {}", support_dir.display())
    }
}

/// Convenience wrapper for wait_timeout on Child
trait ChildExt {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl ChildExt for Child {
    fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        use std::thread;
        use std::time::Instant;

        let start = Instant::now();
        loop {
            match self.try_wait()? {
                Some(status) => return Ok(Some(status)),
                None => {
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}
