//! Ghidra Bridge - manages a persistent Ghidra process.
//!
//! Instead of spawning a new `analyzeHeadless` process for each command,
//! the bridge maintains a single long-running Ghidra process that serves
//! commands via a TCP socket.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

/// Default bridge port
const DEFAULT_BRIDGE_PORT: u16 = 18700;

/// Response from the bridge
#[derive(Debug, Deserialize)]
pub struct BridgeResponse<T> {
    pub status: String,
    pub data: Option<T>,
    #[serde(default)]
    pub message: Option<String>,
}

/// Request to the bridge
#[derive(Debug, Serialize)]
struct BridgeRequest {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<serde_json::Value>,
}

/// Manages a persistent Ghidra bridge process.
pub struct GhidraBridge {
    /// Child process handle
    child: Option<Child>,
    /// TCP connection to the bridge
    stream: Option<TcpStream>,
    /// Bridge port
    port: u16,
    /// Project name
    project_name: String,
    /// Program name
    program_name: String,
    /// Path to Ghidra installation
    ghidra_install_dir: PathBuf,
    /// Project directory
    project_dir: PathBuf,
    /// Whether the bridge is running
    running: Arc<AtomicBool>,
}

impl GhidraBridge {
    /// Create a new bridge (not started yet).
    pub fn new(
        ghidra_install_dir: PathBuf,
        project_dir: PathBuf,
        project_name: String,
        program_name: String,
    ) -> Self {
        Self {
            child: None,
            stream: None,
            port: DEFAULT_BRIDGE_PORT,
            project_name,
            program_name,
            ghidra_install_dir,
            project_dir,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the bridge.
    pub fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Starting Ghidra bridge...");

        // Find headless script (pyghidraRun or analyzeHeadless)
        let headless_script = self.find_headless_script()?;
        let is_pyghidra = headless_script
            .file_name()
            .map(|n| n.to_string_lossy().contains("pyghidra"))
            .unwrap_or(false);

        // Get bridge script path
        let bridge_script = self.get_bridge_script_path()?;

        // Build command - pyghidraRun needs different arguments
        let mut cmd = Command::new(&headless_script);

        if is_pyghidra {
            // pyghidraRun --headless passes remaining args to AnalyzeHeadless
            // The install_dir is auto-detected by pyghidraRun from its script location
            cmd.arg("--headless")
                .arg(&self.project_dir)
                .arg(&self.project_name)
                .arg("-process")
                .arg(&self.program_name)
                .arg("-noanalysis")
                .arg("-scriptPath")
                .arg(bridge_script.parent().unwrap())
                .arg("-postScript")
                .arg("bridge.py")
                .arg(self.port.to_string());
        } else {
            // analyzeHeadless format: analyzeHeadless <project_dir> <project_name> -process ...
            cmd.arg(&self.project_dir)
                .arg(&self.project_name)
                .arg("-process")
                .arg(&self.program_name)
                .arg("-noanalysis")
                .arg("-scriptPath")
                .arg(bridge_script.parent().unwrap())
                .arg("-postScript")
                .arg("bridge.py")
                .arg(self.port.to_string());
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Spawn the process
        let mut child = cmd.spawn().context("Failed to spawn Ghidra headless")?;

        // Wait for ready signal
        let stdout = child.stdout.take().expect("stdout should be piped");
        let reader = BufReader::new(stdout);

        let mut ready = false;
        for line in reader.lines() {
            let line = line?;
            debug!("Ghidra: {}", line);

            // Look for ready signal
            if line.contains("---GHIDRA_CLI_START---") {
                // Read the next line for the JSON ready message
                continue;
            }
            if line.contains("\"status\": \"ready\"") || line.contains("\"status\":\"ready\"") {
                info!("Bridge is ready on port {}", self.port);
                ready = true;
                break;
            }
            if line.contains("---GHIDRA_CLI_END---") && ready {
                break;
            }
        }

        if !ready {
            // Check if process died
            match child.try_wait() {
                Ok(Some(status)) => {
                    anyhow::bail!("Ghidra process exited with status: {}", status);
                }
                Ok(None) => {
                    anyhow::bail!("Ghidra bridge did not send ready signal");
                }
                Err(e) => {
                    anyhow::bail!("Error checking process status: {}", e);
                }
            }
        }

        // Connect to the bridge
        let stream = TcpStream::connect(format!("127.0.0.1:{}", self.port))
            .context("Failed to connect to bridge")?;
        stream.set_read_timeout(Some(Duration::from_secs(300))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

        self.child = Some(child);
        self.stream = Some(stream);
        self.running.store(true, Ordering::SeqCst);

        info!("Ghidra bridge started successfully");
        Ok(())
    }

    /// Send a command to the bridge.
    pub fn send_command<T: for<'de> Deserialize<'de>>(
        &mut self,
        command: &str,
        args: Option<serde_json::Value>,
    ) -> Result<BridgeResponse<T>> {
        if !self.running.load(Ordering::SeqCst) {
            anyhow::bail!("Bridge not running");
        }

        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No connection to bridge"))?;

        let request = BridgeRequest {
            command: command.to_string(),
            args,
        };

        let request_json = serde_json::to_string(&request)?;
        debug!("Sending: {}", request_json);

        // Send request
        writeln!(stream, "{}", request_json)?;
        stream.flush()?;

        // Read response
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        debug!("Received: {}", response_line.trim());

        let response: BridgeResponse<T> = serde_json::from_str(&response_line)?;
        Ok(response)
    }

    /// Stop the bridge.
    pub fn stop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping Ghidra bridge...");

        // Send shutdown command
        if let Ok(response) = self.send_command::<serde_json::Value>("shutdown", None) {
            debug!("Shutdown response: {:?}", response);
        }

        // Close stream
        self.stream.take();

        // Wait for child to exit
        if let Some(mut child) = self.child.take() {
            match child.wait_timeout(Duration::from_secs(10)) {
                Ok(Some(status)) => {
                    info!("Ghidra process exited with status: {}", status);
                }
                Ok(None) => {
                    warn!("Ghidra process did not exit, killing...");
                    child.kill().ok();
                }
                Err(e) => {
                    error!("Error waiting for process: {}", e);
                    child.kill().ok();
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        info!("Bridge stopped");
        Ok(())
    }

    /// Check if the bridge is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get the embedded bridge script path, writing all scripts to disk.
    fn get_bridge_script_path(&self) -> Result<PathBuf> {
        let scripts_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
            .join("ghidra-cli")
            .join("scripts");

        std::fs::create_dir_all(&scripts_dir)?;

        // Write all embedded Python scripts
        // Bridge and its module dependencies
        let scripts: &[(&str, &str)] = &[
            ("bridge.py", include_str!("scripts/bridge.py")),
            ("comments.py", include_str!("scripts/comments.py")),
            ("symbols.py", include_str!("scripts/symbols.py")),
            ("types.py", include_str!("scripts/types.py")),
            ("graph.py", include_str!("scripts/graph.py")),
            ("find.py", include_str!("scripts/find.py")),
            ("diff.py", include_str!("scripts/diff.py")),
            ("patch.py", include_str!("scripts/patch.py")),
            ("disasm.py", include_str!("scripts/disasm.py")),
            ("stats.py", include_str!("scripts/stats.py")),
            ("program.py", include_str!("scripts/program.py")),
            ("script_runner.py", include_str!("scripts/script_runner.py")),
            ("batch.py", include_str!("scripts/batch.py")),
        ];

        for (name, content) in scripts {
            std::fs::write(scripts_dir.join(name), content)?;
        }

        Ok(scripts_dir.join("bridge.py"))
    }

    /// Find the analyzeHeadless script.
    fn find_headless_script(&self) -> Result<PathBuf> {
        // First try pyghidraRun for Ghidra 12+ (required for Python support)
        #[cfg(unix)]
        let pyghidra_name = "pyghidraRun";
        #[cfg(windows)]
        let pyghidra_name = "pyghidraRun.bat";

        let support_dir = self.ghidra_install_dir.join("support");
        let pyghidra_path = support_dir.join(pyghidra_name);

        if pyghidra_path.exists() {
            return Ok(pyghidra_path);
        }

        // Fall back to analyzeHeadless for older versions
        #[cfg(unix)]
        let script_name = "analyzeHeadless";
        #[cfg(windows)]
        let script_name = "analyzeHeadless.bat";

        let script_path = support_dir.join(script_name);

        if script_path.exists() {
            Ok(script_path)
        } else {
            anyhow::bail!(
                "Neither pyghidraRun nor analyzeHeadless found at: {}",
                support_dir.display()
            )
        }
    }
}

impl Drop for GhidraBridge {
    fn drop(&mut self) {
        if let Err(e) = self.stop() {
            error!("Error stopping bridge on drop: {}", e);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_request_serialization() {
        let req = BridgeRequest {
            command: "list_functions".to_string(),
            args: Some(serde_json::json!({"limit": 100})),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("list_functions"));
        assert!(json.contains("100"));
    }

    #[test]
    fn test_bridge_response_deserialization() {
        let json = r#"{"status": "success", "data": {"count": 42}}"#;
        let resp: BridgeResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "success");
        assert!(resp.data.is_some());
    }
}
