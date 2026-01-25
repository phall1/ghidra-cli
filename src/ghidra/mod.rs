#![allow(dead_code)]

pub mod bridge;
pub mod headless;
pub mod data;
pub mod scripts;
pub mod setup;

use std::path::{Path, PathBuf};
use std::process::Command;
use crate::config::Config;
use crate::error::{GhidraError, Result};

#[derive(Debug)]
pub struct GhidraClient {
    config: Config,
    install_dir: PathBuf,
    project_dir: PathBuf,
}

impl GhidraClient {
    pub fn new(config: Config) -> Result<Self> {
        let install_dir = config.get_ghidra_install_dir()?;
        let project_dir = config.get_project_dir()?;

        // Create project directory if it doesn't exist
        if !project_dir.exists() {
            std::fs::create_dir_all(&project_dir)?;
        }

        Ok(Self {
            config,
            install_dir,
            project_dir,
        })
    }

    pub fn install_dir(&self) -> &PathBuf {
        &self.install_dir
    }

    pub fn get_headless_script(&self) -> PathBuf {
        let support_dir = self.install_dir.join("support");

        #[cfg(target_os = "windows")]
        {
            // Use analyzeHeadless with Jython support
            support_dir.join("analyzeHeadless.bat")
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Use analyzeHeadless with Jython support
            support_dir.join("analyzeHeadless")
        }
    }

    pub fn verify_installation(&self) -> Result<()> {
        let headless = self.get_headless_script();

        if !headless.exists() {
            return Err(GhidraError::GhidraNotFound);
        }

        Ok(())
    }

    pub fn get_project_path(&self, project_name: &str) -> PathBuf {
        self.project_dir.join(project_name)
    }

    pub fn project_exists(&self, project_name: &str) -> bool {
        let project_path = self.get_project_path(project_name);
        project_path.exists() && project_path.join(format!("{}.rep", project_name)).exists()
    }

    pub fn create_project(&self, project_name: &str) -> Result<()> {
        let project_path = self.get_project_path(project_name);

        if self.project_exists(project_name) {
            return Ok(());
        }

        // Ghidra creates the project automatically when you import or process a file
        // Just create the directory structure
        std::fs::create_dir_all(&project_path)?;

        Ok(())
    }

    pub fn import_binary(&self, project_name: &str, binary_path: &Path, program_name: Option<&str>) -> Result<String> {
        if !self.project_exists(project_name) {
            self.create_project(project_name)?;
        }

        let program_name = program_name.unwrap_or_else(|| {
            binary_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("program")
        });

        let project_path = self.get_project_path(project_name);
        let headless = self.get_headless_script();

        let output = Command::new(&headless)
            .arg(project_path.to_str().unwrap())
            .arg(project_name)
            .arg("-import")
            .arg(binary_path.to_str().unwrap())
            .arg("-overwrite")
            .output()?;

        if !output.status.success() {
            return Err(GhidraError::ExecutionFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        Ok(program_name.to_string())
    }

    pub fn analyze_program(&self, project_name: &str, program_name: &str) -> Result<()> {
        let project_path = self.get_project_path(project_name);
        let headless = self.get_headless_script();

        let output = Command::new(&headless)
            .arg(project_path.to_str().unwrap())
            .arg(project_name)
            .arg("-process")
            .arg(program_name)
            .output()?;

        if !output.status.success() {
            return Err(GhidraError::ExecutionFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        Ok(())
    }

    pub fn run_script(&self, project_name: &str, program_name: &str, script_path: &Path, args: &[String]) -> Result<String> {
        let project_path = self.get_project_path(project_name);
        let headless = self.get_headless_script();

        let mut cmd = Command::new(&headless);
        cmd.arg(project_path.to_str().unwrap())
            .arg(project_name)
            .arg("-process")
            .arg(program_name)
            .arg("-scriptPath")
            .arg(script_path.parent().unwrap().to_str().unwrap())
            .arg("-postScript")
            .arg(script_path.file_name().unwrap().to_str().unwrap());

        for arg in args {
            cmd.arg(arg);
        }

        let output = cmd.output()?;

        if !output.status.success() {
            return Err(GhidraError::ExecutionFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn get_scripts_dir(&self) -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| GhidraError::ConfigError("Could not determine config directory".to_string()))?;

        let scripts_dir = config_dir.join("ghidra-cli").join("scripts");

        if !scripts_dir.exists() {
            std::fs::create_dir_all(&scripts_dir)?;
        }

        Ok(scripts_dir)
    }

    pub fn get_install_dir(&self) -> &Path {
        &self.install_dir
    }

    pub fn get_project_dir(&self) -> &Path {
        &self.project_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_client_creation() {
        // This will fail if GHIDRA_INSTALL_DIR is not set, which is expected
        let config = Config::default();
        let result = GhidraClient::new(config);

        // We can't test this properly without a Ghidra installation
        // Just verify the error is what we expect
        if result.is_err() {
            assert!(matches!(result.unwrap_err(), GhidraError::GhidraNotFound));
        }
    }
}
