use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use crate::error::{GhidraError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ghidra_install_dir: Option<PathBuf>,
    pub ghidra_project_dir: Option<PathBuf>,
    pub default_program: Option<String>,
    pub default_project: Option<String>,
    pub default_output_format: Option<String>,
    pub default_limit: Option<usize>,
    pub timeout: Option<u64>,
    pub aliases: std::collections::HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ghidra_install_dir: None,
            ghidra_project_dir: None,
            default_program: None,
            default_project: None,
            default_output_format: Some("auto".to_string()),
            default_limit: Some(1000),
            timeout: Some(300),
            aliases: std::collections::HashMap::new(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&config_path)?;
        let config: Config = serde_yaml::from_str(&content)?;

        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_yaml::to_string(self)?;
        fs::write(config_path, content)?;

        Ok(())
    }

    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| GhidraError::ConfigError("Could not determine config directory".to_string()))?;

        Ok(config_dir.join("ghidra-cli").join("config.yaml"))
    }

    pub fn get_ghidra_install_dir(&self) -> Result<PathBuf> {
        // Check environment variable first
        if let Ok(dir) = std::env::var("GHIDRA_INSTALL_DIR") {
            return Ok(PathBuf::from(dir));
        }

        // Check config
        if let Some(dir) = &self.ghidra_install_dir {
            return Ok(dir.clone());
        }

        // Try to auto-detect on Windows
        #[cfg(target_os = "windows")]
        {
            if let Some(dir) = Self::detect_ghidra_windows() {
                return Ok(dir);
            }
        }

        Err(GhidraError::GhidraNotFound)
    }

    pub fn get_project_dir(&self) -> Result<PathBuf> {
        // Check environment variable first
        if let Ok(dir) = std::env::var("GHIDRA_PROJECT_DIR") {
            return Ok(PathBuf::from(dir));
        }

        // Check config
        if let Some(dir) = &self.ghidra_project_dir {
            return Ok(dir.clone());
        }

        // Default to ~/.ghidra-projects
        let home = dirs::home_dir()
            .ok_or_else(|| GhidraError::ConfigError("Could not determine home directory".to_string()))?;

        Ok(home.join(".ghidra-projects"))
    }

    #[cfg(target_os = "windows")]
    fn detect_ghidra_windows() -> Option<PathBuf> {
        // Check common installation paths
        let common_paths = vec![
            PathBuf::from("C:\\Program Files\\Ghidra"),
            PathBuf::from("C:\\Program Files (x86)\\Ghidra"),
            PathBuf::from("C:\\ghidra"),
        ];

        for path in common_paths {
            if path.exists() {
                // Look for ghidra_* directories
                if let Ok(entries) = fs::read_dir(&path) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if entry_path.is_dir() {
                            let name = entry_path.file_name()?.to_str()?;
                            if name.starts_with("ghidra_") {
                                // Check if analyzeHeadless.bat exists
                                let headless = entry_path.join("support").join("analyzeHeadless.bat");
                                if headless.exists() {
                                    return Some(entry_path);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    pub fn get_timeout(&self) -> u64 {
        std::env::var("GHIDRA_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(self.timeout)
            .unwrap_or(300)
    }

    pub fn get_default_program(&self) -> Option<String> {
        std::env::var("GHIDRA_DEFAULT_PROGRAM")
            .ok()
            .or_else(|| self.default_program.clone())
    }

    pub fn get_default_project(&self) -> Option<String> {
        std::env::var("GHIDRA_DEFAULT_PROJECT")
            .ok()
            .or_else(|| self.default_project.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.timeout, Some(300));
        assert_eq!(config.default_limit, Some(1000));
    }
}
