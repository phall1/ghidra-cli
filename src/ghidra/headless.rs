use std::path::Path;
use std::process::Command;
use serde_json::Value as JsonValue;
use crate::error::{GhidraError, Result};
use super::GhidraClient;
use super::scripts;

pub struct HeadlessExecutor<'a> {
    client: &'a GhidraClient,
}

impl<'a> HeadlessExecutor<'a> {
    pub fn new(client: &'a GhidraClient) -> Self {
        Self { client }
    }

    pub fn execute_script(
        &self,
        project_name: &str,
        program_name: &str,
        script_content: &str,
        script_name: &str,
        args: &[String],
    ) -> Result<JsonValue> {
        // Save script to disk
        let scripts_dir = self.get_scripts_dir()?;
        let script_path = scripts::save_script(script_name, script_content, &scripts_dir)?;

        // Execute script
        let output = self.run_ghidra_script(project_name, program_name, &script_path, args)?;

        // Parse JSON output
        let json: JsonValue = serde_json::from_str(&output)
            .map_err(|e| GhidraError::ExecutionFailed(format!("Failed to parse script output: {}", e)))?;

        Ok(json)
    }

    fn run_ghidra_script(
        &self,
        project_name: &str,
        program_name: &str,
        script_path: &Path,
        args: &[String],
    ) -> Result<String> {
        let project_path = self.client.get_project_path(project_name);
        let headless = self.client.get_headless_script();

        let mut cmd = Command::new(&headless);
        cmd.arg(project_path.to_str().unwrap())
            .arg(project_name)
            .arg("-process")
            .arg(program_name)
            .arg("-noanalysis")
            .arg("-scriptPath")
            .arg(script_path.parent().unwrap().to_str().unwrap())
            .arg("-postScript")
            .arg(script_path.file_name().unwrap().to_str().unwrap());

        for arg in args {
            cmd.arg(arg);
        }

        // Capture output
        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GhidraError::ExecutionFailed(format!("Script execution failed: {}", stderr)));
        }

        // Extract JSON from output (Ghidra adds some logging we need to skip)
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_output = self.extract_json_from_output(&stdout)?;

        Ok(json_output)
    }

    fn extract_json_from_output(&self, output: &str) -> Result<String> {
        // Find the JSON output in the Ghidra output
        // Look for lines starting with { or [
        let lines: Vec<&str> = output.lines().collect();

        let mut json_start = None;
        let mut json_end = None;
        let mut brace_count = 0;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if json_start.is_none() && (trimmed.starts_with('{') || trimmed.starts_with('[')) {
                json_start = Some(i);
                brace_count = trimmed.chars().filter(|&c| c == '{' || c == '[').count() as i32;
                brace_count -= trimmed.chars().filter(|&c| c == '}' || c == ']').count() as i32;

                if brace_count == 0 {
                    json_end = Some(i);
                    break;
                }
            } else if json_start.is_some() {
                brace_count += trimmed.chars().filter(|&c| c == '{' || c == '[').count() as i32;
                brace_count -= trimmed.chars().filter(|&c| c == '}' || c == ']').count() as i32;

                if brace_count == 0 {
                    json_end = Some(i);
                    break;
                }
            }
        }

        if let (Some(start), Some(end)) = (json_start, json_end) {
            let json_lines = &lines[start..=end];
            Ok(json_lines.join("\n"))
        } else {
            Err(GhidraError::ExecutionFailed("Could not find JSON in script output".to_string()))
        }
    }

    fn get_scripts_dir(&self) -> Result<std::path::PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| GhidraError::ConfigError("Could not determine config directory".to_string()))?;

        let scripts_dir = config_dir.join("ghidra-cli").join("scripts");

        if !scripts_dir.exists() {
            std::fs::create_dir_all(&scripts_dir)?;
        }

        Ok(scripts_dir)
    }

    pub fn list_functions(&self, project_name: &str, program_name: &str) -> Result<JsonValue> {
        self.execute_script(
            project_name,
            program_name,
            scripts::get_list_functions_script(),
            "list_functions",
            &[],
        )
    }

    pub fn decompile_function(&self, project_name: &str, program_name: &str, address: &str) -> Result<JsonValue> {
        self.execute_script(
            project_name,
            program_name,
            scripts::get_decompile_function_script(),
            "decompile_function",
            &[address.to_string()],
        )
    }

    pub fn list_strings(&self, project_name: &str, program_name: &str) -> Result<JsonValue> {
        self.execute_script(
            project_name,
            program_name,
            scripts::get_list_strings_script(),
            "list_strings",
            &[],
        )
    }

    pub fn list_imports(&self, project_name: &str, program_name: &str) -> Result<JsonValue> {
        self.execute_script(
            project_name,
            program_name,
            scripts::get_list_imports_script(),
            "list_imports",
            &[],
        )
    }

    pub fn list_exports(&self, project_name: &str, program_name: &str) -> Result<JsonValue> {
        self.execute_script(
            project_name,
            program_name,
            scripts::get_list_exports_script(),
            "list_exports",
            &[],
        )
    }

    pub fn get_memory_map(&self, project_name: &str, program_name: &str) -> Result<JsonValue> {
        self.execute_script(
            project_name,
            program_name,
            scripts::get_memory_map_script(),
            "memory_map",
            &[],
        )
    }

    pub fn get_program_info(&self, project_name: &str, program_name: &str) -> Result<JsonValue> {
        self.execute_script(
            project_name,
            program_name,
            scripts::get_program_info_script(),
            "program_info",
            &[],
        )
    }

    pub fn get_xrefs_to(&self, project_name: &str, program_name: &str, address: &str) -> Result<JsonValue> {
        self.execute_script(
            project_name,
            program_name,
            scripts::get_xrefs_to_script(),
            "xrefs_to",
            &[address.to_string()],
        )
    }
}
