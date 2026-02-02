use crate::error::Result;

pub fn doctor() -> Result<String> {
    let mut lines = Vec::new();
    let mut all_ok = true;

    // Check .NET runtime
    let dotnet_ok = check_dotnet_runtime(&mut lines);
    if !dotnet_ok {
        all_ok = false;
    }

    // Check bridge DLL
    let bridge_ok = check_bridge_dll(&mut lines);
    if !bridge_ok {
        all_ok = false;
    }

    // Try loading the bridge
    if bridge_ok {
        check_bridge_load(&mut lines, &mut all_ok);
    }

    lines.push(String::new());
    if all_ok {
        lines.push("All checks passed.".to_string());
    } else {
        lines.push("Some checks failed. See above for details.".to_string());
    }

    Ok(lines.join("\n"))
}

fn check_dotnet_runtime(lines: &mut Vec<String>) -> bool {
    match std::process::Command::new("dotnet").arg("--info").output() {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Extract runtime version
                let version = stdout
                    .lines()
                    .find(|l| l.contains("Host") || l.contains("Version"))
                    .map(|l| l.trim().to_string())
                    .unwrap_or_else(|| "installed".to_string());
                lines.push(format!("[OK] .NET runtime: {version}"));
                true
            } else {
                lines.push("[FAIL] .NET runtime: dotnet command failed".to_string());
                false
            }
        }
        Err(_) => {
            lines.push("[FAIL] .NET runtime: 'dotnet' not found in PATH".to_string());
            lines.push("       Install .NET 8 SDK from https://dot.net/download".to_string());
            false
        }
    }
}

fn check_bridge_dll(lines: &mut Vec<String>) -> bool {
    // Check next to executable
    if let Ok(exe) = std::env::current_exe() {
        let exe_dir = exe.parent().unwrap_or(std::path::Path::new("."));

        for candidate in &[
            exe_dir.join("bridge").join("IlSpyBridge.dll"),
            exe_dir.join("IlSpyBridge.dll"),
        ] {
            if candidate.exists() {
                lines.push(format!("[OK] Bridge DLL: {}", candidate.display()));
                return true;
            }
        }
    }

    // Check ILSPY_BRIDGE_DIR
    if let Ok(dir) = std::env::var("ILSPY_BRIDGE_DIR") {
        let p = std::path::PathBuf::from(&dir).join("IlSpyBridge.dll");
        if p.exists() {
            lines.push(format!("[OK] Bridge DLL: {}", p.display()));
            return true;
        }
    }

    lines.push("[FAIL] Bridge DLL: IlSpyBridge.dll not found".to_string());
    lines.push("       Build with 'cargo build' or set ILSPY_BRIDGE_DIR".to_string());
    false
}

fn check_bridge_load(lines: &mut Vec<String>, all_ok: &mut bool) {
    match crate::bridge::IlSpyBridge::new() {
        Ok(_) => {
            lines.push("[OK] Bridge loads successfully".to_string());
        }
        Err(e) => {
            lines.push(format!("[FAIL] Bridge load: {e}"));
            *all_ok = false;
        }
    }
}
