use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bridge/IlSpyBridge.cs");
    println!("cargo:rerun-if-changed=bridge/IlSpyBridge.csproj");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let csproj = manifest_dir.join("bridge").join("IlSpyBridge.csproj");
    let output_dir = manifest_dir.join("target").join("bridge");

    // Build the C# bridge project
    let status = Command::new("dotnet")
        .args([
            "publish",
            csproj.to_str().expect("invalid csproj path"),
            "-c",
            "Release",
            "-o",
            output_dir.to_str().expect("invalid output path"),
        ])
        .status()
        .expect("Failed to run 'dotnet publish'. Is the .NET 8 SDK installed?");

    assert!(
        status.success(),
        "Failed to build C# bridge. Run 'dotnet publish bridge/IlSpyBridge.csproj -c Release' manually to see errors."
    );

    // Also copy the bridge DLL to the binary output directory so tests and
    // debug builds can find it.
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = manifest_dir.join("target").join(&profile).join("bridge");

    if !target_dir.exists() {
        std::fs::create_dir_all(&target_dir).ok();
    }

    // Copy all files from publish output to target/profile/bridge/
    if let Ok(entries) = std::fs::read_dir(&output_dir) {
        for entry in entries.flatten() {
            let src = entry.path();
            let dest = target_dir.join(entry.file_name());
            std::fs::copy(&src, &dest).ok();
        }
    }
}
