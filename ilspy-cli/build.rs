use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bridge/IlSpyBridge.cs");
    println!("cargo:rerun-if-changed=bridge/IlSpyBridge.csproj");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let csproj = manifest_dir.join("bridge").join("IlSpyBridge.csproj");
    let bridge_out = out_dir.join("bridge");

    // Build the C# bridge project into OUT_DIR/bridge/ so include_bytes! can
    // embed the DLLs into the final binary.
    let status = Command::new("dotnet")
        .args([
            "publish",
            csproj.to_str().expect("invalid csproj path"),
            "-c",
            "Release",
            "-o",
            bridge_out.to_str().expect("invalid output path"),
        ])
        .status()
        .expect("Failed to run 'dotnet publish'. Is the .NET 8 SDK installed?");

    assert!(
        status.success(),
        "Failed to build C# bridge. Run 'dotnet publish bridge/IlSpyBridge.csproj -c Release' manually to see errors."
    );

    // Copy bridge files next to the binary output directory so `cargo run`
    // and tests can find them without extraction.
    // OUT_DIR is like: target/debug/build/ilspy-cli-HASH/out
    // Binary dir is:   target/debug/
    // Navigate: out → HASH → build → {profile}
    let binary_dir = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent());

    if let Some(bin_dir) = binary_dir {
        let target_bridge = bin_dir.join("bridge");
        std::fs::create_dir_all(&target_bridge).ok();
        if let Ok(entries) = std::fs::read_dir(&bridge_out) {
            for entry in entries.flatten() {
                let dest = target_bridge.join(entry.file_name());
                std::fs::copy(entry.path(), &dest).ok();
            }
        }
    }
}
