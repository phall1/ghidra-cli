
Here is the implementation plan to add a `ghidra setup` command that automates the downloading and installation of Ghidra.

### 1. Update Dependencies

First, we need to add crates for HTTP requests, file downloading, zip extraction, and progress bars.

**Action:** Update `Cargo.toml`

```toml
[dependencies]
# ... existing dependencies ...
reqwest = { version = "0.11", features = ["json", "stream", "rustls-tls"] }
zip = "0.6"
futures-util = "0.3" # For handling download streams
indicatif = "0.17"   # For progress bars

```

### 2. Update CLI Definition

Add the `setup` command to the argument parser.

**Action:** Modify `src/cli.rs`

```rust
// In enum Commands
#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum Commands {
    // ... existing commands ...
    
    /// Download and setup Ghidra automatically
    Setup(SetupArgs),
}

// Define arguments
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetupArgs {
    /// Specific Ghidra version to install (e.g., "11.0"). Defaults to latest.
    #[arg(long)]
    pub version: Option<String>,

    /// Installation directory. Defaults to standard data directory.
    #[arg(long, short = 'd')]
    pub dir: Option<String>,

    /// Skip Java check
    #[arg(long)]
    pub force: bool,
}

```

### 3. Create Setup Module

Create a new module to handle the download and extraction logic. This keeps `main.rs` clean.

**Action:** Create `src/ghidra/setup.rs`

This file will contain logic to:

1. **Check for Java**: Run `java -version` to ensure prerequisites are met.
2. **Fetch Release Info**: Query the GitHub API (`https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest`) to get the download URL.
3. **Download**: Stream the zip file with a progress bar using `reqwest` and `indicatif`.
4. **Extract**: Unzip the file to the target directory using `zip`.
5. **Detect Installation**: Find the actual Ghidra folder inside the zip (usually `ghidra_X.X.X_PUBLIC`).

**Sketch of `src/ghidra/setup.rs`:**

```rust
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Write;
use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};

pub async fn install_ghidra(version: Option<String>, target_dir: PathBuf) -> Result<PathBuf> {
    // 1. Resolve Version & URL (GitHub API or hardcoded fallback for specific versions)
    let (download_url, filename) = resolve_version_url(version).await?;
    
    // 2. Download File
    let zip_path = target_dir.join(&filename);
    download_file(&download_url, &zip_path).await?;
    
    // 3. Extract
    let install_path = extract_zip(&zip_path, &target_dir)?;
    
    // 4. Cleanup zip
    std::fs::remove_file(zip_path)?;
    
    Ok(install_path)
}

async fn download_file(url: &str, path: &Path) -> Result<()> {
    let client = reqwest::Client::new();
    let res = client.get(url).send().await?;
    let total_size = res.content_length().unwrap_or(0);
    
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));
    pb.set_message(format!("Downloading from {}", url));

    let mut file = File::create(path)?;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item?;
        file.write_all(&chunk)?;
        pb.inc(chunk.len() as u64);
    }
    pb.finish_with_message("Download complete");
    Ok(())
}

fn extract_zip(zip_path: &Path, target_dir: &Path) -> Result<PathBuf> {
    // Uses 'zip' crate to extract
    // Returns the path to the extracted 'ghidra_X.X.X' directory
}

pub fn check_java_requirement() -> Result<()> {
    // Exec "java -version" and check output
}

```

### 4. Integrate Module

Expose the new module.

**Action:** Modify `src/ghidra/mod.rs`

```rust
pub mod setup;
// ... existing code ...

```

### 5. Implement Handler in Main

Connect the CLI command to the logic and update the configuration upon success.

**Action:** Modify `src/main.rs`

1. Add to the `run` match arm:
```rust
// In run() function
Commands::Setup(args) => handle_setup(args).await,

```


2. Implement `handle_setup`:
```rust
async fn handle_setup(args: cli::SetupArgs) -> anyhow::Result<()> {
    println!("Ghidra Setup Wizard");
    println!("===================");

    // 1. Check Java
    if !args.force {
        if let Err(e) = ghidra::setup::check_java_requirement() {
            eprintln!("Warning: Java prerequisite check failed: {}", e);
            eprintln!("Ghidra requires JDK 17+. Continue anyway? [y/N]");
            // ... input confirmation logic ...
        }
    }

    // 2. Determine Install Directory
    let install_base = if let Some(d) = args.dir {
        PathBuf::from(d)
    } else {
        // Default to XDG_DATA_HOME/ghidra-cli/ghidra
        dirs::data_local_dir()
            .ok_or(anyhow::anyhow!("Could not determine data directory"))?
            .join("ghidra-cli")
            .join("ghidra")
    };

    std::fs::create_dir_all(&install_base)?;

    // 3. Install
    println!("Installing to: {}", install_base.display());
    let final_path = ghidra::setup::install_ghidra(args.version, install_base).await?;

    // 4. Update Config
    let mut config = Config::load()?;
    config.ghidra_install_dir = Some(final_path.clone());
    config.save()?;

    println!("\nSuccess! Ghidra installed at: {}", final_path.display());
    println!("Configuration updated.");

    // 5. Verify
    println!("\nVerifying installation...");
    // Reuse existing doctor logic or verify_installation()
    let client = GhidraClient::new(config)?;
    client.verify_installation()?;
    println!("Verification passed!");

    Ok(())
}

```



### 6. Make Main Async-Aware for Sync Commands

Currently `run` is synchronous, but `reqwest` is async.

* The `main` function is already `#[tokio::main]`.
* We need to change `run(cli: Cli)` to `async fn run(cli: Cli)`.
* Most existing handlers in `run` are synchronous; calling them from an async function is fine.
* However, `handle_setup` needs to be awaited.

**Refactoring:**
Change the signature of `run` in `src/main.rs`:

```rust
async fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        // ...
        Commands::Setup(args) => handle_setup(args).await, // New async handler
        _ => {
            // Existing sync handlers can wrap in simple blocks if needed, 
            // or just be called directly as they return Result
            match cli.command {
                Commands::Query(args) => handle_query(args),
                // ... rest of sync commands
                _ => Ok(()) 
            }
        }
    }
}

```

### Summary of Workflow

1. User runs `ghidra setup`.
2. CLI checks for Java.
3. CLI fetches latest release URL from GitHub.
4. CLI downloads ~300MB+ zip file showing progress.
5. CLI unzips it.
6. CLI updates `config.yaml` automatically setting `ghidra_install_dir`.
7. User can immediately run `ghidra quick binary.exe`.
