mod cli;
mod config;
mod daemon;
mod error;
mod filter;
mod format;
mod ghidra;
mod ipc;
mod query;

use clap::Parser;
use cli::{Cli, Commands, DaemonCommands, QueryArgs, QueryOptions, SetupArgs};
use config::Config;
use daemon::process::{get_data_dir, get_running_daemon_info, ensure_not_running};
use daemon::rpc as daemon_rpc;
use daemon::{DaemonConfig, run as run_daemon};
use error::{GhidraError, Result};
use format::OutputFormat;
use ghidra::GhidraClient;
use query::{Query, DataType, FieldSelector, SortKey};
use std::path::PathBuf;
use tracing::{info, error};

#[cfg(unix)]
use daemonize::Daemonize;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Daemon(_) | Commands::Setup(_) => {
            // Daemon and Setup commands are async
            run_async(cli).await
        }
        _ => {
            // Other commands can be sync or we check if daemon is running
            run_with_daemon_check(cli).await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Query(args) => handle_query(args),
        Commands::Init => handle_init(),
        Commands::Doctor => handle_doctor(),
        Commands::Version => handle_version(),
        Commands::Import(args) => handle_import(args),
        Commands::Analyze(args) => handle_analyze(args),
        Commands::Summary(args) => handle_summary(args.options),
        Commands::Quick(args) => handle_quick(args),
        Commands::Function(cmd) => handle_function_command(cmd),
        Commands::Strings(cmd) => handle_strings_command(cmd),
        Commands::Memory(cmd) => handle_memory_command(cmd),
        Commands::Dump(cmd) => handle_dump_command(cmd),
        Commands::Decompile(args) => handle_decompile(args),
        Commands::Config(cmd) => handle_config_command(cmd),
        Commands::SetDefault(args) => handle_set_default(args),
        Commands::Project(args) => handle_project_command(args.command),
        _ => {
            println!("Command not yet implemented");
            Ok(())
        }
    }
}

/// Run async commands (daemon management, setup).
async fn run_async(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Daemon(cmd) => handle_daemon_command(cmd).await,
        Commands::Setup(args) => handle_setup(args).await,
        _ => unreachable!("run_async called with non-async command"),
    }
}

/// Run commands with daemon check - route through daemon if running.
async fn run_with_daemon_check(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;

    // Determine project path
    let project_path = match &cli.command {
        Commands::Query(args) => {
            let program = resolve_program(&args.program, &config)?;
            PathBuf::from(resolve_project(&args.project, &config, &program)?)
        }
        Commands::Import(args) => {
            let program = resolve_program(&args.program, &config)?;
            PathBuf::from(resolve_project(&args.project, &config, &program)?)
        }
        Commands::Analyze(args) => {
            let program = resolve_program(&args.program, &config)?;
            PathBuf::from(resolve_project(&args.project, &config, &program)?)
        }
        _ => {
            // For commands that don't specify project, use default or run directly
            if let Some(ref proj) = config.default_project {
                PathBuf::from(proj)
            } else {
                // No project specified, run command directly
                return run(cli);
            }
        }
    };

    // Check if daemon is running for this project
    if let Some(daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        info!("Daemon is running, routing command through daemon (port: {})", daemon_info.port);

        // Connect to daemon and execute command
        let mut client = daemon_rpc::DaemonClient::connect(daemon_info.port).await?;
        let output = client.execute(cli.command).await?;
        println!("{}", output);
        Ok(())
    } else {
        // No daemon running, execute directly
        run(cli)
    }
}

/// Handle daemon management commands.
async fn handle_daemon_command(cmd: DaemonCommands) -> anyhow::Result<()> {
    match cmd {
        DaemonCommands::Start { project, port, foreground } => {
            handle_daemon_start(project, port, foreground).await
        }
        DaemonCommands::Stop { project } => {
            handle_daemon_stop(project).await
        }
        DaemonCommands::Restart { project, port } => {
            handle_daemon_restart(project, port).await
        }
        DaemonCommands::Status { project } => {
            handle_daemon_status(project).await
        }
        DaemonCommands::Ping { project } => {
            handle_daemon_ping(project).await
        }
        DaemonCommands::ClearCache { project } => {
            handle_daemon_clear_cache(project).await
        }
    }
}

/// Start the daemon.
async fn handle_daemon_start(project: Option<String>, port: Option<u16>, foreground: bool) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;

    // Resolve project path
    let project_path = if let Some(proj) = project {
        PathBuf::from(proj)
    } else if let Some(ref default_proj) = config.default_project {
        PathBuf::from(default_proj)
    } else {
        anyhow::bail!("No project specified and no default project configured");
    };

    // Check if daemon is already running
    ensure_not_running(&data_dir, &project_path)?;

    // Create log file path
    let log_file = data_dir.join("daemon.log");

    let daemon_config = DaemonConfig {
        project_path: project_path.clone(),
        port,
        ghidra_install_dir: config.ghidra_install_dir.map(PathBuf::from),
        log_file,
        program_name: config.default_program.clone(),
    };

    if foreground {
        // Run in foreground
        println!("Starting daemon in foreground mode...");
        run_daemon(daemon_config).await?;
    } else {
        // Run in background - platform-specific daemonization
        println!("Starting daemon for project: {}", project_path.display());

        #[cfg(unix)]
        {
            daemonize_unix(daemon_config)?;
        }

        #[cfg(windows)]
        {
            daemonize_windows(daemon_config, port)?;
        }

        println!("Daemon started successfully");
        println!("  Log file: {}", data_dir.join("daemon.log").display());
        println!("  Use 'ghidra daemon status' to check daemon status");
    }

    Ok(())
}

/// Stop the daemon.
async fn handle_daemon_stop(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;

    let project_path = if let Some(proj) = project {
        PathBuf::from(proj)
    } else if let Some(ref default_proj) = config.default_project {
        PathBuf::from(default_proj)
    } else {
        anyhow::bail!("No project specified and no default project configured");
    };

    if let Some(daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        println!("Stopping daemon (PID: {}, port: {})...", daemon_info.pid, daemon_info.port);

        // Connect and send shutdown
        let mut client = daemon_rpc::DaemonClient::connect(daemon_info.port).await?;
        client.shutdown().await?;

        println!("Daemon stopped successfully");
    } else {
        println!("No daemon running for project: {}", project_path.display());
    }

    Ok(())
}

/// Restart the daemon.
async fn handle_daemon_restart(project: Option<String>, port: Option<u16>) -> anyhow::Result<()> {
    // Stop first
    handle_daemon_stop(project.clone()).await?;

    // Wait a moment
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Start again
    handle_daemon_start(project, port, false).await
}

/// Get daemon status.
async fn handle_daemon_status(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;

    let project_path = if let Some(proj) = project {
        PathBuf::from(proj)
    } else if let Some(ref default_proj) = config.default_project {
        PathBuf::from(default_proj)
    } else {
        anyhow::bail!("No project specified and no default project configured");
    };

    if let Some(daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        println!("Daemon is running:");
        println!("  PID: {}", daemon_info.pid);
        println!("  Port: {}", daemon_info.port);
        println!("  Project: {}", daemon_info.project_path.display());
        println!("  Started: {}", daemon_info.started_at);
        println!("  Log file: {}", daemon_info.log_file.display());

        // Try to get detailed status from daemon
        if let Ok(mut client) = daemon_rpc::DaemonClient::connect(daemon_info.port).await {
            if let Ok(status) = client.status().await {
                println!("\nDaemon status:");
                println!("  Queue depth: {}", status.queue_depth);
                println!("  Completed commands: {}", status.completed_commands);
                println!("  Uptime: {} seconds", status.uptime_seconds);
            }
        }
    } else {
        println!("No daemon running for project: {}", project_path.display());
    }

    Ok(())
}

/// Ping the daemon.
async fn handle_daemon_ping(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;

    let project_path = if let Some(proj) = project {
        PathBuf::from(proj)
    } else if let Some(ref default_proj) = config.default_project {
        PathBuf::from(default_proj)
    } else {
        anyhow::bail!("No project specified and no default project configured");
    };

    if let Some(daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        let mut client = daemon_rpc::DaemonClient::connect(daemon_info.port).await?;
        client.ping().await?;
        println!("Daemon is responsive (port: {})", daemon_info.port);
    } else {
        println!("No daemon running for project: {}", project_path.display());
    }

    Ok(())
}

/// Clear daemon cache.
async fn handle_daemon_clear_cache(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;

    let project_path = if let Some(proj) = project {
        PathBuf::from(proj)
    } else if let Some(ref default_proj) = config.default_project {
        PathBuf::from(default_proj)
    } else {
        anyhow::bail!("No project specified and no default project configured");
    };

    if let Some(daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        // TODO: Implement cache clear via RPC
        println!("Cache clear not yet implemented via RPC");
        // For now, just notify
        println!("Note: Cache will naturally expire after TTL");
    } else {
        println!("No daemon running for project: {}", project_path.display());
    }

    Ok(())
}

/// Handle the setup command - download and install Ghidra.
async fn handle_setup(args: SetupArgs) -> anyhow::Result<()> {
    println!("Ghidra Setup Wizard");
    println!("===================\n");

    // 1. Check Java
    if !args.force {
        if let Err(e) = ghidra::setup::check_java_requirement() {
            eprintln!("⚠ Java prerequisite check failed: {}", e);
            eprintln!("Ghidra requires JDK 17+. Use --force to continue anyway.");
            std::process::exit(1);
        }
    } else {
        println!("⚠ Skipping Java check (--force specified)");
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
    println!("\nInstalling to: {}", install_base.display());
    let final_path = ghidra::setup::install_ghidra(args.version, install_base).await?;

    // 4. Update Config
    let mut config = Config::load()?;
    config.ghidra_install_dir = Some(final_path.clone());
    config.save()?;

    println!("\n✓ Success! Ghidra installed at: {}", final_path.display());
    println!("✓ Configuration updated.");

    // 5. Verify
    println!("\nVerifying installation...");
    let client = GhidraClient::new(config)?;
    if client.verify_installation().is_ok() {
        println!("✓ Verification passed!");
        println!("\nYou can now run: ghidra quick <binary>");
    } else {
        println!("⚠ Verification failed - analyzeHeadless not found");
        println!("  The installation may be incomplete.");
    }

    Ok(())
}

/// Daemonize on Unix systems using fork and detach.
#[cfg(unix)]
fn daemonize_unix(daemon_config: DaemonConfig) -> anyhow::Result<()> {
    use std::fs::OpenOptions;

    let log_file_path = daemon_config.log_file.clone();
    let project_path = daemon_config.project_path.clone();

    // Open log file for stdout/stderr
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)?;

    let stdout = log_file.try_clone()?;
    let stderr = log_file;

    // Get PID file path - use hash of project path like lock file
    let data_dir = get_data_dir()?;
    let project_hash = format!("{:x}", md5::compute(project_path.to_string_lossy().as_bytes()));
    let pid_file = data_dir.join(format!("daemon-{}.pid", project_hash));

    // Configure daemonization
    let daemonize = Daemonize::new()
        .pid_file(pid_file)
        .working_directory("/")
        .stdout(stdout)
        .stderr(stderr);

    // Fork and daemonize
    daemonize.start()
        .map_err(|e| anyhow::anyhow!("Failed to daemonize: {}", e))?;

    // We're now in the daemon process - initialize tokio runtime and run
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        run_daemon(daemon_config).await
    })?;

    Ok(())
}

/// Daemonize on Windows by spawning a detached process.
#[cfg(windows)]
fn daemonize_windows(daemon_config: DaemonConfig, port: Option<u16>) -> anyhow::Result<()> {
    use std::process::Command;

    // Get the current executable path
    let exe_path = std::env::current_exe()?;

    // Build the command to spawn ourselves with --foreground flag
    let mut cmd = Command::new(exe_path);
    cmd.arg("daemon")
        .arg("start")
        .arg("--foreground");

    // Add project path
    cmd.arg("--project")
        .arg(daemon_config.project_path.to_string_lossy().to_string());

    // Add port if specified
    if let Some(p) = port {
        cmd.arg("--port").arg(p.to_string());
    }

    // Windows-specific: CREATE_NO_WINDOW flag
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }

    // Spawn the detached process
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn daemon process: {}", e))?;

    Ok(())
}

fn handle_query(args: QueryArgs) -> anyhow::Result<()> {
    let config = Config::load()?;
    let client = GhidraClient::new(config.clone())?;

    // Resolve program and project
    let program = resolve_program(&args.program, &config)?;
    let project = resolve_project(&args.project, &config, &program)?;

    // Parse data type
    let data_type = DataType::from_str(&args.data_type)?;

    // Build query
    let mut query = Query::new(data_type);

    // Add filter if provided
    if let Some(filter_str) = args.filter {
        let filter = filter::Filter::parse(&filter_str)?;
        query = query.with_filter(filter);
    }

    // Add format
    let format = if args.json {
        OutputFormat::Json
    } else if let Some(fmt) = args.format {
        OutputFormat::from_str(&fmt)?
    } else {
        // Auto-detect based on TTY
        format::auto_detect_format(atty::is(atty::Stream::Stdout))
    };
    query = query.with_format(format);

    // Add limit
    if let Some(limit) = args.limit {
        query = query.with_limit(limit);
    }

    // Add offset
    if let Some(offset) = args.offset {
        query = query.with_offset(offset);
    }

    // Add sort
    if let Some(sort_str) = args.sort {
        let sort_keys = SortKey::parse(&sort_str);
        query.sort = Some(sort_keys);
    }

    // Add field selection
    if let Some(fields_str) = args.fields {
        let selector = FieldSelector::parse(&fields_str)?;
        query.fields = Some(selector);
    }

    // Count only?
    if args.count {
        query = query.count_only();
    }

    // Execute query
    let result = query.execute(&client, &project, &program)?;
    println!("{}", result);

    Ok(())
}

fn handle_function_command(cmd: cli::FunctionCommands) -> anyhow::Result<()> {
    use cli::FunctionCommands;

    match cmd {
        FunctionCommands::List(opts) => {
            let mut args = QueryArgs {
                data_type: "functions".to_string(),
                program: opts.program,
                project: opts.project,
                filter: opts.filter,
                fields: opts.fields,
                format: opts.format,
                limit: opts.limit,
                offset: opts.offset,
                sort: opts.sort,
                count: opts.count,
                json: opts.json,
            };
            handle_query(args)
        }
        FunctionCommands::Decompile(args) => {
            // Decompile specific function
            let mut query_args = QueryArgs {
                data_type: "functions".to_string(),
                program: args.options.program,
                project: args.options.project,
                filter: Some(format!("address={} OR name={}", args.target, args.target)),
                fields: args.options.fields,
                format: args.options.format,
                limit: Some(1),
                offset: None,
                sort: None,
                count: false,
                json: args.options.json,
            };
            handle_decompile_impl(args.target, query_args)
        }
        _ => {
            println!("Function subcommand not yet implemented");
            Ok(())
        }
    }
}

fn handle_decompile(args: cli::DecompileArgs) -> anyhow::Result<()> {
    let query_args = QueryArgs {
        data_type: "functions".to_string(),
        program: args.options.program,
        project: args.options.project,
        filter: None,
        fields: None,
        format: Some("c".to_string()),
        limit: None,
        offset: None,
        sort: None,
        count: false,
        json: false,
    };
    handle_decompile_impl(args.target, query_args)
}

fn handle_decompile_impl(target: String, args: QueryArgs) -> anyhow::Result<()> {
    let config = Config::load()?;
    let client = GhidraClient::new(config.clone())?;

    let program = resolve_program(&args.program, &config)?;
    let project = resolve_project(&args.project, &config, &program)?;

    // Use headless executor to decompile
    let executor = ghidra::headless::HeadlessExecutor::new(&client);
    let result = executor.decompile_function(&project, &program, &target)?;

    // Format output
    if let Some(code) = result.get("code") {
        if let Some(code_str) = code.as_str() {
            println!("{}", code_str);
            return Ok(());
        }
    }

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn handle_strings_command(cmd: cli::StringsCommands) -> anyhow::Result<()> {
    use cli::StringsCommands;

    match cmd {
        StringsCommands::List(opts) => {
            let args = QueryArgs {
                data_type: "strings".to_string(),
                program: opts.program,
                project: opts.project,
                filter: opts.filter,
                fields: opts.fields,
                format: opts.format,
                limit: opts.limit,
                offset: opts.offset,
                sort: opts.sort,
                count: opts.count,
                json: opts.json,
            };
            handle_query(args)
        }
        _ => {
            println!("Strings subcommand not yet implemented");
            Ok(())
        }
    }
}

fn handle_memory_command(cmd: cli::MemoryCommands) -> anyhow::Result<()> {
    use cli::MemoryCommands;

    match cmd {
        MemoryCommands::Map(opts) => {
            let args = QueryArgs {
                data_type: "memory".to_string(),
                program: opts.program,
                project: opts.project,
                filter: opts.filter,
                fields: opts.fields,
                format: opts.format,
                limit: opts.limit,
                offset: opts.offset,
                sort: opts.sort,
                count: opts.count,
                json: opts.json,
            };
            handle_query(args)
        }
        _ => {
            println!("Memory subcommand not yet implemented");
            Ok(())
        }
    }
}

fn handle_dump_command(cmd: cli::DumpCommands) -> anyhow::Result<()> {
    use cli::DumpCommands;

    match cmd {
        DumpCommands::Imports(opts) => {
            let args = QueryArgs {
                data_type: "imports".to_string(),
                program: opts.program,
                project: opts.project,
                filter: opts.filter,
                fields: opts.fields,
                format: opts.format,
                limit: opts.limit,
                offset: opts.offset,
                sort: opts.sort,
                count: opts.count,
                json: opts.json,
            };
            handle_query(args)
        }
        DumpCommands::Exports(opts) => {
            let args = QueryArgs {
                data_type: "exports".to_string(),
                program: opts.program,
                project: opts.project,
                filter: opts.filter,
                fields: opts.fields,
                format: opts.format,
                limit: opts.limit,
                offset: opts.offset,
                sort: opts.sort,
                count: opts.count,
                json: opts.json,
            };
            handle_query(args)
        }
        DumpCommands::Functions(opts) => {
            let args = QueryArgs {
                data_type: "functions".to_string(),
                program: opts.program,
                project: opts.project,
                filter: opts.filter,
                fields: opts.fields,
                format: opts.format,
                limit: opts.limit,
                offset: opts.offset,
                sort: opts.sort,
                count: opts.count,
                json: opts.json,
            };
            handle_query(args)
        }
        DumpCommands::Strings(opts) => {
            let args = QueryArgs {
                data_type: "strings".to_string(),
                program: opts.program,
                project: opts.project,
                filter: opts.filter,
                fields: opts.fields,
                format: opts.format,
                limit: opts.limit,
                offset: opts.offset,
                sort: opts.sort,
                count: opts.count,
                json: opts.json,
            };
            handle_query(args)
        }
    }
}

fn handle_init() -> anyhow::Result<()> {
    println!("Ghidra CLI Initialization");
    println!("========================\n");

    let mut config = Config::default();

    // Check if Ghidra is installed
    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = Config::detect_ghidra_windows() {
            println!("Found Ghidra installation at: {}", dir.display());
            config.ghidra_install_dir = Some(dir);
        }
    }

    if config.ghidra_install_dir.is_none() {
        println!("Ghidra installation not found automatically.");
        println!("Please set GHIDRA_INSTALL_DIR environment variable or update the config file.");
        println!("\nExample:");
        println!("  set GHIDRA_INSTALL_DIR=C:\\ghidra\\ghidra_11.0");
    }

    // Set default project directory
    let home = dirs::home_dir()
        .ok_or_else(|| GhidraError::ConfigError("Could not determine home directory".to_string()))?;
    let project_dir = home.join(".ghidra-projects");
    config.ghidra_project_dir = Some(project_dir.clone());

    println!("\nProject directory: {}", project_dir.display());

    // Save config
    config.save()?;

    println!("\nConfiguration saved to: {}", Config::config_path()?.display());
    println!("\nRun 'ghidra doctor' to verify your installation.");

    Ok(())
}

fn handle_doctor() -> anyhow::Result<()> {
    println!("Ghidra CLI Doctor");
    println!("=================\n");

    let config = Config::load()?;

    // Check Ghidra installation
    print!("Checking Ghidra installation... ");
    match config.get_ghidra_install_dir() {
        Ok(dir) => {
            println!("✓");
            println!("  Location: {}", dir.display());

            let client = GhidraClient::new(config.clone());
            match client {
                Ok(c) => {
                    if c.verify_installation().is_ok() {
                        println!("  analyzeHeadless: ✓");
                    } else {
                        println!("  analyzeHeadless: ✗ (not found)");
                    }
                }
                Err(e) => {
                    println!("  Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("✗");
            println!("  Error: {}", e);
        }
    }

    // Check project directory
    print!("\nChecking project directory... ");
    match config.get_project_dir() {
        Ok(dir) => {
            println!("✓");
            println!("  Location: {}", dir.display());
            println!("  Exists: {}", if dir.exists() { "yes" } else { "no (will be created)" });
        }
        Err(e) => {
            println!("✗");
            println!("  Error: {}", e);
        }
    }

    // Check config file
    print!("\nConfig file... ");
    match Config::config_path() {
        Ok(path) => {
            println!("✓");
            println!("  Location: {}", path.display());
            println!("  Exists: {}", if path.exists() { "yes" } else { "no" });
        }
        Err(e) => {
            println!("✗");
            println!("  Error: {}", e);
        }
    }

    println!("\nDone!");
    Ok(())
}

fn handle_version() -> anyhow::Result<()> {
    println!("ghidra-cli {}", env!("CARGO_PKG_VERSION"));
    println!("Rust CLI for Ghidra reverse engineering");
    Ok(())
}

fn handle_import(args: cli::ImportArgs) -> anyhow::Result<()> {
    let config = Config::load()?;
    let client = GhidraClient::new(config.clone())?;

    let project = resolve_project(&args.project, &config, &args.program.as_ref().unwrap_or(&"unknown".to_string()))?;

    let binary_path = PathBuf::from(&args.binary);
    if !binary_path.exists() {
        anyhow::bail!(format!("Binary not found: {}", args.binary));
    }

    println!("Importing {} into project {}...", args.binary, project);

    let program_name = client.import_binary(&project, &binary_path, args.program.as_deref())?;

    println!("Successfully imported as: {}", program_name);

    Ok(())
}

fn handle_analyze(args: cli::AnalyzeArgs) -> anyhow::Result<()> {
    let config = Config::load()?;
    let client = GhidraClient::new(config.clone())?;

    let program = resolve_program(&args.program, &config)?;
    let project = resolve_project(&args.project, &config, &program)?;

    println!("Analyzing {}...", program);

    client.analyze_program(&project, &program)?;

    println!("Analysis complete!");

    Ok(())
}

fn handle_summary(opts: QueryOptions) -> anyhow::Result<()> {
    let config = Config::load()?;
    let client = GhidraClient::new(config.clone())?;

    let program = resolve_program(&opts.program, &config)?;
    let project = resolve_project(&opts.project, &config, &program)?;

    println!("Program Summary");
    println!("===============\n");

    // Get program info
    let executor = ghidra::headless::HeadlessExecutor::new(&client);
    let info = executor.get_program_info(&project, &program)?;

    if let Some(name) = info.get("name") {
        println!("Name: {}", name);
    }
    if let Some(format) = info.get("executable_format") {
        println!("Format: {}", format);
    }
    if let Some(lang) = info.get("language") {
        println!("Language: {}", lang);
    }
    if let Some(count) = info.get("function_count") {
        println!("Functions: {}", count);
    }
    if let Some(count) = info.get("instruction_count") {
        println!("Instructions: {}", count);
    }

    Ok(())
}

fn handle_quick(args: cli::QuickArgs) -> anyhow::Result<()> {
    let config = Config::load()?;
    let client = GhidraClient::new(config.clone())?;

    let project = args.project.unwrap_or_else(|| "quick-analysis".to_string());
    let binary_path = PathBuf::from(&args.binary);

    println!("Quick analysis of {}...\n", args.binary);

    // Import
    println!("[1/3] Importing binary...");
    let program_name = client.import_binary(&project, &binary_path, None)?;

    // Analyze
    println!("[2/3] Running analysis...");
    client.analyze_program(&project, &program_name)?;

    // Summary
    println!("[3/3] Generating summary...\n");
    let opts = QueryOptions {
        program: Some(program_name),
        project: Some(project),
        filter: None,
        fields: None,
        format: None,
        limit: None,
        offset: None,
        sort: None,
        count: false,
        json: false,
    };
    handle_summary(opts)?;

    Ok(())
}

fn handle_config_command(cmd: cli::ConfigCommands) -> anyhow::Result<()> {
    use cli::ConfigCommands;

    match cmd {
        ConfigCommands::List => {
            let config = Config::load()?;
            println!("{}", serde_yaml::to_string(&config)?);
        }
        ConfigCommands::Get { key } => {
            let config = Config::load()?;
            let yaml = serde_yaml::to_value(&config)?;
            if let Some(value) = yaml.get(&key) {
                println!("{}", serde_yaml::to_string(value)?);
            } else {
                println!("Key not found: {}", key);
            }
        }
        ConfigCommands::Set { key, value } => {
            let mut config = Config::load()?;
            // Simple key-value setting (could be expanded)
            match key.as_str() {
                "default_output_format" => config.default_output_format = Some(value),
                "timeout" => {
                    let timeout: u64 = value.parse()
                        .map_err(|_| GhidraError::ConfigError("Invalid timeout value".to_string()))?;
                    config.timeout = Some(timeout);
                }
                _ => {
                    anyhow::bail!("Unknown config key: {}", key);
                }
            }
            config.save()?;
            println!("Configuration updated");
        }
        ConfigCommands::Reset => {
            let config = Config::default();
            config.save()?;
            println!("Configuration reset to defaults");
        }
    }

    Ok(())
}

fn handle_set_default(args: cli::SetDefaultArgs) -> anyhow::Result<()> {
    let mut config = Config::load()?;

    match args.kind.as_str() {
        "program" => {
            config.default_program = Some(args.value.clone());
            config.save()?;
            println!("Default program set to: {}", args.value);
        }
        "project" => {
            config.default_project = Some(args.value.clone());
            config.save()?;
            println!("Default project set to: {}", args.value);
        }
        _ => {
            anyhow::bail!(format!("Unknown default kind: {}", args.kind));
        }
    }

    Ok(())
}

fn handle_project_command(cmd: cli::ProjectCommands) -> anyhow::Result<()> {
    use cli::ProjectCommands;

    let config = Config::load()?;
    let client = GhidraClient::new(config)?;

    match cmd {
        ProjectCommands::Create { name } => {
            client.create_project(&name)?;
            println!("Project '{}' created", name);
        }
        ProjectCommands::List => {
            let project_dir = client.get_project_dir();
            if !project_dir.exists() {
                println!("No projects found");
                return Ok(());
            }

            println!("Projects:");
            for entry in std::fs::read_dir(project_dir)? {
                let entry = entry?;
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        println!("  {}", name);
                    }
                }
            }
        }
        ProjectCommands::Delete { name } => {
            let project_path = client.get_project_path(&name);
            if project_path.exists() {
                std::fs::remove_dir_all(&project_path)?;
                println!("Project '{}' deleted", name);
            } else {
                println!("Project '{}' not found", name);
            }
        }
        ProjectCommands::Info { name } => {
            let project_name = name.unwrap_or_else(|| "default".to_string());
            let project_path = client.get_project_path(&project_name);
            println!("Project: {}", project_name);
            println!("Path: {}", project_path.display());
            println!("Exists: {}", project_path.exists());
        }
    }

    Ok(())
}

fn resolve_program(program: &Option<String>, config: &Config) -> Result<String> {
    program
        .clone()
        .or_else(|| config.get_default_program())
        .ok_or_else(|| GhidraError::Other("No program specified. Use --program or set default with 'ghidra set-default program <name>'".to_string()))
}

fn resolve_project(project: &Option<String>, config: &Config, program: &str) -> Result<String> {
    Ok(project
        .clone()
        .or_else(|| config.get_default_project())
        .unwrap_or_else(|| format!("{}-project", program)))
}
