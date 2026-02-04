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
use cli::{Cli, Commands, DaemonCommands};
use config::Config;
use error::{GhidraError, Result};
use format::{auto_detect_format, DefaultFormatter, Formatter, OutputFormat};
use ghidra::bridge::{self, BridgeStartMode, BridgeStatus};
use ghidra::GhidraClient;
use ipc::client::BridgeClient;
use std::path::{Path, PathBuf};

fn main() {
    // Initialize logging with info level by default, can be overridden via RUST_LOG
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Setup(_) => {
            // Setup needs async for downloading
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(run_setup(cli))
        }
        Commands::Daemon(_) => handle_daemon_command_dispatch(cli),
        _ => run_command(cli),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Run a command, starting the bridge if needed.
fn run_command(cli: Cli) -> anyhow::Result<()> {
    match &cli.command {
        // Non-bridge commands
        Commands::Init => handle_init(),
        Commands::Doctor => handle_doctor(),
        Commands::Version => handle_version(),
        Commands::Config(cmd) => handle_config_command(cmd.clone()),
        Commands::SetDefault(args) => handle_set_default(args.clone()),
        Commands::Project(args) => handle_project_command(args.command.clone()),
        // Commands requiring bridge
        _ if requires_bridge(&cli.command) => run_with_bridge(cli),
        _ => {
            println!("Command not yet implemented");
            Ok(())
        }
    }
}

/// Determines if a command requires the bridge to be running.
fn requires_bridge(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Import(_)
            | Commands::Analyze(_)
            | Commands::Quick(_)
            | Commands::Query(_)
            | Commands::Decompile(_)
            | Commands::Function(_)
            | Commands::Strings(_)
            | Commands::Memory(_)
            | Commands::Dump(_)
            | Commands::Summary(_)
            | Commands::XRef(_)
            | Commands::Symbol(_)
            | Commands::Type(_)
            | Commands::Comment(_)
            | Commands::Graph(_)
            | Commands::Find(_)
            | Commands::Diff(_)
            | Commands::Patch(_)
            | Commands::Script(_)
            | Commands::Disasm(_)
            | Commands::Batch(_)
            | Commands::Stats(_)
            | Commands::Program(_)
    )
}

/// Extract the project name from a command's args (if present).
fn extract_project_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Import(args) => args.project.clone(),
        Commands::Analyze(args) => args.project.clone(),
        Commands::Quick(args) => args.project.clone(),
        Commands::Query(args) => args.project.clone(),
        Commands::Summary(args) => args.options.project.clone(),
        Commands::Decompile(args) => args.options.project.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(opts) => opts.project.clone(),
            cli::FunctionCommands::Decompile(args) => args.options.project.clone(),
            cli::FunctionCommands::Get(args) => args.options.project.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.project.clone(),
            cli::FunctionCommands::Calls(args) => args.options.project.clone(),
            cli::FunctionCommands::XRefs(args) => args.options.project.clone(),
            cli::FunctionCommands::Rename(args) => args.project.clone(),
            cli::FunctionCommands::Create(args) => args.project.clone(),
            cli::FunctionCommands::Delete(args) => args.options.project.clone(),
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.project.clone(),
            cli::StringsCommands::Refs(args) => args.options.project.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.project.clone(),
            cli::MemoryCommands::Read(args) => args.options.project.clone(),
            cli::MemoryCommands::Write(args) => args.project.clone(),
            cli::MemoryCommands::Search(args) => args.options.project.clone(),
        },
        Commands::Dump(cmd) => match cmd {
            cli::DumpCommands::Imports(opts) => opts.project.clone(),
            cli::DumpCommands::Exports(opts) => opts.project.clone(),
            cli::DumpCommands::Functions(opts) => opts.project.clone(),
            cli::DumpCommands::Strings(opts) => opts.project.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.project.clone(),
            cli::XRefCommands::From(args) => args.options.project.clone(),
            cli::XRefCommands::List(args) => args.options.project.clone(),
        },
        Commands::Stats(args) => args.options.project.clone(),
        Commands::Disasm(args) => args.options.project.clone(),
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => args.options.project.clone(),
            cli::FindCommands::Bytes(args) => args.options.project.clone(),
            cli::FindCommands::Function(args) => args.options.project.clone(),
            cli::FindCommands::Calls(args) => args.options.project.clone(),
            cli::FindCommands::Crypto(opts) => opts.project.clone(),
            cli::FindCommands::Interesting(opts) => opts.project.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => opts.project.clone(),
            cli::GraphCommands::Callers(args) => args.options.project.clone(),
            cli::GraphCommands::Callees(args) => args.options.project.clone(),
            cli::GraphCommands::Export(args) => args.options.project.clone(),
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => opts.project.clone(),
            cli::CommentCommands::Get(args) => args.options.project.clone(),
            cli::CommentCommands::Set(args) => args.project.clone(),
            cli::CommentCommands::Delete(args) => args.options.project.clone(),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts) => opts.project.clone(),
            cli::SymbolCommands::Get(args) => args.options.project.clone(),
            cli::SymbolCommands::Create(args) => args.project.clone(),
            cli::SymbolCommands::Delete(args) => args.options.project.clone(),
            cli::SymbolCommands::Rename(args) => args.project.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.project.clone(),
            cli::TypeCommands::Get(args) => args.options.project.clone(),
            cli::TypeCommands::Create(args) => args.project.clone(),
            cli::TypeCommands::Apply(args) => args.project.clone(),
        },
        Commands::Patch(cmd) => match cmd {
            cli::PatchCommands::Bytes(args) => args.project.clone(),
            cli::PatchCommands::Nop(args) => args.project.clone(),
            cli::PatchCommands::Export(args) => args.project.clone(),
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.project.clone(),
            cli::ScriptCommands::Python(args) => args.project.clone(),
            cli::ScriptCommands::Java(args) => args.project.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::List(args) => args.project.clone(),
            cli::ProgramCommands::Open(args) => args.project.clone(),
            cli::ProgramCommands::Close(args) => args.project.clone(),
            cli::ProgramCommands::Delete(args) => args.project.clone(),
            cli::ProgramCommands::Info(args) => args.project.clone(),
            cli::ProgramCommands::Export(args) => args.project.clone(),
        },
        _ => None,
    }
}

/// Run a command that requires the bridge.
fn run_with_bridge(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load()?;

    // Extract project from command args, fall back to config default
    let project_from_cmd = extract_project_from_command(&cli.command);
    let project_path = resolve_project_path(&project_from_cmd, &config)?;

    let ghidra_install_dir = config
        .ghidra_install_dir
        .clone()
        .or_else(|| config.get_ghidra_install_dir().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Ghidra installation directory not configured. Run 'ghidra setup' first."
            )
        })?;

    // For Import and Quick, we may need to start a new bridge
    let client = match &cli.command {
        Commands::Import(args) => {
            let binary_path = PathBuf::from(&args.binary);
            if !binary_path.exists() {
                anyhow::bail!("Binary not found: {}", args.binary);
            }

            // Check if bridge is already running
            if bridge::is_bridge_running(&project_path) {
                // Bridge running - import via bridge command
                let port = bridge::read_port_file(&project_path)?
                    .ok_or_else(|| anyhow::anyhow!("Bridge port file not found"))?;
                let client = BridgeClient::new(port);
                let result = client.import_binary(&args.binary, args.program.as_deref())?;

                let program_name = args.program.clone().unwrap_or_else(|| {
                    result
                        .get("program")
                        .and_then(|p| p.as_str())
                        .unwrap_or("unknown")
                        .to_string()
                });

                // Switch to the newly imported program
                client.open_program(&program_name)?;
                println!("Successfully imported as: {}", program_name);
                return Ok(());
            }

            // No bridge running - start one in import mode
            eprintln!("Starting Ghidra bridge...");
            let port = bridge::ensure_bridge_running(
                &project_path,
                &ghidra_install_dir,
                BridgeStartMode::Import {
                    binary_path: args.binary.clone(),
                },
            )?;
            let client = BridgeClient::new(port);
            let info = client.program_info()?;
            let program_name = args.program.clone().unwrap_or_else(|| {
                info.get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string()
            });
            println!("Successfully imported as: {}", program_name);
            return Ok(());
        }

        Commands::Quick(args) => {
            let binary_path = PathBuf::from(&args.binary);
            if !binary_path.exists() {
                anyhow::bail!("Binary not found: {}", args.binary);
            }

            println!("Quick analysis of {}...\n", args.binary);

            println!("[1/3] Importing binary...");
            let port = bridge::ensure_bridge_running(
                &project_path,
                &ghidra_install_dir,
                BridgeStartMode::Import {
                    binary_path: args.binary.clone(),
                },
            )?;
            let client = BridgeClient::new(port);

            client.program_info()?;

            println!("[2/3] Running analysis...");
            client.analyze()?;

            println!("[3/3] Done!\n");
            println!("Analysis complete. The bridge is running on port {}.", port);
            println!("\nRun queries like:");
            println!("  ghidra function list");
            println!("  ghidra decompile main");
            println!("  ghidra summary");

            return Ok(());
        }

        Commands::Analyze(args) => {
            let program = resolve_program(&args.program, &config)?;

            // If bridge is already running, just send analyze command
            if bridge::is_bridge_running(&project_path) {
                let client = connect_to_bridge(&project_path)?;
                println!("Analyzing {}...", program);
                client.analyze()?;
                println!("Analysis complete!");
                return Ok(());
            }

            // Start bridge in process mode
            eprintln!("Starting Ghidra bridge...");
            let port = bridge::ensure_bridge_running(
                &project_path,
                &ghidra_install_dir,
                BridgeStartMode::Process {
                    program_name: program.clone(),
                },
            )?;
            let client = BridgeClient::new(port);
            println!("Analyzing {}...", program);
            client.analyze()?;
            println!("Analysis complete!");
            return Ok(());
        }

        _ => {
            // For query commands, ensure bridge is running (auto-start in process mode if needed)
            if !bridge::is_bridge_running(&project_path) {
                // Need a program name to start the bridge in process mode
                let program = config.get_default_program().ok_or_else(|| {
                    anyhow::anyhow!(
                        "No bridge running and no default program configured.\n\
                         Import a binary first: ghidra import <binary>\n\
                         Or set a default: ghidra set-default program <name>"
                    )
                })?;

                eprintln!("Starting Ghidra bridge...");
                let port = bridge::ensure_bridge_running(
                    &project_path,
                    &ghidra_install_dir,
                    BridgeStartMode::Process {
                        program_name: program,
                    },
                )?;
                eprintln!("Bridge ready.");
                BridgeClient::new(port)
            } else {
                connect_to_bridge(&project_path)?
            }
        }
    };

    // Execute the command via bridge
    let result = execute_via_bridge(&client, &cli.command)?;

    // Determine output format based on flags and TTY detection
    let format = if cli.pretty {
        OutputFormat::Json
    } else if cli.json {
        OutputFormat::JsonCompact
    } else {
        auto_detect_format(atty::is(atty::Stream::Stdout))
    };

    // Detect if result is already an array before wrapping
    let values = match result {
        serde_json::Value::Array(arr) => arr,
        single => vec![single],
    };

    let formatter = DefaultFormatter;
    let output = formatter.format(&values, format)?;
    if !output.is_empty() {
        println!("{}", output);
    }
    Ok(())
}

/// Execute a command via the bridge client.
fn execute_via_bridge(
    client: &BridgeClient,
    command: &Commands,
) -> anyhow::Result<serde_json::Value> {
    use serde_json::json;

    match command {
        Commands::Query(args) => match args.data_type.as_str() {
            "functions" => client.list_functions(args.limit, args.filter.clone()),
            "strings" => client.list_strings(args.limit),
            "imports" => client.list_imports(),
            "exports" => client.list_exports(),
            "memory" => client.memory_map(),
            other => anyhow::bail!("Query type '{}' not supported", other),
        },
        Commands::Decompile(args) => client.decompile(args.target.clone()),
        Commands::Function(cmd) => {
            use cli::FunctionCommands;
            match cmd {
                FunctionCommands::List(opts) => {
                    client.list_functions(opts.limit, opts.filter.clone())
                }
                FunctionCommands::Decompile(args) => client.decompile(args.target.clone()),
                FunctionCommands::Get(args) => {
                    client.send_command("get_function", Some(json!({"address": args.target})))
                }
                FunctionCommands::Disasm(args) => client.disasm(&args.target, None),
                FunctionCommands::Calls(args) => client.find_calls(&args.target),
                FunctionCommands::XRefs(args) => client.xrefs_to(args.target.clone()),
                FunctionCommands::Rename(args) => client.send_command(
                    "rename_function",
                    Some(json!({
                        "old_name": args.old_name,
                        "new_name": args.new_name,
                    })),
                ),
                FunctionCommands::Create(args) => client.send_command(
                    "create_function",
                    Some(json!({
                        "address": args.address,
                        "name": args.name,
                    })),
                ),
                FunctionCommands::Delete(args) => client.send_command(
                    "delete_function",
                    Some(json!({
                        "address": args.target,
                    })),
                ),
            }
        }
        Commands::Strings(cmd) => {
            use cli::StringsCommands;
            match cmd {
                StringsCommands::List(opts) => client.list_strings(opts.limit),
                StringsCommands::Refs(args) => client.xrefs_to(args.string.clone()),
            }
        }
        Commands::Memory(cmd) => {
            use cli::MemoryCommands;
            match cmd {
                MemoryCommands::Map(_) => client.memory_map(),
                MemoryCommands::Read(args) => client.send_command(
                    "read_memory",
                    Some(json!({
                        "address": args.address,
                        "size": args.size,
                    })),
                ),
                MemoryCommands::Write(args) => client.send_command(
                    "write_memory",
                    Some(json!({
                        "address": args.address,
                        "bytes": args.bytes,
                    })),
                ),
                MemoryCommands::Search(args) => client.send_command(
                    "search_memory",
                    Some(json!({
                        "pattern": args.pattern,
                    })),
                ),
            }
        }
        Commands::Dump(cmd) => {
            use cli::DumpCommands;
            match cmd {
                DumpCommands::Imports(_) => client.list_imports(),
                DumpCommands::Exports(_) => client.list_exports(),
                DumpCommands::Functions(opts) => {
                    client.list_functions(opts.limit, opts.filter.clone())
                }
                DumpCommands::Strings(opts) => client.list_strings(opts.limit),
            }
        }
        Commands::Summary(_) => client.program_info(),
        Commands::XRef(cmd) => {
            use cli::XRefCommands;
            match cmd {
                XRefCommands::To(args) => client.xrefs_to(args.address.clone()),
                XRefCommands::From(args) => client.xrefs_from(args.address.clone()),
                XRefCommands::List(_) => client.send_command("xrefs_list", None),
            }
        }
        Commands::Program(cmd) => {
            use cli::ProgramCommands;
            match cmd {
                ProgramCommands::List(_) => client.list_programs(),
                ProgramCommands::Open(args) => {
                    let program = args.program.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Program name required. Use --program <name>")
                    })?;
                    client.open_program(program)
                }
                ProgramCommands::Close(_) => client.program_close(),
                ProgramCommands::Delete(args) => {
                    let program = args
                        .program
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Program name required"))?;
                    client.program_delete(program)
                }
                ProgramCommands::Info(_) => client.program_info(),
                ProgramCommands::Export(args) => {
                    client.program_export(&args.format, args.output.as_deref())
                }
            }
        }
        Commands::Symbol(cmd) => {
            use cli::SymbolCommands;
            match cmd {
                SymbolCommands::List(opts) => client.symbol_list(opts.filter.as_deref()),
                SymbolCommands::Get(args) => client.symbol_get(&args.name),
                SymbolCommands::Create(args) => client.symbol_create(&args.address, &args.name),
                SymbolCommands::Delete(args) => client.symbol_delete(&args.name),
                SymbolCommands::Rename(args) => {
                    client.symbol_rename(&args.old_name, &args.new_name)
                }
            }
        }
        Commands::Type(cmd) => {
            use cli::TypeCommands;
            match cmd {
                TypeCommands::List(_) => client.type_list(),
                TypeCommands::Get(args) => client.type_get(&args.name),
                TypeCommands::Create(args) => client.type_create(&args.definition),
                TypeCommands::Apply(args) => client.type_apply(&args.address, &args.type_name),
            }
        }
        Commands::Comment(cmd) => {
            use cli::CommentCommands;
            match cmd {
                CommentCommands::List(_) => client.comment_list(),
                CommentCommands::Get(args) => client.comment_get(&args.address),
                CommentCommands::Set(args) => {
                    client.comment_set(&args.address, &args.text, args.comment_type.as_deref())
                }
                CommentCommands::Delete(args) => client.comment_delete(&args.address),
            }
        }
        Commands::Graph(cmd) => {
            use cli::GraphCommands;
            match cmd {
                GraphCommands::Calls(opts) => client.graph_calls(opts.limit),
                GraphCommands::Callers(args) => client.graph_callers(&args.function, args.depth),
                GraphCommands::Callees(args) => client.graph_callees(&args.function, args.depth),
                GraphCommands::Export(args) => client.graph_export(&args.format),
            }
        }
        Commands::Find(cmd) => {
            use cli::FindCommands;
            match cmd {
                FindCommands::String(args) => client.find_string(&args.pattern),
                FindCommands::Bytes(args) => client.find_bytes(&args.hex),
                FindCommands::Function(args) => client.find_function(&args.pattern),
                FindCommands::Calls(args) => client.find_calls(&args.function),
                FindCommands::Crypto(_) => client.find_crypto(),
                FindCommands::Interesting(_) => client.find_interesting(),
            }
        }
        Commands::Diff(cmd) => {
            use cli::DiffCommands;
            match cmd {
                DiffCommands::Programs(args) => {
                    client.diff_programs(&args.program1, &args.program2)
                }
                DiffCommands::Functions(args) => client.diff_functions(&args.func1, &args.func2),
            }
        }
        Commands::Patch(cmd) => {
            use cli::PatchCommands;
            match cmd {
                PatchCommands::Bytes(args) => client.patch_bytes(&args.address, &args.hex),
                PatchCommands::Nop(args) => client.patch_nop(&args.address),
                PatchCommands::Export(args) => client.patch_export(&args.output),
            }
        }
        Commands::Script(cmd) => {
            use cli::ScriptCommands;
            match cmd {
                ScriptCommands::Run(args) => client.script_run(&args.script_path, &args.args),
                ScriptCommands::Python(args) => client.script_python(&args.code),
                ScriptCommands::Java(args) => client.script_java(&args.code),
                ScriptCommands::List => client.script_list(),
            }
        }
        Commands::Disasm(args) => client.disasm(&args.address, args.num_instructions),
        Commands::Batch(args) => {
            // Read batch file and send commands
            let content = std::fs::read_to_string(&args.script_file)
                .map_err(|e| anyhow::anyhow!("Failed to read batch file: {}", e))?;
            let commands: Vec<serde_json::Value> = content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .map(|l| serde_json::from_str(l).unwrap_or_else(|_| json!({"command": l.trim()})))
                .collect();
            client.batch(&commands)
        }
        Commands::Stats(_) => client.stats(),
        _ => anyhow::bail!("Command not supported"),
    }
}

/// Dispatch daemon (bridge management) commands.
fn handle_daemon_command_dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Daemon(cmd) => match cmd {
            DaemonCommands::Start {
                project,
                program,
                port: _,
                foreground: _,
            } => handle_bridge_start(project, program),
            DaemonCommands::Stop { project } => handle_bridge_stop(project),
            DaemonCommands::Restart {
                project,
                program,
                port: _,
            } => {
                handle_bridge_stop(project.clone())?;
                std::thread::sleep(std::time::Duration::from_secs(1));
                handle_bridge_start(project, program)
            }
            DaemonCommands::Status { project } => handle_bridge_status(project),
            DaemonCommands::Ping { project } => handle_bridge_ping(project),
            DaemonCommands::ClearCache { project: _ } => {
                println!("Cache is managed by the bridge process");
                Ok(())
            }
        },
        _ => unreachable!(),
    }
}

/// Start the bridge for a project.
fn handle_bridge_start(project: Option<String>, program: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let project_path = resolve_project_path(&project, &config)?;

    let ghidra_install_dir = config
        .ghidra_install_dir
        .clone()
        .or_else(|| config.get_ghidra_install_dir().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Ghidra installation directory not configured. Run 'ghidra setup' first."
            )
        })?;

    // Check if bridge is already running
    if bridge::is_bridge_running(&project_path) {
        println!(
            "Bridge is already running for project: {}",
            project_path.display()
        );
        return Ok(());
    }

    // Determine start mode
    let mode = if let Some(prog) = program {
        BridgeStartMode::Process { program_name: prog }
    } else {
        // Need a program name
        let prog = config.get_default_program().ok_or_else(|| {
            anyhow::anyhow!("No program specified. Use --program <name> or set a default.")
        })?;
        BridgeStartMode::Process { program_name: prog }
    };

    println!("Starting bridge for project: {}", project_path.display());

    let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;

    println!("Bridge started on port {}", port);
    Ok(())
}

/// Stop the bridge for a project.
fn handle_bridge_stop(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let project_path = resolve_project_path(&project, &config)?;

    if bridge::is_bridge_running(&project_path) {
        println!("Stopping bridge...");
        bridge::stop_bridge(&project_path)?;
        println!("Bridge stopped");
    } else {
        println!("No bridge running for project: {}", project_path.display());
    }

    Ok(())
}

/// Get bridge status for a project.
fn handle_bridge_status(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let project_path = resolve_project_path(&project, &config)?;

    match bridge::bridge_status(&project_path)? {
        BridgeStatus::Running { port, pid } => {
            println!("Bridge is running:");
            println!("  PID: {}", pid);
            println!("  Port: {}", port);
            println!("  Project: {}", project_path.display());
        }
        BridgeStatus::Stopped => {
            println!("No bridge running for project: {}", project_path.display());
        }
    }

    Ok(())
}

/// Ping the bridge.
fn handle_bridge_ping(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let project_path = resolve_project_path(&project, &config)?;

    if bridge::is_bridge_running(&project_path) {
        let client = connect_to_bridge(&project_path)?;
        if client.ping()? {
            println!("Bridge is responsive");
        } else {
            println!("Bridge is not responding");
        }
    } else {
        println!("No bridge running for project: {}", project_path.display());
    }

    Ok(())
}

/// Handle the setup command - download and install Ghidra.
async fn run_setup(cli: Cli) -> anyhow::Result<()> {
    let args = match cli.command {
        Commands::Setup(args) => args,
        _ => unreachable!(),
    };

    println!("Ghidra Setup Wizard");
    println!("===================\n");

    // 1. Check Java
    if !args.force {
        if let Err(e) = ghidra::setup::check_java_requirement() {
            eprintln!("Java prerequisite check failed: {}", e);
            eprintln!("Ghidra requires JDK 17+. Use --force to continue anyway.");
            std::process::exit(1);
        }
    } else {
        println!("Skipping Java check (--force specified)");
    }

    // 2. Determine Install Directory
    let install_base = if let Some(d) = args.dir {
        PathBuf::from(d)
    } else {
        dirs::data_local_dir()
            .ok_or(anyhow::anyhow!("Could not determine data directory"))?
            .join("ghidra-cli")
            .join("ghidra")
    };

    std::fs::create_dir_all(&install_base)?;

    // 3. Install Ghidra
    println!("\nInstalling to: {}", install_base.display());
    let final_path = ghidra::setup::install_ghidra(args.version, install_base).await?;

    // 4. Update Config
    let mut config = Config::load()?;
    config.ghidra_install_dir = Some(final_path.clone());
    config.save()?;

    println!("\nSuccess! Ghidra installed at: {}", final_path.display());
    println!("Configuration updated.");

    // 5. Verify
    println!("\nVerifying installation...");
    let client = GhidraClient::new(config)?;
    if client.verify_installation().is_ok() {
        println!("Verification passed!");
        println!("\nYou can now run: ghidra quick <binary>");
    } else {
        println!("Verification failed - analyzeHeadless not found");
        println!("  The installation may be incomplete.");
    }

    Ok(())
}

fn handle_init() -> anyhow::Result<()> {
    println!("Ghidra CLI Initialization");
    println!("========================\n");

    let mut config = Config::default();

    if config.ghidra_install_dir.is_none() {
        println!("Ghidra installation not found automatically.");
        println!("Please set GHIDRA_INSTALL_DIR environment variable or run 'ghidra setup'.");
    }

    // Set default project directory
    let home = dirs::home_dir().ok_or_else(|| {
        GhidraError::ConfigError("Could not determine home directory".to_string())
    })?;
    let project_dir = home.join(".ghidra-projects");
    config.ghidra_project_dir = Some(project_dir.clone());

    println!("\nProject directory: {}", project_dir.display());

    // Save config
    config.save()?;

    println!(
        "\nConfiguration saved to: {}",
        Config::config_path()?.display()
    );
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
            println!("OK");
            println!("  Location: {}", dir.display());

            let client = GhidraClient::new(config.clone());
            match client {
                Ok(c) => {
                    if c.verify_installation().is_ok() {
                        println!("  analyzeHeadless: OK");
                    } else {
                        println!("  analyzeHeadless: NOT FOUND");
                    }
                }
                Err(e) => {
                    println!("  Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    // Check Java
    print!("\nChecking Java... ");
    match ghidra::setup::check_java_requirement() {
        Ok(()) => println!("OK (JDK 17+)"),
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    // Check project directory
    print!("\nChecking project directory... ");
    match config.get_project_dir() {
        Ok(dir) => {
            println!("OK");
            println!("  Location: {}", dir.display());
            println!(
                "  Exists: {}",
                if dir.exists() {
                    "yes"
                } else {
                    "no (will be created)"
                }
            );
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    // Check config file
    print!("\nConfig file... ");
    match Config::config_path() {
        Ok(path) => {
            println!("OK");
            println!("  Location: {}", path.display());
            println!("  Exists: {}", if path.exists() { "yes" } else { "no" });
        }
        Err(e) => {
            println!("FAILED");
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
            match key.as_str() {
                "default_output_format" => config.default_output_format = Some(value),
                "timeout" => {
                    let timeout: u64 = value.parse().map_err(|_| {
                        GhidraError::ConfigError("Invalid timeout value".to_string())
                    })?;
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

/// Connect to a running bridge for a project.
fn connect_to_bridge(project_path: &Path) -> anyhow::Result<BridgeClient> {
    let port = bridge::read_port_file(project_path)?.ok_or_else(|| {
        anyhow::anyhow!("Bridge not running for project: {}", project_path.display())
    })?;
    Ok(BridgeClient::new(port))
}

/// Resolve a project name to its full path on disk.
fn resolve_project_path(project: &Option<String>, config: &Config) -> anyhow::Result<PathBuf> {
    let project_name = project
        .clone()
        .or_else(|| config.default_project.clone())
        .ok_or_else(|| anyhow::anyhow!("No project specified and no default project configured"))?;

    let project_dir = config.get_project_dir()?;

    if PathBuf::from(&project_name).is_absolute() {
        Ok(PathBuf::from(project_name))
    } else {
        Ok(project_dir.join(project_name))
    }
}
