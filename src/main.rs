mod cli;
mod config;
mod error;
mod filter;
mod format;
mod ghidra;
mod query;

use clap::Parser;
use cli::{Cli, Commands, QueryArgs, QueryOptions};
use config::Config;
use error::{GhidraError, Result};
use format::OutputFormat;
use ghidra::GhidraClient;
use query::{Query, DataType, FieldSelector, SortKey};
use std::path::PathBuf;

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
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

fn handle_query(args: QueryArgs) -> Result<()> {
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

fn handle_function_command(cmd: cli::FunctionCommands) -> Result<()> {
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

fn handle_decompile(args: cli::DecompileArgs) -> Result<()> {
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

fn handle_decompile_impl(target: String, args: QueryArgs) -> Result<()> {
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

fn handle_strings_command(cmd: cli::StringsCommands) -> Result<()> {
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

fn handle_memory_command(cmd: cli::MemoryCommands) -> Result<()> {
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

fn handle_dump_command(cmd: cli::DumpCommands) -> Result<()> {
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

fn handle_init() -> Result<()> {
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

fn handle_doctor() -> Result<()> {
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

fn handle_version() -> Result<()> {
    println!("ghidra-cli {}", env!("CARGO_PKG_VERSION"));
    println!("Rust CLI for Ghidra reverse engineering");
    Ok(())
}

fn handle_import(args: cli::ImportArgs) -> Result<()> {
    let config = Config::load()?;
    let client = GhidraClient::new(config.clone())?;

    let project = resolve_project(&args.project, &config, &args.program.as_ref().unwrap_or(&"unknown".to_string()))?;

    let binary_path = PathBuf::from(&args.binary);
    if !binary_path.exists() {
        return Err(GhidraError::Other(format!("Binary not found: {}", args.binary)));
    }

    println!("Importing {} into project {}...", args.binary, project);

    let program_name = client.import_binary(&project, &binary_path, args.program.as_deref())?;

    println!("Successfully imported as: {}", program_name);

    Ok(())
}

fn handle_analyze(args: cli::AnalyzeArgs) -> Result<()> {
    let config = Config::load()?;
    let client = GhidraClient::new(config.clone())?;

    let program = resolve_program(&args.program, &config)?;
    let project = resolve_project(&args.project, &config, &program)?;

    println!("Analyzing {}...", program);

    client.analyze_program(&project, &program)?;

    println!("Analysis complete!");

    Ok(())
}

fn handle_summary(opts: QueryOptions) -> Result<()> {
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

fn handle_quick(args: cli::QuickArgs) -> Result<()> {
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

fn handle_config_command(cmd: cli::ConfigCommands) -> Result<()> {
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
                    return Err(GhidraError::ConfigError(format!("Unknown config key: {}", key)));
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

fn handle_set_default(args: cli::SetDefaultArgs) -> Result<()> {
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
            return Err(GhidraError::Other(format!("Unknown default kind: {}", args.kind)));
        }
    }

    Ok(())
}

fn handle_project_command(cmd: cli::ProjectCommands) -> Result<()> {
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
