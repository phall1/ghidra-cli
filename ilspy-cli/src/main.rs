use std::process;

use clap::Parser;

mod bridge;
mod cli;
mod commands;
mod error;
mod format;
mod ilspy;

use cli::{Cli, Commands, ListCommands, OutputFormat};

fn main() {
    let cli = Cli::parse();
    let format = OutputFormat::from_cli(&cli);

    let result = run(&cli, format);

    match result {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Err(e) => {
            // For JSON output, emit structured error
            if matches!(format, OutputFormat::Json | OutputFormat::JsonPretty) {
                let err_json = serde_json::json!({ "error": e.to_string() });
                if format == OutputFormat::JsonPretty {
                    eprintln!("{}", serde_json::to_string_pretty(&err_json).unwrap());
                } else {
                    eprintln!("{err_json}");
                }
            } else {
                eprintln!("Error: {e}");
            }
            process::exit(1);
        }
    }
}

fn run(cli: &Cli, format: OutputFormat) -> error::Result<String> {
    match &cli.command {
        // Detect and Doctor don't need the bridge
        Commands::Detect(args) => commands::detect::detect(args, format),
        Commands::Doctor => commands::doctor::doctor(),

        // Everything else needs the bridge
        Commands::List { what } => {
            let bridge = bridge::IlSpyBridge::new()?;
            match what {
                ListCommands::Types(args) => commands::list::list_types(&bridge, args, format),
                ListCommands::Methods(args) => commands::list::list_methods(&bridge, args, format),
            }
        }
        Commands::Decompile(args) => {
            let bridge = bridge::IlSpyBridge::new()?;
            commands::decompile::decompile(&bridge, args, format)
        }
        Commands::Search(args) => {
            let bridge = bridge::IlSpyBridge::new()?;
            commands::search::search(&bridge, args, format)
        }
        Commands::Info(args) => {
            let bridge = bridge::IlSpyBridge::new()?;
            commands::info::info(&bridge, args, format)
        }
    }
}
