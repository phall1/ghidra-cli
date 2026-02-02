use clap::{Parser, Subcommand, Args, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ilspy",
    version,
    about = "Agent-friendly .NET decompilation CLI",
    long_about = "Decompile .NET assemblies using ICSharpCode.Decompiler (ILSpy engine).\n\
                  Supports single-method decompilation, structured JSON output, and .NET detection."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Output as pretty-printed JSON
    #[arg(long, global = true)]
    pub pretty: bool,

    /// Compact output (one line per item)
    #[arg(long, global = true)]
    pub compact: bool,

    /// Verbose output
    #[arg(long, short, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List types or methods in an assembly
    List {
        #[command(subcommand)]
        what: ListCommands,
    },

    /// Decompile an assembly, type, or method
    Decompile(DecompileArgs),

    /// Search decompiled source with regex
    Search(SearchArgs),

    /// Show assembly metadata
    Info(InfoArgs),

    /// Detect .NET vs native binaries
    Detect(DetectArgs),

    /// Check .NET runtime and bridge health
    Doctor,
}

#[derive(Subcommand, Debug)]
pub enum ListCommands {
    /// List types (classes, interfaces, structs, enums)
    Types(ListTypesArgs),

    /// List methods with signatures
    Methods(ListMethodsArgs),
}

#[derive(Args, Debug)]
pub struct ListTypesArgs {
    /// Path to .NET assembly (.dll or .exe)
    pub assembly: PathBuf,

    /// Filter types by name (substring match)
    #[arg(long, short)]
    pub filter: Option<String>,

    /// Filter by type kind
    #[arg(long, value_enum)]
    pub kind: Option<TypeKind>,
}

#[derive(Args, Debug)]
pub struct ListMethodsArgs {
    /// Path to .NET assembly (.dll or .exe)
    pub assembly: PathBuf,

    /// Filter to methods of a specific type (full name)
    #[arg(long, short = 't')]
    pub r#type: Option<String>,

    /// Filter methods by name (substring match)
    #[arg(long, short)]
    pub filter: Option<String>,
}

#[derive(Args, Debug)]
pub struct DecompileArgs {
    /// Path to .NET assembly (.dll or .exe)
    pub assembly: PathBuf,

    /// Decompile a specific type (full name)
    #[arg(long, short = 't')]
    pub r#type: Option<String>,

    /// Decompile a specific method (requires --type)
    #[arg(long, short, requires = "type")]
    pub method: Option<String>,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Path to .NET assembly (.dll or .exe)
    pub assembly: PathBuf,

    /// Regex pattern to search for
    pub pattern: String,
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Path to .NET assembly (.dll or .exe)
    pub assembly: PathBuf,
}

#[derive(Args, Debug)]
pub struct DetectArgs {
    /// Path to a file or directory
    pub path: PathBuf,

    /// Recursively scan directories
    #[arg(long, short)]
    pub recursive: bool,

    /// Only show .NET assemblies
    #[arg(long)]
    pub dotnet_only: bool,

    /// Only show native binaries
    #[arg(long)]
    pub native_only: bool,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum TypeKind {
    Class,
    Interface,
    Struct,
    Enum,
    Delegate,
}

impl TypeKind {
    pub fn matches(&self, kind_str: &str) -> bool {
        match self {
            TypeKind::Class => kind_str == "Class",
            TypeKind::Interface => kind_str == "Interface",
            TypeKind::Struct => kind_str == "Struct",
            TypeKind::Enum => kind_str == "Enum",
            TypeKind::Delegate => kind_str == "Delegate",
        }
    }
}

/// Determine the output format from CLI flags and TTY detection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    /// Human-readable table
    Table,
    /// Compact one-line-per-item
    Compact,
    /// JSON (minified)
    Json,
    /// JSON (pretty-printed)
    JsonPretty,
    /// Raw source code
    Source,
}

impl OutputFormat {
    pub fn from_cli(cli: &Cli) -> Self {
        if cli.pretty {
            OutputFormat::JsonPretty
        } else if cli.json {
            OutputFormat::Json
        } else if cli.compact {
            OutputFormat::Compact
        } else if atty::is(atty::Stream::Stdout) {
            OutputFormat::Table
        } else {
            // Non-TTY: default to compact (agent-friendly, not JSON)
            OutputFormat::Compact
        }
    }
}
