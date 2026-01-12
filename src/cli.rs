use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(name = "ghidra")]
#[command(version, about = "Rust CLI for Ghidra reverse engineering", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Universal query command for any data type
    Query(QueryArgs),

    /// Project management commands
    Project(ProjectArgs),

    /// Program/binary management commands
    #[command(subcommand)]
    Program(ProgramCommands),

    /// Function operations
    #[command(subcommand, alias = "fn")]
    Function(FunctionCommands),

    /// String operations
    #[command(subcommand)]
    Strings(StringsCommands),

    /// Symbol operations
    #[command(subcommand, alias = "sym")]
    Symbol(SymbolCommands),

    /// Memory operations
    #[command(subcommand, alias = "mem")]
    Memory(MemoryCommands),

    /// Cross-reference operations
    #[command(subcommand)]
    XRef(XRefCommands),

    /// Type operations
    #[command(subcommand)]
    Type(TypeCommands),

    /// Comment operations
    #[command(subcommand)]
    Comment(CommentCommands),

    /// Search operations
    #[command(subcommand)]
    Find(FindCommands),

    /// Graph operations
    #[command(subcommand)]
    Graph(GraphCommands),

    /// Decompile function
    Decompile(DecompileArgs),

    /// Disassemble code
    Disasm(DisasmArgs),

    /// Diff operations
    #[command(subcommand)]
    Diff(DiffCommands),

    /// Dump/export data
    #[command(subcommand)]
    Dump(DumpCommands),

    /// Patch binary
    #[command(subcommand)]
    Patch(PatchCommands),

    /// Script execution
    #[command(subcommand)]
    Script(ScriptCommands),

    /// Batch operations
    Batch(BatchArgs),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Set default values
    SetDefault(SetDefaultArgs),

    /// Quick analysis (import + analyze + summary)
    Quick(QuickArgs),

    /// Program summary
    Summary(SummaryArgs),

    /// Program statistics
    Stats(StatsArgs),

    /// Show version information
    Version,

    /// Check Ghidra installation
    Doctor,

    /// Initialize configuration
    Init,

    /// Import a binary into a project
    Import(ImportArgs),

    /// Analyze a program
    Analyze(AnalyzeArgs),
}

#[derive(Args)]
pub struct QueryArgs {
    /// Data type to query (functions, strings, imports, etc.)
    pub data_type: String,

    /// Target program
    #[arg(long, env = "GHIDRA_DEFAULT_PROGRAM")]
    pub program: Option<String>,

    /// Project name
    #[arg(long, env = "GHIDRA_DEFAULT_PROJECT")]
    pub project: Option<String>,

    /// Filter expression
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Field selection (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,

    /// Output format
    #[arg(long, short = 'o')]
    pub format: Option<String>,

    /// Maximum number of results
    #[arg(long)]
    pub limit: Option<usize>,

    /// Skip first N results
    #[arg(long)]
    pub offset: Option<usize>,

    /// Sort by field(s) (comma-separated, prefix with - for descending)
    #[arg(long)]
    pub sort: Option<String>,

    /// Only return count
    #[arg(long)]
    pub count: bool,

    /// Output as JSON (shorthand for --format=json)
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommands,
}

#[derive(Subcommand)]
pub enum ProjectCommands {
    /// Create a new project
    Create { name: String },
    /// List all projects
    List,
    /// Delete a project
    Delete { name: String },
    /// Show project information
    Info { name: Option<String> },
}

#[derive(Subcommand)]
pub enum ProgramCommands {
    /// Close a program
    Close(ProgramTargetArgs),
    /// Delete a program
    Delete(ProgramTargetArgs),
    /// Show program information
    Info(ProgramTargetArgs),
    /// Export program
    Export(ExportArgs),
}

#[derive(Args)]
pub struct ProgramTargetArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Export format (xml, json, asm, c)
    pub format: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Output file
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Subcommand)]
pub enum FunctionCommands {
    /// List all functions
    List(QueryOptions),
    /// Get function details
    Get(FunctionGetArgs),
    /// Decompile function
    Decompile(FunctionGetArgs),
    /// Disassemble function
    Disasm(FunctionGetArgs),
    /// Get function calls
    Calls(FunctionGetArgs),
    /// Get cross-references to function
    XRefs(FunctionGetArgs),
    /// Rename function
    Rename(RenameArgs),
    /// Create function
    Create(CreateFunctionArgs),
    /// Delete function
    Delete(FunctionGetArgs),
}

#[derive(Args)]
pub struct FunctionGetArgs {
    /// Function address or name
    pub target: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct RenameArgs {
    pub old_name: String,
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct CreateFunctionArgs {
    pub address: String,
    pub name: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand)]
pub enum StringsCommands {
    /// List all strings
    List(QueryOptions),
    /// Get references to a string
    Refs(StringRefsArgs),
}

#[derive(Args)]
pub struct StringRefsArgs {
    pub string: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand)]
pub enum SymbolCommands {
    /// List all symbols
    List(QueryOptions),
    /// Get symbol details
    Get(SymbolGetArgs),
    /// Create symbol
    Create(CreateSymbolArgs),
    /// Delete symbol
    Delete(SymbolGetArgs),
    /// Rename symbol
    Rename(RenameArgs),
}

#[derive(Args)]
pub struct SymbolGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct CreateSymbolArgs {
    pub address: String,
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand)]
pub enum MemoryCommands {
    /// Show memory map
    Map(QueryOptions),
    /// Read memory
    Read(MemReadArgs),
    /// Write memory
    Write(MemWriteArgs),
    /// Search memory
    Search(MemSearchArgs),
}

#[derive(Args)]
pub struct MemReadArgs {
    pub address: String,
    pub size: usize,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct MemWriteArgs {
    pub address: String,
    pub bytes: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct MemSearchArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand)]
pub enum XRefCommands {
    /// Get cross-references to address
    To(XRefArgs),
    /// Get cross-references from address
    From(XRefArgs),
    /// List all cross-references
    List(XRefArgs),
}

#[derive(Args)]
pub struct XRefArgs {
    pub address: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand)]
pub enum TypeCommands {
    /// List data types
    List(QueryOptions),
    /// Get type definition
    Get(TypeGetArgs),
    /// Create type
    Create(CreateTypeArgs),
    /// Apply type to address
    Apply(ApplyTypeArgs),
}

#[derive(Args)]
pub struct TypeGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct CreateTypeArgs {
    pub definition: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct ApplyTypeArgs {
    pub address: String,
    pub type_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand)]
pub enum CommentCommands {
    /// List all comments
    List(QueryOptions),
    /// Get comment at address
    Get(CommentGetArgs),
    /// Set comment
    Set(CommentSetArgs),
    /// Delete comment
    Delete(CommentGetArgs),
}

#[derive(Args)]
pub struct CommentGetArgs {
    pub address: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct CommentSetArgs {
    pub address: String,
    pub text: String,
    #[arg(long)]
    pub comment_type: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand)]
pub enum FindCommands {
    /// Find strings
    String(FindStringArgs),
    /// Find byte patterns
    Bytes(FindBytesArgs),
    /// Find functions
    Function(FindFunctionArgs),
    /// Find calls to function
    Calls(FindCallsArgs),
    /// Find crypto constants
    Crypto(QueryOptions),
    /// Find interesting functions
    Interesting(QueryOptions),
}

#[derive(Args)]
pub struct FindStringArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct FindBytesArgs {
    pub hex: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct FindFunctionArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct FindCallsArgs {
    pub function: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand)]
pub enum GraphCommands {
    /// Call graph
    Calls(QueryOptions),
    /// Get callers of function
    Callers(GraphFunctionArgs),
    /// Get callees of function
    Callees(GraphFunctionArgs),
    /// Export graph
    Export(GraphExportArgs),
}

#[derive(Args)]
pub struct GraphFunctionArgs {
    pub function: String,
    #[arg(long)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct GraphExportArgs {
    pub format: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct DecompileArgs {
    pub target: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct DisasmArgs {
    pub address: String,
    #[arg(long)]
    pub count: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand)]
pub enum DiffCommands {
    /// Compare two programs
    Programs(DiffProgramsArgs),
    /// Compare functions
    Functions(QueryOptions),
}

#[derive(Args)]
pub struct DiffProgramsArgs {
    pub program1: String,
    pub program2: String,
    #[arg(long)]
    pub format: Option<String>,
}

#[derive(Subcommand)]
pub enum DumpCommands {
    /// Dump imports
    Imports(QueryOptions),
    /// Dump exports
    Exports(QueryOptions),
    /// Dump functions
    Functions(QueryOptions),
    /// Dump strings
    Strings(QueryOptions),
}

#[derive(Subcommand)]
pub enum PatchCommands {
    /// Patch bytes
    Bytes(PatchBytesArgs),
    /// NOP instructions
    Nop(PatchNopArgs),
    /// Export patched binary
    Export(PatchExportArgs),
}

#[derive(Args)]
pub struct PatchBytesArgs {
    pub address: String,
    pub hex: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct PatchNopArgs {
    pub address: String,
    #[arg(long)]
    pub count: Option<usize>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct PatchExportArgs {
    #[arg(short, long)]
    pub output: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand)]
pub enum ScriptCommands {
    /// Run a script file
    Run(ScriptRunArgs),
    /// Execute inline Python code
    Python(ScriptInlineArgs),
    /// Execute inline Java code
    Java(ScriptInlineArgs),
    /// List available scripts
    List,
}

#[derive(Args)]
pub struct ScriptRunArgs {
    pub script_path: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Script arguments (after --)
    #[arg(last = true)]
    pub args: Vec<String>,
}

#[derive(Args)]
pub struct ScriptInlineArgs {
    pub code: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct BatchArgs {
    pub script_file: String,
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// List all configuration
    List,
    /// Get configuration value
    Get { key: String },
    /// Set configuration value
    Set { key: String, value: String },
    /// Reset configuration
    Reset,
}

#[derive(Args)]
pub struct SetDefaultArgs {
    pub kind: String,
    pub value: String,
}

#[derive(Args)]
pub struct QuickArgs {
    pub binary: String,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct SummaryArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct StatsArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args)]
pub struct ImportArgs {
    pub binary: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args)]
pub struct AnalyzeArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

/// Common query options used across commands
#[derive(Args)]
pub struct QueryOptions {
    #[arg(long)]
    pub program: Option<String>,

    #[arg(long)]
    pub project: Option<String>,

    #[arg(short, long)]
    pub filter: Option<String>,

    #[arg(long)]
    pub fields: Option<String>,

    #[arg(long, short = 'o')]
    pub format: Option<String>,

    #[arg(long)]
    pub limit: Option<usize>,

    #[arg(long)]
    pub offset: Option<usize>,

    #[arg(long)]
    pub sort: Option<String>,

    #[arg(long)]
    pub count: bool,

    #[arg(long)]
    pub json: bool,
}
