use rmcp::{
    ErrorData as McpError,
    ServerHandler,
    handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::*,
    tool, tool_handler, tool_router,
    service::ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::ipc::client::BridgeClient;

#[derive(Clone)]
pub struct GhidraServer {
    port: u16,
    project_path: String,
    ghidra_install_dir: String,
    tool_router: ToolRouter<Self>,
}

impl GhidraServer {
    pub fn new(port: u16, project_path: String, ghidra_install_dir: String) -> Self {
        Self {
            port,
            project_path,
            ghidra_install_dir,
            tool_router: Self::tool_router(),
        }
    }

    pub async fn run_stdio(self) -> anyhow::Result<()> {
        let service = self.serve((tokio::io::stdin(), tokio::io::stdout()))
            .await
            .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;
        service.waiting().await
            .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;
        Ok(())
    }

    fn client(&self) -> BridgeClient {
        BridgeClient::new(self.port)
    }

    fn ok_result(value: &serde_json::Value) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(value).unwrap_or_default(),
        )]))
    }

    fn err_result(e: anyhow::Error) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::error(vec![Content::text(format!("Error: {}", e))]))
    }

    fn call_bridge<F>(&self, f: F) -> Result<CallToolResult, McpError>
    where
        F: FnOnce(&BridgeClient) -> anyhow::Result<serde_json::Value>,
    {
        let client = self.client();
        match f(&client) {
            Ok(val) => Self::ok_result(&val),
            Err(e) => Self::err_result(e),
        }
    }
}

#[tool_handler]
impl ServerHandler for GhidraServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "ghidra-cli",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(format!(
                "Ghidra reverse engineering tools. Analyze binaries, decompile functions, \
                 search for patterns, and annotate code. Project: {} Ghidra: {}",
                self.project_path, self.ghidra_install_dir,
            ))
    }
}

// --- Parameter structs ---

#[derive(Debug, Deserialize, JsonSchema)]
struct EmptyParams {}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListFunctionsParams {
    limit: Option<usize>,
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TargetParams {
    target: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DisasmParams {
    address: String,
    count: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListStringsParams {
    limit: Option<usize>,
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SymbolListParams {
    limit: Option<usize>,
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SymbolGetParams {
    target: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SymbolCreateParams {
    address: String,
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SymbolDeleteParams {
    target: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SymbolRenameParams {
    old_name: String,
    new_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TypeListParams {
    limit: Option<usize>,
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TypeGetParams {
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TypeCreateParams {
    definition: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TypeApplyParams {
    address: String,
    type_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CommentListParams {
    limit: Option<usize>,
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CommentGetParams {
    address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CommentSetParams {
    address: String,
    text: String,
    comment_type: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CommentDeleteParams {
    address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MemoryReadParams {
    address: String,
    length: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MemoryWriteParams {
    address: String,
    hex_bytes: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct XRefsParams {
    address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindStringParams {
    pattern: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindBytesParams {
    hex_pattern: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindFunctionParams {
    pattern: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindCallsParams {
    function_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GraphCallsParams {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GraphFunctionParams {
    function: String,
    depth: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PatchBytesParams {
    address: String,
    hex: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PatchNopParams {
    address: String,
    count: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PatchExportParams {
    output_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ScriptRunParams {
    script_path: String,
    args: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ScriptCodeParams {
    code: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ImportBinaryParams {
    binary_path: String,
    program_name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct OpenProgramParams {
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeleteProgramParams {
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ExportProgramParams {
    format: String,
    output: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DiffProgramsParams {
    program1: String,
    program2: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DiffFunctionsParams {
    func1: String,
    func2: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GraphExportParams {
    format: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StructListParams {
    limit: Option<usize>,
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StructGetParams {
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StructCreateParams {
    name: String,
    size: Option<usize>,
    category: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StructAddFieldParams {
    struct_name: String,
    field_name: String,
    field_type: String,
    size: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StructRenameFieldParams {
    struct_name: String,
    old_name: String,
    new_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StructDeleteParams {
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct VariableListParams {
    /// Function name or address containing the variables
    function: String,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct VariableRenameParams {
    /// Function name or address containing the variable
    function: String,
    /// Current variable name
    old_name: String,
    /// New variable name
    new_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct VariableRetypeParams {
    /// Function name or address containing the variable
    function: String,
    /// Variable name to retype
    variable: String,
    /// New data type (e.g. int, long, char*, pointer, or any defined type name)
    new_type: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct BatchParams {
    commands: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RenameFunctionParams {
    old_name: String,
    new_name: String,
}

// --- Tool implementations ---

#[tool_router]
impl GhidraServer {
    // === Program/Info ===

    #[tool(description = "Get information about the currently loaded program")]
    async fn get_program_info(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.program_info())
    }

    #[tool(description = "Get statistics about the currently loaded program")]
    async fn get_program_stats(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.stats())
    }

    #[tool(description = "Get bridge status information")]
    async fn get_bridge_info(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.bridge_info())
    }

    #[tool(description = "List all programs in the current project")]
    async fn list_programs(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.list_programs())
    }

    #[tool(description = "Open/switch to a program by name")]
    async fn open_program(&self, Parameters(p): Parameters<OpenProgramParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.open_program(&p.name))
    }

    #[tool(description = "Close the current program")]
    async fn close_program(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.program_close())
    }

    #[tool(description = "Delete a program from the project")]
    async fn delete_program(&self, Parameters(p): Parameters<DeleteProgramParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.program_delete(&p.name))
    }

    #[tool(description = "Export the current program in a specified format (xml, json, asm, c)")]
    async fn export_program(&self, Parameters(p): Parameters<ExportProgramParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.program_export(&p.format, p.output.as_deref()))
    }

    // === Import/Analysis ===

    #[tool(description = "Import a binary file into the project for analysis")]
    async fn import_binary(&self, Parameters(p): Parameters<ImportBinaryParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.import_binary(&p.binary_path, p.program_name.as_deref()))
    }

    #[tool(description = "Run auto-analysis on the currently loaded program")]
    async fn analyze_program(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.analyze())
    }

    // === Functions ===

    #[tool(description = "List functions in the binary. Use filter for name matching and limit to cap results.")]
    async fn list_functions(&self, Parameters(p): Parameters<ListFunctionsParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.list_functions(p.limit, p.filter.clone()))
    }

    #[tool(description = "Decompile a function to C-like pseudocode. Target can be a function name or address (e.g. 'main' or '0x401000').")]
    async fn decompile_function(&self, Parameters(p): Parameters<TargetParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.decompile(p.target.clone()))
    }

    #[tool(description = "Disassemble instructions at an address. Returns assembly instructions.")]
    async fn disassemble(&self, Parameters(p): Parameters<DisasmParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.disasm(&p.address, p.count))
    }

    // === Strings ===

    #[tool(description = "List defined strings in the binary. Use filter for content matching.")]
    async fn list_strings(&self, Parameters(p): Parameters<ListStringsParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.list_strings(p.limit, p.filter.clone()))
    }

    // === Symbols ===

    #[tool(description = "List symbols (labels, function names, etc.)")]
    async fn list_symbols(&self, Parameters(p): Parameters<SymbolListParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.symbol_list(p.limit, p.filter.as_deref()))
    }

    #[tool(description = "Get details of a symbol by name or address")]
    async fn get_symbol(&self, Parameters(p): Parameters<SymbolGetParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.symbol_get(&p.target))
    }

    #[tool(description = "Create a new symbol/label at an address")]
    async fn create_symbol(&self, Parameters(p): Parameters<SymbolCreateParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.symbol_create(&p.address, &p.name))
    }

    #[tool(description = "Delete a symbol by name or address")]
    async fn delete_symbol(&self, Parameters(p): Parameters<SymbolDeleteParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.symbol_delete(&p.target))
    }

    #[tool(description = "Rename a symbol")]
    async fn rename_symbol(&self, Parameters(p): Parameters<SymbolRenameParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.symbol_rename(&p.old_name, &p.new_name))
    }

    // === Types ===

    #[tool(description = "List data types defined in the program")]
    async fn list_types(&self, Parameters(p): Parameters<TypeListParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.type_list(p.limit, p.filter.as_deref()))
    }

    #[tool(description = "Get the definition of a data type by name")]
    async fn get_type(&self, Parameters(p): Parameters<TypeGetParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.type_get(&p.name))
    }

    #[tool(description = "Create a new data type from a C-like definition string")]
    async fn create_type(&self, Parameters(p): Parameters<TypeCreateParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.type_create(&p.definition))
    }

    #[tool(description = "Apply a data type to an address")]
    async fn apply_type(&self, Parameters(p): Parameters<TypeApplyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.type_apply(&p.address, &p.type_name))
    }

    // === Memory ===

    #[tool(description = "Get the memory map showing all memory blocks/sections")]
    async fn get_memory_map(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.memory_map())
    }

    #[tool(description = "Read memory bytes at an address")]
    async fn read_memory(&self, Parameters(p): Parameters<MemoryReadParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| {
            c.send_command("read_memory", Some(serde_json::json!({
                "address": p.address,
                "size": p.length,
            })))
        })
    }

    #[tool(description = "Write hex bytes to a memory address")]
    async fn write_memory(&self, Parameters(p): Parameters<MemoryWriteParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| {
            c.send_command("write_memory", Some(serde_json::json!({
                "address": p.address,
                "bytes": p.hex_bytes,
            })))
        })
    }

    // === Cross-References ===

    #[tool(description = "Get cross-references TO an address (who references this address)")]
    async fn get_xrefs_to(&self, Parameters(p): Parameters<XRefsParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.xrefs_to(p.address.clone()))
    }

    #[tool(description = "Get cross-references FROM an address (what this address references)")]
    async fn get_xrefs_from(&self, Parameters(p): Parameters<XRefsParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.xrefs_from(p.address.clone()))
    }

    // === Comments ===

    #[tool(description = "List all comments in the program")]
    async fn list_comments(&self, Parameters(p): Parameters<CommentListParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.comment_list(p.limit, p.filter.as_deref()))
    }

    #[tool(description = "Get the comment at a specific address")]
    async fn get_comment(&self, Parameters(p): Parameters<CommentGetParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.comment_get(&p.address))
    }

    #[tool(description = "Set a comment at an address. comment_type can be EOL, PRE, POST, PLATE, or REPEATABLE.")]
    async fn set_comment(&self, Parameters(p): Parameters<CommentSetParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.comment_set(&p.address, &p.text, p.comment_type.as_deref()))
    }

    #[tool(description = "Delete the comment at an address")]
    async fn delete_comment(&self, Parameters(p): Parameters<CommentDeleteParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.comment_delete(&p.address))
    }

    // === Search ===

    #[tool(description = "Search for strings matching a pattern")]
    async fn find_strings(&self, Parameters(p): Parameters<FindStringParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.find_string(&p.pattern))
    }

    #[tool(description = "Search for a hex byte pattern in the binary (e.g. '90 90 90')")]
    async fn find_bytes(&self, Parameters(p): Parameters<FindBytesParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.find_bytes(&p.hex_pattern))
    }

    #[tool(description = "Search for functions matching a name pattern (supports wildcards)")]
    async fn find_functions(&self, Parameters(p): Parameters<FindFunctionParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.find_function(&p.pattern))
    }

    #[tool(description = "Find all calls to a specific function")]
    async fn find_calls(&self, Parameters(p): Parameters<FindCallsParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.find_calls(&p.function_name))
    }

    #[tool(description = "Find cryptographic constants and patterns in the binary")]
    async fn find_crypto(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.find_crypto())
    }

    #[tool(description = "Find interesting/suspicious functions (dangerous APIs, anti-debug, etc.)")]
    async fn find_interesting(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.find_interesting())
    }

    // === Graph ===

    #[tool(description = "Get the full call graph of the program")]
    async fn get_call_graph(&self, Parameters(p): Parameters<GraphCallsParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.graph_calls(p.limit))
    }

    #[tool(description = "Get functions that call the specified function (callers/incoming)")]
    async fn get_callers(&self, Parameters(p): Parameters<GraphFunctionParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.graph_callers(&p.function, p.depth))
    }

    #[tool(description = "Get functions called by the specified function (callees/outgoing)")]
    async fn get_callees(&self, Parameters(p): Parameters<GraphFunctionParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.graph_callees(&p.function, p.depth))
    }

    #[tool(description = "Export the call graph in a format (e.g. 'dot', 'json')")]
    async fn export_graph(&self, Parameters(p): Parameters<GraphExportParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.graph_export(&p.format))
    }

    // === Patching ===

    #[tool(description = "Patch bytes at an address with hex values")]
    async fn patch_bytes(&self, Parameters(p): Parameters<PatchBytesParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.patch_bytes(&p.address, &p.hex))
    }

    #[tool(description = "NOP out instructions at an address")]
    async fn patch_nop(&self, Parameters(p): Parameters<PatchNopParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.patch_nop(&p.address, p.count))
    }

    #[tool(description = "Export the patched binary to a file")]
    async fn export_patched(&self, Parameters(p): Parameters<PatchExportParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.patch_export(&p.output_path))
    }

    // === Scripts ===

    #[tool(description = "Run a Ghidra script file with optional arguments")]
    async fn run_script(&self, Parameters(p): Parameters<ScriptRunParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.script_run(&p.script_path, &p.args))
    }

    #[tool(description = "Execute inline Python code in Ghidra's Jython interpreter")]
    async fn run_python(&self, Parameters(p): Parameters<ScriptCodeParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.script_python(&p.code))
    }

    #[tool(description = "Execute inline Java code in Ghidra")]
    async fn run_java(&self, Parameters(p): Parameters<ScriptCodeParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.script_java(&p.code))
    }

    #[tool(description = "List available Ghidra scripts")]
    async fn list_scripts(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.script_list())
    }

    // === Diff ===

    #[tool(description = "Compare two programs and show differences")]
    async fn diff_programs(&self, Parameters(p): Parameters<DiffProgramsParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.diff_programs(&p.program1, &p.program2))
    }

    #[tool(description = "Compare two functions and show differences")]
    async fn diff_functions(&self, Parameters(p): Parameters<DiffFunctionsParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.diff_functions(&p.func1, &p.func2))
    }

    // === Rename ===

    #[tool(description = "Rename a function (shortcut for rename via bridge command)")]
    async fn rename_function(&self, Parameters(p): Parameters<RenameFunctionParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| {
            c.send_command("rename_function", Some(serde_json::json!({
                "old_name": p.old_name,
                "new_name": p.new_name,
            })))
        })
    }

    // === Data dumps ===

    #[tool(description = "List all imported functions/symbols")]
    async fn list_imports(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.list_imports())
    }

    #[tool(description = "List all exported functions/symbols")]
    async fn list_exports(&self, #[allow(unused)] _p: Parameters<EmptyParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.list_exports())
    }

    // === Structures ===

    #[tool(description = "List all structures (C structs) defined in the program's data type manager")]
    async fn list_structures(&self, Parameters(p): Parameters<StructListParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.struct_list(p.limit, p.filter.as_deref()))
    }

    #[tool(description = "Get detailed information about a structure including all fields, offsets, and types")]
    async fn get_structure(&self, Parameters(p): Parameters<StructGetParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.struct_get(&p.name))
    }

    #[tool(description = "Create a new empty structure. Optionally specify initial size and category path.")]
    async fn create_structure(&self, Parameters(p): Parameters<StructCreateParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.struct_create(&p.name, p.size, p.category.as_deref()))
    }

    #[tool(description = "Add a field to an existing structure. field_type can be: int, byte, char, short, long, float, double, void, pointer, or any existing type name.")]
    async fn add_struct_field(&self, Parameters(p): Parameters<StructAddFieldParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.struct_add_field(&p.struct_name, &p.field_name, &p.field_type, p.size))
    }

    #[tool(description = "Rename a field within a structure")]
    async fn rename_struct_field(&self, Parameters(p): Parameters<StructRenameFieldParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.struct_rename_field(&p.struct_name, &p.old_name, &p.new_name))
    }

    #[tool(description = "Delete a structure from the program's data type manager")]
    async fn delete_structure(&self, Parameters(p): Parameters<StructDeleteParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.struct_delete(&p.name))
    }

    #[tool(description = "List all variables (locals + parameters) in a function. Uses decompiler to show the full variable set including types, storage locations, and parameter indices.")]
    async fn list_variables(&self, Parameters(p): Parameters<VariableListParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.variable_list(&p.function, p.limit))
    }

    #[tool(description = "Rename a local variable or parameter in a function. Uses DecompInterface to find the variable in the decompiler's model and commits the rename to the database.")]
    async fn rename_variable(&self, Parameters(p): Parameters<VariableRenameParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.variable_rename(&p.function, &p.old_name, &p.new_name))
    }

    #[tool(description = "Change the data type of a local variable or parameter. Accepts built-in types (int, long, char, byte, etc.) or any type defined in the program's data type manager.")]
    async fn retype_variable(&self, Parameters(p): Parameters<VariableRetypeParams>) -> Result<CallToolResult, McpError> {
        self.call_bridge(|c| c.variable_retype(&p.function, &p.variable, &p.new_type))
    }

    // === Batch ===

    #[tool(description = "Execute multiple bridge commands in sequence. Each string is a raw command (e.g. 'list_functions', 'decompile main').")]
    async fn batch_commands(&self, Parameters(p): Parameters<BatchParams>) -> Result<CallToolResult, McpError> {
        let client = self.client();
        let mut results = Vec::new();
        for cmd_str in &p.commands {
            let parts: Vec<&str> = cmd_str.splitn(2, ' ').collect();
            let command = parts[0];
            let args = if parts.len() > 1 {
                serde_json::from_str(parts[1]).ok()
            } else {
                None
            };
            match client.send_command(command, args) {
                Ok(val) => results.push(serde_json::json!({"command": cmd_str, "result": val})),
                Err(e) => results.push(serde_json::json!({"command": cmd_str, "error": e.to_string()})),
            }
        }
        Self::ok_result(&serde_json::json!(results))
    }
}
