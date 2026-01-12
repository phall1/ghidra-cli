use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub signature: Option<String>,
    pub entry_point: String,
    pub calling_convention: Option<String>,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    #[serde(default)]
    pub local_variables: Vec<LocalVariable>,
    #[serde(default)]
    pub calls: Vec<String>,
    #[serde(default)]
    pub called_by: Vec<String>,
    pub decompiled: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub data_type: String,
    pub ordinal: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVariable {
    pub name: String,
    pub data_type: String,
    pub stack_offset: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringData {
    pub address: String,
    pub value: String,
    pub length: usize,
    pub encoding: String,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub address: String,
    pub symbol_type: String,
    pub namespace: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    pub address: String,
    pub library: String,
    pub ordinal: Option<u32>,
    pub is_external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub address: String,
    pub ordinal: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRef {
    pub from: String,
    pub to: String,
    pub ref_type: String,
    pub from_function: Option<String>,
    pub to_function: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBlock {
    pub name: String,
    pub start: String,
    pub end: String,
    pub size: u64,
    pub permissions: String,
    pub is_initialized: bool,
    pub is_loaded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub virtual_address: String,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub address: String,
    pub comment_type: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataType {
    pub name: String,
    pub category: String,
    pub size: Option<u64>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: String,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: String,
    pub length: u32,
    pub flow_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start: String,
    pub end: String,
    pub size: u64,
    pub instruction_count: u32,
    #[serde(default)]
    pub successors: Vec<String>,
    #[serde(default)]
    pub predecessors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInfo {
    pub name: String,
    pub executable_path: String,
    pub executable_format: String,
    pub compiler: Option<String>,
    pub language: String,
    pub creation_date: Option<String>,
    pub image_base: String,
    pub min_address: String,
    pub max_address: String,
    pub function_count: usize,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GhidraData {
    Function(Function),
    String(StringData),
    Symbol(Symbol),
    Import(Import),
    Export(Export),
    XRef(XRef),
    MemoryBlock(MemoryBlock),
    Section(Section),
    Comment(Comment),
    DataType(DataType),
    Instruction(Instruction),
    BasicBlock(BasicBlock),
}
