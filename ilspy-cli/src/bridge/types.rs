use serde::{Deserialize, Serialize};

/// A type definition in a .NET assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeInfo {
    pub full_name: String,
    pub ns: String,
    pub name: String,
    pub kind: String,
    pub method_count: usize,
    pub property_count: usize,
    pub field_count: usize,
    pub is_public: bool,
}

/// A method definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodInfo {
    pub type_name: String,
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<ParameterInfo>,
    pub accessibility: String,
    pub is_static: bool,
    pub is_virtual: bool,
    pub is_abstract: bool,
}

/// A method parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParameterInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
}

/// Decompiled source result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecompileResult {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
}

/// Assembly metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssemblyInfo {
    pub name: String,
    pub type_count: usize,
    pub target_framework: String,
    pub references: Vec<AssemblyReference>,
}

/// An assembly reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssemblyReference {
    pub name: String,
    pub version: String,
}

/// A search result across decompiled source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub type_name: String,
    pub match_count: usize,
    pub matches: Vec<SearchMatch>,
}

/// An individual match within a search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchMatch {
    pub line: usize,
    pub matched: String,
    pub context: String,
}

/// Error response from the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeError {
    pub error: String,
}
