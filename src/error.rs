#![allow(dead_code)]

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GhidraError {
    #[error("Ghidra installation not found. Set GHIDRA_INSTALL_DIR or run 'ghidra init'")]
    GhidraNotFound,

    #[error("Ghidra project not found: {0}")]
    ProjectNotFound(String),

    #[error("Program not found: {0}")]
    ProgramNotFound(String),

    #[error("Failed to execute Ghidra: {0}")]
    ExecutionFailed(String),

    #[error("Failed to parse filter: {0}")]
    FilterParseError(String),

    #[error("Invalid filter expression: {0}")]
    InvalidFilter(String),

    #[error("Field not found: {0}")]
    FieldNotFound(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Invalid data type: {0}")]
    InvalidDataType(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Analysis timeout after {0} seconds")]
    Timeout(u64),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, GhidraError>;
