use thiserror::Error;

#[derive(Error, Debug)]
pub enum IlSpyError {
    #[error(".NET runtime not found. Install .NET 8 SDK/runtime.")]
    DotNetNotFound,

    #[error("IlSpy bridge DLL not found at: {0}")]
    BridgeDllNotFound(String),

    #[error("Failed to initialize .NET runtime: {0}")]
    RuntimeInitFailed(String),

    #[error("Failed to load bridge function '{0}': {1}")]
    FunctionLoadFailed(String, String),

    #[error("Bridge call failed: {0}")]
    BridgeCallFailed(String),

    #[error("Assembly not found: {0}")]
    AssemblyNotFound(String),

    #[error("Type not found: {0}")]
    TypeNotFound(String),

    #[error("Method not found: {0}")]
    MethodNotFound(String),

    #[error("Not a .NET assembly: {0}")]
    NotDotNet(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, IlSpyError>;
