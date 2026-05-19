//! Library exports for ghidra-cli testing infrastructure.
//!
//! This module exposes internal components needed for integration tests.

#[path = "error.rs"]
pub mod error;

#[path = "config.rs"]
pub mod config;

#[path = "metrics.rs"]
pub mod metrics;

#[path = "ipc/mod.rs"]
pub mod ipc;

#[path = "mcp/mod.rs"]
pub mod mcp;

/// Re-export bridge module for integration tests.
#[path = "ghidra"]
pub mod ghidra {
    pub mod bridge;
}
