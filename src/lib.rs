//! Library exports for ghidra-cli testing infrastructure.
//!
//! This module exposes internal components needed for integration tests.

#[path = "ipc/mod.rs"]
pub mod ipc;

/// Re-export bridge module for integration tests.
#[path = "ghidra"]
pub mod ghidra {
    pub mod bridge;
}
