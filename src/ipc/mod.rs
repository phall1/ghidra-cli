//! IPC module for CLI-to-daemon communication.
//!
//! This module provides cross-platform IPC using local sockets:
//! - Unix domain sockets on Linux/macOS
//! - Named pipes on Windows
//!
//! Follows the pattern from debugger-cli for reliable length-prefixed
//! JSON message framing.

pub mod client;
pub mod protocol;
pub mod transport;

pub use client::DaemonClient;
pub use protocol::{Command, Request, Response};
