//! Transport helpers for bridge TCP communication.
//!
//! The Java bridge uses newline-delimited JSON over TCP.
//! This module provides minimal transport utilities.

use std::net::TcpStream;

/// Check if a TCP port is reachable on localhost.
pub fn port_reachable(port: u16) -> bool {
    TcpStream::connect(format!("127.0.0.1:{}", port))
        .map(|_| true)
        .unwrap_or(false)
}
