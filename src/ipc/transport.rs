//! Cross-platform IPC transport layer.
//!
//! Abstracts Unix domain sockets (Unix/macOS) and named pipes (Windows)
//! using the interprocess crate. Uses length-prefixed message framing.

#![allow(dead_code)]

use std::io;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum message size (10 MB)
const MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024;

/// Socket name for the daemon
const SOCKET_NAME: &str = "ghidra-cli.sock";

// Platform-specific imports and type aliases
#[cfg(unix)]
pub mod platform {
    pub use interprocess::local_socket::tokio::{prelude::*, Listener, Stream};
    pub use interprocess::local_socket::{GenericFilePath, ListenerOptions};
}

#[cfg(windows)]
pub mod platform {
    pub use interprocess::local_socket::tokio::{prelude::*, Listener, Stream};
    pub use interprocess::local_socket::{GenericNamespaced, ListenerOptions};
}

pub use platform::*;

/// Get the socket directory path.
fn socket_dir() -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        // Use XDG runtime dir or /tmp
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = runtime_dir.join("ghidra-cli");
        Ok(dir)
    }

    #[cfg(windows)]
    {
        // Windows named pipes don't need a directory
        Ok(PathBuf::new())
    }
}

/// Get the socket path.
///
/// Checks GHIDRA_CLI_SOCKET env var first (used for testing), then falls back to default.
pub fn socket_path() -> io::Result<PathBuf> {
    if let Ok(path) = std::env::var("GHIDRA_CLI_SOCKET") {
        return Ok(PathBuf::from(path));
    }
    let dir = socket_dir()?;
    Ok(dir.join(SOCKET_NAME))
}

/// Get the socket name for interprocess.
///
/// On Unix, respects GHIDRA_CLI_SOCKET env var for test isolation.
pub fn socket_name() -> String {
    #[cfg(unix)]
    {
        // Check env var first (used for testing)
        if let Ok(path) = std::env::var("GHIDRA_CLI_SOCKET") {
            return path;
        }
        socket_path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| format!("/tmp/ghidra-cli/{}", SOCKET_NAME))
    }

    #[cfg(windows)]
    {
        // Windows uses named pipe namespace
        format!("ghidra-cli-{}", std::process::id())
    }
}

/// Ensure the socket directory exists.
pub fn ensure_socket_dir() -> io::Result<()> {
    #[cfg(unix)]
    {
        let dir = socket_dir()?;
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        Ok(())
    }
}

/// Remove the socket file if it exists.
pub fn remove_socket() -> io::Result<()> {
    #[cfg(unix)]
    {
        let path = socket_path()?;
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        Ok(())
    }
}

/// Check if the socket exists.
pub fn socket_exists() -> bool {
    #[cfg(unix)]
    {
        socket_path().map(|p| p.exists()).unwrap_or(false)
    }

    #[cfg(windows)]
    {
        // On Windows, we can't easily check if a named pipe exists
        // We'll rely on connection attempts instead
        true
    }
}

/// Create a listener for incoming IPC connections.
pub async fn create_listener() -> io::Result<Listener> {
    // Ensure socket directory exists and clean up stale socket
    ensure_socket_dir()?;
    remove_socket()?;

    let name = socket_name();

    #[cfg(unix)]
    let listener = {
        let name = name.to_fs_name::<GenericFilePath>()?;
        ListenerOptions::new().name(name).create_tokio()?
    };

    #[cfg(windows)]
    let listener = {
        let name = name.to_ns_name::<GenericNamespaced>()?;
        ListenerOptions::new().name(name).create_tokio()?
    };

    // Set socket permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = socket_path()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(listener)
}

/// Connect to the daemon's IPC socket.
pub async fn connect() -> io::Result<Stream> {
    let name = socket_name();

    #[cfg(unix)]
    let stream = {
        let name = name.to_fs_name::<GenericFilePath>()?;
        Stream::connect(name).await?
    };

    #[cfg(windows)]
    let stream = {
        let name = name.to_ns_name::<GenericNamespaced>()?;
        Stream::connect(name).await?
    };

    Ok(stream)
}

/// Send a length-prefixed message.
pub async fn send_message<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_MESSAGE_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Message too large",
        ));
    }

    let len = data.len() as u32;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Receive a length-prefixed message.
pub async fn recv_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);

    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Message too large: {} bytes", len),
        ));
    }

    let mut data = vec![0u8; len as usize];
    reader.read_exact(&mut data).await?;
    Ok(data)
}
