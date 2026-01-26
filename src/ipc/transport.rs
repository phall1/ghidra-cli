//! Cross-platform IPC transport layer.
//!
//! Abstracts Unix domain sockets (Unix/macOS) and named pipes (Windows)
//! using the interprocess crate. Uses length-prefixed message framing.
//!
//! Socket paths are per-project to allow concurrent daemons for different
//! projects without conflicts. Socket names use MD5 hash of the project path.

#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum message size (10 MB)
const MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024;

/// Socket name prefix for the daemon
const SOCKET_PREFIX: &str = "ghidra-cli";

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

/// Compute MD5 hash of project path for socket naming.
/// Uses same hashing approach as lock files for consistency.
fn project_hash(project_path: &Path) -> String {
    format!("{:x}", md5::compute(project_path.to_string_lossy().as_bytes()))
}

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

/// Get the socket path for a specific project.
///
/// Checks GHIDRA_CLI_SOCKET env var first (used for testing), then falls back to
/// project-specific socket using MD5 hash of project path.
pub fn socket_path_for_project(project_path: &Path) -> io::Result<PathBuf> {
    if let Ok(path) = std::env::var("GHIDRA_CLI_SOCKET") {
        return Ok(PathBuf::from(path));
    }
    let dir = socket_dir()?;
    let hash = project_hash(project_path);
    Ok(dir.join(format!("{}-{}.sock", SOCKET_PREFIX, hash)))
}

/// Get the socket name for interprocess, for a specific project.
///
/// On Unix, respects GHIDRA_CLI_SOCKET env var for test isolation.
pub fn socket_name_for_project(project_path: &Path) -> String {
    #[cfg(unix)]
    {
        // Check env var first (used for testing)
        if let Ok(path) = std::env::var("GHIDRA_CLI_SOCKET") {
            return path;
        }
        socket_path_for_project(project_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| {
                let hash = project_hash(project_path);
                format!("/tmp/ghidra-cli/{}-{}.sock", SOCKET_PREFIX, hash)
            })
    }

    #[cfg(windows)]
    {
        // Windows uses named pipe namespace with project hash
        let hash = project_hash(project_path);
        format!("{}-{}", SOCKET_PREFIX, hash)
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

/// Remove the socket file for a specific project if it exists.
pub fn remove_socket_for_project(project_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let path = socket_path_for_project(project_path)?;
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        let _ = project_path; // unused on Windows
        Ok(())
    }
}

/// Check if the socket for a specific project exists.
pub fn socket_exists_for_project(project_path: &Path) -> bool {
    #[cfg(unix)]
    {
        socket_path_for_project(project_path).map(|p| p.exists()).unwrap_or(false)
    }

    #[cfg(windows)]
    {
        // On Windows, we can't easily check if a named pipe exists
        // We'll rely on connection attempts instead
        let _ = project_path;
        true
    }
}

/// Create a listener for incoming IPC connections for a specific project.
pub async fn create_listener_for_project(project_path: &Path) -> io::Result<Listener> {
    // Ensure socket directory exists and clean up stale socket
    ensure_socket_dir()?;
    remove_socket_for_project(project_path)?;

    let name = socket_name_for_project(project_path);

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
        let path = socket_path_for_project(project_path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(listener)
}

/// Connect to the daemon's IPC socket for a specific project.
pub async fn connect_for_project(project_path: &Path) -> io::Result<Stream> {
    let name = socket_name_for_project(project_path);

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
