use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::format::DetectResult;

/// Detect whether a PE file is a .NET assembly by reading PE headers.
/// This is pure Rust — no .NET runtime needed.
pub fn detect_pe(path: &Path) -> DetectResult {
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    match detect_pe_inner(path) {
        Ok(result) => result,
        Err(_) => DetectResult {
            path: filename,
            is_dotnet: false,
            framework: "Unknown (not a PE file)".to_string(),
            recommended_tool: "ghidra".to_string(),
        },
    }
}

fn detect_pe_inner(path: &Path) -> std::io::Result<DetectResult> {
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut file = fs::File::open(path)?;
    let mut buf = [0u8; 2];

    // Check MZ signature
    file.read_exact(&mut buf)?;
    if &buf != b"MZ" {
        return Ok(DetectResult {
            path: filename,
            is_dotnet: false,
            framework: "Not a PE file".to_string(),
            recommended_tool: "unknown".to_string(),
        });
    }

    // Read PE header offset at 0x3C
    file.seek(SeekFrom::Start(0x3C))?;
    let mut pe_offset_buf = [0u8; 4];
    file.read_exact(&mut pe_offset_buf)?;
    let pe_offset = u32::from_le_bytes(pe_offset_buf) as u64;

    // Check PE signature
    file.seek(SeekFrom::Start(pe_offset))?;
    let mut pe_sig = [0u8; 4];
    file.read_exact(&mut pe_sig)?;
    if &pe_sig != b"PE\0\0" {
        return Ok(DetectResult {
            path: filename,
            is_dotnet: false,
            framework: "Invalid PE signature".to_string(),
            recommended_tool: "unknown".to_string(),
        });
    }

    // COFF header: Machine (2) + NumberOfSections (2) + ... + SizeOfOptionalHeader (2) + Characteristics (2)
    // Skip to SizeOfOptionalHeader at offset PE+20+16 = PE+24
    file.seek(SeekFrom::Start(pe_offset + 4))?;
    let mut coff_header = [0u8; 20];
    file.read_exact(&mut coff_header)?;
    let size_of_optional = u16::from_le_bytes([coff_header[16], coff_header[17]]);

    if size_of_optional == 0 {
        return Ok(DetectResult {
            path: filename,
            is_dotnet: false,
            framework: "No optional header".to_string(),
            recommended_tool: "ghidra".to_string(),
        });
    }

    // Read optional header magic to determine PE32 vs PE32+
    let optional_header_offset = pe_offset + 24;
    file.seek(SeekFrom::Start(optional_header_offset))?;
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic)?;
    let is_pe32_plus = u16::from_le_bytes(magic) == 0x20B;

    // CLI header is data directory index 14
    // In PE32: data directories start at optional header + 96
    // In PE32+: data directories start at optional header + 112
    let data_dir_base = if is_pe32_plus {
        optional_header_offset + 112
    } else {
        optional_header_offset + 96
    };

    // Each data directory entry is 8 bytes (RVA + Size)
    // CLI header = index 14
    let cli_dir_offset = data_dir_base + 14 * 8;

    // Make sure we don't read past the optional header
    let optional_header_end = optional_header_offset + size_of_optional as u64;
    if cli_dir_offset + 8 > optional_header_end {
        return Ok(DetectResult {
            path: filename,
            is_dotnet: false,
            framework: "Native PE".to_string(),
            recommended_tool: "ghidra".to_string(),
        });
    }

    file.seek(SeekFrom::Start(cli_dir_offset))?;
    let mut cli_dir = [0u8; 8];
    file.read_exact(&mut cli_dir)?;
    let cli_rva = u32::from_le_bytes([cli_dir[0], cli_dir[1], cli_dir[2], cli_dir[3]]);
    let cli_size = u32::from_le_bytes([cli_dir[4], cli_dir[5], cli_dir[6], cli_dir[7]]);

    let is_dotnet = cli_rva != 0 && cli_size != 0;

    // Try to detect framework by scanning for known strings
    let framework = if is_dotnet {
        detect_framework(path)
    } else {
        detect_native_framework(path)
    };

    let recommended_tool = if is_dotnet { "ilspy" } else { "ghidra" };

    Ok(DetectResult {
        path: filename,
        is_dotnet,
        framework,
        recommended_tool: recommended_tool.to_string(),
    })
}

/// Scan file for framework identification strings using raw byte search.
fn detect_framework(path: &Path) -> String {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return ".NET (unknown version)".to_string(),
    };

    // Look for TargetFramework attribute value
    let needle = b".NETCoreApp,Version=v";
    if let Some(pos) = find_bytes(&data, needle) {
        let start = pos + needle.len();
        let version: String = data[start..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit() || b == b'.')
            .map(|&b| b as char)
            .collect();
        let r2r = if contains_bytes(&data, b"ReadyToRun") || contains_bytes(&data, b"R2R") {
            " (ReadyToRun)"
        } else {
            ""
        };
        return format!(".NET {version}{r2r}");
    }

    let needle = b".NETFramework,Version=v";
    if let Some(pos) = find_bytes(&data, needle) {
        let start = pos + needle.len();
        let version: String = data[start..]
            .iter()
            .take_while(|&&b| b.is_ascii_digit() || b == b'.')
            .map(|&b| b as char)
            .collect();
        return format!(".NET Framework {version}");
    }

    if contains_bytes(&data, b".NETStandard") {
        return ".NET Standard".to_string();
    }

    ".NET (unknown version)".to_string()
}

/// Search for a byte pattern in a byte slice.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    find_bytes(haystack, needle).is_some()
}

/// Find the position of a byte pattern in a byte slice.
/// Uses a simple but efficient first-byte scan with memchr-like approach.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        // Find next occurrence of first byte
        if let Some(pos) = haystack[i..].iter().position(|&b| b == first) {
            let start = i + pos;
            if start + needle.len() > haystack.len() {
                return None;
            }
            if &haystack[start..start + needle.len()] == needle {
                return Some(start);
            }
            i = start + 1;
        } else {
            return None;
        }
    }
    None
}

/// Detect native binary framework hints using raw byte searching.
fn detect_native_framework(path: &Path) -> String {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return "Native".to_string(),
    };

    if contains_bytes(&data, b"Embarcadero") || contains_bytes(&data, b"Borland")
        || contains_bytes(&data, b"DELPHICLASS") || contains_bytes(&data, b"Delphi")
    {
        return "Native (Delphi)".to_string();
    }

    if contains_bytes(&data, b"Qt_") || contains_bytes(&data, b"QApplication") {
        return "Native (Qt/C++)".to_string();
    }

    if contains_bytes(&data, b"_MFCXX") || contains_bytes(&data, b"CWinApp") {
        return "Native (MFC/C++)".to_string();
    }

    "Native".to_string()
}
