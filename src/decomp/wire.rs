//! Frame-marker layer of the Ghidra decompiler IPC protocol.
//!
//! The wire is a byte stream with 4-byte "alignment burst" markers of
//! the form `0x00 0x00 0x01 <type>`. The leading three bytes are a
//! resync sentinel; the fourth byte identifies the frame kind. There
//! is **no length prefix** — every frame extends until the matching
//! close marker arrives. Self-synchronising but unforgiving: any raw
//! `0x00 0x00 0x01 ??` byte sequence inside a payload would be
//! misinterpreted, which is why callers must use the A-P nibble
//! encoding (see [`super::nibble`]) for raw bytes and PackedEncode
//! (see [`super::packed`]) for structured payloads.
//!
//! See `docs/decompiler-protocol.md` §2 for the full spec and citations
//! into the upstream Ghidra source (`DecompileProcess.java:38-46`,
//! `ghidra_arch.cc:70-85`).
//!
//! This module provides only the framing layer — payload encoding is
//! delegated to sibling modules. Higher-level callback dispatch lives
//! above this.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Context, Result};

/// Frame markers as they appear on the wire.
///
/// The numeric values are the **type byte** of the 4-byte burst
/// (`0x00 0x00 0x01 <type>`). Cross-referenced with
/// `DecompileProcess.java:38-46` for the named Java side and
/// `ghidra_arch.cc` for the C++ side.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// `command_start` — host opens a top-level command frame.
    CommandStart = 2,
    /// `command_end` — close of the top-level command frame.
    CommandEnd = 3,
    /// `query_start` — decompiler opens a callback query.
    QueryStart = 4,
    /// `query_end` — close of the callback query.
    QueryEnd = 5,
    /// Top-level command response open (rarely seen — the C++ side
    /// typically writes the response directly inside string brackets,
    /// see protocol doc §2.5).
    CommandResponseStart = 6,
    /// Top-level command response close.
    CommandResponseEnd = 7,
    /// `query_response_start` — host opens a response to a callback.
    QueryResponseStart = 8,
    /// `query_response_end` — close of the callback response.
    QueryResponseEnd = 9,
    /// `exception_start` — either side opens an exception payload.
    /// Contains two strings (class name, message).
    ExceptionStart = 10,
    /// `exception_end` — close of an exception payload.
    ExceptionEnd = 11,
    /// `byte_start` — opens a raw byte stream, A-P nibble encoded.
    ByteStart = 12,
    /// `byte_end` — close of a byte stream.
    ByteEnd = 13,
    /// `string_start` — opens a string payload (typically a
    /// PackedEncode document, sometimes ASCII text).
    StringStart = 14,
    /// `string_end` — close of a string payload.
    StringEnd = 15,
    /// "Native message" warning open (`ghidra_arch.cc:138-148`).
    WarningStart = 16,
    /// Warning close.
    WarningEnd = 17,
}

impl FrameType {
    /// Try to convert a raw type byte into a `FrameType`. Returns
    /// `None` for any value outside the known 2..=17 range — callers
    /// should treat that as a protocol violation, not skip silently.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            2 => Some(Self::CommandStart),
            3 => Some(Self::CommandEnd),
            4 => Some(Self::QueryStart),
            5 => Some(Self::QueryEnd),
            6 => Some(Self::CommandResponseStart),
            7 => Some(Self::CommandResponseEnd),
            8 => Some(Self::QueryResponseStart),
            9 => Some(Self::QueryResponseEnd),
            10 => Some(Self::ExceptionStart),
            11 => Some(Self::ExceptionEnd),
            12 => Some(Self::ByteStart),
            13 => Some(Self::ByteEnd),
            14 => Some(Self::StringStart),
            15 => Some(Self::StringEnd),
            16 => Some(Self::WarningStart),
            17 => Some(Self::WarningEnd),
            _ => None,
        }
    }

    /// Returns true if this is an "open" marker. Convenient for the
    /// streaming reader to assert frame nesting without hard-coding
    /// the integer values.
    pub fn is_open(self) -> bool {
        matches!(
            self,
            FrameType::CommandStart
                | FrameType::QueryStart
                | FrameType::CommandResponseStart
                | FrameType::QueryResponseStart
                | FrameType::ExceptionStart
                | FrameType::ByteStart
                | FrameType::StringStart
                | FrameType::WarningStart
        )
    }

    /// Returns the matching close marker for an open marker, or
    /// `None` if `self` is itself a close marker. The C++ and Java
    /// sides pair every open with the corresponding close.
    pub fn matching_close(self) -> Option<FrameType> {
        match self {
            FrameType::CommandStart => Some(FrameType::CommandEnd),
            FrameType::QueryStart => Some(FrameType::QueryEnd),
            FrameType::CommandResponseStart => Some(FrameType::CommandResponseEnd),
            FrameType::QueryResponseStart => Some(FrameType::QueryResponseEnd),
            FrameType::ExceptionStart => Some(FrameType::ExceptionEnd),
            FrameType::ByteStart => Some(FrameType::ByteEnd),
            FrameType::StringStart => Some(FrameType::StringEnd),
            FrameType::WarningStart => Some(FrameType::WarningEnd),
            _ => None,
        }
    }
}

/// Sentinel prefix shared by every marker: `0x00 0x00 0x01`.
pub const SENTINEL: [u8; 3] = [0x00, 0x00, 0x01];

/// Write a single frame marker to `w`. Always writes exactly 4 bytes.
pub fn write_marker<W: Write>(w: &mut W, ty: FrameType) -> Result<()> {
    let bytes = [SENTINEL[0], SENTINEL[1], SENTINEL[2], ty as u8];
    w.write_all(&bytes).context("write frame marker")?;
    Ok(())
}

/// Read the next frame marker from `r`. Matches the C++
/// `readToAnyBurst()` semantics from `ghidra_arch.cc:70-85`: consumes
/// any leading non-sentinel bytes silently, then returns the first
/// frame found. Returns an error if the stream ends before a complete
/// marker has been read.
///
/// **Important:** the silent skip is deliberate, matching the upstream
/// behavior, but it also means a malformed stream produces opaque
/// errors arbitrarily later. Callers logging both sides verbatim during
/// bring-up is essential (see protocol doc §6.5).
pub fn read_marker<R: Read>(r: &mut R) -> Result<FrameType> {
    // Slide a 3-byte window across the stream until it matches the
    // sentinel. Implemented as a tiny state machine to avoid pulling
    // a buffer reader dependency into this layer.
    let mut state: u8 = 0; // counts how many sentinel bytes matched
    loop {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)
            .context("read while scanning for frame sentinel")?;
        let b = buf[0];

        match (state, b) {
            // Re-match progress.
            (0, 0) => state = 1,
            (1, 0) => state = 2,
            (2, 1) => state = 3,
            // After 3 sentinel bytes the next byte is the type code.
            (3, ty) => {
                return FrameType::from_byte(ty)
                    .ok_or_else(|| anyhow!("unknown frame type byte: 0x{:02x}", ty));
            }
            // Out-of-sync: fall back to the smallest prefix that's
            // still consistent with the bytes we just saw. The same
            // logic the C++ side uses — leading zeros after a partial
            // match keep the run alive; anything else resets.
            (_, 0) => state = state.max(1),
            _ => state = 0,
        }
    }
}

/// Convenience: read a marker, assert it equals `expected`.
pub fn expect_marker<R: Read>(r: &mut R, expected: FrameType) -> Result<()> {
    let got = read_marker(r)?;
    if got != expected {
        bail!(
            "expected frame marker {:?}, got {:?} (protocol violation)",
            expected,
            got
        );
    }
    Ok(())
}

/// Open / close a `string_start` / `string_end` frame around `payload`.
/// `payload` is written verbatim — the caller is responsible for
/// ensuring it does not contain a raw sentinel byte sequence (use
/// PackedEncode or escape externally).
pub fn write_string_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<()> {
    write_marker(w, FrameType::StringStart)?;
    w.write_all(payload).context("write string payload")?;
    write_marker(w, FrameType::StringEnd)?;
    Ok(())
}

/// Read a `string_start`..`string_end` frame and return the bytes
/// between the markers. Reads byte-by-byte; appropriate for small
/// frames during bring-up but a future optimization could buffer.
pub fn read_string_frame<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    expect_marker(r, FrameType::StringStart)?;
    let payload = read_until_marker(r, FrameType::StringEnd)?;
    Ok(payload)
}

/// Drain `r` until `close` is observed. Returns the bytes consumed
/// between the cursor and the close marker (excluding the marker
/// itself). Used by the string / exception readers.
pub fn read_until_marker<R: Read>(r: &mut R, close: FrameType) -> Result<Vec<u8>> {
    // Greedy scan: copy bytes into `out` until a sentinel match starts;
    // when a candidate marker is fully decoded, branch on whether it
    // equals `close`.
    let mut out = Vec::new();
    let mut state: u8 = 0;
    loop {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)
            .context("read while scanning for close marker")?;
        let b = buf[0];

        match (state, b) {
            (0, 0) => state = 1,
            (1, 0) => state = 2,
            (2, 1) => state = 3,
            (3, ty) => {
                let got = FrameType::from_byte(ty)
                    .ok_or_else(|| anyhow!("unknown frame type byte: 0x{:02x}", ty))?;
                if got == close {
                    return Ok(out);
                }
                bail!(
                    "expected close marker {:?}, got nested {:?} (frame nesting violation)",
                    close,
                    got
                );
            }
            // Pseudo-sentinel that didn't pan out: the bytes we
            // tentatively held were payload. Flush them.
            (s, _) => {
                if s >= 1 {
                    out.push(0);
                }
                if s >= 2 {
                    out.push(0);
                }
                if s >= 3 {
                    out.push(0x01);
                }
                state = 0;
                // The current byte is also payload unless it itself
                // starts a fresh sentinel.
                if b == 0 {
                    state = 1;
                } else {
                    out.push(b);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_roundtrip() {
        for ty in [
            FrameType::CommandStart,
            FrameType::QueryEnd,
            FrameType::StringStart,
            FrameType::ByteEnd,
            FrameType::WarningStart,
        ] {
            assert_eq!(FrameType::from_byte(ty as u8), Some(ty));
        }
        assert_eq!(FrameType::from_byte(0), None);
        assert_eq!(FrameType::from_byte(1), None);
        assert_eq!(FrameType::from_byte(18), None);
    }

    #[test]
    fn open_close_pairing() {
        assert_eq!(
            FrameType::CommandStart.matching_close(),
            Some(FrameType::CommandEnd)
        );
        assert_eq!(
            FrameType::StringStart.matching_close(),
            Some(FrameType::StringEnd)
        );
        // Close markers aren't themselves "open"-able.
        assert_eq!(FrameType::CommandEnd.matching_close(), None);
    }

    #[test]
    fn marker_roundtrip() {
        let mut buf = Vec::new();
        write_marker(&mut buf, FrameType::QueryStart).unwrap();
        assert_eq!(buf, [0x00, 0x00, 0x01, 0x04]);

        let mut cur = std::io::Cursor::new(buf);
        assert_eq!(read_marker(&mut cur).unwrap(), FrameType::QueryStart);
    }

    #[test]
    fn read_marker_skips_leading_garbage() {
        // The C++ side's readToAnyBurst silently consumes leading
        // out-of-frame bytes — we match that behavior.
        let bytes = [0xff, 0xaa, 0x00, 0x00, 0x01, 0x02];
        let mut cur = std::io::Cursor::new(bytes);
        assert_eq!(read_marker(&mut cur).unwrap(), FrameType::CommandStart);
    }

    #[test]
    fn read_marker_recovers_from_partial_sentinel() {
        // 0x00 0x00 then a non-0x01 → resync, find the real sentinel
        // later.
        let bytes = [0x00, 0x00, 0xff, 0x00, 0x00, 0x01, 0x08];
        let mut cur = std::io::Cursor::new(bytes);
        assert_eq!(read_marker(&mut cur).unwrap(), FrameType::QueryResponseStart);
    }

    #[test]
    fn read_marker_rejects_unknown_type() {
        let bytes = [0x00, 0x00, 0x01, 0xfe];
        let mut cur = std::io::Cursor::new(bytes);
        assert!(read_marker(&mut cur).is_err());
    }

    #[test]
    fn read_marker_errors_on_eof() {
        let bytes = [0x00, 0x00, 0x01]; // truncated
        let mut cur = std::io::Cursor::new(bytes);
        assert!(read_marker(&mut cur).is_err());
    }

    #[test]
    fn string_frame_roundtrip_ascii() {
        let mut buf = Vec::new();
        write_string_frame(&mut buf, b"registerProgram").unwrap();

        let mut cur = std::io::Cursor::new(buf);
        let payload = read_string_frame(&mut cur).unwrap();
        assert_eq!(payload, b"registerProgram");
    }

    #[test]
    fn string_frame_roundtrip_empty() {
        let mut buf = Vec::new();
        write_string_frame(&mut buf, b"").unwrap();
        // string_start immediately followed by string_end → 8 bytes.
        assert_eq!(buf.len(), 8);

        let mut cur = std::io::Cursor::new(buf);
        assert!(read_string_frame(&mut cur).unwrap().is_empty());
    }

    #[test]
    fn expect_marker_mismatch_errors() {
        let mut buf = Vec::new();
        write_marker(&mut buf, FrameType::StringEnd).unwrap();
        let mut cur = std::io::Cursor::new(buf);
        assert!(expect_marker(&mut cur, FrameType::StringStart).is_err());
    }

    #[test]
    fn read_until_marker_flushes_pseudo_sentinel_bytes() {
        // Payload contains 0x00 0x00 0x02 — that's two leading
        // sentinel bytes followed by a non-0x01, which is NOT a real
        // marker. The reader must flush those two zeros as payload
        // and keep scanning.
        let mut buf = Vec::new();
        write_marker(&mut buf, FrameType::StringStart).unwrap();
        buf.extend_from_slice(&[0x00, 0x00, 0x02, b'X']);
        write_marker(&mut buf, FrameType::StringEnd).unwrap();

        let mut cur = std::io::Cursor::new(buf);
        let payload = read_string_frame(&mut cur).unwrap();
        assert_eq!(payload, [0x00, 0x00, 0x02, b'X']);
    }
}
