//! A-P nibble byte encoding used inside `byte_start` / `byte_end`
//! frames in the Ghidra decompiler protocol.
//!
//! Each 8-bit byte is rendered as **two ASCII characters in the range
//! `'A'`..=`'P'`**, where each character carries a 4-bit nibble offset
//! from `'A'` (`A=0`, `B=1`, …, `P=15`). The high nibble comes first.
//!
//! Why not standard hex? Hex output uses `0`..`9` and `a`..`f`. None of
//! those are a problem on their own, but Ghidra's wire format also
//! transmits PackedEncode payloads using *high-bit-set* bytes
//! (`0x80`..`0xff`) for opcode/attribute id bytes; mixing the two
//! within the same self-synchronising stream is simpler when "raw
//! bytes" use a fixed printable-ASCII range that PackedEncode never
//! produces. The A-P range was picked precisely because it cannot be
//! confused with PackedEncode bytes or with the `0x00 0x00 0x01`
//! frame sentinel.
//!
//! Reference: `DecompileProcess.java:879-896` (`getBytes` encode) and
//! `ghidra_arch.cc:467-495` (C++ decode). See `docs/decompiler-protocol.md`
//! §2.2 for the cross-cite.

use anyhow::{anyhow, bail, Result};

/// Encode `bytes` into its A-P nibble representation. The result is
/// exactly `2 * bytes.len()` characters of pure ASCII.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(nibble_to_char((b >> 4) & 0x0f));
        out.push(nibble_to_char(b & 0x0f));
    }
    out
}

/// Encode `bytes` directly into `out`. Useful when streaming into a
/// pre-existing buffer (e.g. a `Vec<u8>` for the byte_start/byte_end
/// frame payload).
pub fn encode_into(bytes: &[u8], out: &mut Vec<u8>) {
    out.reserve(bytes.len() * 2);
    for &b in bytes {
        out.push(nibble_to_char((b >> 4) & 0x0f) as u8);
        out.push(nibble_to_char(b & 0x0f) as u8);
    }
}

/// Decode an A-P nibble string back to bytes. Input length must be
/// even and every character must be in `'A'`..=`'P'`. Anything else
/// returns an error — we never silently coerce, since a misframed
/// stream is the kind of bug we want to fail loudly on.
pub fn decode(s: &[u8]) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("A-P encoded payload has odd length {}", s.len());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks_exact(2) {
        let hi = char_to_nibble(pair[0])?;
        let lo = char_to_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[inline]
fn nibble_to_char(n: u8) -> char {
    debug_assert!(n < 16);
    (b'A' + (n & 0x0f)) as char
}

#[inline]
fn char_to_nibble(c: u8) -> Result<u8> {
    if (b'A'..=b'P').contains(&c) {
        Ok(c - b'A')
    } else {
        Err(anyhow!(
            "byte 0x{:02x} ('{}') is not a valid A-P nibble character",
            c,
            c as char
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_known_values() {
        // 0x00 → 'A''A', 0xff → 'P''P', 0xab → 'K''L'
        assert_eq!(encode(&[0x00]), "AA");
        assert_eq!(encode(&[0xff]), "PP");
        assert_eq!(encode(&[0xab]), "KL");
        // Empty
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn roundtrip_random_bytes() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let encoded = encode(&bytes);
        let decoded = decode(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, bytes);
        assert_eq!(encoded.len(), bytes.len() * 2);
        // Output is pure A-P ASCII.
        assert!(encoded.bytes().all(|c| (b'A'..=b'P').contains(&c)));
    }

    #[test]
    fn decode_rejects_odd_length() {
        assert!(decode(b"A").is_err());
        assert!(decode(b"ABC").is_err());
    }

    #[test]
    fn decode_rejects_invalid_chars() {
        // 'Q' is outside the A-P range — common foot-gun if anyone
        // tries to feed hex-encoded data through this path.
        assert!(decode(b"AQ").is_err());
        // Lowercase too.
        assert!(decode(b"aa").is_err());
        // Digits.
        assert!(decode(b"00").is_err());
    }

    #[test]
    fn encode_into_appends() {
        let mut buf = b"prefix:".to_vec();
        encode_into(&[0x12, 0x34], &mut buf);
        assert_eq!(buf, b"prefix:BCDE");
    }

    #[test]
    fn encoded_output_never_contains_sentinel_bytes() {
        // Critical invariant: A-P output must never embed
        // 0x00 0x00 0x01 — that's the frame sentinel. Verified by the
        // range alone (all bytes are 'A'..='P' which is 0x41..=0x50),
        // but we assert it here so the invariant has a test.
        let bytes: Vec<u8> = (0u8..=255).collect();
        let encoded = encode(&bytes);
        assert!(!encoded.as_bytes().windows(3).any(|w| w == [0, 0, 1]));
    }
}
