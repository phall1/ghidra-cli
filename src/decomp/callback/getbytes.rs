//! `command_getbytes` callback handler.
//!
//! Per `docs/decompiler-protocol.md` §4.2.13, the C++ decompiler asks
//! the host for raw program memory at a virtual address. The request
//! is a PackedEncode element carrying an `addr` (space + offset) and a
//! `size`; the response is the bytes wrapped in a
//! `byte_start`/`byte_end` frame, A-P nibble-encoded
//! (`super::super::nibble`).
//!
//! ### Response shapes
//!
//! On success (host has the bytes):
//!
//! ```text
//! type 8  query_response_start
//!   type 12  byte_start
//!     <A-P encoded bytes>
//!   type 13  byte_end
//! type 9  query_response_end
//! ```
//!
//! On "no data" (loader can't satisfy the read — unmapped address, gap,
//! or any other read error): an empty `query_response` frame, with no
//! `byte_start` inside. This matches the protocol-doc convention noted
//! in §4.1 ("optional payload — ... or nothing if 'not found'") and is
//! how the upstream Java side handles failures from `getBytes`
//! (`DecompileProcess.java:879-896`).
//!
//! ### v1 simplification: structural attribute matching
//!
//! Ghidra's element/attribute name table maps integer ids to symbolic
//! names (`<addr>`, `space`, `offset`, `size`, ...) per namespace.
//! That registry hasn't landed in this crate yet (it will arrive
//! alongside the dispatcher in a follow-up issue). Until it does, this
//! handler matches **structurally** rather than by id: it walks the
//! decoded event stream and picks the first occurring triple of
//!
//! 1. an `AttrValue::AddressSpace` (the address-space index — Ghidra's
//!    `space=` attribute),
//! 2. an `AttrValue::UnsignedInt` (the byte offset within that space),
//! 3. another `AttrValue::UnsignedInt` (the read size).
//!
//! Element open/close events are ignored during the scan. This is
//! correct for every request shape upstream produces today (the C++
//! encoder always emits attributes in `addr`-then-`size` document
//! order), and it lets us land a working handler before the name
//! registry exists. **Revisit when the registry lands** so we can
//! match on real attribute ids and reject malformed requests with
//! unexpected attribute combinations.
//!
//! ### Address-space assumption
//!
//! The `space` attribute is parsed but **ignored**. Phase 3's first
//! vertical slice only supports x86_64 ELF, which exposes exactly one
//! addressable space (`ram`). When PE / Mach-O / multi-space targets
//! land we will need to resolve the space index against the program's
//! space table before dispatching the read.

use std::io::Write;

use anyhow::{anyhow, Context, Result};

use crate::decomp::loader::ElfLoader;
use crate::decomp::nibble;
use crate::decomp::packed::{AttrValue, Decoder};
use crate::decomp::wire::{write_marker, FrameType};

/// Parsed contents of a `command_getbytes` request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
struct GetBytesRequest {
    /// Address-space index (currently unused — see module docs).
    #[allow(dead_code)]
    space: u32,
    /// Virtual byte offset within the address space.
    offset: u64,
    /// Number of bytes the decompiler wants.
    size: u64,
}

/// Handle a `command_getbytes` callback.
///
/// Parses `request_payload` as a PackedEncode stream, calls
/// [`ElfLoader::read_bytes`] for the requested range, and writes the
/// framed response to `out`. See the module docs for the response
/// shape on success vs. "no data".
///
/// Returns an error only on **I/O failures writing to `out`** or on a
/// malformed request that can't be parsed at all (missing space /
/// offset / size attributes). A loader read failure is NOT an error
/// from the caller's perspective — it is communicated to the
/// decompiler as an empty response, which is the protocol's way of
/// saying "no bytes available here".
pub fn handle_getbytes<W: Write>(
    loader: &ElfLoader,
    request_payload: &[u8],
    out: &mut W,
) -> Result<()> {
    let req = parse_request(request_payload).context("parsing command_getbytes request")?;

    // Open the query_response frame regardless of outcome — the
    // decompiler always expects a matched type 8 / type 9 pair.
    write_marker(out, FrameType::QueryResponseStart)?;

    // Conservative upper bound to keep a buggy request from making us
    // allocate gigabytes. The largest legitimate decompiler request
    // we've seen is in the kilobyte range (function instruction
    // window), so 1 MiB is comfortably above the working set without
    // being unbounded.
    const MAX_GETBYTES_LEN: u64 = 1 << 20;

    let read = if req.size == 0 || req.size > MAX_GETBYTES_LEN {
        // Treat oversized / zero requests as "no data" rather than
        // erroring out — same shape as a loader miss.
        Err(())
    } else {
        loader
            .read_bytes(req.offset, req.size as usize)
            .map_err(|_| ())
    };

    if let Ok(bytes) = read {
        write_marker(out, FrameType::ByteStart)?;
        // A-P encode directly into a local buffer, then write in one
        // shot. The encoding never embeds the 0x00 0x00 0x01 frame
        // sentinel (it produces only ASCII 'A'..='P'), so it is safe
        // to drop into the byte frame raw.
        let mut encoded = Vec::with_capacity(bytes.len() * 2);
        nibble::encode_into(&bytes, &mut encoded);
        out.write_all(&encoded)
            .context("writing A-P encoded byte payload")?;
        write_marker(out, FrameType::ByteEnd)?;
    }
    // else: empty response — no byte_start inside the query_response.

    write_marker(out, FrameType::QueryResponseEnd)?;
    Ok(())
}

/// Walk the PackedEncode event stream looking for the
/// `AddressSpace / UnsignedInt / UnsignedInt` triple that carries
/// `(space, offset, size)`. See module docs for why this is
/// structural rather than id-driven.
fn parse_request(payload: &[u8]) -> Result<GetBytesRequest> {
    let mut dec = Decoder::new(payload);
    let mut space: Option<u32> = None;
    let mut offset: Option<u64> = None;
    let mut size: Option<u64> = None;

    while let Some(ev) = dec.next_event()? {
        // Only attribute events carry the values we need. Element
        // open/close are ignored — we'll match against real ids once
        // the namespace registry lands.
        if let crate::decomp::packed::Event::Attribute { value, .. } = ev {
            match value {
                AttrValue::AddressSpace(sp) if space.is_none() => space = Some(sp),
                AttrValue::UnsignedInt(v) if offset.is_none() => offset = Some(v),
                AttrValue::UnsignedInt(v) if size.is_none() => size = Some(v),
                _ => {}
            }
            if space.is_some() && offset.is_some() && size.is_some() {
                break;
            }
        }
    }

    Ok(GetBytesRequest {
        space: space
            .ok_or_else(|| anyhow!("request missing AddressSpace (space) attribute"))?,
        offset: offset
            .ok_or_else(|| anyhow!("request missing UnsignedInt (offset) attribute"))?,
        size: size.ok_or_else(|| anyhow!("request missing UnsignedInt (size) attribute"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decomp::packed::Encoder;
    use crate::decomp::wire::{read_marker, read_until_marker};
    use goblin::elf::program_header::{PF_R, PF_X, PT_LOAD};
    use std::io::Cursor;

    // ---- Test helpers ----------------------------------------------

    /// Build a request payload of the shape:
    /// `<getbytes><addr space=.. offset=../>size=../>` (structural —
    /// element ids are arbitrary placeholders).
    fn make_request(space: u32, offset: u64, size: u64) -> Vec<u8> {
        let mut e = Encoder::new();
        e.open_element(1); // outer <command_getbytes>
        e.open_element(2); // <addr>
        e.attribute_address_space(3, space);
        e.attribute_unsigned_int(4, offset);
        e.close_element(2);
        e.attribute_unsigned_int(5, size);
        e.close_element(1);
        e.finish()
    }

    /// Minimal x86_64 ELF builder, lifted from the loader's tests so
    /// these stay independent. One LOAD segment covering `vaddr` for
    /// `file_data.len()` bytes (no BSS tail).
    fn build_elf(vaddr: u64, file_data: Vec<u8>) -> Vec<u8> {
        const EI_NIDENT: usize = 16;
        const ELF_HEADER_SIZE: usize = 64;
        const PROGRAM_HEADER_SIZE: usize = 56;
        const ET_EXEC: u16 = 2;
        const EM_X86_64: u16 = 62;

        let phdrs_offset = ELF_HEADER_SIZE;
        let phdrs_size = PROGRAM_HEADER_SIZE;
        let seg_offset = (phdrs_offset + phdrs_size) as u64;
        let total = seg_offset as usize + file_data.len();
        let mut image = vec![0u8; total];

        image[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        let mut off = EI_NIDENT;
        image[off..off + 2].copy_from_slice(&ET_EXEC.to_le_bytes());
        off += 2;
        image[off..off + 2].copy_from_slice(&EM_X86_64.to_le_bytes());
        off += 2;
        image[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
        off += 4;
        image[off..off + 8].copy_from_slice(&vaddr.to_le_bytes()); // e_entry
        off += 8;
        image[off..off + 8].copy_from_slice(&(phdrs_offset as u64).to_le_bytes()); // e_phoff
        off += 8;
        image[off..off + 8].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        off += 8;
        image[off..off + 4].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        off += 4;
        image[off..off + 2].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        off += 2;
        image[off..off + 2].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        off += 2;
        image[off..off + 2].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let _ = off;

        let base = phdrs_offset;
        image[base..base + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        image[base + 4..base + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        image[base + 8..base + 16].copy_from_slice(&seg_offset.to_le_bytes());
        image[base + 16..base + 24].copy_from_slice(&vaddr.to_le_bytes());
        image[base + 24..base + 32].copy_from_slice(&vaddr.to_le_bytes());
        image[base + 32..base + 40].copy_from_slice(&(file_data.len() as u64).to_le_bytes());
        image[base + 40..base + 48].copy_from_slice(&(file_data.len() as u64).to_le_bytes());
        image[base + 48..base + 56].copy_from_slice(&0x1000u64.to_le_bytes());

        let start = seg_offset as usize;
        image[start..start + file_data.len()].copy_from_slice(&file_data);
        image
    }

    /// Read a `query_response_start`/`..._end` frame off `cursor` and
    /// return the optional A-P-decoded byte payload between any
    /// `byte_start`/`byte_end` markers inside it. Returns `Ok(None)`
    /// for the empty-response shape.
    fn read_response<R: std::io::Read>(cursor: &mut R) -> Result<Option<Vec<u8>>> {
        let m = read_marker(cursor)?;
        assert_eq!(m, FrameType::QueryResponseStart);
        // Peek next marker.
        let inner = read_marker(cursor)?;
        match inner {
            FrameType::QueryResponseEnd => Ok(None),
            FrameType::ByteStart => {
                let raw = read_until_marker(cursor, FrameType::ByteEnd)?;
                let decoded = nibble::decode(&raw)?;
                // And the closing query_response_end.
                let close = read_marker(cursor)?;
                assert_eq!(close, FrameType::QueryResponseEnd);
                Ok(Some(decoded))
            }
            other => panic!("unexpected marker inside query_response: {other:?}"),
        }
    }

    // ---- Tests -----------------------------------------------------

    #[test]
    fn well_formed_request_returns_byte_frame() {
        // Distinct content so we can tell apart slices.
        let body: Vec<u8> = (0..64u32).map(|x| x as u8).collect();
        let image = build_elf(0x40_0000, body.clone());
        let loader = ElfLoader::from_bytes(image).unwrap();

        let req = make_request(0, 0x40_0010, 8);
        let mut out = Vec::new();
        handle_getbytes(&loader, &req, &mut out).unwrap();

        let mut cur = Cursor::new(out);
        let payload = read_response(&mut cur).unwrap();
        assert_eq!(payload, Some(body[0x10..0x18].to_vec()));
    }

    #[test]
    fn unmapped_request_emits_empty_response() {
        let image = build_elf(0x40_0000, vec![0xCC; 0x100]);
        let loader = ElfLoader::from_bytes(image).unwrap();

        // Address way outside any segment.
        let req = make_request(0, 0x9000_0000, 4);
        let mut out = Vec::new();
        handle_getbytes(&loader, &req, &mut out).unwrap();

        let mut cur = Cursor::new(out);
        assert_eq!(read_response(&mut cur).unwrap(), None);
    }

    #[test]
    fn loader_error_does_not_propagate() {
        // Even a request that straddles a gap should be reported as
        // an empty response, not an error from handle_getbytes.
        let image = build_elf(0x40_0000, vec![0xAA; 0x10]);
        let loader = ElfLoader::from_bytes(image).unwrap();
        let req = make_request(0, 0x40_0008, 0x100);
        let mut out = Vec::new();
        let res = handle_getbytes(&loader, &req, &mut out);
        assert!(res.is_ok());
        let mut cur = Cursor::new(out);
        assert_eq!(read_response(&mut cur).unwrap(), None);
    }

    #[test]
    fn output_round_trips_through_wire_and_nibble_layers() {
        // Wider body so the encoded stream is non-trivial.
        let body: Vec<u8> = (0..200u32).map(|x| (x as u8).wrapping_mul(7)).collect();
        let image = build_elf(0x80_0000, body.clone());
        let loader = ElfLoader::from_bytes(image).unwrap();

        let req = make_request(0, 0x80_0000 + 5, 32);
        let mut out = Vec::new();
        handle_getbytes(&loader, &req, &mut out).unwrap();

        let mut cur = Cursor::new(out);
        let payload = read_response(&mut cur).unwrap().expect("byte frame present");
        assert_eq!(payload, body[5..37]);
    }

    #[test]
    fn output_never_embeds_frame_sentinel() {
        // The A-P-encoded payload is pure ASCII 'A'..='P'; the only
        // 0x00 0x00 0x01 sequences in the output should be the four
        // frame markers themselves (start/byte_start/byte_end/end).
        let body: Vec<u8> = (0u8..=255).collect();
        let image = build_elf(0x10_0000, body);
        let loader = ElfLoader::from_bytes(image).unwrap();

        let req = make_request(0, 0x10_0000, 256);
        let mut out = Vec::new();
        handle_getbytes(&loader, &req, &mut out).unwrap();

        // Strip the four expected markers (their type bytes are 8, 12,
        // 13, 9) and verify the remaining payload bytes have NO
        // 0x00 0x00 0x01 sequence anywhere.
        let markers: &[[u8; 4]] = &[
            [0, 0, 1, FrameType::QueryResponseStart as u8],
            [0, 0, 1, FrameType::ByteStart as u8],
            [0, 0, 1, FrameType::ByteEnd as u8],
            [0, 0, 1, FrameType::QueryResponseEnd as u8],
        ];

        // Walk the output, expecting marker -> payload -> marker -> ...
        let mut i = 0;
        let mut marker_ix = 0;
        let mut payload = Vec::new();
        while i < out.len() {
            if marker_ix < markers.len() && out[i..].starts_with(&markers[marker_ix]) {
                i += 4;
                marker_ix += 1;
            } else {
                payload.push(out[i]);
                i += 1;
            }
        }
        assert_eq!(marker_ix, markers.len(), "didn't see all expected markers");
        assert!(
            !payload.windows(3).any(|w| w == [0x00, 0x00, 0x01]),
            "payload embedded a frame sentinel: {payload:?}"
        );
    }

    #[test]
    fn zero_size_request_emits_empty_response() {
        let image = build_elf(0x40_0000, vec![0xAB; 0x100]);
        let loader = ElfLoader::from_bytes(image).unwrap();
        let req = make_request(0, 0x40_0000, 0);
        let mut out = Vec::new();
        handle_getbytes(&loader, &req, &mut out).unwrap();
        let mut cur = Cursor::new(out);
        assert_eq!(read_response(&mut cur).unwrap(), None);
    }

    #[test]
    fn malformed_request_missing_attrs_errors() {
        // Only space, no offset/size — should fail to parse rather
        // than silently emit anything.
        let mut e = Encoder::new();
        e.open_element(1);
        e.attribute_address_space(3, 0);
        e.close_element(1);
        let payload = e.finish();

        let image = build_elf(0x40_0000, vec![0u8; 0x100]);
        let loader = ElfLoader::from_bytes(image).unwrap();
        let mut out = Vec::new();
        assert!(handle_getbytes(&loader, &payload, &mut out).is_err());
        // And nothing should have been written before the parse error
        // (handler writes only after a successful parse).
        assert!(out.is_empty());
    }
}
