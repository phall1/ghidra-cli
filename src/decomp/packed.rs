//! PackedEncode / PackedDecode binary attributed-XML codec.
//!
//! Ghidra's decompiler IPC layer carries structured payloads (addresses,
//! comment databases, register descriptions, p-code emit, …) as
//! PackedEncode documents — a compact binary serialization of attributed
//! XML element trees. This module implements the **codec only**; the
//! element/attribute *name tables* (which integer id means
//! `<addr>` vs `<hole>` vs `<commentdb>`) are namespace-specific and
//! resolved by callers further up the stack.
//!
//! Reference: `Ghidra/Features/Decompiler/src/decompile/cpp/marshal.{hh,cc}`
//! upstream. The bit layout below matches the constants in `marshal.hh`
//! verbatim.
//!
//! Document structure (no header, no footer — pure record stream):
//!
//! - **Header byte** of every record: `[2-bit type | 1-bit extend | 5-bit id]`.
//! - Type codes: `01` = element-open, `10` = element-close, `11` = attribute.
//! - If the id is ≥ 0x20, the extend bit is set and the next byte is a
//!   continuation carrying the remaining 7 bits.
//! - After an attribute header comes a **type byte**: `[4-bit type | 4-bit length code]`.
//! - Attribute value types: 1=bool, 2=+int, 3=-int, 4=uint, 5=basic
//!   address space, 6=special address space, 7=string.
//! - Integer payload bytes are 7-bit data + high-bit marker (`0x80 | data`).
//! - Strings: length-coded unsigned int, then raw UTF-8 bytes.
//!
//! The codec is intentionally low-level — we don't try to model the
//! full Ghidra element graph here. Higher layers pick element/attribute
//! ids out of generated tables (see ADR-to-be on the registry approach)
//! and feed them through `Encoder::open_element(id)` etc.

use anyhow::{anyhow, bail, Context, Result};

// === Header-byte layout ===

/// Mask isolating the 2-bit record-type field in a header byte.
pub const HEADER_MASK: u8 = 0xc0;
/// Bit indicating the id overflows into a continuation byte.
pub const HEADEREXTEND_MASK: u8 = 0x20;
/// Mask isolating the inline 5-bit id field.
pub const ELEMENTID_MASK: u8 = 0x1f;

/// Header byte for `<elem>` open.
pub const ELEMENT_START: u8 = 0x40;
/// Header byte for `</elem>` close.
pub const ELEMENT_END: u8 = 0x80;
/// Header byte for an attribute record.
pub const ATTRIBUTE: u8 = 0xc0;

// === Continuation / data byte layout ===

/// Mask isolating the 7-bit data field in a continuation byte.
pub const RAWDATA_MASK: u8 = 0x7f;
/// High-bit marker required on every continuation / data byte.
pub const RAWDATA_MARKER: u8 = 0x80;
/// Number of data bits per continuation byte (7).
pub const RAWDATA_BITSPERBYTE: u32 = 7;

// === Attribute type byte layout ===

const TYPECODE_SHIFT: u8 = 4;
const LENGTHCODE_MASK: u8 = 0x0f;

const TYPECODE_BOOLEAN: u8 = 1;
const TYPECODE_SIGNEDINT_POSITIVE: u8 = 2;
const TYPECODE_SIGNEDINT_NEGATIVE: u8 = 3;
const TYPECODE_UNSIGNEDINT: u8 = 4;
const TYPECODE_ADDRESSSPACE: u8 = 5;
const TYPECODE_SPECIALSPACE: u8 = 6;
const TYPECODE_STRING: u8 = 7;

// === Special address-space encodings (4-bit "length" field for type 6) ===

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialSpace {
    Stack = 0,
    Join = 1,
    Fspec = 2,
    Iop = 3,
    Spacebase = 4,
}

impl SpecialSpace {
    fn from_u8(n: u8) -> Result<Self> {
        Ok(match n {
            0 => Self::Stack,
            1 => Self::Join,
            2 => Self::Fspec,
            3 => Self::Iop,
            4 => Self::Spacebase,
            other => bail!("unknown special address-space code {}", other),
        })
    }
}

/// A single value carried by an attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Bool(bool),
    /// Signed integers fit in i64 in every Ghidra-generated payload
    /// we've observed. If a value ever overflows we'd need to widen
    /// to i128, but the upstream encoder caps at 64 bits today.
    SignedInt(i64),
    UnsignedInt(u64),
    /// Index into the registered "basic" address-space list (the
    /// `<space>` table inside a pspec). Resolution happens elsewhere.
    AddressSpace(u32),
    SpecialSpace(SpecialSpace),
    String(String),
}

/// Streaming-decode events. `id` is the inline + continuation-decoded
/// element or attribute id; callers map id → name via their own table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    ElementStart { id: u32 },
    ElementEnd { id: u32 },
    Attribute { id: u32, value: AttrValue },
}

// ============================================================================
// Encoder
// ============================================================================

/// Append-only PackedEncode writer. Callers drive a tree by interleaving
/// `open_element` / `attribute_*` / `close_element` calls. The writer
/// is byte-only and does not validate well-formedness across calls —
/// that's a caller responsibility (mirrors the upstream encoder's
/// behavior).
#[derive(Default, Debug)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume the encoder and return the underlying bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the in-progress buffer (for streaming into a frame
    /// writer without an extra copy).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Write an element-open header.
    pub fn open_element(&mut self, id: u32) {
        write_header(&mut self.buf, ELEMENT_START, id);
    }

    /// Write an element-close header. Caller is responsible for
    /// matching the id with the corresponding open.
    pub fn close_element(&mut self, id: u32) {
        write_header(&mut self.buf, ELEMENT_END, id);
    }

    pub fn attribute_bool(&mut self, id: u32, value: bool) {
        write_header(&mut self.buf, ATTRIBUTE, id);
        // Bool packs the value into the length nibble; no payload bytes.
        let type_byte = (TYPECODE_BOOLEAN << TYPECODE_SHIFT) | (value as u8);
        self.buf.push(type_byte);
    }

    pub fn attribute_signed_int(&mut self, id: u32, value: i64) {
        write_header(&mut self.buf, ATTRIBUTE, id);
        if value >= 0 {
            write_integer_attr(&mut self.buf, TYPECODE_SIGNEDINT_POSITIVE, value as u64);
        } else {
            // Spec: negative integers are stored as their negation
            // under typecode 3. `i64::MIN` would overflow `-value`, so
            // we go through unsigned arithmetic to handle that edge.
            let negated = (value as i128).unsigned_abs() as u64;
            write_integer_attr(&mut self.buf, TYPECODE_SIGNEDINT_NEGATIVE, negated);
        }
    }

    pub fn attribute_unsigned_int(&mut self, id: u32, value: u64) {
        write_header(&mut self.buf, ATTRIBUTE, id);
        write_integer_attr(&mut self.buf, TYPECODE_UNSIGNEDINT, value);
    }

    pub fn attribute_address_space(&mut self, id: u32, space_index: u32) {
        write_header(&mut self.buf, ATTRIBUTE, id);
        write_integer_attr(&mut self.buf, TYPECODE_ADDRESSSPACE, space_index as u64);
    }

    pub fn attribute_special_space(&mut self, id: u32, space: SpecialSpace) {
        write_header(&mut self.buf, ATTRIBUTE, id);
        // Special-space code rides in the length nibble of the type byte.
        let type_byte = (TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | (space as u8);
        self.buf.push(type_byte);
    }

    pub fn attribute_string(&mut self, id: u32, value: &str) {
        write_header(&mut self.buf, ATTRIBUTE, id);
        let bytes = value.as_bytes();
        write_integer_attr(&mut self.buf, TYPECODE_STRING, bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
    }
}

fn write_header(buf: &mut Vec<u8>, record_type: u8, id: u32) {
    if id <= ELEMENTID_MASK as u32 {
        buf.push(record_type | (id as u8 & ELEMENTID_MASK));
    } else {
        // Extend bit: lower 5 bits of id ride in the header, the
        // upper bits go into one continuation byte (the format
        // supports more but Ghidra never produces ids above ~32-bit
        // range, and a single continuation byte covers any id < 4096
        // — well above the populated range).
        buf.push(record_type | HEADEREXTEND_MASK | (id as u8 & ELEMENTID_MASK));
        let continuation = (id >> 5) as u8 & RAWDATA_MASK;
        buf.push(continuation | RAWDATA_MARKER);
    }
}

fn write_integer_attr(buf: &mut Vec<u8>, type_code: u8, value: u64) {
    // Encode the value as a series of 7-bit data bytes, most
    // significant first. Strip leading zero bytes so the length code
    // reflects only meaningful bytes.
    let mut data = [0u8; 10]; // 64 bits / 7 bits per byte → ceil 10
    let mut len = 0;
    let mut v = value;
    // Walk LSB-first into the buffer, then reverse.
    if v == 0 {
        // Length code 0, no payload bytes.
        let type_byte = type_code << TYPECODE_SHIFT;
        buf.push(type_byte);
        return;
    }
    while v != 0 {
        data[len] = (v as u8 & RAWDATA_MASK) | RAWDATA_MARKER;
        v >>= RAWDATA_BITSPERBYTE;
        len += 1;
    }
    // Length code is 4 bits — would overflow for values needing > 15
    // data bytes, but 64-bit ints cap at 10 so we're well within
    // range.
    debug_assert!(len <= 15);
    let type_byte = (type_code << TYPECODE_SHIFT) | (len as u8 & LENGTHCODE_MASK);
    buf.push(type_byte);
    // Reverse-emit so MSB comes first.
    for i in (0..len).rev() {
        buf.push(data[i]);
    }
}

// ============================================================================
// Decoder
// ============================================================================

/// Streaming PackedEncode reader. Decodes one [`Event`] per call to
/// [`Decoder::next`] until the stream is exhausted, at which point it
/// returns `Ok(None)`. Tracks no nesting state — callers compose that
/// on top.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Bytes remaining in the input stream.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub fn is_eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Decode the next event. Returns `Ok(None)` at clean EOF;
    /// returns `Err` on a truncated or invalid record.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        if self.is_eof() {
            return Ok(None);
        }
        let header = self.read_u8().context("read record header")?;
        let record_type = header & HEADER_MASK;
        let id = self.decode_id(header)?;

        match record_type {
            ELEMENT_START => Ok(Some(Event::ElementStart { id })),
            ELEMENT_END => Ok(Some(Event::ElementEnd { id })),
            ATTRIBUTE => {
                let value = self.read_attribute_value()?;
                Ok(Some(Event::Attribute { id, value }))
            }
            other => bail!(
                "invalid record type 0x{:02x} at offset {}",
                other,
                self.pos - 1
            ),
        }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.is_eof() {
            bail!("unexpected EOF in PackedEncode stream at offset {}", self.pos);
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn decode_id(&mut self, header: u8) -> Result<u32> {
        let inline = (header & ELEMENTID_MASK) as u32;
        if header & HEADEREXTEND_MASK == 0 {
            return Ok(inline);
        }
        // Extend bit set: one continuation byte carries the high bits.
        // Ghidra's format technically allows multi-byte continuations
        // for very large ids, but in practice ids are bounded and one
        // byte suffices. We accept any number of marker-set bytes for
        // forward-compat.
        // Single continuation byte is the format Ghidra emits in
        // practice — ids in the populated namespace cap at a few
        // thousand. Multi-byte continuations would need a different
        // sentinel rule (the high-bit-marker on every data byte
        // doesn't itself signal "more to come"), so we lock to one
        // byte. If a future upstream ever produces a multi-byte id
        // we'll see it as a decode error and revisit.
        let b = self.read_u8().context("read id continuation byte")?;
        if b & RAWDATA_MARKER == 0 {
            bail!(
                "id continuation byte 0x{:02x} missing high-bit marker",
                b
            );
        }
        let id = inline | (((b & RAWDATA_MASK) as u32) << 5);
        Ok(id)
    }

    fn read_attribute_value(&mut self) -> Result<AttrValue> {
        let type_byte = self.read_u8().context("read attribute type byte")?;
        let type_code = type_byte >> TYPECODE_SHIFT;
        let length_code = type_byte & LENGTHCODE_MASK;
        match type_code {
            TYPECODE_BOOLEAN => Ok(AttrValue::Bool(length_code != 0)),
            TYPECODE_SIGNEDINT_POSITIVE => {
                Ok(AttrValue::SignedInt(self.read_integer_bytes(length_code)? as i64))
            }
            TYPECODE_SIGNEDINT_NEGATIVE => {
                // Stored negated.
                let v = self.read_integer_bytes(length_code)? as i64;
                Ok(AttrValue::SignedInt(-v))
            }
            TYPECODE_UNSIGNEDINT => Ok(AttrValue::UnsignedInt(self.read_integer_bytes(length_code)?)),
            TYPECODE_ADDRESSSPACE => Ok(AttrValue::AddressSpace(
                self.read_integer_bytes(length_code)? as u32,
            )),
            TYPECODE_SPECIALSPACE => Ok(AttrValue::SpecialSpace(SpecialSpace::from_u8(length_code)?)),
            TYPECODE_STRING => {
                let len = self.read_integer_bytes(length_code)? as usize;
                if self.pos + len > self.bytes.len() {
                    bail!(
                        "string attribute claims {} bytes but only {} remain",
                        len,
                        self.bytes.len() - self.pos
                    );
                }
                let s = std::str::from_utf8(&self.bytes[self.pos..self.pos + len])
                    .map_err(|e| anyhow!("string attribute is not valid UTF-8: {}", e))?
                    .to_owned();
                self.pos += len;
                Ok(AttrValue::String(s))
            }
            other => bail!("unknown attribute type code {}", other),
        }
    }

    fn read_integer_bytes(&mut self, length_code: u8) -> Result<u64> {
        // Length code 0 → value 0, no payload bytes consumed.
        let mut value: u64 = 0;
        for _ in 0..length_code {
            let b = self.read_u8().context("read integer payload byte")?;
            if b & RAWDATA_MARKER == 0 {
                bail!(
                    "integer payload byte 0x{:02x} missing high-bit marker",
                    b
                );
            }
            value = (value << RAWDATA_BITSPERBYTE) | (b & RAWDATA_MASK) as u64;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the encoder + decoder and collect every event.
    fn roundtrip(buf: &[u8]) -> Vec<Event> {
        let mut dec = Decoder::new(buf);
        let mut events = Vec::new();
        while let Some(ev) = dec.next_event().unwrap() {
            events.push(ev);
        }
        events
    }

    #[test]
    fn element_open_close_inline_id() {
        let mut e = Encoder::new();
        e.open_element(7);
        e.close_element(7);
        let buf = e.finish();
        // Header bytes: ELEMENT_START(0x40) | 7 = 0x47, then
        // ELEMENT_END(0x80) | 7 = 0x87.
        assert_eq!(buf, [0x47, 0x87]);

        assert_eq!(
            roundtrip(&buf),
            vec![
                Event::ElementStart { id: 7 },
                Event::ElementEnd { id: 7 },
            ]
        );
    }

    #[test]
    fn element_id_uses_extend_byte_above_31() {
        let mut e = Encoder::new();
        e.open_element(42); // 0x2a = 0b00101010 — 5 low bits = 0x0a, high = 1
        let buf = e.finish();
        // ELEMENT_START | HEADEREXTEND | (42 & 0x1f) = 0x40 | 0x20 | 0x0a = 0x6a
        // Continuation: (42 >> 5) | 0x80 = 0x01 | 0x80 = 0x81
        assert_eq!(buf, [0x6a, 0x81]);
        assert_eq!(
            roundtrip(&buf),
            vec![Event::ElementStart { id: 42 }]
        );
    }

    #[test]
    fn bool_attribute_roundtrip() {
        let mut e = Encoder::new();
        e.attribute_bool(3, true);
        e.attribute_bool(3, false);
        let events = roundtrip(&e.finish());
        assert_eq!(
            events,
            vec![
                Event::Attribute { id: 3, value: AttrValue::Bool(true) },
                Event::Attribute { id: 3, value: AttrValue::Bool(false) },
            ]
        );
    }

    #[test]
    fn unsigned_int_roundtrip_small() {
        let mut e = Encoder::new();
        e.attribute_unsigned_int(5, 0);
        e.attribute_unsigned_int(5, 1);
        e.attribute_unsigned_int(5, 0x7f);
        e.attribute_unsigned_int(5, 0x80); // exactly one byte boundary
        let events = roundtrip(&e.finish());
        assert_eq!(
            events,
            vec![
                Event::Attribute { id: 5, value: AttrValue::UnsignedInt(0) },
                Event::Attribute { id: 5, value: AttrValue::UnsignedInt(1) },
                Event::Attribute { id: 5, value: AttrValue::UnsignedInt(0x7f) },
                Event::Attribute { id: 5, value: AttrValue::UnsignedInt(0x80) },
            ]
        );
    }

    #[test]
    fn unsigned_int_roundtrip_full_u64() {
        let mut e = Encoder::new();
        e.attribute_unsigned_int(5, 0xdead_beef_cafe_babe);
        e.attribute_unsigned_int(5, u64::MAX);
        let events = roundtrip(&e.finish());
        assert_eq!(
            events,
            vec![
                Event::Attribute {
                    id: 5,
                    value: AttrValue::UnsignedInt(0xdead_beef_cafe_babe),
                },
                Event::Attribute {
                    id: 5,
                    value: AttrValue::UnsignedInt(u64::MAX),
                },
            ]
        );
    }

    #[test]
    fn signed_int_negative_roundtrip() {
        let mut e = Encoder::new();
        e.attribute_signed_int(1, -1);
        e.attribute_signed_int(1, -42);
        e.attribute_signed_int(1, 42);
        let events = roundtrip(&e.finish());
        assert_eq!(
            events,
            vec![
                Event::Attribute { id: 1, value: AttrValue::SignedInt(-1) },
                Event::Attribute { id: 1, value: AttrValue::SignedInt(-42) },
                Event::Attribute { id: 1, value: AttrValue::SignedInt(42) },
            ]
        );
    }

    #[test]
    fn string_roundtrip() {
        let mut e = Encoder::new();
        e.attribute_string(11, "");
        e.attribute_string(11, "hello");
        e.attribute_string(11, "non-ascii: π λ ✓");
        let events = roundtrip(&e.finish());
        assert_eq!(
            events,
            vec![
                Event::Attribute { id: 11, value: AttrValue::String("".into()) },
                Event::Attribute { id: 11, value: AttrValue::String("hello".into()) },
                Event::Attribute {
                    id: 11,
                    value: AttrValue::String("non-ascii: π λ ✓".into())
                },
            ]
        );
    }

    #[test]
    fn special_space_roundtrip() {
        let mut e = Encoder::new();
        e.attribute_special_space(2, SpecialSpace::Stack);
        e.attribute_special_space(2, SpecialSpace::Fspec);
        let events = roundtrip(&e.finish());
        assert_eq!(
            events,
            vec![
                Event::Attribute { id: 2, value: AttrValue::SpecialSpace(SpecialSpace::Stack) },
                Event::Attribute { id: 2, value: AttrValue::SpecialSpace(SpecialSpace::Fspec) },
            ]
        );
    }

    #[test]
    fn address_space_roundtrip() {
        let mut e = Encoder::new();
        e.attribute_address_space(6, 0);
        e.attribute_address_space(6, 12345);
        let events = roundtrip(&e.finish());
        assert_eq!(
            events,
            vec![
                Event::Attribute { id: 6, value: AttrValue::AddressSpace(0) },
                Event::Attribute { id: 6, value: AttrValue::AddressSpace(12345) },
            ]
        );
    }

    #[test]
    fn nested_element_with_attrs() {
        // Build the equivalent of: <outer><inner attr=42/></outer>
        let mut e = Encoder::new();
        e.open_element(1); // <outer>
        e.open_element(2); // <inner>
        e.attribute_unsigned_int(3, 42);
        e.close_element(2);
        e.close_element(1);
        let events = roundtrip(&e.finish());
        assert_eq!(
            events,
            vec![
                Event::ElementStart { id: 1 },
                Event::ElementStart { id: 2 },
                Event::Attribute { id: 3, value: AttrValue::UnsignedInt(42) },
                Event::ElementEnd { id: 2 },
                Event::ElementEnd { id: 1 },
            ]
        );
    }

    #[test]
    fn decoder_eof_returns_none() {
        let mut dec = Decoder::new(&[]);
        assert!(dec.next_event().unwrap().is_none());
    }

    #[test]
    fn decoder_rejects_missing_marker_on_payload() {
        // Attribute(id=0, type=uint, length=1) but payload byte has
        // no high-bit marker.
        let bad = [0xc0, 0x41, 0x05];
        let mut dec = Decoder::new(&bad);
        assert!(dec.next_event().is_err());
    }

    #[test]
    fn decoder_rejects_truncated_string() {
        // Attribute(id=0, type=string, length=1, claimed-len=10) with
        // only 3 payload bytes.
        let mut e = Encoder::new();
        e.attribute_string(0, "hello, world");
        let mut bytes = e.finish();
        bytes.truncate(bytes.len() - 5); // chop the tail
        let mut dec = Decoder::new(&bytes);
        assert!(dec.next_event().is_err());
    }

    #[test]
    fn decoder_rejects_invalid_utf8() {
        // Hand-craft: ATTRIBUTE(id=0) + STRING type(7) length(1) +
        // length byte 0x82 (value 2) + 0xff 0xfe (not valid UTF-8).
        let bad = [0xc0, 0x71, 0x82, 0xff, 0xfe];
        let mut dec = Decoder::new(&bad);
        assert!(dec.next_event().is_err());
    }

    #[test]
    fn output_never_emits_frame_sentinel() {
        // Critical: a PackedEncode buffer must never contain
        // 0x00 0x00 0x01 because that's the wire-layer sentinel.
        // Verified by construction (every record byte has bit 6 or
        // 7 set), but we assert here so the invariant is pinned.
        let mut e = Encoder::new();
        for id in 0u32..200 {
            e.open_element(id);
            e.attribute_unsigned_int(id, id as u64 * 0x10001);
            e.attribute_string(id, "abc");
            e.attribute_bool(id, id % 2 == 0);
            e.close_element(id);
        }
        let buf = e.finish();
        assert!(!buf.windows(3).any(|w| w == [0x00, 0x00, 0x01]));
        // Stronger: every byte has at least one of bits 6,7 set
        // (header bytes 0x40/0x80/0xc0 → bit 6 or 7 set; type bytes
        // 0x10..0x7f for low typecodes also keep bit 4-6 in play;
        // data bytes carry RAWDATA_MARKER=0x80). We assert no byte
        // is 0x00 specifically.
        assert!(!buf.contains(&0x00));
    }
}
