//! Rust host for Ghidra's C++ decompiler (E7 / Phase 3).
//!
//! Phase 3 of the vision (see `docs/VISION.md`) replaces the Java host
//! that today drives the upstream `decompile` binary with a Rust host.
//! The decompiler itself stays C++ — we only swap out the side of the
//! pipe that supplies bytes, symbols, types, and (pre-translated)
//! p-code.
//!
//! This module groups the protocol primitives:
//!
//! - [`wire`]    — 4-byte alignment-burst frame markers + streaming
//!   reader/writer over arbitrary byte streams.
//! - [`nibble`]  — A-P nibble byte encoding used inside `byte_start` /
//!   `byte_end` frames (where raw `0x00 0x00 0x01 ??` sentinels would
//!   collide with frame markers).
//! - [`packed`]  — Subset of Ghidra's `PackedEncode` / `PackedDecode`
//!   binary attributed-XML format, enough to carry `<addr>`, `<hole>`,
//!   `<commentdb>`, `<tracked_pointset>`, etc.
//!
//! Higher-level pieces (live child-process spawn, callback dispatch,
//! pspec/cspec resolution, SLEIGH-via-Java-bridge for `getpcode`) will
//! layer on top in subsequent E7.2 follow-ups — see the issue notes
//! for the work breakdown.
//!
//! Reference: `docs/decompiler-protocol.md` (E7.1 deliverable).

pub mod nibble;
pub mod packed;
pub mod wire;
