//! Decompiler callback handlers.
//!
//! When the Rust host drives Ghidra's C++ `decompile` binary, the
//! decompiler interrupts top-level commands with **callback queries**
//! asking the host for program facts (bytes, symbols, p-code, register
//! info, ...). Each module here implements one such callback.
//!
//! All handlers share the same shape: parse a PackedEncode request
//! payload, do some work against the program state, write the framed
//! response back to a `Write` sink. The dispatcher that owns the
//! decompiler's pipe will route incoming query frames to the right
//! handler by command name.
//!
//! See `docs/decompiler-protocol.md` §4 for the full callback table.

pub mod getbytes;
