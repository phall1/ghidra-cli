//! Annotation persistence layer (E6).
//!
//! Phase 2 of the project (see docs/VISION.md) keeps reverse-engineering
//! work — function names, signatures, comments, variable renames —
//! attached to *the function itself*, not the binary's address layout.
//! That way a recompiled or relinked binary doesn't lose every rename
//! the analyst paid for.
//!
//! Two building blocks live here:
//!
//! - `hash`: a stable 128-bit fingerprint of a function's raw PCode.
//!   The fingerprint is the join key between binaries (see ADR 0002).
//! - `db`:   the SQLite-backed annotation store. Schema versioning,
//!   row CRUD, and the migration runner (see ADR 0003 once written).
//!
//! The user-facing `ghidra-cli annotate {export,apply,transfer}`
//! commands (E6.3 / E6.4 / E6.6) layer on top of these two modules.

pub mod db;
pub mod hash;
