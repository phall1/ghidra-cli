# ADR 0002: PCode-based function fingerprint

- **Status**: Accepted (initial spike)
- **Date**: 2026-05-19
- **Closes**: ghidra-cli-3f6 (E6.1, spike portion)
- **Related**: E6.2 (DB schema consumes this hash), E6.3/E6.4 (`annotate
  export/apply` flows look up by this hash)

## Context

Phase 2 of the project introduces a persistent annotation database
(E6.2 / E6.4) that survives recompilation: an analyst names
`FUN_00401234` to `parse_packet_header` in build N; build N+1 reorders
sections and the same function lands at `FUN_004015c0`. The annotation
should follow the *function*, not the *address*.

That requires a function identity that is:

1. **Stable** under address changes, section reordering, link-time
   layout differences, and most `-O0`/`-O2` rewrites.
2. **Deterministic** — same function bytes → same hash, every time,
   across machines and Ghidra versions.
3. **Cheap** — we'll fingerprint thousands of functions on `annotate
   export`; sub-millisecond per function is the budget.
4. **Inspectable** — when two functions collide or a fingerprint
   shifts, an analyst should be able to see *which normalization
   step* let them apart or held them together.

Candidate inputs were:

- **Raw instruction bytes** — fastest, completely useless under
  recompilation. Rejected immediately.
- **Mnemonic sequence** — survives some address jitter but breaks
  on instruction selection differences between `-O0` and `-O2`
  (e.g. `MOV EAX,0` vs `XOR EAX,EAX`).
- **PCode (raw)** — Ghidra emits per-instruction PCode that captures
  *semantics*, not encoding. `MOV EAX,0` and `XOR EAX,EAX` both emit
  `COPY const_0 -> EAX` and `INT_XOR EAX,EAX -> EAX` respectively,
  but standard analyzer normalization rewrites the second to a
  COPY-from-zero. Closer to semantics.
- **PCode (high, post-decompiler)** — the decompiler folds optimization
  artifacts and produces SSA-form PCode. Most stable, but ~30x slower
  to compute (must run DecompInterface per function).

We pick **raw PCode with aggressive normalization** as the v1 strategy.
High PCode is the future upgrade path (E6.5 semantic diff) but the
fingerprint should be cheap enough to run on import.

## The fingerprint

For each function:

1. Pull raw PCode via the bridge `pcode_function {high: false}` call.
   This returns a `pcode: [{mnemonic, opcode, output, inputs[]}]` list.
2. Normalize each op (see below).
3. Concatenate the normalized op stream as canonical bytes.
4. Hash with **MD5 → 128-bit ID**. MD5 is not cryptographically secure
   but is dependency-free (already in our tree for `project_hash`),
   stable, and collision resistance is not a security property here —
   only stability is. If the database ever needs tamper-evident hashes,
   we swap in `blake3`.

### Normalization rules

For each PCode op we keep:

- `opcode` (integer) — the operation identity (COPY, INT_ADD,
  CALL, etc.). The string `mnemonic` is redundant with `opcode` and is
  dropped to avoid divergence between Ghidra versions that rename
  mnemonics.

For each Varnode (output + each input):

| Original kind        | Normalized representation        | Why |
|----------------------|----------------------------------|-----|
| `register`           | `R:<name>:<size>`                | Architectural identity is stable. |
| `stack`              | `S:<size>`                       | Stack offsets shift with frame layout; we keep only size. |
| `unique`             | `U:<seq-id>:<size>`              | "Unique" is the decompiler's temp pool — compiler-specific names. Replace with a per-function sequential ID so within-function aliasing is preserved but the names don't leak. |
| `constant` (small)   | `C:<value>:<size>`               | Small constants (< 0x1000) are usually real magic numbers or shift amounts and carry semantic weight. |
| `constant` (large)   | `C:LARGE:<size>`                 | Large constants are almost always linked addresses (string pointers, jump tables, GOT entries) which differ between builds. Bucket. |
| `ram`                | `M:<size>`                       | Absolute memory addresses move under PIE/ASLR/relink. Strip the offset, keep size. |
| anything else        | `?:<size>`                       | Future-proof catch-all. |

Output varnodes that don't exist are written as the literal byte `.`.

### What this catches

- ✅ Renamed FUN_xxxxxxxx → real_name (address-only changes)
- ✅ Same function compiled to a different absolute address
- ✅ `mov eax,0` vs `xor eax,eax` (raw PCode emits different but
  decompiler-canonicalized PCode would coalesce; we accept this is a
  weak spot — high-PCode upgrade closes it)
- ✅ Constants that are "real" (loop counts, shift amounts)
- ✅ Section reordering, link order changes, debug-info presence

### What this misses (v1)

- ❌ Instruction-selection differences from `-O0` → `-O2` that
  *don't* round-trip to identical raw PCode
- ❌ Inlining (the inlined function's body becomes part of the caller
  and hashes differently in both directions)
- ❌ Significant register allocator changes that re-order independent ops

These are the targets for the **high-PCode upgrade path**: rehash via
`pcode_function {high: true}` once we want sub-1% false-negative rates
across optimization levels. For v1, the bias is toward false negatives
(annotation not transferred) rather than false positives (wrong
annotation applied) — the analyst can always re-apply manually.

## API shape

```rust
// src/annotate/hash.rs

pub fn fingerprint(pcode_response: &serde_json::Value) -> Result<u128>;
pub fn fingerprint_hex(pcode_response: &serde_json::Value) -> Result<String>;
```

Takes the `serde_json::Value` returned by `BridgeClient::pcode_function`
verbatim — no separate parsing step. Returns either the raw 128-bit
integer or the conventional zero-padded lowercase hex (32 chars), which
is what the SQLite schema stores.

## Open questions for v2

1. **Cross-architecture stability.** Same C function compiled for
   x86_64 vs aarch64 should arguably produce *different* hashes — they
   have different semantics at the PCode level (register sizes, calling
   conventions). v1 makes no special accommodation; this is the right
   default but worth re-examining when the cross-binary diff work
   (E6.5) lands.

2. **Tail-call deduplication.** A function ending in a tail-call has
   PCode that ends with `BRANCH <target>` instead of `RETURN`. Today
   we just hash what we see; a more sophisticated normalization could
   canonicalize tail-calls into returns.

3. **Inlining heuristics.** Detecting that function B in build N is
   the inlined body of function A in build N+1 is a research problem.
   v1 does not attempt it.
