//! PCode-based function fingerprint (E6.1 / ghidra-cli-3f6).
//!
//! Produces a 128-bit ID for a function from the JSON returned by
//! `BridgeClient::pcode_function`. The hash is intended to be stable
//! across recompilation, relinking, and trivial optimization changes
//! within an architecture. The full rationale and normalization rules
//! live in `docs/adr/0002-function-fingerprint.md`.
//!
//! API:
//!
//! ```ignore
//! let pcode = client.pcode_function("main", false)?;
//! let id_hex = ghidra_cli::annotate::hash::fingerprint_hex(&pcode)?;
//! // id_hex is a 32-char lowercase hex string; this is the join key
//! // used by the annotation DB.
//! ```

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

/// Constants below this threshold are treated as "real" semantic values
/// (shift amounts, small loop bounds, magic numbers). Constants above
/// this threshold are almost always linked addresses and get bucketed
/// to a placeholder so layout changes don't break the fingerprint.
const SMALL_CONSTANT_MAX: u64 = 0x1000;

/// Compute the 128-bit fingerprint of a function's raw PCode. Input is
/// the `serde_json::Value` returned by `BridgeClient::pcode_function`
/// (either the raw or high level — high-PCode just gives a different
/// stability profile, see ADR 0002).
pub fn fingerprint(pcode_response: &Value) -> Result<u128> {
    let canonical = canonicalize(pcode_response)?;
    let digest = md5::compute(canonical.as_bytes());
    Ok(u128::from_be_bytes(digest.0))
}

/// Same as [`fingerprint`] but returns the canonical 32-char lowercase
/// hex form that the annotation DB stores.
pub fn fingerprint_hex(pcode_response: &Value) -> Result<String> {
    Ok(format!("{:032x}", fingerprint(pcode_response)?))
}

/// Build the canonical normalized byte stream that gets fed to the
/// hasher. Exposed only for tests + the (future) `ghidra-cli annotate
/// debug-hash` subcommand that prints what's being hashed for
/// triage.
pub(crate) fn canonicalize(pcode_response: &Value) -> Result<String> {
    let ops = pcode_response
        .get("pcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("pcode_response is missing the `pcode` array"))?;

    // Sequential IDs for unique-space varnodes. The names Ghidra assigns
    // ("unique:0x1280", "unique:0x1300") are compiler-temp pool slots
    // that drift between Ghidra versions and optimization levels. We
    // preserve *aliasing* (the same temp used twice in the same function
    // hashes to the same ID) by interning on first sight.
    let mut unique_ids: HashMap<String, u32> = HashMap::new();
    let mut next_unique: u32 = 0;

    let mut out = String::with_capacity(ops.len() * 32);

    for op in ops {
        // opcode (integer) is the operation identity. We deliberately
        // ignore the human-readable `mnemonic` string — opcode is
        // language-binding-stable; mnemonic gets renamed across Ghidra
        // releases (e.g. PCODE OP rename in 11.x → 12.x).
        let opcode = op
            .get("opcode")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("pcode op missing integer opcode"))?;
        out.push_str(&format!("O{};", opcode));

        // Output varnode — may be null for ops like BRANCH/RETURN.
        match op.get("output") {
            Some(Value::Null) | None => out.push_str(".;"),
            Some(vn) => {
                normalize_varnode(vn, &mut unique_ids, &mut next_unique, &mut out)?;
                out.push(';');
            }
        }

        // Input varnodes.
        let inputs = op
            .get("inputs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("pcode op missing inputs array"))?;
        for vn in inputs {
            normalize_varnode(vn, &mut unique_ids, &mut next_unique, &mut out)?;
            out.push(',');
        }
        out.push('|');
    }

    Ok(out)
}

fn normalize_varnode(
    vn: &Value,
    unique_ids: &mut HashMap<String, u32>,
    next_unique: &mut u32,
    out: &mut String,
) -> Result<()> {
    let kind = vn
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("varnode missing type"))?;
    let size = vn
        .get("size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    match kind {
        "register" => {
            // Use the register *name* (architectural, stable) rather
            // than the (space, offset) tuple (Ghidra-internal, may
            // shift across versions).
            let name = vn
                .get("register")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            out.push_str(&format!("R:{}:{}", name, size));
        }
        "stack" => {
            // Stack offsets are frame-layout dependent and shift under
            // recompilation. Keep size only.
            out.push_str(&format!("S:{}", size));
        }
        "unique" => {
            // Intern the (space, offset) tuple so the same temp
            // referenced multiple times in the function gets the same
            // ID — preserves intra-function aliasing without leaking
            // compiler-pool names.
            let key = varnode_identity(vn);
            let id = *unique_ids.entry(key).or_insert_with(|| {
                let v = *next_unique;
                *next_unique += 1;
                v
            });
            out.push_str(&format!("U:{}:{}", id, size));
        }
        "constant" => {
            let value = parse_hex_offset(vn).unwrap_or(0);
            if value <= SMALL_CONSTANT_MAX {
                out.push_str(&format!("C:{}:{}", value, size));
            } else {
                // Large constants are almost always linked addresses;
                // bucket so they don't break the fingerprint under
                // relocation.
                out.push_str(&format!("C:LARGE:{}", size));
            }
        }
        "ram" => {
            // RAM addresses move under PIE/ASLR/relink. Strip the
            // address; keep only the access size.
            out.push_str(&format!("M:{}", size));
        }
        other => {
            // Forward compatibility: any new varnode kind hashes as
            // its type tag + size so a Ghidra upgrade that introduces
            // a new kind doesn't crash the hasher.
            out.push_str(&format!("?{}:{}", other, size));
        }
    }
    Ok(())
}

/// Build a stable identity string for a varnode that's used to dedupe
/// references to the same unique-space slot. We use space + offset
/// (the raw Ghidra coordinates) since within a single function those
/// stay consistent op-to-op.
fn varnode_identity(vn: &Value) -> String {
    let space = vn
        .get("space")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let offset = vn
        .get("offset")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    format!("{}@{}", space, offset)
}

/// Varnode offsets come over the wire as hex strings ("0x401000",
/// "0x0"). Parse to u64, tolerating absence (returns 0).
fn parse_hex_offset(vn: &Value) -> Result<u64> {
    let s = vn
        .get("offset")
        .and_then(|v| v.as_str())
        .context("offset missing")?;
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(stripped, 16).context("offset not valid hex")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn op(opcode: i64, output: Value, inputs: Value) -> Value {
        json!({
            "mnemonic": "?",
            "opcode": opcode,
            "output": output,
            "inputs": inputs,
        })
    }

    fn reg(name: &str, size: u64) -> Value {
        json!({
            "space": "register",
            "offset": "0x0",
            "size": size,
            "type": "register",
            "register": name,
        })
    }

    fn const_v(value: u64, size: u64) -> Value {
        json!({
            "space": "const",
            "offset": format!("0x{:x}", value),
            "size": size,
            "type": "constant",
        })
    }

    fn ram(addr: u64, size: u64) -> Value {
        json!({
            "space": "ram",
            "offset": format!("0x{:x}", addr),
            "size": size,
            "type": "ram",
        })
    }

    fn unique(offset: u64, size: u64) -> Value {
        json!({
            "space": "unique",
            "offset": format!("0x{:x}", offset),
            "size": size,
            "type": "unique",
        })
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let pcode = json!({
            "pcode": [
                op(1, reg("RAX", 8), json!([const_v(0, 8)])),
                op(2, reg("RAX", 8), json!([reg("RAX", 8), const_v(1, 8)])),
            ]
        });
        let a = fingerprint(&pcode).unwrap();
        let b = fingerprint(&pcode).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_hex_is_32_chars() {
        let pcode = json!({"pcode": [op(0, Value::Null, json!([]))]});
        let h = fingerprint_hex(&pcode).unwrap();
        assert_eq!(h.len(), 32);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn ram_addresses_dont_affect_fingerprint() {
        // Same function compiled at two different link addresses
        // should fingerprint identically — that is the whole point
        // of the RAM normalization.
        let at_400000 = json!({
            "pcode": [
                op(7, reg("RAX", 8), json!([ram(0x400000, 8)])),
            ]
        });
        let at_500000 = json!({
            "pcode": [
                op(7, reg("RAX", 8), json!([ram(0x500000, 8)])),
            ]
        });
        assert_eq!(
            fingerprint(&at_400000).unwrap(),
            fingerprint(&at_500000).unwrap()
        );
    }

    #[test]
    fn large_constants_bucket_to_same_fingerprint() {
        // Pointer-sized literals are almost always linked addresses.
        // We bucket them — `mov rax, 0x401000` and `mov rax, 0x402000`
        // must hash the same.
        let a = json!({"pcode": [op(1, reg("RAX", 8), json!([const_v(0x401000, 8)]))]});
        let b = json!({"pcode": [op(1, reg("RAX", 8), json!([const_v(0x402000, 8)]))]});
        assert_eq!(fingerprint(&a).unwrap(), fingerprint(&b).unwrap());
    }

    #[test]
    fn small_constants_do_affect_fingerprint() {
        // Shift amounts and small loop bounds are semantic — they
        // must NOT collapse together. `<< 2` and `<< 3` are
        // genuinely different functions.
        let shift_2 = json!({"pcode": [op(8, reg("RAX", 8), json!([reg("RBX", 8), const_v(2, 1)]))]});
        let shift_3 = json!({"pcode": [op(8, reg("RAX", 8), json!([reg("RBX", 8), const_v(3, 1)]))]});
        assert_ne!(fingerprint(&shift_2).unwrap(), fingerprint(&shift_3).unwrap());
    }

    #[test]
    fn unique_varnode_aliasing_is_preserved() {
        // Both ops reference unique@0x100 twice — the second reference
        // must hash as the same intern'd ID, not a fresh one.
        let pcode = json!({
            "pcode": [
                op(1, unique(0x100, 8), json!([reg("RAX", 8)])),
                op(2, reg("RBX", 8), json!([unique(0x100, 8), unique(0x100, 8)])),
            ]
        });
        let canon = canonicalize(&pcode).unwrap();
        // Three references to the same unique slot → all should be "U:0:8".
        let count = canon.matches("U:0:8").count();
        assert_eq!(count, 3, "expected 3 references to U:0:8, got: {}", canon);
    }

    #[test]
    fn different_unique_slots_get_different_ids() {
        let pcode = json!({
            "pcode": [
                op(1, unique(0x100, 8), json!([])),
                op(1, unique(0x200, 8), json!([])),
            ]
        });
        let canon = canonicalize(&pcode).unwrap();
        assert!(canon.contains("U:0:8"));
        assert!(canon.contains("U:1:8"));
    }

    #[test]
    fn missing_pcode_array_errors() {
        let bad = json!({"function": "main"});
        assert!(fingerprint(&bad).is_err());
    }

    #[test]
    fn empty_pcode_still_hashes() {
        // An empty function (e.g. a stub) is a valid fingerprint
        // input — should produce a constant hash, not an error.
        let empty = json!({"pcode": []});
        let h = fingerprint(&empty).unwrap();
        // Constant: md5 of empty string.
        assert_eq!(format!("{:032x}", h), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn null_output_is_handled() {
        // BRANCH/RETURN-style ops have null output. Must not panic.
        let pcode = json!({
            "pcode": [
                op(10, Value::Null, json!([reg("RIP", 8)])),
            ]
        });
        fingerprint(&pcode).unwrap();
    }

    #[test]
    fn unknown_varnode_type_does_not_panic() {
        // Forward-compat: a Ghidra upgrade that introduces a new
        // varnode kind should hash deterministically, not crash.
        let weird = json!({
            "pcode": [
                op(1, json!({
                    "space": "weirdspace",
                    "offset": "0x0",
                    "size": 4,
                    "type": "weird_new_kind",
                }), json!([])),
            ]
        });
        fingerprint(&weird).unwrap();
    }
}
