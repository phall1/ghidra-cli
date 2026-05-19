//! CLI surface for the annotation store (E6.3 / E6.4).
//!
//! `ghidra-cli annotate export --out db.sqlite` walks every function in
//! the current project, fingerprints its PCode (see [`super::hash`]),
//! and upserts an annotation row keyed by that fingerprint into the
//! SQLite DB (see [`super::db`]).
//!
//! `ghidra-cli annotate apply --in db.sqlite` is the inverse: for each
//! function in the project, hash it, look up the hash in the DB, and
//! apply name/signature/return_type if a match is found. `--dry-run`
//! prints proposed changes without touching the project.
//!
//! Scope of the v1 implementation:
//!
//! - Persisted fields: `name`, `signature`, `return_type`. `params`,
//!   `comments`, and `renames` columns are reserved in the schema
//!   (E6.2) but populated as NULL until a follow-up wires the
//!   per-function comment + variable queries through.
//! - Conflict policy on apply: overwrite. The point of the workflow
//!   is "I just re-imported a new build of the same binary, hydrate
//!   it from my previous analysis." Silent re-renames are fine; the
//!   analyst is the source of truth in the DB.
//! - The DB stores the most-recent annotation per
//!   `(function_hash, project, program)` — older entries with the
//!   same key are overwritten by `db::upsert`'s ON CONFLICT clause.
//!   `apply` uses `find_by_hash` and picks the most recent entry
//!   across all projects, biased toward "user's most recent edit
//!   wins."

use anyhow::{Context, Result};
use std::path::Path;

use super::db::{Annotation, Db};
use super::hash;
use crate::ipc::client::BridgeClient;

/// Inputs for [`run_export`]. We intentionally do not depend on the
/// CLI arg structs from `src/cli.rs` — those live in the binary
/// crate, and this module is also compiled as part of the library
/// crate (where `crate::cli` doesn't exist).
pub struct ExportOptions<'a> {
    pub out: &'a Path,
    pub limit: Option<usize>,
}

/// Inputs for [`run_apply`].
pub struct ApplyOptions<'a> {
    pub input: &'a Path,
    pub dry_run: bool,
    pub limit: Option<usize>,
}

/// Drive `ghidra-cli annotate export`. Caller is responsible for
/// having the bridge already running (the routing layer in main.rs
/// guarantees that for any `Annotate(_)` command).
pub fn run_export(
    client: &BridgeClient,
    project: &str,
    program: &str,
    opts: &ExportOptions<'_>,
) -> Result<()> {
    let db = Db::open(opts.out).with_context(|| format!("open annotation DB {:?}", opts.out))?;

    let functions = list_functions(client, opts.limit)?;
    let total = functions.len();
    eprintln!(
        "Exporting annotations for {} function(s) → {}",
        total,
        opts.out.display()
    );

    let mut written = 0usize;
    let mut skipped = 0usize;

    for (idx, func) in functions.iter().enumerate() {
        let name = func
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>");
        let address = match func.get("address").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => {
                eprintln!("  [{idx}/{total}] {name}: skipped (no address)");
                skipped += 1;
                continue;
            }
        };

        let pcode = match client.pcode_function(address, false) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  [{idx}/{total}] {name} @ {address}: pcode failed: {e}");
                skipped += 1;
                continue;
            }
        };

        let fp = match hash::fingerprint_hex(&pcode) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("  [{idx}/{total}] {name} @ {address}: hash failed: {e}");
                skipped += 1;
                continue;
            }
        };

        let ann = Annotation {
            function_hash: fp,
            project: project.to_owned(),
            program: program.to_owned(),
            name: Some(name.to_owned()),
            signature: func
                .get("signature")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            // Best-effort: the list_functions response carries
            // signature but not return_type as a discrete field.
            // Parsing it out of the signature string is brittle, so
            // we leave it NULL for v1 and let `apply` derive it from
            // the signature it sets.
            return_type: None,
            params: None,
            comments: None,
            renames: None,
            updated_at: None,
        };
        db.upsert(&ann)
            .with_context(|| format!("upsert annotation for {name} @ {address}"))?;
        written += 1;
    }

    println!(
        "Exported {} annotation(s); {} skipped; DB now has {} total row(s).",
        written,
        skipped,
        db.count().unwrap_or(-1)
    );
    Ok(())
}

/// Drive `ghidra-cli annotate apply`. Same precondition as export
/// (bridge already running, project + program resolved).
pub fn run_apply(client: &BridgeClient, opts: &ApplyOptions<'_>) -> Result<()> {
    let db =
        Db::open(opts.input).with_context(|| format!("open annotation DB {:?}", opts.input))?;

    let functions = list_functions(client, opts.limit)?;
    let total = functions.len();
    let mode = if opts.dry_run { "dry-run" } else { "apply" };
    eprintln!(
        "Applying annotations ({mode}) to {total} function(s) from {}",
        opts.input.display()
    );

    let mut matched = 0usize;
    let mut renamed = 0usize;
    let mut sig_set = 0usize;
    let mut rettype_set = 0usize;
    let mut skipped = 0usize;

    for (idx, func) in functions.iter().enumerate() {
        let current_name = func
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>");
        let address = match func.get("address").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => {
                eprintln!("  [{idx}/{total}] {current_name}: skipped (no address)");
                skipped += 1;
                continue;
            }
        };

        let pcode = match client.pcode_function(address, false) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "  [{idx}/{total}] {current_name} @ {address}: pcode failed: {e}"
                );
                skipped += 1;
                continue;
            }
        };

        let fp = match hash::fingerprint_hex(&pcode) {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "  [{idx}/{total}] {current_name} @ {address}: hash failed: {e}"
                );
                skipped += 1;
                continue;
            }
        };

        let hits = db.find_by_hash(&fp)?;
        let Some(ann) = hits.into_iter().next() else {
            // No prior annotation for this fingerprint — nothing to do.
            continue;
        };
        matched += 1;

        // Decide what changes we'd make. Each comparison is "skip if
        // the project already has this value" so re-running `apply`
        // is a no-op the second time.
        let proposed_name = ann
            .name
            .as_deref()
            .filter(|n| !n.is_empty() && *n != current_name);
        let current_sig = func.get("signature").and_then(|v| v.as_str());
        let proposed_sig = ann
            .signature
            .as_deref()
            .filter(|s| !s.is_empty() && Some(*s) != current_sig);
        let proposed_rettype = ann.return_type.as_deref().filter(|t| !t.is_empty());

        if let Some(new_name) = proposed_name {
            println!(
                "  rename   @ {address}: {} -> {}",
                current_name, new_name
            );
            if !opts.dry_run {
                client
                    .symbol_rename(current_name, new_name)
                    .with_context(|| format!("rename {current_name} -> {new_name}"))?;
                renamed += 1;
            }
        }
        if let Some(new_sig) = proposed_sig {
            println!("  signature@ {address}: {new_sig}");
            if !opts.dry_run {
                client
                    .set_function_signature(address, new_sig)
                    .with_context(|| format!("set signature on {address}"))?;
                sig_set += 1;
            }
        }
        if let Some(new_rt) = proposed_rettype {
            println!("  rettype  @ {address}: {new_rt}");
            if !opts.dry_run {
                client
                    .set_return_type(address, new_rt)
                    .with_context(|| format!("set return type on {address}"))?;
                rettype_set += 1;
            }
        }
    }

    println!(
        "Summary: {matched}/{total} function(s) matched a fingerprint in the DB. \
         {} rename(s), {} signature change(s), {} return-type change(s). \
         {} skipped due to errors.",
        if opts.dry_run { matched } else { renamed },
        if opts.dry_run { matched } else { sig_set },
        if opts.dry_run { matched } else { rettype_set },
        skipped,
    );
    Ok(())
}

/// Pull the full list of functions (or up to `limit`) from the bridge.
/// `list_functions` returns `{count, functions: [{name, address, ...}]}`.
fn list_functions(client: &BridgeClient, limit: Option<usize>) -> Result<Vec<serde_json::Value>> {
    let resp = client.list_functions(limit, None)?;
    let arr = resp
        .get("functions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(arr)
}
