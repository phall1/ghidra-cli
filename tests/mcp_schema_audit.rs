//! E4.1: MCP tool schema-byte audit + budget gate.
//!
//! Every MCP tool registered by `ghidra-cli mcp` rides in the LLM's
//! context on `tools/list`. They are not free. This test enumerates the
//! tool list, sums the per-tool serialized byte counts, prints a sorted
//! table, and asserts the total stays under a budget.
//!
//! Override the budget locally via `MCP_SCHEMA_BUDGET_BYTES=NNNN cargo test`.
//! Default budget tracks roughly the current footprint plus headroom; if
//! you legitimately need to grow it (e.g. adding a tool category), bump
//! [`DEFAULT_BUDGET_BYTES`] in the same PR and explain why in the commit.

use ghidra_cli::mcp::GhidraServer;

/// Default schema-bytes budget. Tight ratchet over the current footprint
/// (~25.5 KiB at the time of writing) so growth shows up immediately;
/// ratchet downward as `--mcp-tier` gating (E4.2) lands.
const DEFAULT_BUDGET_BYTES: usize = 32 * 1024;

fn current_budget() -> usize {
    std::env::var("MCP_SCHEMA_BUDGET_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BUDGET_BYTES)
}

#[test]
fn schema_byte_total_is_under_budget() {
    let audit = GhidraServer::audit_schemas();
    let budget = current_budget();

    eprintln!(
        "\nMCP tool schema audit\n=====================\n  tools:        {}\n  total bytes:  {} ({:.1} KiB)\n  budget:       {} ({:.1} KiB)\n  utilization:  {:.1}%\n",
        audit.tool_count,
        audit.total_bytes,
        audit.total_bytes as f64 / 1024.0,
        budget,
        budget as f64 / 1024.0,
        (audit.total_bytes as f64 / budget as f64) * 100.0,
    );

    eprintln!("Top 20 by bytes (largest first):");
    eprintln!(
        "  {:>5} {:>5} {:>5}  name",
        "total", "desc", "schema"
    );
    for entry in audit.entries.iter().take(20) {
        eprintln!(
            "  {:>5} {:>5} {:>5}  {}",
            entry.total_bytes, entry.description_bytes, entry.schema_bytes, entry.name
        );
    }
    eprintln!();

    assert!(
        audit.total_bytes <= budget,
        "MCP tool schemas total {} bytes, exceeding budget of {} bytes. \
         Either trim descriptions/schemas or, if growth is intentional, \
         bump DEFAULT_BUDGET_BYTES in tests/mcp_schema_audit.rs and explain.",
        audit.total_bytes,
        budget,
    );
}

#[test]
fn audit_reports_all_tools() {
    let audit = GhidraServer::audit_schemas();
    assert!(
        audit.tool_count >= 60,
        "audit reports {} tools — far fewer than expected (~80). \
         Check that all #[tool] handlers are still registered.",
        audit.tool_count
    );

    // Every tool must have a non-empty name and a non-zero on-wire size.
    for entry in &audit.entries {
        assert!(!entry.name.is_empty(), "tool with empty name");
        assert!(
            entry.total_bytes > 0,
            "tool {} serialized to 0 bytes — broken Serialize?",
            entry.name
        );
    }
}
