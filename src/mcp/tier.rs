//! MCP tool tier classification.
//!
//! Tiers let callers trade context-window cost for tool surface area. Tier 1
//! is the minimum viable RE workflow; tier 3 is everything.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum McpTier {
    Essential = 1,
    Frequent = 2,
    Specialized = 3,
}

impl McpTier {
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::Essential),
            2 => Some(Self::Frequent),
            3 => Some(Self::Specialized),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Tier 1 — essential RE workflow: load, inspect, decompile, annotate, search.
const TIER1_TOOLS: &[&str] = &[
    "get_program_info",
    "get_bridge_info",
    "list_programs",
    "open_program",
    "import_binary",
    "analyze_program",
    "list_functions",
    "decompile_function",
    "disassemble",
    "get_function",
    "list_strings",
    "list_symbols",
    "get_symbol",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_memory_map",
    "set_comment",
    "get_comment",
    "find_strings",
    "find_bytes",
];

/// Tier 2 — frequent edits and richer analysis: types, structs, patches, graphs.
const TIER2_TOOLS: &[&str] = &[
    "close_program",
    "delete_program",
    "export_program",
    "get_program_stats",
    "create_symbol",
    "delete_symbol",
    "rename_symbol",
    "rename_function",
    "create_function",
    "delete_function",
    "set_function_signature",
    "set_return_type",
    "list_types",
    "get_type",
    "create_type",
    "apply_type",
    "list_comments",
    "delete_comment",
    "find_functions",
    "find_calls",
    "find_crypto",
    "find_interesting",
    "get_call_graph",
    "get_callers",
    "get_callees",
    "patch_bytes",
    "patch_nop",
    "export_patched",
    "list_structures",
    "get_structure",
    "create_structure",
    "add_struct_field",
    "rename_struct_field",
    "delete_structure",
    "list_variables",
    "rename_variable",
    "retype_variable",
    "list_imports",
    "list_exports",
];

/// Tier 3 — specialized/rarely-used: PCode, raw memory, scripts, batch, bookmarks.
const TIER3_TOOLS: &[&str] = &[
    "read_memory",
    "write_memory",
    "export_graph",
    "run_script",
    "run_python",
    "run_java",
    "list_scripts",
    "diff_programs",
    "diff_functions",
    "create_enum",
    "create_typedef",
    "parse_c_type",
    "list_bookmarks",
    "add_bookmark",
    "delete_bookmark",
    "get_pcode_at",
    "get_pcode_function",
    "list_analyzers",
    "set_analyzer",
    "run_analysis",
    "batch_commands",
];

/// Returns every tool name known to the static tier classification.
///
/// Used by `stats tools` to list registered-but-never-called tools.
pub fn all_known_tool_names() -> Vec<&'static str> {
    let mut v = Vec::with_capacity(TIER1_TOOLS.len() + TIER2_TOOLS.len() + TIER3_TOOLS.len());
    v.extend_from_slice(TIER1_TOOLS);
    v.extend_from_slice(TIER2_TOOLS);
    v.extend_from_slice(TIER3_TOOLS);
    v
}

/// Look up the tier for a given MCP tool name.
///
/// Returns `McpTier::Specialized` for unknown names so new/unclassified tools
/// stay accessible at the default tier without silently disappearing.
pub fn tier_for_tool(name: &str) -> McpTier {
    if TIER1_TOOLS.contains(&name) {
        McpTier::Essential
    } else if TIER2_TOOLS.contains(&name) {
        McpTier::Frequent
    } else {
        McpTier::Specialized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering() {
        assert!(McpTier::Essential < McpTier::Frequent);
        assert!(McpTier::Frequent < McpTier::Specialized);
    }

    #[test]
    fn from_u8_round_trip() {
        assert_eq!(McpTier::from_u8(1), Some(McpTier::Essential));
        assert_eq!(McpTier::from_u8(2), Some(McpTier::Frequent));
        assert_eq!(McpTier::from_u8(3), Some(McpTier::Specialized));
        assert_eq!(McpTier::from_u8(0), None);
        assert_eq!(McpTier::from_u8(4), None);
    }

    #[test]
    fn tier1_count_is_around_twenty() {
        assert_eq!(TIER1_TOOLS.len(), 20);
    }

    #[test]
    fn known_tools_classified() {
        assert_eq!(tier_for_tool("decompile_function"), McpTier::Essential);
        assert_eq!(tier_for_tool("create_structure"), McpTier::Frequent);
        assert_eq!(tier_for_tool("get_pcode_at"), McpTier::Specialized);
    }
}
