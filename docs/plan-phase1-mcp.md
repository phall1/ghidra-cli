# Phase 1: MCP Server + Complete Tool Coverage

> Detailed implementation plan. See [VISION.md](./VISION.md) for the big picture.

## Overview

Phase 1 turns ghidra-cli into an MCP server that any LLM can drive. The binary goes from a human CLI tool to the backbone of AI-native reverse engineering.

**Current state**: 62 bridge commands, Rust CLI, TCP/JSON protocol to Java bridge. No MCP.  
**Target state**: `ghidra-cli mcp` starts an MCP server. ~70 tools. Complete RE workflow coverage.

---

## Completion Status

**Phase 1 is COMPLETE.** All 5 milestones delivered.

| Milestone | Status | Commits | Tools Added |
|-----------|--------|---------|-------------|
| M0: Bug Fixes | Complete | 1 | 0 |
| M1: MCP Server | Complete | 1 | 45 |
| M2: Struct CRUD + Variables | Complete | 4 | 9 |
| M3: Function Management | Complete | 2 | 5 |
| M4: Types, Bookmarks, PCode, Analysis | Complete | 4 | 11 |
| M5: Polish & Documentation | Complete | -- | -- |
| **Total** | **Done** | **12+** | **80 tools** |

### Final Stats
- **80 MCP tools** (target was ~70)
- **142 E2E tests** across 19 test suites
- **~85 bridge commands** in GhidraCliBridge.java
- Clean `cargo check --tests` on all code

### What Exceeded Plan
- Tool count: 80 vs 70 target (+14%)
- Test coverage: 142 tests vs no specific target
- All tools have both CLI and MCP exposure

---

## Milestone 0: Bug Fixes & Prep (1-2 days) [Complete]

Fix known issues before building on top of them.

### 0.1 Fix `patch nop --count`

**Problem**: CLI parses `--count N` but the bridge ignores it — always NOPs a single instruction.

**Files**:
- `src/cli.rs` — `PatchCommands::Nop` already has `count` field ✓
- `src/main.rs` — sends command to bridge, verify `count` is included in args
- `src/ghidra/scripts/GhidraCliBridge.java` — `handlePatchNop()` must loop `count` times

**Fix**: Bridge handler needs to read `count` from args and NOP that many consecutive instructions.

### 0.2 Fix `comment set --comment-type`

**Problem**: CLI sends `comment_type` key, bridge expects `commentType` (or vice versa) — falls back to EOL.

**Files**:
- `src/main.rs` — check what key is sent in the JSON args
- `src/ghidra/scripts/GhidraCliBridge.java` — `handleCommentSet()`, check what key it reads

**Fix**: Align the key name between CLI and bridge.

### 0.3 Verify test suite passes

```bash
cargo test
```

If tests require Ghidra installed (they do, via `require_ghidra!()`), verify they pass in the local environment before proceeding.

---

## Milestone 1: MCP Server Skeleton (2-3 days) [Complete]

### 1.1 Add `rmcp` dependency

```toml
# Cargo.toml additions
rmcp = { version = "1.1.1", features = ["server", "macros", "transport-io", "schemars"] }
schemars = "1.0"
```

Also ensure tokio has `rt-multi-thread` and `macros` features (currently only has `rt`, `io-util`, `time`, `net`).

### 1.2 Create MCP server module

New files:
```
src/mcp/
  mod.rs          — MCP server struct, tool router, ServerHandler impl
  tools/
    mod.rs        — tool category modules
    program.rs    — program/project management tools
    functions.rs  — function listing, decompilation, renaming
    symbols.rs    — symbol operations
    types.rs      — type and struct operations
    memory.rs     — memory read/write, segments
    xrefs.rs      — cross-reference queries
    comments.rs   — comment CRUD
    search.rs     — string/byte/function search
    graph.rs      — call graph operations
    patch.rs      — binary patching
    analysis.rs   — analysis control
    disasm.rs     — disassembly
```

### 1.3 Wire up CLI entry point

Add `Mcp` variant to `Commands` enum in `src/cli.rs`:

```rust
/// Start MCP server (stdio transport for LLM integration)
Mcp(McpArgs),
```

In `src/main.rs`, handle the command:

```rust
Commands::Mcp(args) => {
    // Logs MUST go to stderr — stdout is the MCP wire
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    
    let server = GhidraServer::new(/* bridge config */);
    server.serve(rmcp::transport::stdio()).await?;
}
```

### 1.4 Implement one tool end-to-end

Pick `list_functions` as the proof-of-concept:

```rust
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFunctionsParams {
    /// Filter expression (e.g., "size > 100")
    #[schemars(description = "Optional filter expression")]
    pub filter: Option<String>,
    /// Maximum number of results
    pub limit: Option<usize>,
}

#[tool(description = "List all functions in the analyzed binary")]
async fn list_functions(
    &self,
    Parameters(p): Parameters<ListFunctionsParams>,
) -> Result<CallToolResult, McpError> {
    let result = self.bridge.send_command("function_list", &args).await?;
    Ok(CallToolResult::success(vec![Content::text(result)]))
}
```

### 1.5 Test with Claude

Configure Claude Desktop or Claude Code to use the MCP server:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "ghidra-cli",
      "args": ["mcp", "--project", "myproject", "--program", "mybinary"]
    }
  }
}
```

Verify: Claude can call `list_functions` and get results.

### Design Decisions

**Bridge connection**: The MCP server needs a persistent `BridgeClient` connection. Two options:

1. **MCP server manages its own bridge** — `ghidra-cli mcp --project X --program Y` auto-starts a bridge (like other commands do), holds the connection for the lifetime of the MCP session.
2. **MCP server connects to existing bridge** — user starts bridge separately, MCP server connects.

**Recommendation**: Option 1. The MCP server should be self-contained. The bridge auto-start logic already exists in `ensure_bridge_running()`.

**Async bridge client**: Current `BridgeClient` is synchronous (blocking TCP). For the MCP server, we need async. Options:
1. Wrap sync client in `tokio::task::spawn_blocking`
2. Rewrite client to use `tokio::net::TcpStream`

**Recommendation**: Start with option 1 (spawn_blocking). It works, it's fast, it avoids rewriting the client. Optimize later if needed.

---

## Milestone 2: Core Tools — Tier 1 (3-5 days) [Complete]

These are the tools an LLM uses in every RE session. All have existing bridge commands.

### 2.1 Orientation Tools

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `get_program_info` | `info` | ✅ Exists |
| `get_program_stats` | `stats` | ✅ Exists |
| `get_program_summary` | `summary` | ✅ Exists |

### 2.2 Discovery Tools

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `list_functions` | `function_list` | ✅ Exists |
| `search_functions` | `function_search` | ✅ Exists |
| `list_imports` | `symbol_list` (filtered) | ✅ Exists |
| `list_exports` | `symbol_list` (filtered) | ✅ Exists |
| `list_strings` | `strings_list` | ✅ Exists |
| `list_segments` | `memory_segments` | ✅ Exists |
| `list_namespaces` | `symbol_list` (filtered) | ✅ Exists |

### 2.3 Core Analysis Tools

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `decompile_function` | `decompile` | ✅ Exists |
| `disassemble` | `disasm` | ✅ Exists |
| `get_function_info` | `function_get` | ✅ Exists |
| `get_xrefs_to` | `xref_to` | ✅ Exists |
| `get_xrefs_from` | `xref_from` | ✅ Exists |

### 2.4 Annotation Tools

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `rename_function` | `function_rename` | ✅ Exists |
| `rename_symbol` | `symbol_rename` | ✅ Exists |
| `set_comment` | `comment_set` | ✅ Exists (needs bug fix) |
| `get_comment` | `comment_get` | ✅ Exists |
| `list_comments` | `comment_list` | ✅ Exists |

### 2.5 Project Management Tools

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `import_binary` | `import` | ✅ Exists |
| `analyze_program` | `analyze` | ✅ Exists |
| `list_projects` | `project_list` | ✅ Exists |

**Estimated work**: All Tier 1 tools have existing bridge commands. This milestone is purely MCP tool definition + parameter mapping. Mostly mechanical.

---

## Milestone 3: Tier 2 Tools — Types, Variables, Graphs (3-5 days) [Complete]

These tools require **new bridge commands** in GhidraCliBridge.java.

### 3.1 Struct Operations (NEW bridge commands needed)

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `list_structures` | `type_list` (filtered) | ✅ Exists |
| `get_structure` | `type_get` | ✅ Exists |
| `create_structure` | `struct_create` | ⚠️ **NEW** |
| `add_struct_field` | `struct_add_field` | ⚠️ **NEW** |
| `rename_struct_field` | `struct_rename_field` | ⚠️ **NEW** |
| `retype_struct_field` | `struct_retype_field` | ⚠️ **NEW** |
| `delete_structure` | `struct_delete` | ⚠️ **NEW** |

**Java implementation**: Use Ghidra's `DataTypeManager`, `StructureDataType`, `StructureDB` APIs.

### 3.2 Function Signature & Variable Operations (NEW bridge commands needed)

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `set_function_signature` | `function_set_signature` | ⚠️ Partial — bridge may handle prototype but not full C-style signatures |
| `rename_variable` | `variable_rename` | ⚠️ **NEW** |
| `retype_variable` | `variable_retype` | ⚠️ **NEW** |
| `list_variables` | `function_get_variables` | ✅ Exists |
| `set_return_type` | `function_set_return_type` | ⚠️ **NEW** |

**Java implementation**: Use `HighFunction`, `HighVariable`, `DecompInterface` for decompiler-aware variable manipulation. Direct `Variable` manipulation via `Function.getLocalVariables()`, `Function.getParameters()`.

### 3.3 Call Graph Tools

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `get_call_graph` | `graph_calls` | ✅ Exists |
| `get_callers` | `graph_callers` | ✅ Exists |
| `get_callees` | `graph_callees` | ✅ Exists |

### 3.4 Memory Tools

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `read_memory` | `memory_read` | ✅ Exists |
| `write_memory` | `memory_write` | ✅ Exists |
| `search_bytes` | `find_bytes` | ✅ Exists |

---

## Milestone 4: Tier 3 Tools — Advanced Operations (3-5 days) [Complete]

Specialized tools for power users and advanced RE workflows.

### 4.1 PCode / Intermediate Representation (NEW bridge commands)

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `get_pcode_at` | `pcode_at` | ⚠️ **NEW** |
| `get_pcode_for_function` | `pcode_function` | ⚠️ **NEW** |

**Java implementation**: Use `DecompInterface.decompileFunction()` → `HighFunction.getPcodeOps()`, or lower-level `Listing.getInstructionAt()` → `Instruction.getPcode()`.

### 4.2 Analysis Control (NEW bridge commands)

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `list_analyzers` | `analyzer_list` | ⚠️ **NEW** |
| `set_analyzer_enabled` | `analyzer_set` | ⚠️ **NEW** |
| `run_analysis` | `analyze_run` | ⚠️ **NEW** (re-run analysis on demand) |

**Java implementation**: Use `AutoAnalysisManager`, `AnalysisOptions` via the `GhidraScript` parent class.

### 4.3 Advanced Patching

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `patch_bytes` | `patch_bytes` | ✅ Exists |
| `patch_nop` | `patch_nop` | ✅ Exists (needs bug fix) |
| `export_patched` | `patch_export` | ✅ Exists |

### 4.4 Data Type Management (NEW bridge commands)

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `create_typedef` | `type_create_typedef` | ⚠️ **NEW** |
| `create_enum` | `type_create_enum` | ⚠️ **NEW** |
| `parse_c_type` | `type_parse_c` | ⚠️ **NEW** |
| `apply_type_at` | `type_apply` | ⚠️ **NEW** |

**Java implementation**: `DataTypeManager.addDataType()`, `CParser` for C-style type definitions.

### 4.5 Bookmark / Tag Operations (NEW bridge commands)

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `add_bookmark` | `bookmark_add` | ⚠️ **NEW** |
| `list_bookmarks` | `bookmark_list` | ⚠️ **NEW** |
| `delete_bookmark` | `bookmark_delete` | ⚠️ **NEW** |

### 4.6 Script Execution

| MCP Tool | Bridge Command | Status |
|----------|---------------|--------|
| `run_script` | `script_run` | ✅ Exists |
| `run_python` | `script_python` | ✅ Exists |

---

## Milestone 5: Integration Testing & Polish (2-3 days) [Complete]

### 5.1 MCP Protocol Compliance

- Test tool discovery (`tools/list`)
- Test parameter validation (missing required params, wrong types)
- Test error responses (bridge down, binary not loaded, invalid address)
- Test with multiple MCP clients (Claude Desktop, Claude Code, generic MCP client)

### 5.2 End-to-End RE Workflow Tests

Script a full RE workflow through MCP and verify it works:

1. Import binary → analyze → list functions → decompile main → find interesting strings
2. Rename functions based on behavior → set comments → export annotated project
3. Search for crypto → trace xrefs → decompile callers → annotate call chain
4. Create struct → add fields → apply to variable → re-decompile to verify

### 5.3 Performance

- Verify sub-second response for queries (function list, decompile, xrefs)
- Profile any slow tools
- Ensure bridge connection pooling works (one connection per MCP session, not per tool call)

### 5.4 Documentation

- Update README.md with MCP server usage
- Add MCP configuration examples for Claude Desktop, Claude Code, Cursor
- Document all available tools with parameter descriptions

---

## New Bridge Commands Summary

Total new Java bridge handlers needed:

| Category | New Commands | Ghidra API Surface |
|----------|-------------|-------------------|
| Structs | 5 | `StructureDataType`, `DataTypeManager` |
| Variables | 3 | `HighFunction`, `Variable`, `DecompInterface` |
| Function signature | 2 | `FunctionSignature`, `Function.setReturnType()` |
| PCode | 2 | `Instruction.getPcode()`, `HighFunction.getPcodeOps()` |
| Analysis control | 3 | `AutoAnalysisManager`, `AnalysisOptions` |
| Data types | 4 | `DataTypeManager`, `CParser`, `EnumDataType` |
| Bookmarks | 3 | `BookmarkManager` |
| **Total** | **~22** | |

Plus ~25 existing commands that just need MCP tool wrappers.

---

## Tool Count Targets

| Milestone | Target Tools | Actual Tools | Description |
|-----------|-------------|--------------|-------------|
| M0 | 0 | 0 | Bug fixes only |
| M1 | 1 | 45 | MCP skeleton + all existing commands wrapped |
| M2 | ~25 | 54 | Tier 1 + struct CRUD + variables |
| M3 | ~40 | 59 | + function management |
| M4 | ~60-70 | 80 | + types, bookmarks, PCode, analysis |
| M5 | ~60-70 | 80 | Polish, testing, documentation |

### Coverage vs. Existing Implementations

| Implementation | Tool Count | Our Target |
|---|---|---|
| LaurieWired/GhidraMCP | ~25 | Exceeded at M2 |
| GhidrAssistMCP | ~34 | Exceeded at M3 |
| GhydraMCP (starsong) | ~50 | Exceeded at M4 |
| 13bm/GhidraMCP | ~69 | Matched at M4 |
| Union of all (theoretical max) | ~172 | ~70 (practical coverage — the remaining 100 are niche/redundant) |

The ~70 tool target covers the practical maximum. The ~100 tools we skip are things like `detect_control_flow_flattening`, `find_rop_gadgets`, `emulate_function` — specialized analysis that belongs in Phase 2 as AI-driven features, not raw MCP tools.

---

## Dependency Graph

```
M0 (Bug Fixes)
 └─▶ M1 (MCP Skeleton)
      ├─▶ M2 (Tier 1 Tools) ── all existing bridge commands
      │    └─▶ M3 (Tier 2 Tools) ── new bridge commands needed
      │         └─▶ M4 (Tier 3 Tools) ── more new bridge commands
      │              └─▶ M5 (Testing & Polish)
      │
      └─▶ Can start M2 immediately after M1 proof-of-concept works
```

M2 and M3 can partially overlap — start wrapping existing commands while building new bridge handlers.

---

## Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| `rmcp` API breaking changes | Low | Medium | Pin exact version, vendor if needed |
| Bridge async issues | Medium | Medium | Start with `spawn_blocking`, works fine |
| Decompiler-aware variable ops are complex | High | Medium | Start with simple rename/retype, skip advanced writeback |
| PCode output format is large/noisy | Medium | Low | Truncate/summarize for LLM consumption |
| MCP client compatibility issues | Low | Low | Test with Claude Desktop + Claude Code early |

---

## What's NOT in Phase 1

These are explicitly deferred to Phase 2 or later:

- **AI-driven analysis** (auto-rename, auto-classify, "explain binary") → Phase 2
- **MCP resources** (persistent context, RE notebook) → Phase 2  
- **HTTP/SSE transport** (remote access, multi-client) → if needed
- **Transaction management** (undo/redo via MCP) → Phase 2
- **Cross-binary analysis** (diffing, annotation transfer) → Phase 2
- **Format-specific tools** (PE headers, ELF sections) → Phase 2 or script-based
- **Emulation** → Phase 2
- **Custom analysis passes** (via MCP) → Phase 2
