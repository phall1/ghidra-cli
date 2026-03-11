# Vision: AI-Native Reverse Engineering

> Kill the JVM. Keep the decompiler. Ship the future of RE.

## The Thesis

Ghidra is the best open-source reverse engineering framework — but it's trapped in a Java Swing UI from 2004. The decompiler is brilliant C++ code. Everything around it (loader, analysis, UI, scripting) is Java that exists to serve a GUI nobody wants to use.

We're building the tool where **the LLM is the primary interface** and Ghidra's analysis engine is a headless backend. Reverse engineering through vibes — describe what you're looking at, and the AI does the mechanical work.

This happens in three phases.

---

## Phase 1: MCP Server + Complete Tool Coverage

**Status**: Active  
**Goal**: An LLM can fully drive reverse engineering via ghidra-cli — no UI, no manual commands.  
**Deliverable**: `ghidra-cli mcp` starts an MCP server over stdio that Claude/other LLMs can connect to.

### What We're Building

1. **MCP server** built into ghidra-cli using `rmcp` (official Rust MCP SDK)
   - stdio transport (Claude Desktop, Claude Code, Cursor, etc.)
   - Every CLI command exposed as a typed MCP tool
   - JSON Schema auto-generated from Rust types via `schemars`

2. **Complete tool surface** for AI-driven RE workflows (~70 tools across 13 categories)
   - Tier 1 (essential): decompile, disassemble, list functions, xrefs, rename, comment, search
   - Tier 2 (frequent): struct CRUD, function signatures, variables, call graphs, memory map
   - Tier 3 (specialized): PCode, advanced patching, batch operations, analysis control

3. **Bug fixes** in existing bridge commands
   - `patch nop --count` — parsed but ignored at runtime
   - `comment set --comment-type` — key mismatch falls back to EOL

4. **New bridge commands** for AI-critical operations not yet exposed:
   - Struct field manipulation (add/rename/retype fields)
   - Function parameters and local variables (rename, retype, create, remove)
   - Instruction semantics (PCode at address)
   - Data flow queries
   - Analysis control (enable/disable specific analyzers)
   - Decompiler AST access

### Architecture

```
┌─────────────────────────────┐
│  LLM (Claude, GPT, etc.)   │
└──────────┬──────────────────┘
           │ MCP (JSON-RPC over stdio)
┌──────────▼──────────────────┐
│  ghidra-cli mcp             │  ← Rust binary
│  (rmcp server + tool defs)  │
└──────────┬──────────────────┘
           │ TCP (JSON protocol)
┌──────────▼──────────────────┐
│  GhidraCliBridge.java       │  ← Runs inside Ghidra's JVM
│  (analyzeHeadless -postScript)
└──────────┬──────────────────┘
           │ Ghidra Flat API
┌──────────▼──────────────────┐
│  Ghidra Framework           │  ← Java analysis engine
│  + C++ Decompiler (IPC)     │
└─────────────────────────────┘
```

### Success Criteria

- [ ] `ghidra-cli mcp` works with Claude Desktop and Claude Code
- [ ] An LLM can import a binary, analyze it, decompile functions, rename symbols, annotate code, and export results — entirely through MCP tool calls
- [ ] Tool coverage matches or exceeds GhidraMCP (LaurieWired) + GhydraMCP (starsong) combined
- [ ] Sub-second response times for queries (leveraging the warm JVM bridge)

### Detailed plan: [plan-phase1-mcp.md](./plan-phase1-mcp.md)

---

## Phase 2: Smart AI Features

**Status**: Not started  
**Goal**: AI doesn't just execute commands — it understands binaries.  
**Prerequisite**: Phase 1 complete.

### What We're Building

1. **Auto-indexing on import**
   - On `import + analyze`, automatically build a semantic index of all functions
   - Cluster functions by behavior (crypto, networking, string manipulation, control flow)
   - Generate a "binary summary" that an LLM can use as context

2. **Batch rename with confidence**
   - LLM proposes renames for all `FUN_*` functions with confidence scores
   - User reviews high-confidence renames, manually checks low-confidence ones
   - Persistent annotation DB (not just Ghidra comments — survives recompilation via function hashing)

3. **"What does this binary do?" workflow**
   - Single command: `ghidra-cli explain <binary>`
   - Imports, analyzes, indexes, then produces a structured report:
     - Purpose, capabilities, notable strings, suspicious patterns
     - Network activity, file system access, crypto usage
     - Recommended functions to investigate

4. **Conversation context management**
   - MCP resources for current analysis state (current function, recent findings, hypotheses)
   - The LLM maintains a "RE notebook" — findings, unanswered questions, next steps
   - Context window optimization — send decompiled code for relevant functions, not all 10k functions

5. **Cross-binary analysis**
   - Compare two binaries (different versions, similar malware families)
   - Function-level diffing with semantic similarity (not just byte-level)
   - Transfer annotations from analyzed binary to new variant

### Success Criteria

- [ ] `ghidra-cli explain` produces useful output for common binary types (ELF, PE, Mach-O)
- [ ] Batch rename correctly identifies >70% of functions in standard test binaries
- [ ] Cross-binary annotation transfer works for minor version changes

---

## Phase 3: Kill the JVM

**Status**: Long-term  
**Goal**: The C++ decompiler runs standalone. No Java. No JVM. Pure Rust/C++ tool.  
**Prerequisite**: Phase 2 mature, deep understanding of Ghidra internals.

### The Problem

Ghidra's C++ decompiler is a standalone process that communicates via IPC. But it doesn't work alone — it asks the Java host for everything:

```
Decompiler (C++) ──query──▶ Java Host
  "Give me bytes at 0x401000"         → COMMAND_GETBYTES
  "What symbol is at 0x402000?"       → COMMAND_GETSYMBOL  
  "What's the type of this variable?" → COMMAND_GETDATATYPE
  "Give me PCode for this block"      → COMMAND_GETPCODE
  ... (17 query types total)
```

The Java host loads the binary, runs analysis, builds the symbol table, manages types — then feeds this to the decompiler on demand. Phase 3 replaces the Java host with a Rust one.

### What We're Building

1. **Binary loader** — Replace Ghidra's Java loaders with Rust
   - Use `goblin` (ELF, PE, Mach-O) and/or `lief` for binary parsing
   - Build the memory image, segment map, import/export tables
   - Handle relocations, overlays, special sections

2. **Callback host** — Implement the 17 decompiler callback queries in Rust
   - `COMMAND_GETBYTES` — read bytes from loaded binary
   - `COMMAND_GETSYMBOL` — look up symbol at address
   - `COMMAND_GETDATATYPE` — resolve type definitions
   - `COMMAND_GETPCODE` — provide raw PCode (from SLEIGH)
   - `COMMAND_GETCOMMENTS` — return user annotations
   - `COMMAND_GETCALLFIXUP` — provide calling convention fixups
   - ... and 11 more

3. **SLEIGH integration** — Reuse the C++ SLEIGH compiler and runtime
   - SLEIGH `.sla` files already compiled, can be loaded directly
   - SLEIGH disassembly → PCode translation is C++ and stays C++
   - Rust wrapper around SLEIGH for instruction decode + PCode emission

4. **Analysis layer** — Rebuild core analysis passes in Rust
   - Function discovery (entry points, call targets, pattern matching)
   - Reference tracking (code refs, data refs)
   - Type propagation (basic type inference from PCode)
   - Symbol resolution (imports, exports, debug info)
   - NOTE: We don't need Ghidra-level analysis — 80% of the value comes from the decompiler. Basic function boundaries + import resolution gets us there.

5. **New architecture**

```
┌─────────────────────────────┐
│  LLM / CLI / MCP            │
└──────────┬──────────────────┘
           │
┌──────────▼──────────────────┐
│  ghidra-cli (Rust)          │
│  - Binary loader (goblin)   │
│  - Analysis engine          │
│  - Callback host            │
│  - MCP server               │
└──────────┬──────────────────┘
           │ IPC (stdin/stdout, binary protocol)
┌──────────▼──────────────────┐
│  Decompiler (C++)           │  ← Ghidra's decompiler, unchanged
│  + SLEIGH (C++)             │  ← Ghidra's SLEIGH, unchanged
└─────────────────────────────┘
```

### What Stays C++

- **Decompiler** (~190k LOC) — this is the crown jewel, don't touch it
- **SLEIGH compiler** (~20k LOC) — compiles architecture specs to .sla files
- **SLEIGH runtime** — decodes instructions, emits PCode
- **Processor specs** (~277k LOC of .sla/.pspec/.cspec) — architecture definitions

### What Gets Replaced (Java → Rust)

- Binary loading (Java → goblin/lief)
- Memory management (Ghidra's AddressSpace → Rust)
- Symbol table (Ghidra's SymbolTable → Rust)
- Type system (Ghidra's DataTypeManager → Rust)
- Analysis passes (Ghidra's analyzers → Rust, simplified)
- Project management (Ghidra's .gpr/.rep → simpler format)
- IPC protocol host (Java DecompileProcess → Rust)

### Existing Art

- **pypcode** (206⭐) — Python bindings to SLEIGH (PCode only, no decompiler)
- **angr/cle** — Binary loader in Python
- **goblin** — Binary loader in Rust (ELF, PE, Mach-O)
- **lief** — Binary loader in C++ with Python/Rust bindings

### Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Decompiler protocol changes between Ghidra versions | Medium | Pin to stable version, abstract protocol layer |
| 17 callbacks are more complex than they appear | High | Incremental: get GETBYTES working first, iterate |
| Analysis quality won't match Ghidra | Medium | Focus on "good enough for decompilation" not "match Ghidra" |
| Undocumented protocol behaviors | High | Extensive testing against Java reference implementation |
| Multi-arch support is vast | Medium | Start with x86_64 only, expand incrementally |

### Success Criteria

- [ ] `ghidra-cli decompile <binary>` works without Java installed
- [ ] x86_64 ELF and PE binaries decompile correctly
- [ ] Function discovery finds >90% of functions that Ghidra finds
- [ ] Import resolution works for standard libraries
- [ ] Startup time < 1 second (vs ~10 seconds with JVM)
- [ ] Memory usage < 500MB for typical binaries (vs ~2GB with JVM)

---

## Timeline (Rough)

| Phase | Estimated Effort | Prerequisites |
|-------|-----------------|---------------|
| Phase 1 | 2-4 weeks | ghidra-cli fork (done) |
| Phase 2 | 4-8 weeks | Phase 1 complete |
| Phase 3 | 3-6 months | Phase 2 mature, deep Ghidra internals knowledge |

Phase 1 is the foundation. It must be solid before building on it.

---

## Non-Goals

- **No Swing UI. Ever.** The LLM is the UI.
- **No Ghidra plugin marketplace compatibility.** We're not extending Ghidra, we're wrapping then replacing it.
- **No server mode for Phase 1.** stdio MCP is sufficient. HTTP/SSE can come later if needed.
- **No Windows/Linux GUI toolkits.** Terminal + MCP only.
