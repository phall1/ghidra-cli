# Ghidra-CLI Open Source Release Plan

## Overview

Prepare ghidra-cli for professional open source release on GitHub. The project is architecturally complete (~6,800 lines of Rust) with working CLI, daemon mode, and query system, but has release blockers: minimal README (4 lines), invalid repository URL (localhost), 49 compiler warnings, and XRefs query type unimplemented despite backend support existing.

**Chosen approach**: Full Polish - fix all warnings, expand README comprehensively, implement XRefs query (backend already exists in bridge.py and scripts.rs), add E2E test. Estimated effort: 8-10 hours.

## Planning Context

### Decision Log

| Decision | Reasoning Chain |
|----------|-----------------|
| Full Polish over Minimal Change | XRefs backend exists in bridge.py:222-286 and scripts.rs:322-362 -> wiring takes 2-3 hours -> shipping without it wastes existing work -> full polish provides professional release quality |
| Fix ALL 49 warnings | Partial fix leaves project looking incomplete -> enables `#[deny(warnings)]` in CI -> professional open source projects have zero warnings |
| E2E tests over unit tests | Project already uses E2E pattern in tests/e2e.rs -> consistency with existing codebase -> E2E covers real Ghidra integration which is the risky part |
| Repository URL github.com/akiselev | Matches author field in Cargo.toml -> user confirmed this URL -> enables crates.io publishing |
| XRefs uses HeadlessExecutor not Bridge | Bridge requires daemon running -> HeadlessExecutor pattern matches other query types (functions, strings, etc.) -> consistent user experience |
| Remove dead code over #[allow(dead_code)] | Dead code indicates incomplete features or abandoned refactoring -> removal is cleaner than suppression -> forces decision on whether code is needed |
| Keep data.rs structs despite being unused | Structs define data model for future query types -> removing would require re-adding later -> suppress with #[allow(dead_code)] annotation |
| Keep IPC infrastructure despite current non-use | Daemon mode planned for v0.2 with 10x faster queries -> removing would require full re-implementation -> suppression with #[allow(dead_code)] cheaper than removal+restoration |
| README 9-section structure | User confirmed standard open source structure -> covers all stakeholders (users, developers, contributors) -> comprehensive without being excessive |

### Rejected Alternatives

| Alternative | Why Rejected |
|-------------|--------------|
| Minimal Change approach | Would ship with backend code users can't access -> XRefs is high-value for RE workflows -> extra 2-3 hours is worth it |
| Feature-Forward (Symbols, Sections) | No backend exists for these -> requires new Jython scripts -> 15+ hours vs 8-10 -> diminishing returns for v0.1.0 |
| Unit tests for query parsing | Query parsing already works (5 types operational) -> risk is Ghidra integration not parsing -> E2E catches real issues |
| Connect XRefs via Bridge instead of Headless | Would require daemon to be running for XRefs only -> inconsistent with other query types -> confusing UX |

### Constraints & Assumptions

- **Technical**: Rust 2021 edition, Ghidra 10.x+ compatibility, existing clap CLI structure
- **Pattern preservation**: All query types use HeadlessExecutor pattern (query/mod.rs:104-116)
- **Testing**: E2E tests require working Ghidra installation, 300s timeout for operations
- **Dependencies**: bridge.py xrefs handlers exist and are tested manually (assumed working)
- **User-specified**: GitHub URL is github.com/akiselev/ghidra-cli
- **User-specified**: Testing approach is E2E only
- **User-specified**: Keep IPC infrastructure for daemon mode in v0.2
- **User-specified**: README uses 9-section structure (Overview, Features, Installation, Quick Start, CLI Reference, AI Agent Integration, Configuration, Development, Contributing, License)

### Known Risks

| Risk | Mitigation | Anchor |
|------|------------|--------|
| XRefs script may have edge cases | E2E test with sample_binary will catch common issues; defer edge cases to bug reports | scripts.rs:322-362 (script exists) |
| README may miss important details | Include comprehensive sections; link to CLAUDE_SKILL.md for advanced usage | CLAUDE_SKILL.md (463 lines of examples) |
| Dead code removal may break compilation | Compile after each file change; warnings guide what's safe to remove | Compiler output lists exact locations |
| Removing IpcServer dead fields may affect future work | Fields store useful data; document in code comment why kept or remove if truly unused | ipc_server.rs:25-27 |

## Invisible Knowledge

### Architecture

```
User CLI Command
      |
      v
+-------------+     +------------------+
| main.rs     |---->| HeadlessExecutor |
| (routing)   |     | (script runner)  |
+-------------+     +------------------+
      |                    |
      v                    v
+-------------+     +------------------+
| query/mod.rs|     | Ghidra Headless  |
| (filtering) |     | (Jython scripts) |
+-------------+     +------------------+
      |
      v
+-------------+
| format/     |
| (output)    |
+-------------+
```

### Data Flow for Query Command

```
ghidra query xrefs --to main --program binary
    |
    v
CLI parses args -> DataType::XRefs + target address
    |
    v
Query::execute() -> HeadlessExecutor::get_xrefs_to()
    |
    v
Write Jython script to temp file -> Run analyzeHeadless
    |
    v
Parse JSON between markers (---GHIDRA_CLI_START/END---)
    |
    v
Apply filter, sort, pagination -> Format output
```

### Why This Structure

The query system uses a universal pattern where all data types flow through the same execute() method. This enables:
- Consistent filtering/sorting/pagination across all types
- Single point to add new output formats
- Reusable CLI argument parsing

XRefs differs from other types by requiring a target address parameter, which is passed via script args to Ghidra.

### Invariants

- All Jython scripts MUST wrap output in `---GHIDRA_CLI_START---` / `---GHIDRA_CLI_END---` markers
- Query data types in enum must match case in execute() or return "not implemented" error
- HeadlessExecutor methods must return `Result<JsonValue>` where JsonValue is an array

### Tradeoffs

- **XRefs via Headless vs Bridge**: Chose Headless for consistency even though Bridge is faster. Cost: ~5-10s per query instead of <1s. Benefit: Works without daemon, matches other commands.
- **Remove vs suppress dead code**: Chose remove for cleanup, suppress for data.rs. Cost: More investigation time. Benefit: Cleaner codebase, clear intent.

## Milestones

> All file paths are relative to repository root (`/home/kiselev/git/ghidra-cli/`)

### Milestone 1: Fix Cargo.toml and Create docs Directory

**Files**:
- `Cargo.toml`

**Requirements**:
- Update repository URL from localhost to GitHub
- Ensure docs/ directory exists for plan file

**Acceptance Criteria**:
- `cargo metadata` shows valid repository URL
- URL matches `https://github.com/akiselev/ghidra-cli`

**Tests**: Skip - configuration change, no runtime behavior

**Code Intent**:
- Modify `Cargo.toml` line 8: change repository URL from `http://127.0.0.1:62915/git/akiselev/ghidra-cli` to `https://github.com/akiselev/ghidra-cli`

**Code Changes**: (Developer fills)

---

### Milestone 2: Fix Compiler Warnings - Unused Imports

**Files**:
- `src/daemon/handler.rs`
- `src/daemon/queue.rs`
- `src/daemon/ipc_server.rs`
- `src/ghidra/bridge.rs`
- `src/ghidra/setup.rs`
- `src/query/mod.rs`
- `src/main.rs`

**Flags**: `conformance`

**Requirements**:
- Remove all unused import warnings
- Preserve imports that are actually used

**Acceptance Criteria**:
- `cargo build 2>&1 | grep "unused import"` returns no results
- Project compiles successfully

**Tests**: Skip - removing unused code, compilation is the test

**Code Intent**:
- `handler.rs:9`: Remove `info`, `warn` from tracing import
- `queue.rs:11`: Remove `error` from tracing import
- `ipc_server.rs:16`: Remove `platform::Listener` from transport import
- `bridge.rs:9`: Remove `Path` from std::path import (keep PathBuf)
- `setup.rs:2`: Remove `Read`, `Seek` from std::io import (keep Write)
- `query/mod.rs:3`: Remove `FilterExpr` from filter import
- `main.rs:22`: Remove `error` from tracing import

**Code Changes**: (Developer fills)

---

### Milestone 3: Fix Compiler Warnings - Dead Code

**Files**:
- `src/daemon/ipc_server.rs`
- `src/daemon/queue.rs`
- `src/config.rs`
- `src/daemon/cache.rs`
- `src/ghidra/data.rs`
- `src/daemon/state.rs`
- `src/ipc/client.rs`
- `src/ipc/transport.rs`
- `src/ipc/protocol.rs`
- `src/format/mod.rs`

**Flags**: `conformance`, `needs-rationale`

**Requirements**:
- Address dead code warnings for methods/fields that won't be used
- For data.rs and state.rs: add #[allow(dead_code)] with comment explaining future use
- For truly dead code: remove it

**Acceptance Criteria**:
- `cargo build 2>&1 | grep "never used\|never read\|never called"` returns no results OR only intentionally suppressed items
- Project compiles without warnings (or with only documented allowances)

**Tests**: Skip - removing/suppressing unused code, compilation is the test

**Code Intent**:
- `ipc_server.rs:25-27`: Remove `shutdown_tx` and `started_at` fields OR add #[allow(dead_code)] with comment if needed for future shutdown handling
- `queue.rs:115-138`: Remove `queue_depth()`, `queue_depth_async()`, `completed_count()`, `completed_count_async()` methods - they return hardcoded 0 or are never called
- `config.rs:153`: Remove `get_timeout()` if unused, or wire up to actual usage
- `cache.rs:82`: Remove `clear()`, `cleanup()` methods if unused
- `ghidra/data.rs`: Add `#[allow(dead_code)]` to module with comment "Data structures for future query type implementations"
- `daemon/state.rs`: Add `#[allow(dead_code)]` to DaemonState with comment "State tracking for daemon lifecycle management"
- `ipc/client.rs`, `ipc/transport.rs`, `ipc/protocol.rs`: Add `#[allow(dead_code)]` with comment "IPC infrastructure for daemon communication - preserved for v0.2 daemon mode" (Decision: "Keep IPC infrastructure despite current non-use")
- `format/mod.rs:47`: Remove `is_human_friendly()`, `is_machine_friendly()` if unused

**Code Changes**: (Developer fills)

---

### Milestone 4: Implement XRefs Query Type

**Files**:
- `src/query/mod.rs`
- `src/ghidra/headless.rs`
- `src/cli.rs`

**Flags**: `conformance`, `needs-rationale`

**Requirements**:
- Add XRefs case to Query::execute() in query/mod.rs
- Add get_xrefs_to() method to HeadlessExecutor
- Modify CLI to accept --to parameter for xrefs query
- Use existing get_xrefs_to_script() from scripts.rs

**Acceptance Criteria**:
- `ghidra query xrefs --to 0x401000 --program binary` returns JSON array of xrefs
- `ghidra query xrefs --to main --program binary` works with function name
- Output format matches other query types (filterable, sortable)

**Tests**:
- **Test files**: `tests/e2e.rs`
- **Test type**: E2E
- **Backing**: user-specified (E2E only approach)
- **Scenarios**:
  - Normal (name): Query xrefs using `--to main` (function name) returns results
  - Normal (address): Query xrefs using `--to 0x<addr>` (numeric address) returns results
  - Edge: Query xrefs to non-existent address returns empty array

**Code Intent**:
- `query/mod.rs:104-116`: Add `DataType::XRefs => executor.get_xrefs_to(project, program, target)?` case in match statement
- `query/mod.rs`: Add `target: Option<String>` field to Query struct for XRefs target address
- `headless.rs`: Add `pub fn get_xrefs_to(&self, project: &str, program: &str, target: &str) -> Result<JsonValue>` method using existing `get_xrefs_to_script()` pattern
- `cli.rs`: Add `--to <ADDRESS>` parameter to query subcommand, required when data_type is xrefs (Decision: "XRefs requires target address")

**Code Changes**: (Developer fills)

---

### Milestone 5: Add XRefs E2E Test

**Files**:
- `tests/e2e.rs`

**Requirements**:
- Add test for xrefs query command
- Follow existing test patterns (serial, timeout, ensure_project_setup)

**Acceptance Criteria**:
- `cargo test test_xrefs -- --nocapture` passes
- Test verifies command returns success and valid output

**Tests**:
- **Test files**: `tests/e2e.rs`
- **Test type**: E2E
- **Backing**: user-specified
- **Scenarios**:
  - Normal: xrefs to main function succeeds

**Code Intent**:
- Add `test_xrefs_by_name()` function following pattern of `test_function_list()`
  - Use `ensure_project_setup()` for fixture
  - Query xrefs --to main with PROJECT_NAME and PROGRAM_NAME
  - Assert success and stdout contains expected fields ("from", "to", "ref_type")
- Add `test_xrefs_by_address()` function
  - Use `ensure_project_setup()` for fixture
  - Query xrefs using --to with a known address (e.g., entry point from summary)
  - Assert success
- Add `test_xrefs_nonexistent()` function for edge case
  - Query xrefs --to 0xdeadbeef (invalid address)
  - Assert success (returns empty array, not error)

**Code Changes**: (Developer fills)

---

### Milestone 6: Expand README.md

**Files**:
- `README.md`

**Requirements**:
- Comprehensive README for open source release
- Installation instructions (cargo install, from source)
- Quick start guide with examples
- Feature overview
- Link to CLAUDE_SKILL.md for AI agent integration
- License and contributing sections

**Acceptance Criteria**:
- Contains all 9 sections: Overview, Features, Installation, Quick Start, CLI Reference, AI Agent Integration, Configuration, Development, Contributing, License
- Links to CLAUDE_SKILL.md in AI Agent Integration section
- Each section contains at least one code example or substantive content

**Tests**: Skip - documentation only

**Code Intent**:
- Replace 4-line README with comprehensive documentation
- Sections: Overview, Features, Installation, Quick Start, CLI Reference (brief), AI Agent Integration (link to CLAUDE_SKILL.md), Configuration, Development, Contributing, License
- Include code examples for: ghidra doctor, ghidra import, ghidra query functions, ghidra decompile

**Code Changes**: (Developer fills)

---

### Milestone 7: Documentation

**Delegated to**: @agent-technical-writer (mode: post-implementation)

**Source**: `## Invisible Knowledge` section of this plan

**Files**:
- `src/query/README.md` (query system architecture)
- `src/ghidra/README.md` (Ghidra integration details)

**Requirements**:
- Document query system data flow
- Document XRefs implementation rationale
- Reference Decision Log for architectural choices

**Acceptance Criteria**:
- README.md files explain non-obvious design decisions
- Architecture diagrams match Invisible Knowledge section
- Self-contained (no external documentation references)

## Milestone Dependencies

```
M1 (Cargo.toml) ----+
                    |
M2 (Imports)   ----+----> M4 (XRefs) ----> M5 (E2E Test)
                    |
M3 (Dead Code) ----+
                    |
                    +----> M6 (README) ----> M7 (Docs)
```

**Parallel execution**: M1, M2, M3 can run in parallel (no dependencies)
**Sequential**: M4 requires M2/M3 (clean compilation), M5 requires M4 (feature exists), M7 requires M6 (README first)
