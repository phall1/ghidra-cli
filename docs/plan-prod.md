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
| Keep IPC infrastructure despite current non-use | IPC layer (src/ipc/) is newer local-socket infrastructure -> daemon already works via daemon/rpc.rs (TCP) -> IPC provides cross-platform local socket support for future -> suppress with #[allow(dead_code)] |
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

**Code Changes**:
```diff
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -5,7 +5,7 @@ edition = "2021"
 authors = ["Alexander Kiselev"]
 description = "Rust CLI to run Ghidra headless for reverse engineering with Claude Code and other agents"
 license = "GPL-3.0"
-repository = "http://127.0.0.1:62915/git/akiselev/ghidra-cli"
+repository = "https://github.com/akiselev/ghidra-cli"

 [dependencies]
 # CLI framework
```

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

**Code Changes**:
```diff
--- a/src/daemon/handler.rs
+++ b/src/daemon/handler.rs
@@ -6,7 +6,7 @@ use std::sync::Arc;

 use serde_json::json;
 use tokio::sync::Mutex;
-use tracing::{debug, info, warn};
+use tracing::debug;

 use crate::ghidra::bridge::GhidraBridge;
 use crate::ipc::protocol::{Command, Response};
```

```diff
--- a/src/daemon/queue.rs
+++ b/src/daemon/queue.rs
@@ -8,7 +8,7 @@ use std::sync::Arc;

 use anyhow::{Context, Result};
 use tokio::sync::{Mutex, Semaphore, oneshot};
-use tracing::{info, warn, error};
+use tracing::{info, warn};

 use crate::cli::Commands;
 use crate::daemon::cache::Cache;
```

```diff
--- a/src/daemon/ipc_server.rs
+++ b/src/daemon/ipc_server.rs
@@ -13,7 +13,6 @@ use tracing::{debug, error, info};

 use crate::ghidra::bridge::GhidraBridge;
 use crate::ipc::protocol::{Command, Request, Response};
-use crate::ipc::transport::{self, platform::Listener};
+use crate::ipc::transport;

 use super::handler;
```

```diff
--- a/src/ghidra/bridge.rs
+++ b/src/ghidra/bridge.rs
@@ -6,7 +6,7 @@

 use std::io::{BufRead, BufReader, Write};
 use std::net::TcpStream;
-use std::path::{Path, PathBuf};
+use std::path::PathBuf;
 use std::process::{Child, Command, Stdio};
 use std::sync::atomic::{AtomicBool, Ordering};
 use std::sync::Arc;
```

```diff
--- a/src/ghidra/setup.rs
+++ b/src/ghidra/setup.rs
@@ -1,5 +1,5 @@
 use std::fs::File;
-use std::io::{Read, Write, Seek};
+use std::io::Write;
 use std::path::{Path, PathBuf};
 use anyhow::{Context, Result, anyhow};
 use futures_util::StreamExt;
```

```diff
--- a/src/query/mod.rs
+++ b/src/query/mod.rs
@@ -1,6 +1,6 @@
 use serde_json::Value as JsonValue;
 use crate::error::{GhidraError, Result};
-use crate::filter::{Filter, FilterExpr};
+use crate::filter::Filter;
 use crate::format::{OutputFormat, Formatter, DefaultFormatter};
 use crate::ghidra::GhidraClient;
 use crate::ghidra::headless::HeadlessExecutor;
```

```diff
--- a/src/main.rs
+++ b/src/main.rs
@@ -19,7 +19,7 @@ use ghidra::GhidraClient;
 use query::{Query, DataType, FieldSelector, SortKey};
 use std::path::PathBuf;
-use tracing::{info, error};
+use tracing::info;

 #[cfg(unix)]
 use daemonize::Daemonize;
```

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

**Code Changes**:
```diff
--- a/src/daemon/ipc_server.rs
+++ b/src/daemon/ipc_server.rs
@@ -21,10 +21,6 @@ use super::handler;
 pub struct IpcServer {
     /// The Ghidra bridge instance
     bridge: Arc<Mutex<Option<GhidraBridge>>>,
-    // Shutdown signal and timing are unused: current IPC implementation
-    // delegates to the TCP-based daemon/rpc.rs for shutdown coordination
-    /// Shutdown signal sender
-    shutdown_tx: broadcast::Sender<()>,
-    /// Server start time
-    started_at: Instant,
 }

 impl IpcServer {
@@ -35,8 +31,6 @@ impl IpcServer {
     ) -> Self {
         Self {
             bridge,
-            shutdown_tx,
-            started_at: Instant::now(),
         }
     }
```

```diff
--- a/src/daemon/queue.rs
+++ b/src/daemon/queue.rs
@@ -111,34 +111,6 @@ impl CommandQueue {
         });
     }

-    // Removed sync/async queue depth and completed count methods:
-    // Sync versions returned hardcoded 0 (unreliable), async versions unused.
-    // Decision: remove incomplete/unused methods to reduce dead code.
-    /// Get the current queue depth.
-    pub fn queue_depth(&self) -> usize {
-        // This is a synchronous method, so we can't await the lock
-        // Return 0 as an estimate (actual depth available via async method)
-        0
-    }
-
-    /// Get the current queue depth (async version).
-    pub async fn queue_depth_async(&self) -> usize {
-        let queue = self.queue.lock().await;
-        queue.len()
-    }
-
-    /// Get the number of completed commands.
-    pub fn completed_count(&self) -> usize {
-        // This is a synchronous method, so we can't await the lock
-        // Return 0 as an estimate (actual count available via async method)
-        0
-    }
-
-    /// Get the number of completed commands (async version).
-    pub async fn completed_count_async(&self) -> usize {
-        let count = self.completed_count.lock().await;
-        *count
-    }
-
     /// Get the project path.
     pub fn project_path(&self) -> &Path {
         &self.project_path
```

```diff
--- a/src/config.rs
+++ b/src/config.rs
@@ -150,13 +150,6 @@ impl Config {
         None
     }

-    pub fn get_timeout(&self) -> u64 {
-        std::env::var("GHIDRA_TIMEOUT")
-            .ok()
-            .and_then(|s| s.parse().ok())
-            .or(self.timeout)
-            .unwrap_or(300)
-    }
-
     pub fn get_default_program(&self) -> Option<String> {
         std::env::var("GHIDRA_DEFAULT_PROGRAM")
             .ok()
```

```diff
--- a/src/daemon/cache.rs
+++ b/src/daemon/cache.rs
@@ -78,20 +78,6 @@ impl Cache {
         }
     }

-    /// Clear all cached entries.
-    pub async fn clear(&self) {
-        let mut entries = self.entries.write().await;
-        entries.clear();
-        debug!("Cache cleared");
-    }
-
-    /// Remove expired entries.
-    pub async fn cleanup(&self) {
-        let mut entries = self.entries.write().await;
-        let ttl = self.ttl;
-        entries.retain(|_, entry| !entry.is_expired(ttl));
-        debug!("Cache cleanup completed");
-    }
-
     /// Generate a cache key for a command.
     /// Only cacheable commands return Some.
     fn cache_key(&self, command: &Commands) -> Option<String> {
```

```diff
--- a/src/ghidra/data.rs
+++ b/src/ghidra/data.rs
@@ -1,3 +1,5 @@
+// Data structures for query type implementations
+#![allow(dead_code)]
 use serde::{Deserialize, Serialize};

 #[derive(Debug, Clone, Serialize, Deserialize)]
```

```diff
--- a/src/daemon/state.rs
+++ b/src/daemon/state.rs
@@ -1,6 +1,8 @@
 //! Daemon state management.
 //!
 //! Manages the state of loaded Ghidra projects and maintains metadata.
+// State tracking for daemon lifecycle management
+#![allow(dead_code)]

 use std::path::{Path, PathBuf};
 use std::sync::Arc;
```

```diff
--- a/src/ipc/client.rs
+++ b/src/ipc/client.rs
@@ -1,3 +1,5 @@
+// IPC infrastructure: provides cross-platform local socket support for daemon communication
+#![allow(dead_code)]
 // IPC client implementation will go here
```

```diff
--- a/src/ipc/transport.rs
+++ b/src/ipc/transport.rs
@@ -1,3 +1,5 @@
+// IPC infrastructure: provides cross-platform local socket support for daemon communication
+#![allow(dead_code)]
 // IPC transport layer implementation will go here
```

```diff
--- a/src/ipc/protocol.rs
+++ b/src/ipc/protocol.rs
@@ -1,3 +1,5 @@
+// IPC infrastructure: provides cross-platform local socket support for daemon communication
+#![allow(dead_code)]
 use serde::{Deserialize, Serialize};
```

```diff
--- a/src/format/mod.rs
+++ b/src/format/mod.rs
@@ -44,14 +44,6 @@ impl OutputFormat {
         }
     }

-    pub fn is_human_friendly(&self) -> bool {
-        matches!(self, Self::Full | Self::Compact | Self::Table | Self::Tree)
-    }
-
-    pub fn is_machine_friendly(&self) -> bool {
-        matches!(self, Self::Json | Self::JsonCompact | Self::JsonStream | Self::Csv | Self::Tsv)
-    }
-}
-
 pub trait Formatter {
     fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String>;
 }
```

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

**Code Changes**:
```diff
--- a/src/query/mod.rs
+++ b/src/query/mod.rs
@@ -49,6 +49,7 @@ impl DataType {

 pub struct Query {
     pub data_type: DataType,
+    // Target address for XRefs queries; unused by other query types.
+    // XRefs requires specifying where references point (a function or address).
+    pub target: Option<String>,
     pub filter: Option<Filter>,
     pub fields: Option<FieldSelector>,
     pub format: OutputFormat,
@@ -62,6 +63,7 @@ impl Query {
     pub fn new(data_type: DataType) -> Self {
         Self {
             data_type,
+            target: None,
             filter: None,
             fields: None,
             format: OutputFormat::Json,
@@ -97,6 +99,11 @@ impl Query {
         self
     }

+    pub fn with_target(mut self, target: String) -> Self {
+        self.target = Some(target);
+        self
+    }
+
     pub fn execute(&self, client: &GhidraClient, project: &str, program: &str) -> Result<String> {
         let executor = HeadlessExecutor::new(client);

@@ -107,6 +114,11 @@ impl Query {
             DataType::Imports => executor.list_imports(project, program)?,
             DataType::Exports => executor.list_exports(project, program)?,
             DataType::Memory => executor.get_memory_map(project, program)?,
+            DataType::XRefs => {
+                let target = self.target.as_ref()
+                    .ok_or_else(|| GhidraError::Other("XRefs query requires --to parameter".to_string()))?;
+                executor.get_xrefs_to(project, program, target)?
+            }
             _ => {
                 return Err(GhidraError::Other(format!(
                     "Data type {:?} not yet implemented",
```

```diff
--- a/src/cli.rs
+++ b/src/cli.rs
@@ -145,6 +145,10 @@ pub struct QueryArgs {
     /// Filter expression
     #[arg(short, long)]
     pub filter: Option<String>,
+
+    /// Target address or function name (required for xrefs)
+    #[arg(long)]
+    pub to: Option<String>,

     /// Field selection (comma-separated)
     #[arg(long)]
```

```diff
--- a/src/main.rs
+++ b/src/main.rs
@@ -483,6 +483,11 @@ fn handle_query(args: QueryArgs) -> anyhow::Result<()> {
     // Build query
     let mut query = Query::new(data_type);

+    // Target address for XRefs query type
+    if let Some(target) = args.to {
+        query = query.with_target(target);
+    }
+
     // Add filter if provided
     if let Some(filter_str) = args.filter {
         let filter = filter::Filter::parse(&filter_str)?;
```

Note: `get_xrefs_to()` method already exists in headless.rs at lines 182-190, no changes needed to headless.rs.

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

**Code Changes**:
```diff
--- a/tests/e2e.rs
+++ b/tests/e2e.rs
@@ -232,4 +232,67 @@ mod e2e_tests {
             .assert()
             .success()
             .stdout(predicate::str::contains("Program Summary"));
     }
+
+    /// Test xrefs query by function name
+    #[test]
+    #[serial]
+    fn test_xrefs_by_name() {
+        ensure_project_setup();
+
+        let mut cmd = Command::cargo_bin("ghidra").unwrap();
+        cmd.arg("query")
+            .arg("xrefs")
+            .arg("--to")
+            .arg("main")
+            .arg("--project")
+            .arg(PROJECT_NAME)
+            .arg("--program")
+            .arg(PROGRAM_NAME)
+            .timeout(std::time::Duration::from_secs(300))
+            .assert()
+            .success()
+            .stdout(predicate::str::contains("from"))
+            .stdout(predicate::str::contains("to"))
+            .stdout(predicate::str::contains("ref_type"));
+    }
+
+    /// Test xrefs query by address
+    #[test]
+    #[serial]
+    fn test_xrefs_by_address() {
+        ensure_project_setup();
+
+        // First get the entry point address from summary
+        let mut summary_cmd = Command::cargo_bin("ghidra").unwrap();
+        let summary_output = summary_cmd
+            .arg("summary")
+            .arg("--project")
+            .arg(PROJECT_NAME)
+            .arg("--program")
+            .arg(PROGRAM_NAME)
+            .timeout(std::time::Duration::from_secs(300))
+            .output()
+            .expect("Failed to get summary");
+
+        // Query xrefs using a hardcoded entry point (typical for x86_64 ELF)
+        let mut cmd = Command::cargo_bin("ghidra").unwrap();
+        cmd.arg("query")
+            .arg("xrefs")
+            .arg("--to")
+            .arg("0x00100000") // Common entry point for test binary
+            .arg("--project")
+            .arg(PROJECT_NAME)
+            .arg("--program")
+            .arg(PROGRAM_NAME)
+            .timeout(std::time::Duration::from_secs(300))
+            .assert()
+            .success();
+    }
+
+    /// Test xrefs query to nonexistent address (should return empty array)
+    #[test]
+    #[serial]
+    fn test_xrefs_nonexistent() {
+        ensure_project_setup();
+
+        let mut cmd = Command::cargo_bin("ghidra").unwrap();
+        cmd.arg("query")
+            .arg("xrefs")
+            .arg("--to")
+            .arg("0xdeadbeef")
+            .arg("--project")
+            .arg(PROJECT_NAME)
+            .arg("--program")
+            .arg(PROGRAM_NAME)
+            .timeout(std::time::Duration::from_secs(300))
+            .assert()
+            .success()
+            .stdout(predicate::str::contains("[]"));
+    }
 }
```

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

**Code Changes**:
```diff
--- a/README.md
+++ b/README.md
@@ -1,4 +1,215 @@
 # Ghidra CLI

 A high-performance Rust CLI for automating Ghidra reverse engineering tasks, designed for both direct usage and AI agent integration (like Claude Code).

+## Overview
+
+`ghidra-cli` is a Rust-based command-line interface for Ghidra, the NSA's reverse engineering platform. It enables:
+
+- **Headless automation**: Run Ghidra analysis without the GUI
+- **Query-based data extraction**: Functions, strings, imports, exports, memory maps, cross-references
+- **Decompilation**: Extract C pseudocode from binaries
+- **Project management**: Create, import, and manage Ghidra projects from the command line
+- **AI agent integration**: Structured output formats (JSON, CSV) for use with Claude Code and other AI tools
+
+## Features
+
+- **Universal query system**: Query any Ghidra data type (functions, strings, xrefs, etc.) with filtering, sorting, and pagination
+- **Multiple output formats**: JSON, CSV, TSV, table, minimal
+- **Headless execution**: Runs Ghidra scripts without opening the GUI
+- **Built-in setup**: Automatic Ghidra download and installation
+- **Fast**: Rust implementation with optimized Jython scripts
+- **Type-safe**: Rust's type system ensures reliable operations
+
+## Installation
+
+### Prerequisites
+
+- **JDK 17+** (required by Ghidra)
+- **Ghidra 10.x+** (can be auto-installed via `ghidra setup`)
+
+### From source
+
+```bash
+git clone https://github.com/akiselev/ghidra-cli
+cd ghidra-cli
+cargo build --release
+cargo install --path .
+```
+
+### Install Ghidra
+
+If you don't have Ghidra installed, use the built-in setup command:
+
+```bash
+ghidra setup
+```
+
+This downloads and installs the latest Ghidra release automatically.
+
+## Quick Start
+
+### 1. Verify installation
+
+```bash
+ghidra doctor
+```
+
+### 2. Import a binary
+
+```bash
+ghidra import /path/to/binary --project my-project --program my-binary
+```
+
+### 3. Query functions
+
+```bash
+# List all functions
+ghidra query functions --project my-project --program my-binary
+
+# List functions with filtering
+ghidra query functions --project my-project --program my-binary --filter "size > 100"
+
+# Output as CSV
+ghidra query functions --project my-project --program my-binary --format csv
+```
+
+### 4. Decompile a function
+
+```bash
+ghidra decompile main --project my-project --program my-binary
+```
+
+### 5. Query cross-references
+
+```bash
+# XRefs to main function
+ghidra query xrefs --to main --project my-project --program my-binary
+
+# XRefs to a specific address
+ghidra query xrefs --to 0x401000 --project my-project --program my-binary
+```
+
+### Quick analysis
+
+For a one-shot analysis without setting up a project:
+
+```bash
+ghidra quick /path/to/binary
+```
+
+This imports, analyzes, and displays a summary in one command.
+
+## CLI Reference
+
+### Core Commands
+
+- `ghidra query <type>` - Query Ghidra data (functions, strings, imports, exports, xrefs, memory)
+- `ghidra decompile <target>` - Decompile a function by name or address
+- `ghidra import <binary>` - Import a binary into a project
+- `ghidra analyze` - Run Ghidra analysis on a program
+- `ghidra summary` - Display program summary
+- `ghidra quick <binary>` - Quick analysis (import + analyze + summary)
+
+### Project Management
+
+- `ghidra project create <name>` - Create a new project
+- `ghidra project list` - List all projects
+- `ghidra project info <name>` - Show project details
+- `ghidra project delete <name>` - Delete a project
+
+### Configuration
+
+- `ghidra config list` - Show current configuration
+- `ghidra config get <key>` - Get a specific config value
+- `ghidra config set <key> <value>` - Set a config value
+- `ghidra set-default program <name>` - Set default program
+- `ghidra set-default project <name>` - Set default project
+
+### Utilities
+
+- `ghidra doctor` - Verify installation and configuration
+- `ghidra init` - Initialize configuration
+- `ghidra setup` - Download and install Ghidra
+- `ghidra version` - Show version information
+
+### Query Options
+
+All query commands support:
+
+- `--filter <expr>` - Filter results (e.g., `"name LIKE main"`, `"size > 100"`)
+- `--fields <fields>` - Select specific fields (comma-separated)
+- `--sort <field>` - Sort by field (prefix with `-` for descending)
+- `--limit <n>` - Limit number of results
+- `--offset <n>` - Skip first N results
+- `--format <format>` - Output format (json, csv, tsv, table, minimal)
+- `--count` - Only return count of results
+
+## AI Agent Integration
+
+ghidra-cli is designed for AI agent integration. See [CLAUDE_SKILL.md](CLAUDE_SKILL.md) for detailed usage with Claude Code, including:
+
+- Skill configuration for Claude Code
+- Example workflows and commands
+- Advanced usage patterns
+- Tool integration examples
+
+### Example: Using with Claude Code
+
+```bash
+# Claude can use this to analyze a binary
+ghidra query functions --project malware-analysis --program sample.exe --format json
+```
+
+The JSON output is structured for parsing by AI agents, enabling automated reverse engineering workflows.
+
+## Configuration
+
+Configuration is stored in `~/.config/ghidra-cli/config.yaml` (Linux/macOS) or `%APPDATA%\ghidra-cli\config.yaml` (Windows).
+
+### Environment Variables
+
+- `GHIDRA_INSTALL_DIR` - Path to Ghidra installation
+- `GHIDRA_PROJECT_DIR` - Default project directory
+- `GHIDRA_DEFAULT_PROJECT` - Default project name
+- `GHIDRA_DEFAULT_PROGRAM` - Default program name
+- `GHIDRA_TIMEOUT` - Timeout for Ghidra operations (seconds)
+
+### Configuration File
+
+```yaml
+ghidra_install_dir: /path/to/ghidra_10.4_PUBLIC
+ghidra_project_dir: ~/git
+default_project: my-project
+default_program: my-binary
+default_output_format: json
+timeout: 300
+```
+
+## Development
+
+### Building from source
+
+```bash
+cargo build --release
+```
+
+### Running tests
+
+```bash
+# Unit tests
+cargo test
+
+# E2E tests (requires Ghidra installation)
+cargo test --test e2e
+```
+
+## Contributing
+
+Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/akiselev/ghidra-cli).
+
+## License
+
+GPL-3.0 - See [LICENSE](LICENSE) for details.
+
+Ghidra is developed by the National Security Agency and is licensed separately under the Apache License 2.0.
```

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
