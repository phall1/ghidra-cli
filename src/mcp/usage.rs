//! Per-tool MCP invocation counters.
//!
//! Persisted to `<data_local_dir>/ghidra-cli/tool-usage.json`. The file
//! survives across runs and informs eval coverage + dead-tool pruning.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const FLUSH_EVERY: u64 = 50;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolUsageEntry {
    pub count: u64,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolUsage {
    #[serde(flatten)]
    pub tools: BTreeMap<String, ToolUsageEntry>,
}

impl ToolUsage {
    pub fn load_from(path: &std::path::Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        match fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save_to(&self, path: &std::path::Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        // Atomic write via temp file + rename so a crash mid-write can't truncate prior data.
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn record(&mut self, tool: &str) {
        let entry = self.tools.entry(tool.to_string()).or_default();
        entry.count += 1;
        entry.last_used = Some(Utc::now());
    }
}

/// Default location of the usage file.
pub fn default_usage_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ghidra-cli")
        .join("tool-usage.json")
}

/// Thread-safe tracker that wraps `ToolUsage` with a flush-every-N-invocations policy.
pub struct UsageTracker {
    inner: Mutex<TrackerState>,
    path: PathBuf,
}

struct TrackerState {
    usage: ToolUsage,
    pending: u64,
}

impl UsageTracker {
    pub fn new(path: PathBuf) -> Self {
        let usage = ToolUsage::load_from(&path);
        Self {
            inner: Mutex::new(TrackerState {
                usage,
                pending: 0,
            }),
            path,
        }
    }

    pub fn record(&self, tool: &str) {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.usage.record(tool);
        state.pending += 1;
        if state.pending >= FLUSH_EVERY {
            let _ = state.usage.save_to(&self.path);
            state.pending = 0;
        }
    }

    pub fn flush(&self) {
        if let Ok(mut state) = self.inner.lock() {
            if state.pending > 0 {
                let _ = state.usage.save_to(&self.path);
                state.pending = 0;
            }
        }
    }
}

impl Drop for UsageTracker {
    fn drop(&mut self) {
        // Final flush on shutdown so counts aren't lost between FLUSH_EVERY boundaries.
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn round_trip_save_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("usage.json");
        let mut usage = ToolUsage::default();
        usage.record("decompile_function");
        usage.record("decompile_function");
        usage.record("list_functions");
        usage.save_to(&path).unwrap();

        let loaded = ToolUsage::load_from(&path);
        assert_eq!(loaded.tools.get("decompile_function").unwrap().count, 2);
        assert_eq!(loaded.tools.get("list_functions").unwrap().count, 1);
        assert!(loaded
            .tools
            .get("decompile_function")
            .unwrap()
            .last_used
            .is_some());
    }

    #[test]
    fn tracker_flushes_on_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("usage.json");
        {
            let tracker = UsageTracker::new(path.clone());
            tracker.record("foo");
            tracker.record("bar");
        }
        let loaded = ToolUsage::load_from(&path);
        assert_eq!(loaded.tools.get("foo").unwrap().count, 1);
        assert_eq!(loaded.tools.get("bar").unwrap().count, 1);
    }

    #[test]
    fn load_missing_returns_default() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let loaded = ToolUsage::load_from(&path);
        assert!(loaded.tools.is_empty());
    }
}
