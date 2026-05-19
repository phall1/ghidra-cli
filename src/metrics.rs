//! Per-command latency histograms (E2.2).
//!
//! In-memory rolling histograms keyed by bridge command name. Flushed to
//! stderr on process exit (and on demand) using `MetricsGuard`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

use hdrhistogram::Histogram;

const HIST_LOW: u64 = 1;
const HIST_HIGH: u64 = 60_000_000;
const HIST_SIGFIG: u8 = 3;

const BUCKETS_US: &[(u64, &str)] = &[
    (1_000, "1ms"),
    (10_000, "10ms"),
    (100_000, "100ms"),
    (1_000_000, "1s"),
    (10_000_000, "10s"),
    (60_000_000, "60s"),
];

static REGISTRY: OnceLock<Mutex<HashMap<&'static str, Histogram<u64>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<&'static str, Histogram<u64>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record a single command latency in microseconds.
pub fn record(command: &str, duration_us: u64) {
    let cmd: &'static str = intern(command);
    let Ok(mut map) = registry().lock() else {
        return;
    };
    let hist = map
        .entry(cmd)
        .or_insert_with(|| Histogram::<u64>::new_with_bounds(HIST_LOW, HIST_HIGH, HIST_SIGFIG).expect("valid histogram bounds"));
    let clamped = duration_us.clamp(HIST_LOW, HIST_HIGH);
    let _ = hist.record(clamped);
}

// Bridge command names are a closed set in client.rs, but we accept &str
// so we don't have to thread the static through. Leak once per distinct name.
fn intern(s: &str) -> &'static str {
    use std::sync::RwLock;
    static INTERNED: OnceLock<RwLock<HashMap<String, &'static str>>> = OnceLock::new();
    let lock = INTERNED.get_or_init(|| RwLock::new(HashMap::new()));
    if let Some(v) = lock.read().ok().and_then(|r| r.get(s).copied()) {
        return v;
    }
    let mut w = lock.write().expect("interner lock");
    if let Some(v) = w.get(s).copied() {
        return v;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    w.insert(leaked.to_owned(), leaked);
    leaked
}

#[derive(Copy, Clone, Debug)]
pub enum FlushFormat {
    Human,
    Json,
}

/// Flush the current histogram snapshot to stderr in the chosen format.
pub fn flush(format: FlushFormat) {
    let Ok(map) = registry().lock() else {
        return;
    };
    if map.is_empty() {
        return;
    }
    match format {
        FlushFormat::Human => flush_human(&map),
        FlushFormat::Json => flush_json(&map),
    }
}

fn flush_human(map: &HashMap<&'static str, Histogram<u64>>) {
    let mut keys: Vec<&&'static str> = map.keys().collect();
    keys.sort();
    eprintln!("--- ghidra-cli command latency (us) ---");
    eprintln!(
        "{:<28} {:>7} {:>9} {:>9} {:>9} {:>9}",
        "command", "count", "p50", "p90", "p99", "max"
    );
    for k in keys {
        let h = &map[k];
        eprintln!(
            "{:<28} {:>7} {:>9} {:>9} {:>9} {:>9}",
            k,
            h.len(),
            h.value_at_quantile(0.50),
            h.value_at_quantile(0.90),
            h.value_at_quantile(0.99),
            h.max()
        );
    }
    eprintln!("buckets (count <= upper_us):");
    for k in map.keys() {
        let h = &map[*k];
        let mut line = format!("  {}:", k);
        for (upper, label) in BUCKETS_US {
            let n = h.count_between(0, *upper);
            line.push_str(&format!(" {}={}", label, n));
        }
        eprintln!("{}", line);
    }
}

fn flush_json(map: &HashMap<&'static str, Histogram<u64>>) {
    use serde_json::json;
    let mut entries = Vec::with_capacity(map.len());
    for (k, h) in map.iter() {
        let mut buckets = serde_json::Map::new();
        for (upper, label) in BUCKETS_US {
            buckets.insert((*label).to_string(), json!(h.count_between(0, *upper)));
        }
        entries.push(json!({
            "command": k,
            "count": h.len(),
            "p50_us": h.value_at_quantile(0.50),
            "p90_us": h.value_at_quantile(0.90),
            "p99_us": h.value_at_quantile(0.99),
            "max_us": h.max(),
            "buckets": serde_json::Value::Object(buckets),
        }));
    }
    let line = json!({"event": "ghidra_cli.metrics", "commands": entries});
    eprintln!("{}", line);
}

/// RAII guard that flushes the histogram on drop (process exit).
pub struct MetricsGuard {
    format: FlushFormat,
}

impl MetricsGuard {
    pub fn new(format: FlushFormat) -> Self {
        Self { format }
    }
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        flush(self.format);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_flushes_without_panicking() {
        record("__test_cmd", 100);
        record("__test_cmd", 10_000);
        // Both flush paths should be panic-free even with data present.
        flush(FlushFormat::Human);
        flush(FlushFormat::Json);
    }
}
