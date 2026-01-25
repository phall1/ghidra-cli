//! Caching layer for common requests.
//!
//! Caches results of expensive Ghidra operations to speed up repeated queries.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::debug;

use crate::cli::Commands;

/// A cached entry with timestamp.
struct CacheEntry {
    value: String,
    inserted_at: Instant,
}

impl CacheEntry {
    fn new(value: String) -> Self {
        Self {
            value,
            inserted_at: Instant::now(),
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() > ttl
    }
}

/// Cache for command results.
pub struct Cache {
    /// Cache storage
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Time-to-live for cache entries
    ttl: Duration,
}

impl Cache {
    /// Create a new cache with default TTL (5 minutes).
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(300))
    }

    /// Create a new cache with custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    /// Get a cached value if it exists and hasn't expired.
    pub async fn get(&self, command: &Commands) -> Option<String> {
        let key = self.cache_key(command)?;

        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(&key) {
            if !entry.is_expired(self.ttl) {
                debug!("Cache hit for key: {}", key);
                return Some(entry.value.clone());
            } else {
                debug!("Cache entry expired for key: {}", key);
            }
        }

        None
    }

    /// Set a cached value.
    pub async fn set(&self, command: &Commands, value: String) {
        if let Some(key) = self.cache_key(command) {
            let mut entries = self.entries.write().await;
            entries.insert(key.clone(), CacheEntry::new(value));
            debug!("Cached result for key: {}", key);
        }
    }

    /// Clear all cached entries.
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        debug!("Cache cleared");
    }

    /// Remove expired entries.
    pub async fn cleanup(&self) {
        let mut entries = self.entries.write().await;
        let ttl = self.ttl;
        entries.retain(|_, entry| !entry.is_expired(ttl));
        debug!("Cache cleanup completed");
    }

    /// Generate a cache key for a command.
    /// Only cacheable commands return Some.
    fn cache_key(&self, command: &Commands) -> Option<String> {
        // For now, generate a simple cache key based on debug representation
        // TODO: Implement proper cache key generation for specific command types
        Some(format!("{:?}", command))
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_operations() {
        let cache = Cache::new();

        // Create a test command (using Version since it's simple)
        let command = Commands::Version;

        // Should be empty initially
        assert!(cache.get(&command).await.is_none());

        // Set a value
        cache.set(&command, "test result".to_string()).await;

        // Should return the value
        assert_eq!(cache.get(&command).await, Some("test result".to_string()));

        // Clear cache
        cache.clear().await;

        // Should be empty again
        assert!(cache.get(&command).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = Cache::with_ttl(Duration::from_millis(100));

        let command = Commands::Version;

        cache.set(&command, "test".to_string()).await;
        assert!(cache.get(&command).await.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        assert!(cache.get(&command).await.is_none());
    }
}
