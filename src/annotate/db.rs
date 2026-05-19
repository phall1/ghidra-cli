//! SQLite-backed annotation store (E6.2 / ghidra-cli-0pn).
//!
//! The store keeps function-level annotations (name, signature,
//! return type, parameters, comments, variable renames) keyed by the
//! PCode-based fingerprint defined in [`super::hash`]. The join key
//! survives recompilation, so a project re-imported from a newer build
//! of the same binary can recover all the analyst-authored knowledge.
//!
//! Migration model:
//!
//! - The schema lives in [`MIGRATIONS`] as an ordered list of
//!   `(version, sql)` pairs. Versions are strictly increasing
//!   integers, never reused. To evolve the schema, *append* a new
//!   entry; never edit a shipped one.
//! - `schema_migrations` records every applied version. On `open()`,
//!   any migration whose `version` is greater than the max recorded
//!   value is applied inside one transaction per migration.
//! - There are no down-migrations. If something goes wrong we ship a
//!   forward-fix migration; backing out a half-applied schema is the
//!   user's last resort (delete the .sqlite file).
//!
//! All JSON-shaped columns (params, comments, renames) carry
//! `serde_json::Value` and are stored as TEXT, not BLOB, so a human
//! poking the DB with the `sqlite3` CLI sees readable rows.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Append-only migration log. Each entry must have a strictly
/// increasing `version`. Do not edit a shipped entry — write a new one.
const MIGRATIONS: &[(i32, &str)] = &[(
    1,
    r#"
    CREATE TABLE annotations (
        function_hash  TEXT    NOT NULL,
        project        TEXT    NOT NULL,
        program        TEXT    NOT NULL,
        name           TEXT,
        signature      TEXT,
        return_type    TEXT,
        params         TEXT,   -- JSON array of {name, type, ...}
        comments       TEXT,   -- JSON array of {address, text, type}
        renames        TEXT,   -- JSON object of variable renames
        updated_at     INTEGER NOT NULL,  -- unix epoch seconds
        PRIMARY KEY (function_hash, project, program)
    );

    -- Hash lookups dominate the `annotate apply` path; project lookups
    -- dominate the `annotate export` (walk one project) path. Both
    -- get explicit indices so we don't fall back to scans on bigger
    -- projects.
    CREATE INDEX idx_annot_hash    ON annotations(function_hash);
    CREATE INDEX idx_annot_project ON annotations(project);
    "#,
)];

/// A single annotation row. JSON-shaped fields are kept as
/// `serde_json::Value` so callers can round-trip whatever payload
/// makes sense for them without us baking in a schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Annotation {
    pub function_hash: String,
    pub project: String,
    pub program: String,
    pub name: Option<String>,
    pub signature: Option<String>,
    pub return_type: Option<String>,
    pub params: Option<serde_json::Value>,
    pub comments: Option<serde_json::Value>,
    pub renames: Option<serde_json::Value>,
    /// Unix epoch seconds. Filled by [`Db::upsert`] if `None`; passed
    /// through if `Some` (useful for tests + replay imports).
    pub updated_at: Option<i64>,
}

pub struct Db {
    conn: Connection,
}

impl Db {
    /// Open (or create) the annotation DB at `path`. Runs any pending
    /// migrations as part of the open — callers don't need to invoke
    /// the migrator separately.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path.as_ref())
            .with_context(|| format!("failed to open annotation DB at {:?}", path.as_ref()))?;
        let mut db = Self { conn };
        db.migrate().context("schema migration failed")?;
        Ok(db)
    }

    /// In-memory variant — useful for tests that want a transient DB
    /// without touching the filesystem.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory DB")?;
        let mut db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Apply every migration whose version is greater than what's
    /// recorded. Idempotent: opening an already-migrated DB is a
    /// no-op other than reading the version row.
    pub fn migrate(&mut self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version    INTEGER PRIMARY KEY,
                 applied_at INTEGER NOT NULL
             );",
        )?;

        let current: i32 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        for (version, sql) in MIGRATIONS {
            if *version <= current {
                continue;
            }
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)
                .with_context(|| format!("migration {} failed", version))?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                params![*version, now_unix()],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Insert-or-replace an annotation row. The (function_hash,
    /// project, program) tuple is the natural key — repeated upserts
    /// on the same key overwrite. `updated_at` is filled with the
    /// current epoch if the caller didn't supply one.
    pub fn upsert(&self, ann: &Annotation) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO annotations
                    (function_hash, project, program, name, signature, return_type,
                     params, comments, renames, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(function_hash, project, program) DO UPDATE SET
                    name        = excluded.name,
                    signature   = excluded.signature,
                    return_type = excluded.return_type,
                    params      = excluded.params,
                    comments    = excluded.comments,
                    renames     = excluded.renames,
                    updated_at  = excluded.updated_at",
                params![
                    ann.function_hash,
                    ann.project,
                    ann.program,
                    ann.name,
                    ann.signature,
                    ann.return_type,
                    ann.params.as_ref().map(|v| v.to_string()),
                    ann.comments.as_ref().map(|v| v.to_string()),
                    ann.renames.as_ref().map(|v| v.to_string()),
                    ann.updated_at.unwrap_or_else(now_unix),
                ],
            )
            .context("insert annotation")?;
        Ok(())
    }

    /// Fetch annotation by exact (function_hash, project, program).
    /// Returns `None` if no row matches — callers decide whether
    /// that's an error.
    pub fn get(
        &self,
        function_hash: &str,
        project: &str,
        program: &str,
    ) -> Result<Option<Annotation>> {
        self.conn
            .query_row(
                "SELECT function_hash, project, program, name, signature, return_type,
                        params, comments, renames, updated_at
                   FROM annotations
                  WHERE function_hash = ?1 AND project = ?2 AND program = ?3",
                params![function_hash, project, program],
                row_to_annotation,
            )
            .optional()
            .context("query annotation")
    }

    /// Fetch all annotations that match a function hash, across any
    /// project/program. This is the `annotate apply` lookup path: we
    /// have a hash from the *current* project and want to find prior
    /// analysis from any other project that contained the same
    /// function.
    pub fn find_by_hash(&self, function_hash: &str) -> Result<Vec<Annotation>> {
        let mut stmt = self.conn.prepare(
            "SELECT function_hash, project, program, name, signature, return_type,
                    params, comments, renames, updated_at
               FROM annotations
              WHERE function_hash = ?1
              ORDER BY updated_at DESC",
        )?;
        let rows = stmt
            .query_map(params![function_hash], row_to_annotation)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// List every annotation in a project. Drives `annotate export`.
    pub fn list_project(&self, project: &str) -> Result<Vec<Annotation>> {
        let mut stmt = self.conn.prepare(
            "SELECT function_hash, project, program, name, signature, return_type,
                    params, comments, renames, updated_at
               FROM annotations
              WHERE project = ?1
              ORDER BY program, function_hash",
        )?;
        let rows = stmt
            .query_map(params![project], row_to_annotation)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Total row count. Mostly for `ghidra-cli annotate stats` and
    /// for tests; not hot.
    pub fn count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM annotations", [], |r| r.get(0))?)
    }

    /// Highest migration version recorded. Test hook so callers can
    /// assert the schema is at the expected level.
    pub fn schema_version(&self) -> Result<i32> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?)
    }
}

fn row_to_annotation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Annotation> {
    Ok(Annotation {
        function_hash: row.get(0)?,
        project: row.get(1)?,
        program: row.get(2)?,
        name: row.get(3)?,
        signature: row.get(4)?,
        return_type: row.get(5)?,
        params: row
            .get::<_, Option<String>>(6)?
            .map(|s| serde_json::from_str(&s).unwrap_or(serde_json::Value::Null)),
        comments: row
            .get::<_, Option<String>>(7)?
            .map(|s| serde_json::from_str(&s).unwrap_or(serde_json::Value::Null)),
        renames: row
            .get::<_, Option<String>>(8)?
            .map(|s| serde_json::from_str(&s).unwrap_or(serde_json::Value::Null)),
        updated_at: row.get(9)?,
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample(hash: &str) -> Annotation {
        Annotation {
            function_hash: hash.to_owned(),
            project: "proj1".to_owned(),
            program: "binary.elf".to_owned(),
            name: Some("parse_packet_header".to_owned()),
            signature: Some("int parse_packet_header(uint8_t*)".to_owned()),
            return_type: Some("int".to_owned()),
            params: Some(json!([{"name": "buf", "type": "uint8_t*"}])),
            comments: Some(json!([{"address": "0x401000", "text": "entry", "type": "PRE"}])),
            renames: Some(json!({"local_4": "header_len"})),
            updated_at: None,
        }
    }

    #[test]
    fn schema_applies_on_open() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.schema_version().unwrap(), 1);
    }

    #[test]
    fn migrate_is_idempotent() {
        // Open, drop, reopen the *same* file path → should not blow up
        // re-applying migration 1. We can't use in_memory here because
        // its lifetime ends when the Db drops, so use a real tempfile.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        {
            let _ = Db::open(&path).unwrap();
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(db.schema_version().unwrap(), 1);
    }

    #[test]
    fn upsert_then_get_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        let a = sample("aaaa");
        db.upsert(&a).unwrap();
        let got = db.get("aaaa", "proj1", "binary.elf").unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("parse_packet_header"));
        assert_eq!(got.params, a.params);
        assert_eq!(got.comments, a.comments);
        assert_eq!(got.renames, a.renames);
        // updated_at should have been backfilled
        assert!(got.updated_at.unwrap() > 0);
    }

    #[test]
    fn upsert_overwrites_on_conflict() {
        let db = Db::open_in_memory().unwrap();
        let mut a = sample("aaaa");
        db.upsert(&a).unwrap();
        a.name = Some("new_name".to_owned());
        a.updated_at = Some(12345); // pin so we can assert
        db.upsert(&a).unwrap();

        let got = db.get("aaaa", "proj1", "binary.elf").unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("new_name"));
        assert_eq!(got.updated_at, Some(12345));
        assert_eq!(db.count().unwrap(), 1, "must overwrite, not insert");
    }

    #[test]
    fn find_by_hash_returns_all_projects() {
        let db = Db::open_in_memory().unwrap();
        let mut a = sample("aaaa");
        a.updated_at = Some(1);
        db.upsert(&a).unwrap();
        a.project = "proj2".to_owned();
        a.updated_at = Some(3);
        db.upsert(&a).unwrap();
        a.project = "proj3".to_owned();
        a.updated_at = Some(2);
        db.upsert(&a).unwrap();

        let hits = db.find_by_hash("aaaa").unwrap();
        assert_eq!(hits.len(), 3);
        // Ordered by updated_at DESC: 3, 2, 1.
        assert_eq!(hits[0].project, "proj2");
        assert_eq!(hits[1].project, "proj3");
        assert_eq!(hits[2].project, "proj1");
    }

    #[test]
    fn list_project_filters_correctly() {
        let db = Db::open_in_memory().unwrap();
        let mut a = sample("aaaa");
        db.upsert(&a).unwrap();
        a.project = "other".to_owned();
        a.function_hash = "bbbb".to_owned();
        db.upsert(&a).unwrap();

        let proj1 = db.list_project("proj1").unwrap();
        assert_eq!(proj1.len(), 1);
        assert_eq!(proj1[0].function_hash, "aaaa");
    }

    #[test]
    fn missing_row_returns_none_not_error() {
        let db = Db::open_in_memory().unwrap();
        let got = db.get("nope", "nope", "nope").unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn null_json_fields_roundtrip_as_none() {
        let db = Db::open_in_memory().unwrap();
        let a = Annotation {
            function_hash: "z".to_owned(),
            project: "p".to_owned(),
            program: "b".to_owned(),
            name: None,
            signature: None,
            return_type: None,
            params: None,
            comments: None,
            renames: None,
            updated_at: Some(42),
        };
        db.upsert(&a).unwrap();
        let got = db.get("z", "p", "b").unwrap().unwrap();
        assert_eq!(got, a);
    }
}
