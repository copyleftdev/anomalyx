//! SQLite database parser — app/telemetry data that lives in `.db` files.
//!
//! The first user table (alphabetically, excluding the `sqlite_*` internals)
//! is scanned straight into a RecordSet: `SELECT *` in rowid order, each SQLite
//! value mapped to the closed [`Value`] set — so the full detector taxonomy
//! applies. The database is loaded from the byte buffer via SQLite's deserialize
//! API (no temp file). `REAL`→`Float`, `INTEGER`→`Int`, `TEXT`→`Str`, `BLOB`→hex
//! `Str`, `NULL`/non-finite→`Null`.
//!
//! Detected by the `SQLite format 3\0` magic; extensions `.db`/`.sqlite`/
//! `.sqlite3`/`.db3`. Behind the default-on `sqlite` feature (binary format).

use crate::parser::{Confidence, FormatParser, MAGIC};
use crate::table::TableBuilder;
use ax_core::{AxError, Column, Value};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, MAIN_DB};
use std::collections::BTreeMap;
use std::io::Cursor;

/// The 16-byte SQLite database file header.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\x00";

#[derive(Debug, Default, Clone)]
pub struct SqliteParser;

/// Maps a SQLite cell to the closed [`Value`] set. A blob becomes its lowercase
/// hex (deterministic; structural detectors still see the column exists).
fn value_ref_to_value(v: ValueRef) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::Int(i),
        ValueRef::Real(f) => {
            if f.is_finite() {
                Value::Float(f)
            } else {
                Value::Null
            }
        }
        ValueRef::Text(bytes) => Value::Str(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            Value::Str(hex)
        }
    }
}

impl SqliteParser {
    fn err(&self, msg: impl std::fmt::Display) -> AxError {
        AxError::Parse {
            format: self.id().to_string(),
            message: msg.to_string(),
        }
    }
}

impl FormatParser for SqliteParser {
    fn id(&self) -> &'static str {
        "sqlite"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["db", "sqlite", "sqlite3", "db3"]
    }
    fn sniff(&self, bytes: &[u8]) -> Option<Confidence> {
        bytes.starts_with(SQLITE_MAGIC).then_some(MAGIC)
    }
    fn parse(&self, _source: &str, bytes: &[u8]) -> Result<Vec<Column>, AxError> {
        // A WAL-mode database sets the file header's *read version* (byte 19) to
        // 2. We only ever receive the main-file image — the `-wal` companion does
        // not travel in a byte stream — and SQLite refuses to open a
        // read-version-2 image read-only, returning SQLITE_CANTOPEN. The main
        // image of a checkpointed WAL database is itself a complete, valid
        // database, so we reinterpret it as legacy (read version 1) on a private
        // copy and read its checkpointed state. This is read-only: we never write
        // these bytes back. (Byte 18, the write version, does not gate reads.)
        let patched: Vec<u8>;
        let data: &[u8] = if bytes.get(19) == Some(&2) {
            let mut v = bytes.to_vec();
            v[19] = 1;
            patched = v;
            &patched
        } else {
            bytes
        };

        let mut conn = Connection::open_in_memory().map_err(|e| self.err(e))?;
        conn.deserialize_read_exact(MAIN_DB, Cursor::new(data), data.len(), true)
            .map_err(|e| self.err(e))?;

        // First user table (deterministic order; internal tables excluded).
        let table: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| self.err(format!("no readable table: {e}")))?;

        let sql = format!("SELECT * FROM \"{}\"", table.replace('"', "\"\""));
        let mut stmt = conn.prepare(&sql).map_err(|e| self.err(e))?;
        let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();

        let mut rows = stmt.query([]).map_err(|e| self.err(e))?;
        let mut builder = TableBuilder::new();
        while let Some(row) = rows.next().map_err(|e| self.err(e))? {
            let mut record: BTreeMap<String, Value> = BTreeMap::new();
            for (i, name) in names.iter().enumerate() {
                let cell = row.get_ref(i).map_err(|e| self.err(e))?;
                record.insert(name.clone(), value_ref_to_value(cell));
            }
            builder.push_row(record);
        }
        Ok(builder.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ax_core::ColType;

    /// Builds an in-memory SQLite DB and serializes it to bytes (no committed
    /// binary fixture).
    fn build_db(setup: &str) -> Vec<u8> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(setup).unwrap();
        conn.serialize(MAIN_DB).unwrap().to_vec()
    }

    const EVENTS: &str = "CREATE TABLE events (id INTEGER, host TEXT, score REAL, ok INTEGER);\
        INSERT INTO events VALUES (1,'a',9.5,1),(2,'b',3.0,0),(3,'c',7.5,1);";

    fn col<'a>(cols: &'a [Column], name: &str) -> &'a Column {
        cols.iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
    }

    #[test]
    fn scans_a_table_into_typed_columns() {
        let cols = SqliteParser.parse("app.db", &build_db(EVENTS)).unwrap();
        assert_eq!(col(&cols, "id").ty, ColType::Int);
        assert_eq!(
            col(&cols, "id").cells,
            vec![Value::Int(1), Value::Int(2), Value::Int(3)]
        );
        assert_eq!(
            col(&cols, "host").cells,
            vec![
                Value::Str("a".into()),
                Value::Str("b".into()),
                Value::Str("c".into())
            ]
        );
        assert_eq!(col(&cols, "score").numeric(), vec![9.5, 3.0, 7.5]);
        assert_eq!(col(&cols, "ok").cells[1], Value::Int(0));
    }

    #[test]
    fn picks_the_first_table_alphabetically() {
        let db = build_db(
            "CREATE TABLE zeta (z INTEGER); INSERT INTO zeta VALUES (9);\
             CREATE TABLE alpha (a TEXT); INSERT INTO alpha VALUES ('first');",
        );
        let cols = SqliteParser.parse("-", &db).unwrap();
        // `alpha` sorts before `zeta`, so its column is the one scanned.
        assert_eq!(col(&cols, "a").cells, vec![Value::Str("first".into())]);
        assert!(cols.iter().all(|c| c.name != "z"));
    }

    #[test]
    fn reads_a_wal_mode_database() {
        // Production databases (browsers, peewee/yfinance, many apps) default to
        // WAL journal mode, whose header read-version byte (19) is 2. The
        // main-file image alone then can't be opened read-only without its `-wal`
        // companion — SQLite returns CANTOPEN. Flip a valid DB's read-version to
        // 2 to simulate WAL; the parser must still read it by reinterpreting the
        // checkpointed image as legacy (read-version 1).
        let mut db = build_db(EVENTS);
        assert_eq!(db[19], 1, "serialized fixture should start as legacy");
        db[19] = 2;
        let cols = SqliteParser.parse("app.db", &db).unwrap();
        assert_eq!(
            col(&cols, "id").cells,
            vec![Value::Int(1), Value::Int(2), Value::Int(3)]
        );
    }

    #[test]
    fn null_and_blob_cells() {
        let db = build_db(
            "CREATE TABLE t (v BLOB, n INTEGER);\
             INSERT INTO t VALUES (x'01ff', NULL);",
        );
        let cols = SqliteParser.parse("-", &db).unwrap();
        assert_eq!(col(&cols, "v").cells[0], Value::Str("01ff".into())); // blob → hex
        assert_eq!(col(&cols, "n").cells[0], Value::Null);
    }

    #[test]
    fn value_ref_units() {
        assert_eq!(value_ref_to_value(ValueRef::Null), Value::Null);
        assert_eq!(value_ref_to_value(ValueRef::Integer(7)), Value::Int(7));
        assert_eq!(value_ref_to_value(ValueRef::Real(1.5)), Value::Float(1.5));
        assert_eq!(value_ref_to_value(ValueRef::Real(f64::NAN)), Value::Null);
        assert_eq!(
            value_ref_to_value(ValueRef::Text(b"hi")),
            Value::Str("hi".into())
        );
        assert_eq!(
            value_ref_to_value(ValueRef::Blob(&[0x00, 0xab])),
            Value::Str("00ab".into())
        );
    }

    #[test]
    fn malformed_input_errors() {
        assert!(matches!(
            SqliteParser.parse("app.db", b"this is not a sqlite database"),
            Err(AxError::Parse { .. })
        ));
        // Magic header but otherwise garbage.
        let mut bad = SQLITE_MAGIC.to_vec();
        bad.extend_from_slice(b"corrupt");
        assert!(matches!(
            SqliteParser.parse("app.db", &bad),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn database_with_no_user_tables_errors() {
        assert!(matches!(
            SqliteParser.parse("-", &build_db("PRAGMA user_version = 1;")),
            Err(AxError::Parse { .. })
        ));
    }

    #[test]
    fn sniff_keys_on_magic() {
        assert_eq!(SqliteParser.sniff(&build_db(EVENTS)), Some(MAGIC));
        assert_eq!(
            SqliteParser.sniff(b"SQLite format 3\x00........"),
            Some(MAGIC)
        );
        assert_eq!(SqliteParser.sniff(b"SQLite format 3"), None); // missing the NUL
        assert_eq!(SqliteParser.sniff(b"PK\x03\x04"), None); // zip, not sqlite
        assert_eq!(SqliteParser.sniff(b"{\"a\":1}"), None);
    }

    #[test]
    fn claims_sqlite_extensions() {
        assert_eq!(
            SqliteParser.extensions(),
            &["db", "sqlite", "sqlite3", "db3"]
        );
    }

    #[test]
    fn resolves_by_extension_and_magic() {
        let reg = crate::parser::ParserRegistry::default();
        assert_eq!(reg.resolve("app.db", b"zz").unwrap().id(), "sqlite");
        assert_eq!(reg.resolve("data.sqlite3", b"zz").unwrap().id(), "sqlite");
        assert_eq!(reg.resolve("-", &build_db(EVENTS)).unwrap().id(), "sqlite");
    }
}
