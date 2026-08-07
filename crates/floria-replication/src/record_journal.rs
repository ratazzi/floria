//! Authenticated machine-local persistence for transport-neutral revisions.
//!
//! This database is deliberately separate from the runtime catalog. Creating it cannot bump the
//! catalog schema or make an installation depend on sync. A later durable-intent step will bridge
//! accepted records into the catalog/store projection.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use floria_integrity::StateAuthenticator;
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::record::{EntityRevision, RevisionAnalysis, RevisionSet};
use crate::{ReplicationError, ReplicationResult};

const SCHEMA_VERSION: i64 = 1;
const INTEGRITY_DOMAIN_PREFIX: &str = "sync-record-journal";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundRevision {
    revision: EntityRevision,
    expected_head_revision_id: Option<String>,
    created_at: String,
}

impl OutboundRevision {
    pub fn revision(&self) -> &EntityRevision {
        &self.revision
    }

    pub fn expected_head_revision_id(&self) -> Option<&str> {
        self.expected_head_revision_id.as_deref()
    }

    pub fn created_at(&self) -> &str {
        &self.created_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundRevision {
    revision: EntityRevision,
    received_at: String,
}

impl InboundRevision {
    pub fn revision(&self) -> &EntityRevision {
        &self.revision
    }

    pub fn received_at(&self) -> &str {
        &self.received_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SchemaObject {
    kind: String,
    name: String,
    table_name: String,
    sql: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JournalSecuritySnapshot {
    schema_version: i64,
    schema: Vec<SchemaObject>,
    revisions: Vec<EntityRevision>,
    outbound: Vec<OutboundRevision>,
    inbound: Vec<InboundRevision>,
}

struct JournalIntegrity {
    authenticator: Arc<StateAuthenticator>,
    sidecar: PathBuf,
    domain: String,
}

/// A private authenticated SQLite journal for encrypted records and delivery queues.
pub struct RecordJournal {
    path: PathBuf,
    integrity: JournalIntegrity,
    mutation: Mutex<()>,
}

impl RecordJournal {
    pub fn open(
        path: impl Into<PathBuf>,
        vault_id: &str,
        authenticator: Arc<StateAuthenticator>,
    ) -> ReplicationResult<Self> {
        require_uuid("vault id", vault_id)?;
        let path = path.into();
        ensure_parent(&path)?;
        let created = create_private_database_file(&path)?;
        let path = fs::canonicalize(&path).map_err(|source| ReplicationError::Io {
            path: path.clone(),
            source,
        })?;

        let mut conn = open_connection(&path)?;
        initialize_or_require_schema(&mut conn, created)?;
        let current = security_snapshot_from(&conn)?;
        validate_snapshot(&current)?;

        let sidecar = path.with_extension("integrity.json");
        let domain = format!("{INTEGRITY_DOMAIN_PREFIX}:{vault_id}");
        let loaded = authenticator.load::<JournalSecuritySnapshot>(&sidecar, &domain)?;
        match loaded.value {
            Some(authenticated) if authenticated == current => {}
            Some(_) => {
                return Err(ReplicationError::Invalid(
                    "record journal does not match its authenticated snapshot".to_string(),
                ))
            }
            None if created && loaded.generation == 0 => {
                authenticator.persist(&sidecar, &domain, 0, &current)?;
            }
            None if loaded.generation == 0 => {
                return Err(ReplicationError::Invalid(
                    "refusing to adopt an existing record journal without an authenticated snapshot"
                        .to_string(),
                ))
            }
            None => {
                return Err(ReplicationError::Invalid(format!(
                    "record journal sidecar {} is missing at authenticated generation {}",
                    sidecar.display(),
                    loaded.generation
                )))
            }
        }

        Ok(Self {
            path,
            integrity: JournalIntegrity {
                authenticator,
                sidecar,
                domain,
            },
            mutation: Mutex::new(()),
        })
    }

    /// Persist one local immutable revision and its pending CAS publication in one transaction.
    pub fn queue_outbound(
        &self,
        revision: EntityRevision,
        expected_head_revision_id: Option<String>,
        created_at: impl Into<String>,
    ) -> ReplicationResult<()> {
        let revision = canonical_revision(revision)?;
        if let Some(expected) = &expected_head_revision_id {
            require_uuid("expected head revision id", expected)?;
            if !revision.parents().iter().any(|parent| parent == expected) {
                return Err(ReplicationError::Invalid(format!(
                    "expected head {expected} is not a parent of revision {}",
                    revision.revision_id()
                )));
            }
        }
        let created_at = require_time("outbound creation time", created_at.into())?;
        self.with_mutation(|tx| {
            store_revision(tx, &revision)?;
            let item = OutboundRevision {
                revision: revision.clone(),
                expected_head_revision_id,
                created_at,
            };
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO record_outbox (
                    revision_id, expected_head_revision_id, created_at
                 ) VALUES (?1, ?2, ?3)",
                params![
                    revision.revision_id(),
                    item.expected_head_revision_id,
                    item.created_at,
                ],
            )?;
            if inserted == 0 {
                let existing = outbound_by_id(tx, revision.revision_id())?.ok_or_else(|| {
                    ReplicationError::Invalid("record outbox row disappeared".to_string())
                })?;
                if existing != item {
                    return Err(ReplicationError::Invalid(format!(
                        "outbound revision {} is already queued with different delivery state",
                        revision.revision_id()
                    )));
                }
            }
            Ok(())
        })
    }

    /// Persist one remote immutable revision until projection applies it.
    pub fn receive_inbound(
        &self,
        revision: EntityRevision,
        received_at: impl Into<String>,
    ) -> ReplicationResult<()> {
        let revision = canonical_revision(revision)?;
        let received_at = require_time("inbound receipt time", received_at.into())?;
        self.with_mutation(|tx| {
            store_revision(tx, &revision)?;
            let item = InboundRevision {
                revision: revision.clone(),
                received_at,
            };
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO record_inbox (revision_id, received_at) VALUES (?1, ?2)",
                params![revision.revision_id(), item.received_at],
            )?;
            if inserted == 0 {
                let existing = inbound_by_id(tx, revision.revision_id())?.ok_or_else(|| {
                    ReplicationError::Invalid("record inbox row disappeared".to_string())
                })?;
                if existing != item {
                    return Err(ReplicationError::Invalid(format!(
                        "inbound revision {} is already queued with a different receipt",
                        revision.revision_id()
                    )));
                }
            }
            Ok(())
        })
    }

    /// A repeated adapter acknowledgement is harmless. The immutable revision remains as history.
    pub fn settle_outbound(&self, revision_id: &str) -> ReplicationResult<bool> {
        require_uuid("outbound revision id", revision_id)?;
        self.with_mutation(|tx| {
            Ok(tx.execute(
                "DELETE FROM record_outbox WHERE revision_id = ?1",
                params![revision_id],
            )? != 0)
        })
    }

    /// A repeated projection acknowledgement is harmless. The immutable revision remains as history.
    pub fn settle_inbound(&self, revision_id: &str) -> ReplicationResult<bool> {
        require_uuid("inbound revision id", revision_id)?;
        self.with_mutation(|tx| {
            Ok(tx.execute(
                "DELETE FROM record_inbox WHERE revision_id = ?1",
                params![revision_id],
            )? != 0)
        })
    }

    pub fn outbound(&self) -> ReplicationResult<Vec<OutboundRevision>> {
        self.with_read(|_, snapshot| Ok(snapshot.outbound.clone()))
    }

    pub fn inbound(&self) -> ReplicationResult<Vec<InboundRevision>> {
        self.with_read(|_, snapshot| Ok(snapshot.inbound.clone()))
    }

    pub fn analysis(&self) -> ReplicationResult<RevisionAnalysis> {
        self.with_read(|_, snapshot| analysis_from(&snapshot.revisions))
    }

    fn with_read<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>, &JournalSecuritySnapshot) -> ReplicationResult<T>,
    ) -> ReplicationResult<T> {
        let _mutation = self.mutation.lock().expect("record journal lock poisoned");
        let mut conn = open_connection(&self.path)?;
        let tx = conn.transaction()?;
        let current = security_snapshot_from(&tx)?;
        self.verify_snapshot(&current)?;
        let result = operation(&tx, &current)?;
        tx.commit()?;
        Ok(result)
    }

    fn with_mutation<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> ReplicationResult<T>,
    ) -> ReplicationResult<T> {
        let _mutation = self.mutation.lock().expect("record journal lock poisoned");
        let mut conn = open_connection(&self.path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = security_snapshot_from(&tx)?;
        let generation = self.verify_snapshot(&current)?;
        let result = operation(&tx)?;
        let next = security_snapshot_from(&tx)?;
        validate_snapshot(&next)?;
        self.integrity.authenticator.persist(
            &self.integrity.sidecar,
            &self.integrity.domain,
            generation,
            &next,
        )?;
        tx.commit()?;
        Ok(result)
    }

    fn verify_snapshot(&self, current: &JournalSecuritySnapshot) -> ReplicationResult<u64> {
        let loaded = self
            .integrity
            .authenticator
            .load::<JournalSecuritySnapshot>(&self.integrity.sidecar, &self.integrity.domain)?;
        let authenticated = loaded.value.ok_or_else(|| {
            ReplicationError::Invalid("authenticated record journal snapshot is missing".to_string())
        })?;
        if authenticated != *current {
            return Err(ReplicationError::Invalid(
                "record journal changed outside its authenticated transaction boundary".to_string(),
            ));
        }
        Ok(loaded.generation)
    }
}

fn initialize_or_require_schema(conn: &mut Connection, created: bool) -> ReplicationResult<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if created && version == 0 {
        let tx = conn.transaction()?;
        tx.execute_batch(
            "CREATE TABLE record_revisions (
                revision_id TEXT PRIMARY KEY,
                entity_id TEXT NOT NULL,
                envelope_json BLOB NOT NULL
            );
            CREATE INDEX record_revisions_entity_idx
                ON record_revisions(entity_id, revision_id);

            CREATE TABLE record_outbox (
                revision_id TEXT PRIMARY KEY
                    REFERENCES record_revisions(revision_id) ON DELETE RESTRICT,
                expected_head_revision_id TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX record_outbox_created_idx
                ON record_outbox(created_at, revision_id);

            CREATE TABLE record_inbox (
                revision_id TEXT PRIMARY KEY
                    REFERENCES record_revisions(revision_id) ON DELETE RESTRICT,
                received_at TEXT NOT NULL
            );
            CREATE INDEX record_inbox_received_idx
                ON record_inbox(received_at, revision_id);

            PRAGMA user_version = 1;",
        )?;
        tx.commit()?;
        return Ok(());
    }
    if version != SCHEMA_VERSION {
        return Err(ReplicationError::Invalid(format!(
            "record journal schema is {version}, expected {SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn open_connection(path: &Path) -> ReplicationResult<Connection> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(Duration::from_secs(2))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(conn)
}

fn security_snapshot_from(conn: &Connection) -> ReplicationResult<JournalSecuritySnapshot> {
    let schema_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version != SCHEMA_VERSION {
        return Err(ReplicationError::Invalid(format!(
            "record journal schema is {schema_version}, expected {SCHEMA_VERSION}"
        )));
    }
    let schema = schema_objects_from(conn)?;
    if let Some(object) = schema
        .iter()
        .find(|object| matches!(object.kind.as_str(), "trigger" | "view"))
    {
        return Err(ReplicationError::Invalid(format!(
            "record journal contains unsupported {} {:?}",
            object.kind, object.name
        )));
    }
    let revisions = revisions_from(conn)?;
    let outbound = outbound_from(conn)?;
    let inbound = inbound_from(conn)?;
    Ok(JournalSecuritySnapshot {
        schema_version,
        schema,
        revisions,
        outbound,
        inbound,
    })
}

fn validate_snapshot(snapshot: &JournalSecuritySnapshot) -> ReplicationResult<()> {
    analysis_from(&snapshot.revisions)?;
    for item in &snapshot.outbound {
        if !snapshot
            .revisions
            .iter()
            .any(|revision| revision == item.revision())
        {
            return Err(ReplicationError::Invalid(format!(
                "outbox revision {} is missing from immutable history",
                item.revision().revision_id()
            )));
        }
    }
    for item in &snapshot.inbound {
        if !snapshot
            .revisions
            .iter()
            .any(|revision| revision == item.revision())
        {
            return Err(ReplicationError::Invalid(format!(
                "inbox revision {} is missing from immutable history",
                item.revision().revision_id()
            )));
        }
    }
    Ok(())
}

fn analysis_from(revisions: &[EntityRevision]) -> ReplicationResult<RevisionAnalysis> {
    let mut set = RevisionSet::new();
    for revision in revisions {
        set.insert(revision.clone())
            .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
    }
    set.analyze()
        .map_err(|error| ReplicationError::Invalid(error.to_string()))
}

fn canonical_revision(revision: EntityRevision) -> ReplicationResult<EntityRevision> {
    let revision_id = revision.revision_id().to_string();
    let mut set = RevisionSet::new();
    set.insert(revision)
        .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
    Ok(set
        .get(&revision_id)
        .expect("inserted revision is present")
        .clone())
}

fn store_revision(tx: &Transaction<'_>, revision: &EntityRevision) -> ReplicationResult<()> {
    let envelope = serde_json::to_vec(revision)?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO record_revisions (revision_id, entity_id, envelope_json)
         VALUES (?1, ?2, ?3)",
        params![revision.revision_id(), revision.entity_id(), envelope],
    )?;
    if inserted == 0 {
        let existing = revision_by_id(tx, revision.revision_id())?.ok_or_else(|| {
            ReplicationError::Invalid("record revision row disappeared".to_string())
        })?;
        if existing != *revision {
            return Err(ReplicationError::Invalid(format!(
                "revision id {} was reused for different content",
                revision.revision_id()
            )));
        }
    }
    Ok(())
}

fn revisions_from(conn: &Connection) -> ReplicationResult<Vec<EntityRevision>> {
    let mut statement = conn.prepare(
        "SELECT revision_id, entity_id, envelope_json
         FROM record_revisions ORDER BY revision_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut revisions = Vec::new();
    for row in rows {
        let (revision_id, entity_id, envelope) = row?;
        let revision: EntityRevision = serde_json::from_slice(&envelope)?;
        let revision = canonical_revision(revision)?;
        if revision.revision_id() != revision_id || revision.entity_id() != entity_id {
            return Err(ReplicationError::Invalid(format!(
                "record revision index does not match envelope {revision_id}"
            )));
        }
        revisions.push(revision);
    }
    Ok(revisions)
}

fn revision_by_id(
    conn: &Connection,
    revision_id: &str,
) -> ReplicationResult<Option<EntityRevision>> {
    let envelope = conn
        .query_row(
            "SELECT envelope_json FROM record_revisions WHERE revision_id = ?1",
            params![revision_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    envelope
        .map(|envelope| {
            let revision = serde_json::from_slice(&envelope)?;
            canonical_revision(revision)
        })
        .transpose()
}

fn outbound_from(conn: &Connection) -> ReplicationResult<Vec<OutboundRevision>> {
    let mut statement = conn.prepare(
        "SELECT revision_id, expected_head_revision_id, created_at
         FROM record_outbox ORDER BY created_at, revision_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut items = Vec::new();
    for row in rows {
        let (revision_id, expected_head_revision_id, created_at) = row?;
        let revision = revision_by_id(conn, &revision_id)?.ok_or_else(|| {
            ReplicationError::Invalid(format!("outbox revision {revision_id} is missing"))
        })?;
        items.push(OutboundRevision {
            revision,
            expected_head_revision_id,
            created_at,
        });
    }
    Ok(items)
}

fn outbound_by_id(
    conn: &Connection,
    revision_id: &str,
) -> ReplicationResult<Option<OutboundRevision>> {
    Ok(outbound_from(conn)?
        .into_iter()
        .find(|item| item.revision.revision_id() == revision_id))
}

fn inbound_from(conn: &Connection) -> ReplicationResult<Vec<InboundRevision>> {
    let mut statement = conn.prepare(
        "SELECT revision_id, received_at
         FROM record_inbox ORDER BY received_at, revision_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut items = Vec::new();
    for row in rows {
        let (revision_id, received_at) = row?;
        let revision = revision_by_id(conn, &revision_id)?.ok_or_else(|| {
            ReplicationError::Invalid(format!("inbox revision {revision_id} is missing"))
        })?;
        items.push(InboundRevision {
            revision,
            received_at,
        });
    }
    Ok(items)
}

fn inbound_by_id(
    conn: &Connection,
    revision_id: &str,
) -> ReplicationResult<Option<InboundRevision>> {
    Ok(inbound_from(conn)?
        .into_iter()
        .find(|item| item.revision.revision_id() == revision_id))
}

fn schema_objects_from(conn: &Connection) -> ReplicationResult<Vec<SchemaObject>> {
    let mut statement = conn.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '')
         FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name, tbl_name",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok(SchemaObject {
                kind: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReplicationError::from)?;
    Ok(objects)
}

fn ensure_parent(path: &Path) -> ReplicationResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|source| ReplicationError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
    }
    Ok(())
}

fn create_private_database_file(path: &Path) -> ReplicationResult<bool> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|source| ReplicationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ReplicationError::Invalid(format!(
                "record journal {} must be a regular file",
                path.display()
            )));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ReplicationError::Invalid(format!(
                "record journal {} must be private, got mode {mode:04o}",
                path.display()
            )));
        }
        return Ok(false);
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| ReplicationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(true)
}

fn require_uuid(label: &str, value: &str) -> ReplicationResult<()> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ReplicationError::Invalid(format!("{label} is not a UUID: {value:?}")))
}

fn require_time(label: &str, value: String) -> ReplicationResult<String> {
    if value.trim().is_empty() {
        Err(ReplicationError::Invalid(format!("{label} cannot be empty")))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ImmutableObjectRef;

    fn id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn revision(entity_id: &str, revision_id: &str, parents: Vec<String>) -> EntityRevision {
        EntityRevision::new(
            entity_id,
            revision_id,
            parents,
            b"encrypted-record-fixture".to_vec(),
            vec![ImmutableObjectRef::new("cd".repeat(32), 24).unwrap()],
        )
        .unwrap()
    }

    fn authenticator() -> Arc<StateAuthenticator> {
        Arc::new(StateAuthenticator::for_tests([91; 32]))
    }

    fn open(
        directory: &tempfile::TempDir,
        vault_id: &str,
        authenticator: Arc<StateAuthenticator>,
    ) -> RecordJournal {
        RecordJournal::open(
            directory.path().join("records.sqlite"),
            vault_id,
            authenticator,
        )
        .unwrap()
    }

    #[test]
    fn outbound_is_atomic_idempotent_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let entity_id = id();
        let revision_id = id();
        let item = revision(&entity_id, &revision_id, Vec::new());
        let authenticator = authenticator();
        let journal = open(&directory, &vault_id, Arc::clone(&authenticator));

        journal
            .queue_outbound(item.clone(), None, "2026-08-07T00:00:00Z")
            .unwrap();
        journal
            .queue_outbound(item, None, "2026-08-07T00:00:00Z")
            .unwrap();
        assert_eq!(journal.outbound().unwrap().len(), 1);
        assert_eq!(
            journal.analysis().unwrap().heads_for(&entity_id),
            std::slice::from_ref(&revision_id)
        );
        drop(journal);

        let reopened = open(&directory, &vault_id, authenticator);
        assert_eq!(reopened.outbound().unwrap().len(), 1);
        assert!(reopened.settle_outbound(&revision_id).unwrap());
        assert!(!reopened.settle_outbound(&revision_id).unwrap());
        assert!(reopened.outbound().unwrap().is_empty());
        assert_eq!(
            reopened.analysis().unwrap().heads_for(&entity_id),
            std::slice::from_ref(&revision_id)
        );
    }

    #[test]
    fn inbound_can_arrive_child_first_and_remains_pending_until_parent_arrives() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let entity_id = id();
        let root_id = id();
        let child_id = id();
        let journal = open(&directory, &vault_id, authenticator());

        journal
            .receive_inbound(
                revision(&entity_id, &child_id, vec![root_id.clone()]),
                "2026-08-07T00:00:01Z",
            )
            .unwrap();
        assert_eq!(journal.analysis().unwrap().pending().len(), 1);
        journal
            .receive_inbound(
                revision(&entity_id, &root_id, Vec::new()),
                "2026-08-07T00:00:02Z",
            )
            .unwrap();
        assert_eq!(journal.analysis().unwrap().heads_for(&entity_id), &[child_id]);
        assert!(journal.analysis().unwrap().pending().is_empty());
        assert_eq!(journal.inbound().unwrap().len(), 2);
    }

    #[test]
    fn outbound_expected_head_must_be_a_parent() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let entity_id = id();
        let revision_id = id();
        let unrelated = id();
        let journal = open(&directory, &vault_id, authenticator());

        let error = journal
            .queue_outbound(
                revision(&entity_id, &revision_id, Vec::new()),
                Some(unrelated.clone()),
                "2026-08-07T00:00:00Z",
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains(&format!("expected head {unrelated} is not a parent")));
        assert!(journal.outbound().unwrap().is_empty());
    }

    #[test]
    fn external_database_tampering_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let entity_id = id();
        let revision_id = id();
        let path = directory.path().join("records.sqlite");
        let journal = open(&directory, &vault_id, authenticator());
        journal
            .queue_outbound(
                revision(&entity_id, &revision_id, Vec::new()),
                None,
                "2026-08-07T00:00:00Z",
            )
            .unwrap();

        let attacker = Connection::open(path).unwrap();
        attacker
            .execute(
                "UPDATE record_outbox SET created_at = 'changed' WHERE revision_id = ?1",
                params![revision_id],
            )
            .unwrap();
        drop(attacker);

        assert!(journal
            .outbound()
            .unwrap_err()
            .to_string()
            .contains("outside its authenticated transaction boundary"));
    }
}
