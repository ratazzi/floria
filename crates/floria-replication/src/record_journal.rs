//! Authenticated machine-local persistence for transport-neutral revisions.
//!
//! This database is deliberately separate from the runtime catalog. Creating it cannot bump the
//! catalog schema or make an installation depend on sync. A later durable-intent step will bridge
//! accepted records into the catalog/store projection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use floria_integrity::StateAuthenticator;
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::record::{
    CommitReadiness, EntityRevision, RevisionAnalysis, RevisionCommit, RevisionSet,
};
use crate::{ReplicationError, ReplicationResult};

const SCHEMA_VERSION: i64 = 3;
const INTEGRITY_DOMAIN_PREFIX: &str = "sync-record-journal";
const MAX_PROJECTION_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundCommit {
    commit: RevisionCommit,
    revisions: Vec<EntityRevision>,
    expected_heads: BTreeMap<String, Option<String>>,
    created_at: String,
}

impl OutboundCommit {
    pub fn commit(&self) -> &RevisionCommit {
        &self.commit
    }

    pub fn revisions(&self) -> &[EntityRevision] {
        &self.revisions
    }

    pub fn expected_heads(&self) -> &BTreeMap<String, Option<String>> {
        &self.expected_heads
    }

    pub fn created_at(&self) -> &str {
        &self.created_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundCommit {
    commit: RevisionCommit,
    readiness: CommitReadiness,
    received_at: String,
}

/// Complete, conflict-free encrypted history accepted as input to Local Projection.
///
/// The plan builder still authenticates every envelope. This type only proves that the journal
/// observed complete transaction closures and selected heads without consulting arrival order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionRecords {
    commits: Vec<RevisionCommit>,
    revisions: Vec<EntityRevision>,
    head_revision_ids: Vec<String>,
}

/// Exact desired state that must be replayed before a newer projection can begin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingProjection {
    plan_id: String,
    document: Vec<u8>,
    head_revisions: BTreeMap<String, String>,
    prepared_at: String,
}

impl PendingProjection {
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn document(&self) -> &[u8] {
        &self.document
    }

    pub fn head_revisions(&self) -> &BTreeMap<String, String> {
        &self.head_revisions
    }

    pub fn prepared_at(&self) -> &str {
        &self.prepared_at
    }
}

/// Last projection known to have crossed every machine-local persistence boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionCheckpoint {
    plan_id: String,
    head_revisions: BTreeMap<String, String>,
    applied_at: String,
}

impl ProjectionCheckpoint {
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn head_revisions(&self) -> &BTreeMap<String, String> {
        &self.head_revisions
    }

    pub fn applied_at(&self) -> &str {
        &self.applied_at
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionPreparation {
    Prepared,
    AlreadyPrepared,
    AlreadyApplied,
}

impl ProjectionRecords {
    pub fn commits(&self) -> &[RevisionCommit] {
        &self.commits
    }

    pub fn revisions(&self) -> &[EntityRevision] {
        &self.revisions
    }

    pub fn head_revision_ids(&self) -> &[String] {
        &self.head_revision_ids
    }
}

impl InboundCommit {
    pub fn commit(&self) -> &RevisionCommit {
        &self.commit
    }

    pub fn readiness(&self) -> &CommitReadiness {
        &self.readiness
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
    commits: Vec<RevisionCommit>,
    outbound: Vec<OutboundCommit>,
    inbound: Vec<InboundCommit>,
    pending_projection: Option<PendingProjection>,
    projection_checkpoint: Option<ProjectionCheckpoint>,
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

    /// Persist one complete local transaction and its pending publication atomically.
    pub fn queue_outbound(
        &self,
        commit: RevisionCommit,
        revisions: Vec<EntityRevision>,
        expected_heads: BTreeMap<String, Option<String>>,
        created_at: impl Into<String>,
    ) -> ReplicationResult<()> {
        let commit = canonical_commit(commit)?;
        let revisions = canonical_revisions(revisions)?;
        validate_complete_commit(&commit, &revisions, &expected_heads)?;
        let created_at = require_time("outbound creation time", created_at.into())?;
        self.with_mutation(|tx| {
            for revision in &revisions {
                store_revision(tx, revision)?;
            }
            store_commit(tx, &commit)?;
            let expected_heads_json = serde_json::to_vec(&expected_heads)?;
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO record_outbox (
                    commit_id, expected_heads_json, created_at
                 ) VALUES (?1, ?2, ?3)",
                params![commit.commit_id(), expected_heads_json, created_at],
            )?;
            if inserted == 0 {
                let existing = outbound_by_id(tx, commit.commit_id())?.ok_or_else(|| {
                    ReplicationError::Invalid("record outbox row disappeared".to_string())
                })?;
                let item = OutboundCommit {
                    commit: commit.clone(),
                    revisions: revisions.clone(),
                    expected_heads: expected_heads.clone(),
                    created_at: created_at.clone(),
                };
                if existing != item {
                    return Err(ReplicationError::Invalid(format!(
                        "outbound commit {} is already queued with different delivery state",
                        commit.commit_id()
                    )));
                }
            }
            Ok(())
        })
    }

    /// Persist an arbitrary incoming transport batch without depending on arrival order.
    ///
    /// Revisions may arrive before their commit manifest and commits may arrive before members.
    pub fn receive_inbound(
        &self,
        commits: Vec<RevisionCommit>,
        revisions: Vec<EntityRevision>,
        received_at: impl Into<String>,
    ) -> ReplicationResult<()> {
        let commits = canonical_commits(commits)?;
        let revisions = canonical_revisions(revisions)?;
        let received_at = require_time("inbound receipt time", received_at.into())?;
        self.with_mutation(|tx| {
            for revision in &revisions {
                store_revision(tx, revision)?;
            }
            for commit in &commits {
                store_commit(tx, commit)?;
                tx.execute(
                    "INSERT OR IGNORE INTO record_inbox (commit_id, received_at) VALUES (?1, ?2)",
                    params![commit.commit_id(), received_at],
                )?;
            }
            Ok(())
        })
    }

    /// A repeated adapter acknowledgement is harmless. Immutable history remains available.
    pub fn settle_outbound(&self, commit_id: &str) -> ReplicationResult<bool> {
        require_uuid("outbound commit id", commit_id)?;
        self.with_mutation(|tx| {
            Ok(tx.execute(
                "DELETE FROM record_outbox WHERE commit_id = ?1",
                params![commit_id],
            )? != 0)
        })
    }

    /// Atomically acknowledge a transport batch. A repeated acknowledgement of immutable
    /// history is harmless, but an id never observed by this journal is rejected.
    pub fn settle_outbound_batch(
        &self,
        commit_ids: &BTreeSet<String>,
    ) -> ReplicationResult<usize> {
        if commit_ids.is_empty() {
            return Ok(0);
        }
        for commit_id in commit_ids {
            require_uuid("outbound commit id", commit_id)?;
        }
        self.with_mutation(|tx| {
            for commit_id in commit_ids {
                if commit_by_id(tx, commit_id)?.is_none() {
                    return Err(ReplicationError::Invalid(format!(
                        "cannot settle unknown commit {commit_id}"
                    )));
                }
            }
            let mut settled = 0;
            for commit_id in commit_ids {
                settled += tx.execute(
                    "DELETE FROM record_outbox WHERE commit_id = ?1",
                    params![commit_id],
                )?;
            }
            Ok(settled)
        })
    }

    /// Settle only a complete transaction so projection cannot acknowledge partial state.
    pub fn settle_inbound(&self, commit_id: &str) -> ReplicationResult<bool> {
        require_uuid("inbound commit id", commit_id)?;
        self.with_mutation(|tx| {
            let item = inbound_by_id(tx, commit_id)?;
            if let Some(item) = &item {
                if !item.readiness().is_ready() {
                    return Err(ReplicationError::Invalid(format!(
                        "inbound commit {commit_id} is still missing revisions"
                    )));
                }
            }
            Ok(tx.execute(
                "DELETE FROM record_inbox WHERE commit_id = ?1",
                params![commit_id],
            )? != 0)
        })
    }

    pub fn outbound(&self) -> ReplicationResult<Vec<OutboundCommit>> {
        self.with_read(|_, snapshot| Ok(snapshot.outbound.clone()))
    }

    pub fn inbound(&self) -> ReplicationResult<Vec<InboundCommit>> {
        self.with_read(|_, snapshot| Ok(snapshot.inbound.clone()))
    }

    pub fn ready_inbound(&self) -> ReplicationResult<Vec<InboundCommit>> {
        self.with_read(|_, snapshot| {
            Ok(snapshot
                .inbound
                .iter()
                .filter(|item| item.readiness().is_ready())
                .cloned()
                .collect())
        })
    }

    pub fn analysis(&self) -> ReplicationResult<RevisionAnalysis> {
        self.with_read(|_, snapshot| analysis_from(&snapshot.revisions))
    }

    /// Select only revisions protected by complete transaction closures.
    ///
    /// Any concurrent entity heads block the whole projection. Applying the unaffected entities
    /// would violate a transaction that also changed the conflicted entity.
    pub fn projection_records(&self) -> ReplicationResult<ProjectionRecords> {
        self.with_read(|_, snapshot| projection_records_from(snapshot))
    }

    /// Durably fence one exact local projection before catalog or store writes begin.
    pub fn prepare_projection(
        &self,
        plan_id: &str,
        document: &[u8],
        head_revisions: &BTreeMap<String, String>,
        prepared_at: impl Into<String>,
    ) -> ReplicationResult<ProjectionPreparation> {
        require_projection_identity(plan_id, document)?;
        validate_projection_heads(head_revisions)?;
        let prepared_at = require_time("projection preparation time", prepared_at.into())?;
        self.with_mutation(|tx| {
            if let Some(checkpoint) = projection_checkpoint_from(tx)? {
                if checkpoint.plan_id == plan_id && checkpoint.head_revisions == *head_revisions {
                    return Ok(ProjectionPreparation::AlreadyApplied);
                }
                if checkpoint.head_revisions == *head_revisions {
                    return Err(ReplicationError::Invalid(
                        "projection heads already have a different completed plan".to_string(),
                    ));
                }
            }

            if let Some(pending) = pending_projection_from(tx)? {
                if pending.plan_id == plan_id
                    && pending.document == document
                    && pending.head_revisions == *head_revisions
                {
                    return Ok(ProjectionPreparation::AlreadyPrepared);
                }
                return Err(ReplicationError::Invalid(format!(
                    "projection {} must finish before preparing {plan_id}",
                    pending.plan_id
                )));
            }

            tx.execute(
                "INSERT INTO record_projection_intent (
                    singleton, plan_id, document, head_revisions_json, prepared_at
                 ) VALUES (1, ?1, ?2, ?3, ?4)",
                params![
                    plan_id,
                    document,
                    serde_json::to_vec(head_revisions)?,
                    prepared_at
                ],
            )?;
            Ok(ProjectionPreparation::Prepared)
        })
    }

    pub fn pending_projection(&self) -> ReplicationResult<Option<PendingProjection>> {
        self.with_read(|_, snapshot| Ok(snapshot.pending_projection.clone()))
    }

    pub fn projection_checkpoint(&self) -> ReplicationResult<Option<ProjectionCheckpoint>> {
        self.with_read(|_, snapshot| Ok(snapshot.projection_checkpoint.clone()))
    }

    /// Atomically replace the checkpoint and retire the matching durable intent.
    ///
    /// Returning `false` means this exact completion had already committed before a crash.
    pub fn complete_projection(
        &self,
        plan_id: &str,
        head_revisions: &BTreeMap<String, String>,
        applied_at: impl Into<String>,
    ) -> ReplicationResult<bool> {
        require_plan_id(plan_id)?;
        validate_projection_heads(head_revisions)?;
        let applied_at = require_time("projection completion time", applied_at.into())?;
        self.with_mutation(|tx| {
            let pending = pending_projection_from(tx)?;
            let Some(pending) = pending else {
                return match projection_checkpoint_from(tx)? {
                    Some(checkpoint)
                        if checkpoint.plan_id == plan_id
                            && checkpoint.head_revisions == *head_revisions =>
                    {
                        Ok(false)
                    }
                    _ => Err(ReplicationError::Invalid(format!(
                        "projection {plan_id} has no matching durable intent"
                    ))),
                };
            };
            if pending.plan_id != plan_id || pending.head_revisions != *head_revisions {
                return Err(ReplicationError::Invalid(format!(
                    "projection {plan_id} does not match pending projection {}",
                    pending.plan_id
                )));
            }

            tx.execute(
                "INSERT INTO record_projection_checkpoint (
                    singleton, plan_id, head_revisions_json, applied_at
                 ) VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(singleton) DO UPDATE SET
                    plan_id = excluded.plan_id,
                    head_revisions_json = excluded.head_revisions_json,
                    applied_at = excluded.applied_at",
                params![plan_id, serde_json::to_vec(head_revisions)?, applied_at],
            )?;
            tx.execute(
                "DELETE FROM record_projection_intent WHERE singleton = 1",
                [],
            )?;
            Ok(true)
        })
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

            CREATE TABLE record_commits (
                commit_id TEXT PRIMARY KEY,
                manifest_json BLOB NOT NULL
            );

            CREATE TABLE record_outbox (
                commit_id TEXT PRIMARY KEY
                    REFERENCES record_commits(commit_id) ON DELETE RESTRICT,
                expected_heads_json BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX record_outbox_created_idx
                ON record_outbox(created_at, commit_id);

            CREATE TABLE record_inbox (
                commit_id TEXT PRIMARY KEY
                    REFERENCES record_commits(commit_id) ON DELETE RESTRICT,
                received_at TEXT NOT NULL
            );
            CREATE INDEX record_inbox_received_idx
                ON record_inbox(received_at, commit_id);

            CREATE TABLE record_projection_intent (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                plan_id TEXT NOT NULL,
                document BLOB NOT NULL,
                head_revisions_json BLOB NOT NULL,
                prepared_at TEXT NOT NULL
            );

            CREATE TABLE record_projection_checkpoint (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                plan_id TEXT NOT NULL,
                head_revisions_json BLOB NOT NULL,
                applied_at TEXT NOT NULL
            );

            PRAGMA user_version = 3;",
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
    let commits = commits_from(conn)?;
    let outbound = outbound_from(conn)?;
    let inbound = inbound_from(conn)?;
    let pending_projection = pending_projection_from(conn)?;
    let projection_checkpoint = projection_checkpoint_from(conn)?;
    Ok(JournalSecuritySnapshot {
        schema_version,
        schema,
        revisions,
        commits,
        outbound,
        inbound,
        pending_projection,
        projection_checkpoint,
    })
}

fn validate_snapshot(snapshot: &JournalSecuritySnapshot) -> ReplicationResult<()> {
    let set = revision_set_from(&snapshot.revisions)?;
    set.analyze()
        .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
    for commit in &snapshot.commits {
        set.commit_readiness(commit, &snapshot.commits)
            .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
    }
    for item in &snapshot.outbound {
        if !snapshot
            .commits
            .iter()
            .any(|commit| commit == item.commit())
        {
            return Err(ReplicationError::Invalid(format!(
                "outbox commit {} is missing from immutable history",
                item.commit().commit_id()
            )));
        }
        validate_complete_commit(item.commit(), item.revisions(), item.expected_heads())?;
        if !set
            .commit_readiness(item.commit(), &snapshot.commits)
            .map_err(|error| ReplicationError::Invalid(error.to_string()))?
            .is_ready()
        {
            return Err(ReplicationError::Invalid(format!(
                "outbox commit {} is missing immutable ancestry",
                item.commit().commit_id()
            )));
        }
    }
    for item in &snapshot.inbound {
        if !snapshot
            .commits
            .iter()
            .any(|commit| commit == item.commit())
        {
            return Err(ReplicationError::Invalid(format!(
                "inbox commit {} is missing from immutable history",
                item.commit().commit_id()
            )));
        }
        let expected = set
            .commit_readiness(item.commit(), &snapshot.commits)
            .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
        if expected != *item.readiness() {
            return Err(ReplicationError::Invalid(format!(
                "inbox commit {} readiness does not match immutable history",
                item.commit().commit_id()
            )));
        }
    }
    if let Some(pending) = &snapshot.pending_projection {
        validate_pending_projection(pending)?;
    }
    if let Some(checkpoint) = &snapshot.projection_checkpoint {
        validate_projection_checkpoint(checkpoint)?;
    }
    Ok(())
}

fn analysis_from(revisions: &[EntityRevision]) -> ReplicationResult<RevisionAnalysis> {
    revision_set_from(revisions)?
        .analyze()
        .map_err(|error| ReplicationError::Invalid(error.to_string()))
}

fn projection_records_from(
    snapshot: &JournalSecuritySnapshot,
) -> ReplicationResult<ProjectionRecords> {
    let all_revisions = revision_set_from(&snapshot.revisions)?;
    let mut commits = Vec::new();
    let mut revision_ids = BTreeSet::new();
    for commit in &snapshot.commits {
        let readiness = all_revisions
            .commit_readiness(commit, &snapshot.commits)
            .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
        if readiness.is_ready() {
            commits.push(commit.clone());
            revision_ids.extend(commit.revision_ids().iter().cloned());
        }
    }

    let revisions = snapshot
        .revisions
        .iter()
        .filter(|revision| revision_ids.contains(revision.revision_id()))
        .cloned()
        .collect::<Vec<_>>();
    let committed = revision_set_from(&revisions)?;
    let analysis = committed
        .analyze()
        .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
    if !analysis.pending().is_empty() {
        return Err(ReplicationError::Invalid(
            "committed projection history contains missing ancestry".to_string(),
        ));
    }
    let conflicts = analysis
        .heads()
        .iter()
        .filter_map(|(entity_id, heads)| (heads.len() > 1).then_some(entity_id.clone()))
        .collect::<Vec<_>>();
    if !conflicts.is_empty() {
        return Err(ReplicationError::Invalid(format!(
            "local projection is blocked by conflicting entities: {}",
            conflicts.join(", ")
        )));
    }
    let head_revision_ids = analysis
        .heads()
        .values()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    Ok(ProjectionRecords {
        commits,
        revisions,
        head_revision_ids,
    })
}

fn revision_set_from(revisions: &[EntityRevision]) -> ReplicationResult<RevisionSet> {
    let mut set = RevisionSet::new();
    for revision in revisions {
        set.insert(revision.clone())
            .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
    }
    Ok(set)
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

fn canonical_revisions(revisions: Vec<EntityRevision>) -> ReplicationResult<Vec<EntityRevision>> {
    let mut by_id = BTreeMap::new();
    for revision in revisions {
        let revision = canonical_revision(revision)?;
        match by_id.get(revision.revision_id()) {
            Some(existing) if existing == &revision => {}
            Some(_) => {
                return Err(ReplicationError::Invalid(format!(
                    "revision id {} was reused for different content",
                    revision.revision_id()
                )))
            }
            None => {
                by_id.insert(revision.revision_id().to_string(), revision);
            }
        }
    }
    Ok(by_id.into_values().collect())
}

fn canonical_commit(mut commit: RevisionCommit) -> ReplicationResult<RevisionCommit> {
    commit.canonicalize();
    commit
        .validate()
        .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
    Ok(commit)
}

fn canonical_commits(commits: Vec<RevisionCommit>) -> ReplicationResult<Vec<RevisionCommit>> {
    let mut by_id = BTreeMap::new();
    for commit in commits {
        let commit = canonical_commit(commit)?;
        match by_id.get(commit.commit_id()) {
            Some(existing) if existing == &commit => {}
            Some(_) => {
                return Err(ReplicationError::Invalid(format!(
                    "commit id {} was reused for different content",
                    commit.commit_id()
                )))
            }
            None => {
                by_id.insert(commit.commit_id().to_string(), commit);
            }
        }
    }
    Ok(by_id.into_values().collect())
}

fn validate_complete_commit(
    commit: &RevisionCommit,
    revisions: &[EntityRevision],
    expected_heads: &BTreeMap<String, Option<String>>,
) -> ReplicationResult<()> {
    let member_ids = commit.revision_ids().iter().cloned().collect::<BTreeSet<_>>();
    let revision_ids = revisions
        .iter()
        .map(|revision| revision.revision_id().to_string())
        .collect::<BTreeSet<_>>();
    if member_ids != revision_ids {
        return Err(ReplicationError::Invalid(format!(
            "commit {} members do not match its supplied revisions",
            commit.commit_id()
        )));
    }

    let mut entities = BTreeSet::new();
    for revision in revisions {
        if revision.commit_id() != commit.commit_id() {
            return Err(ReplicationError::Invalid(format!(
                "revision {} declares commit {}, not {}",
                revision.revision_id(),
                revision.commit_id(),
                commit.commit_id()
            )));
        }
        if !entities.insert(revision.entity_id().to_string()) {
            return Err(ReplicationError::Invalid(format!(
                "commit {} contains more than one revision for entity {}",
                commit.commit_id(),
                revision.entity_id()
            )));
        }
        let expected = expected_heads.get(revision.entity_id()).ok_or_else(|| {
            ReplicationError::Invalid(format!(
                "commit {} has no expected head for entity {}",
                commit.commit_id(),
                revision.entity_id()
            ))
        })?;
        match expected {
            Some(expected) => {
                require_uuid("expected head revision id", expected)?;
                if !revision.parents().iter().any(|parent| parent == expected) {
                    return Err(ReplicationError::Invalid(format!(
                        "expected head {expected} is not a parent of revision {}",
                        revision.revision_id()
                    )));
                }
            }
            None if revision.parents().is_empty() => {}
            None => {
                return Err(ReplicationError::Invalid(format!(
                    "revision {} has parents but no expected head",
                    revision.revision_id()
                )))
            }
        }
    }
    if entities.len() != expected_heads.len() {
        return Err(ReplicationError::Invalid(format!(
            "commit {} expected heads name entities outside the transaction",
            commit.commit_id()
        )));
    }
    Ok(())
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

fn store_commit(tx: &Transaction<'_>, commit: &RevisionCommit) -> ReplicationResult<()> {
    let manifest = serde_json::to_vec(commit)?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO record_commits (commit_id, manifest_json) VALUES (?1, ?2)",
        params![commit.commit_id(), manifest],
    )?;
    if inserted == 0 {
        let existing = commit_by_id(tx, commit.commit_id())?.ok_or_else(|| {
            ReplicationError::Invalid("record commit row disappeared".to_string())
        })?;
        if existing != *commit {
            return Err(ReplicationError::Invalid(format!(
                "commit id {} was reused for different content",
                commit.commit_id()
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

fn commits_from(conn: &Connection) -> ReplicationResult<Vec<RevisionCommit>> {
    let mut statement = conn.prepare(
        "SELECT commit_id, manifest_json FROM record_commits ORDER BY commit_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut commits = Vec::new();
    for row in rows {
        let (commit_id, manifest) = row?;
        let commit = canonical_commit(serde_json::from_slice(&manifest)?)?;
        if commit.commit_id() != commit_id {
            return Err(ReplicationError::Invalid(format!(
                "record commit index does not match manifest {commit_id}"
            )));
        }
        commits.push(commit);
    }
    Ok(commits)
}

fn commit_by_id(
    conn: &Connection,
    commit_id: &str,
) -> ReplicationResult<Option<RevisionCommit>> {
    let manifest = conn
        .query_row(
            "SELECT manifest_json FROM record_commits WHERE commit_id = ?1",
            params![commit_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    manifest
        .map(|manifest| canonical_commit(serde_json::from_slice(&manifest)?))
        .transpose()
}

fn outbound_from(conn: &Connection) -> ReplicationResult<Vec<OutboundCommit>> {
    let mut statement = conn.prepare(
        "SELECT commit_id, expected_heads_json, created_at
         FROM record_outbox ORDER BY created_at, commit_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut items = Vec::new();
    for row in rows {
        let (commit_id, expected_heads_json, created_at) = row?;
        let commit = commit_by_id(conn, &commit_id)?.ok_or_else(|| {
            ReplicationError::Invalid(format!("outbox commit {commit_id} is missing"))
        })?;
        let revisions = revisions_for_commit(conn, &commit)?;
        let expected_heads = serde_json::from_slice(&expected_heads_json)?;
        items.push(OutboundCommit {
            commit,
            revisions,
            expected_heads,
            created_at,
        });
    }
    Ok(items)
}

fn outbound_by_id(
    conn: &Connection,
    commit_id: &str,
) -> ReplicationResult<Option<OutboundCommit>> {
    Ok(outbound_from(conn)?
        .into_iter()
        .find(|item| item.commit.commit_id() == commit_id))
}

fn inbound_from(conn: &Connection) -> ReplicationResult<Vec<InboundCommit>> {
    let revisions = revisions_from(conn)?;
    let set = revision_set_from(&revisions)?;
    let commits = commits_from(conn)?;
    let mut statement = conn.prepare(
        "SELECT commit_id, received_at
         FROM record_inbox ORDER BY received_at, commit_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut items = Vec::new();
    for row in rows {
        let (commit_id, received_at) = row?;
        let commit = commit_by_id(conn, &commit_id)?.ok_or_else(|| {
            ReplicationError::Invalid(format!("inbox commit {commit_id} is missing"))
        })?;
        let readiness = set
            .commit_readiness(&commit, &commits)
            .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
        items.push(InboundCommit {
            commit,
            readiness,
            received_at,
        });
    }
    Ok(items)
}

fn inbound_by_id(
    conn: &Connection,
    commit_id: &str,
) -> ReplicationResult<Option<InboundCommit>> {
    Ok(inbound_from(conn)?
        .into_iter()
        .find(|item| item.commit.commit_id() == commit_id))
}

fn pending_projection_from(
    conn: &Connection,
) -> ReplicationResult<Option<PendingProjection>> {
    let row = conn
        .query_row(
            "SELECT plan_id, document, head_revisions_json, prepared_at
             FROM record_projection_intent WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(plan_id, document, head_revisions_json, prepared_at)| {
        Ok(PendingProjection {
            plan_id,
            document,
            head_revisions: serde_json::from_slice(&head_revisions_json)?,
            prepared_at,
        })
    })
    .transpose()
}

fn projection_checkpoint_from(
    conn: &Connection,
) -> ReplicationResult<Option<ProjectionCheckpoint>> {
    let row = conn
        .query_row(
            "SELECT plan_id, head_revisions_json, applied_at
             FROM record_projection_checkpoint WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(plan_id, head_revisions_json, applied_at)| {
        Ok(ProjectionCheckpoint {
            plan_id,
            head_revisions: serde_json::from_slice(&head_revisions_json)?,
            applied_at,
        })
    })
    .transpose()
}

fn revisions_for_commit(
    conn: &Connection,
    commit: &RevisionCommit,
) -> ReplicationResult<Vec<EntityRevision>> {
    commit
        .revision_ids()
        .iter()
        .map(|revision_id| {
            revision_by_id(conn, revision_id)?.ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "commit {} revision {revision_id} is missing",
                    commit.commit_id()
                ))
            })
        })
        .collect()
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

fn require_plan_id(value: &str) -> ReplicationResult<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ReplicationError::Invalid(format!(
            "projection plan id is not a lowercase SHA-256 digest: {value:?}"
        )))
    }
}

fn require_projection_document(document: &[u8]) -> ReplicationResult<()> {
    if document.is_empty() || document.len() > MAX_PROJECTION_DOCUMENT_BYTES {
        Err(ReplicationError::Invalid(format!(
            "projection document must be 1..={MAX_PROJECTION_DOCUMENT_BYTES} bytes"
        )))
    } else {
        Ok(())
    }
}

fn require_projection_identity(plan_id: &str, document: &[u8]) -> ReplicationResult<()> {
    require_plan_id(plan_id)?;
    require_projection_document(document)?;
    let expected = format!("{:x}", Sha256::digest(document));
    if expected != plan_id {
        return Err(ReplicationError::Invalid(
            "projection plan id does not match its document".to_string(),
        ));
    }
    Ok(())
}

fn validate_projection_heads(
    head_revisions: &BTreeMap<String, String>,
) -> ReplicationResult<()> {
    for (entity_id, revision_id) in head_revisions {
        require_uuid("projection entity id", entity_id)?;
        require_uuid("projection head revision id", revision_id)?;
    }
    Ok(())
}

fn validate_pending_projection(pending: &PendingProjection) -> ReplicationResult<()> {
    require_projection_identity(&pending.plan_id, &pending.document)?;
    validate_projection_heads(&pending.head_revisions)?;
    require_time("projection preparation time", pending.prepared_at.clone())?;
    Ok(())
}

fn validate_projection_checkpoint(checkpoint: &ProjectionCheckpoint) -> ReplicationResult<()> {
    require_plan_id(&checkpoint.plan_id)?;
    validate_projection_heads(&checkpoint.head_revisions)?;
    require_time("projection completion time", checkpoint.applied_at.clone())?;
    Ok(())
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

    fn revision(
        entity_id: &str,
        revision_id: &str,
        commit_id: &str,
        parents: Vec<String>,
    ) -> EntityRevision {
        EntityRevision::new(
            entity_id,
            revision_id,
            commit_id,
            1,
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

    fn make_commit(commit_id: &str, revisions: &[EntityRevision]) -> RevisionCommit {
        RevisionCommit::new(
            commit_id,
            1,
            revisions
                .iter()
                .map(|revision| revision.revision_id().to_string())
                .collect(),
            b"encrypted-commit-fixture".to_vec(),
        )
        .unwrap()
    }

    fn expected_heads(
        revisions: &[EntityRevision],
    ) -> BTreeMap<String, Option<String>> {
        revisions
            .iter()
            .map(|revision| {
                (
                    revision.entity_id().to_string(),
                    revision.parents().first().cloned(),
                )
            })
            .collect()
    }

    #[test]
    fn outbound_commit_is_atomic_idempotent_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let first_entity = id();
        let second_entity = id();
        let commit_id = id();
        let first = revision(&first_entity, &id(), &commit_id, Vec::new());
        let second = revision(&second_entity, &id(), &commit_id, Vec::new());
        let revisions = vec![first, second];
        let commit = make_commit(&commit_id, &revisions);
        let expected_heads = expected_heads(&revisions);
        let authenticator = authenticator();
        let journal = open(&directory, &vault_id, Arc::clone(&authenticator));

        journal
            .queue_outbound(
                commit.clone(),
                revisions.clone(),
                expected_heads.clone(),
                "2026-08-07T00:00:00Z",
            )
            .unwrap();
        journal
            .queue_outbound(
                commit,
                revisions,
                expected_heads,
                "2026-08-07T00:00:00Z",
            )
            .unwrap();
        assert_eq!(journal.outbound().unwrap().len(), 1);
        assert_eq!(journal.outbound().unwrap()[0].revisions().len(), 2);
        drop(journal);

        let reopened = open(&directory, &vault_id, authenticator);
        assert_eq!(reopened.outbound().unwrap().len(), 1);
        assert!(reopened.settle_outbound(&commit_id).unwrap());
        assert!(!reopened.settle_outbound(&commit_id).unwrap());
        assert!(reopened.outbound().unwrap().is_empty());
        assert_eq!(reopened.analysis().unwrap().heads().len(), 2);
    }

    #[test]
    fn projection_intent_and_checkpoint_are_durable_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let authenticator = authenticator();
        let document = b"canonical projection fixture".to_vec();
        let plan_id = format!("{:x}", Sha256::digest(&document));
        let heads = BTreeMap::from([(id(), id())]);
        let journal = open(&directory, &vault_id, Arc::clone(&authenticator));

        assert_eq!(
            journal
                .prepare_projection(
                    &plan_id,
                    &document,
                    &heads,
                    "2026-08-07T00:00:00Z",
                )
                .unwrap(),
            ProjectionPreparation::Prepared
        );
        assert_eq!(
            journal
                .prepare_projection(
                    &plan_id,
                    &document,
                    &heads,
                    "2026-08-07T00:00:01Z",
                )
                .unwrap(),
            ProjectionPreparation::AlreadyPrepared
        );
        drop(journal);

        let reopened = open(&directory, &vault_id, Arc::clone(&authenticator));
        let pending = reopened.pending_projection().unwrap().unwrap();
        assert_eq!(pending.plan_id(), plan_id);
        assert_eq!(pending.document(), document);
        assert_eq!(pending.head_revisions(), &heads);
        assert!(reopened
            .complete_projection(&plan_id, &heads, "2026-08-07T00:00:02Z")
            .unwrap());
        assert!(reopened.pending_projection().unwrap().is_none());
        drop(reopened);

        let reopened = open(&directory, &vault_id, authenticator);
        let checkpoint = reopened.projection_checkpoint().unwrap().unwrap();
        assert_eq!(checkpoint.plan_id(), plan_id);
        assert_eq!(checkpoint.head_revisions(), &heads);
        assert_eq!(
            reopened
                .prepare_projection(
                    &plan_id,
                    &document,
                    &heads,
                    "2026-08-07T00:00:03Z",
                )
                .unwrap(),
            ProjectionPreparation::AlreadyApplied
        );
        assert!(!reopened
            .complete_projection(&plan_id, &heads, "2026-08-07T00:00:04Z")
            .unwrap());
    }

    #[test]
    fn projection_intent_rejects_mismatched_identity_and_parallel_plan() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let journal = open(&directory, &vault_id, authenticator());
        let document = b"first plan".to_vec();
        let plan_id = format!("{:x}", Sha256::digest(&document));
        let heads = BTreeMap::from([(id(), id())]);

        assert!(journal
            .prepare_projection(
                &"00".repeat(32),
                &document,
                &heads,
                "2026-08-07T00:00:00Z",
            )
            .unwrap_err()
            .to_string()
            .contains("does not match its document"));
        journal
            .prepare_projection(
                &plan_id,
                &document,
                &heads,
                "2026-08-07T00:00:00Z",
            )
            .unwrap();
        let other_document = b"other plan".to_vec();
        let other_plan_id = format!("{:x}", Sha256::digest(&other_document));
        assert!(journal
            .prepare_projection(
                &other_plan_id,
                &other_document,
                &BTreeMap::from([(id(), id())]),
                "2026-08-07T00:00:01Z",
            )
            .unwrap_err()
            .to_string()
            .contains("must finish before preparing"));
    }

    #[test]
    fn inbound_commit_waits_when_manifest_and_child_arrive_before_parent() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let entity_id = id();
        let root_id = id();
        let child_id = id();
        let root_commit_id = id();
        let commit_id = id();
        let child = revision(
            &entity_id,
            &child_id,
            &commit_id,
            vec![root_id.clone()],
        );
        let commit = make_commit(&commit_id, std::slice::from_ref(&child));
        let journal = open(&directory, &vault_id, authenticator());

        journal
            .receive_inbound(
                vec![commit],
                vec![child],
                "2026-08-07T00:00:01Z",
            )
            .unwrap();
        assert_eq!(journal.inbound().unwrap().len(), 1);
        assert!(journal.ready_inbound().unwrap().is_empty());
        assert!(journal
            .projection_records()
            .unwrap()
            .head_revision_ids()
            .is_empty());
        assert!(journal.settle_inbound(&commit_id).is_err());
        let root = revision(&entity_id, &root_id, &root_commit_id, Vec::new());
        let root_commit = make_commit(&root_commit_id, std::slice::from_ref(&root));
        journal
            .receive_inbound(
                vec![root_commit],
                vec![root],
                "2026-08-07T00:00:02Z",
            )
            .unwrap();
        assert_eq!(
            journal.analysis().unwrap().heads_for(&entity_id),
            std::slice::from_ref(&child_id)
        );
        let ready = journal.ready_inbound().unwrap();
        assert_eq!(ready.len(), 2);
        assert!(ready
            .iter()
            .any(|item| item.commit().commit_id() == commit_id));
        assert_eq!(
            journal.projection_records().unwrap().head_revision_ids(),
            std::slice::from_ref(&child_id)
        );
        assert!(journal.settle_inbound(&commit_id).unwrap());
    }

    #[test]
    fn concurrent_committed_heads_block_the_whole_projection() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let entity_id = id();
        let first_commit_id = id();
        let second_commit_id = id();
        let first = revision(&entity_id, &id(), &first_commit_id, Vec::new());
        let second = revision(&entity_id, &id(), &second_commit_id, Vec::new());
        let first_commit = make_commit(&first_commit_id, std::slice::from_ref(&first));
        let second_commit = make_commit(&second_commit_id, std::slice::from_ref(&second));
        let journal = open(&directory, &vault_id, authenticator());

        journal
            .receive_inbound(
                vec![first_commit, second_commit],
                vec![first, second],
                "2026-08-07T00:00:00Z",
            )
            .unwrap();

        assert!(journal
            .projection_records()
            .unwrap_err()
            .to_string()
            .contains("blocked by conflicting entities"));
    }

    #[test]
    fn outbound_expected_heads_must_equal_revision_parents() {
        let directory = tempfile::tempdir().unwrap();
        let vault_id = id();
        let entity_id = id();
        let revision_id = id();
        let unrelated = id();
        let commit_id = id();
        let revision = revision(&entity_id, &revision_id, &commit_id, Vec::new());
        let commit = make_commit(&commit_id, std::slice::from_ref(&revision));
        let journal = open(&directory, &vault_id, authenticator());

        let error = journal
            .queue_outbound(
                commit,
                vec![revision],
                BTreeMap::from([(entity_id, Some(unrelated.clone()))]),
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
        let commit_id = id();
        let revision = revision(&entity_id, &revision_id, &commit_id, Vec::new());
        let commit = make_commit(&commit_id, std::slice::from_ref(&revision));
        let path = directory.path().join("records.sqlite");
        let journal = open(&directory, &vault_id, authenticator());
        journal
            .queue_outbound(
                commit,
                vec![revision],
                BTreeMap::from([(entity_id, None)]),
                "2026-08-07T00:00:00Z",
            )
            .unwrap();

        let attacker = Connection::open(path).unwrap();
        attacker
            .execute(
                "UPDATE record_outbox SET created_at = 'changed' WHERE commit_id = ?1",
                params![commit_id],
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
