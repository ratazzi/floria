use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use floria_core::authz::Enforcement;
use floria_integrity::StateAuthenticator;
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::domain::{
    Binding, BindingScope, CatalogSnapshot, EntrySelection, Environment, FileBacking,
    FormatInputModel, ManagedFileConfigurationRemoval, OriginKind, OriginSource, Project,
    ProjectCheckout, ProjectCheckoutKind, ResolvedEnvironment, ResolvedExport, Resource,
    ReplicatedCatalog, ReplicatedProject, ReplicatedSurface, ReplicationOutboxEntry,
    ResourceBindingUsage, ResourceCodec, ResourceKind, ResourceOrigin, ResourceSource,
    ResourceUsage, Surface, SurfaceFormat, SurfaceInput, SurfaceKind, ValueShape,
};
use crate::error::{CatalogError, CatalogResult};

const SCHEMA_VERSION: i64 = 14;
const INTEGRITY_DOMAIN: &str = "catalog-security-state";

#[derive(Clone)]
struct CatalogIntegrity {
    authenticator: Arc<StateAuthenticator>,
    sidecar: PathBuf,
    mutation: Arc<Mutex<()>>,
}

/// The complete security-relevant logical state of the catalog.
///
/// SQLite files, WAL pages, and timestamps are storage details. Authorization depends on the
/// declared schema and the typed domain rows, so those are authenticated together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CatalogSecuritySnapshot {
    schema_version: i64,
    schema: Vec<SchemaObject>,
    catalog: CatalogSnapshot,
    outbox: Vec<ReplicationOutboxEntry>,
    /// Portable rows can exist before this Mac registers a primary checkout, so the runtime
    /// snapshot's path-dependent joins cannot be their integrity boundary.
    #[serde(default)]
    replicated_catalog: ReplicatedCatalog,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SchemaObject {
    kind: String,
    name: String,
    table_name: String,
    sql: String,
}

/// Compatibility reader for the short-lived development checkpoint that authenticated rows but
/// not schema. It is accepted only when the live schema exactly matches a freshly-created v14
/// schema, then immediately upgraded to `CatalogSecuritySnapshot`.
#[derive(Deserialize)]
#[serde(untagged)]
enum AuthenticatedCatalogState {
    Current(CatalogSecuritySnapshot),
    Legacy(CatalogSnapshot),
}

#[derive(Clone)]
pub struct Catalog {
    path: PathBuf,
    integrity: Option<CatalogIntegrity>,
}

impl Catalog {
    /// Open or create a private SQLite metadata catalog.
    pub fn open(path: impl Into<PathBuf>) -> CatalogResult<Self> {
        Self::open_with_integrity(path.into(), None)
    }

    /// Open the live catalog behind an authenticated snapshot and Keychain rollback checkpoint.
    ///
    /// The first authenticated open seals a legacy development catalog once. After that point a
    /// missing, modified, or rolled-back sidecar fails closed before catalog state is consumed.
    pub fn open_authenticated(
        path: impl Into<PathBuf>,
        authenticator: Arc<StateAuthenticator>,
    ) -> CatalogResult<Self> {
        Self::open_with_integrity(path.into(), Some(authenticator))
    }

    fn open_with_integrity(
        path: PathBuf,
        authenticator: Option<Arc<StateAuthenticator>>,
    ) -> CatalogResult<Self> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| CatalogError::io(parent, e))?;
            }
        }

        let created = !path.exists();
        if created {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| CatalogError::io(&path, e))?;
        } else {
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| CatalogError::io(&path, e))?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(CatalogError::Validation(format!(
                    "{} must be a regular file, not a symlink",
                    path.display()
                )));
            }
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(CatalogError::Validation(format!(
                    "{} must not be accessible by group or others (mode {mode:04o})",
                    path.display()
                )));
            }
        }

        // Resolve parent-directory symlinks once, then use SQLITE_OPEN_NOFOLLOW on every
        // connection so replacing the catalog leaf with a symlink cannot redirect trusted I/O.
        let path = std::fs::canonicalize(&path).map_err(|e| CatalogError::io(&path, e))?;

        let catalog = Catalog { path, integrity: None };
        let catalog = match authenticator {
            Some(authenticator) if created => {
                let mut conn = catalog.raw_connection()?;
                migrate(&mut conn)?;
                drop(conn);
                catalog.enable_integrity(authenticator)?
            }
            Some(authenticator) => catalog.enable_integrity(authenticator)?,
            None => {
                let mut conn = catalog.raw_connection()?;
                migrate(&mut conn)?;
                drop(conn);
                catalog
            }
        };
        Ok(catalog)
    }

    fn enable_integrity(mut self, authenticator: Arc<StateAuthenticator>) -> CatalogResult<Self> {
        let sidecar = self.path.with_extension("integrity.json");
        let loaded = authenticator
            .load::<AuthenticatedCatalogState>(&sidecar, INTEGRITY_DOMAIN)?;
        let current = security_snapshot_from(&self.raw_connection()?)?;
        match loaded.value {
            Some(AuthenticatedCatalogState::Current(authenticated)) => {
                if authenticated == current {
                    // Already current.
                } else if authenticated.replicated_catalog == ReplicatedCatalog::default()
                    && authenticated.schema_version == current.schema_version
                    && authenticated.schema == current.schema
                    && authenticated.catalog == current.catalog
                    && authenticated.outbox == current.outbox
                {
                    authenticator.persist(
                        &sidecar,
                        INTEGRITY_DOMAIN,
                        loaded.generation,
                        &current,
                    )?;
                } else {
                    return Err(CatalogError::Validation(
                        "catalog contents do not match the authenticated security-state snapshot"
                            .to_string(),
                    ));
                }
            }
            Some(AuthenticatedCatalogState::Legacy(authenticated)) => {
                require_canonical_schema(&current)?;
                if authenticated != current.catalog {
                    return Err(CatalogError::Validation(
                        "catalog contents do not match the authenticated legacy security-state snapshot"
                            .to_string(),
                    ));
                }
                authenticator.persist(
                    &sidecar,
                    INTEGRITY_DOMAIN,
                    loaded.generation,
                    &current,
                )?;
            }
            None
                if loaded.generation == 0
                    && (current.catalog == CatalogSnapshot::default()
                        && current.replicated_catalog == ReplicatedCatalog::default()
                        || option_env!("FLORIA_INSECURE_DEVELOPMENT_BUILD") == Some("1")) =>
            {
                require_canonical_schema(&current)?;
                tracing::warn!(
                    catalog = %self.path.display(),
                    "sealing existing catalog as authenticated security state"
                );
                authenticator.persist(&sidecar, INTEGRITY_DOMAIN, 0, &current)?;
            }
            None if loaded.generation == 0 => {
                return Err(CatalogError::Validation(
                    "refusing to trust a non-empty catalog without an authenticated checkpoint"
                        .to_string(),
                ))
            }
            None => {
                return Err(CatalogError::Validation(format!(
                    "authenticated catalog sidecar {} is missing at Keychain generation {}",
                    sidecar.display(),
                    loaded.generation
                )))
            }
        };
        self.integrity = Some(CatalogIntegrity {
            authenticator,
            sidecar,
            mutation: Arc::new(Mutex::new(())),
        });
        Ok(self)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schema_version(&self) -> i64 {
        SCHEMA_VERSION
    }

    pub fn current_schema_version() -> i64 {
        SCHEMA_VERSION
    }

    pub fn minimum_supported_schema_version() -> i64 {
        SCHEMA_VERSION
    }

    pub fn snapshot(&self) -> CatalogResult<CatalogSnapshot> {
        self.with_authenticated_read(|_, snapshot| Ok(snapshot.catalog.clone()))
    }

    /// Check SQLite integrity and validate the complete live catalog without modifying it.
    ///
    /// This is intentionally deeper than [`Catalog::snapshot`]: health checks use it to
    /// distinguish a readable catalog from one whose underlying SQLite pages are damaged.
    pub fn verify_integrity(&self) -> CatalogResult<CatalogSnapshot> {
        self.with_authenticated_read(|conn, snapshot| {
            run_physical_integrity_checks(conn)?;
            Ok(snapshot.catalog.clone())
        })
    }

    /// Create a transactionally consistent SQLite copy without pausing readers or writers.
    ///
    /// The destination must not exist. It is created private and is a standalone database:
    /// WAL sidecars from the live catalog are not part of the backup.
    pub fn backup_to(&self, destination: &Path) -> CatalogResult<()> {
        if let Some(parent) = destination.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|source| CatalogError::io(parent, source))?;
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destination)
            .map_err(|source| CatalogError::io(destination, source))?;

        self.with_authenticated_read(|source, _| {
            let mut target = Connection::open(destination)?;
            let backup = rusqlite::backup::Backup::new(source, &mut target)?;
            backup.run_to_completion(32, Duration::from_millis(10), None)?;
            drop(backup);
            target.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            Ok(())
        })?;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o600))
            .map_err(|source| CatalogError::io(destination, source))
    }

    /// Validate a standalone catalog backup without migrating or modifying it.
    pub fn inspect_backup(path: &Path) -> CatalogResult<CatalogSnapshot> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        inspect_connection(&conn)
    }

    /// Adopt one already-verified restored catalog as the new authenticated live state.
    ///
    /// This is deliberately separate from normal open/migration. Restore activation must be an
    /// explicit maintenance transaction; ordinary startup can never reinterpret an older valid
    /// database as a legitimate rollback.
    pub fn authenticate_restored_state(
        path: &Path,
        authenticator: Arc<StateAuthenticator>,
    ) -> CatalogResult<()> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| CatalogError::io(path, error))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(CatalogError::Validation(format!(
                "restored catalog must be a private regular file: {}",
                path.display()
            )));
        }
        let path = std::fs::canonicalize(path).map_err(|error| CatalogError::io(path, error))?;
        let conn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let snapshot = security_snapshot_from(&conn)?;
        require_canonical_schema(&snapshot)?;
        run_physical_integrity_checks(&conn)?;
        let sidecar = path.with_extension("integrity.json");
        let generation = authenticator.checkpoint_generation(INTEGRITY_DOMAIN)?;
        authenticator.persist(
            &sidecar,
            INTEGRITY_DOMAIN,
            generation,
            &snapshot,
        )?;
        Ok(())
    }

    /// Verify and consume catalog state from one SQLite read snapshot.
    ///
    /// Callers never receive a bare connection, which prevents a verified state from being used
    /// after another writer has replaced the rows it referred to.
    fn with_authenticated_read<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>, &CatalogSecuritySnapshot) -> CatalogResult<T>,
    ) -> CatalogResult<T> {
        let _mutation = self.integrity.as_ref().map(|integrity| {
            integrity.mutation.lock().expect("catalog integrity lock poisoned")
        });
        let mut conn = self.raw_connection()?;
        let tx = conn.transaction()?;
        let current = security_snapshot_from(&tx)?;
        self.verify_security_snapshot(&current)?;
        let result = operation(&tx, &current)?;
        tx.commit()?;
        Ok(result)
    }

    /// Verify, mutate, validate, and checkpoint catalog state as one serialized transaction.
    ///
    /// The authenticated sidecar is advanced while SQLite's immediate writer lock is still held.
    /// If the final SQLite commit fails, the catalog fails closed against the newer checkpoint.
    fn with_authenticated_mutation<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> CatalogResult<T>,
    ) -> CatalogResult<T> {
        let _mutation = self.integrity.as_ref().map(|integrity| {
            integrity.mutation.lock().expect("catalog integrity lock poisoned")
        });
        let mut conn = self.raw_connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = security_snapshot_from(&tx)?;
        let generation = self.verify_security_snapshot(&current)?;
        let result = operation(&tx)?;
        let next = security_snapshot_from(&tx)?;
        validate_snapshot_conflicts(&next.catalog)?;
        if let Some(integrity) = &self.integrity {
            integrity.authenticator.persist(
                &integrity.sidecar,
                INTEGRITY_DOMAIN,
                generation,
                &next,
            )?;
        }
        tx.commit()?;
        Ok(result)
    }

    fn verify_security_snapshot(&self, current: &CatalogSecuritySnapshot) -> CatalogResult<u64> {
        let Some(integrity) = &self.integrity else { return Ok(0) };
        let loaded = integrity
            .authenticator
            .load::<CatalogSecuritySnapshot>(&integrity.sidecar, INTEGRITY_DOMAIN)?;
        let authenticated = loaded.value.ok_or_else(|| {
            CatalogError::Validation("authenticated catalog snapshot is missing".to_string())
        })?;
        if authenticated != *current {
            return Err(CatalogError::Validation(
                "catalog schema or contents changed outside the authenticated daemon transaction boundary"
                    .to_string(),
            ));
        }
        Ok(loaded.generation)
    }

    fn raw_connection(&self) -> CatalogResult<Connection> {
        let conn = Connection::open_with_flags(
            &self.path,
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
}

fn inspect_connection(conn: &Connection) -> CatalogResult<CatalogSnapshot> {
    let security = security_snapshot_from(conn)?;
    require_canonical_schema(&security)?;
    run_physical_integrity_checks(conn)?;
    Ok(security.catalog)
}

fn run_physical_integrity_checks(conn: &Connection) -> CatalogResult<()> {
    let quick_check: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(CatalogError::Validation(format!(
            "catalog integrity check failed: {quick_check}"
        )));
    }
    let foreign_key_violation: Option<(String, i64, String)> = conn
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()?;
    if let Some((table, rowid, parent)) = foreign_key_violation {
        return Err(CatalogError::Validation(format!(
            "catalog foreign-key check failed for {table} row {rowid} referencing {parent}"
        )));
    }
    Ok(())
}

fn security_snapshot_from(conn: &Connection) -> CatalogResult<CatalogSecuritySnapshot> {
    let schema_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version != SCHEMA_VERSION {
        return Err(CatalogError::UnsupportedSchema {
            found: schema_version,
            expected: SCHEMA_VERSION,
        });
    }
    let schema = schema_objects_from(conn)?;
    if let Some(object) = schema
        .iter()
        .find(|object| matches!(object.kind.as_str(), "trigger" | "view"))
    {
        return Err(CatalogError::Validation(format!(
            "catalog contains unsupported {} {:?}",
            object.kind, object.name
        )));
    }
    let catalog = snapshot_from(conn)?;
    let outbox = outbox_from(conn)?;
    let replicated_catalog = replicated_catalog_from(conn, &catalog)?;
    validate_snapshot_conflicts(&catalog)?;
    replication::validate_replicated_catalog(&replicated_catalog)?;
    Ok(CatalogSecuritySnapshot {
        schema_version,
        schema,
        catalog,
        outbox,
        replicated_catalog,
    })
}

fn schema_objects_from(conn: &Connection) -> CatalogResult<Vec<SchemaObject>> {
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
        .collect::<Result<Vec<_>, _>>()?;
    Ok(objects)
}

fn require_canonical_schema(snapshot: &CatalogSecuritySnapshot) -> CatalogResult<()> {
    let mut expected = Connection::open_in_memory()?;
    migrate(&mut expected)?;
    let expected = schema_objects_from(&expected)?;
    if snapshot.schema_version != SCHEMA_VERSION
        || !schema_objects_equivalent(&snapshot.schema, &expected)
    {
        return Err(CatalogError::Validation(
            "catalog schema does not exactly match the supported schema".to_string(),
        ));
    }
    Ok(())
}

fn schema_objects_equivalent(actual: &[SchemaObject], expected: &[SchemaObject]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.kind == expected.kind
                && actual.name == expected.name
                && actual.table_name == expected.table_name
                && normalize_schema_sql(&actual.sql) == normalize_schema_sql(&expected.sql)
        })
}

/// SQLite preserves the formatting of the DDL used to create an object. Formatting is not part
/// of the schema's security semantics, so compare token spacing rather than raw source text.
fn normalize_schema_sql(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    let mut quote = None;
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote {
            normalized.push(character);
            if character == terminator {
                if characters.peek() == Some(&terminator) {
                    normalized.push(characters.next().expect("peeked character exists"));
                } else {
                    quote = None;
                }
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                quote = Some(character);
                normalized.push(character);
            }
            '[' => {
                quote = Some(']');
                normalized.push(character);
            }
            character if character.is_whitespace() => {
                while characters.peek().is_some_and(|next| next.is_whitespace()) {
                    characters.next();
                }
                if normalized.chars().last().is_some_and(schema_word_character)
                    && characters.peek().copied().is_some_and(schema_word_character)
                {
                    normalized.push(' ');
                }
            }
            _ => normalized.push(character),
        }
    }
    normalized
}

fn schema_word_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '$')
}

mod projects;
mod resources;
mod schema;
mod snapshot;
mod surfaces;
mod outbox;
mod replication;
mod validation;

use outbox::outbox_from;
pub use replication::validate_replicated_catalog;
use replication::replicated_catalog_from;
use schema::migrate;
use snapshot::{snapshot_from, validate_snapshot_conflicts};
pub use snapshot::{
    catalog_surface_semantic_revision, resolve_catalog_snapshot, resolve_catalog_surface,
};
use validation::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EntrySpec, SshRouteSpec};

    fn project() -> Project {
        Project {
            id: "floria".to_string(),
            name: "floria".to_string(),
            path: PathBuf::from("/workspace/floria"),
            ..Default::default()
        }
    }

    fn environment() -> Environment {
        Environment {
            id: "development".to_string(),
            project_id: "floria".to_string(),
            name: "Development".to_string(),
            position: 0,
        }
    }

    fn scalar_resource(id: &str, key: &str) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::SharedSecret,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: Some(key.to_string()),
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: key.to_string(),
                key: Some(key.to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: format!("secret-{id}") },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        }
    }

    fn env_file_resource(id: &str) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Dotenv,
            default_env_key: None,
            entries: vec![
                EntrySpec {
                    address: "keys/API_HOST".to_string(),
                    label: "API_HOST".to_string(),
                    key: Some("API_HOST".to_string()),
                    sensitive: true,
                },
                EntrySpec {
                    address: "keys/LOG_LEVEL".to_string(),
                    label: "LOG_LEVEL".to_string(),
                    key: Some("LOG_LEVEL".to_string()),
                    sensitive: true,
                },
            ],
            source: ResourceSource::SecretRef { secret_id: format!("secret-{id}") },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        }
    }

    fn socket_resource(id: &str) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::SshAgent,
            shape: ValueShape::Socket,
            codec: ResourceCodec::Opaque,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "ssh/sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                label: "Fleet key".to_string(),
                key: None,
                sensitive: false,
            }],
            source: ResourceSource::Socket,
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        }
    }

    fn binding(id: &str, resource_id: &str, scope: BindingScope) -> Binding {
        Binding {
            id: id.to_string(),
            project_id: "floria".to_string(),
            scope,
            resource_id: resource_id.to_string(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 0,
        }
    }

    fn catalog() -> (tempfile::TempDir, Catalog) {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog.upsert_project(&project()).unwrap();
        catalog.upsert_environment(&environment()).unwrap();
        (dir, catalog)
    }

    fn replication_outbox_entry() -> ReplicationOutboxEntry {
        ReplicationOutboxEntry {
            intent_id: "11111111-1111-4111-8111-111111111111".to_string(),
            logical_id: "managed-item-1".to_string(),
            parents: vec!["revision-one".to_string()],
            store_versions: vec![crate::domain::ReplicationStoreVersionRef {
                secret_id: "22222222-2222-4222-8222-222222222222".to_string(),
                version: 2,
            }],
            catalog_payload: br#"{"kind":"fixture"}"#.to_vec(),
            created_at: "2026-08-06T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn rejects_old_schema_during_development() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();

        let error = migrate(&mut conn).unwrap_err();
        assert!(matches!(
            error,
            CatalogError::UnsupportedSchema {
                found: 1,
                expected: SCHEMA_VERSION
            }
        ));
    }

    #[test]
    fn fresh_catalog_persists_current_schema_version_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");

        let catalog = Catalog::open(&path).unwrap();
        assert_eq!(catalog.schema_version(), SCHEMA_VERSION);
        drop(catalog);

        let reopened = Catalog::open(&path).unwrap();
        let persisted: i64 = reopened
            .raw_connection()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(persisted, SCHEMA_VERSION);
    }

    #[test]
    fn canonical_schema_comparison_ignores_sql_formatting() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        let mut snapshot = security_snapshot_from(&conn).unwrap();
        let original = snapshot.schema.clone();
        for object in &mut snapshot.schema {
            object.sql = object.sql.split_whitespace().collect::<Vec<_>>().join(" ");
        }
        assert_ne!(snapshot.schema, original);
        require_canonical_schema(&snapshot).unwrap();
        assert_ne!(
            normalize_schema_sql("value TEXT DEFAULT 'a b'"),
            normalize_schema_sql("value TEXT DEFAULT 'ab'")
        );
        assert_ne!(
            normalize_schema_sql("CREATE TABLE item (value TEXT)"),
            normalize_schema_sql("CREATE TABLE item (valueTEXT)")
        );
    }

    #[test]
    fn live_integrity_check_returns_the_validated_snapshot() {
        let (_dir, catalog) = catalog();

        let snapshot = catalog.verify_integrity().unwrap();

        assert_eq!(snapshot.projects, vec![project()]);
        assert_eq!(snapshot.environments, vec![environment()]);
    }

    #[test]
    fn replication_outbox_is_immutable_idempotent_and_removable() {
        let (_dir, catalog) = catalog();
        let entry = replication_outbox_entry();

        catalog.enqueue_replication_outbox(&entry).unwrap();
        catalog.enqueue_replication_outbox(&entry).unwrap();
        assert_eq!(catalog.replication_outbox().unwrap(), vec![entry.clone()]);

        let mut collision = entry.clone();
        collision.catalog_payload = br#"{"kind":"different"}"#.to_vec();
        assert!(catalog
            .enqueue_replication_outbox(&collision)
            .unwrap_err()
            .to_string()
            .contains("different committed state"));

        catalog.remove_replication_outbox(&entry.intent_id).unwrap();
        assert!(catalog.replication_outbox().unwrap().is_empty());
    }

    #[test]
    fn authenticated_catalog_detects_outbox_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");
        let catalog = Catalog::open_authenticated(
            &path,
            Arc::new(StateAuthenticator::for_tests([47; 32])),
        )
        .unwrap();
        let entry = replication_outbox_entry();
        catalog.enqueue_replication_outbox(&entry).unwrap();

        let attacker = Connection::open(&path).unwrap();
        attacker
            .execute(
                "UPDATE replication_outbox SET catalog_payload = X'00' WHERE intent_id = ?1",
                params![entry.intent_id],
            )
            .unwrap();

        assert!(catalog
            .replication_outbox()
            .unwrap_err()
            .to_string()
            .contains("outside"));
    }

    #[test]
    fn authenticated_catalog_rejects_external_database_tampering_and_sidecar_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");
        let auth = Arc::new(StateAuthenticator::for_tests([41; 32]));
        let catalog = Catalog::open_authenticated(&path, Arc::clone(&auth)).unwrap();
        let baseline_sidecar = std::fs::read(path.with_extension("integrity.json")).unwrap();
        catalog.upsert_project(&project()).unwrap();

        let attacker = Connection::open(&path).unwrap();
        attacker
            .execute("UPDATE projects SET name = 'attacker' WHERE id = 'floria'", [])
            .unwrap();
        assert!(catalog.snapshot().unwrap_err().to_string().contains("outside"));
        drop(attacker);

        let trusted = Connection::open(&path).unwrap();
        trusted.execute("UPDATE projects SET name = 'floria' WHERE id = 'floria'", []).unwrap();
        drop(trusted);
        std::fs::write(path.with_extension("integrity.json"), baseline_sidecar).unwrap();
        assert!(catalog.snapshot().unwrap_err().to_string().contains("rolled back"));
    }

    #[test]
    fn authenticated_catalog_rejects_schema_tampering_before_a_legitimate_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");
        let catalog = Catalog::open_authenticated(
            &path,
            Arc::new(StateAuthenticator::for_tests([43; 32])),
        )
        .unwrap();
        catalog.upsert_project(&project()).unwrap();

        let attacker = Connection::open(&path).unwrap();
        attacker
            .execute_batch(
                "CREATE TRIGGER inject_environment AFTER UPDATE ON projects BEGIN
                     INSERT OR IGNORE INTO environments (id, project_id, name, position)
                     VALUES ('attacker', NEW.id, 'Attacker', 0);
                 END;",
            )
            .unwrap();
        drop(attacker);

        let mut changed = project();
        changed.name = "Changed".to_string();
        let error = catalog.upsert_project(&changed).unwrap_err();
        assert!(error.to_string().contains("unsupported trigger"));

        let inspect = Connection::open(&path).unwrap();
        let project_name: String = inspect
            .query_row("SELECT name FROM projects WHERE id = 'floria'", [], |row| row.get(0))
            .unwrap();
        let injected: i64 = inspect
            .query_row(
                "SELECT COUNT(*) FROM environments WHERE id = 'attacker'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(project_name, "floria");
        assert_eq!(injected, 0);
    }

    #[test]
    fn authenticated_catalog_detects_constraint_index_removal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");
        let catalog = Catalog::open_authenticated(
            &path,
            Arc::new(StateAuthenticator::for_tests([46; 32])),
        )
        .unwrap();

        let attacker = Connection::open(&path).unwrap();
        attacker.execute_batch("DROP INDEX bindings_resource_idx;").unwrap();
        drop(attacker);

        let error = catalog.snapshot().unwrap_err();
        assert!(error.to_string().contains("schema or contents changed"));
    }

    #[test]
    fn authenticated_open_never_migrates_an_unverified_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");
        let attacker = Connection::open(&path).unwrap();
        attacker.execute_batch("CREATE TABLE attacker_controlled (value TEXT);").unwrap();
        drop(attacker);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let error = match Catalog::open_authenticated(
            &path,
            Arc::new(StateAuthenticator::for_tests([44; 32])),
        ) {
            Ok(_) => panic!("unverified database was migrated"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CatalogError::UnsupportedSchema { found: 0, expected: SCHEMA_VERSION }
        ));

        let inspect = Connection::open(&path).unwrap();
        let version: i64 = inspect.query_row("PRAGMA user_version", [], |row| row.get(0)).unwrap();
        let projects: i64 = inspect
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'projects'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 0);
        assert_eq!(projects, 0);
    }

    #[test]
    fn authenticated_open_upgrades_a_valid_legacy_row_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");
        let catalog = Catalog::open(&path).unwrap();
        catalog.upsert_project(&project()).unwrap();
        let snapshot = catalog.snapshot().unwrap();
        drop(catalog);

        let auth = Arc::new(StateAuthenticator::for_tests([45; 32]));
        auth.persist(
            &path.with_extension("integrity.json"),
            INTEGRITY_DOMAIN,
            0,
            &snapshot,
        )
        .unwrap();

        let authenticated = Catalog::open_authenticated(&path, auth).unwrap();
        assert_eq!(authenticated.snapshot().unwrap(), snapshot);
    }

    #[test]
    fn authenticated_catalog_does_not_silently_adopt_existing_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");
        let catalog = Catalog::open(&path).unwrap();
        catalog.upsert_project(&project()).unwrap();
        drop(catalog);

        let error = match Catalog::open_authenticated(
            &path,
            Arc::new(StateAuthenticator::for_tests([42; 32])),
        ) {
            Ok(_) => panic!("existing unauthenticated catalog was adopted"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("refusing to trust"));
    }

    #[test]
    fn append_resource_origin_deduplicates_by_path() {
        let (_dir, catalog) = catalog();
        catalog.upsert_resource(&scalar_resource("fixture-secret", "API_TOKEN")).unwrap();
        let source = OriginSource {
            path: PathBuf::from("/workspace/floria/.env"),
            project_id: Some("floria".to_string()),
            environment: Some("development".to_string()),
            imported_at: "2026-07-24T00:00:00Z".to_string(),
        };

        catalog.append_resource_origin("fixture-secret", &source).unwrap();
        catalog.append_resource_origin("fixture-secret", &source).unwrap();
        let other = OriginSource {
            path: PathBuf::from("/workspace/floria/.env.production"),
            ..source.clone()
        };
        catalog.append_resource_origin("fixture-secret", &other).unwrap();

        let snapshot = catalog.snapshot().unwrap();
        let resource =
            snapshot.resources.iter().find(|resource| resource.id == "fixture-secret").unwrap();
        assert_eq!(resource.origin.sources.len(), 2);
        assert_eq!(resource.origin.sources[0].path, Path::new("/workspace/floria/.env"));
        assert!(catalog
            .append_resource_origin("missing", &source)
            .is_err());
    }

    #[test]
    fn entry_selection_must_reference_exposed_entries() {
        let (_dir, catalog) = catalog();
        catalog.upsert_resource(&env_file_resource("fixture-env-file")).unwrap();
        let mut selected = binding(
            "env-file-binding",
            "fixture-env-file",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/API_HOST".to_string()],
        };
        catalog.upsert_binding(&selected).unwrap();

        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/MISSING".to_string()],
        };
        let error = catalog.upsert_binding(&selected).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("not exposed")));
    }

    #[test]
    fn entry_selection_projects_only_the_selected_named_values() {
        let (_dir, catalog) = catalog();
        catalog.upsert_resource(&env_file_resource("fixture-sections")).unwrap();
        let mut selected = binding(
            "section-binding",
            "fixture-sections",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/LOG_LEVEL".to_string()],
        };
        catalog.upsert_binding(&selected).unwrap();

        let resolved = catalog.resolve_environment("floria", "development").unwrap();
        assert_eq!(resolved.exports.len(), 1);
        assert_eq!(resolved.exports[0].key, "LOG_LEVEL");
        assert_eq!(resolved.exports[0].address, "keys/LOG_LEVEL");
    }

    #[test]
    fn ini_keys_are_generic_until_selected_for_a_dotenv_projection() {
        let (_dir, catalog) = catalog();
        let resource = Resource {
            id: "fixture-ini".to_string(),
            name: "Fixture INI".to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Ini,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "sections/fixture/keys/credential-process".to_string(),
                label: "[fixture] credential-process".to_string(),
                key: Some("credential-process".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: "fixture-ini-secret".to_string() },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        };
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding(
                "fixture-ini-binding",
                &resource.id,
                BindingScope::Environment { environment_id: "development".to_string() },
            ))
            .unwrap();

        let error = catalog
            .upsert_surface(&Surface {
                id: "fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: Some(PathBuf::from("/workspace/floria/.env")),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["fixture-ini-binding".to_string()],
                },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();

        assert!(matches!(error, CatalogError::Validation(message) if message.contains("cannot feed dotenv")));

        let mut ini_surface = Surface {
            id: "fixture-ini-output".to_string(),
            environment_id: "development".to_string(),
            name: "credentials.ini".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
            path: Some(PathBuf::from("/workspace/floria/credentials.ini")),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["fixture-ini-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&ini_surface).unwrap();

        let mut duplicate = resource.clone();
        duplicate.id = "fixture-ini-duplicate".to_string();
        duplicate.source = ResourceSource::SecretRef {
            secret_id: "fixture-ini-secret-two".to_string(),
        };
        catalog.upsert_resource(&duplicate).unwrap();
        catalog
            .upsert_binding(&binding(
                "fixture-ini-binding-two",
                &duplicate.id,
                BindingScope::Environment { environment_id: "development".to_string() },
            ))
            .unwrap();
        ini_surface.input = SurfaceInput::Bindings {
            binding_ids: vec![
                "fixture-ini-binding".to_string(),
                "fixture-ini-binding-two".to_string(),
            ],
        };
        assert!(matches!(
            catalog.upsert_surface(&ini_surface),
            Err(CatalogError::Conflict { key, .. })
                if key == "sections/fixture/keys/credential-process"
        ));
    }

    #[test]
    fn snapshot_round_trips_typed_metadata_without_secret_values() {
        let (_dir, catalog) = catalog();
        let mut resource = scalar_resource("cloudflare", "CLOUDFLARE_API_TOKEN");
        resource.enforcement = Enforcement::TouchId;
        resource.metadata.note = Some("Deployment token for the documentation zone".to_string());
        resource.metadata.links.push(crate::domain::ItemLink {
            label: "Cloudflare dashboard".to_string(),
            url: "https://dash.cloudflare.com/example/tokens".to_string(),
        });
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("common-cloudflare", "cloudflare", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: Some(PathBuf::from("/workspace/floria/.env")),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["common-cloudflare".to_string()],
                },
                enforcement: Enforcement::Allow,
                position: 0,
            })
            .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects, vec![project()]);
        assert_eq!(
            snapshot.checkouts,
            vec![ProjectCheckout {
                id: "floria".to_string(),
                project_id: "floria".to_string(),
                path: PathBuf::from("/workspace/floria"),
                environment_id: None,
                kind: ProjectCheckoutKind::Primary,
                git_common_dir: None,
            }]
        );
        assert_eq!(snapshot.environments, vec![environment()]);
        assert_eq!(snapshot.resources, vec![resource]);
        assert_eq!(snapshot.bindings.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(snapshot.surfaces[0].enforcement, Enforcement::Allow);
        assert_eq!(snapshot.resources[0].enforcement, Enforcement::TouchId);
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("plaintext"));
    }

    #[test]
    fn worktree_checkout_requires_an_environment_from_the_same_project() {
        let (_dir, catalog) = catalog();
        let checkout = ProjectCheckout {
            id: "floria-feature".to_string(),
            project_id: "floria".to_string(),
            path: PathBuf::from("/workspace/floria-feature"),
            environment_id: Some("development".to_string()),
            kind: ProjectCheckoutKind::Worktree,
            git_common_dir: Some(PathBuf::from("/workspace/floria/.git")),
        };
        catalog.upsert_checkout(&checkout).unwrap();
        assert_eq!(catalog.snapshot().unwrap().checkouts[1], checkout);

        let mut without_environment = checkout.clone();
        without_environment.id = "floria-unassigned".to_string();
        without_environment.path = PathBuf::from("/workspace/floria-unassigned");
        without_environment.environment_id = None;
        assert!(matches!(
            catalog.upsert_checkout(&without_environment),
            Err(CatalogError::Validation(message))
                if message.contains("must select an environment")
        ));

        assert!(matches!(
            catalog.remove_checkout("floria"),
            Err(CatalogError::Validation(message))
                if message.contains("cannot be removed separately")
        ));
        catalog.remove_checkout(&checkout.id).unwrap();
        assert_eq!(catalog.snapshot().unwrap().checkouts.len(), 1);
    }

    #[test]
    fn surface_paths_are_persisted_relative_to_the_primary_checkout() {
        let (_dir, catalog) = catalog();
        let surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".config/dev.env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: Some(PathBuf::from("/workspace/floria/.config/dev.env")),
            input: SurfaceInput::Bindings { binding_ids: Vec::new() },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();

        let relative: String = catalog
            .raw_connection()
            .unwrap()
            .query_row(
                "SELECT relative_path FROM surfaces WHERE id = ?1",
                [&surface.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(relative, ".config/dev.env");
        assert_eq!(catalog.snapshot().unwrap().surfaces, vec![surface]);
    }

    #[test]
    fn create_resource_refuses_to_replace_existing_metadata() {
        let (_dir, catalog) = catalog();
        let resource = scalar_resource("fixture-shared", "FIXTURE_TOKEN");
        catalog.create_resource(&resource).unwrap();
        let mut replacement = resource.clone();
        replacement.name = "Replacement".to_string();

        assert!(matches!(
            catalog.create_resource(&replacement),
            Err(CatalogError::AlreadyExists { kind: "resource", .. })
        ));
        assert_eq!(catalog.resource(&resource.id).unwrap().name, resource.name);
    }

    #[test]
    fn resource_usage_expands_common_binding_to_affected_surfaces() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_environment(&Environment {
                id: "staging".to_string(),
                project_id: "floria".to_string(),
                name: "Staging".to_string(),
                position: 1,
            })
            .unwrap();
        let resource = scalar_resource("fixture-shared", "FIXTURE_TOKEN");
        catalog.create_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("fixture-common", &resource.id, BindingScope::Common))
            .unwrap();
        for (id, environment_id, path) in [
            ("fixture-dev-env", "development", "/workspace/floria/.env"),
            ("fixture-stage-env", "staging", "/workspace/floria/.env.staging"),
        ] {
            catalog
                .upsert_surface(&Surface {
                    id: id.to_string(),
                    environment_id: environment_id.to_string(),
                    name: ".env".to_string(),
                    kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                    path: Some(PathBuf::from(path)),
                    input: SurfaceInput::Bindings {
                        binding_ids: vec!["fixture-common".to_string()],
                    },
                    enforcement: Enforcement::Prompt,
                    position: 0,
                })
                .unwrap();
        }

        let usage = catalog.resource_usage(&resource.id).unwrap();
        assert_eq!(usage.bindings.len(), 1);
        assert_eq!(usage.bindings[0].environment_ids, vec!["development", "staging"]);
        assert_eq!(
            usage.bindings[0].surface_ids,
            vec!["fixture-dev-env", "fixture-stage-env"]
        );
        assert!(usage.direct_surface_ids.is_empty());
        assert!(matches!(
            catalog.remove_resource(&resource.id),
            Err(CatalogError::ResourceInUse { binding_ids, .. })
                if binding_ids == vec!["fixture-common"]
        ));
    }

    #[test]
    fn surface_path_must_stay_inside_its_project() {
        let (_dir, catalog) = catalog();
        let missing = catalog
            .upsert_surface(&Surface {
                id: "fixture-missing-path".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: None,
                input: SurfaceInput::Bindings { binding_ids: vec![] },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();
        assert!(matches!(missing, CatalogError::Validation(message) if message.contains("file surface requires a project path")));

        let error = catalog
            .upsert_surface(&Surface {
                id: "fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: Some(PathBuf::from("/workspace/other/.env")),
                input: SurfaceInput::Bindings { binding_ids: vec![] },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();
        assert!(matches!(error, CatalogError::Validation(_)));
    }

    #[test]
    fn surface_id_must_be_one_safe_path_component() {
        let (_dir, catalog) = catalog();
        let error = catalog
            .upsert_surface(&Surface {
                id: "../fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: Some(PathBuf::from("/workspace/floria/.env")),
                input: SurfaceInput::Bindings { binding_ids: vec![] },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();
        assert!(matches!(error, CatalogError::Validation(_)));
    }

    #[test]
    fn direct_env_file_surface_requires_and_protects_its_env_file_resource() {
        let (_dir, catalog) = catalog();
        let resource = env_file_resource("fixture-env-file");
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-direct-env".to_string(),
                environment_id: "development".to_string(),
                name: ".env.local".to_string(),
                kind: SurfaceKind::File(FileBacking::EnvFileDirect),
                path: Some(PathBuf::from("/workspace/floria/.env.local")),
                input: SurfaceInput::Resource { resource_id: resource.id.clone() },
                enforcement: Enforcement::Prompt,
                position: 1,
            })
            .unwrap();

        let usage = catalog.resource_usage(&resource.id).unwrap();
        assert_eq!(usage.direct_surface_ids, vec!["fixture-direct-env"]);

        let mut incompatible = resource.clone();
        incompatible.kind = ResourceKind::Command;
        incompatible.source = ResourceSource::Command { argv: vec!["fixture-command".to_string()] };
        assert!(matches!(
            catalog.upsert_resource(&incompatible),
            Err(CatalogError::Validation(_))
        ));
        assert_eq!(catalog.resource(&resource.id).unwrap(), resource);
    }

    #[test]
    fn direct_env_file_surface_rejects_missing_or_scalar_resource() {
        let (_dir, catalog) = catalog();
        let missing = Surface {
            id: "fixture-direct-env".to_string(),
            environment_id: "development".to_string(),
            name: ".env.local".to_string(),
            kind: SurfaceKind::File(FileBacking::EnvFileDirect),
            path: Some(PathBuf::from("/workspace/floria/.env.local")),
            input: SurfaceInput::Bindings { binding_ids: vec![] },
            enforcement: Enforcement::Prompt,
            position: 1,
        };
        assert!(matches!(
            catalog.upsert_surface(&missing),
            Err(CatalogError::Validation(_))
        ));

        let scalar = scalar_resource("fixture-scalar", "FIXTURE_TOKEN");
        catalog.upsert_resource(&scalar).unwrap();
        assert!(matches!(
            catalog.upsert_surface(&Surface {
                input: SurfaceInput::Resource { resource_id: scalar.id },
                ..missing
            }),
            Err(CatalogError::Validation(_))
        ));
    }

    #[test]
    fn conflicting_surface_membership_is_rejected_and_transaction_rolls_back() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("first", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("second", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("first-binding", "first", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_binding(&binding("second-binding", "second", BindingScope::Common))
            .unwrap();
        let mut surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: Some(PathBuf::from("/workspace/floria/.env")),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["first-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();

        surface.input = SurfaceInput::Bindings {
            binding_ids: vec!["first-binding".to_string(), "second-binding".to_string()],
        };
        let error = catalog.upsert_surface(&surface).unwrap_err();
        assert!(matches!(error, CatalogError::Conflict { ref key, .. } if key == "TOKEN"));
        assert_eq!(
            catalog.snapshot().unwrap().surfaces[0].input,
            SurfaceInput::Bindings {
                binding_ids: vec!["first-binding".to_string()]
            }
        );
    }

    #[test]
    fn the_same_key_can_belong_to_separate_surfaces() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("first", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("second", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("first-binding", "first", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_binding(&binding("second-binding", "second", BindingScope::Common))
            .unwrap();

        for (id, name, binding_id, kind) in [
            (
                "first-surface",
                ".env.first",
                "first-binding",
                SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            ),
            (
                "second-surface",
                ".envrc",
                "second-binding",
                SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv)),
            ),
        ] {
            catalog
                .upsert_surface(&Surface {
                    id: id.to_string(),
                    environment_id: "development".to_string(),
                    name: name.to_string(),
                    kind,
                    path: Some(PathBuf::from("/workspace/floria").join(name)),
                    input: SurfaceInput::Bindings {
                        binding_ids: vec![binding_id.to_string()],
                    },
                    enforcement: Enforcement::Prompt,
                    position: 0,
                })
                .unwrap();
        }

        assert_eq!(catalog.snapshot().unwrap().surfaces.len(), 2);
    }

    #[test]
    fn surface_rejects_unknown_members_and_binding_removal_detaches_membership() {
        let (_dir, catalog) = catalog();
        let resource = scalar_resource("fixture", "FIXTURE_TOKEN");
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("fixture-binding", &resource.id, BindingScope::Common))
            .unwrap();
        let mut surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: Some(PathBuf::from("/workspace/floria/.env")),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["missing-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        assert!(matches!(
            catalog.upsert_surface(&surface),
            Err(CatalogError::NotFound(message)) if message.contains("missing-binding")
        ));

        surface.input = SurfaceInput::Bindings {
            binding_ids: vec!["fixture-binding".to_string()],
        };
        catalog.upsert_surface(&surface).unwrap();
        catalog.remove_binding("fixture-binding").unwrap();

        assert_eq!(
            catalog.snapshot().unwrap().surfaces[0].input,
            SurfaceInput::Bindings { binding_ids: Vec::new() }
        );
    }

    #[test]
    fn managed_file_configuration_cleanup_removes_only_unshared_generated_rows() {
        let (_dir, catalog) = catalog();
        let path = PathBuf::from("/workspace/floria/.env");
        let mut resource = env_file_resource("managed-env");
        resource.origin = ResourceOrigin {
            kind: OriginKind::Discovered,
            sources: vec![OriginSource {
                path: path.clone(),
                project_id: Some("floria".to_string()),
                environment: Some("Development".to_string()),
                imported_at: "2026-07-28T00:00:00Z".to_string(),
            }],
        };
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding(
                "managed-binding",
                &resource.id,
                BindingScope::Environment { environment_id: "development".to_string() },
            ))
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "managed-surface".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: Some(path),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["managed-binding".to_string()],
                },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap();

        let removed = catalog
            .remove_managed_file_configuration(
                "managed-surface",
                "managed-binding",
                "managed-env",
            )
            .unwrap();

        assert!(removed.binding_removed);
        assert!(removed.resource_removed);
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.surfaces.is_empty());
        assert!(snapshot.bindings.is_empty());
        assert!(snapshot.resources.is_empty());
    }

    #[test]
    fn managed_file_configuration_cleanup_preserves_reused_content() {
        let (_dir, catalog) = catalog();
        let path = PathBuf::from("/workspace/floria/.env");
        let mut resource = env_file_resource("managed-env");
        resource.origin = ResourceOrigin {
            kind: OriginKind::Discovered,
            sources: vec![OriginSource {
                path: path.clone(),
                project_id: Some("floria".to_string()),
                environment: Some("Development".to_string()),
                imported_at: "2026-07-28T00:00:00Z".to_string(),
            }],
        };
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding(
                "managed-binding",
                &resource.id,
                BindingScope::Environment { environment_id: "development".to_string() },
            ))
            .unwrap();
        for (id, name) in [("managed-surface", ".env"), ("reused-surface", ".envrc")] {
            catalog
                .upsert_surface(&Surface {
                    id: id.to_string(),
                    environment_id: "development".to_string(),
                    name: name.to_string(),
                    kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                    path: Some(PathBuf::from("/workspace/floria").join(name)),
                    input: SurfaceInput::Bindings {
                        binding_ids: vec!["managed-binding".to_string()],
                    },
                    enforcement: Enforcement::Prompt,
                    position: 0,
                })
                .unwrap();
        }

        let removed = catalog
            .remove_managed_file_configuration(
                "managed-surface",
                "managed-binding",
                "managed-env",
            )
            .unwrap();

        assert!(!removed.binding_removed);
        assert!(!removed.resource_removed);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(snapshot.bindings.len(), 1);
        assert_eq!(snapshot.resources.len(), 1);
    }

    #[test]
    fn environment_binding_can_explicitly_override_common_key() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("common", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("development-token", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("common-binding", "common", BindingScope::Common))
            .unwrap();
        let mut environment_binding = binding(
            "development-binding",
            "development-token",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        environment_binding.allow_override = true;
        catalog.upsert_binding(&environment_binding).unwrap();

        let resolved = catalog.resolve_environment("floria", "development").unwrap();
        assert_eq!(resolved.exports.len(), 1);
        assert_eq!(resolved.exports[0].binding_id, "development-binding");
        assert_eq!(
            resolved.exports[0].overrides_binding_id.as_deref(),
            Some("common-binding")
        );
    }

    #[test]
    fn key_override_is_only_allowed_for_scalar_resources() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&Resource {
                id: "defaults".to_string(),
                name: "Defaults".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Dotenv,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "keys/LOG_LEVEL".to_string(),
                    label: "LOG_LEVEL".to_string(),
                    key: Some("LOG_LEVEL".to_string()),
                    sensitive: false,
                }],
                source: ResourceSource::SecretRef { secret_id: "secret-defaults".to_string() },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            })
            .unwrap();
        let mut binding = binding(
            "defaults-binding",
            "defaults",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        binding.key_override = Some("OTHER".to_string());
        let error = catalog.upsert_binding(&binding).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("scalar")));
    }

    #[test]
    fn socket_endpoint_is_machine_local_and_tracks_resource_atomically() {
        let (_dir, catalog) = catalog();
        let socket = socket_resource("fixture-agent-provider");

        assert!(matches!(
            catalog.upsert_resource(&socket),
            Err(CatalogError::Validation(message))
                if message.contains("machine-local endpoint")
        ));
        catalog
            .upsert_socket_resource(&socket, Path::new("/fixture/upstream-agent.sock"))
            .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources, vec![socket.clone()]);
        assert_eq!(
            snapshot.endpoints.get(&socket.id).map(PathBuf::as_path),
            Some(Path::new("/fixture/upstream-agent.sock"))
        );
        let source_json: String = catalog
            .raw_connection()
            .unwrap()
            .query_row(
                "SELECT source_json FROM resources WHERE id = ?1",
                [&socket.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source_json, r#"{"type":"socket"}"#);

        let scalar = scalar_resource(&socket.id, "FIXTURE_TOKEN");
        catalog.upsert_resource(&scalar).unwrap();
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources, vec![scalar]);
        assert!(!snapshot.endpoints.contains_key(&socket.id));
    }

    #[test]
    fn concurrent_snapshots_never_observe_a_socket_without_its_endpoint() {
        let (_dir, catalog) = catalog();
        let resource_id = "fixture-switching-provider";
        catalog
            .upsert_resource(&scalar_resource(resource_id, "FIXTURE_TOKEN"))
            .unwrap();

        let writer = catalog.clone();
        let writer_thread = std::thread::spawn(move || {
            for _ in 0..30 {
                writer
                    .upsert_socket_resource(
                        &socket_resource(resource_id),
                        Path::new("/fixture/upstream-agent.sock"),
                    )
                    .unwrap();
                writer
                    .upsert_resource(&scalar_resource(resource_id, "FIXTURE_TOKEN"))
                    .unwrap();
            }
        });
        for _ in 0..100 {
            let snapshot = catalog.snapshot().unwrap();
            let resource = snapshot
                .resources
                .iter()
                .find(|resource| resource.id == resource_id)
                .unwrap();
            assert_eq!(
                resource.source == ResourceSource::Socket,
                snapshot.endpoints.contains_key(resource_id)
            );
        }
        writer_thread.join().unwrap();
    }

    #[test]
    fn ssh_agent_surface_composes_managed_and_external_identity_bindings() {
        let (_dir, catalog) = catalog();
        let address =
            "ssh/sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let mut external = socket_resource("fixture-agent-provider");
        external.name = "Fixture Agent".to_string();
        external.entries[0].address = address.clone();
        catalog
            .upsert_socket_resource(&external, Path::new("/fixture/upstream-agent.sock"))
            .unwrap();
        let mut selected = binding(
            "fixture-agent-binding",
            "fixture-agent-provider",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec![address.clone()],
        };
        catalog.upsert_binding(&selected).unwrap();
        let managed_address =
            "ssh/sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string();
        catalog
            .upsert_resource(&Resource {
                id: "fixture-managed-identity".to_string(),
                name: "Fixture Managed Identity".to_string(),
                kind: ResourceKind::SshIdentity,
                shape: ValueShape::SshIdentity,
                codec: ResourceCodec::Opaque,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: managed_address,
                    label: "Managed fleet key".to_string(),
                    key: None,
                    sensitive: false,
                }],
                source: ResourceSource::SecretRef {
                    secret_id: "fixture-managed-private-key".to_string(),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            })
            .unwrap();
        let managed = binding(
            "fixture-managed-binding",
            "fixture-managed-identity",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        catalog.upsert_binding(&managed).unwrap();

        let surface = Surface {
            id: "fixture-agent-surface".to_string(),
            environment_id: "development".to_string(),
            name: "AWS fleet".to_string(),
            kind: SurfaceKind::UnixSocket,
            path: None,
            input: SurfaceInput::SshAgent {
                binding_ids: vec![selected.id.clone(), managed.id],
                route: Some(SshRouteSpec {
                    host_patterns: vec!["ec2-*.example.internal".to_string()],
                    hostname: None,
                    user: Some("ubuntu".to_string()),
                    port: None,
                    forward_agent: true,
                }),
            },
            enforcement: Enforcement::TouchId,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();
        assert_eq!(
            catalog
                .snapshot()
                .unwrap()
                .surfaces
                .iter()
                .find(|candidate| candidate.id == surface.id)
                .unwrap()
                .path,
            None
        );

        let project_socket = Surface {
            path: Some(PathBuf::from("/fixture/project/agent.sock")),
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&project_socket).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("capability surface cannot have a project path")));

        let conflicting_route = Surface {
            id: "fixture-agent-surface-two".to_string(),
            name: "Duplicate route".to_string(),
            path: None,
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&conflicting_route).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("ec2-*.example.internal")));

        let invalid_route = Surface {
            input: SurfaceInput::SshAgent {
                binding_ids: vec!["fixture-agent-binding".to_string()],
                route: Some(SshRouteSpec {
                    host_patterns: vec!["fixture\nHost injected".to_string()],
                    hostname: None,
                    user: None,
                    port: None,
                    forward_agent: false,
                }),
            },
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&invalid_route).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("host pattern")));

        let direct = Surface {
            input: SurfaceInput::Resource {
                resource_id: "fixture-agent-provider".to_string(),
            },
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&direct).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("incompatible")));

        let duplicate = Binding {
            id: "fixture-agent-binding-duplicate".to_string(),
            ..selected
        };
        catalog.upsert_binding(&duplicate).unwrap();
        let duplicated_surface = Surface {
            input: SurfaceInput::Bindings {
                binding_ids: vec![
                    "fixture-agent-binding".to_string(),
                    "fixture-agent-binding-duplicate".to_string(),
                ],
            },
            ..surface
        };
        let error = catalog.upsert_surface(&duplicated_surface).unwrap_err();
        assert!(matches!(error, CatalogError::Conflict { key, .. } if key == address));
    }

    #[test]
    fn catalog_file_is_private() {
        let (dir, _catalog) = catalog();
        let mode = std::fs::metadata(dir.path().join("catalog.sqlite"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
