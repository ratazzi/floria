use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use floria_core::authz::{Enforcement, Operation};
use floria_integrity::StateAuthenticator;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 3;
const INTEGRITY_DOMAIN: &str = "authorization-grants";
const MAXIMUM_TTL: Duration = Duration::from_secs(26 * 60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantLifetime {
    Timed { ttl: Duration, scope: GrantScope },
    UntilLock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    Timed,
    Today,
    UntilLock,
}

impl GrantScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timed => "timed",
            Self::Today => "today",
            Self::UntilLock => "until_lock",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GrantKey {
    pub subject: String,
    pub object: String,
    pub operation: Operation,
    pub enforcement: Enforcement,
}

impl GrantKey {
    pub(crate) fn new(
        subject: String,
        object: String,
        operation: Operation,
        enforcement: Enforcement,
    ) -> Self {
        Self { subject, object, operation, enforcement }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantMetadata {
    pub client: String,
    pub executable: Option<String>,
    pub bundle_id: Option<String>,
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveGrant {
    pub id: String,
    pub subject: String,
    pub object: String,
    pub operation: Operation,
    pub enforcement: Enforcement,
    pub scope: GrantScope,
    pub expires_at: Option<i64>,
    pub metadata: GrantMetadata,
}

struct GrantRecord {
    lifetime: GrantRecordLifetime,
    metadata: GrantMetadata,
}

enum GrantRecordLifetime {
    Timed { monotonic: Instant, unix: i64, scope: GrantScope },
    UntilLock,
}

pub(crate) struct GrantCache {
    path: PathBuf,
    authenticator: Arc<StateAuthenticator>,
    persistence: Mutex<GrantPersistence>,
    entries: Mutex<HashMap<GrantKey, GrantRecord>>,
}

#[derive(Default)]
struct GrantPersistence {
    generation: Option<u64>,
    degraded_reason: Option<String>,
}

impl GrantCache {
    pub(crate) fn open(
        path: impl Into<PathBuf>,
        authenticator: Arc<StateAuthenticator>,
    ) -> Self {
        let path = path.into();
        let loaded = authenticator.load::<GrantDocument>(&path, INTEGRITY_DOMAIN);
        let (entries, generation, rejected) = match loaded {
            Ok(loaded) => {
                match loaded.value {
                    Some(document) => match load_document(document) {
                        Ok(entries) => (entries, Some(loaded.generation), None),
                        Err(error) => (
                            HashMap::new(),
                            Some(loaded.generation),
                            Some(format!("authenticated grant document is invalid: {error}")),
                        ),
                    },
                    None if loaded.generation == 0 => {
                        (HashMap::new(), Some(0), None)
                    }
                    None => (
                        HashMap::new(),
                        Some(loaded.generation),
                        Some(format!(
                            "grant state file is missing at authenticated generation {}",
                            loaded.generation
                        )),
                    ),
                }
            }
            Err(error) => {
                let (generation, reason) = match authenticator.checkpoint_generation(INTEGRITY_DOMAIN)
                {
                    Ok(generation) => (Some(generation), error.to_string()),
                    Err(checkpoint_error) => (
                        None,
                        format!(
                            "{error}; Keychain checkpoint is unavailable: {checkpoint_error}"
                        ),
                    ),
                };
                (HashMap::new(), generation, Some(reason))
            }
        };
        let cache = GrantCache {
            path,
            authenticator,
            persistence: Mutex::new(GrantPersistence {
                generation,
                degraded_reason: rejected.clone(),
            }),
            entries: Mutex::new(entries),
        };
        if let Some(reason) = rejected {
            cache.reject_persisted_state(&reason);
        }
        cache
    }

    fn persist_authenticated(&self, entries: &HashMap<GrantKey, GrantRecord>) -> io::Result<()> {
        let document = persisted_document(entries);
        let mut persistence = self
            .persistence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut generation = match persistence.generation {
            Some(generation) => generation,
            None => self
                .authenticator
                .checkpoint_generation(INTEGRITY_DOMAIN)
                .map_err(integrity_io)?,
        };

        let mut first_error = None;
        for _ in 0..2 {
            match self.authenticator.persist(
                &self.path,
                INTEGRITY_DOMAIN,
                generation,
                &document,
            ) {
                Ok(next) => {
                    persistence.generation = Some(next);
                    persistence.degraded_reason = None;
                    return Ok(());
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error.to_string());
                    }
                    match self.authenticator.checkpoint_generation(INTEGRITY_DOMAIN) {
                        Ok(current) => generation = current,
                        Err(_) => break,
                    }
                }
            }
        }

        persistence.generation = Some(generation);
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            first_error.unwrap_or_else(|| "grant persistence failed".to_string()),
        ))
    }

    fn persist_best_effort(
        &self,
        entries: &HashMap<GrantKey, GrantRecord>,
        operation: &str,
    ) {
        if let Err(error) = self.persist_authenticated(entries) {
            self.persistence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .degraded_reason = Some(error.to_string());
            tracing::warn!(
                path = %self.path.display(),
                %error,
                operation,
                "authorization grants are memory-only until authenticated persistence recovers"
            );
        }
    }

    fn reject_persisted_state(&self, reason: &str) {
        tracing::error!(
            path = %self.path.display(),
            reason,
            "authorization grant state was rejected; clearing grants"
        );
        match quarantine_rejected_state(&self.path) {
            Ok(Some(quarantine)) => tracing::warn!(
                path = %self.path.display(),
                quarantine = %quarantine.display(),
                "rejected authorization grant state was quarantined"
            ),
            Ok(None) => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "quarantining rejected authorization grant state failed"
            ),
        }
        let entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.persist_best_effort(&entries, "reset rejected grant state");
    }

    pub(crate) fn is_valid(&self, key: &GrantKey) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(key) {
            Some(GrantRecord { lifetime: GrantRecordLifetime::UntilLock, .. }) => true,
            Some(GrantRecord {
                lifetime: GrantRecordLifetime::Timed { monotonic, .. },
                ..
            }) if *monotonic > Instant::now() => true,
            Some(_) => {
                entries.remove(key);
                self.persist_best_effort(&entries, "remove expired grant");
                false
            }
            None => false,
        }
    }

    pub(crate) fn insert(
        &self,
        key: GrantKey,
        lifetime: GrantLifetime,
        metadata: GrantMetadata,
    ) -> io::Result<()> {
        let lifetime = match lifetime {
            GrantLifetime::UntilLock => GrantRecordLifetime::UntilLock,
            GrantLifetime::Timed { ttl, scope } => {
                if ttl > MAXIMUM_TTL {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "grant TTL exceeds the 26-hour daemon limit",
                    ));
                }
                let expires_at = now_unix()
                    .checked_add(
                        ttl.as_secs().try_into().map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidInput, "grant TTL is too large")
                        })?,
                    )
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "grant expiry overflow")
                    })?;
                let monotonic = Instant::now().checked_add(ttl).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "grant TTL is too large")
                })?;
                GrantRecordLifetime::Timed { monotonic, unix: expires_at, scope }
            }
        };
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.insert(key, GrantRecord { lifetime, metadata });
        self.persist_best_effort(&entries, "insert grant");
        Ok(())
    }

    pub(crate) fn active(&self) -> io::Result<Vec<ActiveGrant>> {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let before = entries.len();
        entries.retain(|_, grant| match &grant.lifetime {
            GrantRecordLifetime::Timed { monotonic, .. } => *monotonic > now,
            GrantRecordLifetime::UntilLock => true,
        });
        if entries.len() != before {
            self.persist_best_effort(&entries, "remove expired grants");
        }
        let mut active = entries
            .iter()
            .map(|(key, record)| active_grant(key, record))
            .collect::<Vec<_>>();
        active.sort_by(|left, right| {
            (left.expires_at, &left.metadata.client, &left.metadata.target)
                .cmp(&(right.expires_at, &right.metadata.client, &right.metadata.target))
        });
        Ok(active)
    }

    pub(crate) fn clear_until_lock(&self) -> io::Result<bool> {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = entries.len();
        entries.retain(|_, grant| {
            !matches!(grant.lifetime, GrantRecordLifetime::UntilLock)
        });
        let removed = entries.len() != before;
        if removed {
            self.persist_best_effort(&entries, "clear lock-bound grants");
        }
        Ok(removed)
    }

    pub(crate) fn revoke(&self, id: &str) -> io::Result<bool> {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = entries.len();
        entries.retain(|key, _| grant_id(key) != id);
        let removed = entries.len() != before;
        if removed {
            self.persist_best_effort(&entries, "revoke grant");
        }
        Ok(removed)
    }

    pub(crate) fn clear(&self) -> io::Result<()> {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.clear();
        self.persist_best_effort(&entries, "clear grants");
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    }

    #[cfg(test)]
    pub(crate) fn is_memory_only(&self) -> bool {
        self.persistence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .degraded_reason
            .is_some()
    }

    #[cfg(test)]
    pub(crate) fn insert_expired(&self, key: GrantKey) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                key,
                GrantRecord {
                    lifetime: GrantRecordLifetime::Timed {
                        monotonic: Instant::now() - Duration::from_secs(1),
                        unix: 1,
                        scope: GrantScope::Timed,
                    },
                    metadata: GrantMetadata {
                        client: "expired-client".to_string(),
                        executable: None,
                        bundle_id: None,
                        target: "expired-target".to_string(),
                    },
                },
            );
    }
}

#[derive(Serialize, Deserialize)]
struct GrantDocument {
    version: u32,
    grants: Vec<PersistedGrant>,
}

#[derive(Serialize, Deserialize)]
struct PersistedGrant {
    subject: String,
    object: String,
    operation: String,
    enforcement: Enforcement,
    scope: GrantScope,
    expires_at: i64,
    client: String,
    executable: Option<String>,
    bundle_id: Option<String>,
    target: String,
}

fn load_document(document: GrantDocument) -> io::Result<HashMap<GrantKey, GrantRecord>> {
    if document.version != SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported grant store schema {}", document.version),
        ));
    }

    let now_unix = now_unix();
    let now_monotonic = Instant::now();
    let mut entries = HashMap::new();
    for persisted in document.grants {
        if persisted.expires_at <= now_unix {
            continue;
        }
        let remaining = u64::try_from(persisted.expires_at - now_unix)
            .map(Duration::from_secs)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid grant expiry"))?;
        if remaining > MAXIMUM_TTL {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persisted grant expiry exceeds the 24-hour daemon limit",
            ));
        }
        let monotonic = now_monotonic
            .checked_add(remaining)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "grant expiry is too large"))?;
        let operation = parse_operation(&persisted.operation)?;
        entries.insert(
            GrantKey::new(
                persisted.subject,
                persisted.object,
                operation,
                persisted.enforcement,
            ),
            GrantRecord {
                lifetime: GrantRecordLifetime::Timed {
                    monotonic,
                    unix: persisted.expires_at,
                    scope: persisted.scope,
                },
                metadata: GrantMetadata {
                    client: persisted.client,
                    executable: persisted.executable,
                    bundle_id: persisted.bundle_id,
                    target: persisted.target,
                },
            },
        );
    }
    Ok(entries)
}

fn persisted_document(entries: &HashMap<GrantKey, GrantRecord>) -> GrantDocument {
    let mut grants = entries
        .iter()
        .filter_map(|(key, record)| {
            let GrantRecordLifetime::Timed { unix, scope, .. } = record.lifetime else {
                return None;
            };
            Some(PersistedGrant {
                subject: key.subject.clone(),
                object: key.object.clone(),
                operation: key.operation.as_str().to_string(),
                enforcement: key.enforcement,
                scope,
                expires_at: unix,
                client: record.metadata.client.clone(),
                executable: record.metadata.executable.clone(),
                bundle_id: record.metadata.bundle_id.clone(),
                target: record.metadata.target.clone(),
            })
        })
        .collect::<Vec<_>>();
    grants.sort_by(|left, right| {
        (
            &left.subject,
            &left.object,
            &left.operation,
            left.enforcement.as_str(),
        )
            .cmp(&(
                &right.subject,
                &right.object,
                &right.operation,
                right.enforcement.as_str(),
            ))
    });
    GrantDocument { version: SCHEMA_VERSION, grants }
}

fn integrity_io(error: floria_integrity::IntegrityError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn active_grant(key: &GrantKey, record: &GrantRecord) -> ActiveGrant {
    let (scope, expires_at) = match record.lifetime {
        GrantRecordLifetime::Timed { unix, scope, .. } => (scope, Some(unix)),
        GrantRecordLifetime::UntilLock => (GrantScope::UntilLock, None),
    };
    ActiveGrant {
        id: grant_id(key),
        subject: key.subject.clone(),
        object: key.object.clone(),
        operation: key.operation,
        enforcement: key.enforcement,
        scope,
        expires_at,
        metadata: record.metadata.clone(),
    }
}

fn grant_id(key: &GrantKey) -> String {
    let mut digest = Sha256::new();
    for field in [
        key.subject.as_bytes(),
        key.object.as_bytes(),
        key.operation.as_str().as_bytes(),
        key.enforcement.as_str().as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn parse_operation(value: &str) -> io::Result<Operation> {
    match value {
        "read" => Ok(Operation::Read),
        "write" => Ok(Operation::Write),
        "sign" => Ok(Operation::Sign),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid persisted grant operation {value:?}"),
        )),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn quarantine_rejected_state(path: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "grant path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("grants.json");
    let quarantine = parent.join(format!("{name}.rejected-{}", uuid::Uuid::new_v4()));
    fs::rename(path, &quarantine)?;
    if fs::symlink_metadata(&quarantine)?.file_type().is_file() {
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o600))?;
    }
    fs::File::open(parent)?.sync_all()?;
    Ok(Some(quarantine))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn authenticator() -> Arc<StateAuthenticator> {
        Arc::new(StateAuthenticator::for_tests([17; 32]))
    }

    fn metadata() -> GrantMetadata {
        GrantMetadata {
            client: "fixture-client".to_string(),
            executable: Some("/usr/bin/fixture-client".to_string()),
            bundle_id: None,
            target: "~/.fixture".to_string(),
        }
    }

    fn key(operation: Operation) -> GrantKey {
        GrantKey::new(
            "repo:/fixture/project".to_string(),
            "secrets/fixture".to_string(),
            operation,
            Enforcement::Prompt,
        )
    }

    fn timed(ttl: Duration) -> GrantLifetime {
        GrantLifetime::Timed { ttl, scope: GrantScope::Timed }
    }

    #[test]
    fn grant_survives_reopen_and_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let auth = authenticator();
        let cache = GrantCache::open(&path, Arc::clone(&auth));
        cache
            .insert(key(Operation::Read), timed(Duration::from_secs(600)), metadata())
            .unwrap();

        assert!(GrantCache::open(&path, Arc::clone(&auth)).is_valid(&key(Operation::Read)));
        let active = GrantCache::open(&path, auth).active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].metadata, metadata());
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn today_grant_persists_but_lock_bound_grant_is_memory_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let auth = authenticator();
        let cache = GrantCache::open(&path, Arc::clone(&auth));
        cache
            .insert(
                key(Operation::Read),
                GrantLifetime::Timed {
                    ttl: Duration::from_secs(3_600),
                    scope: GrantScope::Today,
                },
                metadata(),
            )
            .unwrap();
        cache
            .insert(key(Operation::Sign), GrantLifetime::UntilLock, metadata())
            .unwrap();

        let active = cache.active().unwrap();
        assert_eq!(active.len(), 2);
        assert!(active.iter().any(|grant| {
            grant.scope == GrantScope::Today && grant.expires_at.is_some()
        }));
        assert!(active.iter().any(|grant| {
            grant.scope == GrantScope::UntilLock && grant.expires_at.is_none()
        }));

        let reopened = GrantCache::open(&path, auth);
        assert!(reopened.is_valid(&key(Operation::Read)));
        assert!(!reopened.is_valid(&key(Operation::Sign)));
    }

    #[test]
    fn screen_lock_revokes_only_lock_bound_grants() {
        let dir = tempfile::tempdir().unwrap();
        let cache = GrantCache::open(dir.path().join("grants.json"), authenticator());
        cache
            .insert(
                key(Operation::Read),
                GrantLifetime::Timed {
                    ttl: Duration::from_secs(3_600),
                    scope: GrantScope::Today,
                },
                metadata(),
            )
            .unwrap();
        cache
            .insert(key(Operation::Sign), GrantLifetime::UntilLock, metadata())
            .unwrap();

        assert!(cache.clear_until_lock().unwrap());
        assert!(cache.is_valid(&key(Operation::Read)));
        assert!(!cache.is_valid(&key(Operation::Sign)));
        assert!(!cache.clear_until_lock().unwrap());
    }

    #[test]
    fn expired_grants_are_not_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let document = GrantDocument {
            version: SCHEMA_VERSION,
            grants: vec![PersistedGrant {
                subject: "repo:/fixture/project".to_string(),
                object: "secrets/fixture".to_string(),
                operation: "read".to_string(),
                enforcement: Enforcement::Prompt,
                scope: GrantScope::Timed,
                expires_at: 1,
                client: "fixture-client".to_string(),
                executable: None,
                bundle_id: None,
                target: "~/.fixture".to_string(),
            }],
        };
        let auth = authenticator();
        auth.persist(&path, INTEGRITY_DOMAIN, 0, &document).unwrap();

        assert!(GrantCache::open(path, auth).is_empty());
    }

    #[test]
    fn corrupt_or_overexposed_store_is_quarantined_and_reset() {
        let dir = tempfile::tempdir().unwrap();
        let corrupt_path = dir.path().join("corrupt.json");
        fs::write(&corrupt_path, b"not-json").unwrap();
        fs::set_permissions(&corrupt_path, fs::Permissions::from_mode(0o600)).unwrap();
        let corrupt_auth = authenticator();
        assert!(GrantCache::open(&corrupt_path, Arc::clone(&corrupt_auth)).is_empty());
        let reset = corrupt_auth
            .load::<GrantDocument>(&corrupt_path, INTEGRITY_DOMAIN)
            .unwrap()
            .value
            .unwrap();
        assert!(reset.grants.is_empty());

        let open_path = dir.path().join("open.json");
        fs::write(
            &open_path,
            serde_json::to_vec(&GrantDocument { version: SCHEMA_VERSION, grants: Vec::new() })
                .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&open_path, fs::Permissions::from_mode(0o644)).unwrap();
        let open_auth = authenticator();
        assert!(GrantCache::open(&open_path, Arc::clone(&open_auth)).is_empty());
        assert!(open_auth
            .load::<GrantDocument>(&open_path, INTEGRITY_DOMAIN)
            .unwrap()
            .value
            .unwrap()
            .grants
            .is_empty());

        let rejected = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".rejected-"))
            .count();
        assert_eq!(rejected, 2);
    }

    #[test]
    fn missing_authenticated_store_is_immediately_replaced_with_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let auth = authenticator();
        let cache = GrantCache::open(&path, Arc::clone(&auth));
        cache
            .insert(key(Operation::Read), timed(Duration::from_secs(600)), metadata())
            .unwrap();
        fs::remove_file(&path).unwrap();

        let reopened = GrantCache::open(&path, Arc::clone(&auth));
        assert!(reopened.is_empty());
        assert!(!reopened.is_memory_only());
        let reset = auth
            .load::<GrantDocument>(&path, INTEGRITY_DOMAIN)
            .unwrap()
            .value
            .unwrap();
        assert!(reset.grants.is_empty());
    }

    #[test]
    fn persistence_failure_keeps_grants_in_memory_and_recovers_later() {
        let dir = tempfile::tempdir().unwrap();
        let blocked_parent = dir.path().join("blocked");
        fs::write(&blocked_parent, b"not a directory").unwrap();
        let path = blocked_parent.join("grants.json");
        let auth = authenticator();
        let cache = GrantCache::open(&path, Arc::clone(&auth));

        cache
            .insert(key(Operation::Read), timed(Duration::from_secs(600)), metadata())
            .unwrap();
        assert!(cache.is_valid(&key(Operation::Read)));
        assert!(cache.is_memory_only());

        fs::remove_file(&blocked_parent).unwrap();
        fs::create_dir(&blocked_parent).unwrap();
        cache
            .insert(key(Operation::Sign), timed(Duration::from_secs(600)), metadata())
            .unwrap();
        assert!(!cache.is_memory_only());

        let reopened = GrantCache::open(path, auth);
        assert!(reopened.is_valid(&key(Operation::Read)));
        assert!(reopened.is_valid(&key(Operation::Sign)));
    }

    #[test]
    fn clear_is_persistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let auth = authenticator();
        let cache = GrantCache::open(&path, Arc::clone(&auth));
        cache
            .insert(key(Operation::Sign), timed(Duration::from_secs(600)), metadata())
            .unwrap();
        cache.clear().unwrap();

        assert!(GrantCache::open(path, auth).is_empty());
    }

    #[test]
    fn unrepresentable_ttl_is_rejected_without_caching() {
        let dir = tempfile::tempdir().unwrap();
        let cache = GrantCache::open(dir.path().join("grants.json"), authenticator());

        assert!(cache.insert(key(Operation::Read), timed(Duration::MAX), metadata()).is_err());
        assert!(cache.is_empty());
    }

    #[test]
    fn active_grants_have_stable_ids_and_can_be_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let auth = authenticator();
        let cache = GrantCache::open(&path, Arc::clone(&auth));
        cache
            .insert(key(Operation::Read), timed(Duration::from_secs(600)), metadata())
            .unwrap();

        let active = cache.active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, grant_id(&key(Operation::Read)));
        assert!(cache.revoke(&active[0].id).unwrap());
        assert!(cache.active().unwrap().is_empty());
        assert!(GrantCache::open(path, auth).active().unwrap().is_empty());
    }
}
