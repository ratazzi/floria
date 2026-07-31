use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use floria_core::authz::{Enforcement, Operation};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA_VERSION: u32 = 2;

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
    pub expires_at: i64,
    pub metadata: GrantMetadata,
}

struct GrantRecord {
    monotonic: Instant,
    unix: i64,
    metadata: GrantMetadata,
}

pub(crate) struct GrantCache {
    path: PathBuf,
    entries: Mutex<HashMap<GrantKey, GrantRecord>>,
}

impl GrantCache {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let entries = load(&path).unwrap_or_else(|error| {
            tracing::warn!(
                path = %path.display(),
                %error,
                "loading authorization grants failed; starting with no grants"
            );
            HashMap::new()
        });
        GrantCache { path, entries: Mutex::new(entries) }
    }

    pub(crate) fn is_valid(&self, key: &GrantKey) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(key) {
            Some(expiry) if expiry.monotonic > Instant::now() => true,
            Some(_) => {
                entries.remove(key);
                if let Err(error) = persist(&self.path, &entries) {
                    tracing::warn!(
                        path = %self.path.display(),
                        %error,
                        "persisting expired authorization grant removal failed"
                    );
                }
                false
            }
            None => false,
        }
    }

    pub(crate) fn insert(
        &self,
        key: GrantKey,
        ttl: Duration,
        metadata: GrantMetadata,
    ) -> io::Result<()> {
        let expires_at = now_unix()
            .checked_add(
                ttl.as_secs()
                    .try_into()
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "grant TTL is too large")
                    })?,
            )
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "grant expiry overflow"))?;
        let monotonic = Instant::now()
            .checked_add(ttl)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "grant TTL is too large"))?;
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.insert(key, GrantRecord { monotonic, unix: expires_at, metadata });
        persist(&self.path, &entries)
    }

    pub(crate) fn active(&self) -> io::Result<Vec<ActiveGrant>> {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let before = entries.len();
        entries.retain(|_, grant| grant.monotonic > now);
        if entries.len() != before {
            persist(&self.path, &entries)?;
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

    pub(crate) fn revoke(&self, id: &str) -> io::Result<bool> {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = entries.len();
        entries.retain(|key, _| grant_id(key) != id);
        let removed = entries.len() != before;
        if removed {
            persist(&self.path, &entries)?;
        }
        Ok(removed)
    }

    pub(crate) fn clear(&self) -> io::Result<()> {
        let mut entries = self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.clear();
        persist(&self.path, &entries)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    }

    #[cfg(test)]
    pub(crate) fn insert_expired(&self, key: GrantKey) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                key,
                GrantRecord {
                    monotonic: Instant::now() - Duration::from_secs(1),
                    unix: 1,
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
    expires_at: i64,
    client: String,
    executable: Option<String>,
    bundle_id: Option<String>,
    target: String,
}

fn load(path: &Path) -> io::Result<HashMap<GrantKey, GrantRecord>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grant store must be a regular file",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "grant store must not be accessible by group or other users",
        ));
    }

    let document: GrantDocument = serde_json::from_slice(&fs::read(path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
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
                monotonic,
                unix: persisted.expires_at,
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

fn persist(path: &Path, entries: &HashMap<GrantKey, GrantRecord>) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut grants = entries
        .iter()
        .map(|(key, expiry)| PersistedGrant {
            subject: key.subject.clone(),
            object: key.object.clone(),
            operation: key.operation.as_str().to_string(),
            enforcement: key.enforcement,
            expires_at: expiry.unix,
            client: expiry.metadata.client.clone(),
            executable: expiry.metadata.executable.clone(),
            bundle_id: expiry.metadata.bundle_id.clone(),
            target: expiry.metadata.target.clone(),
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
    let body = serde_json::to_vec(&GrantDocument { version: SCHEMA_VERSION, grants })?;
    let temporary = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&body)?;
    file.sync_all()?;
    fs::rename(temporary, path)
}

fn active_grant(key: &GrantKey, record: &GrantRecord) -> ActiveGrant {
    ActiveGrant {
        id: grant_id(key),
        subject: key.subject.clone(),
        object: key.object.clone(),
        operation: key.operation,
        enforcement: key.enforcement,
        expires_at: record.unix,
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn grant_survives_reopen_and_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let cache = GrantCache::open(&path);
        cache
            .insert(key(Operation::Read), Duration::from_secs(600), metadata())
            .unwrap();

        assert!(GrantCache::open(&path).is_valid(&key(Operation::Read)));
        let active = GrantCache::open(&path).active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].metadata, metadata());
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
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
                expires_at: 1,
                client: "fixture-client".to_string(),
                executable: None,
                bundle_id: None,
                target: "~/.fixture".to_string(),
            }],
        };
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(GrantCache::open(path).is_empty());
    }

    #[test]
    fn corrupt_or_overexposed_store_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let corrupt_path = dir.path().join("corrupt.json");
        fs::write(&corrupt_path, b"not-json").unwrap();
        fs::set_permissions(&corrupt_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(GrantCache::open(corrupt_path).is_empty());

        let open_path = dir.path().join("open.json");
        fs::write(
            &open_path,
            serde_json::to_vec(&GrantDocument { version: SCHEMA_VERSION, grants: Vec::new() })
                .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&open_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(GrantCache::open(open_path).is_empty());
    }

    #[test]
    fn clear_is_persistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let cache = GrantCache::open(&path);
        cache
            .insert(key(Operation::Sign), Duration::from_secs(600), metadata())
            .unwrap();
        cache.clear().unwrap();

        assert!(GrantCache::open(path).is_empty());
    }

    #[test]
    fn unrepresentable_ttl_is_rejected_without_caching() {
        let dir = tempfile::tempdir().unwrap();
        let cache = GrantCache::open(dir.path().join("grants.json"));

        assert!(cache.insert(key(Operation::Read), Duration::MAX, metadata()).is_err());
        assert!(cache.is_empty());
    }

    #[test]
    fn active_grants_have_stable_ids_and_can_be_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let cache = GrantCache::open(&path);
        cache
            .insert(key(Operation::Read), Duration::from_secs(600), metadata())
            .unwrap();

        let active = cache.active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, grant_id(&key(Operation::Read)));
        assert!(cache.revoke(&active[0].id).unwrap());
        assert!(cache.active().unwrap().is_empty());
        assert!(GrantCache::open(path).active().unwrap().is_empty());
    }
}
