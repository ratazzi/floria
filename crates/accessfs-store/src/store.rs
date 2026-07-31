//! `SecretStore`: keep a secret blob confidential at rest, addressed by a stable id.
//!
//! [`AgeDirStore`] is the portable, sync/backup-friendly implementation: each secret is an
//! age-encrypted blob under `<root>/<id>/secret.age` with a plaintext `<id>/meta.toml` sidecar.
//! The id (a v4 UUID) is the identity; the original path is mutable metadata, not the key, so
//! renaming/moving the source never desyncs the store. Plaintext exists only as
//! [`Zeroizing`] in memory and never touches disk here.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use accessfs_core::authz::Enforcement;
use accessfs_core::metadata::ItemMetadata;

use crate::error::{StoreError, StoreResult};
use crate::keys::KeyProvider;

/// Current on-disk layout. Format 2 adds managed (non-file) origins; format 1 file entries remain
/// readable and are updated in place without rewriting their origin metadata.
const STORE_FORMAT: u32 = 2;

/// Stable secret identifier (a v4 UUID string). Immutable for the life of an entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretId(String);

impl SecretId {
    pub fn generate() -> Self {
        SecretId(uuid::Uuid::new_v4().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SecretId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for SecretId {
    type Err = StoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        uuid::Uuid::parse_str(s)
            .map(|u| SecretId(u.to_string()))
            .map_err(|_| StoreError::Invalid(format!("invalid secret id {s:?}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretOrigin {
    File { source_path: PathBuf },
    Managed { label: String },
}

/// What the caller knows about a secret when creating it.
#[derive(Debug, Clone)]
pub struct NewSecret {
    pub origin: SecretOrigin,
    pub mode: u32,
}

impl NewSecret {
    pub fn file(source_path: PathBuf, mode: u32) -> Self {
        NewSecret { origin: SecretOrigin::File { source_path }, mode }
    }

    pub fn managed(label: impl Into<String>) -> Self {
        NewSecret { origin: SecretOrigin::Managed { label: label.into() }, mode: 0o600 }
    }
}

/// A stored secret's metadata (no plaintext), reflecting the current head version.
#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub id: SecretId,
    pub origin: SecretOrigin,
    pub mode: u32,
    /// Size of the head version.
    pub size: u64,
    /// When the secret was first protected.
    pub created: String,
    /// Head version number.
    pub current_version: u32,
    /// Default authorization behavior when no explicit process rule matches this secret.
    pub enforcement: Enforcement,
    /// Project Environments where this file-backed item is exposed to managed worktrees.
    ///
    /// `None` preserves legacy behavior: expose the file in every Environment of its owning
    /// Project. Managed value secrets do not use this field.
    pub environment_ids: Option<Vec<String>>,
    /// Plaintext, non-secret context for display and navigation.
    pub metadata: ItemMetadata,
}

impl SecretRecord {
    pub fn source_path(&self) -> Option<&Path> {
        match &self.origin {
            SecretOrigin::File { source_path } => Some(source_path),
            SecretOrigin::Managed { .. } => None,
        }
    }

    pub fn display_name(&self) -> String {
        match &self.origin {
            SecretOrigin::File { source_path } => source_path.display().to_string(),
            SecretOrigin::Managed { label } => label.clone(),
        }
    }
}

/// One immutable version of a secret (no plaintext).
#[derive(Debug, Clone)]
pub struct VersionRecord {
    pub version: u32,
    pub size: u64,
    pub created: String,
    pub note: Option<String>,
}

/// A place to keep secret blobs confidential at rest, addressed by [`SecretId`].
///
/// Versions are append-only and immutable; each secret has a head pointer (its current version).
/// Writes never destroy prior content — `append_version` adds, `set_head` (rollback) just repoints.
pub trait SecretStore: Send + Sync {
    /// Protect new content, creating version 1.
    fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId>;
    /// Decrypt the head version.
    fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>>;
    /// Decrypt several head versions. Implementations may share expensive key-loading work.
    fn get_many(&self, ids: &[SecretId]) -> StoreResult<Vec<Zeroizing<Vec<u8>>>> {
        ids.iter().map(|id| self.get(id)).collect()
    }
    /// Decrypt a specific version.
    fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>>;
    /// Append a new version (immutable) and move the head to it; returns the new version number.
    fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32>;
    /// All versions, oldest first.
    fn history(&self, id: &SecretId) -> StoreResult<Vec<VersionRecord>>;
    /// Rollback: point the head at an existing version (does not copy or delete anything).
    fn set_head(&self, id: &SecretId, version: u32) -> StoreResult<()>;
    /// Head metadata for a single secret, or `None` if it doesn't exist.
    fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>>;
    fn list(&self) -> StoreResult<Vec<SecretRecord>>;
    fn get_by_path(&self, source_path: &Path) -> StoreResult<Option<SecretRecord>>;
    /// Atomically replace display metadata and authorization behavior without creating a content
    /// version.
    fn update_settings(
        &self,
        id: &SecretId,
        metadata: ItemMetadata,
        enforcement: Enforcement,
        environment_ids: Option<Vec<String>>,
    ) -> StoreResult<()>;
    /// Delete a secret and all its versions.
    fn delete(&self, id: &SecretId) -> StoreResult<()>;
}

/// On-disk `<id>/meta.toml`: entry-level metadata plus the head pointer.
#[derive(Serialize, Deserialize)]
struct MetaFile {
    /// See [`STORE_FORMAT`]. `default` so a pre-format entry reads as 0 and fails the check.
    #[serde(default)]
    format: u32,
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    managed_label: Option<String>,
    mode: u32,
    created: String,
    current_version: u32,
    #[serde(default = "default_secret_enforcement")]
    enforcement: Enforcement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    environment_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "ItemMetadata::is_empty")]
    metadata: ItemMetadata,
}

fn default_secret_enforcement() -> Enforcement {
    Enforcement::Prompt
}

/// On-disk `<id>/v/NNNN.toml`: immutable per-version metadata.
#[derive(Serialize, Deserialize)]
struct VersionMetaFile {
    version: u32,
    size: u64,
    created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// Portable age-encrypted directory store.
pub struct AgeDirStore {
    root: PathBuf,
    keys: Arc<dyn KeyProvider>,
}

impl AgeDirStore {
    /// Open (creating the root directory, mode 0700, if needed).
    pub fn open(root: PathBuf, keys: Arc<dyn KeyProvider>) -> StoreResult<Self> {
        if !root.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&root)
                .map_err(|e| StoreError::io(&root, e))?;
        }
        Ok(AgeDirStore { root, keys })
    }

    /// Take the store-wide exclusive lock (blocking), serializing mutations across processes —
    /// the CLI and the mounted daemon share this store. Released when the returned handle drops.
    /// Reads don't lock: version blobs are immutable and the head pointer is renamed atomically.
    fn lock_exclusive(&self) -> StoreResult<std::fs::File> {
        let path = self.root.join(".lock");
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false) // the file is only ever locked, never written
            .mode(0o600)
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;
        f.lock().map_err(|e| StoreError::io(&path, e))?;
        Ok(f)
    }

    fn entry_dir(&self, id: &SecretId) -> PathBuf {
        self.root.join(id.as_str())
    }

    fn versions_dir(&self, id: &SecretId) -> PathBuf {
        self.entry_dir(id).join("v")
    }

    fn version_blob(&self, id: &SecretId, version: u32) -> PathBuf {
        self.versions_dir(id).join(format!("{version:04}.age"))
    }

    fn version_meta_path(&self, id: &SecretId, version: u32) -> PathBuf {
        self.versions_dir(id).join(format!("{version:04}.toml"))
    }

    fn read_meta(&self, id: &SecretId) -> StoreResult<MetaFile> {
        let path = self.entry_dir(id).join("meta.toml");
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(id.to_string())
            } else {
                StoreError::io(&path, e)
            }
        })?;
        let meta: MetaFile = toml::from_str(&text).map_err(|e| StoreError::Corrupt {
            id: id.to_string(),
            reason: format!("meta.toml: {e}"),
        })?;
        if !matches!(meta.format, 1 | STORE_FORMAT) {
            return Err(StoreError::Corrupt {
                id: id.to_string(),
                reason: format!(
                    "store format {} but this build supports 1 through {}; migrate or delete the entry",
                    meta.format, STORE_FORMAT
                ),
            });
        }
        match (&meta.source_path, &meta.managed_label) {
            (Some(_), None) => {}
            (None, Some(label)) if !label.trim().is_empty() && meta.format >= 2 => {}
            _ => {
                return Err(StoreError::Corrupt {
                    id: id.to_string(),
                    reason: "meta.toml must contain exactly one valid secret origin".to_string(),
                })
            }
        }
        Ok(meta)
    }

    fn write_meta(&self, id: &SecretId, meta: &MetaFile) -> StoreResult<()> {
        let text = toml::to_string_pretty(meta)
            .map_err(|e| StoreError::Crypto(format!("serialize meta: {e}")))?;
        write_private(&self.entry_dir(id).join("meta.toml"), text.as_bytes())
    }

    fn read_version_meta(&self, id: &SecretId, version: u32) -> StoreResult<VersionMetaFile> {
        let path = self.version_meta_path(id, version);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(format!("{id}@v{version}"))
            } else {
                StoreError::io(&path, e)
            }
        })?;
        toml::from_str(&text).map_err(|e| StoreError::Corrupt {
            id: id.to_string(),
            reason: format!("v/{version:04}.toml: {e}"),
        })
    }

    /// Highest existing version number for an entry (0 if none), used to pick the next on append.
    fn max_version(&self, id: &SecretId) -> StoreResult<u32> {
        let vdir = self.versions_dir(id);
        let rd = match std::fs::read_dir(&vdir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(StoreError::io(&vdir, e)),
        };
        let mut max = 0u32;
        for entry in rd {
            let entry = entry.map_err(|e| StoreError::io(&vdir, e))?;
            let name = entry.file_name();
            if let Some(stem) = name.to_string_lossy().strip_suffix(".toml") {
                if let Ok(v) = stem.parse::<u32>() {
                    max = max.max(v);
                }
            }
        }
        Ok(max)
    }

    /// Write one immutable version (ciphertext + metadata sidecar). Does not touch the head pointer.
    fn write_version(
        &self,
        id: &SecretId,
        version: u32,
        plaintext: &[u8],
        note: Option<String>,
    ) -> StoreResult<()> {
        let ciphertext = self.encrypt(plaintext)?;
        write_private(&self.version_blob(id, version), &ciphertext)?;
        let vmeta = VersionMetaFile {
            version,
            size: plaintext.len() as u64,
            created: now_rfc3339(),
            note,
        };
        let text = toml::to_string_pretty(&vmeta)
            .map_err(|e| StoreError::Crypto(format!("serialize version meta: {e}")))?;
        write_private(&self.version_meta_path(id, version), text.as_bytes())
    }

    fn encrypt(&self, plaintext: &[u8]) -> StoreResult<Vec<u8>> {
        let recipients = self.keys.recipients()?;
        let encryptor = age::Encryptor::with_recipients(recipients)
            .ok_or_else(|| StoreError::Crypto("no recipients configured".to_string()))?;
        let mut out = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut out)
            .map_err(|e| StoreError::Crypto(format!("wrap: {e}")))?;
        writer
            .write_all(plaintext)
            .map_err(|e| StoreError::Crypto(format!("write: {e}")))?;
        writer
            .finish()
            .map_err(|e| StoreError::Crypto(format!("finish: {e}")))?;
        Ok(out)
    }

    fn decrypt_with_identity(
        &self,
        ciphertext: &[u8],
        identity: &dyn age::Identity,
    ) -> StoreResult<Zeroizing<Vec<u8>>> {
        let decryptor = match age::Decryptor::new(ciphertext)
            .map_err(|e| StoreError::Crypto(format!("open: {e}")))?
        {
            age::Decryptor::Recipients(d) => d,
            age::Decryptor::Passphrase(_) => {
                return Err(StoreError::Crypto(
                    "blob is passphrase-encrypted, expected recipient-encrypted".to_string(),
                ))
            }
        };
        let mut reader = decryptor
            .decrypt(std::iter::once(identity))
            .map_err(|e| StoreError::Crypto(format!("decrypt: {e}")))?;
        let mut out = Zeroizing::new(Vec::new());
        reader
            .read_to_end(&mut out)
            .map_err(|e| StoreError::Crypto(format!("read: {e}")))?;
        Ok(out)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> StoreResult<Zeroizing<Vec<u8>>> {
        let identity = self.keys.identity()?;
        self.decrypt_with_identity(ciphertext, identity.as_ref())
    }

    fn read_version_ciphertext(&self, id: &SecretId, version: u32) -> StoreResult<Vec<u8>> {
        let path = self.version_blob(id, version);
        std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(format!("{id}@v{version}"))
            } else {
                StoreError::io(&path, e)
            }
        })
    }
}

impl SecretStore for AgeDirStore {
    fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId> {
        let mode = meta.mode;
        let (source_path, managed_label) = match meta.origin {
            SecretOrigin::File { source_path } if source_path.is_absolute() => {
                (Some(source_path.to_string_lossy().into_owned()), None)
            }
            SecretOrigin::File { source_path } => {
                return Err(StoreError::Invalid(format!(
                    "file secret source path must be absolute: {}",
                    source_path.display()
                )))
            }
            SecretOrigin::Managed { label } if !label.trim().is_empty() => (None, Some(label)),
            SecretOrigin::Managed { .. } => {
                return Err(StoreError::Invalid("managed secret label cannot be empty".to_string()))
            }
        };
        let _lock = self.lock_exclusive()?;
        let id = SecretId::generate();
        let vdir = self.versions_dir(&id);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&vdir)
            .map_err(|e| StoreError::io(&vdir, e))?;
        self.write_version(&id, 1, plaintext, None)?;
        self.write_meta(
            &id,
            &MetaFile {
                format: STORE_FORMAT,
                id: id.to_string(),
                source_path,
                managed_label,
                mode,
                created: now_rfc3339(),
                current_version: 1,
                enforcement: Enforcement::Prompt,
                environment_ids: None,
                metadata: ItemMetadata::default(),
            },
        )?;
        Ok(id)
    }

    fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
        let head = self.read_meta(id)?.current_version;
        self.get_version(id, head)
    }

    fn get_many(&self, ids: &[SecretId]) -> StoreResult<Vec<Zeroizing<Vec<u8>>>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let identity = self.keys.identity()?;
        ids.iter()
            .map(|id| {
                let head = self.read_meta(id)?.current_version;
                let ciphertext = self.read_version_ciphertext(id, head)?;
                self.decrypt_with_identity(&ciphertext, identity.as_ref())
            })
            .collect()
    }

    fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
        let ciphertext = self.read_version_ciphertext(id, version)?;
        self.decrypt(&ciphertext)
    }

    fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
        // Order matters: write the immutable version first, then move the head. A crash between
        // the two leaves an orphan version (harmless) rather than a dangling head.
        let _lock = self.lock_exclusive()?;
        let mut meta = self.read_meta(id)?;
        let next = self.max_version(id)?.saturating_add(1);
        self.write_version(id, next, plaintext, None)?;
        meta.current_version = next;
        self.write_meta(id, &meta)?;
        Ok(next)
    }

    fn history(&self, id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
        self.read_meta(id)?; // ensure the entry exists
        let vdir = self.versions_dir(id);
        let rd = std::fs::read_dir(&vdir).map_err(|e| StoreError::io(&vdir, e))?;
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| StoreError::io(&vdir, e))?;
            let name = entry.file_name();
            if let Some(stem) = name.to_string_lossy().strip_suffix(".toml") {
                if let Ok(v) = stem.parse::<u32>() {
                    let vm = self.read_version_meta(id, v)?;
                    out.push(VersionRecord {
                        version: vm.version,
                        size: vm.size,
                        created: vm.created,
                        note: vm.note,
                    });
                }
            }
        }
        out.sort_by_key(|r| r.version);
        Ok(out)
    }

    fn set_head(&self, id: &SecretId, version: u32) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        let mut meta = self.read_meta(id)?;
        if !self.version_blob(id, version).exists() {
            return Err(StoreError::NotFound(format!("{id}@v{version}")));
        }
        meta.current_version = version;
        self.write_meta(id, &meta)
    }

    fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
        let meta = match self.read_meta(id) {
            Ok(m) => m,
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let vm = self.read_version_meta(id, meta.current_version)?;
        let origin = match (meta.source_path, meta.managed_label) {
            (Some(source_path), None) => {
                SecretOrigin::File { source_path: PathBuf::from(source_path) }
            }
            (None, Some(label)) => SecretOrigin::Managed { label },
            _ => unreachable!("read_meta validates exactly one origin"),
        };
        Ok(Some(SecretRecord {
            id: id.clone(),
            origin,
            mode: meta.mode,
            size: vm.size,
            created: meta.created,
            current_version: meta.current_version,
            enforcement: meta.enforcement,
            environment_ids: meta.environment_ids,
            metadata: meta.metadata,
        }))
    }

    fn list(&self) -> StoreResult<Vec<SecretRecord>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(StoreError::io(&self.root, e)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| StoreError::io(&self.root, e))?;
            if !entry.path().is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = name.parse::<SecretId>() else {
                continue; // ignore non-entry directories
            };
            if let Some(rec) = self.record(&id)? {
                out.push(rec);
            }
        }
        out.sort_by_key(SecretRecord::display_name);
        Ok(out)
    }

    fn get_by_path(&self, source_path: &Path) -> StoreResult<Option<SecretRecord>> {
        let target = source_path.to_string_lossy();
        Ok(self
            .list()?
            .into_iter()
            .find(|record| {
                record
                    .source_path()
                    .is_some_and(|path| path.to_string_lossy() == target)
            }))
    }

    fn update_settings(
        &self,
        id: &SecretId,
        metadata: ItemMetadata,
        enforcement: Enforcement,
        environment_ids: Option<Vec<String>>,
    ) -> StoreResult<()> {
        metadata.validate().map_err(StoreError::Invalid)?;
        let _lock = self.lock_exclusive()?;
        let mut meta = self.read_meta(id)?;
        meta.metadata = metadata;
        meta.enforcement = enforcement;
        meta.environment_ids = environment_ids;
        self.write_meta(id, &meta)
    }

    fn delete(&self, id: &SecretId) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        let dir = self.entry_dir(id);
        std::fs::remove_dir_all(&dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(id.to_string())
            } else {
                StoreError::io(&dir, e)
            }
        })
    }
}

/// Current time as a second-precision RFC 3339 string (UTC).
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Write a file with mode 0600, atomically: write+fsync a `.tmp` sibling, then rename over the
/// target. A crash mid-write leaves the old content intact (this guards the head pointer in
/// `meta.toml`). Concurrent writers are serialized by the store lock, so the fixed temp name is safe.
fn write_private(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    let tmp = {
        let mut os = path.as_os_str().to_owned();
        os.push(".tmp");
        PathBuf::from(os)
    };
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| StoreError::io(&tmp, e))?;
    f.write_all(bytes).map_err(|e| StoreError::io(&tmp, e))?;
    f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| StoreError::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StoreResult;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test key provider backed by a native age x25519 key (no ssh, no external tools).
    struct X25519Keys(age::x25519::Identity);
    impl KeyProvider for X25519Keys {
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.0.to_public())])
        }
        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    struct CountingKeys {
        identity: age::x25519::Identity,
        identity_loads: Arc<AtomicUsize>,
    }

    impl KeyProvider for CountingKeys {
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.identity.to_public())])
        }

        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            self.identity_loads.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(self.identity.clone()))
        }
    }

    fn store(root: PathBuf) -> AgeDirStore {
        let keys = Arc::new(X25519Keys(age::x25519::Identity::generate()));
        AgeDirStore::open(root, keys).unwrap()
    }

    #[test]
    fn malformed_secret_id_is_invalid_not_missing() {
        assert!(matches!(
            "not-a-secret-id".parse::<SecretId>(),
            Err(StoreError::Invalid(message)) if message.contains("invalid secret id")
        ));
    }

    #[test]
    fn put_get_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let secret = b"EXAMPLE_CONFIG=placeholder-value-one\n";
        let id = s
            .put(
                NewSecret::file(PathBuf::from("/Users/me/proj/.env"), 0o600),
                secret,
            )
            .unwrap();
        let got = s.get(&id).unwrap();
        assert_eq!(&got[..], secret);

        // ciphertext on disk must not contain the plaintext
        let blob = std::fs::read(s.version_blob(&id, 1)).unwrap();
        assert!(!blob.windows(secret.len()).any(|w| w == secret));
    }

    #[test]
    fn get_many_loads_the_identity_once() {
        let tmp = tempfile::tempdir().unwrap();
        let identity_loads = Arc::new(AtomicUsize::new(0));
        let keys = Arc::new(CountingKeys {
            identity: age::x25519::Identity::generate(),
            identity_loads: Arc::clone(&identity_loads),
        });
        let store = AgeDirStore::open(tmp.path().to_path_buf(), keys).unwrap();
        let first = store
            .put(NewSecret::managed("fixture-bulk-one"), b"fixture-value-one")
            .unwrap();
        let second = store
            .put(NewSecret::managed("fixture-bulk-two"), b"fixture-value-two")
            .unwrap();

        let values = store.get_many(&[first, second]).unwrap();

        assert_eq!(identity_loads.load(Ordering::Relaxed), 1);
        assert_eq!(values[0].as_slice(), b"fixture-value-one");
        assert_eq!(values[1].as_slice(), b"fixture-value-two");
    }

    #[test]
    fn append_version_moves_head_non_destructively() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s
            .put(NewSecret::file(PathBuf::from("/p/.env"), 0o600), b"v1")
            .unwrap();

        assert_eq!(s.append_version(&id, b"v2-longer").unwrap(), 2);
        assert_eq!(s.append_version(&id, b"v3").unwrap(), 3);

        // head is v3; old versions still decrypt
        assert_eq!(s.get(&id).unwrap().as_slice(), b"v3");
        assert_eq!(s.get_version(&id, 1).unwrap().as_slice(), b"v1");
        assert_eq!(s.get_version(&id, 2).unwrap().as_slice(), b"v2-longer");

        // record reflects the head version and its size
        let rec = s.record(&id).unwrap().unwrap();
        assert_eq!(rec.current_version, 3);
        assert_eq!(rec.size, 2);

        // history lists all three, oldest first
        let hist = s.history(&id).unwrap();
        assert_eq!(hist.iter().map(|v| v.version).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn set_head_rolls_back_by_repointing() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s
            .put(NewSecret::file(PathBuf::from("/p/.env"), 0o600), b"first")
            .unwrap();
        s.append_version(&id, b"second").unwrap();

        // rollback head to v1
        s.set_head(&id, 1).unwrap();
        assert_eq!(s.get(&id).unwrap().as_slice(), b"first");
        assert_eq!(s.record(&id).unwrap().unwrap().current_version, 1);

        // a later append goes to max+1 (=3), not head+1, and both older versions survive
        assert_eq!(s.append_version(&id, b"third").unwrap(), 3);
        assert_eq!(s.get_version(&id, 2).unwrap().as_slice(), b"second");

        // rolling back to a nonexistent version fails
        assert!(matches!(s.set_head(&id, 9), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn list_and_get_by_path() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        s.put(NewSecret::file(PathBuf::from("/a/.env"), 0o600), b"A=1").unwrap();
        s.put(NewSecret::file(PathBuf::from("/b/.env"), 0o600), b"B=2").unwrap();

        let all = s.list().unwrap();
        assert_eq!(all.len(), 2);

        let rec = s.get_by_path(Path::new("/b/.env")).unwrap().unwrap();
        assert_eq!(s.get(&rec.id).unwrap().as_slice(), b"B=2");
        assert!(s.get_by_path(Path::new("/nope")).unwrap().is_none());
    }

    #[test]
    fn managed_secret_has_a_label_without_a_fake_source_path() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s
            .put(NewSecret::managed("Fixture Shared Secret"), b"fixture-managed-value")
            .unwrap();

        let record = s.record(&id).unwrap().unwrap();
        assert_eq!(
            record.origin,
            SecretOrigin::Managed { label: "Fixture Shared Secret".to_string() }
        );
        assert!(record.source_path().is_none());
        assert_eq!(s.get(&id).unwrap().as_slice(), b"fixture-managed-value");
        let meta = std::fs::read_to_string(s.entry_dir(&id).join("meta.toml")).unwrap();
        assert!(meta.contains("managed_label = \"Fixture Shared Secret\""));
        assert!(!meta.contains("fixture-managed-value"));
    }

    #[test]
    fn metadata_roundtrips_without_creating_a_content_version() {
        use accessfs_core::metadata::ItemLink;

        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s
            .put(NewSecret::file(PathBuf::from("/fixture/.pgpass"), 0o600), b"fixture")
            .unwrap();
        let metadata = ItemMetadata {
            note: Some("Local reporting database".to_string()),
            links: vec![ItemLink {
                label: "Database console".to_string(),
                url: "https://example.invalid/databases/reporting".to_string(),
            }],
        };

        s.update_settings(
            &id,
            metadata.clone(),
            Enforcement::TouchId,
            Some(vec!["production".to_string(), "staging".to_string()]),
        )
        .unwrap();

        let record = s.record(&id).unwrap().unwrap();
        assert_eq!(record.metadata, metadata);
        assert_eq!(record.enforcement, Enforcement::TouchId);
        assert_eq!(
            record.environment_ids,
            Some(vec!["production".to_string(), "staging".to_string()])
        );
        assert_eq!(record.current_version, 1);
        assert_eq!(s.history(&id).unwrap().len(), 1);
        let sidecar = std::fs::read_to_string(s.entry_dir(&id).join("meta.toml")).unwrap();
        assert!(sidecar.contains("Local reporting database"));
        assert!(sidecar.contains("enforcement = \"touchid\""));
        assert!(!sidecar.contains("fixture\n"));
    }

    #[test]
    fn delete_removes_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s
            .put(NewSecret::file(PathBuf::from("/x/.env"), 0o600), b"X=1")
            .unwrap();
        s.delete(&id).unwrap();
        assert!(matches!(s.get(&id), Err(StoreError::NotFound(_))));
        assert!(s.list().unwrap().is_empty());
    }

    #[test]
    fn wrong_format_is_rejected_with_clear_error() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s
            .put(NewSecret::file(PathBuf::from("/x/.env"), 0o600), b"X=1")
            .unwrap();

        // Simulate an entry written by a different (older/newer) layout.
        let meta_path = tmp.path().join(id.as_str()).join("meta.toml");
        let text = std::fs::read_to_string(&meta_path).unwrap();
        std::fs::write(&meta_path, text.replace("format = 2", "format = 99")).unwrap();

        match s.get(&id) {
            Err(StoreError::Corrupt { reason, .. }) => assert!(reason.contains("format 99")),
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn legacy_file_origin_metadata_remains_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s
            .put(NewSecret::file(PathBuf::from("/fixture/project/.env"), 0o600), b"fixture-v1")
            .unwrap();
        let meta_path = tmp.path().join(id.as_str()).join("meta.toml");
        let text = std::fs::read_to_string(&meta_path).unwrap();
        std::fs::write(&meta_path, text.replace("format = 2", "format = 1")).unwrap();

        assert_eq!(s.get(&id).unwrap().as_slice(), b"fixture-v1");
        assert_eq!(s.append_version(&id, b"fixture-v2").unwrap(), 2);
        assert_eq!(
            s.record(&id).unwrap().unwrap().source_path(),
            Some(Path::new("/fixture/project/.env"))
        );
    }

    #[test]
    fn missing_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = SecretId::generate();
        assert!(matches!(s.get(&id), Err(StoreError::NotFound(_))));
    }

    /// End-to-end with a real (unencrypted) ssh ed25519 key — the dev key path.
    #[test]
    fn ssh_ed25519_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("id_ed25519");
        let ok = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", "test", "-q", "-f"])
            .arg(&key)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("ssh-keygen unavailable; skipping");
            return;
        }
        // The key file must be 0600 for the store's perm check.
        std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();

        let keys = Arc::new(crate::keys::SshKeyProvider::new(key, None));
        let s = AgeDirStore::open(tmp.path().join("store"), keys).unwrap();
        let secret = b"EXAMPLE_CONFIG=placeholder-value-two\n";
        let id = s
            .put(NewSecret::file(PathBuf::from("/p/.env"), 0o600), secret)
            .unwrap();
        assert_eq!(s.get(&id).unwrap().as_slice(), secret);
    }
}
