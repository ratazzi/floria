//! `SecretStore`: keep a secret blob confidential at rest, addressed by a stable id.
//!
//! [`AgeDirStore`] is the portable, sync/backup-friendly implementation: each secret is an
//! age-encrypted blob under `<root>/<id>/secret.age` with a plaintext `<id>/meta.toml` sidecar.
//! The id (a v4 UUID) is the identity; the original path is mutable metadata, not the key, so
//! renaming/moving the source never desyncs the store. Plaintext exists only as
//! [`Zeroizing`] in memory and never touches disk here.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use floria_core::authz::Enforcement;
use floria_core::metadata::ItemMetadata;
use floria_integrity::StateAuthenticator;

use crate::error::{StoreError, StoreResult};
use crate::keys::KeyProvider;

/// Current on-disk layout. Format 3 binds every encrypted payload to its secret id and version;
/// opening an older store rewrites legacy ciphertext before returning it to callers.
pub const STORE_FORMAT_VERSION: u32 = 3;
pub const MIN_SUPPORTED_STORE_FORMAT_VERSION: u32 = 1;

const PAYLOAD_MAGIC: &[u8; 8] = b"FLORIA\0\x03";
const INTEGRITY_DOMAIN: &str = "encrypted-store-security-state";

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
    /// Initial authorization behavior. Once persisted, callers update it only through the
    /// explicit settings interface.
    pub enforcement: Enforcement,
}

impl NewSecret {
    pub fn file(source_path: PathBuf, mode: u32) -> Self {
        NewSecret {
            origin: SecretOrigin::File { source_path },
            mode,
            enforcement: Enforcement::Prompt,
        }
    }

    pub fn managed(label: impl Into<String>) -> Self {
        NewSecret {
            origin: SecretOrigin::Managed { label: label.into() },
            mode: 0o600,
            enforcement: Enforcement::Prompt,
        }
    }

    pub fn with_enforcement(mut self, enforcement: Enforcement) -> Self {
        self.enforcement = enforcement;
        self
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
    /// Stable identity of the cross-backend mutation that created this version.
    /// Ordinary local and legacy versions do not have one.
    pub mutation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreVerification {
    pub secrets: usize,
    pub versions: usize,
    pub plaintext_bytes: u64,
    pub secret_ids: Vec<String>,
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MetaFile {
    /// See [`STORE_FORMAT_VERSION`]. `default` so a pre-format entry reads as 0 and fails the check.
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionMetaFile {
    version: u32,
    size: u64,
    created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mutation_id: Option<String>,
}

/// Portable age-encrypted directory store.
pub struct AgeDirStore {
    root: PathBuf,
    keys: Arc<dyn KeyProvider>,
    integrity: Option<StoreIntegrity>,
}

#[derive(Clone)]
struct StoreIntegrity {
    authenticator: Arc<StateAuthenticator>,
    sidecar: PathBuf,
    generation: Arc<Mutex<u64>>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoreSecuritySnapshot {
    entries: Vec<StoreSecurityEntry>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoreSecurityEntry {
    meta: MetaFile,
    versions: Vec<StoreSecurityVersion>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoreSecurityVersion {
    meta: VersionMetaFile,
    ciphertext_sha256: String,
}

/// Holds the store's cross-process mutation lock for a maintenance operation.
///
/// The guard intentionally exposes no mutation methods. While it is alive, normal store writes
/// block, allowing a caller to verify and atomically replace the store directory as one
/// maintenance transaction.
pub struct StoreMaintenanceGuard {
    _lock: std::fs::File,
    root: PathBuf,
}

impl StoreMaintenanceGuard {
    /// Copy the locked store without trying to acquire the same lock again.
    pub fn backup_to(&self, destination: &Path) -> StoreResult<()> {
        copy_store_directory(&self.root, destination)
    }
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
        let store = AgeDirStore { root, keys, integrity: None };
        store.migrate_context_binding()?;
        Ok(store)
    }

    pub fn open_authenticated(
        root: PathBuf,
        keys: Arc<dyn KeyProvider>,
        authenticator: Arc<StateAuthenticator>,
    ) -> StoreResult<Self> {
        Self::open(root, keys)?.authenticate(authenticator)
    }

    pub fn authenticate(mut self, authenticator: Arc<StateAuthenticator>) -> StoreResult<Self> {
        let sidecar = self.root.join(".integrity.json");
        let loaded = authenticator.load::<StoreSecuritySnapshot>(&sidecar, INTEGRITY_DOMAIN)?;
        let current = self.security_snapshot()?;
        let generation = match loaded.value {
            Some(authenticated) if authenticated == current => loaded.generation,
            Some(_) => {
                return Err(StoreError::Corrupt {
                    id: "store".to_string(),
                    reason: "store contents do not match the authenticated security-state snapshot"
                        .to_string(),
                })
            }
            None
                if loaded.generation == 0
                    && (current.entries.is_empty()
                        || option_env!("FLORIA_INSECURE_DEVELOPMENT_BUILD") == Some("1")) =>
            {
                tracing::warn!(store = %self.root.display(), "sealing existing encrypted store as authenticated security state");
                authenticator.persist(&sidecar, INTEGRITY_DOMAIN, 0, &current)?
            }
            None if loaded.generation == 0 => {
                return Err(StoreError::Corrupt {
                    id: "store".to_string(),
                    reason: "refusing to trust a non-empty encrypted store without an authenticated checkpoint"
                        .to_string(),
                })
            }
            None => {
                return Err(StoreError::Corrupt {
                    id: "store".to_string(),
                    reason: format!(
                        "authenticated store sidecar {} is missing at Keychain generation {}",
                        sidecar.display(),
                        loaded.generation
                    ),
                })
            }
        };
        self.integrity = Some(StoreIntegrity {
            authenticator,
            sidecar,
            generation: Arc::new(Mutex::new(generation)),
        });
        Ok(self)
    }

    /// Adopt the currently mounted root after an explicit, verified restore activation.
    ///
    /// Normal startup never calls this: it compares the live store with the existing checkpoint
    /// and rejects rollback. The restore transaction calls it only after decrypting every staged
    /// version and atomically switching both catalog and store paths.
    pub fn authenticate_restored_state(
        &self,
        authenticator: Arc<StateAuthenticator>,
    ) -> StoreResult<()> {
        let restored = AgeDirStore {
            root: self.root.clone(),
            keys: Arc::clone(&self.keys),
            integrity: None,
        };
        restored.verify_all()?;
        let snapshot = restored.security_snapshot()?;
        let sidecar = self.root.join(".integrity.json");
        let generation = authenticator.checkpoint_generation(INTEGRITY_DOMAIN)?;
        let next = authenticator.persist(
            &sidecar,
            INTEGRITY_DOMAIN,
            generation,
            &snapshot,
        )?;
        if let Some(integrity) = &self.integrity {
            *integrity
                .generation
                .lock()
                .expect("store integrity generation poisoned") = next;
        }
        Ok(())
    }

    fn security_snapshot(&self) -> StoreResult<StoreSecuritySnapshot> {
        let mut ids = std::fs::read_dir(&self.root)
            .map_err(|error| StoreError::io(&self.root, error))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<SecretId>().ok())
            .collect::<Vec<_>>();
        ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let mut entries = Vec::with_capacity(ids.len());
        for id in ids {
            let meta = self.read_meta(&id)?;
            let mut versions = Vec::new();
            for version in self.history_unverified(&id)? {
                let ciphertext = self.read_version_ciphertext(&id, version.version)?;
                versions.push(StoreSecurityVersion {
                    meta: VersionMetaFile {
                        version: version.version,
                        size: version.size,
                        created: version.created,
                        note: version.note,
                        mutation_id: version.mutation_id,
                    },
                    ciphertext_sha256: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(Sha256::digest(ciphertext)),
                });
            }
            entries.push(StoreSecurityEntry { meta, versions });
        }
        Ok(StoreSecuritySnapshot { entries })
    }

    fn verify_security_state(&self) -> StoreResult<()> {
        let Some(integrity) = &self.integrity else { return Ok(()) };
        let loaded = integrity
            .authenticator
            .load::<StoreSecuritySnapshot>(&integrity.sidecar, INTEGRITY_DOMAIN)?;
        let authenticated = loaded.value.ok_or_else(|| StoreError::Corrupt {
            id: "store".to_string(),
            reason: "authenticated store snapshot is missing".to_string(),
        })?;
        if authenticated != self.security_snapshot()? {
            return Err(StoreError::Corrupt {
                id: "store".to_string(),
                reason: "store contents changed outside the authenticated daemon transaction boundary"
                    .to_string(),
            });
        }
        *integrity
            .generation
            .lock()
            .expect("store integrity generation poisoned") = loaded.generation;
        Ok(())
    }

    fn seal_security_state(&self) -> StoreResult<()> {
        let Some(integrity) = &self.integrity else { return Ok(()) };
        let snapshot = self.security_snapshot()?;
        let mut generation = integrity
            .generation
            .lock()
            .expect("store integrity generation poisoned");
        *generation = integrity.authenticator.persist(
            &integrity.sidecar,
            INTEGRITY_DOMAIN,
            *generation,
            &snapshot,
        )?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create version 1 at a caller-selected stable Secret id and bind it to a durable mutation.
    /// Retrying the same mutation is idempotent; reusing the id for different bytes is rejected.
    pub fn put_identified(
        &self,
        id: SecretId,
        meta: NewSecret,
        plaintext: &[u8],
        mutation_id: &str,
    ) -> StoreResult<SecretId> {
        validate_mutation_id(mutation_id)?;
        self.put_internal(id, meta, plaintext, Some(mutation_id.to_string()))
    }

    /// Append one immutable version associated with a durable cross-backend mutation.
    /// A retry returns the original version and never creates a second version.
    pub fn append_version_identified(
        &self,
        id: &SecretId,
        plaintext: &[u8],
        mutation_id: &str,
    ) -> StoreResult<u32> {
        validate_mutation_id(mutation_id)?;
        self.append_version_internal(id, plaintext, Some(mutation_id.to_string()))
    }

    /// Find the immutable version produced by a durable mutation without reading mutable head.
    pub fn version_for_mutation(
        &self,
        id: &SecretId,
        mutation_id: &str,
    ) -> StoreResult<Option<u32>> {
        validate_mutation_id(mutation_id)?;
        self.verify_security_state()?;
        Ok(self
            .history_unverified(id)?
            .into_iter()
            .find(|version| version.mutation_id.as_deref() == Some(mutation_id))
            .map(|version| version.version))
    }

    fn put_internal(
        &self,
        id: SecretId,
        meta: NewSecret,
        plaintext: &[u8],
        mutation_id: Option<String>,
    ) -> StoreResult<SecretId> {
        let mode = meta.mode;
        let enforcement = meta.enforcement;
        let (source_path, managed_label) = validate_new_secret_origin(meta.origin)?;
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        if self.entry_dir(&id).exists() {
            if let Some(expected) = mutation_id.as_deref() {
                if let Some(version) = self
                    .history_unverified(&id)?
                    .into_iter()
                    .find(|version| version.mutation_id.as_deref() == Some(expected))
                {
                    let existing = self.get_version(&id, version.version)?;
                    if existing.as_slice() != plaintext {
                        return Err(StoreError::Invalid(format!(
                            "mutation {expected} was already used for different secret bytes"
                        )));
                    }
                    return Ok(id);
                }
            }
            return Err(StoreError::Invalid(format!(
                "secret id {id} already exists for a different mutation"
            )));
        }
        let vdir = self.versions_dir(&id);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&vdir)
            .map_err(|error| StoreError::io(&vdir, error))?;
        self.write_version(&id, 1, plaintext, None, mutation_id)?;
        self.write_meta(
            &id,
            &MetaFile {
                format: STORE_FORMAT_VERSION,
                id: id.to_string(),
                source_path,
                managed_label,
                mode,
                created: now_rfc3339(),
                current_version: 1,
                enforcement,
                environment_ids: None,
                metadata: ItemMetadata::default(),
            },
        )?;
        self.seal_security_state()?;
        Ok(id)
    }

    fn append_version_internal(
        &self,
        id: &SecretId,
        plaintext: &[u8],
        mutation_id: Option<String>,
    ) -> StoreResult<u32> {
        // The immutable version is published before the mutable head. A retry carrying a stable
        // mutation id finds that exact version and completes only the missing head transition.
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let mut meta = self.read_meta(id)?;
        if let Some(expected) = mutation_id.as_deref() {
            if let Some(version) = self
                .history_unverified(id)?
                .into_iter()
                .find(|version| version.mutation_id.as_deref() == Some(expected))
            {
                let existing = self.get_version(id, version.version)?;
                if existing.as_slice() != plaintext {
                    return Err(StoreError::Invalid(format!(
                        "mutation {expected} was already used for different secret bytes"
                    )));
                }
                if meta.current_version != version.version {
                    meta.current_version = version.version;
                    self.write_meta(id, &meta)?;
                    self.seal_security_state()?;
                }
                return Ok(version.version);
            }
        }
        let next = self
            .max_version(id)?
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid(format!("secret {id} version overflow")))?;
        self.write_version(id, next, plaintext, None, mutation_id)?;
        meta.current_version = next;
        self.write_meta(id, &meta)?;
        self.seal_security_state()?;
        Ok(next)
    }

    /// Copy one immutable, internally consistent encrypted-store snapshot.
    ///
    /// Store mutations take the same exclusive lock. The destination must not exist and no
    /// plaintext or key material is written there.
    pub fn backup_to(&self, destination: &Path) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        copy_store_directory(&self.root, destination)
    }

    /// Verify every version in this store by decrypting it and comparing its declared size.
    pub fn verify_all(&self) -> StoreResult<StoreVerification> {
        let records = self.list()?;
        let mut versions = 0usize;
        let mut plaintext_bytes = 0u64;
        for record in &records {
            let history = self.history(&record.id)?;
            if history.is_empty()
                || !history.iter().any(|version| version.version == record.current_version)
            {
                return Err(StoreError::Corrupt {
                    id: record.id.to_string(),
                    reason: format!(
                        "head version {} is missing from version history",
                        record.current_version
                    ),
                });
            }
            for version in history {
                let plaintext = self.get_version(&record.id, version.version)?;
                if plaintext.len() as u64 != version.size {
                    return Err(StoreError::Corrupt {
                        id: record.id.to_string(),
                        reason: format!(
                            "v{} declares {} bytes but decrypts to {}",
                            version.version,
                            version.size,
                            plaintext.len()
                        ),
                    });
                }
                versions += 1;
                plaintext_bytes = plaintext_bytes.saturating_add(version.size);
            }
        }
        Ok(StoreVerification {
            secrets: records.len(),
            versions,
            plaintext_bytes,
            secret_ids: records.iter().map(|record| record.id.to_string()).collect(),
        })
    }

    /// Verify a copied store with the same key provider as this live store.
    pub fn verify_backup(&self, root: &Path) -> StoreResult<StoreVerification> {
        if !root.is_dir() {
            return Err(StoreError::Invalid(format!(
                "backup store directory does not exist: {}",
                root.display()
            )));
        }
        AgeDirStore {
            root: root.to_path_buf(),
            keys: Arc::clone(&self.keys),
            integrity: None,
        }
        .verify_all()
    }

    pub fn lock_for_maintenance(&self) -> StoreResult<StoreMaintenanceGuard> {
        let lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        Ok(StoreMaintenanceGuard {
            _lock: lock,
            root: self.root.clone(),
        })
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
        if meta.id != id.as_str() {
            return Err(StoreError::Corrupt {
                id: id.to_string(),
                reason: format!("meta.toml id {:?} does not match its directory", meta.id),
            });
        }
        if !(MIN_SUPPORTED_STORE_FORMAT_VERSION..=STORE_FORMAT_VERSION).contains(&meta.format) {
            return Err(StoreError::Corrupt {
                id: id.to_string(),
                reason: format!(
                    "store format {} but this build supports 1 through {}; migrate or delete the entry",
                    meta.format, STORE_FORMAT_VERSION
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

    fn history_unverified(&self, id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
        self.read_meta(id)?;
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
                        mutation_id: vm.mutation_id,
                    });
                }
            }
        }
        out.sort_by_key(|record| record.version);
        Ok(out)
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
        mutation_id: Option<String>,
    ) -> StoreResult<()> {
        let bound = encode_bound_payload(id, version, plaintext)?;
        let ciphertext = self.encrypt(&bound)?;
        write_private(&self.version_blob(id, version), &ciphertext)?;
        let vmeta = VersionMetaFile {
            version,
            size: plaintext.len() as u64,
            created: now_rfc3339(),
            note,
            mutation_id,
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

    fn decrypt_version_with_identity(
        &self,
        id: &SecretId,
        version: u32,
        identity: &dyn age::Identity,
    ) -> StoreResult<Zeroizing<Vec<u8>>> {
        let ciphertext = self.read_version_ciphertext(id, version)?;
        let decrypted = self.decrypt_with_identity(&ciphertext, identity)?;
        decode_bound_payload(id, version, decrypted)
    }

    fn migrate_context_binding(&self) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(StoreError::io(&self.root, error)),
        };
        let mut identity: Option<Box<dyn age::Identity>> = None;
        for entry in entries {
            let entry = entry.map_err(|error| StoreError::io(&self.root, error))?;
            if !entry.path().is_dir() {
                continue;
            }
            let Ok(id) = entry.file_name().to_string_lossy().parse::<SecretId>() else {
                continue;
            };
            let mut meta = self.read_meta(&id)?;
            if meta.format >= 3 {
                continue;
            }
            if identity.is_none() {
                identity = Some(self.keys.identity()?);
            }
            let identity = identity.as_ref().expect("initialized above");
            for version in self.history(&id)? {
                let ciphertext = self.read_version_ciphertext(&id, version.version)?;
                let decrypted = self.decrypt_with_identity(&ciphertext, identity.as_ref())?;
                if payload_is_bound(&id, version.version, &decrypted)? {
                    continue;
                }
                let bound = encode_bound_payload(&id, version.version, &decrypted)?;
                let ciphertext = self.encrypt(&bound)?;
                write_private(&self.version_blob(&id, version.version), &ciphertext)?;
            }
            meta.format = STORE_FORMAT_VERSION;
            self.write_meta(&id, &meta)?;
        }
        Ok(())
    }
}

fn encode_bound_payload(
    id: &SecretId,
    version: u32,
    plaintext: &[u8],
) -> StoreResult<Zeroizing<Vec<u8>>> {
    let id_bytes = id.as_str().as_bytes();
    let id_len = u16::try_from(id_bytes.len())
        .map_err(|_| StoreError::Invalid("secret id is too long".to_string()))?;
    let mut bound = Zeroizing::new(Vec::with_capacity(
        PAYLOAD_MAGIC.len() + 2 + id_bytes.len() + 4 + plaintext.len(),
    ));
    bound.extend_from_slice(PAYLOAD_MAGIC);
    bound.extend_from_slice(&id_len.to_be_bytes());
    bound.extend_from_slice(id_bytes);
    bound.extend_from_slice(&version.to_be_bytes());
    bound.extend_from_slice(plaintext);
    Ok(bound)
}

fn payload_is_bound(id: &SecretId, version: u32, payload: &[u8]) -> StoreResult<bool> {
    if !payload.starts_with(PAYLOAD_MAGIC) {
        return Ok(false);
    }
    decode_bound_payload(id, version, Zeroizing::new(payload.to_vec())).map(|_| true)
}

fn decode_bound_payload(
    expected_id: &SecretId,
    expected_version: u32,
    payload: Zeroizing<Vec<u8>>,
) -> StoreResult<Zeroizing<Vec<u8>>> {
    if !payload.starts_with(PAYLOAD_MAGIC) {
        return Err(StoreError::Corrupt {
            id: expected_id.to_string(),
            reason: format!("v/{expected_version:04}.age has no authenticated context binding"),
        });
    }
    let mut cursor = PAYLOAD_MAGIC.len();
    let id_len_bytes: [u8; 2] = payload
        .get(cursor..cursor + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| StoreError::Corrupt {
            id: expected_id.to_string(),
            reason: format!("v/{expected_version:04}.age has a truncated context header"),
        })?;
    cursor += 2;
    let id_len = u16::from_be_bytes(id_len_bytes) as usize;
    let actual_id = payload.get(cursor..cursor + id_len).ok_or_else(|| StoreError::Corrupt {
        id: expected_id.to_string(),
        reason: format!("v/{expected_version:04}.age has a truncated secret id"),
    })?;
    cursor += id_len;
    let version_bytes: [u8; 4] = payload
        .get(cursor..cursor + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| StoreError::Corrupt {
            id: expected_id.to_string(),
            reason: format!("v/{expected_version:04}.age has a truncated version"),
        })?;
    cursor += 4;
    let actual_version = u32::from_be_bytes(version_bytes);
    if actual_id != expected_id.as_str().as_bytes() || actual_version != expected_version {
        return Err(StoreError::Corrupt {
            id: expected_id.to_string(),
            reason: format!(
                "v/{expected_version:04}.age belongs to {}@v{actual_version}",
                String::from_utf8_lossy(actual_id)
            ),
        });
    }
    Ok(Zeroizing::new(payload[cursor..].to_vec()))
}

fn copy_store_directory(source: &Path, destination: &Path) -> StoreResult<()> {
    if destination.exists() {
        return Err(StoreError::Invalid(format!(
            "backup store destination already exists: {}",
            destination.display()
        )));
    }
    std::fs::DirBuilder::new()
        .recursive(false)
        .mode(0o700)
        .create(destination)
        .map_err(|source| StoreError::io(destination, source))?;
    copy_store_contents(source, destination)
}

fn copy_store_contents(source: &Path, destination: &Path) -> StoreResult<()> {
    let entries = std::fs::read_dir(source).map_err(|error| StoreError::io(source, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| StoreError::io(source, error))?;
        if entry.file_name() == ".lock" {
            continue;
        }
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata =
            std::fs::symlink_metadata(&from).map_err(|error| StoreError::io(&from, error))?;
        if metadata.is_dir() {
            std::fs::DirBuilder::new()
                .recursive(false)
                .mode(0o700)
                .create(&to)
                .map_err(|error| StoreError::io(&to, error))?;
            copy_store_contents(&from, &to)?;
        } else if metadata.is_file() {
            std::fs::copy(&from, &to).map_err(|error| StoreError::io(&to, error))?;
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| StoreError::io(&to, error))?;
        } else {
            return Err(StoreError::Invalid(format!(
                "store contains unsupported filesystem entry: {}",
                from.display()
            )));
        }
    }
    Ok(())
}

impl SecretStore for AgeDirStore {
    fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId> {
        self.put_internal(SecretId::generate(), meta, plaintext, None)
    }

    fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
        self.verify_security_state()?;
        let head = self.read_meta(id)?.current_version;
        self.get_version(id, head)
    }

    fn get_many(&self, ids: &[SecretId]) -> StoreResult<Vec<Zeroizing<Vec<u8>>>> {
        self.verify_security_state()?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let identity = self.keys.identity()?;
        ids.iter()
            .map(|id| {
                let head = self.read_meta(id)?.current_version;
                self.decrypt_version_with_identity(id, head, identity.as_ref())
            })
            .collect()
    }

    fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
        self.verify_security_state()?;
        self.read_meta(id)?;
        let identity = self.keys.identity()?;
        self.decrypt_version_with_identity(id, version, identity.as_ref())
    }

    fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
        self.append_version_internal(id, plaintext, None)
    }

    fn history(&self, id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
        self.verify_security_state()?;
        self.history_unverified(id)
    }

    fn set_head(&self, id: &SecretId, version: u32) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let mut meta = self.read_meta(id)?;
        if !self.version_blob(id, version).exists() {
            return Err(StoreError::NotFound(format!("{id}@v{version}")));
        }
        meta.current_version = version;
        self.write_meta(id, &meta)?;
        self.seal_security_state()
    }

    fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
        self.verify_security_state()?;
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
        self.verify_security_state()?;
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
        self.verify_security_state()?;
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
        self.verify_security_state()?;
        let mut meta = self.read_meta(id)?;
        meta.metadata = metadata;
        meta.enforcement = enforcement;
        meta.environment_ids = environment_ids;
        self.write_meta(id, &meta)?;
        self.seal_security_state()
    }

    fn delete(&self, id: &SecretId) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let dir = self.entry_dir(id);
        std::fs::remove_dir_all(&dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(id.to_string())
            } else {
                StoreError::io(&dir, e)
            }
        })?;
        self.seal_security_state()
    }
}

/// Current time as a second-precision RFC 3339 string (UTC).
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn validate_mutation_id(mutation_id: &str) -> StoreResult<()> {
    uuid::Uuid::parse_str(mutation_id)
        .map(|_| ())
        .map_err(|_| StoreError::Invalid(format!("invalid mutation id {mutation_id:?}")))
}

fn validate_new_secret_origin(
    origin: SecretOrigin,
) -> StoreResult<(Option<String>, Option<String>)> {
    match origin {
        SecretOrigin::File { source_path } if source_path.is_absolute() => {
            Ok((Some(source_path.to_string_lossy().into_owned()), None))
        }
        SecretOrigin::File { source_path } => Err(StoreError::Invalid(format!(
            "file secret source path must be absolute: {}",
            source_path.display()
        ))),
        SecretOrigin::Managed { label } if !label.trim().is_empty() => Ok((None, Some(label))),
        SecretOrigin::Managed { .. } => {
            Err(StoreError::Invalid("managed secret label cannot be empty".to_string()))
        }
    }
}

/// Write a file with mode 0600, atomically: write+fsync a `.tmp` sibling, then rename over the
/// target. A crash mid-write leaves the old content intact (this guards the head pointer in
/// `meta.toml`). Concurrent writers are serialized by the store lock, so the fixed temp name is safe.
fn write_private(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let tmp = {
        let mut os = path.as_os_str().to_owned();
        os.push(format!(
            ".tmp.{}.{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        PathBuf::from(os)
    };
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| StoreError::io(&tmp, e))?;
    f.write_all(bytes).map_err(|e| StoreError::io(&tmp, e))?;
    f.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
    std::fs::rename(&tmp, path).map_err(|e| StoreError::io(path, e))?;
    let parent = path.parent().ok_or_else(|| {
        StoreError::Invalid(format!("private state path has no parent: {}", path.display()))
    })?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| StoreError::io(parent, e))
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
    fn identified_put_is_idempotent_at_a_caller_selected_secret_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store(tmp.path().to_path_buf());
        let id: SecretId = "11111111-1111-4111-8111-111111111111".parse().unwrap();
        let mutation_id = "22222222-2222-4222-8222-222222222222";
        let value = b"fixture payload, not a credential";

        let first = store
            .put_identified(
                id.clone(),
                NewSecret::managed("replicated fixture"),
                value,
                mutation_id,
            )
            .unwrap();
        let retry = store
            .put_identified(
                id.clone(),
                NewSecret::managed("replicated fixture"),
                value,
                mutation_id,
            )
            .unwrap();

        assert_eq!(first, id);
        assert_eq!(retry, id);
        assert_eq!(store.version_for_mutation(&id, mutation_id).unwrap(), Some(1));
        assert_eq!(store.history(&id).unwrap().len(), 1);
        assert!(store
            .put_identified(
                id,
                NewSecret::managed("replicated fixture"),
                b"different fixture bytes",
                mutation_id,
            )
            .unwrap_err()
            .to_string()
            .contains("different secret bytes"));
    }

    #[test]
    fn identified_append_reuses_the_original_immutable_version() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store(tmp.path().to_path_buf());
        let id = store
            .put(NewSecret::managed("replicated fixture"), b"version one")
            .unwrap();
        let mutation_id = "33333333-3333-4333-8333-333333333333";

        let first = store
            .append_version_identified(&id, b"version two", mutation_id)
            .unwrap();
        let retry = store
            .append_version_identified(&id, b"version two", mutation_id)
            .unwrap();

        assert_eq!(first, 2);
        assert_eq!(retry, 2);
        assert_eq!(store.version_for_mutation(&id, mutation_id).unwrap(), Some(2));
        assert_eq!(store.history(&id).unwrap().len(), 2);
        assert!(store
            .append_version_identified(&id, b"different version two", mutation_id)
            .unwrap_err()
            .to_string()
            .contains("different secret bytes"));
    }

    #[test]
    fn ciphertext_and_metadata_cannot_be_transplanted_between_secret_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let first = s
            .put(NewSecret::file(PathBuf::from("/x/first"), 0o600), b"first")
            .unwrap();
        let second = s
            .put(NewSecret::file(PathBuf::from("/x/second"), 0o600), b"second")
            .unwrap();

        std::fs::copy(s.version_blob(&first, 1), s.version_blob(&second, 1)).unwrap();
        assert!(matches!(s.get(&second), Err(StoreError::Corrupt { .. })));

        let first_meta = std::fs::read(s.entry_dir(&first).join("meta.toml")).unwrap();
        std::fs::write(s.entry_dir(&second).join("meta.toml"), first_meta).unwrap();
        assert!(matches!(s.record(&second), Err(StoreError::Corrupt { .. })));
    }

    #[test]
    fn authenticated_store_rejects_external_tampering_and_signed_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let keys: Arc<dyn KeyProvider> =
            Arc::new(X25519Keys(age::x25519::Identity::generate()));
        let auth = Arc::new(StateAuthenticator::for_tests([31; 32]));
        let store = AgeDirStore::open(tmp.path().to_path_buf(), Arc::clone(&keys))
            .unwrap()
            .authenticate(Arc::clone(&auth))
            .unwrap();
        let id = store
            .put(NewSecret::managed("authenticated fixture"), b"version-one")
            .unwrap();
        let old_sidecar = std::fs::read(tmp.path().join(".integrity.json")).unwrap();

        let meta_path = tmp.path().join(id.as_str()).join("meta.toml");
        let original_meta = std::fs::read(&meta_path).unwrap();
        std::fs::write(&meta_path, b"externally modified").unwrap();
        assert!(store.get(&id).is_err());

        std::fs::write(&meta_path, original_meta).unwrap();
        store.append_version(&id, b"version-two").unwrap();
        std::fs::write(tmp.path().join(".integrity.json"), old_sidecar).unwrap();
        assert!(store.get(&id).is_err());
    }

    #[test]
    fn authenticated_store_does_not_silently_adopt_existing_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let keys: Arc<dyn KeyProvider> =
            Arc::new(X25519Keys(age::x25519::Identity::generate()));
        let store = AgeDirStore::open(tmp.path().to_path_buf(), Arc::clone(&keys)).unwrap();
        store
            .put(NewSecret::managed("legacy fixture"), b"legacy-secret")
            .unwrap();
        drop(store);

        let error = match AgeDirStore::open(tmp.path().to_path_buf(), keys)
            .unwrap()
            .authenticate(Arc::new(StateAuthenticator::for_tests([32; 32])))
        {
            Ok(_) => panic!("existing unauthenticated store was adopted"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("refusing to trust"));
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
    fn new_secret_persists_its_initial_enforcement() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s
            .put(
                NewSecret::file(PathBuf::from("/fixture/.envrc"), 0o600)
                    .with_enforcement(Enforcement::Allow),
                b"export FIXTURE=1\n",
            )
            .unwrap();

        assert_eq!(s.record(&id).unwrap().unwrap().enforcement, Enforcement::Allow);
    }

    #[test]
    fn metadata_roundtrips_without_creating_a_content_version() {
        use floria_core::metadata::ItemLink;

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
        std::fs::write(&meta_path, text.replace("format = 3", "format = 99")).unwrap();

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
        std::fs::write(&meta_path, text.replace("format = 3", "format = 1")).unwrap();

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
