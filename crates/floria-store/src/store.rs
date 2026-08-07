//! `SecretStore`: keep a secret blob confidential at rest, addressed by a stable id.
//!
//! Format 5 — the store IS the vault ("一份字节"): the data root splits into a **shared half**
//! (`shared/` — content-addressed immutable version objects, signed vault/device/generation
//! documents; the exact directory a sync tool moves) and a **local half** (`local/` — mutable
//! head documents, the lock, the integrity sidecar; never synced). There is no export, no
//! import copy, and no second key location: the software never synchronizes with itself.
//!
//! A machine that never enables sync is simply a single-device vault; the shared half then
//! lives at `<root>/shared`. Enabling sync relocates the shared half to a user-chosen synced
//! location (recorded in the `shared-location` pointer) — a move, not a copy.
//!
//! Plaintext exists only as [`Zeroizing`] in memory and never touches disk here.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use age::secrecy::ExposeSecret;
use age::x25519;

use floria_core::authz::Enforcement;
use floria_core::metadata::ItemMetadata;
use floria_integrity::StateAuthenticator;

use crate::device::{DeviceKeyMaterial, DeviceKeyStore};
use crate::error::{StoreError, StoreResult};
use crate::generations::GenerationAccess;
use crate::keys::KeyProvider;
use crate::vault::{
    self, ensure_private_directory, publish_immutable, read_untrusted_file, write_key_generation,
    write_new_atomic, write_replace_atomic, SharedLayout, VaultDocument,
};

/// Current on-disk layout. Format 5 stores version objects directly in the shared half and
/// keeps only mutable head documents locally. Older formats are rejected with a
/// migrate-or-delete error; migration is a manual, one-time step during development.
pub const STORE_FORMAT_VERSION: u32 = 5;
pub const MIN_SUPPORTED_STORE_FORMAT_VERSION: u32 = 5;

const PAYLOAD_MAGIC: &[u8; 8] = b"FLORIA\0\x05";
const INTEGRITY_DOMAIN: &str = "encrypted-store-security-state";
const SHARED_LOCATION_FILE: &str = "shared-location";

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
    pub mutation_id: Option<String>,
}

/// Lightweight reference to one immutable version (no ciphertext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreVersionRef {
    pub ordinal: u32,
    pub version_uuid: String,
    pub generation: u32,
    /// Plaintext size as declared by the head document.
    pub size: u64,
    /// On-disk ciphertext size of the object.
    pub ciphertext_size: u64,
    pub digest: String,
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
    /// Delete a secret. On a solo vault this destroys the objects too; once other devices are
    /// enrolled it only removes the local head document (shared objects stay immutable).
    fn delete(&self, id: &SecretId) -> StoreResult<()>;
}

/// On-disk `local/heads/<id>.toml`: entry metadata, the ordered version table, and the head
/// pointer. The single mutable document per secret; everything it references is immutable.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeadsDocument {
    /// See [`STORE_FORMAT_VERSION`]. `default` so a pre-format entry reads as 0 and fails.
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
    versions: Vec<HeadsVersion>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeadsVersion {
    version: u32,
    version_uuid: String,
    generation: u32,
    size: u64,
    digest: String,
    created: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mutation_id: Option<String>,
}

fn default_secret_enforcement() -> Enforcement {
    Enforcement::Prompt
}

#[derive(Clone)]
struct StoreIntegrity {
    authenticator: Arc<StateAuthenticator>,
    sidecar: PathBuf,
    generation: Arc<Mutex<u64>>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoreSecuritySnapshot {
    entries: Vec<HeadsDocument>,
}

/// The mutable shared-half binding: swapped atomically when sync is enabled (relocate) or an
/// existing vault is adopted.
struct SharedState {
    layout: SharedLayout,
    vault: VaultDocument,
}

/// Holds the store's cross-process mutation lock for a maintenance operation.
pub struct StoreMaintenanceGuard {
    _lock: std::fs::File,
    shared_root: PathBuf,
    local_root: PathBuf,
    device_key_path: PathBuf,
}

impl StoreMaintenanceGuard {
    /// Copy the locked store (both halves + the device key file) without re-locking.
    pub fn backup_to(&self, destination: &Path) -> StoreResult<()> {
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
        copy_directory(&self.shared_root, &destination.join("shared"))?;
        copy_directory(&self.local_root, &destination.join("local"))?;
        if self.device_key_path.is_file() {
            let bytes = std::fs::read(&self.device_key_path)
                .map_err(|source| StoreError::io(&self.device_key_path, source))?;
            let target = destination.join("device.age");
            std::fs::write(&target, bytes).map_err(|source| StoreError::io(&target, source))?;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                .map_err(|source| StoreError::io(&target, source))?;
        }
        Ok(())
    }
}

/// Portable age-encrypted store over a shared/local split data root.
pub struct AgeDirStore {
    root: PathBuf,
    keys: Arc<dyn KeyProvider>,
    device: RwLock<Arc<DeviceKeyMaterial>>,
    state: RwLock<SharedState>,
    generations: GenerationAccess,
    integrity: Option<StoreIntegrity>,
}

impl AgeDirStore {
    /// Open the data root (creating it, mode 0700, if needed). A root without a vault becomes
    /// a single-device vault: device identity, genesis vault.json, and generation 1 are created
    /// on first open.
    pub fn open(root: PathBuf, keys: Arc<dyn KeyProvider>) -> StoreResult<Self> {
        ensure_private_directory(&root)?;
        let local = root.join("local");
        ensure_private_directory(&local.join("heads"))?;
        let device = Arc::new(
            DeviceKeyStore::new(root.join("device.age"), Arc::clone(&keys)).load_or_create()?,
        );

        let (layout, pointer_present) = match read_shared_location(&root)? {
            Some(target) => (SharedLayout::new(target), true),
            None => (SharedLayout::new(root.join("shared")), false),
        };
        let vault = match vault::read_vault(&layout) {
            Ok(vault) => vault,
            Err(StoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound && !pointer_present =>
            {
                genesis_initialize(&layout, &device, &local.join("recovery.age"))?
            }
            Err(StoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Err(StoreError::Invalid(format!(
                    "shared-location points at {} but there is no vault there",
                    layout.root().display()
                )));
            }
            Err(error) => return Err(error),
        };
        ensure_private_directory(&layout.envelopes_dir(device.device_id()))?;
        ensure_private_directory(&layout.device_operations_dir(device.device_id()))?;
        ensure_private_directory(&layout.device_checkpoints_dir(device.device_id()))?;

        Ok(AgeDirStore {
            root,
            keys,
            device: RwLock::new(device),
            state: RwLock::new(SharedState { layout, vault }),
            generations: GenerationAccess::new(),
            integrity: None,
        })
    }

    pub fn open_authenticated(
        root: PathBuf,
        keys: Arc<dyn KeyProvider>,
        authenticator: Arc<StateAuthenticator>,
    ) -> StoreResult<Self> {
        Self::open(root, keys)?.authenticate(authenticator)
    }

    pub fn authenticate(mut self, authenticator: Arc<StateAuthenticator>) -> StoreResult<Self> {
        let sidecar = self.root.join("local/.integrity.json");
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
    /// The restored directory has no integrity sidecar yet, so verification runs on an
    /// unauthenticated twin before the fresh snapshot is persisted.
    pub fn authenticate_restored_state(
        &self,
        authenticator: Arc<StateAuthenticator>,
    ) -> StoreResult<()> {
        let restored = AgeDirStore::open(self.root.clone(), Arc::clone(&self.keys))?;
        restored.verify_all()?;
        let snapshot = restored.security_snapshot()?;
        let sidecar = self.root.join("local/.integrity.json");
        let generation = authenticator.checkpoint_generation(INTEGRITY_DOMAIN)?;
        let next = authenticator.persist(&sidecar, INTEGRITY_DOMAIN, generation, &snapshot)?;
        if let Some(integrity) = &self.integrity {
            *integrity
                .generation
                .lock()
                .expect("store integrity generation poisoned") = next;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The shared half's current location (the directory a sync tool moves).
    pub fn shared_root(&self) -> PathBuf {
        self.state.read().expect("shared state poisoned").layout.root().to_path_buf()
    }

    pub fn shared_layout(&self) -> SharedLayout {
        self.state.read().expect("shared state poisoned").layout.clone()
    }

    pub fn vault_document(&self) -> VaultDocument {
        self.state.read().expect("shared state poisoned").vault.clone()
    }

    pub fn device(&self) -> Arc<DeviceKeyMaterial> {
        Arc::clone(&self.device.read().expect("device identity poisoned"))
    }

    pub fn device_key_provider(&self) -> Arc<dyn KeyProvider> {
        Arc::clone(&self.keys)
    }

    /// Encryption recipients for new payloads (current generation + recovery), straight from
    /// the signed generation document — no private key involved.
    pub fn generation_recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
        let state = self.state.read().expect("shared state poisoned");
        self.generations.recipients(&state.layout, &state.vault)
    }

    /// The exact signed generation and recipients used for one new encrypted record.
    pub fn current_generation_recipients(
        &self,
    ) -> StoreResult<(u32, Vec<Box<dyn age::Recipient + Send>>)> {
        let state = self.state.read().expect("shared state poisoned");
        self.generations
            .current_recipients(&state.layout, &state.vault)
    }

    /// Replace a revoked device identity with a fresh keypair and id. Callers must only expose
    /// this after a signed Vault generation identifies the current identity as revoked.
    ///
    /// The local library must stay readable while the new identity waits for approval, so every
    /// generation the OLD identity could unwrap is re-wrapped to the new one first. This grants
    /// no new capability — the machine already held these plaintexts, and a removed device's
    /// historical access is explicitly non-revocable (see portable-replication.md).
    pub fn rotate_device_identity(&self) -> StoreResult<Arc<DeviceKeyMaterial>> {
        let _lock = self.lock_exclusive()?;
        let state = self.state.read().expect("shared state poisoned");
        let old_device = self.device();
        let current = self.generations.current(&state.layout, &state.vault)?;
        let mut reachable = Vec::new();
        for generation in 1..=current {
            if let Ok(identity) =
                self.generations
                    .identity(&state.layout, &state.vault, &old_device, generation)
            {
                reachable.push((generation, identity));
            }
        }
        let rotated = Arc::new(
            DeviceKeyStore::new(self.root.join("device.age"), Arc::clone(&self.keys)).rotate()?,
        );
        ensure_private_directory(&state.layout.envelopes_dir(rotated.device_id()))?;
        ensure_private_directory(&state.layout.device_operations_dir(rotated.device_id()))?;
        ensure_private_directory(&state.layout.device_checkpoints_dir(rotated.device_id()))?;
        for (generation, identity) in reachable {
            let envelope = vault::encrypt_to_recipient(
                &rotated.wrapping_identity().to_public(),
                identity.to_string().expose_secret().as_bytes(),
            )?;
            write_new_atomic(
                &state.layout.envelope(rotated.device_id(), generation),
                &envelope,
            )?;
        }
        drop(state);
        *self.device.write().expect("device identity poisoned") = Arc::clone(&rotated);
        // The old identity's cached unwraps are stale for cache-keying purposes.
        self.generations.clear_identity_cache();
        Ok(rotated)
    }

    /// Move the shared half to a user-chosen (synced) location and record the pointer.
    /// This is enabling sync: a move of the authoritative bytes, never a copy.
    pub fn relocate_shared(&self, target: &Path) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        if target.exists() {
            return Err(StoreError::Invalid(format!(
                "sync location already exists: {}",
                target.display()
            )));
        }
        let mut state = self.state.write().expect("shared state poisoned");
        let source = state.layout.root().to_path_buf();
        if let Some(parent) = target.parent() {
            ensure_private_directory(parent)?;
        }
        std::fs::rename(&source, target).map_err(|source_error| {
            StoreError::io(&source, source_error)
        })?;
        write_new_atomic(
            &self.root.join(SHARED_LOCATION_FILE),
            target.to_string_lossy().as_bytes(),
        )?;
        state.layout = SharedLayout::new(target);
        Ok(())
    }

    /// Point this store at an existing vault (joining as a new device). Legal only while this
    /// store's own vault is unused (no secrets): the local genesis is discarded.
    pub fn adopt_shared_location(&self, target: &Path) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        if !self.heads_ids()?.is_empty() {
            return Err(StoreError::Invalid(
                "cannot join another vault: this store already holds secrets".to_string(),
            ));
        }
        let layout = SharedLayout::new(target);
        let vault = vault::read_vault(&layout)?;
        let mut state = self.state.write().expect("shared state poisoned");
        let old_default = self.root.join("shared");
        write_new_atomic(
            &self.root.join(SHARED_LOCATION_FILE),
            target.to_string_lossy().as_bytes(),
        )?;
        let device = self.device();
        ensure_private_directory(&layout.envelopes_dir(device.device_id()))?;
        ensure_private_directory(&layout.device_operations_dir(device.device_id()))?;
        ensure_private_directory(&layout.device_checkpoints_dir(device.device_id()))?;
        state.layout = layout;
        state.vault = vault;
        self.generations.refresh(&state.layout, &state.vault).ok();
        if old_default.exists() {
            let _ = std::fs::remove_dir_all(&old_default);
        }
        Ok(())
    }

    /// Activate an already materialized and authenticated Vault while preserving the previous
    /// shared half for rollback. This Store must have no local heads: merging a populated Store
    /// into another Vault is a separate copy-and-verify transaction.
    ///
    /// The target is treated as untrusted even when its transport already authenticated the
    /// documents. Before changing the durable pointer this method revalidates the Vault,
    /// requires an identity matching this installation's private Device keys, and unwraps every
    /// reachable generation. No fallible work remains after the pointer is replaced.
    pub fn activate_shared_location(
        &self,
        target: &Path,
        expected_vault_id: &str,
    ) -> StoreResult<PathBuf> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        if !self.heads_ids()?.is_empty() {
            return Err(StoreError::Invalid(
                "cannot activate another Vault: this Store already holds secrets".to_string(),
            ));
        }

        let target = std::fs::canonicalize(target)
            .map_err(|source| StoreError::io(target, source))?;
        let layout = SharedLayout::new(&target);
        let vault = vault::read_vault(&layout)?;
        if vault.vault_id != expected_vault_id {
            return Err(StoreError::Invalid(format!(
                "staged Vault {} does not match selected Vault {expected_vault_id}",
                vault.vault_id
            )));
        }
        self.verify_device_access(&layout, &vault)?;

        let device = self.device();
        ensure_private_directory(&layout.envelopes_dir(device.device_id()))?;
        ensure_private_directory(&layout.device_operations_dir(device.device_id()))?;
        ensure_private_directory(&layout.device_checkpoints_dir(device.device_id()))?;

        let previous = self.shared_root();
        if previous == target {
            self.generations.reset();
            return Ok(previous);
        }
        replace_or_create_regular_file(
            &self.root.join(SHARED_LOCATION_FILE),
            target.to_string_lossy().as_bytes(),
        )?;

        let mut state = self.state.write().expect("shared state poisoned");
        state.layout = layout;
        state.vault = vault;
        self.generations.reset();
        Ok(previous)
    }

    /// Reload lifecycle documents added to the active Vault. Immutable writers publish external
    /// envelopes before generation documents, so a newly visible generation is complete. The
    /// Store nevertheless revalidates the full chain and unwraps every generation before making
    /// the refreshed cache observable.
    pub fn refresh_shared_lifecycle(&self, expected_vault_id: &str) -> StoreResult<u32> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let layout = self.shared_layout();
        let vault = vault::read_vault(&layout)?;
        if vault.vault_id != expected_vault_id {
            return Err(StoreError::Invalid(format!(
                "active Vault {} does not match selected Vault {expected_vault_id}",
                vault.vault_id
            )));
        }
        let generation = self.verify_device_access(&layout, &vault)?;
        self.generations.reset();
        self.generations.refresh(&layout, &vault)?;
        self.state.write().expect("shared state poisoned").vault = vault;
        Ok(generation)
    }

    fn verify_device_access(
        &self,
        layout: &SharedLayout,
        vault: &VaultDocument,
    ) -> StoreResult<u32> {
        let device = self.device();
        let identity = vault::read_device_identity(
            &layout.device_identity(device.device_id()),
            vault,
        )?;
        let local = device.enrollment();
        if identity.signing_public_key != local.signing_public_key
            || identity.wrapping_recipient != local.wrapping_recipient
        {
            return Err(StoreError::Key(format!(
                "Vault Device {} does not match this installation's private keys",
                device.device_id()
            )));
        }

        let access = GenerationAccess::new();
        let current = access.current(layout, vault)?;
        for generation in 1..=current {
            access.identity(layout, vault, &device, generation)?;
        }
        Ok(current)
    }

    /// Create version 1 at a caller-selected stable Secret id bound to a durable mutation.
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
            .read_heads(id)?
            .versions
            .iter()
            .find(|version| version.mutation_id.as_deref() == Some(mutation_id))
            .map(|version| version.version))
    }

    /// All versions of a secret as lightweight replication references, oldest first.
    pub fn version_refs(&self, id: &SecretId) -> StoreResult<Vec<StoreVersionRef>> {
        self.verify_security_state()?;
        let heads = self.read_heads(id)?;
        let state = self.state.read().expect("shared state poisoned");
        heads
            .versions
            .iter()
            .map(|version| {
                let object = state.layout.object(&version.digest);
                let ciphertext_size = std::fs::metadata(&object)
                    .map_err(|e| StoreError::io(&object, e))?
                    .len();
                Ok(StoreVersionRef {
                    ordinal: version.version,
                    version_uuid: version.version_uuid.clone(),
                    generation: version.generation,
                    size: version.size,
                    ciphertext_size,
                    digest: version.digest.clone(),
                })
            })
            .collect()
    }

    /// The complete immutable reference for the current head, read from one authenticated head
    /// document so replication cannot combine metadata from different concurrent versions.
    pub fn head_version_ref(&self, id: &SecretId) -> StoreResult<StoreVersionRef> {
        self.verify_security_state()?;
        let heads = self.read_heads(id)?;
        let version = heads
            .versions
            .iter()
            .find(|version| version.version == heads.current_version)
            .ok_or_else(|| StoreError::Corrupt {
                id: id.to_string(),
                reason: format!(
                    "head version {} is missing from the version table",
                    heads.current_version
                ),
            })?;
        let state = self.state.read().expect("shared state poisoned");
        let object = state.layout.object(&version.digest);
        let ciphertext_size = std::fs::metadata(&object)
            .map_err(|error| StoreError::io(&object, error))?
            .len();
        Ok(StoreVersionRef {
            ordinal: version.version,
            version_uuid: version.version_uuid.clone(),
            generation: version.generation,
            size: version.size,
            ciphertext_size,
            digest: version.digest.clone(),
        })
    }

    /// The transport-stable identity of the head version.
    pub fn head_version_uuid(&self, id: &SecretId) -> StoreResult<String> {
        Ok(self.head_version_ref(id)?.version_uuid)
    }

    /// Point the head at the version carrying `version_uuid`; returns its local ordinal.
    pub fn set_head_to_uuid(&self, id: &SecretId, version_uuid: &str) -> StoreResult<u32> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let mut heads = self.read_heads(id)?;
        let ordinal = heads
            .versions
            .iter()
            .find(|version| version.version_uuid == version_uuid)
            .map(|version| version.version)
            .ok_or_else(|| StoreError::NotFound(format!("{id} version {version_uuid}")))?;
        if heads.current_version != ordinal {
            heads.current_version = ordinal;
            self.write_heads(id, &heads)?;
            self.seal_security_state()?;
        }
        Ok(ordinal)
    }

    /// Install one ciphertext asset received from an untrusted transport.
    ///
    /// The source is streamed into a private sibling and verified before create-only publication.
    /// An identical canonical object is idempotent; different existing bytes are never replaced.
    pub fn install_replicated_object(
        &self,
        digest: &str,
        expected_size: u64,
        source: &Path,
    ) -> StoreResult<bool> {
        validate_object_descriptor(digest, expected_size)?;
        let layout = self.shared_layout();
        let objects = layout.objects_dir();
        ensure_private_directory(&objects)?;
        let target = layout.object(digest);
        match verify_object_file(&target, digest, expected_size) {
            Ok(()) => return Ok(false),
            Err(StoreError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let mut input = open_regular_file(source, expected_size)?;
        let temporary = objects.join(format!(".floria-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|error| StoreError::io(&temporary, error))?;
            let actual_digest = copy_and_hash(
                &mut input,
                &mut output,
                expected_size,
                source,
                &temporary,
            )?;
            if actual_digest != digest {
                return Err(StoreError::Invalid(format!(
                    "replicated object {} has digest {actual_digest}, expected {digest}",
                    source.display()
                )));
            }
            output
                .sync_all()
                .map_err(|error| StoreError::io(&temporary, error))?;
            match std::fs::hard_link(&temporary, &target) {
                Ok(()) => {
                    std::fs::remove_file(&temporary)
                        .map_err(|error| StoreError::io(&temporary, error))?;
                    std::fs::File::open(&objects)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|error| StoreError::io(&objects, error))?;
                    Ok(true)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::fs::remove_file(&temporary)
                        .map_err(|error| StoreError::io(&temporary, error))?;
                    verify_object_file(&target, digest, expected_size)?;
                    Ok(false)
                }
                Err(error) => Err(StoreError::io(&target, error)),
            }
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// Verify the canonical ciphertext asset before transport or local projection uses it.
    pub fn verify_replicated_object(&self, digest: &str, expected_size: u64) -> StoreResult<()> {
        validate_object_descriptor(digest, expected_size)?;
        verify_object_file(
            &self.shared_layout().object(digest),
            digest,
            expected_size,
        )
    }

    /// Register a version that arrived through replication. The object already sits in the
    /// shared half; this verifies it end to end (digest, decrypt, payload binding, declared
    /// size) and appends a row to the local head document. No bytes are copied.
    #[allow(clippy::too_many_arguments)]
    pub fn register_replicated_version(
        &self,
        id: &SecretId,
        create: Option<NewSecret>,
        version_uuid: &str,
        generation: u32,
        expected_size: u64,
        digest: &str,
        mutation_id: &str,
    ) -> StoreResult<u32> {
        validate_mutation_id(mutation_id)?;
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let existing = match self.read_heads(id) {
            Ok(heads) => Some(heads),
            Err(StoreError::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        if let Some(heads) = &existing {
            if let Some(version) = heads
                .versions
                .iter()
                .find(|version| version.version_uuid == version_uuid)
            {
                if version.digest != digest {
                    return Err(StoreError::Corrupt {
                        id: id.to_string(),
                        reason: format!(
                            "version {version_uuid} already exists with a different digest"
                        ),
                    });
                }
                return Ok(version.version);
            }
        }
        // Verify the shared object before trusting it into the head table.
        let ciphertext = self.read_object_verified(digest, id)?;
        let plaintext = {
            let state = self.state.read().expect("shared state poisoned");
            let identity = self.generations.identity(
                &state.layout,
                &state.vault,
                &self.device(),
                generation,
            )?;
            let decrypted = vault::decrypt_with_identity(&identity, &ciphertext)?;
            decode_bound_payload(id, version_uuid, decrypted)?
        };
        if plaintext.len() as u64 != expected_size {
            return Err(StoreError::Invalid(format!(
                "replicated version {version_uuid} declares {expected_size} bytes but decrypts to {}",
                plaintext.len()
            )));
        }
        let mut heads = match existing {
            Some(heads) => heads,
            None => {
                let Some(create) = create else {
                    return Err(StoreError::Invalid(format!(
                        "secret {id} does not exist locally and no descriptor was provided"
                    )));
                };
                new_heads_document(id, create)?
            }
        };
        let ordinal = next_ordinal(&heads)?;
        heads.versions.push(HeadsVersion {
            version: ordinal,
            version_uuid: version_uuid.to_string(),
            generation,
            size: expected_size,
            digest: digest.to_string(),
            created: now_rfc3339(),
            note: None,
            mutation_id: Some(mutation_id.to_string()),
        });
        if heads.versions.len() == 1 {
            heads.current_version = ordinal;
        }
        self.write_heads(id, &heads)?;
        self.seal_security_state()?;
        Ok(ordinal)
    }

    /// Apply the portable descriptor of a replicated Secret while preserving machine-local
    /// placement. A file-backed item keeps its local source path; a managed item adopts the
    /// portable label. Content history and the current head are unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_replicated_settings(
        &self,
        id: &SecretId,
        label: &str,
        mode: u32,
        metadata: ItemMetadata,
        enforcement: Enforcement,
        environment_ids: Option<Vec<String>>,
    ) -> StoreResult<()> {
        if label.trim().is_empty() || label.contains('\0') {
            return Err(StoreError::Invalid(
                "replicated secret label cannot be empty or contain NUL".to_string(),
            ));
        }
        if mode & !0o777 != 0 {
            return Err(StoreError::Invalid(format!(
                "replicated secret mode must contain only permission bits: {mode:o}"
            )));
        }
        metadata.validate().map_err(StoreError::Invalid)?;
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let mut heads = self.read_heads(id)?;
        heads.mode = mode;
        if heads.source_path.is_none() {
            heads.managed_label = Some(label.to_string());
        }
        heads.metadata = metadata;
        heads.enforcement = enforcement;
        heads.environment_ids = environment_ids;
        self.write_heads(id, &heads)?;
        self.seal_security_state()
    }

    /// Remove the local head document for a replicated tombstone. Shared objects stay.
    pub fn remove_replicated_heads(&self, id: &SecretId) -> StoreResult<bool> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let path = self.heads_path(id);
        match std::fs::remove_file(&path) {
            Ok(()) => {
                self.seal_security_state()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(StoreError::io(&path, error)),
        }
    }

    /// The generation new versions are encrypted under right now.
    pub fn current_generation(&self) -> StoreResult<u32> {
        let state = self.state.read().expect("shared state poisoned");
        self.generations.current(&state.layout, &state.vault)
    }

    /// Unwrap the identity for `generation` with this device's wrapping key (cached).
    pub fn generation_identity(&self, generation: u32) -> StoreResult<x25519::Identity> {
        let state = self.state.read().expect("shared state poisoned");
        self.generations.identity(&state.layout, &state.vault, &self.device(), generation)
    }

    /// The plaintext recovery recipient string.
    pub fn recovery_recipient(&self) -> StoreResult<String> {
        let state = self.state.read().expect("shared state poisoned");
        self.generations.recovery_public(&state.layout, &state.vault)
    }

    /// Whether any other, unrevoked device is enrolled in this vault.
    pub fn has_other_enrolled_devices(&self) -> StoreResult<bool> {
        let state = self.state.read().expect("shared state poisoned");
        let generations = vault::load_key_generations(&state.layout, &state.vault)?;
        let revoked = generations
            .values()
            .flat_map(|document| document.revoked_devices.keys().cloned())
            .collect::<std::collections::HashSet<_>>();
        let devices_dir = state.layout.devices_dir();
        let entries = match std::fs::read_dir(&devices_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(StoreError::io(&devices_dir, error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| StoreError::io(&devices_dir, error))?;
            let Some(device_id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if device_id == self.device().device_id() || revoked.contains(&device_id) {
                continue;
            }
            if uuid::Uuid::parse_str(&device_id).is_err() {
                continue;
            }
            let identity_path = state.layout.device_identity(&device_id);
            if identity_path.is_file()
                && vault::read_device_identity(&identity_path, &state.vault).is_ok()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Rotate to a new key generation (device revocation support). Writes the signed
    /// generation document with envelopes for `recipients` and returns the new generation.
    /// Only the genesis device can sign generation documents.
    pub fn rotate_generation(
        &self,
        recipients: &std::collections::BTreeMap<String, x25519::Recipient>,
        revoked_devices: std::collections::BTreeMap<String, u64>,
    ) -> StoreResult<u32> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let state = self.state.read().expect("shared state poisoned");
        let current = self.generations.current(&state.layout, &state.vault)?;
        let recovery = self.generations.recovery_public(&state.layout, &state.vault)?;
        let next = current
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid("key generation overflow".to_string()))?;
        let identity = x25519::Identity::generate();
        write_key_generation(
            &state.layout.generation_document(next),
            &state.vault,
            next,
            Some(current),
            &identity,
            recipients,
            revoked_devices,
            &recovery,
            self.device().signing_key(),
        )?;
        self.generations.refresh(&state.layout, &state.vault)?;
        Ok(next)
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

    /// Verify a copied store backup with the same key provider as this live store.
    pub fn verify_backup(&self, root: &Path) -> StoreResult<StoreVerification> {
        if !root.is_dir() {
            return Err(StoreError::Invalid(format!(
                "backup store directory does not exist: {}",
                root.display()
            )));
        }
        AgeDirStore::open(root.to_path_buf(), Arc::clone(&self.keys))?.verify_all()
    }

    pub fn lock_for_maintenance(&self) -> StoreResult<StoreMaintenanceGuard> {
        let lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        Ok(StoreMaintenanceGuard {
            _lock: lock,
            shared_root: self.shared_root(),
            local_root: self.root.join("local"),
            device_key_path: self.root.join("device.age"),
        })
    }

    /// Copy one immutable, internally consistent encrypted-store snapshot.
    pub fn backup_to(&self, destination: &Path) -> StoreResult<()> {
        self.lock_for_maintenance()?.backup_to(destination)
    }

    fn lock_exclusive(&self) -> StoreResult<std::fs::File> {
        let path = self.root.join("local/.lock");
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|e| StoreError::io(&path, e))?;
        f.lock().map_err(|e| StoreError::io(&path, e))?;
        Ok(f)
    }

    fn heads_dir(&self) -> PathBuf {
        self.root.join("local/heads")
    }

    fn heads_path(&self, id: &SecretId) -> PathBuf {
        self.heads_dir().join(format!("{id}.toml"))
    }

    fn heads_ids(&self) -> StoreResult<Vec<SecretId>> {
        let dir = self.heads_dir();
        let mut ids = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
            Err(error) => return Err(StoreError::io(&dir, error)),
        };
        for entry in entries {
            let entry = entry.map_err(|error| StoreError::io(&dir, error))?;
            let name = entry.file_name();
            if let Some(stem) = name.to_string_lossy().strip_suffix(".toml") {
                if let Ok(id) = stem.parse::<SecretId>() {
                    ids.push(id);
                }
            }
        }
        ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        Ok(ids)
    }

    fn read_heads(&self, id: &SecretId) -> StoreResult<HeadsDocument> {
        let path = self.heads_path(id);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(id.to_string())
            } else {
                StoreError::io(&path, e)
            }
        })?;
        let heads: HeadsDocument = toml::from_str(&text).map_err(|e| StoreError::Corrupt {
            id: id.to_string(),
            reason: format!("head document: {e}"),
        })?;
        if heads.id != id.as_str() {
            return Err(StoreError::Corrupt {
                id: id.to_string(),
                reason: format!("head document id {:?} does not match its filename", heads.id),
            });
        }
        if !(MIN_SUPPORTED_STORE_FORMAT_VERSION..=STORE_FORMAT_VERSION).contains(&heads.format) {
            return Err(StoreError::Corrupt {
                id: id.to_string(),
                reason: format!(
                    "store format {} but this build supports {} through {}; migrate or delete the entry",
                    heads.format, MIN_SUPPORTED_STORE_FORMAT_VERSION, STORE_FORMAT_VERSION
                ),
            });
        }
        match (&heads.source_path, &heads.managed_label) {
            (Some(_), None) => {}
            (None, Some(label)) if !label.trim().is_empty() => {}
            _ => {
                return Err(StoreError::Corrupt {
                    id: id.to_string(),
                    reason: "head document must contain exactly one valid secret origin"
                        .to_string(),
                })
            }
        }
        let mut seen = std::collections::HashSet::new();
        for version in &heads.versions {
            if version.version == 0
                || !seen.insert(version.version)
                || version.version_uuid.is_empty()
                || version.digest.is_empty()
            {
                return Err(StoreError::Corrupt {
                    id: id.to_string(),
                    reason: "head document version table is invalid".to_string(),
                });
            }
        }
        Ok(heads)
    }

    fn write_heads(&self, id: &SecretId, heads: &HeadsDocument) -> StoreResult<()> {
        let text = toml::to_string_pretty(heads)
            .map_err(|e| StoreError::Crypto(format!("serialize head document: {e}")))?;
        write_private(&self.heads_path(id), text.as_bytes())
    }

    fn find_version(&self, heads: &HeadsDocument, ordinal: u32) -> StoreResult<HeadsVersion> {
        heads
            .versions
            .iter()
            .find(|version| version.version == ordinal)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("{}@v{ordinal}", heads.id)))
    }

    /// Read an object from the shared half and require its bytes to match the digest. The
    /// shared half is untrusted input; content addressing makes this check self-contained.
    fn read_object_verified(&self, digest: &str, id: &SecretId) -> StoreResult<Vec<u8>> {
        let path = {
            let state = self.state.read().expect("shared state poisoned");
            state.layout.object(digest)
        };
        let ciphertext = read_untrusted_file(&path, MAX_OBJECT_BYTES).map_err(|error| {
            match error {
                StoreError::Io { source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    StoreError::NotFound(format!("{id} object {digest}"))
                }
                error => error,
            }
        })?;
        if hex_sha256(&ciphertext) != digest {
            return Err(StoreError::Corrupt {
                id: id.to_string(),
                reason: format!("object {digest} does not match its declared digest"),
            });
        }
        Ok(ciphertext)
    }

    fn decrypt_version(&self, id: &SecretId, ordinal: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
        let heads = self.read_heads(id)?;
        let version = self.find_version(&heads, ordinal)?;
        let ciphertext = self.read_object_verified(&version.digest, id)?;
        let identity = {
            let state = self.state.read().expect("shared state poisoned");
            self.generations.identity(
                &state.layout,
                &state.vault,
                &self.device(),
                version.generation,
            )?
        };
        let decrypted = vault::decrypt_with_identity(&identity, &ciphertext)?;
        decode_bound_payload(id, &version.version_uuid, decrypted)
    }

    /// Write one immutable version object and return its table row. The object is published
    /// before the head document changes; a crash in between leaves a harmless orphan object.
    fn write_version_object(
        &self,
        id: &SecretId,
        ordinal: u32,
        plaintext: &[u8],
        note: Option<String>,
        mutation_id: Option<String>,
    ) -> StoreResult<HeadsVersion> {
        let state = self.state.read().expect("shared state poisoned");
        let generation = self.generations.current(&state.layout, &state.vault)?;
        // A device that cannot decrypt what it writes is not enrolled yet; refuse early.
        self.generations.identity(&state.layout, &state.vault, &self.device(), generation)?;
        let version_uuid = uuid::Uuid::new_v4().to_string();
        let bound = encode_bound_payload(id, &version_uuid, plaintext)?;
        let recipients = self.generations.recipients(&state.layout, &state.vault)?;
        let encryptor = age::Encryptor::with_recipients(recipients)
            .ok_or_else(|| StoreError::Crypto("no recipients configured".to_string()))?;
        let mut ciphertext = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|e| StoreError::Crypto(format!("wrap: {e}")))?;
        use std::io::Write as _;
        writer
            .write_all(&bound)
            .map_err(|e| StoreError::Crypto(format!("write: {e}")))?;
        writer
            .finish()
            .map_err(|e| StoreError::Crypto(format!("finish: {e}")))?;
        let digest = hex_sha256(&ciphertext);
        ensure_private_directory(&state.layout.objects_dir())?;
        publish_immutable(&state.layout.object(&digest), &ciphertext)?;
        Ok(HeadsVersion {
            version: ordinal,
            version_uuid,
            generation,
            size: plaintext.len() as u64,
            digest,
            created: now_rfc3339(),
            note,
            mutation_id,
        })
    }

    fn put_internal(
        &self,
        id: SecretId,
        meta: NewSecret,
        plaintext: &[u8],
        mutation_id: Option<String>,
    ) -> StoreResult<SecretId> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        match self.read_heads(&id) {
            Ok(heads) => {
                if let Some(expected) = mutation_id.as_deref() {
                    if let Some(version) = heads
                        .versions
                        .iter()
                        .find(|version| version.mutation_id.as_deref() == Some(expected))
                    {
                        let existing = self.decrypt_version(&id, version.version)?;
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
            Err(StoreError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        let mut heads = new_heads_document(&id, meta)?;
        let version = self.write_version_object(&id, 1, plaintext, None, mutation_id)?;
        heads.versions.push(version);
        heads.current_version = 1;
        self.write_heads(&id, &heads)?;
        self.seal_security_state()?;
        Ok(id)
    }

    fn append_version_internal(
        &self,
        id: &SecretId,
        plaintext: &[u8],
        mutation_id: Option<String>,
    ) -> StoreResult<u32> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let mut heads = self.read_heads(id)?;
        if let Some(expected) = mutation_id.as_deref() {
            if let Some(version) = heads
                .versions
                .iter()
                .find(|version| version.mutation_id.as_deref() == Some(expected))
            {
                let ordinal = version.version;
                let existing = self.decrypt_version(id, ordinal)?;
                if existing.as_slice() != plaintext {
                    return Err(StoreError::Invalid(format!(
                        "mutation {expected} was already used for different secret bytes"
                    )));
                }
                if heads.current_version != ordinal {
                    heads.current_version = ordinal;
                    self.write_heads(id, &heads)?;
                    self.seal_security_state()?;
                }
                return Ok(ordinal);
            }
        }
        let next = next_ordinal(&heads)?;
        let version = self.write_version_object(id, next, plaintext, None, mutation_id)?;
        heads.versions.push(version);
        heads.current_version = next;
        self.write_heads(id, &heads)?;
        self.seal_security_state()?;
        Ok(next)
    }

    fn security_snapshot(&self) -> StoreResult<StoreSecuritySnapshot> {
        let mut entries = Vec::new();
        for id in self.heads_ids()? {
            entries.push(self.read_heads(&id)?);
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
                reason:
                    "store contents changed outside the authenticated daemon transaction boundary"
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
}

const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

fn validate_object_descriptor(digest: &str, expected_size: u64) -> StoreResult<()> {
    let valid_digest = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid_digest {
        return Err(StoreError::Invalid(format!(
            "object digest must be 64 lowercase hexadecimal characters: {digest}"
        )));
    }
    if expected_size > MAX_OBJECT_BYTES {
        return Err(StoreError::Invalid(format!(
            "replicated object {digest} exceeds the {MAX_OBJECT_BYTES} byte format limit"
        )));
    }
    Ok(())
}

fn open_regular_file(path: &Path, expected_size: u64) -> StoreResult<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| StoreError::io(path, error))?;
    let metadata = file.metadata().map_err(|error| StoreError::io(path, error))?;
    if !metadata.file_type().is_file() {
        return Err(StoreError::Invalid(format!(
            "replicated object {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() != expected_size {
        return Err(StoreError::Invalid(format!(
            "replicated object {} has {} bytes, expected {expected_size}",
            path.display(),
            metadata.len()
        )));
    }
    Ok(file)
}

fn verify_object_file(path: &Path, digest: &str, expected_size: u64) -> StoreResult<()> {
    let mut file = open_regular_file(path, expected_size)?;
    let actual_digest = hash_reader(&mut file, expected_size, path)?;
    if actual_digest != digest {
        return Err(StoreError::Invalid(format!(
            "replicated object {} has digest {actual_digest}, expected {digest}",
            path.display()
        )));
    }
    Ok(())
}

fn hash_reader(
    reader: &mut std::fs::File,
    expected_size: u64,
    path: &Path,
) -> StoreResult<String> {
    use std::io::Read as _;

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| StoreError::io(path, error))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| StoreError::Invalid("replicated object size overflow".to_string()))?;
        hasher.update(&buffer[..read]);
    }
    require_stream_size(path, total, expected_size)?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn copy_and_hash(
    input: &mut std::fs::File,
    output: &mut std::fs::File,
    expected_size: u64,
    source: &Path,
    destination: &Path,
) -> StoreResult<String> {
    use std::io::{Read as _, Write as _};

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| StoreError::io(source, error))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| StoreError::Invalid("replicated object size overflow".to_string()))?;
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|error| StoreError::io(destination, error))?;
    }
    require_stream_size(source, total, expected_size)?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn require_stream_size(path: &Path, actual: u64, expected: u64) -> StoreResult<()> {
    if actual != expected {
        return Err(StoreError::Invalid(format!(
            "replicated object {} changed while reading: {actual} bytes, expected {expected}",
            path.display()
        )));
    }
    Ok(())
}

fn new_heads_document(id: &SecretId, meta: NewSecret) -> StoreResult<HeadsDocument> {
    let mode = meta.mode;
    let enforcement = meta.enforcement;
    let (source_path, managed_label) = validate_new_secret_origin(meta.origin)?;
    Ok(HeadsDocument {
        format: STORE_FORMAT_VERSION,
        id: id.to_string(),
        source_path,
        managed_label,
        mode,
        created: now_rfc3339(),
        current_version: 0,
        enforcement,
        environment_ids: None,
        metadata: ItemMetadata::default(),
        versions: Vec::new(),
    })
}

fn next_ordinal(heads: &HeadsDocument) -> StoreResult<u32> {
    heads
        .versions
        .iter()
        .map(|version| version.version)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| StoreError::Invalid(format!("secret {} version overflow", heads.id)))
}

fn read_shared_location(root: &Path) -> StoreResult<Option<PathBuf>> {
    let path = root.join(SHARED_LOCATION_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let target = text.trim();
            if target.is_empty() {
                return Err(StoreError::Invalid(format!(
                    "{} is empty",
                    path.display()
                )));
            }
            Ok(Some(PathBuf::from(target)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StoreError::io(&path, error)),
    }
}

fn replace_or_create_regular_file(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(StoreError::Invalid(format!(
                "replacement path {} is not a regular file",
                path.display()
            )))
        }
        Ok(_) => write_replace_atomic(path, bytes),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            write_new_atomic(path, bytes)
        }
        Err(source) => Err(StoreError::io(path, source)),
    }
}

/// First open of a data root: become a single-device vault. Generation 1 and the recovery
/// recipient are born here; the recovery identity is escrowed next to the local half, wrapped
/// to this device (for later export to offline media).
fn genesis_initialize(
    layout: &SharedLayout,
    device: &DeviceKeyMaterial,
    recovery_escrow_path: &Path,
) -> StoreResult<VaultDocument> {
    ensure_private_directory(layout.root())?;
    ensure_private_directory(&layout.objects_dir())?;
    ensure_private_directory(&layout.devices_dir())?;
    ensure_private_directory(&layout.generations_dir())?;
    ensure_private_directory(&layout.operations_dir())?;
    ensure_private_directory(&layout.checkpoints_dir())?;

    let unsigned = vault::VaultUnsigned {
        format_version: vault::VAULT_FORMAT_VERSION,
        vault_id: uuid::Uuid::new_v4().to_string(),
        genesis_device_id: device.device_id().to_string(),
        genesis_public_key: vault::encode(device.verifying_key().as_bytes()),
        created_at: now_rfc3339(),
    };
    let signature =
        vault::sign_struct(vault::VAULT_SIGNATURE_CONTEXT, &unsigned, device.signing_key())?;
    let document = VaultDocument {
        format_version: unsigned.format_version,
        vault_id: unsigned.vault_id,
        genesis_device_id: unsigned.genesis_device_id,
        genesis_public_key: unsigned.genesis_public_key,
        created_at: unsigned.created_at,
        signature,
    };
    write_new_atomic(
        &layout.vault_json(),
        &serde_json::to_vec_pretty(&document)
            .map_err(|error| StoreError::Invalid(error.to_string()))?,
    )?;

    ensure_private_directory(&layout.device_dir(device.device_id()))?;
    ensure_private_directory(&layout.envelopes_dir(device.device_id()))?;
    vault::write_device_identity(
        &layout.device_identity(device.device_id()),
        &document,
        &device.enrollment(),
        1,
        device.signing_key(),
    )?;

    let generation_identity = x25519::Identity::generate();
    let recovery_identity = x25519::Identity::generate();
    let recipients = std::collections::BTreeMap::from([(
        device.device_id().to_string(),
        device.wrapping_identity().to_public(),
    )]);
    write_key_generation(
        &layout.generation_document(1),
        &document,
        1,
        None,
        &generation_identity,
        &recipients,
        std::collections::BTreeMap::new(),
        &recovery_identity.to_public().to_string(),
        device.signing_key(),
    )?;
    // Escrow the recovery identity wrapped to this device so `keys export-recovery` can later
    // move it to offline media. Losing this file only loses the escrow, not the data.
    let escrow = vault::encrypt_to_recipient(
        &device.wrapping_identity().to_public(),
        recovery_identity.to_string().expose_secret().as_bytes(),
    )?;
    write_new_atomic(recovery_escrow_path, &escrow)?;
    Ok(document)
}

impl SecretStore for AgeDirStore {
    fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId> {
        self.put_internal(SecretId::generate(), meta, plaintext, None)
    }

    fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
        self.verify_security_state()?;
        let head = self.read_heads(id)?.current_version;
        self.decrypt_version(id, head)
    }

    fn get_many(&self, ids: &[SecretId]) -> StoreResult<Vec<Zeroizing<Vec<u8>>>> {
        self.verify_security_state()?;
        ids.iter()
            .map(|id| {
                let head = self.read_heads(id)?.current_version;
                self.decrypt_version(id, head)
            })
            .collect()
    }

    fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
        self.verify_security_state()?;
        self.decrypt_version(id, version)
    }

    fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
        self.append_version_internal(id, plaintext, None)
    }

    fn history(&self, id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
        self.verify_security_state()?;
        let mut heads = self.read_heads(id)?;
        heads.versions.sort_by_key(|version| version.version);
        Ok(heads
            .versions
            .into_iter()
            .map(|version| VersionRecord {
                version: version.version,
                size: version.size,
                created: version.created,
                note: version.note,
                mutation_id: version.mutation_id,
            })
            .collect())
    }

    fn set_head(&self, id: &SecretId, version: u32) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let mut heads = self.read_heads(id)?;
        self.find_version(&heads, version)?;
        heads.current_version = version;
        self.write_heads(id, &heads)?;
        self.seal_security_state()
    }

    fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
        self.verify_security_state()?;
        let heads = match self.read_heads(id) {
            Ok(heads) => heads,
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let head = self.find_version(&heads, heads.current_version)?;
        let origin = match (heads.source_path, heads.managed_label) {
            (Some(source_path), None) => {
                SecretOrigin::File { source_path: PathBuf::from(source_path) }
            }
            (None, Some(label)) => SecretOrigin::Managed { label },
            _ => unreachable!("read_heads validates exactly one origin"),
        };
        Ok(Some(SecretRecord {
            id: id.clone(),
            origin,
            mode: heads.mode,
            size: head.size,
            created: heads.created,
            current_version: heads.current_version,
            enforcement: heads.enforcement,
            environment_ids: heads.environment_ids,
            metadata: heads.metadata,
        }))
    }

    fn list(&self) -> StoreResult<Vec<SecretRecord>> {
        self.verify_security_state()?;
        let mut out = Vec::new();
        for id in self.heads_ids()? {
            if let Some(record) = self.record(&id)? {
                out.push(record);
            }
        }
        out.sort_by_key(SecretRecord::display_name);
        Ok(out)
    }

    fn get_by_path(&self, source_path: &Path) -> StoreResult<Option<SecretRecord>> {
        self.verify_security_state()?;
        let target = source_path.to_string_lossy();
        Ok(self.list()?.into_iter().find(|record| {
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
        let mut heads = self.read_heads(id)?;
        heads.metadata = metadata;
        heads.enforcement = enforcement;
        heads.environment_ids = environment_ids;
        self.write_heads(id, &heads)?;
        self.seal_security_state()
    }

    fn delete(&self, id: &SecretId) -> StoreResult<()> {
        let _lock = self.lock_exclusive()?;
        self.verify_security_state()?;
        let heads = self.read_heads(id)?;
        // Solo vault: nobody else can reference these objects (the payload binding pins them to
        // this secret id), so a delete is a true destruction. With other enrolled devices the
        // objects are shared immutable files; only the local head document goes away and the
        // cross-device meaning is a signed tombstone published by replication.
        if !self.has_other_enrolled_devices()? {
            let state = self.state.read().expect("shared state poisoned");
            for version in &heads.versions {
                let object = state.layout.object(&version.digest);
                match std::fs::remove_file(&object) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(StoreError::io(&object, error)),
                }
            }
        }
        let path = self.heads_path(id);
        std::fs::remove_file(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(id.to_string())
            } else {
                StoreError::io(&path, e)
            }
        })?;
        self.seal_security_state()
    }
}

fn copy_directory(source: &Path, destination: &Path) -> StoreResult<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(destination)
        .map_err(|error| StoreError::io(destination, error))?;
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
            copy_directory(&from, &to)?;
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

/// Lowercase hex SHA-256 — the object filename and the replication Object ID share this exact
/// encoding: they are the same file.
pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Bind the payload to its secret id and transport-stable version UUID.
fn encode_bound_payload(
    id: &SecretId,
    version_uuid: &str,
    plaintext: &[u8],
) -> StoreResult<Zeroizing<Vec<u8>>> {
    let id_bytes = id.as_str().as_bytes();
    let id_len = u16::try_from(id_bytes.len())
        .map_err(|_| StoreError::Invalid("secret id is too long".to_string()))?;
    let uuid_bytes = version_uuid.as_bytes();
    let uuid_len = u16::try_from(uuid_bytes.len())
        .map_err(|_| StoreError::Invalid("version uuid is too long".to_string()))?;
    let mut bound = Zeroizing::new(Vec::with_capacity(
        PAYLOAD_MAGIC.len() + 2 + id_bytes.len() + 2 + uuid_bytes.len() + plaintext.len(),
    ));
    bound.extend_from_slice(PAYLOAD_MAGIC);
    bound.extend_from_slice(&id_len.to_be_bytes());
    bound.extend_from_slice(id_bytes);
    bound.extend_from_slice(&uuid_len.to_be_bytes());
    bound.extend_from_slice(uuid_bytes);
    bound.extend_from_slice(plaintext);
    Ok(bound)
}

fn decode_bound_payload(
    expected_id: &SecretId,
    expected_uuid: &str,
    payload: Zeroizing<Vec<u8>>,
) -> StoreResult<Zeroizing<Vec<u8>>> {
    let corrupt = |reason: String| StoreError::Corrupt {
        id: expected_id.to_string(),
        reason,
    };
    if !payload.starts_with(PAYLOAD_MAGIC) {
        return Err(corrupt("version object has no authenticated context binding".to_string()));
    }
    let mut cursor = PAYLOAD_MAGIC.len();
    let id_len_bytes: [u8; 2] = payload
        .get(cursor..cursor + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| corrupt("version object has a truncated context header".to_string()))?;
    cursor += 2;
    let id_len = u16::from_be_bytes(id_len_bytes) as usize;
    let actual_id = payload
        .get(cursor..cursor + id_len)
        .ok_or_else(|| corrupt("version object has a truncated secret id".to_string()))?
        .to_vec();
    cursor += id_len;
    let uuid_len_bytes: [u8; 2] = payload
        .get(cursor..cursor + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| corrupt("version object has a truncated context header".to_string()))?;
    cursor += 2;
    let uuid_len = u16::from_be_bytes(uuid_len_bytes) as usize;
    let actual_uuid = payload
        .get(cursor..cursor + uuid_len)
        .ok_or_else(|| corrupt("version object has a truncated version uuid".to_string()))?
        .to_vec();
    cursor += uuid_len;
    if actual_id != expected_id.as_str().as_bytes() || actual_uuid != expected_uuid.as_bytes() {
        return Err(corrupt(format!(
            "version object belongs to {}@{}",
            String::from_utf8_lossy(&actual_id),
            String::from_utf8_lossy(&actual_uuid)
        )));
    }
    Ok(Zeroizing::new(payload[cursor..].to_vec()))
}

/// Write a file with mode 0600, atomically: write+fsync a `.tmp` sibling, then rename over the
/// target. A crash mid-write leaves the old content intact. Concurrent writers are serialized
/// by the store lock.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> StoreResult<()> {
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
    use std::io::Write as _;
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
    fn opening_a_root_becomes_a_single_device_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        assert!(tmp.path().join("shared/vault.json").is_file());
        assert!(tmp.path().join("device.age").is_file());
        assert!(tmp.path().join("local/recovery.age").is_file());
        let vault = s.vault_document();
        assert_eq!(vault.genesis_device_id, s.device().device_id());
        assert_eq!(s.current_generation().unwrap(), 1);
        assert!(!s.has_other_enrolled_devices().unwrap());
    }

    #[test]
    fn put_get_roundtrip_stores_the_object_in_the_shared_half() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let secret = b"EXAMPLE_CONFIG=placeholder-value-one\n";
        let id = s
            .put(NewSecret::file(PathBuf::from("/Users/me/proj/.env"), 0o600), secret)
            .unwrap();
        assert_eq!(s.get(&id).unwrap().as_slice(), secret);

        let refs = s.version_refs(&id).unwrap();
        assert_eq!(refs.len(), 1);
        let object = tmp.path().join("shared/objects").join(format!("{}.age", refs[0].digest));
        let blob = std::fs::read(&object).unwrap();
        assert_eq!(hex_sha256(&blob), refs[0].digest);
        assert!(!blob.windows(secret.len()).any(|w| w == secret));
    }

    #[test]
    fn replicated_object_install_is_create_only_and_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().join("store"));
        let source = tmp.path().join("download.age");
        let bytes = b"ciphertext fixture from transport";
        std::fs::write(&source, bytes).unwrap();
        let digest = hex_sha256(bytes);

        assert!(s
            .install_replicated_object(&digest, bytes.len() as u64, &source)
            .unwrap());
        assert!(!s
            .install_replicated_object(&digest, bytes.len() as u64, &source)
            .unwrap());
        s.verify_replicated_object(&digest, bytes.len() as u64)
            .unwrap();
        assert_eq!(std::fs::read(s.shared_layout().object(&digest)).unwrap(), bytes);
    }

    #[test]
    fn replicated_object_install_rejects_tampering_and_symlinks() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().join("store"));
        let source = tmp.path().join("download.age");
        let link = tmp.path().join("download-link.age");
        let bytes = b"ciphertext fixture from transport";
        std::fs::write(&source, bytes).unwrap();
        symlink(&source, &link).unwrap();
        let digest = hex_sha256(bytes);

        assert!(s
            .install_replicated_object(&"0".repeat(64), bytes.len() as u64, &source)
            .is_err());
        assert!(s
            .install_replicated_object(&digest, bytes.len() as u64, &link)
            .is_err());
        assert!(!s.shared_layout().object(&digest).exists());

        let target = s.shared_layout().object(&digest);
        std::fs::write(&target, vec![0_u8; bytes.len()]).unwrap();
        assert!(s
            .install_replicated_object(&digest, bytes.len() as u64, &source)
            .is_err());
        assert_eq!(std::fs::read(target).unwrap(), vec![0_u8; bytes.len()]);
    }

    #[test]
    fn reopening_the_same_root_reloads_the_device_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let keys: Arc<dyn KeyProvider> =
            Arc::new(X25519Keys(age::x25519::Identity::generate()));
        let (id, device_id) = {
            let s = AgeDirStore::open(tmp.path().to_path_buf(), Arc::clone(&keys)).unwrap();
            let id = s.put(NewSecret::managed("reopen fixture"), b"survives reopen").unwrap();
            (id, s.device().device_id().to_string())
        };
        let reopened = AgeDirStore::open(tmp.path().to_path_buf(), keys).unwrap();
        assert_eq!(reopened.device().device_id(), device_id);
        assert_eq!(reopened.get(&id).unwrap().as_slice(), b"survives reopen");
    }

    #[test]
    fn append_version_moves_head_non_destructively() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s.put(NewSecret::file(PathBuf::from("/p/.env"), 0o600), b"v1").unwrap();

        assert_eq!(s.append_version(&id, b"v2-longer").unwrap(), 2);
        assert_eq!(s.append_version(&id, b"v3").unwrap(), 3);

        assert_eq!(s.get(&id).unwrap().as_slice(), b"v3");
        assert_eq!(s.get_version(&id, 1).unwrap().as_slice(), b"v1");
        assert_eq!(s.get_version(&id, 2).unwrap().as_slice(), b"v2-longer");

        let rec = s.record(&id).unwrap().unwrap();
        assert_eq!(rec.current_version, 3);
        assert_eq!(rec.size, 2);

        let hist = s.history(&id).unwrap();
        assert_eq!(hist.iter().map(|v| v.version).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn set_head_rolls_back_by_repointing() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s.put(NewSecret::file(PathBuf::from("/p/.env"), 0o600), b"first").unwrap();
        s.append_version(&id, b"second").unwrap();

        s.set_head(&id, 1).unwrap();
        assert_eq!(s.get(&id).unwrap().as_slice(), b"first");
        assert_eq!(s.record(&id).unwrap().unwrap().current_version, 1);

        assert_eq!(s.append_version(&id, b"third").unwrap(), 3);
        assert_eq!(s.get_version(&id, 2).unwrap().as_slice(), b"second");

        assert!(matches!(s.set_head(&id, 9), Err(StoreError::NotFound(_))));

        // Head moves by transport-stable uuid too.
        let v2_uuid = s.version_refs(&id).unwrap()[1].version_uuid.clone();
        assert_eq!(s.set_head_to_uuid(&id, &v2_uuid).unwrap(), 2);
        assert_eq!(s.head_version_uuid(&id).unwrap(), v2_uuid);
    }

    #[test]
    fn identified_put_and_append_are_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store(tmp.path().to_path_buf());
        let id: SecretId = "11111111-1111-4111-8111-111111111111".parse().unwrap();
        let mutation_id = "22222222-2222-4222-8222-222222222222";
        let value = b"fixture payload, not a credential";

        store
            .put_identified(id.clone(), NewSecret::managed("fixture"), value, mutation_id)
            .unwrap();
        store
            .put_identified(id.clone(), NewSecret::managed("fixture"), value, mutation_id)
            .unwrap();
        assert_eq!(store.version_for_mutation(&id, mutation_id).unwrap(), Some(1));
        assert_eq!(store.history(&id).unwrap().len(), 1);

        let append_mutation = "33333333-3333-4333-8333-333333333333";
        assert_eq!(
            store.append_version_identified(&id, b"version two", append_mutation).unwrap(),
            2
        );
        assert_eq!(
            store.append_version_identified(&id, b"version two", append_mutation).unwrap(),
            2
        );
        assert!(store
            .append_version_identified(&id, b"different", append_mutation)
            .unwrap_err()
            .to_string()
            .contains("different secret bytes"));
    }

    #[test]
    fn list_get_by_path_and_settings_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        s.put(NewSecret::file(PathBuf::from("/a/.env"), 0o600), b"A=1").unwrap();
        let id = s.put(NewSecret::file(PathBuf::from("/b/.env"), 0o600), b"B=2").unwrap();
        assert_eq!(s.list().unwrap().len(), 2);
        let rec = s.get_by_path(Path::new("/b/.env")).unwrap().unwrap();
        assert_eq!(rec.id, id);

        s.update_settings(
            &id,
            ItemMetadata::default(),
            Enforcement::TouchId,
            Some(vec!["production".to_string()]),
        )
        .unwrap();
        let rec = s.record(&id).unwrap().unwrap();
        assert_eq!(rec.enforcement, Enforcement::TouchId);
        assert_eq!(rec.environment_ids, Some(vec!["production".to_string()]));
        assert_eq!(rec.current_version, 1);
    }

    #[test]
    fn replicated_settings_preserve_local_file_placement_and_update_managed_labels() {
        let tmp = tempfile::tempdir().unwrap();
        let store = store(tmp.path().to_path_buf());
        let file_id = store
            .put(NewSecret::file(PathBuf::from("/local/.env"), 0o600), b"A=1")
            .unwrap();
        let managed_id = store
            .put(NewSecret::managed("Old label"), b"fixture")
            .unwrap();

        store
            .apply_replicated_settings(
                &file_id,
                "Portable file label",
                0o640,
                ItemMetadata::default(),
                Enforcement::Allow,
                None,
            )
            .unwrap();
        store
            .apply_replicated_settings(
                &managed_id,
                "New label",
                0o400,
                ItemMetadata::default(),
                Enforcement::TouchId,
                None,
            )
            .unwrap();

        let file = store.record(&file_id).unwrap().unwrap();
        assert_eq!(file.source_path(), Some(Path::new("/local/.env")));
        assert_eq!(file.mode, 0o640);
        assert_eq!(file.enforcement, Enforcement::Allow);
        let managed = store.record(&managed_id).unwrap().unwrap();
        assert_eq!(managed.display_name(), "New label");
        assert_eq!(managed.mode, 0o400);
        assert_eq!(managed.enforcement, Enforcement::TouchId);
    }

    #[test]
    fn solo_delete_destroys_objects_too() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s.put(NewSecret::managed("solo delete"), b"gone for real").unwrap();
        let digest = s.version_refs(&id).unwrap()[0].digest.clone();
        let object = tmp.path().join("shared/objects").join(format!("{digest}.age"));
        assert!(object.is_file());

        s.delete(&id).unwrap();
        assert!(matches!(s.get(&id), Err(StoreError::NotFound(_))));
        assert!(!object.exists(), "solo delete must destroy the object");
    }

    #[test]
    fn delete_with_other_enrolled_devices_keeps_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s.put(NewSecret::managed("shared delete"), b"kept as history").unwrap();
        let digest = s.version_refs(&id).unwrap()[0].digest.clone();
        let object = tmp.path().join("shared/objects").join(format!("{digest}.age"));

        // Enroll a second device: genesis-signed identity in its own namespace.
        let second = DeviceKeyMaterial::generate().unwrap();
        let layout = s.shared_layout();
        ensure_private_directory(&layout.device_dir(second.device_id())).unwrap();
        vault::write_device_identity(
            &layout.device_identity(second.device_id()),
            &s.vault_document(),
            &second.enrollment(),
            1,
            s.device().signing_key(),
        )
        .unwrap();
        assert!(s.has_other_enrolled_devices().unwrap());

        s.delete(&id).unwrap();
        assert!(matches!(s.get(&id), Err(StoreError::NotFound(_))));
        assert!(object.is_file(), "shared objects are immutable once other devices exist");
    }

    #[test]
    fn second_device_reads_the_same_object_without_any_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let a = store(tmp.path().join("a"));
        let id = a.put(NewSecret::managed("single copy"), b"one byte set").unwrap();
        a.append_version(&id, b"second version").unwrap();

        // Device B: own root, then adopt A's shared half (fresh install joining a vault).
        let b_keys: Arc<dyn KeyProvider> =
            Arc::new(X25519Keys(age::x25519::Identity::generate()));
        let b = AgeDirStore::open(tmp.path().join("b"), b_keys).unwrap();
        b.adopt_shared_location(&a.shared_root()).unwrap();

        // Genesis enrolls B: identity + a generation-1 envelope in B's namespace.
        let layout = a.shared_layout();
        let b_device = b.device();
        ensure_private_directory(&layout.device_dir(b_device.device_id())).unwrap();
        ensure_private_directory(&layout.envelopes_dir(b_device.device_id())).unwrap();
        vault::write_device_identity(
            &layout.device_identity(b_device.device_id()),
            &a.vault_document(),
            &b_device.enrollment(),
            1,
            a.device().signing_key(),
        )
        .unwrap();
        let generation_identity = a.generation_identity(1).unwrap();
        let envelope = vault::encrypt_to_recipient(
            &b_device
                .enrollment()
                .wrapping_recipient
                .parse::<x25519::Recipient>()
                .unwrap(),
            generation_identity.to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        write_new_atomic(&layout.envelope(b_device.device_id(), 1), &envelope).unwrap();

        // B registers A's versions from references only — no bytes move anywhere.
        for reference in a.version_refs(&id).unwrap() {
            let assigned = b
                .register_replicated_version(
                    &id,
                    Some(NewSecret::managed("single copy")),
                    &reference.version_uuid,
                    reference.generation,
                    reference.size,
                    &reference.digest,
                    "44444444-4444-4444-8444-444444444444",
                )
                .unwrap();
            assert_eq!(assigned, reference.ordinal);
        }
        let head_uuid = a.head_version_uuid(&id).unwrap();
        b.set_head_to_uuid(&id, &head_uuid).unwrap();
        assert_eq!(b.get(&id).unwrap().as_slice(), b"second version");

        // The single-copy property: both devices resolve the same physical file.
        let digest = a.version_refs(&id).unwrap()[1].digest.clone();
        assert_eq!(
            a.shared_layout().object(&digest),
            b.shared_layout().object(&digest)
        );

        // Tombstone import removes only B's head document.
        assert!(b.remove_replicated_heads(&id).unwrap());
        assert!(matches!(b.get(&id), Err(StoreError::NotFound(_))));
        assert_eq!(a.get(&id).unwrap().as_slice(), b"second version");
    }

    #[test]
    fn unenrolled_device_cannot_write_into_an_adopted_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let a = store(tmp.path().join("a"));
        let b = store(tmp.path().join("b"));
        b.adopt_shared_location(&a.shared_root()).unwrap();
        let error = b.put(NewSecret::managed("premature"), b"nope").unwrap_err();
        assert!(
            error.to_string().contains("no envelope"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn adopting_a_vault_requires_an_unused_store() {
        let tmp = tempfile::tempdir().unwrap();
        let a = store(tmp.path().join("a"));
        let b = store(tmp.path().join("b"));
        b.put(NewSecret::managed("existing"), b"data").unwrap();
        assert!(b
            .adopt_shared_location(&a.shared_root())
            .unwrap_err()
            .to_string()
            .contains("already holds secrets"));
    }

    #[test]
    fn relocating_the_shared_half_is_a_move_with_a_pointer() {
        let tmp = tempfile::tempdir().unwrap();
        let keys: Arc<dyn KeyProvider> =
            Arc::new(X25519Keys(age::x25519::Identity::generate()));
        let s = AgeDirStore::open(tmp.path().join("root"), Arc::clone(&keys)).unwrap();
        let id = s.put(NewSecret::managed("relocated"), b"still readable").unwrap();

        let target = tmp.path().join("Synced/My Floria.floriavault");
        s.relocate_shared(&target).unwrap();
        assert!(target.join("vault.json").is_file());
        assert!(!tmp.path().join("root/shared").exists());
        assert_eq!(s.get(&id).unwrap().as_slice(), b"still readable");

        // Reopening resolves the pointer.
        drop(s);
        let reopened = AgeDirStore::open(tmp.path().join("root"), keys).unwrap();
        assert_eq!(reopened.shared_root(), target);
        assert_eq!(reopened.get(&id).unwrap().as_slice(), b"still readable");
    }

    #[test]
    fn tampered_object_fails_the_digest_check() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s.put(NewSecret::managed("tamper fixture"), b"original").unwrap();
        let digest = s.version_refs(&id).unwrap()[0].digest.clone();
        let object = tmp.path().join("shared/objects").join(format!("{digest}.age"));
        let mut blob = std::fs::read(&object).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        std::fs::write(&object, &blob).unwrap();
        assert!(matches!(s.get(&id), Err(StoreError::Corrupt { .. })));
    }

    #[test]
    fn wrong_format_is_rejected_with_a_migrate_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().to_path_buf());
        let id = s.put(NewSecret::file(PathBuf::from("/x/.env"), 0o600), b"X=1").unwrap();

        let heads_path = tmp.path().join("local/heads").join(format!("{id}.toml"));
        let text = std::fs::read_to_string(&heads_path).unwrap();
        std::fs::write(&heads_path, text.replace("format = 5", "format = 4")).unwrap();

        match s.get(&id) {
            Err(StoreError::Corrupt { reason, .. }) => {
                assert!(reason.contains("migrate or delete"), "unexpected reason: {reason}")
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn authenticated_store_rejects_tampering_but_tolerates_sync_arrivals() {
        let tmp = tempfile::tempdir().unwrap();
        let keys: Arc<dyn KeyProvider> =
            Arc::new(X25519Keys(age::x25519::Identity::generate()));
        let auth = Arc::new(StateAuthenticator::for_tests([31; 32]));
        let store = AgeDirStore::open(tmp.path().to_path_buf(), Arc::clone(&keys))
            .unwrap()
            .authenticate(Arc::clone(&auth))
            .unwrap();
        let id = store.put(NewSecret::managed("authenticated fixture"), b"version-one").unwrap();
        let sidecar = tmp.path().join("local/.integrity.json");
        let old_sidecar = std::fs::read(&sidecar).unwrap();

        // A foreign object arriving through the sync tool must NOT trip integrity: the local
        // snapshot covers only head documents.
        std::fs::write(
            tmp.path().join("shared/objects/feedfacefeedface.age"),
            b"unreferenced arrival",
        )
        .unwrap();
        assert_eq!(store.get(&id).unwrap().as_slice(), b"version-one");

        // Tampering with the local head document fails closed.
        let heads_path = tmp.path().join("local/heads").join(format!("{id}.toml"));
        let original = std::fs::read(&heads_path).unwrap();
        std::fs::write(&heads_path, b"externally modified").unwrap();
        assert!(store.get(&id).is_err());
        std::fs::write(&heads_path, original).unwrap();

        // Signed rollback of the sidecar fails closed.
        store.append_version(&id, b"version-two").unwrap();
        std::fs::write(&sidecar, old_sidecar).unwrap();
        assert!(store.get(&id).is_err());
    }

    #[test]
    fn authenticated_store_does_not_silently_adopt_existing_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let keys: Arc<dyn KeyProvider> =
            Arc::new(X25519Keys(age::x25519::Identity::generate()));
        {
            let store = AgeDirStore::open(tmp.path().to_path_buf(), Arc::clone(&keys)).unwrap();
            store.put(NewSecret::managed("legacy fixture"), b"legacy-secret").unwrap();
        }
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
    fn enrollment_request_roundtrip_and_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let a = store(tmp.path().join("a"));
        let b = DeviceKeyMaterial::generate().unwrap();
        let request = b
            .enrollment_request(&a.vault_document(), Some("Laptop".to_string()), "2026-08-06T00:00:00Z")
            .unwrap();
        let layout = a.shared_layout();
        ensure_private_directory(&layout.device_dir(b.device_id())).unwrap();
        write_new_atomic(
            &layout.enrollment_request(b.device_id()),
            &serde_json::to_vec_pretty(&request).unwrap(),
        )
        .unwrap();

        let read = vault::read_enrollment_request(
            &layout.enrollment_request(b.device_id()),
            &a.vault_document(),
        )
        .unwrap();
        assert_eq!(read.device_id, b.device_id());
        assert_eq!(read.device_name.as_deref(), Some("Laptop"));
        let fingerprint = read.fingerprint();
        assert_eq!(fingerprint.len(), 14); // XXXX-XXXX-XXXX
        assert_eq!(fingerprint, request.fingerprint());

        // A tampered request fails validation.
        let mut forged = request.clone();
        forged.device_name = Some("Evil".to_string());
        assert!(vault::validate_enrollment_request(&forged, &a.vault_document()).is_err());
    }

    #[test]
    fn backup_and_verify_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path().join("live"));
        s.put(NewSecret::managed("backup fixture"), b"backup me").unwrap();
        let destination = tmp.path().join("backup");
        s.backup_to(&destination).unwrap();
        let verification = s.verify_backup(&destination).unwrap();
        assert_eq!(verification.secrets, 1);
        assert_eq!(verification.versions, 1);
    }
}
