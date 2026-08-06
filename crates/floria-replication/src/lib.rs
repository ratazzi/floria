//! Untrusted-directory format for Floria replication packages.
//!
//! [`ReplicationPackage`] is the storage-format module underneath the future
//! `ReplicationEngine`. It owns canonical signing bytes, age encryption, immutable publication,
//! digest validation, conflict-copy normalization, and hostile-directory parsing. Catalog
//! outboxes, device enrollment, sequence self-fencing, and Local Projection application remain
//! above this interface.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use age::x25519;
use age::secrecy::ExposeSecret;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use floria_catalog::{Catalog, ReplicatedCatalog, ReplicationOutboxEntry};
use floria_core::authz::Enforcement;
use floria_core::metadata::ItemMetadata;
use floria_integrity::StateAuthenticator;
use floria_store::{AgeDirStore, NewSecret, SecretId, SecretOrigin, SecretStore};
use floria_surface::ManagedMutationCoordinator;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: u32 = 1;
const VAULT_SIGNATURE_CONTEXT: &[u8] = b"floria-vault-v1\0";
const DEVICE_SIGNATURE_CONTEXT: &[u8] = b"floria-device-v1\0";
const KEY_GENERATION_SIGNATURE_CONTEXT: &[u8] = b"floria-key-generation-v1\0";
const OPERATION_SIGNATURE_CONTEXT: &[u8] = b"floria-operation-v1\0";
const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_OPERATION_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_REPORTED_DAMAGED_FILES: usize = 20;
/// Operation payload format: v2 carries per-entity deltas of one committed local transaction.
const PAYLOAD_FORMAT_VERSION: u32 = 2;
/// Transitional logical entity for whole-catalog metadata until catalog rows become entities.
const CATALOG_LOGICAL_ID: &str = "catalog/v1";
/// Placeholder logical id recorded on outbox rows (real per-entity ids live in the delta).
const TRANSACTION_LOGICAL_ID: &str = "txn/v2";

#[derive(Debug, Error)]
pub enum ReplicationError {
    #[error("replication I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid replication package: {0}")]
    Invalid(String),
    #[error("Device {device_id} is waiting for enrollment in this Vault")]
    EnrollmentRequired { device_id: String },
    #[error("Device {device_id} was revoked at key generation {generation}")]
    DeviceRevoked { device_id: String, generation: u32 },
    #[error("replication encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("replication encryption failed: {0}")]
    Encryption(String),
    #[error("replication signature failed: {0}")]
    Signature(String),
    #[error("replication local-state integrity failed: {0}")]
    Integrity(#[from] floria_integrity::IntegrityError),
    #[error("replication catalog failed: {0}")]
    Catalog(#[from] floria_catalog::CatalogError),
    #[error("replication local store failed: {0}")]
    Store(#[from] floria_store::StoreError),
}

pub type ReplicationResult<T> = Result<T, ReplicationError>;

/// Device-local material. Both private keys stay on this Mac; enrollment publishes only their
/// public halves and a Vault-key envelope encrypted to the wrapping recipient.
pub struct DeviceKeyMaterial {
    device_id: String,
    signing_key: SigningKey,
    wrapping_identity: x25519::Identity,
}

impl DeviceKeyMaterial {
    pub fn generate() -> ReplicationResult<Self> {
        let mut signing_seed = [0_u8; 32];
        getrandom::getrandom(&mut signing_seed).map_err(|error| {
            ReplicationError::Encryption(format!("generate Device signing key: {error}"))
        })?;
        let material = Self::new(
            uuid::Uuid::new_v4().to_string(),
            signing_seed,
            x25519::Identity::generate(),
        );
        signing_seed.zeroize();
        material
    }

    pub fn new(
        device_id: impl Into<String>,
        signing_seed: [u8; 32],
        wrapping_identity: x25519::Identity,
    ) -> ReplicationResult<Self> {
        let device_id = device_id.into();
        require_uuid("device id", &device_id)?;
        Ok(Self {
            device_id,
            signing_key: SigningKey::from_bytes(&signing_seed),
            wrapping_identity,
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn enrollment(&self) -> DeviceEnrollment {
        self.enrollment_named(None)
    }

    pub fn enrollment_named(&self, device_name: Option<String>) -> DeviceEnrollment {
        DeviceEnrollment {
            device_id: self.device_id.clone(),
            signing_public_key: encode(self.verifying_key().as_bytes()),
            wrapping_recipient: self.wrapping_identity.to_public().to_string(),
            device_name,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct LocalDeviceSecretDocument {
    format_version: u32,
    device_id: String,
    signing_seed: String,
    wrapping_identity: String,
}

impl Drop for LocalDeviceSecretDocument {
    fn drop(&mut self) {
        self.signing_seed.zeroize();
        self.wrapping_identity.zeroize();
    }
}

/// Encrypted, machine-local persistence for one Device identity. The same `KeyProvider` that
/// protects the local store wraps these bytes, so enabling replication adds no plaintext key file
/// and no second platform credential source.
pub struct DeviceKeyStore {
    path: PathBuf,
    keys: Arc<dyn floria_store::KeyProvider>,
}

impl DeviceKeyStore {
    pub fn new(
        path: impl Into<PathBuf>,
        keys: Arc<dyn floria_store::KeyProvider>,
    ) -> Self {
        Self { path: path.into(), keys }
    }

    pub fn load_or_create(&self) -> ReplicationResult<DeviceKeyMaterial> {
        let parent = self.path.parent().ok_or_else(|| {
            ReplicationError::Invalid(format!("{} has no parent directory", self.path.display()))
        })?;
        ensure_private_local_state_directory(parent)?;
        match fs::symlink_metadata(&self.path) {
            Ok(_) => self.load(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let material = DeviceKeyMaterial::generate()?;
                self.persist(&material)?;
                Ok(material)
            }
            Err(source) => Err(io_error(&self.path, source)),
        }
    }

    pub fn load(&self) -> ReplicationResult<DeviceKeyMaterial> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|source| io_error(&self.path, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ReplicationError::Invalid(format!(
                "Device key path {} is not a regular file",
                self.path.display()
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ReplicationError::Invalid(format!(
                "Device key file {} must not be accessible by group or others",
                self.path.display()
            )));
        }
        let ciphertext = read_untrusted_file(&self.path, MAX_DESCRIPTOR_BYTES)?;
        let plaintext = decrypt_with_provider(self.keys.as_ref(), &ciphertext)?;
        let document: LocalDeviceSecretDocument = serde_json::from_slice(&plaintext)?;
        if document.format_version != FORMAT_VERSION {
            return Err(ReplicationError::Invalid(format!(
                "unsupported local Device key format {}",
                document.format_version
            )));
        }
        let signing_seed = decode("Device signing seed", &document.signing_seed)?;
        let mut signing_seed: [u8; 32] = signing_seed.try_into().map_err(|_| {
            ReplicationError::Invalid("Device signing seed must be 32 bytes".to_string())
        })?;
        let wrapping_identity = document
            .wrapping_identity
            .parse::<x25519::Identity>()
            .map_err(|error| {
                ReplicationError::Invalid(format!("invalid Device wrapping identity: {error}"))
            })?;
        let material = DeviceKeyMaterial::new(
            document.device_id.clone(),
            signing_seed,
            wrapping_identity,
        );
        signing_seed.zeroize();
        material
    }

    /// Replace a revoked local identity with a fresh Device id and keypair. Callers must only
    /// expose this after a signed Vault generation identifies the current identity as revoked.
    pub fn rotate(&self) -> ReplicationResult<DeviceKeyMaterial> {
        self.load()?;
        let material = DeviceKeyMaterial::generate()?;
        let ciphertext = self.encrypt_material(&material)?;
        write_replace_atomic(&self.path, &ciphertext)?;
        Ok(material)
    }

    fn persist(&self, material: &DeviceKeyMaterial) -> ReplicationResult<()> {
        let ciphertext = self.encrypt_material(material)?;
        write_new_atomic(&self.path, &ciphertext)
    }

    fn encrypt_material(&self, material: &DeviceKeyMaterial) -> ReplicationResult<Vec<u8>> {
        let document = LocalDeviceSecretDocument {
            format_version: FORMAT_VERSION,
            device_id: material.device_id.clone(),
            signing_seed: encode(&material.signing_key.to_bytes()),
            wrapping_identity: material
                .wrapping_identity
                .to_string()
                .expose_secret()
                .to_string(),
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&document)?);
        encrypt_with_provider(self.keys.as_ref(), &plaintext)
    }
}

/// Public material approved by the genesis Device. It is safe to move between machines while
/// the corresponding private keys remain local.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnrollment {
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

/// Authenticated device membership projected from signed identity and key-generation documents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicationDevice {
    pub device_id: String,
    pub device_name: Option<String>,
    pub enrolled_generation: u32,
    pub revoked_generation: Option<u32>,
    pub is_genesis: bool,
    pub is_current: bool,
}

/// One already-sequenced local mutation. `operation_id` and `sequence` are supplied by the
/// durable outbox layer so a crash can persist and retry exactly one signed envelope.
pub(crate) struct PackageMutation<'a> {
    pub(crate) sequence: u64,
    pub(crate) operation_id: &'a str,
    /// Per-entity deltas of the committed local transaction.
    pub(crate) entities: &'a [EntityPayload],
    /// Verbatim store version files referenced by the entities, keyed by their digest.
    pub(crate) objects: &'a [PreparedObject],
}

/// Fully encrypted, signed bytes. Persist this value locally before calling `publish`; retrying a
/// crash must reuse these exact bytes instead of encrypting or signing the slot again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPublication {
    pub sequence: u64,
    pub operation_id: String,
    /// Verbatim store version files to publish under `objects/<id>.age` — never re-encrypted.
    objects: Vec<PreparedObject>,
    operation: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedObject {
    pub(crate) id: String,
    pub(crate) bytes: Vec<u8>,
}

/// A local-store mutation that must become an immutable version before the catalog outbox can
/// commit. `mutation_id` is written into that version's authenticated metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentStoreMutation {
    pub secret_id: String,
    pub mutation_id: String,
}

/// Durable pre-commit evidence for one shared mutation. It deliberately contains no plaintext;
/// secret data is recovered only through the stable local-store mutation identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationIntent {
    pub intent_id: String,
    pub logical_id: String,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default)]
    pub store_mutations: Vec<IntentStoreMutation>,
    #[serde(default)]
    pub store_versions: Vec<floria_catalog::ReplicationStoreVersionRef>,
    pub catalog_payload: Vec<u8>,
    pub created_at: String,
    #[serde(default)]
    prepared: Option<PreparedPublication>,
}

impl ReplicationIntent {
    pub fn new(
        intent_id: impl Into<String>,
        logical_id: impl Into<String>,
        parents: Vec<String>,
        store_mutations: Vec<IntentStoreMutation>,
        catalog_payload: Vec<u8>,
        created_at: impl Into<String>,
    ) -> ReplicationResult<Self> {
        let intent = Self {
            intent_id: intent_id.into(),
            logical_id: logical_id.into(),
            parents,
            store_mutations,
            store_versions: Vec::new(),
            catalog_payload,
            created_at: created_at.into(),
            prepared: None,
        };
        validate_intent(&intent)?;
        Ok(intent)
    }

    fn transaction(
        intent_id: impl Into<String>,
        parents: Vec<String>,
        store_versions: Vec<floria_catalog::ReplicationStoreVersionRef>,
        catalog_payload: Vec<u8>,
        created_at: impl Into<String>,
    ) -> ReplicationResult<Self> {
        let intent = Self {
            intent_id: intent_id.into(),
            logical_id: TRANSACTION_LOGICAL_ID.to_string(),
            parents,
            store_mutations: Vec::new(),
            store_versions,
            catalog_payload,
            created_at: created_at.into(),
            prepared: None,
        };
        validate_intent(&intent)?;
        Ok(intent)
    }

    pub fn prepared(&self) -> Option<&PreparedPublication> {
        self.prepared.as_ref()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct IntentJournalState {
    entries: Vec<ReplicationIntent>,
    #[serde(default)]
    accepted_operations: BTreeMap<String, BTreeMap<u64, String>>,
    #[serde(default)]
    accepted_key_generations: BTreeMap<u32, String>,
}

struct IntentJournalMemory {
    generation: u64,
    state: IntentJournalState,
}

/// Authenticated local crash-recovery journal. This is not the sync package and never leaves the
/// device; it bridges store/catalog/outbox commits that cannot share one physical transaction.
pub struct ReplicationIntentJournal {
    path: PathBuf,
    domain: String,
    authenticator: Arc<StateAuthenticator>,
    memory: Mutex<IntentJournalMemory>,
}

impl ReplicationIntentJournal {
    pub fn open(
        path: impl Into<PathBuf>,
        vault_id: &str,
        authenticator: Arc<StateAuthenticator>,
    ) -> ReplicationResult<Self> {
        require_uuid("vault id", vault_id)?;
        let path = path.into();
        let domain = format!("replication-intents:{vault_id}");
        let loaded = authenticator.load::<IntentJournalState>(&path, &domain)?;
        let (generation, state) = match loaded.value {
            Some(state) => (loaded.generation, state),
            None if loaded.generation == 0 => {
                let state = IntentJournalState::default();
                let generation = authenticator.persist(&path, &domain, 0, &state)?;
                (generation, state)
            }
            None => {
                return Err(ReplicationError::Invalid(format!(
                    "replication intent journal {} is missing at authenticated generation {}",
                    path.display(),
                    loaded.generation
                )))
            }
        };
        validate_journal(&state)?;
        Ok(Self {
            path,
            domain,
            authenticator,
            memory: Mutex::new(IntentJournalMemory { generation, state }),
        })
    }

    pub fn entries(&self) -> Vec<ReplicationIntent> {
        self.memory
            .lock()
            .expect("replication intent journal poisoned")
            .state
            .entries
            .clone()
    }

    pub fn device_sequence(&self, device_id: &str) -> u64 {
        self.memory
            .lock()
            .expect("replication intent journal poisoned")
            .state
            .accepted_operations
            .get(device_id)
            .and_then(|operations| operations.last_key_value().map(|(sequence, _)| *sequence))
            .unwrap_or(0)
    }

    pub fn accepted_operations(&self, device_id: &str) -> BTreeMap<u64, String> {
        self.memory
            .lock()
            .expect("replication intent journal poisoned")
            .state
            .accepted_operations
            .get(device_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn accept_key_generations(
        &self,
        generations: &BTreeMap<u32, String>,
    ) -> ReplicationResult<()> {
        self.mutate(|state| {
            for (generation, fingerprint) in &state.accepted_key_generations {
                if generations.get(generation) != Some(fingerprint) {
                    return Err(ReplicationError::Invalid(format!(
                        "accepted key generation {generation} is missing or was replaced"
                    )));
                }
            }
            for (generation, fingerprint) in generations {
                if let Some(existing) = state.accepted_key_generations.get(generation) {
                    if existing != fingerprint {
                        return Err(ReplicationError::Invalid(format!(
                            "accepted key generation {generation} was replaced"
                        )));
                    }
                    continue;
                }
                let expected = state
                    .accepted_key_generations
                    .last_key_value()
                    .map_or(Some(1), |(current, _)| current.checked_add(1))
                    .ok_or_else(|| {
                        ReplicationError::Invalid(
                            "key generation checkpoint overflow".to_string(),
                        )
                    })?;
                if *generation != expected {
                    return Err(ReplicationError::Invalid(format!(
                        "key generation checkpoint has a gap before {generation}"
                    )));
                }
                state.accepted_key_generations.insert(*generation, fingerprint.clone());
            }
            Ok(())
        })
    }

    pub fn accept_device_operation(
        &self,
        device_id: &str,
        sequence: u64,
        operation_id: &str,
    ) -> ReplicationResult<()> {
        require_uuid("device id", device_id)?;
        require_uuid("operation id", operation_id)?;
        if sequence == 0 {
            return Err(ReplicationError::Invalid(
                "device operation sequence starts at 1".to_string(),
            ));
        }
        self.mutate(|state| {
            let operations = state
                .accepted_operations
                .entry(device_id.to_string())
                .or_default();
            let expected = operations
                .last_key_value()
                .map_or(Some(1), |(current, _)| current.checked_add(1))
                .ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "device {device_id} operation sequence overflow"
                    ))
                })?;
            if operations.get(&sequence).is_some_and(|existing| existing == operation_id) {
                return Ok(());
            }
            if sequence != expected {
                return Err(ReplicationError::Invalid(format!(
                    "device {device_id} checkpoint expected sequence {expected}, got {sequence}"
                )));
            }
            operations.insert(sequence, operation_id.to_string());
            Ok(())
        })
    }

    /// Establish durable evidence before touching the encrypted store or catalog.
    pub fn enqueue(&self, intent: ReplicationIntent) -> ReplicationResult<()> {
        validate_intent(&intent)?;
        self.mutate(|state| {
            if let Some(existing) = state
                .entries
                .iter()
                .find(|existing| existing.intent_id == intent.intent_id)
            {
                if existing == &intent {
                    return Ok(());
                }
                return Err(ReplicationError::Invalid(format!(
                    "replication intent {} already names different state",
                    intent.intent_id
                )));
            }
            state.entries.push(intent);
            state.entries.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then(left.intent_id.cmp(&right.intent_id))
            });
            Ok(())
        })
    }

    /// Save the exact signed bytes before any package publication. An existing signed value can
    /// only be retried byte-for-byte.
    pub fn save_prepared(
        &self,
        intent_id: &str,
        prepared: PreparedPublication,
    ) -> ReplicationResult<()> {
        require_uuid("replication intent id", intent_id)?;
        if prepared.operation_id != intent_id {
            return Err(ReplicationError::Invalid(
                "prepared operation id does not match its durable intent".to_string(),
            ));
        }
        self.mutate(|state| {
            let intent = state
                .entries
                .iter_mut()
                .find(|intent| intent.intent_id == intent_id)
                .ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "replication intent {intent_id} does not exist"
                    ))
                })?;
            match &intent.prepared {
                Some(existing) if existing == &prepared => Ok(()),
                Some(_) => Err(ReplicationError::Invalid(format!(
                    "replication intent {intent_id} already has different signed bytes"
                ))),
                None => {
                    intent.prepared = Some(prepared);
                    Ok(())
                }
            }
        })
    }

    /// Remove a published intent. Signed-but-unpublished intents cannot use the discard path.
    pub fn complete(&self, intent_id: &str) -> ReplicationResult<()> {
        self.remove(intent_id, true)
    }

    /// Drop a business mutation proven not to have committed anywhere. Once signed, evidence is
    /// retained until publication or explicit recovery.
    pub fn discard_unsigned(&self, intent_id: &str) -> ReplicationResult<()> {
        self.remove(intent_id, false)
    }

    fn remove(&self, intent_id: &str, require_prepared: bool) -> ReplicationResult<()> {
        require_uuid("replication intent id", intent_id)?;
        self.mutate(|state| {
            let index = state
                .entries
                .iter()
                .position(|intent| intent.intent_id == intent_id)
                .ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "replication intent {intent_id} does not exist"
                    ))
                })?;
            let prepared = state.entries[index].prepared.is_some();
            if require_prepared && !prepared {
                return Err(ReplicationError::Invalid(format!(
                    "replication intent {intent_id} has not been signed"
                )));
            }
            if !require_prepared && prepared {
                return Err(ReplicationError::Invalid(format!(
                    "signed replication intent {intent_id} cannot be discarded"
                )));
            }
            state.entries.remove(index);
            Ok(())
        })
    }

    fn mutate(
        &self,
        operation: impl FnOnce(&mut IntentJournalState) -> ReplicationResult<()>,
    ) -> ReplicationResult<()> {
        let mut memory = self.memory.lock().expect("replication intent journal poisoned");
        let mut next = memory.state.clone();
        operation(&mut next)?;
        validate_journal(&next)?;
        let generation = self.authenticator.persist(
            &self.path,
            &self.domain,
            memory.generation,
            &next,
        )?;
        memory.generation = generation;
        memory.state = next;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMutation {
    pub device_id: String,
    pub key_generation: u32,
    pub sequence: u64,
    pub operation_id: String,
    /// Decrypted, validated per-entity payload. Object bytes are NOT here — they stay verbatim
    /// in `objects/` and are handed to the store during import.
    payload: OperationPayload,
}

impl VerifiedMutation {
    fn entity_ids(&self) -> impl Iterator<Item = &str> {
        self.payload.entities.iter().map(|entity| entity.logical_id.as_str())
    }

    fn all_parents(&self) -> impl Iterator<Item = &str> {
        self.payload
            .entities
            .iter()
            .flat_map(|entity| entity.parents.iter().map(String::as_str))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOperation {
    pub device_id: String,
    pub sequence: u64,
    pub operation_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DamagedFile {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalConflict {
    pub logical_id: String,
    pub head_operation_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedOperation {
    pub device_id: String,
    pub sequence: u64,
    pub operation_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackageScan {
    /// Every unique, validly signed slot, including operations whose object is still pending or
    /// damaged. Self-fencing must use this set rather than only successfully materialized values.
    pub observed: Vec<ObservedOperation>,
    pub verified: Vec<VerifiedMutation>,
    pub pending: Vec<PendingOperation>,
    pub damaged: Vec<DamagedFile>,
    /// Logical items with more than one causally valid head. Their mutations remain verified but
    /// are not projected until one signed merge operation names every head as a parent.
    pub conflicts: Vec<LogicalConflict>,
    /// Devices whose valid signed history is internally inconsistent and must not publish.
    pub fenced_devices: Vec<String>,
    pub duplicate_files: usize,
}

#[derive(Serialize, Deserialize)]
struct VaultUnsigned {
    format_version: u32,
    vault_id: String,
    genesis_device_id: String,
    genesis_public_key: String,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
struct VaultDocument {
    format_version: u32,
    vault_id: String,
    genesis_device_id: String,
    genesis_public_key: String,
    created_at: String,
    signature: String,
}

impl VaultDocument {
    fn unsigned(&self) -> VaultUnsigned {
        VaultUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            genesis_device_id: self.genesis_device_id.clone(),
            genesis_public_key: self.genesis_public_key.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
struct DeviceUnsigned {
    format_version: u32,
    vault_id: String,
    device_id: String,
    signing_public_key: String,
    wrapping_recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    authorized_by: String,
    enrolled_generation: u32,
}

#[derive(Serialize, Deserialize)]
struct DeviceDocument {
    format_version: u32,
    vault_id: String,
    device_id: String,
    signing_public_key: String,
    wrapping_recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    authorized_by: String,
    enrolled_generation: u32,
    signature: String,
}

impl DeviceDocument {
    fn unsigned(&self) -> DeviceUnsigned {
        DeviceUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
            signing_public_key: self.signing_public_key.clone(),
            wrapping_recipient: self.wrapping_recipient.clone(),
            device_name: self.device_name.clone(),
            authorized_by: self.authorized_by.clone(),
            enrolled_generation: self.enrolled_generation,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct KeyGenerationUnsigned {
    format_version: u32,
    vault_id: String,
    generation: u32,
    previous_generation: Option<u32>,
    authorized_by: String,
    envelopes: BTreeMap<String, String>,
    revoked_devices: BTreeMap<String, u64>,
    /// The vault-wide recovery recipient every store encrypts to (from the genesis store).
    recovery_public: String,
}

#[derive(Serialize, Deserialize)]
struct KeyGenerationDocument {
    format_version: u32,
    vault_id: String,
    generation: u32,
    previous_generation: Option<u32>,
    authorized_by: String,
    envelopes: BTreeMap<String, String>,
    revoked_devices: BTreeMap<String, u64>,
    recovery_public: String,
    signature: String,
}

impl KeyGenerationDocument {
    fn unsigned(&self) -> KeyGenerationUnsigned {
        KeyGenerationUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            generation: self.generation,
            previous_generation: self.previous_generation,
            authorized_by: self.authorized_by.clone(),
            envelopes: self.envelopes.clone(),
            revoked_devices: self.revoked_devices.clone(),
            recovery_public: self.recovery_public.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct OperationUnsigned {
    format_version: u32,
    vault_id: String,
    device_id: String,
    key_generation: u32,
    sequence: u64,
    operation_id: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct OperationDocument {
    format_version: u32,
    vault_id: String,
    device_id: String,
    key_generation: u32,
    sequence: u64,
    operation_id: String,
    ciphertext: String,
    signature: String,
}

impl OperationDocument {
    fn unsigned(&self) -> OperationUnsigned {
        OperationUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
            key_generation: self.key_generation,
            sequence: self.sequence,
            operation_id: self.operation_id.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }
}

/// The encrypted business payload of one operation: the entity-level deltas of a single
/// committed local transaction. Secret content never rides in the payload — version bytes are
/// verbatim store files published as objects and referenced by digest (invariants 13/14 in
/// `docs/design/portable-replication.md`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OperationPayload {
    format_version: u32,
    entities: Vec<EntityPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct EntityPayload {
    /// Shared entity UUID (a secret id), or [`CATALOG_LOGICAL_ID`] for the transitional
    /// whole-catalog metadata entity.
    logical_id: String,
    /// Head operation ids of THIS entity that the delta builds on.
    parents: Vec<String>,
    delta: EntityDelta,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum EntityDelta {
    Secret(SecretDelta),
    /// Serialized `ReplicatedCatalog` (metadata only). Transitional single entity until catalog
    /// rows become individual entities.
    Catalog { payload: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SecretDelta {
    descriptor: ExportStoreDescriptor,
    /// New immutable versions introduced by this operation, oldest first.
    versions: Vec<SecretVersionRef>,
    /// The version the head points at after applying this delta.
    head_uuid: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SecretVersionRef {
    version_uuid: String,
    generation: u32,
    size: u64,
    object: ObjectReference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ObjectReference {
    id: String,
    ciphertext_size: u64,
}

/// Immutable package-format module. It deliberately has no transport adapter: a normal directory
/// is the only production representation in v1.
pub struct ReplicationPackage {
    root: PathBuf,
    vault: VaultDocument,
    device: DeviceKeyMaterial,
    metadata: RwLock<PackageMetadata>,
}

struct PackageMetadata {
    vault_identities: BTreeMap<u32, Arc<x25519::Identity>>,
    current_generation: u32,
    generation_fingerprints: BTreeMap<u32, String>,
    trusted_devices: HashMap<String, TrustedDevice>,
    /// From the highest signed key-generation document.
    recovery_public: String,
}

#[derive(Clone)]
struct TrustedDevice {
    verifying_key: VerifyingKey,
    wrapping_recipient: x25519::Recipient,
    device_name: Option<String>,
    enrolled_generation: u32,
    revoked_generation: Option<u32>,
    revoked_after_sequence: Option<u64>,
}

impl ReplicationPackage {
    pub fn create(
        root: impl Into<PathBuf>,
        vault_id: impl Into<String>,
        created_at: impl Into<String>,
        device: DeviceKeyMaterial,
        vault_identity: x25519::Identity,
        recovery_public: String,
    ) -> ReplicationResult<Self> {
        Self::create_named(
            root,
            vault_id,
            created_at,
            device,
            None,
            vault_identity,
            recovery_public,
        )
    }

    /// Create the vault. Generation 1's identity comes from the genesis store (`keys/1`), so the
    /// version files that store already wrote are decryptable by every enrolled device — the
    /// zero-transcode property depends on this single key domain.
    pub fn create_named(
        root: impl Into<PathBuf>,
        vault_id: impl Into<String>,
        created_at: impl Into<String>,
        device: DeviceKeyMaterial,
        device_name: Option<String>,
        vault_identity: x25519::Identity,
        recovery_public: String,
    ) -> ReplicationResult<Self> {
        let root = root.into();
        let vault_id = vault_id.into();
        require_uuid("vault id", &vault_id)?;
        if path_exists(&root)? {
            return Err(ReplicationError::Invalid(format!(
                "replication package already exists at {}",
                root.display()
            )));
        }
        let parent = root.parent().ok_or_else(|| {
            ReplicationError::Invalid(format!("{} has no parent directory", root.display()))
        })?;
        let temporary = parent.join(format!(".floria-vault-{}.tmp", uuid::Uuid::new_v4()));
        create_private_directory(&temporary)?;

        let result = (|| {
            create_private_directory(&temporary.join("devices"))?;
            create_private_directory(&temporary.join("generations"))?;
            create_private_directory(&temporary.join("operations"))?;
            create_private_directory(&temporary.join("objects"))?;
            create_private_directory(&temporary.join("checkpoints"))?;

            let unsigned = VaultUnsigned {
                format_version: FORMAT_VERSION,
                vault_id: vault_id.clone(),
                genesis_device_id: device.device_id.clone(),
                genesis_public_key: encode(device.verifying_key().as_bytes()),
                created_at: created_at.into(),
            };
            let signature = sign_struct(VAULT_SIGNATURE_CONTEXT, &unsigned, &device.signing_key)?;
            let vault = VaultDocument {
                format_version: unsigned.format_version,
                vault_id: unsigned.vault_id,
                genesis_device_id: unsigned.genesis_device_id,
                genesis_public_key: unsigned.genesis_public_key,
                created_at: unsigned.created_at,
                signature,
            };
            write_new_atomic(
                &temporary.join("vault.json"),
                &serde_json::to_vec_pretty(&vault)?,
            )?;

            let device_directory = temporary.join("devices").join(&device.device_id);
            create_private_directory(&device_directory)?;
            create_private_directory(&device_directory.join("envelopes"))?;
            create_private_directory(&temporary.join("operations").join(&device.device_id))?;
            create_private_directory(&temporary.join("checkpoints").join(&device.device_id))?;
            write_device_identity(
                &device_directory.join("identity.json"),
                &vault,
                &device.enrollment_named(device_name.clone()),
                1,
                &device.signing_key,
            )?;
            write_vault_envelope(
                &device_directory.join("envelopes/1.age"),
                &vault_identity,
                &device.wrapping_identity.to_public(),
            )?;
            write_key_generation(
                &temporary.join("generations").join(generation_filename(1)),
                &vault,
                1,
                None,
                &vault_identity,
                &BTreeMap::from([(
                    device.device_id.clone(),
                    device.wrapping_identity.to_public(),
                )]),
                BTreeMap::new(),
                &recovery_public,
                &device.signing_key,
            )?;
            sync_directory(&temporary)?;
            rename_directory_exclusive(&temporary, &root)?;
            sync_directory(parent)?;
            Ok(vault)
        })();
        let vault = match result {
            Ok(vault) => vault,
            Err(error) => {
                let _ = fs::remove_dir_all(&temporary);
                return Err(error);
            }
        };

        let generations = load_key_generations(&root, &vault)?;
        let generation_fingerprints = key_generation_fingerprints(&generations)?;
        let trusted_devices = HashMap::from([(
            device.device_id.clone(),
            TrustedDevice {
                verifying_key: device.verifying_key(),
                wrapping_recipient: device.wrapping_identity.to_public(),
                device_name,
                enrolled_generation: 1,
                revoked_generation: None,
                revoked_after_sequence: None,
            },
        )]);
        let vault_identities = BTreeMap::from([(1, Arc::new(vault_identity))]);
        Ok(Self {
            root,
            vault,
            device,
            metadata: RwLock::new(PackageMetadata {
                vault_identities,
                current_generation: 1,
                generation_fingerprints,
                trusted_devices,
                recovery_public,
            }),
        })
    }

    pub fn open(
        root: impl Into<PathBuf>,
        device: DeviceKeyMaterial,
    ) -> ReplicationResult<Self> {
        let root = root.into();
        let bytes = read_untrusted_file(&root.join("vault.json"), MAX_DESCRIPTOR_BYTES)?;
        let vault: VaultDocument = serde_json::from_slice(&bytes)?;
        validate_vault(&vault)?;
        let metadata = load_package_metadata(&root, &vault, &device)?;
        Ok(Self {
            root,
            vault,
            device,
            metadata: RwLock::new(metadata),
        })
    }

    /// Authorize another Device without copying either Device's private keys. Only the genesis
    /// Device may extend the enrollment set in v1; the signed identity and encrypted Vault-key
    /// envelope are published together as one immutable directory.
    pub fn enroll_device(&mut self, enrollment: DeviceEnrollment) -> ReplicationResult<()> {
        if self.device.device_id != self.vault.genesis_device_id {
            return Err(ReplicationError::Invalid(
                "only the genesis Device may enroll another Device".to_string(),
            ));
        }
        validate_enrollment(&enrollment)?;
        self.refresh_metadata()?;
        let (current_generation, vault_identities, revoked) = {
            let metadata = self.metadata.read().expect("replication metadata poisoned");
            (
                metadata.current_generation,
                metadata.vault_identities.clone(),
                metadata
                    .trusted_devices
                    .get(&enrollment.device_id)
                    .and_then(|device| device.revoked_generation),
            )
        };
        if revoked.is_some() {
            return Err(ReplicationError::Invalid(format!(
                "revoked Device {} must re-enroll with a new Device id",
                enrollment.device_id
            )));
        }

        let devices_root = self.root.join("devices");
        let target = devices_root.join(&enrollment.device_id);
        if path_exists(&target)? {
            let existing = read_device_identity(&target.join("identity.json"), &self.vault)?;
            if existing.device_id != enrollment.device_id
                || existing.signing_public_key != enrollment.signing_public_key
                || existing.wrapping_recipient != enrollment.wrapping_recipient
            {
                return Err(ReplicationError::Invalid(format!(
                    "device {} is already enrolled with different public keys",
                    enrollment.device_id
                )));
            }
            read_untrusted_file(&target.join("envelopes/1.age"), MAX_DESCRIPTOR_BYTES)?;
            self.ensure_device_directories(&enrollment.device_id)?;
            return self.refresh_metadata();
        }

        let temporary = devices_root.join(format!(
            ".device-{}-{}.tmp",
            enrollment.device_id,
            uuid::Uuid::new_v4()
        ));
        create_private_directory(&temporary)?;
        let result = (|| {
            create_private_directory(&temporary.join("envelopes"))?;
            write_device_identity(
                &temporary.join("identity.json"),
                &self.vault,
                &enrollment,
                current_generation,
                &self.device.signing_key,
            )?;
            let recipient = enrollment
                .wrapping_recipient
                .parse::<x25519::Recipient>()
                .map_err(|error| {
                    ReplicationError::Invalid(format!(
                        "invalid Device wrapping recipient: {error}"
                    ))
                })?;
            for (generation, vault_identity) in &vault_identities {
                write_vault_envelope(
                    &temporary.join("envelopes").join(envelope_filename(*generation)),
                    vault_identity.as_ref(),
                    &recipient,
                )?;
            }
            sync_directory(&temporary)?;
            rename_directory_exclusive(&temporary, &target)?;
            sync_directory(&devices_root)
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&temporary);
            return Err(error);
        }

        self.ensure_device_directories(&enrollment.device_id)?;
        self.refresh_metadata()
    }

    /// Revoke a non-genesis Device and rotate the Vault data key. The signed generation document
    /// atomically binds the new envelopes to the revoked Device's final accepted sequence.
    pub fn revoke_device(
        &self,
        device_id: &str,
        next_identity: x25519::Identity,
        recovery_public: &str,
    ) -> ReplicationResult<u32> {
        if self.device.device_id != self.vault.genesis_device_id {
            return Err(ReplicationError::Invalid(
                "only the genesis Device may revoke another Device".to_string(),
            ));
        }
        require_uuid("revoked Device id", device_id)?;
        if device_id == self.vault.genesis_device_id {
            return Err(ReplicationError::Invalid(
                "v1 cannot revoke the genesis Device".to_string(),
            ));
        }
        let scan = self.scan()?;
        let final_sequence = scan
            .observed
            .iter()
            .filter(|operation| operation.device_id == device_id)
            .map(|operation| operation.sequence)
            .max()
            .unwrap_or(0);
        let (current_generation, generation, recipients) = {
            let metadata = self.metadata.read().expect("replication metadata poisoned");
            let target = metadata.trusted_devices.get(device_id).ok_or_else(|| {
                ReplicationError::Invalid(format!("Device {device_id} is not enrolled"))
            })?;
            if target.revoked_generation.is_some() {
                return Err(ReplicationError::Invalid(format!(
                    "Device {device_id} is already revoked"
                )));
            }
            let generation = metadata.current_generation.checked_add(1).ok_or_else(|| {
                ReplicationError::Invalid("Vault key generation overflow".to_string())
            })?;
            let recipients = metadata
                .trusted_devices
                .iter()
                .filter(|(candidate_id, device)| {
                    candidate_id.as_str() != device_id && device.revoked_generation.is_none()
                })
                .map(|(candidate_id, device)| {
                    (candidate_id.clone(), device.wrapping_recipient.clone())
                })
                .collect::<BTreeMap<_, _>>();
            (metadata.current_generation, generation, recipients)
        };
        write_key_generation(
            &self
                .root
                .join("generations")
                .join(generation_filename(generation)),
            &self.vault,
            generation,
            Some(current_generation),
            &next_identity,
            &recipients,
            BTreeMap::from([(device_id.to_string(), final_sequence)]),
            recovery_public,
            &self.device.signing_key,
        )?;
        self.refresh_metadata()?;
        Ok(generation)
    }

    /// Every generation identity this device can unwrap, as wrappable secret strings
    /// (for installing into the local store when joining a vault).
    fn generation_identity_secrets(&self) -> Vec<(u32, Zeroizing<String>)> {
        self.metadata
            .read()
            .expect("replication metadata poisoned")
            .vault_identities
            .iter()
            .map(|(generation, identity)| {
                (
                    *generation,
                    Zeroizing::new(identity.to_string().expose_secret().clone()),
                )
            })
            .collect()
    }

    fn recovery_public(&self) -> String {
        self.metadata
            .read()
            .expect("replication metadata poisoned")
            .recovery_public
            .clone()
    }

    pub fn vault_id(&self) -> &str {
        &self.vault.vault_id
    }

    pub fn current_generation(&self) -> u32 {
        self.metadata
            .read()
            .expect("replication metadata poisoned")
            .current_generation
    }

    pub fn devices(&self) -> Vec<ReplicationDevice> {
        let metadata = self.metadata.read().expect("replication metadata poisoned");
        let mut devices = metadata
            .trusted_devices
            .iter()
            .map(|(device_id, device)| ReplicationDevice {
                device_id: device_id.clone(),
                device_name: device.device_name.clone(),
                enrolled_generation: device.enrolled_generation,
                revoked_generation: device.revoked_generation,
                is_genesis: device_id == &self.vault.genesis_device_id,
                is_current: device_id == &self.device.device_id,
            })
            .collect::<Vec<_>>();
        devices.sort_by(|left, right| {
            right
                .is_current
                .cmp(&left.is_current)
                .then(right.is_genesis.cmp(&left.is_genesis))
                .then(left.revoked_generation.is_some().cmp(&right.revoked_generation.is_some()))
                .then(left.device_name.cmp(&right.device_name))
                .then(left.device_id.cmp(&right.device_id))
        });
        devices
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn device_id(&self) -> &str {
        &self.device.device_id
    }

    fn generation_fingerprints(&self) -> BTreeMap<u32, String> {
        self.metadata
            .read()
            .expect("replication metadata poisoned")
            .generation_fingerprints
            .clone()
    }

    fn refresh_metadata(&self) -> ReplicationResult<()> {
        let refreshed = load_package_metadata(&self.root, &self.vault, &self.device)?;
        *self.metadata.write().expect("replication metadata poisoned") = refreshed;
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        mutation: PackageMutation<'_>,
    ) -> ReplicationResult<PreparedPublication> {
        self.refresh_metadata()?;
        if mutation.sequence == 0 {
            return Err(ReplicationError::Invalid(
                "operation sequence starts at 1".to_string(),
            ));
        }
        require_uuid("operation id", mutation.operation_id)?;
        validate_entities(mutation.operation_id, mutation.entities)?;
        // Every referenced object must be supplied verbatim with a matching digest and size;
        // unreferenced objects must not ride along.
        let mut referenced: HashMap<&str, u64> = HashMap::new();
        for entity in mutation.entities {
            if let EntityDelta::Secret(delta) = &entity.delta {
                for version in &delta.versions {
                    if referenced
                        .insert(&version.object.id, version.object.ciphertext_size)
                        .is_some()
                    {
                        return Err(ReplicationError::Invalid(format!(
                            "operation {} references object {} twice",
                            mutation.operation_id, version.object.id
                        )));
                    }
                }
            }
        }
        if referenced.len() != mutation.objects.len() {
            return Err(ReplicationError::Invalid(format!(
                "operation {} supplies {} object(s) but references {}",
                mutation.operation_id,
                mutation.objects.len(),
                referenced.len()
            )));
        }
        for object in mutation.objects {
            if digest(&object.bytes) != object.id {
                return Err(ReplicationError::Invalid(format!(
                    "supplied object {} does not match its digest",
                    object.id
                )));
            }
            match referenced.get(object.id.as_str()) {
                Some(size) if *size == object.bytes.len() as u64 => {}
                Some(_) => {
                    return Err(ReplicationError::Invalid(format!(
                        "supplied object {} does not match its referenced size",
                        object.id
                    )))
                }
                None => {
                    return Err(ReplicationError::Invalid(format!(
                        "supplied object {} is not referenced by any entity",
                        object.id
                    )))
                }
            }
        }
        let (current_generation, vault_identity) = {
            let metadata = self.metadata.read().expect("replication metadata poisoned");
            let identity = metadata
                .vault_identities
                .get(&metadata.current_generation)
                .cloned()
                .ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "local Device cannot decrypt current key generation {}",
                        metadata.current_generation
                    ))
                })?;
            (metadata.current_generation, identity)
        };
        let vault_recipient = vault_identity.to_public();
        let payload = OperationPayload {
            format_version: PAYLOAD_FORMAT_VERSION,
            entities: mutation.entities.to_vec(),
        };
        let ciphertext = encrypt(&vault_recipient, &serde_json::to_vec(&payload)?)?;
        let unsigned = OperationUnsigned {
            format_version: FORMAT_VERSION,
            vault_id: self.vault.vault_id.clone(),
            device_id: self.device.device_id.clone(),
            key_generation: current_generation,
            sequence: mutation.sequence,
            operation_id: mutation.operation_id.to_string(),
            ciphertext: encode(&ciphertext),
        };
        let signature = sign_struct(
            OPERATION_SIGNATURE_CONTEXT,
            &unsigned,
            &self.device.signing_key,
        )?;
        let operation = serde_json::to_vec(&OperationDocument {
            format_version: unsigned.format_version,
            vault_id: unsigned.vault_id,
            device_id: unsigned.device_id,
            key_generation: unsigned.key_generation,
            sequence: unsigned.sequence,
            operation_id: unsigned.operation_id.clone(),
            ciphertext: unsigned.ciphertext,
            signature,
        })?;
        Ok(PreparedPublication {
            sequence: mutation.sequence,
            operation_id: unsigned.operation_id,
            objects: mutation.objects.to_vec(),
            operation,
        })
    }

    /// Publish every Object before the Operation. Existing identical immutable bytes are
    /// accepted; a colliding canonical path with different bytes is never overwritten.
    pub fn publish(&self, prepared: &PreparedPublication) -> ReplicationResult<()> {
        self.refresh_metadata()?;
        self.verify_prepared(prepared)?;
        for object in &prepared.objects {
            publish_immutable(
                &self.root.join("objects").join(format!("{}.age", object.id)),
                &object.bytes,
            )?;
        }
        publish_immutable(&self.operation_path(prepared), &prepared.operation)?;
        Ok(())
    }

    /// Read one verified object's verbatim bytes (digest re-checked).
    fn read_object(&self, id: &str) -> ReplicationResult<Vec<u8>> {
        let path = self.root.join("objects").join(format!("{id}.age"));
        let bytes = read_untrusted_file(&path, MAX_OBJECT_BYTES)?;
        if digest(&bytes) != id {
            return Err(ReplicationError::Invalid(format!(
                "object {id} does not match its digest"
            )));
        }
        Ok(bytes)
    }

    pub fn scan(&self) -> ReplicationResult<PackageScan> {
        self.refresh_metadata()?;
        let mut report = PackageScan::default();
        let objects = scan_objects(&self.root.join("objects"), &mut report)?;
        let operations_root = self.root.join("operations");
        let mut slots: BTreeMap<(String, u64), (PathBuf, Vec<u8>, OperationDocument)> =
            BTreeMap::new();
        let mut operation_ids: HashMap<String, (Vec<u8>, String)> = HashMap::new();
        let mut equivocated = HashSet::new();

        for path in regular_files_recursively(&operations_root)? {
            let bytes = match read_untrusted_file(&path, MAX_OPERATION_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    report.damaged.push(DamagedFile { path, reason: error.to_string() });
                    continue;
                }
            };
            let operation: OperationDocument = match serde_json::from_slice(&bytes) {
                Ok(operation) => operation,
                Err(error) => {
                    report.damaged.push(DamagedFile {
                        path,
                        reason: format!("operation JSON is invalid: {error}"),
                    });
                    continue;
                }
            };
            if let Err(error) = self.validate_operation(&operation) {
                report.damaged.push(DamagedFile { path, reason: error.to_string() });
                continue;
            }
            if let Some((existing, existing_device_id)) =
                operation_ids.get(&operation.operation_id)
            {
                if existing == &bytes {
                    report.duplicate_files += 1;
                    continue;
                }
                report.damaged.push(DamagedFile {
                    path,
                    reason: format!(
                        "operation id {} has multiple valid envelopes",
                        operation.operation_id
                    ),
                });
                report.fenced_devices.push(existing_device_id.clone());
                report.fenced_devices.push(operation.device_id.clone());
                continue;
            }
            operation_ids.insert(
                operation.operation_id.clone(),
                (bytes.clone(), operation.device_id.clone()),
            );
            let slot = (operation.device_id.clone(), operation.sequence);
            if equivocated.contains(&slot) {
                report.damaged.push(DamagedFile {
                    path,
                    reason: format!(
                        "device {} equivocated at sequence {}",
                        operation.device_id, operation.sequence
                    ),
                });
                continue;
            }
            if let Some((existing_path, existing_bytes, _)) = slots.get(&slot) {
                if existing_bytes == &bytes {
                    report.duplicate_files += 1;
                } else {
                    report.damaged.push(DamagedFile {
                        path: existing_path.clone(),
                        reason: format!(
                            "device {} equivocated at sequence {}",
                            operation.device_id, operation.sequence
                        ),
                    });
                    report.damaged.push(DamagedFile {
                        path,
                        reason: format!(
                            "device {} equivocated at sequence {}",
                            operation.device_id, operation.sequence
                        ),
                    });
                    report.fenced_devices.push(operation.device_id.clone());
                    slots.remove(&slot);
                    equivocated.insert(slot);
                }
                continue;
            }
            slots.insert(slot, (path, bytes, operation));
        }

        let mut expected_sequences: HashMap<String, u64> = HashMap::new();
        for ((device_id, sequence), (path, _, operation)) in slots {
            report.observed.push(ObservedOperation {
                device_id: device_id.clone(),
                sequence,
                operation_id: operation.operation_id.clone(),
            });
            let expected = expected_sequences.entry(device_id.clone()).or_insert(1);
            if sequence != *expected {
                report.pending.push(PendingOperation {
                    device_id,
                    sequence,
                    operation_id: operation.operation_id,
                    reason: format!("sequence {} has not arrived", *expected),
                });
                continue;
            }
            if self.materialize_verified(path, operation, &objects, &mut report)? {
                *expected += 1;
            }
        }
        report.verified.sort_by(|left, right| {
            left.device_id
                .cmp(&right.device_id)
                .then(left.sequence.cmp(&right.sequence))
        });
        resolve_logical_history(&mut report);
        report.observed.sort_by(|left, right| {
            left.device_id
                .cmp(&right.device_id)
                .then(left.sequence.cmp(&right.sequence))
        });
        report.fenced_devices.sort();
        report.fenced_devices.dedup();
        Ok(report)
    }

    fn operation_path(&self, prepared: &PreparedPublication) -> PathBuf {
        self.root
            .join("operations")
            .join(&self.device.device_id)
            .join(format!(
                "{:020}-{}.op",
                prepared.sequence, prepared.operation_id
            ))
    }

    fn ensure_device_directories(&self, device_id: &str) -> ReplicationResult<()> {
        ensure_private_package_directory(&self.root.join("operations").join(device_id))?;
        ensure_private_package_directory(&self.root.join("checkpoints").join(device_id))
    }

    fn verify_prepared(&self, prepared: &PreparedPublication) -> ReplicationResult<()> {
        for object in &prepared.objects {
            if digest(&object.bytes) != object.id {
                return Err(ReplicationError::Invalid(
                    "prepared object digest does not match its id".to_string(),
                ));
            }
        }
        let operation: OperationDocument = serde_json::from_slice(&prepared.operation)?;
        self.validate_operation(&operation)?;
        if operation.sequence != prepared.sequence
            || operation.operation_id != prepared.operation_id
        {
            return Err(ReplicationError::Invalid(
                "prepared publication metadata does not match its signed operation".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_operation(&self, operation: &OperationDocument) -> ReplicationResult<()> {
        if operation.format_version != FORMAT_VERSION {
            return Err(ReplicationError::Invalid(format!(
                "unsupported operation format {}",
                operation.format_version
            )));
        }
        if operation.vault_id != self.vault.vault_id {
            return Err(ReplicationError::Invalid(
                "operation belongs to a different Vault".to_string(),
            ));
        }
        let metadata = self.metadata.read().expect("replication metadata poisoned");
        let device_key = metadata.trusted_devices.get(&operation.device_id).ok_or_else(|| {
            ReplicationError::Invalid(format!(
                "operation device {} is not enrolled",
                operation.device_id
            ))
        })?;
        if operation.key_generation == 0 || operation.key_generation > metadata.current_generation {
            return Err(ReplicationError::Invalid(format!(
                "operation names unavailable key generation {}",
                operation.key_generation
            )));
        }
        if operation.key_generation < device_key.enrolled_generation
            || device_key
                .revoked_generation
                .is_some_and(|generation| operation.key_generation >= generation)
            || device_key
                .revoked_after_sequence
                .is_some_and(|sequence| operation.sequence > sequence)
        {
            return Err(ReplicationError::Invalid(format!(
                "operation device {} is not authorized for key generation {}",
                operation.device_id, operation.key_generation
            )));
        }
        require_uuid("operation id", &operation.operation_id)?;
        if operation.sequence == 0 {
            return Err(ReplicationError::Invalid(
                "operation sequence starts at 1".to_string(),
            ));
        }
        verify_struct(
            OPERATION_SIGNATURE_CONTEXT,
            &operation.unsigned(),
            &operation.signature,
            &device_key.verifying_key,
        )
    }

    fn materialize_verified(
        &self,
        operation_path: PathBuf,
        operation: OperationDocument,
        objects: &HashMap<String, Vec<u8>>,
        report: &mut PackageScan,
    ) -> ReplicationResult<bool> {
        let vault_identity = self
            .metadata
            .read()
            .expect("replication metadata poisoned")
            .vault_identities
            .get(&operation.key_generation)
            .cloned();
        let Some(vault_identity) = vault_identity else {
            report.pending.push(PendingOperation {
                device_id: operation.device_id,
                sequence: operation.sequence,
                operation_id: operation.operation_id,
                reason: format!(
                    "key generation {} envelope has not arrived",
                    operation.key_generation
                ),
            });
            return Ok(false);
        };
        let ciphertext = decode("operation ciphertext", &operation.ciphertext)?;
        let plaintext = match decrypt(vault_identity.as_ref(), &ciphertext) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                report.damaged.push(DamagedFile {
                    path: operation_path,
                    reason: error.to_string(),
                });
                return Ok(false);
            }
        };
        let payload: OperationPayload = match serde_json::from_slice(&plaintext) {
            Ok(payload) => payload,
            Err(error) => {
                report.damaged.push(DamagedFile {
                    path: operation_path,
                    reason: format!("operation payload is invalid: {error}"),
                });
                return Ok(false);
            }
        };
        if payload.format_version != PAYLOAD_FORMAT_VERSION {
            report.damaged.push(DamagedFile {
                path: operation_path,
                reason: format!(
                    "unsupported operation payload format {}",
                    payload.format_version
                ),
            });
            return Ok(false);
        }
        if let Err(error) = validate_entities(&operation.operation_id, &payload.entities) {
            report.damaged.push(DamagedFile {
                path: operation_path,
                reason: error.to_string(),
            });
            return Ok(false);
        }
        // Objects are the verbatim store version files: presence and digest/size are checked
        // here, decryption and payload binding are the importing store's job.
        for entity in &payload.entities {
            let EntityDelta::Secret(delta) = &entity.delta else { continue };
            for version in &delta.versions {
                let Some(object) = objects.get(&version.object.id) else {
                    report.pending.push(PendingOperation {
                        device_id: operation.device_id,
                        sequence: operation.sequence,
                        operation_id: operation.operation_id,
                        reason: format!("object {} has not arrived", version.object.id),
                    });
                    return Ok(false);
                };
                if object.len() as u64 != version.object.ciphertext_size {
                    report.damaged.push(DamagedFile {
                        path: self
                            .root
                            .join("objects")
                            .join(format!("{}.age", version.object.id)),
                        reason: format!("object {} has the wrong size", version.object.id),
                    });
                    return Ok(false);
                }
            }
        }
        report.verified.push(VerifiedMutation {
            device_id: operation.device_id,
            key_generation: operation.key_generation,
            sequence: operation.sequence,
            operation_id: operation.operation_id,
            payload,
        });
        Ok(true)
    }
}

/// Shared structural validation of a v2 entity list (used by prepare and by import).
fn validate_entities(operation_id: &str, entities: &[EntityPayload]) -> ReplicationResult<()> {
    if entities.is_empty() {
        return Err(ReplicationError::Invalid(format!(
            "operation {operation_id} contains no entities"
        )));
    }
    let mut seen = HashSet::new();
    for entity in entities {
        if entity.logical_id.is_empty() {
            return Err(ReplicationError::Invalid(format!(
                "operation {operation_id} contains an entity with an empty logical id"
            )));
        }
        if !seen.insert(entity.logical_id.as_str()) {
            return Err(ReplicationError::Invalid(format!(
                "operation {operation_id} names entity {} twice",
                entity.logical_id
            )));
        }
        let mut unique_parents = HashSet::new();
        for parent in &entity.parents {
            require_uuid("parent operation id", parent)?;
            if parent == operation_id || !unique_parents.insert(parent.as_str()) {
                return Err(ReplicationError::Invalid(format!(
                    "operation {operation_id} has an invalid or duplicate parent {parent}"
                )));
            }
        }
        match &entity.delta {
            EntityDelta::Secret(delta) => {
                if entity.logical_id.parse::<SecretId>().is_err() {
                    return Err(ReplicationError::Invalid(format!(
                        "operation {operation_id} secret entity has a non-uuid id {}",
                        entity.logical_id
                    )));
                }
                if delta.head_uuid.is_empty() {
                    return Err(ReplicationError::Invalid(format!(
                        "operation {operation_id} secret entity {} has no head",
                        entity.logical_id
                    )));
                }
                let mut uuids = HashSet::new();
                for version in &delta.versions {
                    if version.version_uuid.is_empty()
                        || version.generation == 0
                        || version.object.id.is_empty()
                        || !uuids.insert(version.version_uuid.as_str())
                    {
                        return Err(ReplicationError::Invalid(format!(
                            "operation {operation_id} secret entity {} has an invalid version",
                            entity.logical_id
                        )));
                    }
                }
            }
            EntityDelta::Catalog { payload } => {
                if entity.logical_id != CATALOG_LOGICAL_ID {
                    return Err(ReplicationError::Invalid(format!(
                        "operation {operation_id} catalog entity has unexpected id {}",
                        entity.logical_id
                    )));
                }
                if payload.is_empty() {
                    return Err(ReplicationError::Invalid(format!(
                        "operation {operation_id} catalog entity has an empty payload"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn resolve_logical_history(report: &mut PackageScan) {
    let candidates = std::mem::take(&mut report.verified);
    // An operation may touch several entities; each entity declares its own parents. A parent
    // is valid for an entity only if that parent operation itself touches the same entity.
    let ownership = candidates
        .iter()
        .map(|mutation| {
            (
                mutation.operation_id.clone(),
                mutation.entity_ids().map(str::to_owned).collect::<HashSet<_>>(),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut remaining = Vec::with_capacity(candidates.len());
    for mutation in candidates {
        let problem = mutation.payload.entities.iter().find_map(|entity| {
            entity.parents.iter().find_map(|parent| match ownership.get(parent) {
                None => Some(format!("parent operation {parent} has not arrived")),
                Some(entities) if !entities.contains(&entity.logical_id) => Some(format!(
                    "parent operation {parent} does not touch entity {}",
                    entity.logical_id
                )),
                Some(_) => None,
            })
        });
        if let Some(reason) = problem {
            report.pending.push(PendingOperation {
                device_id: mutation.device_id,
                sequence: mutation.sequence,
                operation_id: mutation.operation_id,
                reason,
            });
        } else {
            remaining.push(mutation);
        }
    }

    let mut emitted = HashSet::new();
    let mut ordered = Vec::with_capacity(remaining.len());
    while let Some(index) = remaining
        .iter()
        .position(|mutation| mutation.all_parents().all(|parent| emitted.contains(parent)))
    {
        let mutation = remaining.remove(index);
        emitted.insert(mutation.operation_id.clone());
        ordered.push(mutation);
    }
    for mutation in remaining {
        report.pending.push(PendingOperation {
            device_id: mutation.device_id,
            sequence: mutation.sequence,
            operation_id: mutation.operation_id,
            reason: "logical history contains a cycle or an unavailable parent".to_string(),
        });
    }

    let mut heads: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for mutation in &ordered {
        for entity in &mutation.payload.entities {
            let logical_heads = heads.entry(entity.logical_id.clone()).or_default();
            for parent in &entity.parents {
                logical_heads.remove(parent);
            }
            logical_heads.insert(mutation.operation_id.clone());
        }
    }
    report.conflicts = heads
        .into_iter()
        .filter_map(|(logical_id, head_operation_ids)| {
            (head_operation_ids.len() > 1).then(|| LogicalConflict {
                logical_id,
                head_operation_ids: head_operation_ids.into_iter().collect(),
            })
        })
        .collect();
    report.verified = ordered;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplicationReport {
    pub published: usize,
    pub imported: usize,
    pub recovered_local: usize,
    pub observed: usize,
    pub pending: usize,
    pub damaged: usize,
    /// Package-relative files that failed structural, digest, signature, or decryption checks.
    /// Callers may reveal these files, but must never delete them automatically: some are
    /// evidence of a signed Device fork rather than disposable sync-provider conflict copies.
    pub damaged_files: Vec<PathBuf>,
    pub conflicts: usize,
    pub local_device_fenced: bool,
    pub messages: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ExportStoreDescriptor {
    label: String,
    mode: u32,
    enforcement: Enforcement,
    environment_ids: Option<Vec<String>>,
    metadata: ItemMetadata,
}

/// The durable outbox form of one committed transaction's entity deltas (stored in the outbox
/// row's payload column; secret content never rides here).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TransactionDelta {
    format_version: u32,
    entities: Vec<EntityPayload>,
}

/// Everything already replicated or locally queued, folded from causally ordered verified
/// operations plus the pending outbox. Staging diffs the live catalog/store against this.
#[derive(Default)]
struct KnownState {
    catalog_payload: Option<Vec<u8>>,
    catalog_heads: Vec<String>,
    secrets: HashMap<String, KnownSecret>,
}

#[derive(Default)]
struct KnownSecret {
    version_uuids: HashSet<String>,
    head_uuid: String,
    descriptor: Option<ExportStoreDescriptor>,
    heads: Vec<String>,
}

fn fold_known_state(
    verified: &[VerifiedMutation],
    outbox: &[ReplicationOutboxEntry],
) -> ReplicationResult<KnownState> {
    let mut state = KnownState::default();
    let mut catalog_heads: BTreeSet<String> = BTreeSet::new();
    let mut secret_heads: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut apply = |operation_id: &str, entities: &[EntityPayload]| {
        for entity in entities {
            match &entity.delta {
                EntityDelta::Catalog { payload } => {
                    state.catalog_payload = Some(payload.clone());
                    for parent in &entity.parents {
                        catalog_heads.remove(parent);
                    }
                    catalog_heads.insert(operation_id.to_string());
                }
                EntityDelta::Secret(delta) => {
                    let secret =
                        state.secrets.entry(entity.logical_id.clone()).or_default();
                    for version in &delta.versions {
                        secret.version_uuids.insert(version.version_uuid.clone());
                    }
                    secret.head_uuid = delta.head_uuid.clone();
                    secret.descriptor = Some(delta.descriptor.clone());
                    let heads = secret_heads.entry(entity.logical_id.clone()).or_default();
                    for parent in &entity.parents {
                        heads.remove(parent);
                    }
                    heads.insert(operation_id.to_string());
                }
            }
        }
    };
    for mutation in verified {
        apply(&mutation.operation_id, &mutation.payload.entities);
    }
    for entry in outbox {
        let delta: TransactionDelta = serde_json::from_slice(&entry.catalog_payload)?;
        if delta.format_version != PAYLOAD_FORMAT_VERSION {
            return Err(ReplicationError::Invalid(format!(
                "outbox intent {} has unsupported delta format {}",
                entry.intent_id, delta.format_version
            )));
        }
        apply(&entry.intent_id, &delta.entities);
    }
    state.catalog_heads = catalog_heads.into_iter().collect();
    for (logical_id, heads) in secret_heads {
        if let Some(secret) = state.secrets.get_mut(&logical_id) {
            secret.heads = heads.into_iter().collect();
        }
    }
    Ok(state)
}

/// Generation-1 material for creating a vault from the genesis store. The store's own keys ARE
/// the vault keys — its version files must decrypt under the vault's generation identities.
fn genesis_generation_material(
    store: &AgeDirStore,
) -> ReplicationResult<(x25519::Identity, String)> {
    let generation = store.current_generation()?;
    if generation != 1 {
        return Err(ReplicationError::Invalid(format!(
            "creating a vault from a store at key generation {generation} is not supported yet"
        )));
    }
    Ok((store.generation_identity(1)?, store.recovery_recipient()?))
}

fn descriptor_from_record(record: &floria_store::SecretRecord) -> ExportStoreDescriptor {
    ExportStoreDescriptor {
        label: portable_store_label(&record.origin),
        mode: record.mode,
        enforcement: record.enforcement,
        environment_ids: record.environment_ids.clone(),
        metadata: record.metadata.clone(),
    }
}

/// Single entry point for the stage-2 replication loop. Directory parsing, self-fencing,
/// immutable local-store reads, exact signed retry, and outbox completion stay behind `sync()`.
pub struct ReplicationEngine {
    package: ReplicationPackage,
    intents: Arc<ReplicationIntentJournal>,
    catalog: Arc<Catalog>,
    store: Arc<AgeDirStore>,
    mutations: Arc<ManagedMutationCoordinator>,
}

#[derive(Clone)]
pub struct ReplicationRuntime {
    local_state_directory: PathBuf,
    authenticator: Arc<StateAuthenticator>,
    catalog: Arc<Catalog>,
    store: Arc<AgeDirStore>,
    mutations: Arc<ManagedMutationCoordinator>,
}

impl ReplicationRuntime {
    pub fn new(
        local_state_directory: impl Into<PathBuf>,
        authenticator: Arc<StateAuthenticator>,
        catalog: Arc<Catalog>,
        store: Arc<AgeDirStore>,
        mutations: Arc<ManagedMutationCoordinator>,
    ) -> Self {
        Self {
            local_state_directory: local_state_directory.into(),
            authenticator,
            catalog,
            store,
            mutations,
        }
    }
}

impl ReplicationEngine {
    pub fn create(
        directory: impl Into<PathBuf>,
        vault_id: impl Into<String>,
        created_at: impl Into<String>,
        device: DeviceKeyMaterial,
        runtime: ReplicationRuntime,
    ) -> ReplicationResult<Self> {
        Self::create_named(directory, vault_id, created_at, device, None, runtime)
    }

    pub fn create_named(
        directory: impl Into<PathBuf>,
        vault_id: impl Into<String>,
        created_at: impl Into<String>,
        device: DeviceKeyMaterial,
        device_name: Option<String>,
        runtime: ReplicationRuntime,
    ) -> ReplicationResult<Self> {
        let (vault_identity, recovery_public) = genesis_generation_material(&runtime.store)?;
        let package = ReplicationPackage::create_named(
            directory,
            vault_id,
            created_at,
            device,
            device_name,
            vault_identity,
            recovery_public,
        )?;
        Self::with_runtime(package, runtime)
    }

    fn with_runtime(
        package: ReplicationPackage,
        runtime: ReplicationRuntime,
    ) -> ReplicationResult<Self> {
        ensure_private_local_state_directory(&runtime.local_state_directory)?;
        let intents = Arc::new(ReplicationIntentJournal::open(
            runtime
                .local_state_directory
                .join(format!("replication-{}.json", package.vault_id())),
            package.vault_id(),
            runtime.authenticator,
        )?);
        Ok(Self {
            package,
            intents,
            catalog: runtime.catalog,
            store: runtime.store,
            mutations: runtime.mutations,
        })
    }

    pub fn open(
        directory: impl Into<PathBuf>,
        device: DeviceKeyMaterial,
        runtime: ReplicationRuntime,
    ) -> ReplicationResult<Self> {
        let package = ReplicationPackage::open(directory, device)?;
        Self::with_runtime(package, runtime)
    }

    pub fn from_parts(
        package: ReplicationPackage,
        intents: Arc<ReplicationIntentJournal>,
        catalog: Arc<Catalog>,
        store: Arc<AgeDirStore>,
    ) -> Self {
        Self {
            package,
            intents,
            catalog,
            store,
            mutations: Arc::new(ManagedMutationCoordinator::new()),
        }
    }

    pub fn from_parts_with_mutations(
        package: ReplicationPackage,
        intents: Arc<ReplicationIntentJournal>,
        catalog: Arc<Catalog>,
        store: Arc<AgeDirStore>,
        mutations: Arc<ManagedMutationCoordinator>,
    ) -> Self {
        Self { package, intents, catalog, store, mutations }
    }

    pub fn vault_id(&self) -> &str {
        self.package.vault_id()
    }

    pub fn device_id(&self) -> &str {
        self.package.device_id()
    }

    pub fn current_generation(&self) -> u32 {
        self.package.current_generation()
    }

    pub fn devices(&self) -> Vec<ReplicationDevice> {
        self.package.devices()
    }

    pub fn enrollment(&self) -> DeviceEnrollment {
        self.package.device.enrollment()
    }

    pub fn enroll_device(&mut self, enrollment: DeviceEnrollment) -> ReplicationResult<()> {
        self.package.enroll_device(enrollment)
    }

    pub fn revoke_device(&self, device_id: &str) -> ReplicationResult<ReplicationReport> {
        self.mutations.run(|| {
            // The new generation is born in the store (its files are the objects), then the
            // vault publishes its signed document and envelopes. A crash between the two leaves
            // the store one generation ahead; the retry reuses it instead of rotating again.
            let package_generation = self.package.current_generation();
            let store_generation = self.store.current_generation()?;
            let next = if store_generation == package_generation.saturating_add(1) {
                store_generation
            } else if store_generation == package_generation {
                self.store.rotate_generation()?
            } else {
                return Err(ReplicationError::Invalid(format!(
                    "store generation {store_generation} and vault generation \
                     {package_generation} have diverged"
                )));
            };
            let identity = self.store.generation_identity(next)?;
            let recovery = self.store.recovery_recipient()?;
            let generation = self.package.revoke_device(device_id, identity, &recovery)?;
            if generation != next {
                return Err(ReplicationError::Invalid(format!(
                    "vault rotated to generation {generation} but the store rotated to {next}"
                )));
            }
            self.sync_uncoordinated()
        })
    }

    /// Stage one complete, portable Vault-state snapshot after the caller has serialized normal
    /// catalog/store mutations through `ManagedMutationCoordinator`. Unchanged state is an
    /// idempotent no-op; successive unsynchronized states form a durable parent chain.
    pub fn stage_current_snapshot(&self, created_at: &str) -> ReplicationResult<bool> {
        self.mutations.run(|| self.stage_current_snapshot_uncoordinated(created_at))
    }

    /// Checkpoint the exact state of a successful local mutation while its coordinator gate is
    /// still held. Callers must only invoke this from `ManagedMutationObserver`; ordinary callers
    /// use `stage_current_snapshot()` so the coordinator is acquired safely.
    pub fn stage_committed_snapshot(&self, created_at: &str) -> ReplicationResult<bool> {
        self.stage_current_snapshot_uncoordinated(created_at)
    }

    /// Resolve the replicated-state conflict by keeping the Local Projection currently visible
    /// on this Device. The signed merge names every conflicting head, so other Devices converge
    /// without trusting arrival order or silently selecting a winner.
    pub fn resolve_conflict_with_current(
        &self,
        created_at: &str,
    ) -> ReplicationResult<ReplicationReport> {
        self.mutations
            .run(|| self.resolve_conflict_with_current_uncoordinated(created_at))
    }

    fn stage_current_snapshot_uncoordinated(&self, created_at: &str) -> ReplicationResult<bool> {
        if created_at.trim().is_empty() {
            return Err(ReplicationError::Invalid(
                "replication snapshot creation time is empty".to_string(),
            ));
        }
        let outbox = ordered_outbox(self.catalog.replication_outbox()?)?;
        let scan = self.package.scan()?;
        if !scan.pending.is_empty() || !scan.damaged.is_empty() || !scan.conflicts.is_empty() {
            return Err(ReplicationError::Invalid(
                "replication package must be fully synchronized before staging local state"
                    .to_string(),
            ));
        }
        let known = fold_known_state(&scan.verified, &outbox)?;
        let (entities, store_versions) = self.build_delta_entities(&known, None)?;
        if entities.is_empty() {
            return Ok(false);
        }
        self.enqueue_transaction(entities, store_versions, created_at)?;
        Ok(true)
    }

    /// Compute the entity deltas between the local catalog/store and the already replicated or
    /// queued state. `conflict_parents` overrides per-entity parents when building an explicit
    /// merge (conflict resolution); `None` means normal forward progress from the known heads.
    fn build_delta_entities(
        &self,
        known: &KnownState,
        conflict_parents: Option<&HashMap<String, Vec<String>>>,
    ) -> ReplicationResult<(Vec<EntityPayload>, Vec<floria_catalog::ReplicationStoreVersionRef>)>
    {
        let parents_for = |logical_id: &str, known_heads: &[String]| -> Vec<String> {
            match conflict_parents {
                Some(overrides) => overrides
                    .get(logical_id)
                    .cloned()
                    .unwrap_or_else(|| known_heads.to_vec()),
                None => known_heads.to_vec(),
            }
        };
        let mut entities = Vec::new();
        let mut store_versions = Vec::new();

        let projection = self.catalog.replicated_catalog()?;
        let catalog_payload = serde_json::to_vec(&projection)?;
        let catalog_changed = known.catalog_payload.as_deref() != Some(catalog_payload.as_slice());
        let forced_catalog = conflict_parents.is_some_and(|c| c.contains_key(CATALOG_LOGICAL_ID));
        if catalog_changed || forced_catalog {
            entities.push(EntityPayload {
                logical_id: CATALOG_LOGICAL_ID.to_string(),
                parents: parents_for(CATALOG_LOGICAL_ID, &known.catalog_heads),
                delta: EntityDelta::Catalog { payload: catalog_payload },
            });
        }

        let secret_ids = projection
            .resources
            .iter()
            .filter_map(|resource| match &resource.source {
                floria_catalog::ResourceSource::SecretRef { secret_id } => {
                    Some(secret_id.clone())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for secret_id in secret_ids {
            let parsed: SecretId = secret_id.parse()?;
            let record = self.store.record(&parsed)?.ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "portable catalog references missing secret {secret_id}"
                ))
            })?;
            let descriptor = descriptor_from_record(&record);
            let head_uuid = self.store.head_version_uuid(&parsed)?;
            let known_secret = known.secrets.get(secret_id.as_str());
            let refs = self.store.version_refs(&parsed)?;
            let new_versions = refs
                .iter()
                .filter(|reference| {
                    known_secret
                        .is_none_or(|secret| !secret.version_uuids.contains(&reference.version_uuid))
                })
                .collect::<Vec<_>>();
            let forced = conflict_parents.is_some_and(|c| c.contains_key(secret_id.as_str()));
            let changed = !new_versions.is_empty()
                || known_secret.is_none_or(|secret| {
                    secret.head_uuid != head_uuid
                        || secret.descriptor.as_ref() != Some(&descriptor)
                });
            if !(changed || forced) {
                continue;
            }
            let known_heads =
                known_secret.map(|secret| secret.heads.as_slice()).unwrap_or_default();
            entities.push(EntityPayload {
                logical_id: secret_id.clone(),
                parents: parents_for(&secret_id, known_heads),
                delta: EntityDelta::Secret(SecretDelta {
                    descriptor,
                    versions: new_versions
                        .iter()
                        .map(|reference| SecretVersionRef {
                            version_uuid: reference.version_uuid.clone(),
                            generation: reference.generation,
                            size: reference.size,
                            object: ObjectReference {
                                id: reference.digest.clone(),
                                ciphertext_size: reference.ciphertext_size,
                            },
                        })
                        .collect(),
                    head_uuid,
                }),
            });
            store_versions.extend(new_versions.iter().map(|reference| {
                floria_catalog::ReplicationStoreVersionRef {
                    secret_id: secret_id.clone(),
                    version: reference.ordinal,
                }
            }));
        }
        Ok((entities, store_versions))
    }

    fn resolve_conflict_with_current_uncoordinated(
        &self,
        created_at: &str,
    ) -> ReplicationResult<ReplicationReport> {
        if !self.catalog.replication_outbox()?.is_empty() {
            return Err(ReplicationError::Invalid(
                "local changes must finish publishing before resolving a conflict".to_string(),
            ));
        }
        let scan = self.package.scan()?;
        if !scan.pending.is_empty() || !scan.damaged.is_empty() {
            return Err(ReplicationError::Invalid(
                "replication package has incomplete or damaged files".to_string(),
            ));
        }
        if scan
            .fenced_devices
            .iter()
            .any(|device| device == self.package.device_id())
        {
            return Err(ReplicationError::Invalid(
                "the local Device is fenced and cannot resolve conflicts".to_string(),
            ));
        }
        if scan.conflicts.is_empty() {
            return Err(ReplicationError::Invalid(
                "there is no replicated-state conflict to resolve".to_string(),
            ));
        }

        // The signed merge covers exactly the conflicted entities; each names all of its heads
        // as parents and carries this Device's current state for that entity.
        let known = fold_known_state(&scan.verified, &[])?;
        let conflict_parents = scan
            .conflicts
            .iter()
            .map(|conflict| (conflict.logical_id.clone(), conflict.head_operation_ids.clone()))
            .collect::<HashMap<_, _>>();
        let (entities, store_versions) =
            self.build_delta_entities(&known, Some(&conflict_parents))?;
        let entities = entities
            .into_iter()
            .filter(|entity| conflict_parents.contains_key(&entity.logical_id))
            .collect::<Vec<_>>();
        if entities.len() != conflict_parents.len() {
            return Err(ReplicationError::Invalid(
                "cannot build a local merge for every conflicted entity".to_string(),
            ));
        }
        let kept = entities
            .iter()
            .map(|entity| entity.logical_id.clone())
            .collect::<HashSet<_>>();
        let store_versions = store_versions
            .into_iter()
            .filter(|reference| kept.contains(reference.secret_id.as_str()))
            .collect::<Vec<_>>();
        self.enqueue_transaction(entities, store_versions, created_at)?;

        // The explicit merge acknowledges every parent branch. Checkpoint their per-Device slots
        // without projecting their values: the current catalog/store is the user-selected merge
        // result and the queued operation durably names all of those heads.
        for mutation in scan
            .verified
            .iter()
            .filter(|mutation| mutation.device_id != self.package.device_id())
        {
            let accepted = self.intents.accepted_operations(&mutation.device_id);
            match accepted.get(&mutation.sequence) {
                Some(operation_id) if operation_id == &mutation.operation_id => continue,
                Some(_) => {
                    return Err(ReplicationError::Invalid(format!(
                        "accepted operation {}:{} was replaced",
                        mutation.device_id, mutation.sequence
                    )))
                }
                None => self.intents.accept_device_operation(
                    &mutation.device_id,
                    mutation.sequence,
                    &mutation.operation_id,
                )?,
            }
        }
        self.sync_uncoordinated()
    }

    /// Queue one transaction delta durably: pre-commit journal first, then the catalog outbox.
    fn enqueue_transaction(
        &self,
        entities: Vec<EntityPayload>,
        store_versions: Vec<floria_catalog::ReplicationStoreVersionRef>,
        created_at: &str,
    ) -> ReplicationResult<()> {
        if created_at.trim().is_empty() {
            return Err(ReplicationError::Invalid(
                "replication transaction creation time is empty".to_string(),
            ));
        }
        let intent_id = uuid::Uuid::new_v4().to_string();
        validate_entities(&intent_id, &entities)?;
        let parents = {
            let mut parents = entities
                .iter()
                .flat_map(|entity| entity.parents.iter().cloned())
                .collect::<BTreeSet<_>>();
            parents.take(&intent_id);
            parents.into_iter().collect::<Vec<_>>()
        };
        let delta = TransactionDelta {
            format_version: PAYLOAD_FORMAT_VERSION,
            entities,
        };
        let entry = ReplicationOutboxEntry {
            intent_id: intent_id.clone(),
            logical_id: TRANSACTION_LOGICAL_ID.to_string(),
            parents,
            store_versions,
            catalog_payload: serde_json::to_vec(&delta)?,
            created_at: created_at.to_string(),
        };
        self.intents.enqueue(ReplicationIntent::transaction(
            &intent_id,
            entry.parents.clone(),
            entry.store_versions.clone(),
            entry.catalog_payload.clone(),
            &entry.created_at,
        )?)?;
        if let Err(error) = self.catalog.enqueue_replication_outbox(&entry) {
            let _ = self.intents.discard_unsigned(&intent_id);
            return Err(error.into());
        }
        Ok(())
    }

    pub fn sync(&self) -> ReplicationResult<ReplicationReport> {
        self.mutations.run(|| self.sync_uncoordinated())
    }

    /// Align the local store's generation keys with the vault's, so imported version files and
    /// new local writes share the vault's key domain — the zero-transcode invariant.
    ///
    /// Three cases:
    /// - no overlap (a freshly enrolled device whose store only has its unused self-generated
    ///   keys): adopt the vault's generation set wholesale — legal only for an empty store;
    /// - every store generation matches the vault's by public key: install any generations the
    ///   store is missing (a re-enrolled member learning newer keys) without touching files;
    /// - a store generation differs from the vault's, or the store holds generations the vault
    ///   does not know (beyond one pending local rotation): fail loudly — a populated library
    ///   in a foreign key domain needs a one-time re-key that v1 does not implement.
    fn reconcile_generations(&self) -> ReplicationResult<()> {
        let identities = self.package.generation_identity_secrets();
        if identities.is_empty() {
            return Ok(());
        }
        let recovery = self.package.recovery_public();
        let mut matched = 0usize;
        let mut mismatched = false;
        let mut missing = Vec::new();
        for (generation, secret) in &identities {
            let expected = secret
                .trim()
                .parse::<x25519::Identity>()
                .map_err(|error| {
                    ReplicationError::Invalid(format!(
                        "vault generation {generation} identity is invalid: {error}"
                    ))
                })?
                .to_public()
                .to_string();
            match self.store.generation_public(*generation)? {
                Some(public) if public == expected => matched += 1,
                Some(_) => mismatched = true,
                None => missing.push((*generation, secret)),
            }
        }
        if matched == 0 {
            // Fresh join: adopt everything. Fails loudly for a populated store.
            self.store.adopt_generations(&identities, &recovery)?;
            return Ok(());
        }
        if mismatched {
            return Err(ReplicationError::Invalid(
                "a local store key generation differs from the vault's; the local library is in \
                 a foreign key domain"
                    .to_string(),
            ));
        }
        let vault_max = identities
            .iter()
            .map(|(generation, _)| *generation)
            .max()
            .expect("identities are non-empty");
        let store_current = self.store.current_generation()?;
        if store_current > vault_max.saturating_add(1) {
            return Err(ReplicationError::Invalid(format!(
                "store generation {store_current} is ahead of vault generation {vault_max}"
            )));
        }
        if self.store.recovery_recipient()? != recovery {
            return Err(ReplicationError::Invalid(
                "the store's recovery recipient differs from the vault's".to_string(),
            ));
        }
        for (generation, secret) in missing {
            self.store.install_generation(generation, secret)?;
        }
        Ok(())
    }

    fn sync_uncoordinated(&self) -> ReplicationResult<ReplicationReport> {
        self.reconcile_generations()?;
        let scan = self.package.scan()?;
        let mut report = ReplicationReport {
            observed: scan.observed.len(),
            pending: scan.pending.len(),
            damaged: scan.damaged.len(),
            damaged_files: relative_damaged_paths(&self.package.root, &scan.damaged),
            conflicts: scan.conflicts.len(),
            ..Default::default()
        };
        if let Err(error) = self
            .intents
            .accept_key_generations(&self.package.generation_fingerprints())
        {
            return Ok(fence_report(report, error.to_string()));
        }
        if scan
            .fenced_devices
            .iter()
            .any(|device| device == self.package.device_id())
        {
            return Ok(fence_report(
                report,
                "the local Device has conflicting valid signed operations",
            ));
        }

        let local_observed = scan
            .observed
            .iter()
            .filter(|operation| operation.device_id == self.package.device_id())
            .map(|operation| (operation.sequence, operation.operation_id.clone()))
            .collect::<BTreeMap<_, _>>();
        let accepted = self.intents.accepted_operations(self.package.device_id());
        for (sequence, operation_id) in &accepted {
            if local_observed.get(sequence) != Some(operation_id) {
                return Ok(fence_report(
                    report,
                    format!(
                        "the Replication Directory no longer contains accepted local operation {sequence}"
                    ),
                ));
            }
        }

        let mut checkpoint = self.intents.device_sequence(self.package.device_id());
        let journal_entries = self.intents.entries();
        let outbox = ordered_outbox(self.catalog.replication_outbox()?)?;
        let local_verified = scan
            .verified
            .iter()
            .filter(|mutation| mutation.device_id == self.package.device_id())
            .map(|mutation| (mutation.sequence, mutation))
            .collect::<BTreeMap<_, _>>();
        for (sequence, operation_id) in local_observed.range((
            std::ops::Bound::Excluded(checkpoint),
            std::ops::Bound::Unbounded,
        )) {
            let Some(expected) = checkpoint.checked_add(1) else {
                return Ok(fence_report(report, "the local Device sequence overflowed"));
            };
            if *sequence != expected {
                return Ok(fence_report(
                    report,
                    format!("the local Device history has a gap before sequence {sequence}"),
                ));
            }
            let prepared = journal_entries.iter().find_map(|intent| {
                intent.prepared().filter(|prepared| {
                    prepared.sequence == *sequence && prepared.operation_id == *operation_id
                })
            });
            if let Some(prepared) = prepared {
                self.package.publish(prepared)?;
            } else if journal_entries.is_empty() && outbox.is_empty() {
                let Some(mutation) = local_verified.get(sequence) else {
                    return Ok(fence_report(
                        report,
                        format!(
                            "the local Device is behind operation {sequence}, but its payload is not available"
                        ),
                    ));
                };
                if mutation.operation_id.as_str() != operation_id.as_str() {
                    return Ok(fence_report(
                        report,
                        format!(
                            "the local Device operation {sequence} does not match its verified payload"
                        ),
                    ));
                }
                self.apply_verified_mutation(mutation)?;
                report.recovered_local += 1;
            } else {
                return Ok(fence_report(
                    report,
                    format!(
                        "the local Device is behind signed operation {sequence} while local mutations are pending"
                    ),
                ));
            }
            self.intents.accept_device_operation(
                self.package.device_id(),
                *sequence,
                operation_id,
            )?;
            checkpoint = *sequence;
        }

        let outbox_ids = outbox
            .iter()
            .map(|entry| entry.intent_id.as_str())
            .collect::<HashSet<_>>();
        for intent in self.intents.entries() {
            if outbox_ids.contains(intent.intent_id.as_str()) {
                continue;
            }
            match intent.prepared() {
                Some(prepared)
                    if self
                        .intents
                        .accepted_operations(self.package.device_id())
                        .get(&prepared.sequence)
                        == Some(&prepared.operation_id) =>
                {
                    self.intents.complete(&intent.intent_id)?;
                }
                Some(_) => {
                    return Ok(fence_report(
                        report,
                        format!(
                            "signed intent {} has neither an outbox row nor an accepted operation",
                            intent.intent_id
                        ),
                    ));
                }
                None if self.intent_has_no_store_writes(&intent)? => {
                    self.intents.discard_unsigned(&intent.intent_id)?;
                }
                None => {
                    return Ok(fence_report(
                        report,
                        format!(
                            "intent {} reached the local store but has no committed outbox row",
                            intent.intent_id
                        ),
                    ));
                }
            }
        }

        for entry in outbox {
            let intent = self
                .intents
                .entries()
                .into_iter()
                .find(|intent| intent.intent_id == entry.intent_id)
                .ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "committed outbox intent {} has no durable pre-commit journal entry",
                        entry.intent_id
                    ))
                })?;
            validate_committed_intent(&intent, &entry, self.store.as_ref())?;

            let prepared = match intent.prepared() {
                Some(prepared) => prepared.clone(),
                None => {
                    let delta: TransactionDelta = serde_json::from_slice(&entry.catalog_payload)?;
                    if delta.format_version != PAYLOAD_FORMAT_VERSION {
                        return Err(ReplicationError::Invalid(format!(
                            "outbox intent {} has unsupported delta format {}",
                            entry.intent_id, delta.format_version
                        )));
                    }
                    // Fetch every referenced version file verbatim from the local store.
                    // Zero transcoding: the bytes published as objects are the store files.
                    let mut objects = Vec::with_capacity(entry.store_versions.len());
                    for reference in &entry.store_versions {
                        let secret_id: SecretId = reference.secret_id.parse()?;
                        let export =
                            self.store.export_version(&secret_id, reference.version)?;
                        objects.push(PreparedObject {
                            id: export.digest,
                            bytes: export.ciphertext,
                        });
                    }
                    let next = self
                        .intents
                        .device_sequence(self.package.device_id())
                        .checked_add(1)
                        .ok_or_else(|| {
                            ReplicationError::Invalid(
                                "local Device sequence overflow".to_string(),
                            )
                        })?;
                    let prepared = self.package.prepare(PackageMutation {
                        sequence: next,
                        operation_id: &entry.intent_id,
                        entities: &delta.entities,
                        objects: &objects,
                    })?;
                    self.intents.save_prepared(&entry.intent_id, prepared.clone())?;
                    prepared
                }
            };

            self.package.publish(&prepared)?;
            let accepted = self.intents.accepted_operations(self.package.device_id());
            match accepted.get(&prepared.sequence) {
                Some(operation_id) if operation_id == &prepared.operation_id => {}
                Some(_) => {
                    return Ok(fence_report(
                        report,
                        format!(
                            "local sequence {} is already assigned to another operation",
                            prepared.sequence
                        ),
                    ));
                }
                None => self.intents.accept_device_operation(
                    self.package.device_id(),
                    prepared.sequence,
                    &prepared.operation_id,
                )?,
            }
            self.catalog.remove_replication_outbox(&entry.intent_id)?;
            self.intents.complete(&entry.intent_id)?;
            report.published += 1;
        }

        // Publish the exact local projection before importing newly arrived remote state. If both
        // Devices changed the same parent, the refreshed scan now exposes two heads while this
        // Device keeps showing its own branch; importing first would silently replace the local
        // projection even though its signed operation still becomes a conflict.
        let scan = if report.published > 0 {
            self.package.scan()?
        } else {
            scan
        };
        report.observed = scan.observed.len();
        report.pending = scan.pending.len();
        report.damaged = scan.damaged.len();
        report.damaged_files = relative_damaged_paths(&self.package.root, &scan.damaged);
        report.conflicts = scan.conflicts.len();
        if scan
            .fenced_devices
            .iter()
            .any(|device| device == self.package.device_id())
        {
            return Ok(fence_report(
                report,
                "the local Device has conflicting valid signed operations",
            ));
        }
        if !scan.conflicts.is_empty() {
            report.messages.push(format!(
                "{} replicated item(s) have concurrent heads and require an explicit merge",
                scan.conflicts.len()
            ));
            return Ok(report);
        }

        for mutation in scan
            .verified
            .iter()
            .filter(|mutation| mutation.device_id != self.package.device_id())
        {
            let accepted = self.intents.accepted_operations(&mutation.device_id);
            if let Some(operation_id) = accepted.get(&mutation.sequence) {
                if operation_id != &mutation.operation_id {
                    return Ok(fence_report(
                        report,
                        format!(
                            "accepted operation {}:{} was replaced",
                            mutation.device_id, mutation.sequence
                        ),
                    ));
                }
                continue;
            }
            let expected = self
                .intents
                .device_sequence(&mutation.device_id)
                .checked_add(1)
                .ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "device {} operation sequence overflow",
                        mutation.device_id
                    ))
                })?;
            if mutation.sequence != expected {
                return Ok(fence_report(
                    report,
                    format!(
                        "device {} local projection expected sequence {expected}, got {}",
                        mutation.device_id, mutation.sequence
                    ),
                ));
            }
            self.apply_verified_mutation(mutation)?;
            self.intents.accept_device_operation(
                &mutation.device_id,
                mutation.sequence,
                &mutation.operation_id,
            )?;
            report.imported += 1;
        }
        Ok(report)
    }

    fn apply_verified_mutation(&self, mutation: &VerifiedMutation) -> ReplicationResult<()> {
        for entity in &mutation.payload.entities {
            match &entity.delta {
                EntityDelta::Catalog { payload } => {
                    let projection: ReplicatedCatalog = serde_json::from_slice(payload)?;
                    self.catalog.apply_replicated_catalog(&projection)?;
                }
                EntityDelta::Secret(delta) => {
                    let secret_id: SecretId = entity.logical_id.parse()?;
                    for version in &delta.versions {
                        // The object is the exact version file another store wrote: verify and
                        // land it verbatim. The store re-checks digest, decryptability, payload
                        // binding, and declared size before trusting it.
                        let bytes = self.package.read_object(&version.object.id)?;
                        self.store.import_version(
                            &secret_id,
                            Some(NewSecret {
                                origin: SecretOrigin::Managed {
                                    label: delta.descriptor.label.clone(),
                                },
                                mode: delta.descriptor.mode,
                                enforcement: delta.descriptor.enforcement,
                            }),
                            &bytes,
                            &version.version_uuid,
                            version.generation,
                            version.size,
                            &mutation.operation_id,
                        )?;
                    }
                    self.store.set_head_to_uuid(&secret_id, &delta.head_uuid)?;
                    self.store.update_settings(
                        &secret_id,
                        delta.descriptor.metadata.clone(),
                        delta.descriptor.enforcement,
                        delta.descriptor.environment_ids.clone(),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn intent_has_no_store_writes(&self, intent: &ReplicationIntent) -> ReplicationResult<bool> {
        for mutation in &intent.store_mutations {
            let secret_id: SecretId = mutation.secret_id.parse()?;
            if self
                .store
                .version_for_mutation(&secret_id, &mutation.mutation_id)?
                .is_some()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

}

fn portable_store_label(origin: &SecretOrigin) -> String {
    match origin {
        SecretOrigin::Managed { label } => label.clone(),
        SecretOrigin::File { source_path } => source_path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("Managed file")
            .to_string(),
    }
}

/// Return committed local publications in causal order.
///
/// Wall-clock timestamps are descriptive only: restored clocks and multiple mutations within one
/// timestamp tick must not reorder signed history. A local outbox therefore has exactly one
/// causal head, and its parent operation ids are the authority for publication order.
fn ordered_outbox(
    entries: Vec<ReplicationOutboxEntry>,
) -> ReplicationResult<Vec<ReplicationOutboxEntry>> {
    if entries.len() < 2 {
        return Ok(entries);
    }

    let entry_ids = entries
        .iter()
        .map(|entry| entry.intent_id.clone())
        .collect::<HashSet<_>>();
    let internal_parents = entries
        .iter()
        .flat_map(|entry| entry.parents.iter().map(String::as_str))
        .filter(|parent| entry_ids.contains(*parent))
        .map(str::to_owned)
        .collect::<HashSet<_>>();
    let heads = entries
        .iter()
        .filter(|entry| !internal_parents.contains(entry.intent_id.as_str()))
        .count();
    if heads != 1 {
        return Err(ReplicationError::Invalid(format!(
            "replication outbox has {heads} causal heads; expected exactly one"
        )));
    }

    let mut remaining = entries;
    let mut emitted = HashSet::new();
    let mut ordered = Vec::with_capacity(remaining.len());
    while let Some(index) = remaining.iter().position(|entry| {
        entry
            .parents
            .iter()
            .all(|parent| !entry_ids.contains(parent.as_str()) || emitted.contains(parent))
    }) {
        let entry = remaining.remove(index);
        emitted.insert(entry.intent_id.clone());
        ordered.push(entry);
    }
    if !remaining.is_empty() {
        return Err(ReplicationError::Invalid(
            "replication outbox parent chain contains a cycle".to_string(),
        ));
    }
    Ok(ordered)
}

fn validate_committed_intent(
    intent: &ReplicationIntent,
    outbox: &ReplicationOutboxEntry,
    store: &AgeDirStore,
) -> ReplicationResult<()> {
    if intent.intent_id != outbox.intent_id
        || intent.logical_id != outbox.logical_id
        || intent.parents != outbox.parents
        || intent.catalog_payload != outbox.catalog_payload
    {
        return Err(ReplicationError::Invalid(format!(
            "outbox intent {} does not match its durable pre-commit state",
            outbox.intent_id
        )));
    }
    if intent.store_mutations.len() + intent.store_versions.len() != outbox.store_versions.len() {
        return Err(ReplicationError::Invalid(format!(
            "outbox intent {} has a different store mutation count",
            outbox.intent_id
        )));
    }
    for mutation in &intent.store_mutations {
        let reference = outbox
            .store_versions
            .iter()
            .find(|reference| reference.secret_id == mutation.secret_id)
            .ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "outbox intent {} lost store mutation {}",
                    outbox.intent_id, mutation.mutation_id
                ))
            })?;
        let secret_id: SecretId = mutation.secret_id.parse()?;
        if store.version_for_mutation(&secret_id, &mutation.mutation_id)?
            != Some(reference.version)
        {
            return Err(ReplicationError::Invalid(format!(
                "outbox intent {} does not reference its immutable store version",
                outbox.intent_id
            )));
        }
    }
    for expected in &intent.store_versions {
        if !outbox.store_versions.contains(expected) {
            return Err(ReplicationError::Invalid(format!(
                "outbox intent {} lost immutable store version {}:{}",
                outbox.intent_id, expected.secret_id, expected.version
            )));
        }
        let secret_id: SecretId = expected.secret_id.parse()?;
        if !store
            .history(&secret_id)?
            .iter()
            .any(|version| version.version == expected.version)
        {
            return Err(ReplicationError::Invalid(format!(
                "outbox intent {} references unavailable store version {}:{}",
                outbox.intent_id, expected.secret_id, expected.version
            )));
        }
    }
    Ok(())
}

fn fence_report(mut report: ReplicationReport, message: impl Into<String>) -> ReplicationReport {
    report.local_device_fenced = true;
    report.messages.push(message.into());
    report
}

fn relative_damaged_paths(root: &Path, damaged: &[DamagedFile]) -> Vec<PathBuf> {
    let mut paths = damaged
        .iter()
        .filter_map(|file| file.path.strip_prefix(root).ok().map(Path::to_path_buf))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths.truncate(MAX_REPORTED_DAMAGED_FILES);
    paths
}

fn device_unsigned(
    vault: &VaultDocument,
    enrollment: &DeviceEnrollment,
    enrolled_generation: u32,
) -> DeviceUnsigned {
    DeviceUnsigned {
        format_version: FORMAT_VERSION,
        vault_id: vault.vault_id.clone(),
        device_id: enrollment.device_id.clone(),
        signing_public_key: enrollment.signing_public_key.clone(),
        wrapping_recipient: enrollment.wrapping_recipient.clone(),
        device_name: enrollment.device_name.clone(),
        authorized_by: vault.genesis_device_id.clone(),
        enrolled_generation,
    }
}

fn write_device_identity(
    path: &Path,
    vault: &VaultDocument,
    enrollment: &DeviceEnrollment,
    enrolled_generation: u32,
    genesis_signing_key: &SigningKey,
) -> ReplicationResult<()> {
    validate_enrollment(enrollment)?;
    if genesis_signing_key.verifying_key()
        != verifying_key("genesis public key", &vault.genesis_public_key)?
    {
        return Err(ReplicationError::Invalid(
            "Device enrollment signer is not the genesis Device".to_string(),
        ));
    }
    if enrolled_generation == 0 {
        return Err(ReplicationError::Invalid(
            "Device enrollment generation starts at 1".to_string(),
        ));
    }
    let unsigned = device_unsigned(vault, enrollment, enrolled_generation);
    let signature = sign_struct(DEVICE_SIGNATURE_CONTEXT, &unsigned, genesis_signing_key)?;
    let document = DeviceDocument {
        format_version: unsigned.format_version,
        vault_id: unsigned.vault_id,
        device_id: unsigned.device_id,
        signing_public_key: unsigned.signing_public_key,
        wrapping_recipient: unsigned.wrapping_recipient,
        device_name: unsigned.device_name,
        authorized_by: unsigned.authorized_by,
        enrolled_generation: unsigned.enrolled_generation,
        signature,
    };
    write_new_atomic(path, &serde_json::to_vec_pretty(&document)?)
}

fn write_vault_envelope(
    path: &Path,
    vault_identity: &x25519::Identity,
    recipient: &x25519::Recipient,
) -> ReplicationResult<()> {
    let encoded = vault_identity.to_string();
    let ciphertext = encrypt(recipient, encoded.expose_secret().as_bytes())?;
    write_new_atomic(path, &ciphertext)
}

#[allow(clippy::too_many_arguments)]
fn write_key_generation(
    path: &Path,
    vault: &VaultDocument,
    generation: u32,
    previous_generation: Option<u32>,
    vault_identity: &x25519::Identity,
    recipients: &BTreeMap<String, x25519::Recipient>,
    revoked_devices: BTreeMap<String, u64>,
    recovery_public: &str,
    genesis_signing_key: &SigningKey,
) -> ReplicationResult<()> {
    if generation == 0
        || previous_generation != generation.checked_sub(1).filter(|previous| *previous > 0)
    {
        return Err(ReplicationError::Invalid(
            "Vault key generations must form a consecutive chain starting at 1".to_string(),
        ));
    }
    if genesis_signing_key.verifying_key()
        != verifying_key("genesis public key", &vault.genesis_public_key)?
    {
        return Err(ReplicationError::Invalid(
            "key generation signer is not the genesis Device".to_string(),
        ));
    }
    let encoded_identity = vault_identity.to_string();
    let envelopes = recipients
        .iter()
        .map(|(device_id, recipient)| {
            require_uuid("envelope Device id", device_id)?;
            Ok((
                device_id.clone(),
                encode(&encrypt(recipient, encoded_identity.expose_secret().as_bytes())?),
            ))
        })
        .collect::<ReplicationResult<BTreeMap<_, _>>>()?;
    let unsigned = KeyGenerationUnsigned {
        format_version: FORMAT_VERSION,
        vault_id: vault.vault_id.clone(),
        generation,
        previous_generation,
        authorized_by: vault.genesis_device_id.clone(),
        envelopes,
        revoked_devices,
        recovery_public: recovery_public.to_string(),
    };
    let signature = sign_struct(
        KEY_GENERATION_SIGNATURE_CONTEXT,
        &unsigned,
        genesis_signing_key,
    )?;
    let document = KeyGenerationDocument {
        format_version: unsigned.format_version,
        vault_id: unsigned.vault_id,
        generation: unsigned.generation,
        previous_generation: unsigned.previous_generation,
        authorized_by: unsigned.authorized_by,
        envelopes: unsigned.envelopes,
        revoked_devices: unsigned.revoked_devices,
        recovery_public: unsigned.recovery_public,
        signature,
    };
    write_new_atomic(path, &serde_json::to_vec_pretty(&document)?)
}

fn generation_filename(generation: u32) -> String {
    format!("{generation:020}.json")
}

fn envelope_filename(generation: u32) -> String {
    format!("{generation}.age")
}

fn load_key_generations(
    root: &Path,
    vault: &VaultDocument,
) -> ReplicationResult<BTreeMap<u32, KeyGenerationDocument>> {
    let generations_root = root.join("generations");
    let mut by_generation: BTreeMap<u32, (Vec<u8>, KeyGenerationDocument)> = BTreeMap::new();
    for path in regular_files_recursively(&generations_root)? {
        let bytes = read_untrusted_file(&path, MAX_DESCRIPTOR_BYTES)?;
        let document: KeyGenerationDocument = serde_json::from_slice(&bytes)?;
        validate_key_generation(&document, vault)?;
        match by_generation.get(&document.generation) {
            Some((existing, _)) if existing != &bytes => {
                return Err(ReplicationError::Invalid(format!(
                    "Vault key generation {} has multiple signed documents",
                    document.generation
                )));
            }
            Some(_) => {}
            None => {
                by_generation.insert(document.generation, (bytes, document));
            }
        }
    }
    if by_generation.is_empty() {
        return Err(ReplicationError::Invalid(
            "Vault has no signed key generation".to_string(),
        ));
    }
    let mut expected = 1;
    for (generation, (_, document)) in &by_generation {
        if *generation != expected
            || document.previous_generation
                != generation.checked_sub(1).filter(|previous| *previous > 0)
        {
            return Err(ReplicationError::Invalid(format!(
                "Vault key generation history has a gap before {generation}"
            )));
        }
        expected = expected.checked_add(1).ok_or_else(|| {
            ReplicationError::Invalid("Vault key generation overflow".to_string())
        })?;
    }
    Ok(by_generation
        .into_iter()
        .map(|(generation, (_, document))| (generation, document))
        .collect())
}

fn load_package_metadata(
    root: &Path,
    vault: &VaultDocument,
    device: &DeviceKeyMaterial,
) -> ReplicationResult<PackageMetadata> {
    let mut trusted_devices = load_trusted_devices(root, vault)?;
    let generations = load_key_generations(root, vault)?;
    apply_generation_membership(&mut trusted_devices, &generations, vault)?;
    let expected = trusted_devices.get(&device.device_id).ok_or_else(|| {
        ReplicationError::EnrollmentRequired { device_id: device.device_id.clone() }
    })?;
    if expected.verifying_key != device.verifying_key()
        || expected.wrapping_recipient != device.wrapping_identity.to_public()
    {
        return Err(ReplicationError::Invalid(
            "Device private keys do not match its enrolled identity".to_string(),
        ));
    }
    if let Some(generation) = expected.revoked_generation {
        return Err(ReplicationError::DeviceRevoked {
            device_id: device.device_id.clone(),
            generation,
        });
    }
    let current_generation = *generations
        .keys()
        .next_back()
        .expect("key generations were validated as non-empty");
    let vault_identities = load_vault_identities(root, device, &generations)?;
    let generation_fingerprints = key_generation_fingerprints(&generations)?;
    let recovery_public = generations
        .values()
        .next_back()
        .map(|document| document.recovery_public.clone())
        .expect("key generations were validated as non-empty");
    Ok(PackageMetadata {
        vault_identities,
        current_generation,
        generation_fingerprints,
        trusted_devices,
        recovery_public,
    })
}

fn key_generation_fingerprints(
    generations: &BTreeMap<u32, KeyGenerationDocument>,
) -> ReplicationResult<BTreeMap<u32, String>> {
    generations
        .iter()
        .map(|(generation, document)| {
            Ok((*generation, digest(&serde_json::to_vec(document)?)))
        })
        .collect()
}

fn validate_key_generation(
    document: &KeyGenerationDocument,
    vault: &VaultDocument,
) -> ReplicationResult<()> {
    if document.format_version != FORMAT_VERSION
        || document.vault_id != vault.vault_id
        || document.authorized_by != vault.genesis_device_id
        || document.generation == 0
    {
        return Err(ReplicationError::Invalid(
            "key generation does not match vault.json".to_string(),
        ));
    }
    for (device_id, envelope) in &document.envelopes {
        require_uuid("envelope Device id", device_id)?;
        let bytes = decode("Vault key envelope", envelope)?;
        if bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
            return Err(ReplicationError::Invalid(
                "Vault key envelope exceeds the format limit".to_string(),
            ));
        }
    }
    for device_id in document.revoked_devices.keys() {
        require_uuid("revoked Device id", device_id)?;
        if document.envelopes.contains_key(device_id) {
            return Err(ReplicationError::Invalid(format!(
                "revoked Device {device_id} still has an envelope in generation {}",
                document.generation
            )));
        }
    }
    let genesis_key = verifying_key("genesis public key", &vault.genesis_public_key)?;
    verify_struct(
        KEY_GENERATION_SIGNATURE_CONTEXT,
        &document.unsigned(),
        &document.signature,
        &genesis_key,
    )
}

fn load_trusted_devices(
    root: &Path,
    vault: &VaultDocument,
) -> ReplicationResult<HashMap<String, TrustedDevice>> {
    let mut trusted: HashMap<String, TrustedDevice> = HashMap::new();
    let devices_root = root.join("devices");
    for entry in fs::read_dir(&devices_root).map_err(|source| io_error(&devices_root, source))? {
        let entry = entry.map_err(|source| io_error(&devices_root, source))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| io_error(&path, source))?;
        if !file_type.is_dir() {
            continue;
        }
        let Some(directory_device_id) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if uuid::Uuid::parse_str(&directory_device_id).is_err() {
            continue;
        }
        let identity_path = path.join("identity.json");
        let identity = match read_device_identity(&identity_path, vault) {
            Ok(identity) => identity,
            Err(ReplicationError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        if identity.device_id != directory_device_id {
            return Err(ReplicationError::Invalid(format!(
                "Device identity {} is stored under directory {}",
                identity.device_id, directory_device_id
            )));
        }
        let device = TrustedDevice {
            verifying_key: verifying_key("Device public key", &identity.signing_public_key)?,
            wrapping_recipient: identity
                .wrapping_recipient
                .parse::<x25519::Recipient>()
                .map_err(|error| {
                    ReplicationError::Invalid(format!(
                        "invalid Device wrapping recipient: {error}"
                    ))
                })?,
            device_name: identity.device_name.clone(),
            enrolled_generation: identity.enrolled_generation,
            revoked_generation: None,
            revoked_after_sequence: None,
        };
        match trusted.get(&identity.device_id) {
            Some(existing)
                if existing.verifying_key != device.verifying_key
                    || existing.wrapping_recipient != device.wrapping_recipient
                    || existing.enrolled_generation != device.enrolled_generation =>
            {
                return Err(ReplicationError::Invalid(format!(
                    "Device {} has conflicting enrolled signing keys",
                    identity.device_id
                )));
            }
            Some(_) => {}
            None => {
                trusted.insert(identity.device_id.clone(), device);
            }
        }
    }
    if !trusted.contains_key(&vault.genesis_device_id) {
        return Err(ReplicationError::Invalid(
            "genesis Device identity has not arrived".to_string(),
        ));
    }
    Ok(trusted)
}

fn apply_generation_membership(
    trusted: &mut HashMap<String, TrustedDevice>,
    generations: &BTreeMap<u32, KeyGenerationDocument>,
    vault: &VaultDocument,
) -> ReplicationResult<()> {
    let current_generation = *generations.keys().next_back().expect("non-empty generations");
    for (device_id, device) in trusted.iter() {
        if device.enrolled_generation == 0 || device.enrolled_generation > current_generation {
            return Err(ReplicationError::Invalid(format!(
                "Device {device_id} names unavailable enrollment generation {}",
                device.enrolled_generation
            )));
        }
    }
    for (generation, document) in generations {
        for (device_id, sequence) in &document.revoked_devices {
            if device_id == &vault.genesis_device_id {
                return Err(ReplicationError::Invalid(
                    "v1 cannot revoke the genesis Device".to_string(),
                ));
            }
            let device = trusted.get_mut(device_id).ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "key generation {generation} revokes unknown Device {device_id}"
                ))
            })?;
            if device.enrolled_generation >= *generation || device.revoked_generation.is_some() {
                return Err(ReplicationError::Invalid(format!(
                    "Device {device_id} has an invalid revocation at generation {generation}"
                )));
            }
            device.revoked_generation = Some(*generation);
            device.revoked_after_sequence = Some(*sequence);
        }
    }
    Ok(())
}

fn load_vault_identities(
    root: &Path,
    device: &DeviceKeyMaterial,
    generations: &BTreeMap<u32, KeyGenerationDocument>,
) -> ReplicationResult<BTreeMap<u32, Arc<x25519::Identity>>> {
    let mut identities = BTreeMap::new();
    for (generation, document) in generations {
        let envelope = match document.envelopes.get(&device.device_id) {
            Some(envelope) => decode("Vault key envelope", envelope)?,
            None => read_untrusted_file(
                &root
                    .join("devices")
                    .join(&device.device_id)
                    .join("envelopes")
                    .join(envelope_filename(*generation)),
                MAX_DESCRIPTOR_BYTES,
            )?,
        };
        let identity_text = decrypt(&device.wrapping_identity, &envelope)?;
        let identity_text = std::str::from_utf8(&identity_text).map_err(|_| {
            ReplicationError::Encryption("Vault envelope is not UTF-8".to_string())
        })?;
        let identity = identity_text.parse::<x25519::Identity>().map_err(|error| {
            ReplicationError::Encryption(format!("Vault envelope identity is invalid: {error}"))
        })?;
        identities.insert(*generation, Arc::new(identity));
    }
    Ok(identities)
}

fn read_device_identity(
    path: &Path,
    vault: &VaultDocument,
) -> ReplicationResult<DeviceDocument> {
    let bytes = read_untrusted_file(path, MAX_DESCRIPTOR_BYTES)?;
    let identity: DeviceDocument = serde_json::from_slice(&bytes)?;
    validate_device_identity(&identity, vault)?;
    Ok(identity)
}

fn validate_enrollment(enrollment: &DeviceEnrollment) -> ReplicationResult<()> {
    require_uuid("device id", &enrollment.device_id)?;
    if let Some(device_name) = &enrollment.device_name {
        if device_name.is_empty()
            || device_name.trim() != device_name
            || device_name.chars().count() > 80
            || device_name.chars().any(char::is_control)
        {
            return Err(ReplicationError::Invalid(
                "Device name must be 1-80 printable characters without surrounding whitespace"
                    .to_string(),
            ));
        }
    }
    verifying_key("Device public key", &enrollment.signing_public_key)?;
    enrollment
        .wrapping_recipient
        .parse::<x25519::Recipient>()
        .map_err(|error| {
            ReplicationError::Invalid(format!("invalid Device wrapping recipient: {error}"))
        })?;
    Ok(())
}

fn validate_vault(vault: &VaultDocument) -> ReplicationResult<()> {
    if vault.format_version != FORMAT_VERSION {
        return Err(ReplicationError::Invalid(format!(
            "unsupported Vault format {}",
            vault.format_version
        )));
    }
    require_uuid("vault id", &vault.vault_id)?;
    require_uuid("genesis device id", &vault.genesis_device_id)?;
    let key = verifying_key("genesis public key", &vault.genesis_public_key)?;
    verify_struct(VAULT_SIGNATURE_CONTEXT, &vault.unsigned(), &vault.signature, &key)
}

fn validate_device_identity(
    identity: &DeviceDocument,
    vault: &VaultDocument,
) -> ReplicationResult<()> {
    if identity.format_version != FORMAT_VERSION
        || identity.vault_id != vault.vault_id
        || identity.authorized_by != vault.genesis_device_id
        || identity.enrolled_generation == 0
    {
        return Err(ReplicationError::Invalid(
            "Device identity does not match vault.json".to_string(),
        ));
    }
    validate_enrollment(&DeviceEnrollment {
        device_id: identity.device_id.clone(),
        signing_public_key: identity.signing_public_key.clone(),
        wrapping_recipient: identity.wrapping_recipient.clone(),
        device_name: identity.device_name.clone(),
    })?;
    if identity.device_id == vault.genesis_device_id
        && identity.signing_public_key != vault.genesis_public_key
    {
        return Err(ReplicationError::Invalid(
            "genesis Device identity does not match vault.json".to_string(),
        ));
    }
    let key = verifying_key("genesis public key", &vault.genesis_public_key)?;
    verify_struct(
        DEVICE_SIGNATURE_CONTEXT,
        &identity.unsigned(),
        &identity.signature,
        &key,
    )
}

fn sign_struct<T: Serialize>(
    context: &[u8],
    value: &T,
    key: &SigningKey,
) -> ReplicationResult<String> {
    let message = signing_bytes(context, value)?;
    Ok(encode(&key.sign(&message).to_bytes()))
}

fn verify_struct<T: Serialize>(
    context: &[u8],
    value: &T,
    encoded_signature: &str,
    key: &VerifyingKey,
) -> ReplicationResult<()> {
    let bytes = decode("signature", encoded_signature)?;
    let bytes: [u8; 64] = bytes.try_into().map_err(|_| {
        ReplicationError::Signature("Ed25519 signature must be 64 bytes".to_string())
    })?;
    key.verify(&signing_bytes(context, value)?, &Signature::from_bytes(&bytes))
        .map_err(|error| ReplicationError::Signature(error.to_string()))
}

fn signing_bytes<T: Serialize>(context: &[u8], value: &T) -> ReplicationResult<Vec<u8>> {
    let encoded = serde_json::to_vec(value)?;
    let mut message = Vec::with_capacity(context.len() + encoded.len());
    message.extend_from_slice(context);
    message.extend_from_slice(&encoded);
    Ok(message)
}

fn verifying_key(label: &str, encoded: &str) -> ReplicationResult<VerifyingKey> {
    let bytes = decode(label, encoded)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        ReplicationError::Invalid(format!("{label} must be 32 bytes"))
    })?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| ReplicationError::Invalid(format!("invalid {label}: {error}")))
}

fn encrypt(recipient: &x25519::Recipient, plaintext: &[u8]) -> ReplicationResult<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .ok_or_else(|| ReplicationError::Encryption("Vault has no recipient".to_string()))?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    writer
        .finish()
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    Ok(ciphertext)
}

fn encrypt_with_provider(
    keys: &dyn floria_store::KeyProvider,
    plaintext: &[u8],
) -> ReplicationResult<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(keys.recipients()?)
        .ok_or_else(|| ReplicationError::Encryption("Device key has no recipient".to_string()))?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    writer
        .finish()
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    Ok(ciphertext)
}

fn decrypt_with_provider(
    keys: &dyn floria_store::KeyProvider,
    ciphertext: &[u8],
) -> ReplicationResult<Zeroizing<Vec<u8>>> {
    let decryptor = match age::Decryptor::new(ciphertext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?
    {
        age::Decryptor::Recipients(decryptor) => decryptor,
        age::Decryptor::Passphrase(_) => {
            return Err(ReplicationError::Encryption(
                "Device key is passphrase-encrypted".to_string(),
            ));
        }
    };
    let identity = keys.identity()?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity.as_ref()))
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    Ok(plaintext)
}

fn decrypt(identity: &x25519::Identity, ciphertext: &[u8]) -> ReplicationResult<Zeroizing<Vec<u8>>> {
    let decryptor = match age::Decryptor::new(ciphertext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?
    {
        age::Decryptor::Recipients(decryptor) => decryptor,
        age::Decryptor::Passphrase(_) => {
            return Err(ReplicationError::Encryption(
                "passphrase-encrypted data is not a Vault object".to_string(),
            ));
        }
    };
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    Ok(plaintext)
}

fn scan_objects(
    root: &Path,
    report: &mut PackageScan,
) -> ReplicationResult<HashMap<String, Vec<u8>>> {
    let mut objects = HashMap::new();
    for path in regular_files_recursively(root)? {
        let bytes = match read_untrusted_file(&path, MAX_OBJECT_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                report.damaged.push(DamagedFile { path, reason: error.to_string() });
                continue;
            }
        };
        let id = digest(&bytes);
        if let Some(claimed) = canonical_object_id(&path) {
            if claimed != id {
                report.damaged.push(DamagedFile {
                    path,
                    reason: format!(
                        "canonical object name claims digest {claimed}, actual digest is {id}"
                    ),
                });
                continue;
            }
        }
        if objects.insert(id.clone(), bytes.clone()).is_some() {
            report.duplicate_files += 1;
        }
        let canonical = root.join(format!("{id}.age"));
        if path != canonical && !canonical.exists() {
            if let Err(error) = publish_immutable(&canonical, &bytes) {
                report.damaged.push(DamagedFile {
                    path: path.clone(),
                    reason: format!("cannot normalize object conflict copy: {error}"),
                });
            }
        }
    }
    Ok(objects)
}

fn regular_files_recursively(root: &Path) -> ReplicationResult<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| io_error(&directory, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|source| io_error(&path, source))?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn read_untrusted_file(path: &Path, maximum: u64) -> ReplicationResult<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.is_file() {
        return Err(ReplicationError::Invalid(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(ReplicationError::Invalid(format!(
            "{} exceeds the {} byte format limit",
            path.display(), maximum
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|source| io_error(path, source))?;
    Ok(bytes)
}

fn publish_immutable(path: &Path, bytes: &[u8]) -> ReplicationResult<()> {
    match read_untrusted_file(path, bytes.len() as u64) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {
            return Err(ReplicationError::Invalid(format!(
                "immutable path {} already contains different bytes",
                path.display()
            )));
        }
        Err(ReplicationError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    write_new_atomic(path, bytes)
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> ReplicationResult<()> {
    let parent = path.parent().ok_or_else(|| {
        ReplicationError::Invalid(format!("{} has no parent directory", path.display()))
    })?;
    let temporary = parent.join(format!(".floria-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|source| io_error(&temporary, source))?;
    file.write_all(bytes).map_err(|source| io_error(&temporary, source))?;
    file.sync_all().map_err(|source| io_error(&temporary, source))?;
    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            fs::remove_file(&temporary).map_err(|source| io_error(&temporary, source))?;
        }
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            return publish_immutable(path, bytes);
        }
        Err(source) => {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(path, source));
        }
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(parent, source))
}

fn write_replace_atomic(path: &Path, bytes: &[u8]) -> ReplicationResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReplicationError::Invalid(format!(
            "replacement path {} is not a regular file",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        ReplicationError::Invalid(format!("{} has no parent directory", path.display()))
    })?;
    let temporary = parent.join(format!(".floria-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|source| io_error(&temporary, source))?;
        file.write_all(bytes).map_err(|source| io_error(&temporary, source))?;
        file.sync_all().map_err(|source| io_error(&temporary, source))?;
        fs::rename(&temporary, path).map_err(|source| io_error(path, source))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(parent, source))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn canonical_object_id(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let id = name.strip_suffix(".age")?;
    (id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| id.to_ascii_lowercase())
}

fn create_private_directory(path: &Path) -> ReplicationResult<()> {
    fs::DirBuilder::new()
        .recursive(false)
        .mode(0o700)
        .create(path)
        .map_err(|source| io_error(path, source))
}

fn ensure_private_package_directory(path: &Path) -> ReplicationResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(ReplicationError::Invalid(format!(
                "replication package path {} is not a real directory",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_private_directory(path),
        Err(source) => Err(io_error(path, source)),
    }
}

fn ensure_private_local_state_directory(path: &Path) -> ReplicationResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(ReplicationError::Invalid(format!(
                "replication local-state path {} is not a real directory",
                path.display()
            )))
        }
        Ok(metadata) if metadata.permissions().mode() & 0o077 != 0 => {
            Err(ReplicationError::Invalid(format!(
                "replication local-state directory {} must not be accessible by group or others",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "replication local-state path {} has no parent",
                    path.display()
                ))
            })?;
            let parent_metadata = fs::symlink_metadata(parent)
                .map_err(|source| io_error(parent, source))?;
            if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
                return Err(ReplicationError::Invalid(format!(
                    "replication local-state parent {} is not a real directory",
                    parent.display()
                )));
            }
            create_private_directory(path)
        }
        Err(source) => Err(io_error(path, source)),
    }
}

fn path_exists(path: &Path) -> ReplicationResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn sync_directory(path: &Path) -> ReplicationResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

#[cfg(target_os = "macos")]
fn rename_directory_exclusive(source: &Path, target: &Path) -> ReplicationResult<()> {
    let source_bytes = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        ReplicationError::Invalid(format!("{} contains a NUL byte", source.display()))
    })?;
    let target_bytes = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
        ReplicationError::Invalid(format!("{} contains a NUL byte", target.display()))
    })?;
    // SAFETY: both pointers are valid NUL-terminated paths for the duration of the call.
    let result = unsafe {
        libc::renamex_np(
            source_bytes.as_ptr(),
            target_bytes.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_error(target, io::Error::last_os_error()))
    }
}

#[cfg(not(target_os = "macos"))]
fn rename_directory_exclusive(source: &Path, target: &Path) -> ReplicationResult<()> {
    if path_exists(target)? {
        return Err(ReplicationError::Invalid(format!(
            "replication package already exists at {}",
            target.display()
        )));
    }
    fs::rename(source, target).map_err(|error| io_error(target, error))
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(label: &str, value: &str) -> ReplicationResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| ReplicationError::Invalid(format!("{label} is not Base64: {error}")))
}

fn require_uuid(label: &str, value: &str) -> ReplicationResult<()> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ReplicationError::Invalid(format!("{label} is not a UUID: {value:?}")))
}

fn validate_intent(intent: &ReplicationIntent) -> ReplicationResult<()> {
    require_uuid("replication intent id", &intent.intent_id)?;
    if intent.logical_id.trim().is_empty() {
        return Err(ReplicationError::Invalid(
            "replication intent logical id is empty".to_string(),
        ));
    }
    if intent.catalog_payload.is_empty() {
        return Err(ReplicationError::Invalid(
            "replication intent catalog payload is empty".to_string(),
        ));
    }
    if intent.created_at.trim().is_empty() {
        return Err(ReplicationError::Invalid(
            "replication intent creation time is empty".to_string(),
        ));
    }
    let mut mutation_ids = HashSet::new();
    let mut secret_ids = HashSet::new();
    for mutation in &intent.store_mutations {
        require_uuid("replication store secret id", &mutation.secret_id)?;
        require_uuid("replication store mutation id", &mutation.mutation_id)?;
        if !mutation_ids.insert(&mutation.mutation_id) {
            return Err(ReplicationError::Invalid(format!(
                "replication store mutation {} is duplicated",
                mutation.mutation_id
            )));
        }
        if !secret_ids.insert(&mutation.secret_id) {
            return Err(ReplicationError::Invalid(format!(
                "replication store secret {} appears more than once",
                mutation.secret_id
            )));
        }
    }
    for reference in &intent.store_versions {
        require_uuid("replication store secret id", &reference.secret_id)?;
        if reference.version == 0 || !secret_ids.insert(&reference.secret_id) {
            return Err(ReplicationError::Invalid(format!(
                "replication store version {}:{} is invalid or duplicated",
                reference.secret_id, reference.version
            )));
        }
    }
    if let Some(prepared) = &intent.prepared {
        if prepared.operation_id != intent.intent_id {
            return Err(ReplicationError::Invalid(
                "prepared operation id does not match its durable intent".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_journal(state: &IntentJournalState) -> ReplicationResult<()> {
    let mut ids = HashSet::new();
    for intent in &state.entries {
        validate_intent(intent)?;
        if !ids.insert(&intent.intent_id) {
            return Err(ReplicationError::Invalid(format!(
                "replication intent {} appears more than once",
                intent.intent_id
            )));
        }
    }
    for (device_id, operations) in &state.accepted_operations {
        require_uuid("device checkpoint id", device_id)?;
        for (index, (sequence, operation_id)) in operations.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "device checkpoint {device_id} sequence overflow"
                    ))
                })?;
            if *sequence != expected {
                return Err(ReplicationError::Invalid(format!(
                    "device checkpoint {device_id} has a gap before sequence {sequence}"
                )));
            }
            require_uuid("checkpoint operation id", operation_id)?;
        }
    }
    for (index, (generation, fingerprint)) in state.accepted_key_generations.iter().enumerate() {
        let expected = u32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or_else(|| {
                ReplicationError::Invalid("key generation checkpoint overflow".to_string())
            })?;
        if *generation != expected {
            return Err(ReplicationError::Invalid(format!(
                "key generation checkpoint has a gap before {generation}"
            )));
        }
        if fingerprint.len() != 64
            || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ReplicationError::Invalid(format!(
                "key generation {generation} checkpoint fingerprint is invalid"
            )));
        }
    }
    Ok(())
}

fn io_error(path: &Path, source: io::Error) -> ReplicationError {
    ReplicationError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
mod tests {
    use super::*;
    use floria_catalog::{
        EntrySpec, ReplicatedCatalog, ReplicatedProject, ReplicationStoreVersionRef, Resource,
        ResourceCodec, ResourceKind, ResourceSource, ValueShape,
    };
    use floria_store::{KeyProvider, NewSecret, StoreResult};
    use std::os::unix::fs::PermissionsExt;

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_ID: &str = "22222222-2222-4222-8222-222222222222";
    const OPERATION_ID: &str = "33333333-3333-4333-8333-333333333333";
    const SECOND_DEVICE_ID: &str = "44444444-4444-4444-8444-444444444444";
    const SECOND_OPERATION_ID: &str = "77777777-7777-4777-8777-777777777777";
    const GENESIS_CHILD_OPERATION_ID: &str = "99999999-9999-4999-8999-999999999999";
    const MERGE_OPERATION_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const THIRD_OPERATION_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    fn keys(seed: u8, vault_identity: x25519::Identity) -> DeviceKeyMaterial {
        DeviceKeyMaterial::new(DEVICE_ID, [seed; 32], vault_identity).unwrap()
    }

    fn second_device_keys(seed: u8, wrapping_identity: x25519::Identity) -> DeviceKeyMaterial {
        DeviceKeyMaterial::new(SECOND_DEVICE_ID, [seed; 32], wrapping_identity).unwrap()
    }

    fn third_device_keys(wrapping_identity: x25519::Identity) -> DeviceKeyMaterial {
        DeviceKeyMaterial::new(
            "88888888-8888-4888-8888-888888888888",
            [9; 32],
            wrapping_identity,
        )
        .unwrap()
    }

    fn package() -> (tempfile::TempDir, ReplicationPackage) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let package = ReplicationPackage::create(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, x25519::Identity::generate()),
            x25519::Identity::generate(),
            x25519::Identity::generate().to_public().to_string(),
        )
        .unwrap();
        (directory, package)
    }

    fn open_store(directory: &Path, label: &str) -> Arc<AgeDirStore> {
        Arc::new(
            AgeDirStore::open(
                directory.join(format!("{label}-store")),
                Arc::new(LocalStoreKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        )
    }

    /// Create a Vault whose generation 1 IS the local store's, so the version files that store
    /// already wrote stay decryptable for every enrolled Device (zero transcoding).
    fn package_for_store(
        root: &Path,
        store: &AgeDirStore,
        device: DeviceKeyMaterial,
    ) -> ReplicationPackage {
        ReplicationPackage::create(
            root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            device,
            store.generation_identity(1).unwrap(),
            store.recovery_recipient().unwrap(),
        )
        .unwrap()
    }

    fn catalog_entity(projection: &ReplicatedCatalog, parents: Vec<String>) -> EntityPayload {
        EntityPayload {
            logical_id: CATALOG_LOGICAL_ID.to_string(),
            parents,
            delta: EntityDelta::Catalog {
                payload: serde_json::to_vec(projection).unwrap(),
            },
        }
    }

    fn decoded_catalog(entity: &EntityPayload) -> ReplicatedCatalog {
        match &entity.delta {
            EntityDelta::Catalog { payload } => serde_json::from_slice(payload).unwrap(),
            EntityDelta::Secret(_) => panic!("expected a catalog entity"),
        }
    }

    /// One secret entity plus the verbatim version file it references, taken from a local store.
    fn secret_entity(
        store: &AgeDirStore,
        id: &SecretId,
        ordinal: u32,
        parents: Vec<String>,
    ) -> (EntityPayload, PreparedObject) {
        let export = store.export_version(id, ordinal).unwrap();
        let descriptor = descriptor_from_record(&store.record(id).unwrap().unwrap());
        let entity = EntityPayload {
            logical_id: id.to_string(),
            parents,
            delta: EntityDelta::Secret(SecretDelta {
                descriptor,
                versions: vec![SecretVersionRef {
                    version_uuid: export.version_uuid.clone(),
                    generation: export.generation,
                    size: export.size,
                    object: ObjectReference {
                        id: export.digest.clone(),
                        ciphertext_size: export.ciphertext.len() as u64,
                    },
                }],
                head_uuid: export.version_uuid,
            }),
        };
        (entity, PreparedObject { id: export.digest, bytes: export.ciphertext })
    }

    fn version_blob(store: &AgeDirStore, id: &SecretId, digest: &str) -> Vec<u8> {
        fs::read(store.root().join(id.to_string()).join("v").join(format!("{digest}.age")))
            .unwrap()
    }

    fn intent(intent_id: &str) -> ReplicationIntent {
        ReplicationIntent::new(
            intent_id,
            "managed-item-1",
            Vec::new(),
            vec![IntentStoreMutation {
                secret_id: "55555555-5555-4555-8555-555555555555".to_string(),
                mutation_id: "66666666-6666-4666-8666-666666666666".to_string(),
            }],
            br#"{"kind":"fixture"}"#.to_vec(),
            "2026-08-06T00:00:00Z",
        )
        .unwrap()
    }

    fn projection(secret_id: &SecretId) -> ReplicatedCatalog {
        ReplicatedCatalog {
            resources: vec![Resource {
                id: "resource-1".to_string(),
                name: "Fixture value".to_string(),
                kind: ResourceKind::SharedSecret,
                shape: ValueShape::Scalar,
                codec: ResourceCodec::Opaque,
                default_env_key: Some("FIXTURE_VALUE".to_string()),
                entries: vec![EntrySpec {
                    address: "value".to_string(),
                    label: "FIXTURE_VALUE".to_string(),
                    key: Some("FIXTURE_VALUE".to_string()),
                    sensitive: true,
                }],
                source: ResourceSource::SecretRef { secret_id: secret_id.to_string() },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            }],
            ..Default::default()
        }
    }

    fn project_projection(name: &str) -> ReplicatedCatalog {
        ReplicatedCatalog {
            projects: vec![ReplicatedProject {
                id: "project-1".to_string(),
                name: name.to_string(),
                default_environment_id: None,
            }],
            ..Default::default()
        }
    }

    fn project_with_secret_projection(secret_id: &SecretId, name: &str) -> ReplicatedCatalog {
        let mut projection = projection(secret_id);
        projection.projects = project_projection(name).projects;
        projection
    }

    fn engine_for_package(
        directory: &Path,
        label: &str,
        package: ReplicationPackage,
        authentication_key: [u8; 32],
        store: Arc<AgeDirStore>,
    ) -> (ReplicationEngine, Arc<Catalog>) {
        let catalog = Arc::new(
            Catalog::open(directory.join(format!("{label}-catalog.sqlite"))).unwrap(),
        );
        let engine = ReplicationEngine::from_parts(
            package,
            Arc::new(
                ReplicationIntentJournal::open(
                    directory.join(format!("{label}-intents.json")),
                    VAULT_ID,
                    Arc::new(StateAuthenticator::for_tests(authentication_key)),
                )
                .unwrap(),
            ),
            Arc::clone(&catalog),
            store,
        );
        (engine, catalog)
    }

    struct LocalStoreKeys(x25519::Identity);

    impl KeyProvider for LocalStoreKeys {
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.0.to_public())])
        }

        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    #[test]
    fn create_open_and_single_device_round_trip() {
        let (directory, package) = package();
        let identity = package.device.wrapping_identity.clone();
        let projection = project_projection("Fixture project");
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(&projection, Vec::new())],
                objects: &[],
            })
            .unwrap();
        package.publish(&prepared).unwrap();

        let reopened = ReplicationPackage::open(
            directory.path().join("Personal.floriavault"),
            keys(7, identity),
        )
        .unwrap();
        let scan = reopened.scan().unwrap();

        assert!(scan.pending.is_empty());
        assert!(scan.damaged.is_empty());
        assert_eq!(scan.verified.len(), 1);
        let entities = &scan.verified[0].payload.entities;
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].logical_id, CATALOG_LOGICAL_ID);
        assert_eq!(decoded_catalog(&entities[0]), projection);
    }

    #[test]
    fn enrolled_device_can_decrypt_and_publish_its_own_operations() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let mut genesis = ReplicationPackage::create(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, x25519::Identity::generate()),
            x25519::Identity::generate(),
            x25519::Identity::generate().to_public().to_string(),
        )
        .unwrap();
        let second_wrapping_identity = x25519::Identity::generate();
        let second = second_device_keys(8, second_wrapping_identity.clone());
        genesis.enroll_device(second.enrollment()).unwrap();

        let from_genesis = project_projection("From genesis");
        let genesis_publication = genesis
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(&from_genesis, Vec::new())],
                objects: &[],
            })
            .unwrap();
        genesis.publish(&genesis_publication).unwrap();

        let second = ReplicationPackage::open(
            &root,
            second_device_keys(8, second_wrapping_identity),
        )
        .unwrap();
        let initial_scan = second.scan().unwrap();
        assert!(initial_scan.damaged.is_empty());
        assert_eq!(initial_scan.verified.len(), 1);
        assert_eq!(
            decoded_catalog(&initial_scan.verified[0].payload.entities[0]),
            from_genesis
        );

        let from_second = project_projection("From second Device");
        let second_publication = second
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: SECOND_OPERATION_ID,
                entities: &[catalog_entity(&from_second, vec![OPERATION_ID.to_string()])],
                objects: &[],
            })
            .unwrap();
        second.publish(&second_publication).unwrap();

        let final_scan = genesis.scan().unwrap();
        assert!(final_scan.damaged.is_empty());
        assert_eq!(final_scan.verified.len(), 2);
        assert!(final_scan.verified.iter().any(|mutation| {
            mutation.device_id == SECOND_DEVICE_ID
                && mutation.operation_id == SECOND_OPERATION_ID
                && decoded_catalog(&mutation.payload.entities[0]) == from_second
        }));
    }

    #[test]
    fn enrolled_device_requires_its_private_wrapping_identity() {
        let (directory, mut package) = package();
        let second = second_device_keys(8, x25519::Identity::generate());
        package.enroll_device(second.enrollment()).unwrap();

        let error = match ReplicationPackage::open(
            directory.path().join("Personal.floriavault"),
            second_device_keys(8, x25519::Identity::generate()),
        ) {
            Ok(_) => panic!("wrong wrapping identity unexpectedly opened the Vault"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("private keys do not match"));
    }

    #[test]
    fn tampered_enrollment_is_rejected_before_vault_key_unwrap() {
        let (directory, mut package) = package();
        let wrapping_identity = x25519::Identity::generate();
        let second = second_device_keys(8, wrapping_identity.clone());
        package.enroll_device(second.enrollment()).unwrap();
        let identity_path = directory
            .path()
            .join("Personal.floriavault/devices")
            .join(SECOND_DEVICE_ID)
            .join("identity.json");
        let mut document: DeviceDocument =
            serde_json::from_slice(&fs::read(&identity_path).unwrap()).unwrap();
        document.wrapping_recipient = x25519::Identity::generate().to_public().to_string();
        fs::write(&identity_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let error = match ReplicationPackage::open(
            directory.path().join("Personal.floriavault"),
            second_device_keys(8, wrapping_identity),
        ) {
            Ok(_) => panic!("tampered enrollment unexpectedly opened the Vault"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("replication signature failed"));
    }

    #[test]
    fn non_genesis_device_cannot_enroll_another_device() {
        let (directory, mut genesis) = package();
        let second_wrapping_identity = x25519::Identity::generate();
        genesis
            .enroll_device(
                second_device_keys(8, second_wrapping_identity.clone()).enrollment(),
            )
            .unwrap();
        let mut second = ReplicationPackage::open(
            directory.path().join("Personal.floriavault"),
            second_device_keys(8, second_wrapping_identity),
        )
        .unwrap();
        let third = DeviceKeyMaterial::new(
            "88888888-8888-4888-8888-888888888888",
            [9; 32],
            x25519::Identity::generate(),
        )
        .unwrap();

        let error = second.enroll_device(third.enrollment()).unwrap_err();

        assert!(error.to_string().contains("only the genesis Device"));
    }

    #[test]
    fn concurrent_heads_require_an_explicit_signed_merge() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let mut genesis = ReplicationPackage::create(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, x25519::Identity::generate()),
            x25519::Identity::generate(),
            x25519::Identity::generate().to_public().to_string(),
        )
        .unwrap();
        let second_wrapping_identity = x25519::Identity::generate();
        genesis
            .enroll_device(
                second_device_keys(8, second_wrapping_identity.clone()).enrollment(),
            )
            .unwrap();
        let second = ReplicationPackage::open(
            &root,
            second_device_keys(8, second_wrapping_identity),
        )
        .unwrap();

        let base = genesis
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(&project_projection("Base"), Vec::new())],
                objects: &[],
            })
            .unwrap();
        genesis.publish(&base).unwrap();
        let base_parent = vec![OPERATION_ID.to_string()];
        let genesis_child = genesis
            .prepare(PackageMutation {
                sequence: 2,
                operation_id: GENESIS_CHILD_OPERATION_ID,
                entities: &[catalog_entity(
                    &project_projection("Genesis branch"),
                    base_parent.clone(),
                )],
                objects: &[],
            })
            .unwrap();
        genesis.publish(&genesis_child).unwrap();
        let second_child = second
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: SECOND_OPERATION_ID,
                entities: &[catalog_entity(
                    &project_projection("Second branch"),
                    base_parent.clone(),
                )],
                objects: &[],
            })
            .unwrap();
        second.publish(&second_child).unwrap();

        let conflicted = genesis.scan().unwrap();
        assert!(conflicted.pending.is_empty());
        assert_eq!(conflicted.conflicts.len(), 1);
        assert_eq!(conflicted.conflicts[0].logical_id, CATALOG_LOGICAL_ID);
        assert_eq!(
            conflicted.conflicts[0].head_operation_ids,
            vec![SECOND_OPERATION_ID.to_string(), GENESIS_CHILD_OPERATION_ID.to_string()]
        );

        let merge_parents = vec![
            GENESIS_CHILD_OPERATION_ID.to_string(),
            SECOND_OPERATION_ID.to_string(),
        ];
        let merge = genesis
            .prepare(PackageMutation {
                sequence: 3,
                operation_id: MERGE_OPERATION_ID,
                entities: &[catalog_entity(&project_projection("Merged"), merge_parents)],
                objects: &[],
            })
            .unwrap();
        genesis.publish(&merge).unwrap();

        let resolved = second.scan().unwrap();
        assert!(resolved.pending.is_empty());
        assert!(resolved.conflicts.is_empty());
        assert_eq!(resolved.verified.len(), 4);
        assert_eq!(resolved.verified.last().unwrap().operation_id, MERGE_OPERATION_ID);
    }

    #[test]
    fn concurrent_local_snapshots_keep_each_devices_projection_and_report_the_conflict() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis = package_for_store(
            &root,
            &genesis_store,
            keys(7, x25519::Identity::generate()),
        );
        let second_wrapping_identity = x25519::Identity::generate();
        genesis
            .enroll_device(
                second_device_keys(8, second_wrapping_identity.clone()).enrollment(),
            )
            .unwrap();
        let second = ReplicationPackage::open(
            &root,
            second_device_keys(8, second_wrapping_identity),
        )
        .unwrap();
        let (genesis, genesis_catalog) = engine_for_package(
            directory.path(),
            "genesis",
            genesis,
            [81; 32],
            Arc::clone(&genesis_store),
        );
        let (second, second_catalog) = engine_for_package(
            directory.path(),
            "second",
            second,
            [82; 32],
            Arc::clone(&second_store),
        );

        let secret_id: SecretId = "77777777-7777-4777-8777-777777777777".parse().unwrap();
        genesis_store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("Conflict resolution fixture"),
                b"base fixture payload",
                "88888888-8888-4888-8888-888888888888",
            )
            .unwrap();
        genesis_catalog
            .apply_replicated_catalog(&project_with_secret_projection(&secret_id, "Base"))
            .unwrap();

        assert!(genesis.stage_current_snapshot("base").unwrap());
        assert_eq!(genesis.sync().unwrap().published, 1);
        assert_eq!(second.sync().unwrap().imported, 1);
        assert_eq!(
            second_store.get(&secret_id).unwrap().as_slice(),
            b"base fixture payload"
        );

        genesis_store
            .append_version(&secret_id, b"genesis branch fixture payload")
            .unwrap();
        second_store
            .append_version(&secret_id, b"second branch fixture payload")
            .unwrap();
        genesis_catalog
            .apply_replicated_catalog(&project_with_secret_projection(
                &secret_id,
                "Genesis branch",
            ))
            .unwrap();
        second_catalog
            .apply_replicated_catalog(&project_with_secret_projection(
                &secret_id,
                "Second branch",
            ))
            .unwrap();
        assert!(genesis.stage_current_snapshot("genesis edit").unwrap());
        assert!(second.stage_current_snapshot("second edit").unwrap());

        assert_eq!(genesis.sync().unwrap().published, 1);
        let second_report = second.sync().unwrap();

        // Both Devices changed the catalog and the same secret: two entities, two conflicts.
        assert_eq!(second_report.published, 1);
        assert_eq!(second_report.imported, 0);
        assert_eq!(second_report.conflicts, 2);
        assert_eq!(
            genesis_catalog.replicated_catalog().unwrap(),
            project_with_secret_projection(&secret_id, "Genesis branch")
        );
        assert_eq!(
            second_catalog.replicated_catalog().unwrap(),
            project_with_secret_projection(&secret_id, "Second branch")
        );
        assert_eq!(
            genesis_store.get(&secret_id).unwrap().as_slice(),
            b"genesis branch fixture payload"
        );
        assert_eq!(
            second_store.get(&secret_id).unwrap().as_slice(),
            b"second branch fixture payload"
        );
        assert_eq!(genesis.sync().unwrap().conflicts, 2);

        let resolved = second
            .resolve_conflict_with_current("keep second branch")
            .unwrap();
        assert_eq!(resolved.published, 1);
        assert_eq!(resolved.conflicts, 0);
        assert_eq!(genesis.sync().unwrap().imported, 2);
        assert_eq!(
            genesis_catalog.replicated_catalog().unwrap(),
            project_with_secret_projection(&secret_id, "Second branch")
        );
        assert_eq!(
            second_catalog.replicated_catalog().unwrap(),
            project_with_secret_projection(&secret_id, "Second branch")
        );
        assert_eq!(
            genesis_store.get(&secret_id).unwrap().as_slice(),
            b"second branch fixture payload"
        );
        assert_eq!(
            second_store.get(&secret_id).unwrap().as_slice(),
            b"second branch fixture payload"
        );
    }

    #[test]
    fn revocation_rotates_the_vault_key_and_fences_late_operations() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let genesis_wrapping_identity = x25519::Identity::generate();
        let genesis_store = open_store(directory.path(), "genesis");
        let mut genesis = ReplicationPackage::create_named(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, genesis_wrapping_identity.clone()),
            Some("Owner Mac".to_string()),
            genesis_store.generation_identity(1).unwrap(),
            genesis_store.recovery_recipient().unwrap(),
        )
        .unwrap();
        let second_wrapping_identity = x25519::Identity::generate();
        genesis
            .enroll_device(
                second_device_keys(8, second_wrapping_identity.clone())
                    .enrollment_named(Some("Second Mac".to_string())),
            )
            .unwrap();
        let second = ReplicationPackage::open(
            &root,
            second_device_keys(8, second_wrapping_identity.clone()),
        )
        .unwrap();
        let before_revocation = second
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: SECOND_OPERATION_ID,
                entities: &[catalog_entity(
                    &project_projection("Accepted before revocation"),
                    Vec::new(),
                )],
                objects: &[],
            })
            .unwrap();
        second.publish(&before_revocation).unwrap();
        let late = second
            .prepare(PackageMutation {
                sequence: 2,
                operation_id: GENESIS_CHILD_OPERATION_ID,
                entities: &[catalog_entity(
                    &project_projection("Must not be accepted"),
                    vec![SECOND_OPERATION_ID.to_string()],
                )],
                objects: &[],
            })
            .unwrap();

        let (mut genesis, _genesis_catalog) = engine_for_package(
            directory.path(),
            "genesis",
            genesis,
            [83; 32],
            Arc::clone(&genesis_store),
        );
        let devices = genesis.devices();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].device_name.as_deref(), Some("Owner Mac"));
        assert!(devices[0].is_current);
        assert_eq!(devices[1].device_name.as_deref(), Some("Second Mac"));
        assert!(!devices[1].is_current);

        // Revocation rotates the store first, then publishes the matching Vault generation, so
        // the two key domains stay in lockstep.
        assert!(!genesis.revoke_device(SECOND_DEVICE_ID).unwrap().local_device_fenced);
        assert_eq!(genesis.current_generation(), 2);
        assert_eq!(genesis_store.current_generation().unwrap(), 2);
        assert_eq!(
            genesis_store.generation_public(2).unwrap(),
            Some(
                genesis
                    .package
                    .generation_identity_secrets()
                    .into_iter()
                    .find(|(generation, _)| *generation == 2)
                    .map(|(_, secret)| secret.trim().parse::<x25519::Identity>().unwrap())
                    .unwrap()
                    .to_public()
                    .to_string()
            )
        );
        assert_eq!(genesis.devices()[1].revoked_generation, Some(2));
        let re_enrollment = genesis
            .enroll_device(
                second_device_keys(8, second_wrapping_identity.clone()).enrollment(),
            )
            .unwrap_err();
        assert!(re_enrollment.to_string().contains("new Device id"));
        let after_rotation = genesis
            .package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(
                    &project_projection("New generation"),
                    vec![SECOND_OPERATION_ID.to_string()],
                )],
                objects: &[],
            })
            .unwrap();
        genesis.package.publish(&after_rotation).unwrap();

        let local_fence = second.publish(&late).unwrap_err();
        assert!(local_fence.to_string().contains("was revoked at key generation 2"));
        publish_immutable(&second.operation_path(&late), &late.operation).unwrap();

        let scan = genesis.package.scan().unwrap();
        assert_eq!(scan.verified.len(), 2);
        assert!(scan.damaged.iter().any(|damaged| {
            damaged.reason.contains("not authorized for key generation")
        }));

        let reopened = ReplicationPackage::open(
            &root,
            keys(7, genesis_wrapping_identity),
        )
        .unwrap();
        assert_eq!(reopened.current_generation(), 2);
        let revoked_error = match ReplicationPackage::open(
            &root,
            second_device_keys(8, second_wrapping_identity),
        ) {
            Ok(_) => panic!("revoked Device unexpectedly reopened the Vault"),
            Err(error) => error,
        };
        assert!(revoked_error.to_string().contains("was revoked at key generation 2"));

        let third_wrapping_identity = x25519::Identity::generate();
        genesis
            .enroll_device(third_device_keys(third_wrapping_identity.clone()).enrollment())
            .unwrap();
        let third = ReplicationPackage::open(
            &root,
            third_device_keys(third_wrapping_identity),
        )
        .unwrap();
        assert_eq!(third.current_generation(), 2);
        let third_publication = third
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: THIRD_OPERATION_ID,
                entities: &[catalog_entity(
                    &project_projection("Enrolled after rotation"),
                    vec![OPERATION_ID.to_string()],
                )],
                objects: &[],
            })
            .unwrap();
        third.publish(&third_publication).unwrap();
        let final_scan = genesis.package.scan().unwrap();
        assert!(final_scan.verified.iter().any(|mutation| {
            mutation.device_id == third.device_id()
                && mutation.key_generation == 2
                && mutation.operation_id == THIRD_OPERATION_ID
        }));
    }

    #[test]
    fn operation_waits_when_object_has_not_arrived() {
        let (directory, package) = package();
        let store = open_store(directory.path(), "source");
        let secret_id: SecretId = "55555555-5555-4555-8555-555555555555".parse().unwrap();
        store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("Fixture value"),
                b"fixture payload, not a credential",
                "66666666-6666-4666-8666-666666666666",
            )
            .unwrap();
        let (entity, object) = secret_entity(&store, &secret_id, 1, Vec::new());
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[entity],
                objects: std::slice::from_ref(&object),
            })
            .unwrap();
        publish_immutable(&package.operation_path(&prepared), &prepared.operation).unwrap();

        let pending = package.scan().unwrap();
        assert_eq!(pending.pending.len(), 1);
        assert!(pending.pending[0].reason.contains("has not arrived"));

        publish_immutable(
            &package.root.join("objects").join(format!("{}.age", object.id)),
            &object.bytes,
        )
        .unwrap();
        let complete = package.scan().unwrap();
        assert_eq!(complete.verified.len(), 1);
        assert!(complete.pending.is_empty());
    }

    #[test]
    fn object_conflict_copy_is_validated_and_normalized_by_digest() {
        let (directory, package) = package();
        let store = open_store(directory.path(), "source");
        let secret_id: SecretId = "55555555-5555-4555-8555-555555555555".parse().unwrap();
        store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("Fixture value"),
                b"fixture payload, not a credential",
                "66666666-6666-4666-8666-666666666666",
            )
            .unwrap();
        let (entity, object) = secret_entity(&store, &secret_id, 1, Vec::new());
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[entity],
                objects: std::slice::from_ref(&object),
            })
            .unwrap();
        let conflict_copy = package.root.join("objects/object (conflicted copy).age");
        fs::write(&conflict_copy, &object.bytes).unwrap();
        publish_immutable(&package.operation_path(&prepared), &prepared.operation).unwrap();

        let scan = package.scan().unwrap();
        assert_eq!(scan.verified.len(), 1);
        assert!(package
            .root
            .join("objects")
            .join(format!("{}.age", object.id))
            .is_file());
    }

    #[test]
    fn tampered_operation_is_rejected_before_decryption() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(&project_projection("Fixture"), Vec::new())],
                objects: &[],
            })
            .unwrap();
        package.publish(&prepared).unwrap();
        let path = package.operation_path(&prepared);
        let mut operation: OperationDocument =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        operation.sequence = 2;
        fs::write(&path, serde_json::to_vec(&operation).unwrap()).unwrap();

        let scan = package.scan().unwrap();
        assert!(scan.verified.is_empty());
        assert_eq!(scan.damaged.len(), 1);
        assert!(scan.damaged[0].reason.contains("signature"));
    }

    #[test]
    fn sequence_gap_keeps_later_operation_pending() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 2,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(&project_projection("Fixture"), Vec::new())],
                objects: &[],
            })
            .unwrap();
        package.publish(&prepared).unwrap();

        let scan = package.scan().unwrap();
        assert!(scan.verified.is_empty());
        assert_eq!(scan.pending.len(), 1);
        assert_eq!(scan.pending[0].reason, "sequence 1 has not arrived");
    }

    #[test]
    fn two_valid_envelopes_for_one_device_slot_are_equivocation() {
        let (_directory, package) = package();
        let first = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(&project_projection("First"), Vec::new())],
                objects: &[],
            })
            .unwrap();
        let second = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: "44444444-4444-4444-8444-444444444444",
                entities: &[catalog_entity(&project_projection("Second"), Vec::new())],
                objects: &[],
            })
            .unwrap();
        package.publish(&first).unwrap();
        package.publish(&second).unwrap();

        let scan = package.scan().unwrap();
        assert!(scan.verified.is_empty());
        assert_eq!(scan.damaged.len(), 2);
        assert!(scan
            .damaged
            .iter()
            .all(|damaged| damaged.reason.contains("equivocated")));
    }

    #[test]
    fn immutable_publication_never_overwrites_existing_bytes() {
        let (_directory, package) = package();
        let path = package.root.join("objects/collision.age");
        publish_immutable(&path, b"first").unwrap();

        let error = publish_immutable(&path, b"second").unwrap_err();

        assert!(error.to_string().contains("different bytes"));
        assert_eq!(fs::read(path).unwrap(), b"first");
    }

    #[test]
    fn package_creation_never_replaces_an_existing_directory() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("keep"), b"existing package marker").unwrap();

        let error = ReplicationPackage::create(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, x25519::Identity::generate()),
            x25519::Identity::generate(),
            x25519::Identity::generate().to_public().to_string(),
        )
        .err()
        .unwrap();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read(root.join("keep")).unwrap(), b"existing package marker");
    }

    #[test]
    fn canonical_object_name_with_wrong_digest_is_damaged() {
        let (_directory, package) = package();
        let path = package
            .root
            .join("objects")
            .join(format!("{}.age", "0".repeat(64)));
        fs::write(path, b"not an age ciphertext").unwrap();

        let scan = package.scan().unwrap();

        assert_eq!(scan.damaged.len(), 1);
        assert!(scan.damaged[0].reason.contains("actual digest"));
    }

    #[test]
    fn engine_reports_damaged_files_relative_to_the_replication_package() {
        let (directory, package) = package();
        let root = package.root.clone();
        let store = open_store(directory.path(), "damaged");
        let (engine, _) =
            engine_for_package(directory.path(), "damaged", package, [43; 32], store);
        let relative = PathBuf::from("objects").join(format!("{}.age", "0".repeat(64)));
        fs::write(root.join(&relative), b"not an age ciphertext").unwrap();

        let report = engine.sync().unwrap();

        assert_eq!(report.damaged, 1);
        assert_eq!(report.damaged_files, vec![relative]);
    }

    #[test]
    fn vault_descriptor_has_stable_signing_vector() {
        let unsigned = VaultUnsigned {
            format_version: 1,
            vault_id: VAULT_ID.to_string(),
            genesis_device_id: DEVICE_ID.to_string(),
            genesis_public_key: encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()),
            created_at: "2026-08-06T00:00:00Z".to_string(),
        };
        assert_eq!(
            String::from_utf8(signing_bytes(VAULT_SIGNATURE_CONTEXT, &unsigned).unwrap()).unwrap(),
            "floria-vault-v1\0{\"format_version\":1,\"vault_id\":\"11111111-1111-4111-8111-111111111111\",\"genesis_device_id\":\"22222222-2222-4222-8222-222222222222\",\"genesis_public_key\":\"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw\",\"created_at\":\"2026-08-06T00:00:00Z\"}"
        );
        assert_eq!(
            sign_struct(VAULT_SIGNATURE_CONTEXT, &unsigned, &SigningKey::from_bytes(&[7; 32]))
                .unwrap(),
            "iGeZuPC-ulM5c5tLijmtXWaKPNQsaQX7djOuLPjM1o0hmI91TNixOcqsMBTnLA9GOIexEoS6-ydW4G5PJsx6BA"
        );
    }

    #[test]
    fn device_key_store_encrypts_and_reopens_one_stable_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replication/device.age");
        let local_identity = x25519::Identity::generate();
        let first = DeviceKeyStore::new(
            &path,
            Arc::new(LocalStoreKeys(local_identity.clone())),
        )
        .load_or_create()
        .unwrap();
        let enrollment = first.enrollment();
        drop(first);

        let ciphertext = fs::read(&path).unwrap();
        assert!(!ciphertext
            .windows(enrollment.device_id.len())
            .any(|window| window == enrollment.device_id.as_bytes()));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        let reopened = DeviceKeyStore::new(
            &path,
            Arc::new(LocalStoreKeys(local_identity)),
        )
        .load_or_create()
        .unwrap();
        assert_eq!(reopened.enrollment(), enrollment);
    }

    #[test]
    fn device_key_store_explicitly_rotates_a_revoked_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replication/device.age");
        let local_identity = x25519::Identity::generate();
        let key_store = DeviceKeyStore::new(
            &path,
            Arc::new(LocalStoreKeys(local_identity.clone())),
        );
        let previous = key_store.load_or_create().unwrap().enrollment();

        let replacement = key_store.rotate().unwrap().enrollment();

        assert_ne!(replacement.device_id, previous.device_id);
        assert_ne!(replacement.signing_public_key, previous.signing_public_key);
        assert_ne!(replacement.wrapping_recipient, previous.wrapping_recipient);
        let reopened = DeviceKeyStore::new(&path, Arc::new(LocalStoreKeys(local_identity)))
            .load()
            .unwrap();
        assert_eq!(reopened.enrollment(), replacement);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn device_key_store_fails_closed_with_an_unrelated_local_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replication/device.age");
        DeviceKeyStore::new(
            &path,
            Arc::new(LocalStoreKeys(x25519::Identity::generate())),
        )
        .load_or_create()
        .unwrap();

        let error = match DeviceKeyStore::new(
            &path,
            Arc::new(LocalStoreKeys(x25519::Identity::generate())),
        )
        .load()
        {
            Ok(_) => panic!("unrelated local key unexpectedly decrypted Device identity"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("replication encryption failed"));
    }

    #[test]
    fn intent_journal_is_private_authenticated_and_reopens() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replication-intents.json");
        let authenticator = Arc::new(StateAuthenticator::for_tests([71; 32]));
        let journal =
            ReplicationIntentJournal::open(&path, VAULT_ID, Arc::clone(&authenticator)).unwrap();
        let entry = intent(OPERATION_ID);
        journal.enqueue(entry.clone()).unwrap();
        journal.enqueue(entry.clone()).unwrap();
        drop(journal);

        let reopened =
            ReplicationIntentJournal::open(&path, VAULT_ID, Arc::clone(&authenticator)).unwrap();

        assert_eq!(reopened.entries(), vec![entry]);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn signed_intent_keeps_exact_prepared_bytes_until_completion() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replication-intents.json");
        let authenticator = Arc::new(StateAuthenticator::for_tests([72; 32]));
        let journal = ReplicationIntentJournal::open(&path, VAULT_ID, authenticator).unwrap();
        journal.enqueue(intent(OPERATION_ID)).unwrap();
        let package = ReplicationPackage::create(
            directory.path().join("Personal.floriavault"),
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, x25519::Identity::generate()),
            x25519::Identity::generate(),
            x25519::Identity::generate().to_public().to_string(),
        )
        .unwrap();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(&project_projection("Fixture"), Vec::new())],
                objects: &[],
            })
            .unwrap();

        journal.save_prepared(OPERATION_ID, prepared.clone()).unwrap();
        journal.save_prepared(OPERATION_ID, prepared.clone()).unwrap();
        assert_eq!(journal.entries()[0].prepared(), Some(&prepared));
        assert!(journal.discard_unsigned(OPERATION_ID).unwrap_err().to_string().contains("signed"));

        let different = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(
                    &project_projection("Different fixture"),
                    Vec::new(),
                )],
                objects: &[],
            })
            .unwrap();
        assert!(journal
            .save_prepared(OPERATION_ID, different)
            .unwrap_err()
            .to_string()
            .contains("different signed bytes"));

        journal.complete(OPERATION_ID).unwrap();
        assert!(journal.entries().is_empty());
    }

    #[test]
    fn missing_intent_file_is_not_reset_after_an_authenticated_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replication-intents.json");
        let authenticator = Arc::new(StateAuthenticator::for_tests([73; 32]));
        let journal =
            ReplicationIntentJournal::open(&path, VAULT_ID, Arc::clone(&authenticator)).unwrap();
        journal.enqueue(intent(OPERATION_ID)).unwrap();
        drop(journal);
        fs::remove_file(&path).unwrap();

        let error = ReplicationIntentJournal::open(&path, VAULT_ID, authenticator)
            .err()
            .unwrap();

        assert!(error.to_string().contains("missing at authenticated generation"));
    }

    #[test]
    fn engine_publishes_committed_outbox_from_the_exact_store_version() {
        let directory = tempfile::tempdir().unwrap();
        let store = open_store(directory.path(), "local");
        let secret_id: SecretId = "55555555-5555-4555-8555-555555555555".parse().unwrap();
        let mutation_id = "66666666-6666-4666-8666-666666666666";
        store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("replicated fixture"),
                b"fixture payload, not a credential",
                mutation_id,
            )
            .unwrap();
        let package = package_for_store(
            &directory.path().join("Personal.floriavault"),
            &store,
            keys(7, x25519::Identity::generate()),
        );
        let authenticator = Arc::new(StateAuthenticator::for_tests([74; 32]));
        let intents = Arc::new(
            ReplicationIntentJournal::open(
                directory.path().join("replication-intents.json"),
                VAULT_ID,
                authenticator,
            )
            .unwrap(),
        );
        let catalog = Arc::new(Catalog::open(directory.path().join("catalog.sqlite")).unwrap());
        let (entity, object) = secret_entity(&store, &secret_id, 1, Vec::new());
        let catalog_payload = serde_json::to_vec(&TransactionDelta {
            format_version: PAYLOAD_FORMAT_VERSION,
            entities: vec![entity],
        })
        .unwrap();
        intents
            .enqueue(
                ReplicationIntent::new(
                    OPERATION_ID,
                    TRANSACTION_LOGICAL_ID,
                    Vec::new(),
                    vec![IntentStoreMutation {
                        secret_id: secret_id.to_string(),
                        mutation_id: mutation_id.to_string(),
                    }],
                    catalog_payload.clone(),
                    "2026-08-06T00:00:00Z",
                )
                .unwrap(),
            )
            .unwrap();
        catalog
            .enqueue_replication_outbox(&ReplicationOutboxEntry {
                intent_id: OPERATION_ID.to_string(),
                logical_id: TRANSACTION_LOGICAL_ID.to_string(),
                parents: Vec::new(),
                store_versions: vec![ReplicationStoreVersionRef {
                    secret_id: secret_id.to_string(),
                    version: 1,
                }],
                catalog_payload,
                created_at: "2026-08-06T00:00:00Z".to_string(),
            })
            .unwrap();
        let engine = ReplicationEngine::from_parts(
            package,
            Arc::clone(&intents),
            Arc::clone(&catalog),
            Arc::clone(&store),
        );

        let report = engine.sync().unwrap();

        assert_eq!(report.published, 1);
        assert!(!report.local_device_fenced);
        assert!(catalog.replication_outbox().unwrap().is_empty());
        assert!(intents.entries().is_empty());
        assert_eq!(intents.device_sequence(DEVICE_ID), 1);
        let scan = engine.package.scan().unwrap();
        assert_eq!(scan.verified.len(), 1);
        // Zero transcoding: the published Object is byte-for-byte the store's version file.
        assert_eq!(
            fs::read(
                engine
                    .package
                    .root
                    .join("objects")
                    .join(format!("{}.age", object.id))
            )
            .unwrap(),
            version_blob(&store, &secret_id, &object.id)
        );
    }

    #[test]
    fn engine_self_fences_when_an_accepted_local_operation_disappears() {
        let (directory, package) = package();
        let authenticator = Arc::new(StateAuthenticator::for_tests([75; 32]));
        let intents = Arc::new(
            ReplicationIntentJournal::open(
                directory.path().join("replication-intents.json"),
                VAULT_ID,
                authenticator,
            )
            .unwrap(),
        );
        let catalog = Arc::new(Catalog::open(directory.path().join("catalog.sqlite")).unwrap());
        let store = open_store(directory.path(), "local");
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[catalog_entity(&project_projection("Fixture"), Vec::new())],
                objects: &[],
            })
            .unwrap();
        package.publish(&prepared).unwrap();
        intents.enqueue(intent(OPERATION_ID)).unwrap();
        intents.save_prepared(OPERATION_ID, prepared.clone()).unwrap();
        intents.accept_device_operation(DEVICE_ID, 1, OPERATION_ID).unwrap();
        intents.complete(OPERATION_ID).unwrap();
        fs::remove_file(package.operation_path(&prepared)).unwrap();
        let engine = ReplicationEngine::from_parts(package, intents, catalog, store);

        let report = engine.sync().unwrap();

        assert!(report.local_device_fenced);
        assert!(report.messages[0].contains("no longer contains accepted"));
    }

    #[test]
    fn engine_refreshes_metadata_and_fences_a_key_generation_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let genesis_wrapping_identity = x25519::Identity::generate();
        let administrator_store = open_store(directory.path(), "administrator");
        let mut administrator = package_for_store(
            &root,
            &administrator_store,
            keys(7, genesis_wrapping_identity.clone()),
        );
        administrator
            .enroll_device(
                second_device_keys(8, x25519::Identity::generate()).enrollment(),
            )
            .unwrap();
        let intents = Arc::new(
            ReplicationIntentJournal::open(
                directory.path().join("replication-intents.json"),
                VAULT_ID,
                Arc::new(StateAuthenticator::for_tests([79; 32])),
            )
            .unwrap(),
        );
        let engine = ReplicationEngine::from_parts(
            ReplicationPackage::open(
                &root,
                keys(7, genesis_wrapping_identity),
            )
            .unwrap(),
            intents,
            Arc::new(Catalog::open(directory.path().join("catalog.sqlite")).unwrap()),
            open_store(directory.path(), "local"),
        );

        assert!(!engine.sync().unwrap().local_device_fenced);
        let rotated = administrator_store.rotate_generation().unwrap();
        administrator
            .revoke_device(
                SECOND_DEVICE_ID,
                administrator_store.generation_identity(rotated).unwrap(),
                &administrator_store.recovery_recipient().unwrap(),
            )
            .unwrap();
        assert!(!engine.sync().unwrap().local_device_fenced);
        assert_eq!(engine.package.current_generation(), 2);

        fs::remove_file(root.join("generations").join(generation_filename(2))).unwrap();
        let rollback = engine.sync().unwrap();

        assert!(rollback.local_device_fenced);
        assert!(rollback.messages[0].contains("accepted key generation 2"));
    }

    #[test]
    fn verified_commit_replays_into_an_empty_catalog_and_store() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_wrapping_identity = x25519::Identity::generate();
        let source_store = open_store(directory.path(), "source");
        let mut package = package_for_store(
            &directory.path().join("Personal.floriavault"),
            &source_store,
            keys(7, genesis_wrapping_identity.clone()),
        );
        let target_wrapping_identity = x25519::Identity::generate();
        package
            .enroll_device(
                second_device_keys(8, target_wrapping_identity.clone()).enrollment(),
            )
            .unwrap();
        let source_intents = Arc::new(
            ReplicationIntentJournal::open(
                directory.path().join("source-intents.json"),
                VAULT_ID,
                Arc::new(StateAuthenticator::for_tests([76; 32])),
            )
            .unwrap(),
        );
        let source_catalog = Arc::new(
            Catalog::open(directory.path().join("source-catalog.sqlite")).unwrap(),
        );
        let secret_id: SecretId = "55555555-5555-4555-8555-555555555555".parse().unwrap();
        let store_mutation_id = "66666666-6666-4666-8666-666666666666";
        source_store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("Fixture value"),
                b"fixture payload, not a credential",
                store_mutation_id,
            )
            .unwrap();
        source_catalog
            .apply_replicated_catalog(&projection(&secret_id))
            .unwrap();
        let source = ReplicationEngine::from_parts(
            package,
            source_intents,
            Arc::clone(&source_catalog),
            Arc::clone(&source_store),
        );
        assert!(source.stage_current_snapshot("2026-08-06T00:00:00Z").unwrap());
        assert!(!source.stage_current_snapshot("2026-08-06T00:00:01Z").unwrap());
        source_store
            .append_version(&secret_id, b"fixture payload version two")
            .unwrap();
        assert!(source.stage_current_snapshot("2026-08-06T00:00:02Z").unwrap());
        source_store
            .append_version(&secret_id, b"fixture payload version three")
            .unwrap();
        assert!(source.stage_current_snapshot("2026-08-06T00:00:02Z").unwrap());
        let queued = ordered_outbox(source_catalog.replication_outbox().unwrap()).unwrap();
        assert_eq!(queued.len(), 3);
        assert_eq!(queued[1].parents, vec![queued[0].intent_id.clone()]);
        assert_eq!(queued[2].parents, vec![queued[1].intent_id.clone()]);
        assert_eq!(source.sync().unwrap().published, 3);
        assert!(!source.stage_current_snapshot("2026-08-06T00:00:03Z").unwrap());

        let restored_catalog = Arc::new(
            Catalog::open(directory.path().join("restored-catalog.sqlite")).unwrap(),
        );
        let restored_store = open_store(directory.path(), "restored");
        let restored = ReplicationEngine::from_parts(
            ReplicationPackage::open(
                directory.path().join("Personal.floriavault"),
                keys(7, genesis_wrapping_identity),
            )
            .unwrap(),
            Arc::new(
                ReplicationIntentJournal::open(
                    directory.path().join("restored-intents.json"),
                    VAULT_ID,
                    Arc::new(StateAuthenticator::for_tests([78; 32])),
                )
                .unwrap(),
            ),
            Arc::clone(&restored_catalog),
            Arc::clone(&restored_store),
        );
        let recovery = restored.sync().unwrap();
        assert_eq!(recovery.recovered_local, 3);
        assert!(!recovery.local_device_fenced);
        assert_eq!(
            restored_store.get(&secret_id).unwrap().as_slice(),
            b"fixture payload version three"
        );
        assert_eq!(restored_catalog.replicated_catalog().unwrap(), projection(&secret_id));

        let target_catalog = Arc::new(
            Catalog::open(directory.path().join("target-catalog.sqlite")).unwrap(),
        );
        let target_store = open_store(directory.path(), "target");
        let target = ReplicationEngine::from_parts(
            ReplicationPackage::open(
                directory.path().join("Personal.floriavault"),
                second_device_keys(8, target_wrapping_identity),
            )
            .unwrap(),
            Arc::new(
                ReplicationIntentJournal::open(
                    directory.path().join("target-intents.json"),
                    VAULT_ID,
                    Arc::new(StateAuthenticator::for_tests([77; 32])),
                )
                .unwrap(),
            ),
            Arc::clone(&target_catalog),
            Arc::clone(&target_store),
        );

        let first_sync = target.sync().unwrap();
        let second_sync = target.sync().unwrap();

        assert_eq!(first_sync.imported, 3);
        assert_eq!(second_sync.imported, 0);

        assert_eq!(
            target_store.get(&secret_id).unwrap().as_slice(),
            b"fixture payload version three"
        );
        assert_eq!(target_catalog.replicated_catalog().unwrap(), projection(&secret_id));

        // Zero transcoding end to end: source version file == published Object == imported file.
        for reference in source_store.version_refs(&secret_id).unwrap() {
            let source_bytes = version_blob(&source_store, &secret_id, &reference.digest);
            assert_eq!(
                fs::read(
                    directory
                        .path()
                        .join("Personal.floriavault/objects")
                        .join(format!("{}.age", reference.digest))
                )
                .unwrap(),
                source_bytes
            );
            assert_eq!(
                version_blob(&target_store, &secret_id, &reference.digest),
                source_bytes
            );
        }
    }

    #[test]
    fn disjoint_entity_edits_from_two_devices_do_not_conflict() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis_package = package_for_store(
            &root,
            &genesis_store,
            keys(7, x25519::Identity::generate()),
        );
        let second_wrapping_identity = x25519::Identity::generate();
        genesis_package
            .enroll_device(
                second_device_keys(8, second_wrapping_identity.clone()).enrollment(),
            )
            .unwrap();
        let second_package = ReplicationPackage::open(
            &root,
            second_device_keys(8, second_wrapping_identity),
        )
        .unwrap();
        let (genesis, genesis_catalog) = engine_for_package(
            directory.path(),
            "genesis",
            genesis_package,
            [84; 32],
            Arc::clone(&genesis_store),
        );
        let (second, second_catalog) = engine_for_package(
            directory.path(),
            "second",
            second_package,
            [85; 32],
            Arc::clone(&second_store),
        );

        let secret_id: SecretId = "55555555-5555-4555-8555-555555555555".parse().unwrap();
        genesis_store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("Disjoint fixture"),
                b"base fixture payload",
                "66666666-6666-4666-8666-666666666666",
            )
            .unwrap();
        genesis_catalog
            .apply_replicated_catalog(&project_with_secret_projection(&secret_id, "Base"))
            .unwrap();
        assert!(genesis.stage_current_snapshot("base").unwrap());
        assert_eq!(genesis.sync().unwrap().published, 1);
        assert_eq!(second.sync().unwrap().imported, 1);

        // One Device touches only the secret, the other only the catalog: different entities.
        genesis_store
            .append_version(&secret_id, b"genesis only touches the secret")
            .unwrap();
        second_catalog
            .apply_replicated_catalog(&project_with_secret_projection(&secret_id, "Renamed"))
            .unwrap();
        assert!(genesis.stage_current_snapshot("secret edit").unwrap());
        assert!(second.stage_current_snapshot("catalog edit").unwrap());

        assert_eq!(genesis.sync().unwrap().published, 1);
        let second_report = second.sync().unwrap();
        assert_eq!(second_report.published, 1);
        assert_eq!(second_report.imported, 1);
        assert_eq!(second_report.conflicts, 0);
        let genesis_report = genesis.sync().unwrap();
        assert_eq!(genesis_report.imported, 1);
        assert_eq!(genesis_report.conflicts, 0);

        let converged = project_with_secret_projection(&secret_id, "Renamed");
        assert_eq!(genesis_catalog.replicated_catalog().unwrap(), converged);
        assert_eq!(second_catalog.replicated_catalog().unwrap(), converged);
        assert_eq!(
            second_store.get(&secret_id).unwrap().as_slice(),
            b"genesis only touches the secret"
        );
        assert!(!genesis.stage_current_snapshot("converged").unwrap());
        assert!(!second.stage_current_snapshot("converged").unwrap());
    }
}
