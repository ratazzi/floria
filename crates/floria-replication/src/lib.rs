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
const VAULT_STATE_LOGICAL_ID: &str = "vault-state/v1";

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
        DeviceEnrollment {
            device_id: self.device_id.clone(),
            signing_public_key: encode(self.verifying_key().as_bytes()),
            wrapping_recipient: self.wrapping_identity.to_public().to_string(),
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

    fn persist(&self, material: &DeviceKeyMaterial) -> ReplicationResult<()> {
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
        let ciphertext = encrypt_with_provider(self.keys.as_ref(), &plaintext)?;
        write_new_atomic(&self.path, &ciphertext)
    }
}

/// Public material approved by the genesis Device. It is safe to move between machines while
/// the corresponding private keys remain local.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnrollment {
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_recipient: String,
}

/// One already-sequenced local mutation. `operation_id` and `sequence` are supplied by the
/// durable outbox layer so a crash can persist and retry exactly one signed envelope.
pub struct PackageMutation<'a> {
    pub sequence: u64,
    pub operation_id: &'a str,
    pub logical_id: &'a str,
    pub parents: &'a [String],
    pub value: &'a [u8],
}

/// Fully encrypted, signed bytes. Persist this value locally before calling `publish`; retrying a
/// crash must reuse these exact bytes instead of encrypting or signing the slot again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPublication {
    pub sequence: u64,
    pub operation_id: String,
    pub object_id: String,
    object: Vec<u8>,
    operation: Vec<u8>,
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

    fn snapshot(
        intent_id: impl Into<String>,
        parents: Vec<String>,
        store_versions: Vec<floria_catalog::ReplicationStoreVersionRef>,
        catalog_payload: Vec<u8>,
        created_at: impl Into<String>,
    ) -> ReplicationResult<Self> {
        let intent = Self {
            intent_id: intent_id.into(),
            logical_id: VAULT_STATE_LOGICAL_ID.to_string(),
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
    pub logical_id: String,
    pub parents: Vec<String>,
    pub object_id: String,
    pub value: Zeroizing<Vec<u8>>,
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

#[derive(Serialize, Deserialize)]
struct OperationPayload {
    format_version: u32,
    logical_id: String,
    parents: Vec<String>,
    object: ObjectReference,
}

#[derive(Serialize, Deserialize)]
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
}

#[derive(Clone)]
struct TrustedDevice {
    verifying_key: VerifyingKey,
    wrapping_recipient: x25519::Recipient,
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
        let vault_identity = x25519::Identity::generate();

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
                &device.enrollment(),
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
    pub fn revoke_device(&mut self, device_id: &str) -> ReplicationResult<u32> {
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
        let vault_identity = x25519::Identity::generate();
        write_key_generation(
            &self
                .root
                .join("generations")
                .join(generation_filename(generation)),
            &self.vault,
            generation,
            Some(current_generation),
            &vault_identity,
            &recipients,
            BTreeMap::from([(device_id.to_string(), final_sequence)]),
            &self.device.signing_key,
        )?;
        self.refresh_metadata()?;
        Ok(generation)
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

    pub fn prepare(&self, mutation: PackageMutation<'_>) -> ReplicationResult<PreparedPublication> {
        self.refresh_metadata()?;
        if mutation.sequence == 0 {
            return Err(ReplicationError::Invalid(
                "operation sequence starts at 1".to_string(),
            ));
        }
        require_uuid("operation id", mutation.operation_id)?;
        if mutation.logical_id.is_empty() {
            return Err(ReplicationError::Invalid("logical id is empty".to_string()));
        }
        let mut unique_parents = HashSet::new();
        for parent in mutation.parents {
            require_uuid("parent operation id", parent)?;
            if parent == mutation.operation_id || !unique_parents.insert(parent) {
                return Err(ReplicationError::Invalid(format!(
                    "operation {} has an invalid or duplicate parent {parent}",
                    mutation.operation_id
                )));
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
        let object = encrypt(&vault_recipient, mutation.value)?;
        let object_id = digest(&object);
        let payload = OperationPayload {
            format_version: FORMAT_VERSION,
            logical_id: mutation.logical_id.to_string(),
            parents: mutation.parents.to_vec(),
            object: ObjectReference {
                id: object_id.clone(),
                ciphertext_size: object.len() as u64,
            },
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
            object_id,
            object,
            operation,
        })
    }

    /// Publish the Object before the Operation. Existing identical immutable bytes are accepted;
    /// a colliding canonical path with different bytes is never overwritten.
    pub fn publish(&self, prepared: &PreparedPublication) -> ReplicationResult<()> {
        self.refresh_metadata()?;
        self.verify_prepared(prepared)?;
        publish_immutable(
            &self.root.join("objects").join(format!("{}.age", prepared.object_id)),
            &prepared.object,
        )?;
        publish_immutable(&self.operation_path(prepared), &prepared.operation)?;
        Ok(())
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
        if digest(&prepared.object) != prepared.object_id {
            return Err(ReplicationError::Invalid(
                "prepared object digest does not match its id".to_string(),
            ));
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
        if payload.format_version != FORMAT_VERSION {
            report.damaged.push(DamagedFile {
                path: operation_path,
                reason: format!(
                    "unsupported operation payload format {}",
                    payload.format_version
                ),
            });
            return Ok(false);
        }
        let Some(object) = objects.get(&payload.object.id) else {
            report.pending.push(PendingOperation {
                device_id: operation.device_id,
                sequence: operation.sequence,
                operation_id: operation.operation_id,
                reason: format!("object {} has not arrived", payload.object.id),
            });
            return Ok(false);
        };
        if object.len() as u64 != payload.object.ciphertext_size {
            report.damaged.push(DamagedFile {
                path: self
                    .root
                    .join("objects")
                    .join(format!("{}.age", payload.object.id)),
                reason: format!("object {} has the wrong size", payload.object.id),
            });
            return Ok(false);
        }
        let value = match decrypt(vault_identity.as_ref(), object) {
            Ok(value) => value,
            Err(error) => {
                report.damaged.push(DamagedFile {
                    path: self
                        .root
                        .join("objects")
                        .join(format!("{}.age", payload.object.id)),
                    reason: error.to_string(),
                });
                return Ok(false);
            }
        };
        report.verified.push(VerifiedMutation {
            device_id: operation.device_id,
            key_generation: operation.key_generation,
            sequence: operation.sequence,
            operation_id: operation.operation_id,
            logical_id: payload.logical_id,
            parents: payload.parents,
            object_id: payload.object.id,
            value,
        });
        Ok(true)
    }
}

fn resolve_logical_history(report: &mut PackageScan) {
    let candidates = std::mem::take(&mut report.verified);
    let ownership = candidates
        .iter()
        .map(|mutation| (mutation.operation_id.clone(), mutation.logical_id.clone()))
        .collect::<HashMap<_, _>>();
    let mut remaining = Vec::with_capacity(candidates.len());
    for mutation in candidates {
        let mut unique_parents = HashSet::new();
        let problem = mutation.parents.iter().find_map(|parent| {
            if !unique_parents.insert(parent.as_str()) {
                return Some(format!("parent operation {parent} is listed more than once"));
            }
            match ownership.get(parent) {
                None => Some(format!("parent operation {parent} has not arrived")),
                Some(logical_id) if logical_id != &mutation.logical_id => Some(format!(
                    "parent operation {parent} belongs to logical item {logical_id}"
                )),
                Some(_) => None,
            }
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
        .position(|mutation| mutation.parents.iter().all(|parent| emitted.contains(parent)))
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
        let logical_heads = heads.entry(mutation.logical_id.clone()).or_default();
        for parent in &mutation.parents {
            logical_heads.remove(parent);
        }
        logical_heads.insert(mutation.operation_id.clone());
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
    pub conflicts: usize,
    pub local_device_fenced: bool,
    pub messages: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ExportCommit<'a> {
    format_version: u32,
    catalog_payload: std::borrow::Cow<'a, [u8]>,
    store_values: Vec<ExportStoreValue<'a>>,
}

#[derive(Serialize, Deserialize)]
struct ExportStoreValue<'a> {
    secret_id: std::borrow::Cow<'a, str>,
    version: u32,
    descriptor: ExportStoreDescriptor,
    value: std::borrow::Cow<'a, [u8]>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ExportStoreDescriptor {
    label: String,
    mode: u32,
    enforcement: Enforcement,
    environment_ids: Option<Vec<String>>,
    metadata: ItemMetadata,
}

impl Drop for ExportCommit<'_> {
    fn drop(&mut self) {
        if let std::borrow::Cow::Owned(payload) = &mut self.catalog_payload {
            payload.zeroize();
        }
    }
}

impl Drop for ExportStoreValue<'_> {
    fn drop(&mut self) {
        if let std::borrow::Cow::Owned(value) = &mut self.value {
            value.zeroize();
        }
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
        let package = ReplicationPackage::create(directory, vault_id, created_at, device)?;
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

    pub fn enrollment(&self) -> DeviceEnrollment {
        self.package.device.enrollment()
    }

    pub fn enroll_device(&mut self, enrollment: DeviceEnrollment) -> ReplicationResult<()> {
        self.package.enroll_device(enrollment)
    }

    /// Stage one complete, portable Vault-state snapshot after the caller has serialized normal
    /// catalog/store mutations through `ManagedMutationCoordinator`. Unchanged state and an
    /// already-staged outbox are both idempotent no-ops.
    pub fn stage_current_snapshot(&self, created_at: &str) -> ReplicationResult<bool> {
        self.mutations.run(|| self.stage_current_snapshot_uncoordinated(created_at))
    }

    fn stage_current_snapshot_uncoordinated(&self, created_at: &str) -> ReplicationResult<bool> {
        if created_at.trim().is_empty() {
            return Err(ReplicationError::Invalid(
                "replication snapshot creation time is empty".to_string(),
            ));
        }
        if !self.catalog.replication_outbox()?.is_empty() {
            return Ok(false);
        }
        let scan = self.package.scan()?;
        if !scan.pending.is_empty() || !scan.damaged.is_empty() || !scan.conflicts.is_empty() {
            return Err(ReplicationError::Invalid(
                "replication package must be fully synchronized before staging local state"
                    .to_string(),
            ));
        }
        let latest = scan
            .verified
            .iter()
            .rfind(|mutation| mutation.logical_id == VAULT_STATE_LOGICAL_ID);
        let parents = latest
            .map(|mutation| vec![mutation.operation_id.clone()])
            .unwrap_or_default();
        let projection = self.catalog.replicated_catalog()?;
        let catalog_payload = serde_json::to_vec(&projection)?;
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
        let store_versions = secret_ids
            .into_iter()
            .map(|secret_id| {
                let parsed: SecretId = secret_id.parse()?;
                let record = self.store.record(&parsed)?.ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "portable catalog references missing secret {secret_id}"
                    ))
                })?;
                Ok(floria_catalog::ReplicationStoreVersionRef {
                    secret_id,
                    version: record.current_version,
                })
            })
            .collect::<ReplicationResult<Vec<_>>>()?;
        let intent_id = uuid::Uuid::new_v4().to_string();
        let entry = ReplicationOutboxEntry {
            intent_id: intent_id.clone(),
            logical_id: VAULT_STATE_LOGICAL_ID.to_string(),
            parents: parents.clone(),
            store_versions: store_versions.clone(),
            catalog_payload: catalog_payload.clone(),
            created_at: created_at.to_string(),
        };
        let encoded = self.export_value(&entry)?;
        if latest.is_some_and(|mutation| mutation.value.as_slice() == encoded.as_slice()) {
            return Ok(false);
        }
        self.intents.enqueue(ReplicationIntent::snapshot(
            &intent_id,
            parents,
            store_versions,
            catalog_payload,
            created_at,
        )?)?;
        if let Err(error) = self.catalog.enqueue_replication_outbox(&entry) {
            let _ = self.intents.discard_unsigned(&intent_id);
            return Err(error.into());
        }
        Ok(true)
    }

    pub fn sync(&self) -> ReplicationResult<ReplicationReport> {
        self.mutations.run(|| self.sync_uncoordinated())
    }

    fn sync_uncoordinated(&self) -> ReplicationResult<ReplicationReport> {
        let scan = self.package.scan()?;
        let mut report = ReplicationReport {
            observed: scan.observed.len(),
            pending: scan.pending.len(),
            damaged: scan.damaged.len(),
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

        let conflicted_logical_ids = scan
            .conflicts
            .iter()
            .map(|conflict| conflict.logical_id.as_str())
            .collect::<HashSet<_>>();
        for mutation in scan
            .verified
            .iter()
            .filter(|mutation| {
                mutation.device_id != self.package.device_id()
                    && !conflicted_logical_ids.contains(mutation.logical_id.as_str())
            })
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

        if !scan.conflicts.is_empty() {
            report.messages.push(format!(
                "{} replicated item(s) have concurrent heads and require an explicit merge",
                scan.conflicts.len()
            ));
            return Ok(report);
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
        let outbox = self.catalog.replication_outbox()?;
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
                    let value = self.export_value(&entry)?;
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
                        logical_id: &entry.logical_id,
                        parents: &entry.parents,
                        value: &value,
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
        Ok(report)
    }

    fn apply_verified_mutation(&self, mutation: &VerifiedMutation) -> ReplicationResult<()> {
        let commit: ExportCommit<'_> = serde_json::from_slice(&mutation.value)?;
        if commit.format_version != FORMAT_VERSION {
            return Err(ReplicationError::Invalid(format!(
                "unsupported exported commit format {}",
                commit.format_version
            )));
        }
        let projection: ReplicatedCatalog = serde_json::from_slice(&commit.catalog_payload)?;
        let referenced_secret_ids = projection
            .resources
            .iter()
            .filter_map(|resource| match &resource.source {
                floria_catalog::ResourceSource::SecretRef { secret_id } => Some(secret_id.as_str()),
                _ => None,
            })
            .collect::<HashSet<_>>();
        let mut imported_secret_ids = HashSet::new();
        for imported in &commit.store_values {
            if imported.version == 0
                || !referenced_secret_ids.contains(imported.secret_id.as_ref())
                || !imported_secret_ids.insert(imported.secret_id.as_ref())
            {
                return Err(ReplicationError::Invalid(format!(
                    "operation {} contains an invalid or duplicate store value",
                    mutation.operation_id
                )));
            }
            let secret_id: SecretId = imported.secret_id.parse()?;
            match self.store.record(&secret_id)? {
                None if imported.version == 1 => {
                    self.store.put_identified(
                        secret_id.clone(),
                        NewSecret {
                            origin: SecretOrigin::Managed {
                                label: imported.descriptor.label.clone(),
                            },
                            mode: imported.descriptor.mode,
                            enforcement: imported.descriptor.enforcement,
                        },
                        imported.value.as_ref(),
                        &mutation.operation_id,
                    )?;
                }
                None => {
                    return Err(ReplicationError::Invalid(format!(
                        "operation {} starts secret {} at version {}, not 1",
                        mutation.operation_id, secret_id, imported.version
                    )))
                }
                Some(record) => match self
                    .store
                    .version_for_mutation(&secret_id, &mutation.operation_id)?
                {
                    Some(version) if version == imported.version => {}
                    Some(version) => {
                        return Err(ReplicationError::Invalid(format!(
                            "operation {} already created store version {version}, not {}",
                            mutation.operation_id, imported.version
                        )))
                    }
                    None if record.current_version.checked_add(1) == Some(imported.version) => {
                        self.store.append_version_identified(
                            &secret_id,
                            imported.value.as_ref(),
                            &mutation.operation_id,
                        )?;
                    }
                    None => {
                        return Err(ReplicationError::Invalid(format!(
                            "operation {} cannot append secret {} version {} after local version {}",
                            mutation.operation_id,
                            secret_id,
                            imported.version,
                            record.current_version
                        )))
                    }
                },
            }
            self.store.update_settings(
                &secret_id,
                imported.descriptor.metadata.clone(),
                imported.descriptor.enforcement,
                imported.descriptor.environment_ids.clone(),
            )?;
        }
        self.catalog.apply_replicated_catalog(&projection)?;
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

    fn export_value(&self, entry: &ReplicationOutboxEntry) -> ReplicationResult<Zeroizing<Vec<u8>>> {
        let _maintenance = self.store.lock_for_maintenance()?;
        let plaintexts = entry
            .store_versions
            .iter()
            .map(|reference| {
                let secret_id: SecretId = reference.secret_id.parse()?;
                self.store.get_version(&secret_id, reference.version)
            })
            .collect::<Result<Vec<_>, floria_store::StoreError>>()?;
        let records = entry
            .store_versions
            .iter()
            .map(|reference| {
                let secret_id: SecretId = reference.secret_id.parse()?;
                self.store.record(&secret_id)?.ok_or_else(|| {
                    floria_store::StoreError::NotFound(reference.secret_id.clone())
                })
            })
            .collect::<Result<Vec<_>, floria_store::StoreError>>()?;
        let store_values = entry
            .store_versions
            .iter()
            .zip(plaintexts.iter().zip(&records))
            .map(|(reference, (value, record))| ExportStoreValue {
                secret_id: std::borrow::Cow::Borrowed(&reference.secret_id),
                version: reference.version,
                descriptor: ExportStoreDescriptor {
                    label: portable_store_label(&record.origin),
                    mode: record.mode,
                    enforcement: record.enforcement,
                    environment_ids: record.environment_ids.clone(),
                    metadata: record.metadata.clone(),
                },
                value: std::borrow::Cow::Borrowed(value.as_slice()),
            })
            .collect();
        let encoded = serde_json::to_vec(&ExportCommit {
            format_version: FORMAT_VERSION,
            catalog_payload: std::borrow::Cow::Borrowed(&entry.catalog_payload),
            store_values,
        })?;
        Ok(Zeroizing::new(encoded))
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
        return Err(ReplicationError::Invalid(format!(
            "Device {} was revoked at key generation {generation}",
            device.device_id
        )));
    }
    let current_generation = *generations
        .keys()
        .next_back()
        .expect("key generations were validated as non-empty");
    let vault_identities = load_vault_identities(root, device, &generations)?;
    let generation_fingerprints = key_generation_fingerprints(&generations)?;
    Ok(PackageMetadata {
        vault_identities,
        current_generation,
        generation_fingerprints,
        trusted_devices,
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
        EntrySpec, ReplicatedCatalog, ReplicationStoreVersionRef, Resource, ResourceCodec,
        ResourceKind, ResourceSource, ValueShape,
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
        )
        .unwrap();
        (directory, package)
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
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload, not a credential",
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
        assert_eq!(scan.verified[0].logical_id, "managed-item-1");
        assert_eq!(&*scan.verified[0].value, b"fixture payload, not a credential");
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
        )
        .unwrap();
        let second_wrapping_identity = x25519::Identity::generate();
        let second = second_device_keys(8, second_wrapping_identity.clone());
        genesis.enroll_device(second.enrollment()).unwrap();

        let genesis_publication = genesis
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"from genesis",
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
        assert_eq!(&*initial_scan.verified[0].value, b"from genesis");

        let second_publication = second
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: SECOND_OPERATION_ID,
                logical_id: "managed-item-2",
                parents: &[],
                value: b"from second Device",
            })
            .unwrap();
        second.publish(&second_publication).unwrap();

        let final_scan = genesis.scan().unwrap();
        assert!(final_scan.damaged.is_empty());
        assert_eq!(final_scan.verified.len(), 2);
        assert!(final_scan.verified.iter().any(|mutation| {
            mutation.device_id == SECOND_DEVICE_ID
                && mutation.operation_id == SECOND_OPERATION_ID
                && mutation.value.as_slice() == b"from second Device"
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
                logical_id: "managed-item-1",
                parents: &[],
                value: b"base",
            })
            .unwrap();
        genesis.publish(&base).unwrap();
        let base_parent = vec![OPERATION_ID.to_string()];
        let genesis_child = genesis
            .prepare(PackageMutation {
                sequence: 2,
                operation_id: GENESIS_CHILD_OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &base_parent,
                value: b"genesis branch",
            })
            .unwrap();
        genesis.publish(&genesis_child).unwrap();
        let second_child = second
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: SECOND_OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &base_parent,
                value: b"second branch",
            })
            .unwrap();
        second.publish(&second_child).unwrap();

        let conflicted = genesis.scan().unwrap();
        assert!(conflicted.pending.is_empty());
        assert_eq!(conflicted.conflicts.len(), 1);
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
                logical_id: "managed-item-1",
                parents: &merge_parents,
                value: b"merged",
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
    fn revocation_rotates_the_vault_key_and_fences_late_operations() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let genesis_wrapping_identity = x25519::Identity::generate();
        let mut genesis = ReplicationPackage::create(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, genesis_wrapping_identity.clone()),
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
            second_device_keys(8, second_wrapping_identity.clone()),
        )
        .unwrap();
        let before_revocation = second
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: SECOND_OPERATION_ID,
                logical_id: "second-item",
                parents: &[],
                value: b"accepted before revocation",
            })
            .unwrap();
        second.publish(&before_revocation).unwrap();
        let late = second
            .prepare(PackageMutation {
                sequence: 2,
                operation_id: GENESIS_CHILD_OPERATION_ID,
                logical_id: "late-item",
                parents: &[],
                value: b"must not be accepted",
            })
            .unwrap();

        assert_eq!(genesis.revoke_device(SECOND_DEVICE_ID).unwrap(), 2);
        assert_eq!(genesis.current_generation(), 2);
        let re_enrollment = genesis
            .enroll_device(
                second_device_keys(8, second_wrapping_identity.clone()).enrollment(),
            )
            .unwrap_err();
        assert!(re_enrollment.to_string().contains("new Device id"));
        let after_rotation = genesis
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "genesis-item",
                parents: &[],
                value: b"new generation",
            })
            .unwrap();
        genesis.publish(&after_rotation).unwrap();

        let local_fence = second.publish(&late).unwrap_err();
        assert!(local_fence.to_string().contains("was revoked at key generation 2"));
        publish_immutable(
            &second.root.join("objects").join(format!("{}.age", late.object_id)),
            &late.object,
        )
        .unwrap();
        publish_immutable(&second.operation_path(&late), &late.operation).unwrap();

        let scan = genesis.scan().unwrap();
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
                logical_id: "third-item",
                parents: &[],
                value: b"enrolled after rotation",
            })
            .unwrap();
        third.publish(&third_publication).unwrap();
        let final_scan = genesis.scan().unwrap();
        assert!(final_scan.verified.iter().any(|mutation| {
            mutation.device_id == third.device_id()
                && mutation.key_generation == 2
                && mutation.operation_id == THIRD_OPERATION_ID
        }));
    }

    #[test]
    fn operation_waits_when_object_has_not_arrived() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
            })
            .unwrap();
        publish_immutable(&package.operation_path(&prepared), &prepared.operation).unwrap();

        let pending = package.scan().unwrap();
        assert_eq!(pending.pending.len(), 1);
        assert!(pending.pending[0].reason.contains("has not arrived"));

        publish_immutable(
            &package.root.join("objects").join(format!("{}.age", prepared.object_id)),
            &prepared.object,
        )
        .unwrap();
        let complete = package.scan().unwrap();
        assert_eq!(complete.verified.len(), 1);
        assert!(complete.pending.is_empty());
    }

    #[test]
    fn object_conflict_copy_is_validated_and_normalized_by_digest() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
            })
            .unwrap();
        let conflict_copy = package.root.join("objects/object (conflicted copy).age");
        fs::write(&conflict_copy, &prepared.object).unwrap();
        publish_immutable(&package.operation_path(&prepared), &prepared.operation).unwrap();

        let scan = package.scan().unwrap();
        assert_eq!(scan.verified.len(), 1);
        assert!(package
            .root
            .join("objects")
            .join(format!("{}.age", prepared.object_id))
            .is_file());
    }

    #[test]
    fn tampered_operation_is_rejected_before_decryption() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
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
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
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
                logical_id: "managed-item-1",
                parents: &[],
                value: b"first fixture payload",
            })
            .unwrap();
        let second = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: "44444444-4444-4444-8444-444444444444",
                logical_id: "managed-item-1",
                parents: &[],
                value: b"second fixture payload",
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
        )
        .unwrap();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
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
                logical_id: "managed-item-1",
                parents: &[],
                value: b"different fixture payload",
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
        let package = ReplicationPackage::create(
            directory.path().join("Personal.floriavault"),
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, x25519::Identity::generate()),
        )
        .unwrap();
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
        let store = Arc::new(
            AgeDirStore::open(
                directory.path().join("store"),
                Arc::new(LocalStoreKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let secret_id: SecretId = "55555555-5555-4555-8555-555555555555".parse().unwrap();
        let mutation_id = "66666666-6666-4666-8666-666666666666";
        let catalog_payload = br#"{"kind":"fixture"}"#.to_vec();
        intents.enqueue(intent(OPERATION_ID)).unwrap();
        store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("replicated fixture"),
                b"fixture payload, not a credential",
                mutation_id,
            )
            .unwrap();
        catalog
            .enqueue_replication_outbox(&ReplicationOutboxEntry {
                intent_id: OPERATION_ID.to_string(),
                logical_id: "managed-item-1".to_string(),
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
        let store = Arc::new(
            AgeDirStore::open(
                directory.path().join("store"),
                Arc::new(LocalStoreKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
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
        let mut administrator = ReplicationPackage::create(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, genesis_wrapping_identity.clone()),
        )
        .unwrap();
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
            Arc::new(
                AgeDirStore::open(
                    directory.path().join("store"),
                    Arc::new(LocalStoreKeys(x25519::Identity::generate())),
                )
                .unwrap(),
            ),
        );

        assert!(!engine.sync().unwrap().local_device_fenced);
        administrator.revoke_device(SECOND_DEVICE_ID).unwrap();
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
        let mut package = ReplicationPackage::create(
            directory.path().join("Personal.floriavault"),
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, genesis_wrapping_identity.clone()),
        )
        .unwrap();
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
        let source_store = Arc::new(
            AgeDirStore::open(
                directory.path().join("source-store"),
                Arc::new(LocalStoreKeys(x25519::Identity::generate())),
            )
            .unwrap(),
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
            source_catalog,
            source_store,
        );
        assert!(source.stage_current_snapshot("2026-08-06T00:00:00Z").unwrap());
        assert!(!source.stage_current_snapshot("2026-08-06T00:00:01Z").unwrap());
        assert_eq!(source.sync().unwrap().published, 1);
        assert!(!source.stage_current_snapshot("2026-08-06T00:00:02Z").unwrap());

        let restored_catalog = Arc::new(
            Catalog::open(directory.path().join("restored-catalog.sqlite")).unwrap(),
        );
        let restored_store = Arc::new(
            AgeDirStore::open(
                directory.path().join("restored-store"),
                Arc::new(LocalStoreKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
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
        assert_eq!(recovery.recovered_local, 1);
        assert!(!recovery.local_device_fenced);
        assert_eq!(
            restored_store.get(&secret_id).unwrap().as_slice(),
            b"fixture payload, not a credential"
        );
        assert_eq!(restored_catalog.replicated_catalog().unwrap(), projection(&secret_id));

        let target_catalog = Arc::new(
            Catalog::open(directory.path().join("target-catalog.sqlite")).unwrap(),
        );
        let target_store = Arc::new(
            AgeDirStore::open(
                directory.path().join("target-store"),
                Arc::new(LocalStoreKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
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

        assert_eq!(first_sync.imported, 1);
        assert_eq!(second_sync.imported, 0);

        assert_eq!(
            target_store.get(&secret_id).unwrap().as_slice(),
            b"fixture payload, not a credential"
        );
        assert_eq!(target_catalog.replicated_catalog().unwrap(), projection(&secret_id));
    }
}
