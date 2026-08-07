//! The operation log of a Floria vault's shared half.
//!
//! Since format 5 the shared half IS the storage (`floria-store` owns its layout: `vault.json`,
//! `objects/`, `devices/`, `generations/`). [`ReplicationPackage`] adds the parts that make it a
//! replicated log — `operations/`, `checkpoints/`, self-fencing, conflict detection, and device
//! enrollment — on top of the store's documents. Nothing here copies a version byte: an operation
//! only names the object the store already wrote.

pub mod record;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use age::x25519;
use age::secrecy::ExposeSecret;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use floria_catalog::{Catalog, ReplicatedCatalog, ReplicationOutboxEntry};
use floria_core::authz::Enforcement;
use floria_core::metadata::ItemMetadata;
use floria_integrity::StateAuthenticator;
// The shared half's document model belongs to the store; re-export what callers need so a vault's
// public material has one import path.
pub use floria_store::vault::{
    self, DeviceEnrollment, EnrollmentRequestDocument, KeyGenerationDocument, SharedLayout,
    VaultDocument, OPERATION_SIGNATURE_CONTEXT,
};
pub use floria_store::{
    AgeDirStore, DeviceKeyMaterial, DeviceKeyStore, NewSecret, SecretId, SecretOrigin, SecretStore,
    StoreError,
};
use floria_surface::ManagedMutationCoordinator;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Operation envelope format. The signed documents the store owns carry their own
/// [`vault::VAULT_FORMAT_VERSION`].
const FORMAT_VERSION: u32 = 1;
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
    /// The store objects the entities reference. They are already in the shared half; this list
    /// exists so `prepare` can cross-check the references against what the caller believes it is
    /// publishing.
    pub(crate) objects: &'a [PreparedObject],
}

/// Fully encrypted, signed bytes. Persist this value locally before calling `publish`; retrying a
/// crash must reuse these exact bytes instead of encrypting or signing the slot again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPublication {
    pub sequence: u64,
    pub operation_id: String,
    /// The objects this operation names. They are the store's own files and are never copied,
    /// re-encrypted, or carried in the envelope — only their identity is recorded here.
    objects: Vec<PreparedObject>,
    operation: Vec<u8>,
}

/// A reference to one immutable version object already sitting in the shared half.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedObject {
    pub(crate) id: String,
    pub(crate) ciphertext_size: u64,
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
    /// Self-signed join requests waiting for the genesis Mac's approval. They carry no trust:
    /// the fingerprint is what a human compares out of band before approving.
    pub pending_enrollments: Vec<PendingEnrollment>,
    pub duplicate_files: usize,
}

/// A device that dropped a valid `request.json` into its own namespace but has no signed
/// identity yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingEnrollment {
    pub device_id: String,
    pub device_name: Option<String>,
    /// Short fingerprint of the requesting signing key, for on-screen comparison.
    pub fingerprint: String,
    pub requested_at: String,
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
    /// The secret no longer exists. Objects stay in the shared half (immutable, possibly still
    /// referenced by an older head elsewhere); only the receiving device's head document goes.
    Tombstone,
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

/// The operation log over a store's shared half. It owns no bytes of its own: the vault, device,
/// and generation documents belong to the store, and version objects are the store's files.
pub struct ReplicationPackage {
    store: Arc<AgeDirStore>,
    vault: VaultDocument,
    device: Arc<DeviceKeyMaterial>,
    metadata: RwLock<PackageMetadata>,
}

struct PackageMetadata {
    current_generation: u32,
    generation_fingerprints: BTreeMap<u32, String>,
    trusted_devices: HashMap<String, TrustedDevice>,
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
    /// Build the operation log over an open store's shared half. The store has already created
    /// (or adopted) the vault; this only adds the `operations/` and `checkpoints/` namespaces and
    /// projects device membership. A store whose device is not enrolled yet reports
    /// [`ReplicationError::EnrollmentRequired`].
    pub fn for_store(store: Arc<AgeDirStore>) -> ReplicationResult<Self> {
        let vault = store.vault_document();
        let device = store.device();
        let layout = store.shared_layout();
        ensure_private_package_directory(&layout.operations_dir())?;
        ensure_private_package_directory(&layout.checkpoints_dir())?;
        ensure_private_package_directory(&layout.device_operations_dir(device.device_id()))?;
        ensure_private_package_directory(&layout.device_checkpoints_dir(device.device_id()))?;
        let metadata = load_package_metadata(&layout, &vault, &device)?;
        Ok(Self {
            store,
            vault,
            device,
            metadata: RwLock::new(metadata),
        })
    }

    /// The shared half's current location. Never cached: enabling sync moves it.
    fn layout(&self) -> SharedLayout {
        self.store.shared_layout()
    }

    /// Authorize another Device without copying either Device's private keys. Only the genesis
    /// Device may extend the enrollment set in v1: it writes the signed identity and one Vault-key
    /// envelope per existing generation into the new Device's own namespace.
    pub fn enroll_device(&mut self, enrollment: DeviceEnrollment) -> ReplicationResult<()> {
        if self.device.device_id() != self.vault.genesis_device_id {
            return Err(ReplicationError::Invalid(
                "only the genesis Device may enroll another Device".to_string(),
            ));
        }
        vault::validate_enrollment(&enrollment)?;
        self.refresh_metadata()?;
        let revoked = self
            .metadata
            .read()
            .expect("replication metadata poisoned")
            .trusted_devices
            .get(&enrollment.device_id)
            .and_then(|device| device.revoked_generation);
        if revoked.is_some() {
            return Err(ReplicationError::Invalid(format!(
                "revoked Device {} must re-enroll with a new Device id",
                enrollment.device_id
            )));
        }

        let layout = self.layout();
        let current_generation = self.store.current_generation()?;
        ensure_private_package_directory(&layout.device_dir(&enrollment.device_id))?;
        ensure_private_package_directory(&layout.envelopes_dir(&enrollment.device_id))?;

        let identity_path = layout.device_identity(&enrollment.device_id);
        if path_exists(&identity_path)? {
            let existing = vault::read_device_identity(&identity_path, &self.vault)?;
            if existing.device_id != enrollment.device_id
                || existing.signing_public_key != enrollment.signing_public_key
                || existing.wrapping_recipient != enrollment.wrapping_recipient
            {
                return Err(ReplicationError::Invalid(format!(
                    "device {} is already enrolled with different public keys",
                    enrollment.device_id
                )));
            }
        } else {
            vault::write_device_identity(
                &identity_path,
                &self.vault,
                &enrollment,
                current_generation,
                self.device.signing_key(),
            )?;
        }

        let recipient = enrollment
            .wrapping_recipient
            .parse::<x25519::Recipient>()
            .map_err(|error| {
                ReplicationError::Invalid(format!("invalid Device wrapping recipient: {error}"))
            })?;
        for generation in 1..=current_generation {
            let path = layout.envelope(&enrollment.device_id, generation);
            if path_exists(&path)? {
                continue;
            }
            let identity = self.store.generation_identity(generation)?;
            let secret = Zeroizing::new(identity.to_string().expose_secret().clone());
            let envelope = vault::encrypt_to_recipient(&recipient, secret.as_bytes())?;
            write_new_atomic(&path, &envelope)?;
        }

        self.ensure_device_directories(&enrollment.device_id)?;
        // The request has been answered; leaving it would keep the device listed as pending.
        let request = layout.enrollment_request(&enrollment.device_id);
        match fs::remove_file(&request) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(&request, source)),
        }
        self.refresh_metadata()
    }

    /// Approve a device that published a self-signed join request into the sync directory. The
    /// caller must have shown the request's fingerprint for out-of-band comparison first: a
    /// request proves key possession only, never authorization.
    pub fn enroll_requested(&mut self, device_id: &str) -> ReplicationResult<()> {
        require_uuid("device id", device_id)?;
        let request = vault::read_enrollment_request(
            &self.layout().enrollment_request(device_id),
            &self.vault,
        )?;
        if request.device_id != device_id {
            return Err(ReplicationError::Invalid(format!(
                "enrollment request in namespace {device_id} names Device {}",
                request.device_id
            )));
        }
        self.enroll_device(request.enrollment())
    }

    /// The surviving devices' wrapping recipients for a revocation, after checking that this
    /// Device may revoke `device_id` at all.
    fn revocation_recipients(
        &self,
        device_id: &str,
    ) -> ReplicationResult<BTreeMap<String, x25519::Recipient>> {
        if self.device.device_id() != self.vault.genesis_device_id {
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
        let metadata = self.metadata.read().expect("replication metadata poisoned");
        let target = metadata.trusted_devices.get(device_id).ok_or_else(|| {
            ReplicationError::Invalid(format!("Device {device_id} is not enrolled"))
        })?;
        if target.revoked_generation.is_some() {
            return Err(ReplicationError::Invalid(format!(
                "Device {device_id} is already revoked"
            )));
        }
        Ok(metadata
            .trusted_devices
            .iter()
            .filter(|(candidate_id, device)| {
                candidate_id.as_str() != device_id && device.revoked_generation.is_none()
            })
            .map(|(candidate_id, device)| (candidate_id.clone(), device.wrapping_recipient.clone()))
            .collect())
    }

    /// The last sequence a device published, which the revoking generation fences it at.
    fn final_sequence(&self, device_id: &str) -> ReplicationResult<u64> {
        Ok(self
            .scan()?
            .observed
            .iter()
            .filter(|operation| operation.device_id == device_id)
            .map(|operation| operation.sequence)
            .max()
            .unwrap_or(0))
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
                is_current: device_id == self.device.device_id(),
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

    /// The directory a sync tool moves. It changes when sync is enabled, so callers must not
    /// cache it either.
    pub fn root(&self) -> PathBuf {
        self.store.shared_root()
    }

    pub fn device_id(&self) -> &str {
        self.device.device_id()
    }

    fn generation_fingerprints(&self) -> BTreeMap<u32, String> {
        self.metadata
            .read()
            .expect("replication metadata poisoned")
            .generation_fingerprints
            .clone()
    }

    fn refresh_metadata(&self) -> ReplicationResult<()> {
        let refreshed = load_package_metadata(&self.layout(), &self.vault, &self.device)?;
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
        // Objects are not carried: they are the store's own files, already in the shared half.
        // What must hold is that every reference names a distinct object that is actually there
        // with the size the entity claims.
        let layout = self.layout();
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
                    let path = layout.object(&version.object.id);
                    let size = fs::metadata(&path)
                        .map_err(|source| io_error(&path, source))?
                        .len();
                    if size != version.object.ciphertext_size {
                        return Err(ReplicationError::Invalid(format!(
                            "object {} is {size} bytes but the entity claims {}",
                            version.object.id, version.object.ciphertext_size
                        )));
                    }
                }
            }
        }
        if referenced.len() != mutation.objects.len() {
            return Err(ReplicationError::Invalid(format!(
                "operation {} names {} object(s) but references {}",
                mutation.operation_id,
                mutation.objects.len(),
                referenced.len()
            )));
        }
        for object in mutation.objects {
            match referenced.get(object.id.as_str()) {
                Some(size) if *size == object.ciphertext_size => {}
                Some(_) => {
                    return Err(ReplicationError::Invalid(format!(
                        "object {} does not match its referenced size",
                        object.id
                    )))
                }
                None => {
                    return Err(ReplicationError::Invalid(format!(
                        "object {} is not referenced by any entity",
                        object.id
                    )))
                }
            }
        }
        // Encrypt to the same generation the store writes under, so both halves of a device's
        // output name one key domain.
        let current_generation = self.store.current_generation()?;
        let recipients = self.store.generation_recipients()?;
        let payload = OperationPayload {
            format_version: PAYLOAD_FORMAT_VERSION,
            entities: mutation.entities.to_vec(),
        };
        let ciphertext = encrypt(recipients, &serde_json::to_vec(&payload)?)?;
        let unsigned = OperationUnsigned {
            format_version: FORMAT_VERSION,
            vault_id: self.vault.vault_id.clone(),
            device_id: self.device.device_id().to_string(),
            key_generation: current_generation,
            sequence: mutation.sequence,
            operation_id: mutation.operation_id.to_string(),
            ciphertext: encode(&ciphertext),
        };
        let signature = vault::sign_struct(
            OPERATION_SIGNATURE_CONTEXT,
            &unsigned,
            self.device.signing_key(),
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

    /// Publish the Operation. The objects it names were written by the store when the versions
    /// were created — there is nothing else to move.
    pub fn publish(&self, prepared: &PreparedPublication) -> ReplicationResult<()> {
        self.refresh_metadata()?;
        self.verify_prepared(prepared)?;
        publish_immutable(&self.operation_path(prepared), &prepared.operation)?;
        Ok(())
    }

    pub fn scan(&self) -> ReplicationResult<PackageScan> {
        self.refresh_metadata()?;
        let layout = self.layout();
        let mut report = PackageScan::default();
        let objects = scan_objects(&layout.objects_dir(), &mut report)?;
        self.scan_enrollment_requests(&layout, &mut report)?;
        let operations_root = layout.operations_dir();
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

    /// Report every device that asked to join and has not been approved. Requests are untrusted
    /// input from the sync directory: an unparsable or badly signed one is damage, not a request.
    fn scan_enrollment_requests(
        &self,
        layout: &SharedLayout,
        report: &mut PackageScan,
    ) -> ReplicationResult<()> {
        let devices_root = layout.devices_dir();
        let entries = match fs::read_dir(&devices_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(io_error(&devices_root, source)),
        };
        for entry in entries {
            let entry = entry.map_err(|source| io_error(&devices_root, source))?;
            let Some(device_id) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            if uuid::Uuid::parse_str(&device_id).is_err() {
                continue;
            }
            let request_path = layout.enrollment_request(&device_id);
            if !path_exists(&request_path)? {
                continue;
            }
            match vault::read_enrollment_request(&request_path, &self.vault) {
                Ok(request) if request.device_id == device_id => {
                    if self
                        .metadata
                        .read()
                        .expect("replication metadata poisoned")
                        .trusted_devices
                        .contains_key(&device_id)
                    {
                        continue;
                    }
                    report.pending_enrollments.push(PendingEnrollment {
                        device_id,
                        device_name: request.device_name.clone(),
                        fingerprint: request.fingerprint(),
                        requested_at: request.requested_at.clone(),
                    });
                }
                Ok(request) => report.damaged.push(DamagedFile {
                    path: request_path,
                    reason: format!(
                        "enrollment request in namespace {device_id} names Device {}",
                        request.device_id
                    ),
                }),
                Err(error) => report.damaged.push(DamagedFile {
                    path: request_path,
                    reason: error.to_string(),
                }),
            }
        }
        report
            .pending_enrollments
            .sort_by(|left, right| left.device_id.cmp(&right.device_id));
        Ok(())
    }

    fn operation_path(&self, prepared: &PreparedPublication) -> PathBuf {
        self.layout()
            .device_operations_dir(self.device.device_id())
            .join(format!(
                "{:020}-{}.op",
                prepared.sequence, prepared.operation_id
            ))
    }

    fn ensure_device_directories(&self, device_id: &str) -> ReplicationResult<()> {
        let layout = self.layout();
        ensure_private_package_directory(&layout.device_operations_dir(device_id))?;
        ensure_private_package_directory(&layout.device_checkpoints_dir(device_id))
    }

    fn verify_prepared(&self, prepared: &PreparedPublication) -> ReplicationResult<()> {
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
        Ok(vault::verify_struct(
            OPERATION_SIGNATURE_CONTEXT,
            &operation.unsigned(),
            &operation.signature,
            &device_key.verifying_key,
        )?)
    }

    fn materialize_verified(
        &self,
        operation_path: PathBuf,
        operation: OperationDocument,
        objects: &HashMap<String, Vec<u8>>,
        report: &mut PackageScan,
    ) -> ReplicationResult<bool> {
        // The store unwraps the generation identity from this device's envelope. A missing
        // envelope is not damage: enrollment for that generation has not reached us yet.
        let vault_identity = match self.store.generation_identity(operation.key_generation) {
            Ok(identity) => identity,
            Err(StoreError::Key(_)) => {
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
            }
            Err(error) => return Err(error.into()),
        };
        let ciphertext = decode("operation ciphertext", &operation.ciphertext)?;
        let plaintext = match decrypt(&vault_identity, &ciphertext) {
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
                        path: self.layout().object(&version.object.id),
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
            EntityDelta::Tombstone => {
                if entity.logical_id.parse::<SecretId>().is_err() {
                    return Err(ReplicationError::Invalid(format!(
                        "operation {operation_id} tombstone has a non-uuid id {}",
                        entity.logical_id
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
    /// Devices asking to join this Vault. Approving one requires comparing its fingerprint out
    /// of band, so this is surfaced to the user rather than acted on automatically.
    pub pending_enrollments: Vec<PendingEnrollment>,
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
                EntityDelta::Tombstone => {
                    // The entity is gone: a later staging pass must not rediscover it as a
                    // missing local secret and publish the same tombstone again.
                    state.secrets.remove(&entity.logical_id);
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
    /// Drive replication for an open store. The store already is the vault, so there is nothing
    /// to create: a machine that never enabled sync simply has a single-device vault.
    pub fn for_runtime(runtime: ReplicationRuntime) -> ReplicationResult<Self> {
        let package = ReplicationPackage::for_store(Arc::clone(&runtime.store))?;
        Self::with_runtime(package, runtime)
    }

    /// Enable sync: move the authoritative shared half to a user-chosen synced location. This is
    /// a move of the only copy, never a second one.
    pub fn enable_sync_at(store: &Arc<AgeDirStore>, target: &Path) -> ReplicationResult<()> {
        store.relocate_shared(target)?;
        let layout = store.shared_layout();
        ensure_private_package_directory(&layout.operations_dir())?;
        ensure_private_package_directory(&layout.checkpoints_dir())?;
        Ok(())
    }

    /// Join an existing vault: adopt its shared half and drop a self-signed join request into
    /// this device's namespace. Building an engine afterwards reports
    /// [`ReplicationError::EnrollmentRequired`] until the genesis Mac approves the request.
    pub fn join_vault_at(
        store: &Arc<AgeDirStore>,
        target: &Path,
        device_name: Option<String>,
        requested_at: &str,
    ) -> ReplicationResult<()> {
        store.adopt_shared_location(target)?;
        publish_enrollment_request(store, device_name, requested_at)
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

    /// Approve a pending join request after its fingerprint was compared out of band.
    pub fn enroll_requested(&mut self, device_id: &str) -> ReplicationResult<()> {
        self.package.enroll_requested(device_id)
    }

    /// Devices waiting for approval, newest state as of the last directory read.
    pub fn pending_enrollments(&self) -> ReplicationResult<Vec<PendingEnrollment>> {
        Ok(self.package.scan()?.pending_enrollments)
    }

    /// Revoke a Device and rotate the vault's data key in one signed step. The new generation
    /// document carries envelopes for the surviving devices only, and fences the revoked Device
    /// at its final published sequence.
    pub fn revoke_device(&self, device_id: &str) -> ReplicationResult<ReplicationReport> {
        self.mutations.run(|| {
            self.package.refresh_metadata()?;
            let recipients = self.package.revocation_recipients(device_id)?;
            let final_sequence = self.package.final_sequence(device_id)?;
            self.store.rotate_generation(
                &recipients,
                BTreeMap::from([(device_id.to_string(), final_sequence)]),
            )?;
            self.package.refresh_metadata()?;
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

        // A replicated secret that no longer exists locally was deleted here: say so explicitly.
        // Its objects stay in the shared half — other devices may still point older heads at them.
        for logical_id in known.secrets.keys().collect::<BTreeSet<_>>() {
            let parsed: SecretId = logical_id.parse()?;
            if self.store.record(&parsed)?.is_some() {
                continue;
            }
            let known_heads = known
                .secrets
                .get(logical_id)
                .map(|secret| secret.heads.as_slice())
                .unwrap_or_default();
            entities.push(EntityPayload {
                logical_id: logical_id.clone(),
                parents: parents_for(logical_id, known_heads),
                delta: EntityDelta::Tombstone,
            });
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

    fn sync_uncoordinated(&self) -> ReplicationResult<ReplicationReport> {
        let scan = self.package.scan()?;
        let mut report = ReplicationReport {
            observed: scan.observed.len(),
            pending: scan.pending.len(),
            damaged: scan.damaged.len(),
            damaged_files: relative_damaged_paths(&self.package.root(), &scan.damaged),
            conflicts: scan.conflicts.len(),
            pending_enrollments: scan.pending_enrollments.clone(),
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
                    // Nothing is fetched from the store: the objects the delta names are the
                    // files the store already wrote into the shared half.
                    let objects = delta
                        .entities
                        .iter()
                        .filter_map(|entity| match &entity.delta {
                            EntityDelta::Secret(secret) => Some(secret),
                            _ => None,
                        })
                        .flat_map(|secret| secret.versions.iter())
                        .map(|version| PreparedObject {
                            id: version.object.id.clone(),
                            ciphertext_size: version.object.ciphertext_size,
                        })
                        .collect::<Vec<_>>();
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
        report.damaged_files = relative_damaged_paths(&self.package.root(), &scan.damaged);
        report.conflicts = scan.conflicts.len();
        report.pending_enrollments = scan.pending_enrollments.clone();
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
                EntityDelta::Tombstone => {
                    let secret_id: SecretId = entity.logical_id.parse()?;
                    self.store.remove_replicated_heads(&secret_id)?;
                }
                EntityDelta::Secret(delta) => {
                    let secret_id: SecretId = entity.logical_id.parse()?;
                    for version in &delta.versions {
                        // No bytes move: the object is already the authoritative file. The store
                        // re-checks digest, decryptability, payload binding, and declared size
                        // before adding the row to its local head document.
                        self.store.register_replicated_version(
                            &secret_id,
                            Some(NewSecret {
                                origin: SecretOrigin::Managed {
                                    label: delta.descriptor.label.clone(),
                                },
                                mode: delta.descriptor.mode,
                                enforcement: delta.descriptor.enforcement,
                            }),
                            &version.version_uuid,
                            version.generation,
                            version.size,
                            &version.object.id,
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

/// Announce this device to a vault it wants to join by writing a self-signed request into its own
/// namespace. The request proves key possession only; the genesis Mac authorizes it after a human
/// compares [`EnrollmentRequestDocument::fingerprint`] on both screens.
pub fn publish_enrollment_request(
    store: &Arc<AgeDirStore>,
    device_name: Option<String>,
    requested_at: &str,
) -> ReplicationResult<()> {
    let vault = store.vault_document();
    let device = store.device();
    let layout = store.shared_layout();
    if path_exists(&layout.device_identity(device.device_id()))? {
        // Already enrolled: there is nothing to ask for.
        return Ok(());
    }
    let request = device.enrollment_request(&vault, device_name, requested_at)?;
    let bytes = serde_json::to_vec_pretty(&request)?;
    ensure_private_package_directory(&layout.device_dir(device.device_id()))?;
    let path = layout.enrollment_request(device.device_id());
    match read_untrusted_file(&path, MAX_DESCRIPTOR_BYTES) {
        Ok(existing) if existing == bytes => Ok(()),
        Ok(_) => write_replace_atomic(&path, &bytes),
        Err(ReplicationError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            write_new_atomic(&path, &bytes)
        }
        Err(error) => Err(error),
    }
}

/// Ask to rejoin a vault that revoked this device: the old identity can never be re-enrolled, so
/// the store mints a fresh one and publishes a new request under it.
pub fn request_reenrollment(
    store: &Arc<AgeDirStore>,
    device_name: Option<String>,
    requested_at: &str,
) -> ReplicationResult<()> {
    store.rotate_device_identity()?;
    publish_enrollment_request(store, device_name, requested_at)
}

fn load_package_metadata(
    layout: &SharedLayout,
    vault: &VaultDocument,
    device: &DeviceKeyMaterial,
) -> ReplicationResult<PackageMetadata> {
    let mut trusted_devices = load_trusted_devices(layout, vault)?;
    let generations = vault::load_key_generations(layout, vault)?;
    apply_generation_membership(&mut trusted_devices, &generations, vault)?;
    let expected = trusted_devices.get(device.device_id()).ok_or_else(|| {
        ReplicationError::EnrollmentRequired { device_id: device.device_id().to_string() }
    })?;
    if expected.verifying_key != device.verifying_key()
        || expected.wrapping_recipient != device.wrapping_identity().to_public()
    {
        return Err(ReplicationError::Invalid(
            "Device private keys do not match its enrolled identity".to_string(),
        ));
    }
    if let Some(generation) = expected.revoked_generation {
        return Err(ReplicationError::DeviceRevoked {
            device_id: device.device_id().to_string(),
            generation,
        });
    }
    let current_generation = *generations
        .keys()
        .next_back()
        .expect("key generations were validated as non-empty");
    let generation_fingerprints = key_generation_fingerprints(&generations)?;
    Ok(PackageMetadata {
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

fn load_trusted_devices(
    layout: &SharedLayout,
    vault: &VaultDocument,
) -> ReplicationResult<HashMap<String, TrustedDevice>> {
    let mut trusted: HashMap<String, TrustedDevice> = HashMap::new();
    let devices_root = layout.devices_dir();
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
        let identity = match vault::read_device_identity(&identity_path, vault) {
            Ok(identity) => identity,
            // A device namespace with no signed identity is a pending join request, not damage.
            Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if identity.device_id != directory_device_id {
            return Err(ReplicationError::Invalid(format!(
                "Device identity {} is stored under directory {}",
                identity.device_id, directory_device_id
            )));
        }
        let device = TrustedDevice {
            verifying_key: vault::verifying_key(
                "Device public key",
                &identity.signing_public_key,
            )?,
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

/// age-encrypt an operation payload to the store's current recipients (generation + recovery).
fn encrypt(
    recipients: Vec<Box<dyn age::Recipient + Send>>,
    plaintext: &[u8],
) -> ReplicationResult<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(recipients)
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
    use ed25519_dalek::SigningKey;
    use floria_store::{KeyProvider, NewSecret, StoreResult};
    use std::os::unix::fs::PermissionsExt;

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const OPERATION_ID: &str = "33333333-3333-4333-8333-333333333333";
    const SECOND_OPERATION_ID: &str = "77777777-7777-4777-8777-777777777777";
    const GENESIS_CHILD_OPERATION_ID: &str = "99999999-9999-4999-8999-999999999999";
    const MERGE_OPERATION_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const THIRD_OPERATION_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const REQUESTED_AT: &str = "2026-08-06T00:00:00Z";

    fn store_keys() -> Arc<dyn KeyProvider> {
        Arc::new(LocalStoreKeys(x25519::Identity::generate()))
    }

    fn open_store_at(root: PathBuf, keys: Arc<dyn KeyProvider>) -> Arc<AgeDirStore> {
        Arc::new(AgeDirStore::open(root, keys).unwrap())
    }

    /// One machine: its own data root, its own device identity, its own single-device vault.
    fn open_store(directory: &Path, label: &str) -> Arc<AgeDirStore> {
        open_store_at(directory.join(format!("{label}-store")), store_keys())
    }

    /// A genesis package: the store opened its own vault, replication just logs on top of it.
    fn package_for_store(store: &Arc<AgeDirStore>) -> ReplicationPackage {
        ReplicationPackage::for_store(Arc::clone(store)).unwrap()
    }

    fn package() -> (tempfile::TempDir, ReplicationPackage) {
        let directory = tempfile::tempdir().unwrap();
        let store = open_store(directory.path(), "genesis");
        let package = package_for_store(&store);
        (directory, package)
    }

    /// Join `store` to the genesis vault the way a second Mac does: adopt the shared half, drop a
    /// self-signed request in, and have the genesis Device approve it after checking the
    /// fingerprint.
    fn join_vault(
        genesis: &mut ReplicationPackage,
        store: &Arc<AgeDirStore>,
        device_name: Option<&str>,
    ) -> ReplicationPackage {
        ReplicationEngine::join_vault_at(
            store,
            &genesis.root(),
            device_name.map(ToOwned::to_owned),
            REQUESTED_AT,
        )
        .unwrap();
        genesis.enroll_requested(store.device().device_id()).unwrap();
        package_for_store(store)
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
            EntityDelta::Secret(_) | EntityDelta::Tombstone => {
                panic!("expected a catalog entity")
            }
        }
    }

    /// One secret entity naming the version object the store already wrote.
    fn secret_entity(
        store: &AgeDirStore,
        id: &SecretId,
        ordinal: u32,
        parents: Vec<String>,
    ) -> (EntityPayload, PreparedObject) {
        let reference = store
            .version_refs(id)
            .unwrap()
            .into_iter()
            .find(|reference| reference.ordinal == ordinal)
            .unwrap();
        let descriptor = descriptor_from_record(&store.record(id).unwrap().unwrap());
        let entity = EntityPayload {
            logical_id: id.to_string(),
            parents,
            delta: EntityDelta::Secret(SecretDelta {
                descriptor,
                versions: vec![SecretVersionRef {
                    version_uuid: reference.version_uuid.clone(),
                    generation: reference.generation,
                    size: reference.size,
                    object: ObjectReference {
                        id: reference.digest.clone(),
                        ciphertext_size: reference.ciphertext_size,
                    },
                }],
                head_uuid: reference.version_uuid,
            }),
        };
        (
            entity,
            PreparedObject {
                id: reference.digest,
                ciphertext_size: reference.ciphertext_size,
            },
        )
    }

    /// Every object file in the shared half, by digest. There is exactly one copy of each.
    fn shared_objects(store: &AgeDirStore) -> BTreeSet<String> {
        regular_files_recursively(&store.shared_layout().objects_dir())
            .unwrap()
            .iter()
            .filter_map(|path| canonical_object_id(path))
            .collect()
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

    fn journal(
        directory: &Path,
        label: &str,
        vault_id: &str,
        key: [u8; 32],
    ) -> Arc<ReplicationIntentJournal> {
        Arc::new(
            ReplicationIntentJournal::open(
                directory.join(format!("{label}-intents.json")),
                vault_id,
                Arc::new(StateAuthenticator::for_tests(key)),
            )
            .unwrap(),
        )
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
        let intents = journal(directory, label, package.vault_id(), authentication_key);
        let engine =
            ReplicationEngine::from_parts(package, intents, Arc::clone(&catalog), store);
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
    fn single_device_store_round_trips_one_operation() {
        let directory = tempfile::tempdir().unwrap();
        let keys = store_keys();
        let root = directory.path().join("genesis-store");
        let store = open_store_at(root.clone(), Arc::clone(&keys));
        let package = package_for_store(&store);
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
        drop(package);
        drop(store);

        let reopened = package_for_store(&open_store_at(root, keys));
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
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis = package_for_store(&genesis_store);
        let second = join_vault(&mut genesis, &second_store, Some("Second Mac"));

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
            mutation.device_id == second_store.device().device_id()
                && mutation.operation_id == SECOND_OPERATION_ID
                && decoded_catalog(&mutation.payload.entities[0]) == from_second
        }));
        // Approval is what makes the request go away; nothing stays pending afterwards.
        assert!(final_scan.pending_enrollments.is_empty());
    }

    #[test]
    fn pending_enrollment_is_reported_with_a_fingerprint_until_it_is_approved() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis = package_for_store(&genesis_store);
        let secret_id: SecretId = "55555555-5555-4555-8555-555555555555".parse().unwrap();
        genesis_store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("Fixture value"),
                b"fixture payload, not a credential",
                "66666666-6666-4666-8666-666666666666",
            )
            .unwrap();

        ReplicationEngine::join_vault_at(
            &second_store,
            &genesis.root(),
            Some("Second Mac".to_string()),
            REQUESTED_AT,
        )
        .unwrap();
        // Republishing the same request is idempotent, not a second pending device.
        publish_enrollment_request(
            &second_store,
            Some("Second Mac".to_string()),
            REQUESTED_AT,
        )
        .unwrap();

        let waiting = genesis.scan().unwrap();
        assert!(waiting.damaged.is_empty());
        assert_eq!(waiting.pending_enrollments.len(), 1);
        let request = &waiting.pending_enrollments[0];
        assert_eq!(request.device_id, second_store.device().device_id());
        assert_eq!(request.device_name.as_deref(), Some("Second Mac"));
        assert_eq!(request.requested_at, REQUESTED_AT);
        assert!(!request.fingerprint.is_empty());
        // Until it is approved the joining Device cannot even build a package.
        assert!(matches!(
            ReplicationPackage::for_store(Arc::clone(&second_store)),
            Err(ReplicationError::EnrollmentRequired { .. })
        ));

        genesis.enroll_requested(&request.device_id.clone()).unwrap();

        assert!(genesis.scan().unwrap().pending_enrollments.is_empty());
        assert!(!genesis
            .layout()
            .enrollment_request(second_store.device().device_id())
            .exists());
        // Approval hands over the generation envelope, so the joining store can read the vault.
        package_for_store(&second_store);
        assert_eq!(
            second_store.generation_identity(1).unwrap().to_public().to_string(),
            genesis_store.generation_identity(1).unwrap().to_public().to_string()
        );
    }

    #[test]
    fn enrolled_identity_must_match_the_local_device_keys() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis = package_for_store(&genesis_store);
        second_store
            .adopt_shared_location(&genesis.root())
            .unwrap();
        // Enroll the joining Device's id, but bound to keys it does not hold.
        let impostor = DeviceKeyMaterial::generate().unwrap();
        let mut enrollment = impostor.enrollment();
        enrollment.device_id = second_store.device().device_id().to_string();
        genesis.enroll_device(enrollment).unwrap();

        let error = match ReplicationPackage::for_store(Arc::clone(&second_store)) {
            Ok(_) => panic!("foreign enrolled keys unexpectedly opened the Vault"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("private keys do not match"));
    }

    #[test]
    fn tampered_enrollment_is_rejected_before_vault_key_unwrap() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis = package_for_store(&genesis_store);
        join_vault(&mut genesis, &second_store, None);
        let identity_path = genesis
            .layout()
            .device_identity(second_store.device().device_id());
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&identity_path).unwrap()).unwrap();
        document["wrapping_recipient"] =
            serde_json::Value::String(x25519::Identity::generate().to_public().to_string());
        fs::write(&identity_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let error = match ReplicationPackage::for_store(Arc::clone(&second_store)) {
            Ok(_) => panic!("tampered enrollment unexpectedly opened the Vault"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("signature verification failed"));
    }

    #[test]
    fn non_genesis_device_cannot_enroll_another_device() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis = package_for_store(&genesis_store);
        let mut second = join_vault(&mut genesis, &second_store, None);
        let third = DeviceKeyMaterial::generate().unwrap();

        let error = second.enroll_device(third.enrollment()).unwrap_err();

        assert!(error.to_string().contains("only the genesis Device"));
    }

    #[test]
    fn concurrent_heads_require_an_explicit_signed_merge() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis = package_for_store(&genesis_store);
        let second = join_vault(&mut genesis, &second_store, None);

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
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis = package_for_store(&genesis_store);
        let second = join_vault(&mut genesis, &second_store, None);
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
        let genesis_keys = store_keys();
        let genesis_root = directory.path().join("genesis-store");
        let genesis_store = open_store_at(genesis_root.clone(), Arc::clone(&genesis_keys));
        let second_keys = store_keys();
        let second_root = directory.path().join("second-store");
        let second_store = open_store_at(second_root.clone(), Arc::clone(&second_keys));
        let mut genesis = package_for_store(&genesis_store);
        let second_device_id = second_store.device().device_id().to_string();
        let second = join_vault(&mut genesis, &second_store, Some("Second Mac"));
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
        assert!(devices[0].is_genesis);
        assert!(devices[0].is_current);
        assert_eq!(devices[1].device_name.as_deref(), Some("Second Mac"));
        assert!(!devices[1].is_current);

        // One signed step: the store writes the new generation document, so the vault and the
        // bytes it encrypts can never name different key domains.
        assert!(!genesis.revoke_device(&second_device_id).unwrap().local_device_fenced);
        assert_eq!(genesis.current_generation(), 2);
        assert_eq!(genesis_store.current_generation().unwrap(), 2);
        let rotated: KeyGenerationDocument = serde_json::from_slice(
            &fs::read(genesis.package.layout().generation_document(2)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            rotated.envelopes.keys().cloned().collect::<Vec<_>>(),
            vec![genesis_store.device().device_id().to_string()]
        );
        assert_eq!(
            rotated.revoked_devices,
            BTreeMap::from([(second_device_id.clone(), 1)])
        );
        assert_eq!(genesis.devices()[1].revoked_generation, Some(2));
        let re_enrollment = genesis
            .enroll_device(second_store.device().enrollment())
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

        let reopened = package_for_store(&open_store_at(genesis_root, genesis_keys));
        assert_eq!(reopened.current_generation(), 2);
        let revoked_error =
            match ReplicationPackage::for_store(open_store_at(second_root, second_keys)) {
                Ok(_) => panic!("revoked Device unexpectedly reopened the Vault"),
                Err(error) => error,
            };
        assert!(revoked_error.to_string().contains("was revoked at key generation 2"));

        let third_store = open_store(directory.path(), "third");
        let third = join_vault(&mut genesis.package, &third_store, Some("Third Mac"));
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

    /// Put one secret into the package's own store and describe it as an entity.
    fn fixture_secret(package: &ReplicationPackage) -> (SecretId, EntityPayload, PreparedObject) {
        let store = Arc::clone(&package.store);
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
        (secret_id, entity, object)
    }

    #[test]
    fn operation_waits_when_its_object_is_missing_from_the_shared_half() {
        let (_directory, package) = package();
        let (_secret_id, entity, object) = fixture_secret(&package);
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[entity],
                objects: std::slice::from_ref(&object),
            })
            .unwrap();
        publish_immutable(&package.operation_path(&prepared), &prepared.operation).unwrap();

        // The operation file synced ahead of the object it names.
        let object_path = package.layout().object(&object.id);
        let bytes = fs::read(&object_path).unwrap();
        fs::remove_file(&object_path).unwrap();
        let pending = package.scan().unwrap();
        assert_eq!(pending.pending.len(), 1);
        assert!(pending.pending[0].reason.contains("has not arrived"));

        publish_immutable(&object_path, &bytes).unwrap();
        let complete = package.scan().unwrap();
        assert_eq!(complete.verified.len(), 1);
        assert!(complete.pending.is_empty());
    }

    #[test]
    fn object_conflict_copy_is_validated_and_normalized_by_digest() {
        let (_directory, package) = package();
        let (secret_id, entity, object) = fixture_secret(&package);
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                entities: &[entity],
                objects: std::slice::from_ref(&object),
            })
            .unwrap();
        publish_immutable(&package.operation_path(&prepared), &prepared.operation).unwrap();
        // A sync provider renamed the object aside; only the conflict copy is left.
        let object_path = package.layout().object(&object.id);
        let bytes = fs::read(&object_path).unwrap();
        fs::remove_file(&object_path).unwrap();
        fs::write(
            package
                .layout()
                .objects_dir()
                .join("object (conflicted copy).age"),
            &bytes,
        )
        .unwrap();

        let scan = package.scan().unwrap();

        assert_eq!(scan.verified.len(), 1);
        assert!(object_path.is_file());
        // Restoring the canonical name restores the store's own read path.
        assert_eq!(
            package.store.get(&secret_id).unwrap().as_slice(),
            b"fixture payload, not a credential"
        );
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
        let path = package.layout().objects_dir().join("collision.age");
        publish_immutable(&path, b"first").unwrap();

        let error = publish_immutable(&path, b"second").unwrap_err();

        assert!(error.to_string().contains("different bytes"));
        assert_eq!(fs::read(path).unwrap(), b"first");
    }

    #[test]
    fn enabling_sync_never_replaces_an_existing_directory() {
        let directory = tempfile::tempdir().unwrap();
        let store = open_store(directory.path(), "genesis");
        let target = directory.path().join("Sync/Personal.floriavault");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("keep"), b"existing package marker").unwrap();

        let error = ReplicationEngine::enable_sync_at(&store, &target).err().unwrap();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            fs::read(target.join("keep")).unwrap(),
            b"existing package marker"
        );
        // The authoritative shared half never left its original location.
        assert_eq!(store.shared_root(), directory.path().join("genesis-store/shared"));
        assert!(store.shared_layout().vault_json().is_file());
    }

    #[test]
    fn canonical_object_name_with_wrong_digest_is_damaged() {
        let (_directory, package) = package();
        let path = package.layout().object(&"0".repeat(64));
        fs::write(path, b"not an age ciphertext").unwrap();

        let scan = package.scan().unwrap();

        assert_eq!(scan.damaged.len(), 1);
        assert!(scan.damaged[0].reason.contains("actual digest"));
    }

    #[test]
    fn engine_reports_damaged_files_relative_to_the_replication_package() {
        let (directory, package) = package();
        let root = package.root();
        let store = Arc::clone(&package.store);
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
        let unsigned = vault::VaultUnsigned {
            format_version: 1,
            vault_id: VAULT_ID.to_string(),
            genesis_device_id: "22222222-2222-4222-8222-222222222222".to_string(),
            genesis_public_key: encode(
                SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes(),
            ),
            created_at: "2026-08-06T00:00:00Z".to_string(),
        };
        // The signed bytes are the context followed by this exact JSON; the signature below
        // pins both halves.
        assert_eq!(
            String::from_utf8(serde_json::to_vec(&unsigned).unwrap()).unwrap(),
            "{\"format_version\":1,\"vault_id\":\"11111111-1111-4111-8111-111111111111\",\"genesis_device_id\":\"22222222-2222-4222-8222-222222222222\",\"genesis_public_key\":\"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw\",\"created_at\":\"2026-08-06T00:00:00Z\"}"
        );
        assert_eq!(
            vault::sign_struct(
                vault::VAULT_SIGNATURE_CONTEXT,
                &unsigned,
                &SigningKey::from_bytes(&[7; 32])
            )
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

        assert!(error.to_string().contains("crypto error"));
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
        let package = package_for_store(&open_store(directory.path(), "genesis"));
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
    fn engine_publishes_committed_outbox_without_copying_the_object() {
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
        let package = package_for_store(&store);
        let intents = journal(directory.path(), "local", package.vault_id(), [74; 32]);
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
        assert_eq!(intents.device_sequence(store.device().device_id()), 1);
        let scan = engine.package.scan().unwrap();
        assert_eq!(scan.verified.len(), 1);
        // Publishing moved no bytes: the object the operation names is the one file the store
        // wrote, at the path the store reads it from.
        assert_eq!(shared_objects(&store), BTreeSet::from([object.id.clone()]));
        assert!(store.shared_layout().object(&object.id).is_file());
        assert_eq!(
            store.get(&secret_id).unwrap().as_slice(),
            b"fixture payload, not a credential"
        );
    }

    #[test]
    fn engine_self_fences_when_an_accepted_local_operation_disappears() {
        let (directory, package) = package();
        let store = Arc::clone(&package.store);
        let intents = journal(directory.path(), "local", package.vault_id(), [75; 32]);
        let catalog = Arc::new(Catalog::open(directory.path().join("catalog.sqlite")).unwrap());
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
        intents
            .accept_device_operation(store.device().device_id(), 1, OPERATION_ID)
            .unwrap();
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
        let administrator_store = open_store(directory.path(), "administrator");
        let second_store = open_store(directory.path(), "second");
        let mut administrator = package_for_store(&administrator_store);
        let second_device_id = second_store.device().device_id().to_string();
        join_vault(&mut administrator, &second_store, None);
        let layout = administrator.layout();
        let (engine, _catalog) = engine_for_package(
            directory.path(),
            "administrator",
            administrator,
            [79; 32],
            Arc::clone(&administrator_store),
        );

        assert!(!engine.sync().unwrap().local_device_fenced);
        assert!(!engine.revoke_device(&second_device_id).unwrap().local_device_fenced);
        assert_eq!(engine.package.current_generation(), 2);

        // A rollback of the shared half drops a generation this Device already checkpointed.
        fs::remove_file(layout.generation_document(2)).unwrap();
        let rollback = engine.sync().unwrap();

        assert!(rollback.local_device_fenced);
        assert!(rollback.messages[0].contains("accepted key generation 2"));
    }

    #[test]
    fn verified_commit_replays_into_an_empty_catalog_and_store() {
        let directory = tempfile::tempdir().unwrap();
        let source_keys = store_keys();
        let source_root = directory.path().join("source-store");
        let source_store = open_store_at(source_root.clone(), Arc::clone(&source_keys));
        let target_store = open_store(directory.path(), "target");
        let mut package = package_for_store(&source_store);
        let target_package = join_vault(&mut package, &target_store, None);
        let source_intents =
            journal(directory.path(), "source", package.vault_id(), [76; 32]);
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

        // A restored Mac: same Device identity and same shared half, but its local library,
        // catalog, and journal are empty. Its own signed operations must replay back into it.
        let digests = source_store
            .version_refs(&secret_id)
            .unwrap()
            .into_iter()
            .map(|reference| reference.digest)
            .collect::<BTreeSet<_>>();
        drop(source);
        drop(source_store);
        for path in regular_files_recursively(&source_root.join("local/heads")).unwrap() {
            fs::remove_file(path).unwrap();
        }
        let restored_catalog = Arc::new(
            Catalog::open(directory.path().join("restored-catalog.sqlite")).unwrap(),
        );
        let restored_store = open_store_at(source_root, source_keys);
        let restored_package = package_for_store(&restored_store);
        let restored_intents =
            journal(directory.path(), "restored", restored_package.vault_id(), [78; 32]);
        let restored = ReplicationEngine::from_parts(
            restored_package,
            restored_intents,
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
        let target_intents =
            journal(directory.path(), "target", target_package.vault_id(), [77; 32]);
        let target = ReplicationEngine::from_parts(
            target_package,
            target_intents,
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

        // One physical copy end to end: writer, restored reader, and importer all read the same
        // three files, and importing created none of its own.
        assert_eq!(shared_objects(&restored_store), digests);
        assert_eq!(shared_objects(&target_store), digests);
        assert_eq!(
            target_store.shared_root(),
            restored_store.shared_root(),
            "both Devices read the same shared half"
        );
        for reference in target_store.version_refs(&secret_id).unwrap() {
            assert_eq!(
                target_store.shared_layout().object(&reference.digest),
                restored_store.shared_layout().object(&reference.digest)
            );
        }
    }

    #[test]
    fn disjoint_entity_edits_from_two_devices_do_not_conflict() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis_package = package_for_store(&genesis_store);
        let second_package = join_vault(&mut genesis_package, &second_store, None);
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

    #[test]
    fn deleting_a_secret_publishes_a_tombstone_and_keeps_the_shared_object() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_store = open_store(directory.path(), "genesis");
        let second_store = open_store(directory.path(), "second");
        let mut genesis_package = package_for_store(&genesis_store);
        let second_package = join_vault(&mut genesis_package, &second_store, None);
        let (genesis, genesis_catalog) = engine_for_package(
            directory.path(),
            "genesis",
            genesis_package,
            [86; 32],
            Arc::clone(&genesis_store),
        );
        let (second, second_catalog) = engine_for_package(
            directory.path(),
            "second",
            second_package,
            [87; 32],
            Arc::clone(&second_store),
        );

        let secret_id: SecretId = "55555555-5555-4555-8555-555555555555".parse().unwrap();
        genesis_store
            .put_identified(
                secret_id.clone(),
                NewSecret::managed("Deleted fixture"),
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
        assert!(second_store.record(&secret_id).unwrap().is_some());
        let objects = shared_objects(&genesis_store);
        assert_eq!(objects.len(), 1);

        // Another Device is enrolled, so deleting drops this Mac's head document and leaves the
        // immutable object behind; the cross-device meaning is a signed tombstone.
        genesis_store.delete(&secret_id).unwrap();
        genesis_catalog
            .apply_replicated_catalog(&project_projection("Base"))
            .unwrap();
        assert!(genesis.stage_current_snapshot("delete").unwrap());
        assert_eq!(genesis.sync().unwrap().published, 1);

        let imported = second.sync().unwrap();

        assert_eq!(imported.imported, 1);
        assert_eq!(imported.conflicts, 0);
        assert!(second_store.record(&secret_id).unwrap().is_none());
        assert_eq!(shared_objects(&second_store), objects);
        assert_eq!(
            second_catalog.replicated_catalog().unwrap(),
            project_projection("Base")
        );
        // A tombstoned entity is not rediscovered as a missing secret on the next pass.
        assert!(!genesis.stage_current_snapshot("settled").unwrap());
        assert!(!second.stage_current_snapshot("settled").unwrap());
    }
}
