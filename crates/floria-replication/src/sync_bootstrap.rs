//! Authenticated Vault control material for transport bootstrap.
//!
//! A platform adapter moves these payloads as opaque bytes. Rust owns their routes, bounds,
//! signature validation, generation-chain validation, and create-only identity. This module does
//! not activate a downloaded Vault or replace the local Store; activation is a separate recovery
//! transaction so a partial bootstrap can never destroy the working Vault.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::x25519;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use floria_store::vault::{
    self, DeviceDocument, EnrollmentRequestDocument, KeyGenerationDocument, MAX_DESCRIPTOR_BYTES,
};
use floria_store::{AgeDirStore, DeviceKeyMaterial, StoreVerification};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{ReplicationError, ReplicationPackage, ReplicationResult};

const MAX_BOOTSTRAP_DEVICES: usize = 64;
const MAX_BOOTSTRAP_GENERATIONS: usize = 64;
const MAX_BOOTSTRAP_ENVELOPES: usize = MAX_BOOTSTRAP_DEVICES * MAX_BOOTSTRAP_GENERATIONS;
/// Leaves two MiB for the control response envelope beneath its eight MiB frame limit.
const MAX_BOOTSTRAP_WIRE_BYTES: usize = 6 * 1024 * 1024;

/// One signed JSON document with a transport-visible stable route and opaque payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncBootstrapDocument {
    route: String,
    document_base64: String,
}

impl SyncBootstrapDocument {
    pub fn route(&self) -> &str {
        &self.route
    }

    pub fn document_base64(&self) -> &str {
        &self.document_base64
    }
}

/// One encrypted historical generation key for a Device enrolled after that generation existed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncBootstrapEnvelope {
    device_id: String,
    generation: u32,
    ciphertext_base64: String,
}

/// Result of preparing this Device to join an authenticated target Vault.
/// The request remains self-signed and carries no authorization until a trusted
/// genesis Device compares its fingerprint and approves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SyncEnrollmentPreparation {
    AlreadyEnrolled { device_id: String },
    Request(SyncEnrollmentRequest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEnrollmentRequest {
    device_id: String,
    device_name: Option<String>,
    requested_at: String,
    fingerprint: String,
    document_base64: String,
}

impl SyncEnrollmentRequest {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn document_base64(&self) -> &str {
        &self.document_base64
    }
}

/// Human-reviewable projection of a cryptographically valid enrollment request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEnrollmentReview {
    device_id: String,
    device_name: Option<String>,
    requested_at: String,
    fingerprint: String,
}

/// Human-reviewable projection of one authenticated Device identity.
///
/// The transport never interprets the signed identity. Rust derives this view only after the
/// complete Vault lifecycle has passed signature and generation-chain validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncVaultDevice {
    device_id: String,
    device_name: Option<String>,
    fingerprint: String,
    enrolled_generation: u32,
    revoked_generation: Option<u32>,
    is_genesis: bool,
    is_current: bool,
}

/// Result of explicitly activating an authenticated, enrolled Vault candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SyncVaultActivation {
    Ready {
        vault_id: String,
        key_generation: u32,
        restart_required: bool,
    },
    MergeRequired {
        current_vault_id: String,
        target_vault_id: String,
        local_items: usize,
    },
}

/// A verified, disposable Store snapshot re-encrypted into an enrolled target Vault.
///
/// This is intentionally not a wire type. The daemon consumes it immediately to create a
/// durable activation package; dropping it removes the plaintext-free staging directory.
pub struct PreparedVaultMerge {
    vault_id: String,
    store: AgeDirStore,
    verification: StoreVerification,
}

impl PreparedVaultMerge {
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn store(&self) -> &AgeDirStore {
        &self.store
    }

    pub fn verification(&self) -> &StoreVerification {
        &self.verification
    }

    pub fn root(&self) -> &Path {
        self.store.root()
    }
}

impl Drop for PreparedVaultMerge {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.store.root());
    }
}

impl SyncEnrollmentReview {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl SyncVaultDevice {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn revoked_generation(&self) -> Option<u32> {
        self.revoked_generation
    }

    pub fn is_genesis(&self) -> bool {
        self.is_genesis
    }

    pub fn is_current(&self) -> bool {
        self.is_current
    }
}

impl SyncBootstrapEnvelope {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn ciphertext_base64(&self) -> &str {
        &self.ciphertext_base64
    }
}

/// A bounded, self-contained snapshot of the public/signed material required to identify a Vault
/// and the encrypted envelopes required to unlock its historical generations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncVaultBootstrap {
    vault_id: String,
    vault_document_base64: String,
    device_identities: Vec<SyncBootstrapDocument>,
    enrollment_requests: Vec<SyncBootstrapDocument>,
    key_generations: Vec<SyncBootstrapDocument>,
    generation_envelopes: Vec<SyncBootstrapEnvelope>,
}

struct ValidatedBootstrap {
    vault: vault::VaultDocument,
    identities: BTreeMap<String, DeviceDocument>,
    requests: BTreeMap<String, EnrollmentRequestDocument>,
    generations: BTreeMap<u32, KeyGenerationDocument>,
}

impl SyncVaultBootstrap {
    /// Capture the current Store's security documents. Every signed input is validated before it
    /// leaves Rust; external envelopes remain opaque until their target Device unwraps them.
    pub fn capture(store: &AgeDirStore) -> ReplicationResult<Self> {
        let vault = store.vault_document();
        vault::validate_vault(&vault)?;
        let layout = store.shared_layout();
        let generations = vault::load_key_generations(&layout, &vault)?;
        require_count("key generations", generations.len(), MAX_BOOTSTRAP_GENERATIONS)?;

        let mut device_identities = Vec::new();
        let mut enrollment_requests = Vec::new();
        let mut generation_envelopes = Vec::new();
        let entries = fs::read_dir(layout.devices_dir())
            .map_err(|source| replication_io(layout.devices_dir(), source))?;
        for entry in entries {
            let entry = entry.map_err(|source| replication_io(layout.devices_dir(), source))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| replication_io(path.clone(), source))?;
            if !metadata.file_type().is_dir() {
                continue;
            }
            let device_id = entry.file_name().into_string().map_err(|_| {
                ReplicationError::Invalid("Vault Device directory name is not UTF-8".to_string())
            })?;
            vault::require_uuid("Device directory", &device_id)?;

            let identity_path = layout.device_identity(&device_id);
            match vault::read_device_identity(&identity_path, &vault) {
                Ok(document) => {
                    if document.device_id != device_id {
                        return Err(ReplicationError::Invalid(format!(
                            "Device identity route {device_id} names Device {}",
                            document.device_id
                        )));
                    }
                    device_identities.push(opaque_document(&device_id, &document)?);
                }
                Err(floria_store::StoreError::Io { source, .. })
                    if source.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }

            let request_path = layout.enrollment_request(&device_id);
            match vault::read_enrollment_request(&request_path, &vault) {
                Ok(document) => {
                    if document.device_id != device_id {
                        return Err(ReplicationError::Invalid(format!(
                            "enrollment request route {device_id} names Device {}",
                            document.device_id
                        )));
                    }
                    enrollment_requests.push(opaque_document(&device_id, &document)?);
                }
                Err(floria_store::StoreError::Io { source, .. })
                    if source.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }

            for generation in generations.keys() {
                let envelope_path = layout.envelope(&device_id, *generation);
                match vault::read_untrusted_file(&envelope_path, MAX_DESCRIPTOR_BYTES) {
                    Ok(ciphertext) => generation_envelopes.push(SyncBootstrapEnvelope {
                        device_id: device_id.clone(),
                        generation: *generation,
                        ciphertext_base64: BASE64.encode(ciphertext),
                    }),
                    Err(floria_store::StoreError::Io { source, .. })
                        if source.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        require_count("Device identities", device_identities.len(), MAX_BOOTSTRAP_DEVICES)?;
        require_count("enrollment requests", enrollment_requests.len(), MAX_BOOTSTRAP_DEVICES)?;
        require_count(
            "generation envelopes",
            generation_envelopes.len(),
            MAX_BOOTSTRAP_ENVELOPES,
        )?;

        device_identities.sort_by(|left, right| left.route.cmp(&right.route));
        enrollment_requests.sort_by(|left, right| left.route.cmp(&right.route));
        generation_envelopes.sort_by(|left, right| {
            (&left.device_id, left.generation).cmp(&(&right.device_id, right.generation))
        });
        let key_generations = generations
            .into_iter()
            .map(|(generation, document)| {
                opaque_document(generation.to_string(), &document)
            })
            .collect::<ReplicationResult<Vec<_>>>()?;
        let snapshot = Self {
            vault_id: vault.vault_id.clone(),
            vault_document_base64: encode_json(&vault)?,
            device_identities,
            enrollment_requests,
            key_generations,
            generation_envelopes,
        };
        snapshot.validate_for_vault(&vault.vault_id)?;
        Ok(snapshot)
    }

    /// Validate an untrusted transport snapshot and bind it to the selected Vault zone. Passing
    /// establishes internal authenticity, not user intent to join that Vault.
    pub fn validate_for_vault(&self, expected_vault_id: &str) -> ReplicationResult<()> {
        self.validated(expected_vault_id).map(|_| ())
    }

    fn validated(&self, expected_vault_id: &str) -> ReplicationResult<ValidatedBootstrap> {
        let wire_size = serde_json::to_vec(self)?.len();
        if wire_size > MAX_BOOTSTRAP_WIRE_BYTES {
            return Err(ReplicationError::Invalid(format!(
                "Vault bootstrap is {wire_size} bytes, maximum is {MAX_BOOTSTRAP_WIRE_BYTES}"
            )));
        }
        require_count("Device identities", self.device_identities.len(), MAX_BOOTSTRAP_DEVICES)?;
        require_count("enrollment requests", self.enrollment_requests.len(), MAX_BOOTSTRAP_DEVICES)?;
        require_count("key generations", self.key_generations.len(), MAX_BOOTSTRAP_GENERATIONS)?;
        require_count(
            "generation envelopes",
            self.generation_envelopes.len(),
            MAX_BOOTSTRAP_ENVELOPES,
        )?;
        if self.vault_id != expected_vault_id {
            return Err(ReplicationError::Invalid(format!(
                "Vault bootstrap {} does not match selected Vault {expected_vault_id}",
                self.vault_id
            )));
        }
        let vault: vault::VaultDocument = decode_json(
            &self.vault_document_base64,
            "Vault bootstrap document",
        )?;
        vault::validate_vault(&vault)?;
        if vault.vault_id != self.vault_id {
            return Err(ReplicationError::Invalid(format!(
                "Vault bootstrap route {} does not match signed Vault {}",
                self.vault_id, vault.vault_id
            )));
        }

        let identities = decode_routed_documents::<DeviceDocument>(
            &self.device_identities,
            "Device identity",
            |document| document.device_id.as_str(),
            |document| vault::validate_device_identity(document, &vault),
        )?;
        if !identities.contains_key(&vault.genesis_device_id) {
            return Err(ReplicationError::Invalid(
                "Vault bootstrap has no genesis Device identity".to_string(),
            ));
        }
        let requests = decode_routed_documents::<EnrollmentRequestDocument>(
            &self.enrollment_requests,
            "enrollment request",
            |document| document.device_id.as_str(),
            |document| vault::validate_enrollment_request(document, &vault),
        )?;
        let generations = decode_generations(&self.key_generations, &vault)?;

        let mut envelope_routes = BTreeSet::new();
        for envelope in &self.generation_envelopes {
            vault::require_uuid("generation envelope Device", &envelope.device_id)?;
            if !identities.contains_key(&envelope.device_id)
                && !requests.contains_key(&envelope.device_id)
            {
                return Err(ReplicationError::Invalid(format!(
                    "generation envelope names unknown Device {}",
                    envelope.device_id
                )));
            }
            if !generations.contains_key(&envelope.generation) {
                return Err(ReplicationError::Invalid(format!(
                    "generation envelope names unavailable generation {}",
                    envelope.generation
                )));
            }
            if !envelope_routes.insert((&envelope.device_id, envelope.generation)) {
                return Err(ReplicationError::Invalid(format!(
                    "generation envelope route {}:{} appears more than once",
                    envelope.device_id, envelope.generation
                )));
            }
            let ciphertext = decode_bounded(
                &envelope.ciphertext_base64,
                "generation envelope",
                MAX_DESCRIPTOR_BYTES as usize,
            )?;
            if ciphertext.is_empty() {
                return Err(ReplicationError::Invalid(
                    "generation envelope cannot be empty".to_string(),
                ));
            }
        }
        Ok(ValidatedBootstrap {
            vault,
            identities,
            requests,
            generations,
        })
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn vault_document_base64(&self) -> &str {
        &self.vault_document_base64
    }

    pub fn device_identities(&self) -> &[SyncBootstrapDocument] {
        &self.device_identities
    }

    pub fn enrollment_requests(&self) -> &[SyncBootstrapDocument] {
        &self.enrollment_requests
    }

    pub fn key_generations(&self) -> &[SyncBootstrapDocument] {
        &self.key_generations
    }

    pub fn generation_envelopes(&self) -> &[SyncBootstrapEnvelope] {
        &self.generation_envelopes
    }

    /// Build or replay this Device's self-signed request for a selected Vault.
    /// Existing immutable requests are reused exactly; a route collision with
    /// other key material is rejected rather than overwritten.
    pub fn prepare_enrollment(
        &self,
        device: &DeviceKeyMaterial,
        device_name: Option<String>,
        requested_at: &str,
    ) -> ReplicationResult<SyncEnrollmentPreparation> {
        let validated = self.validated(&self.vault_id)?;
        let enrollment = device.enrollment_named(device_name.clone());
        if let Some(identity) = validated.identities.get(device.device_id()) {
            if identity.signing_public_key != enrollment.signing_public_key
                || identity.wrapping_recipient != enrollment.wrapping_recipient
            {
                return Err(ReplicationError::Invalid(format!(
                    "Device {} is enrolled with different public keys",
                    device.device_id()
                )));
            }
            return Ok(SyncEnrollmentPreparation::AlreadyEnrolled {
                device_id: device.device_id().to_string(),
            });
        }

        let request = if let Some(existing) = validated.requests.get(device.device_id()) {
            if existing.signing_public_key != enrollment.signing_public_key
                || existing.wrapping_recipient != enrollment.wrapping_recipient
            {
                return Err(ReplicationError::Invalid(format!(
                    "enrollment request for Device {} uses different public keys",
                    device.device_id()
                )));
            }
            existing.clone()
        } else {
            device.enrollment_request(&validated.vault, device_name, requested_at)?
        };
        Ok(SyncEnrollmentPreparation::Request(
            enrollment_request_transport(&request)?,
        ))
    }

    /// Replace this installation's revoked identity and prepare its new self-signed request.
    /// The authenticated lifecycle is the authority for revocation; callers cannot rotate a
    /// healthy identity or substitute a different reviewed fingerprint.
    pub fn prepare_reenrollment(
        &self,
        store: std::sync::Arc<AgeDirStore>,
        expected_fingerprint: &str,
        device_name: Option<String>,
        requested_at: &str,
    ) -> ReplicationResult<SyncEnrollmentPreparation> {
        let current_vault_id = store.vault_document().vault_id;
        let validated = self.validated(&current_vault_id)?;
        let current = store.device();
        let identity = validated.identities.get(current.device_id()).ok_or_else(|| {
            ReplicationError::Invalid(format!(
                "Device {} has not been approved for Vault {}",
                current.device_id(), current_vault_id
            ))
        })?;
        let local = current.enrollment();
        if identity.signing_public_key != local.signing_public_key
            || identity.wrapping_recipient != local.wrapping_recipient
        {
            return Err(ReplicationError::Invalid(format!(
                "approved Device {} does not match this installation's private keys",
                current.device_id()
            )));
        }
        let actual_fingerprint = vault::signing_key_fingerprint(&identity.signing_public_key);
        if actual_fingerprint != expected_fingerprint {
            return Err(ReplicationError::Invalid(format!(
                "Device fingerprint changed for Device {}",
                current.device_id()
            )));
        }
        let revoked = validated.generations.values().any(|generation| {
            generation.revoked_devices.contains_key(current.device_id())
        });
        if !revoked {
            return Err(ReplicationError::Invalid(format!(
                "Device {} has not been removed from Vault {}",
                current.device_id(), current_vault_id
            )));
        }

        let replacement = store.rotate_device_identity()?;
        self.prepare_enrollment(
            replacement.as_ref(),
            device_name,
            requested_at,
        )
    }

    /// Return only valid requests that have not already received a signed Device identity.
    pub fn review_enrollments(&self) -> ReplicationResult<Vec<SyncEnrollmentReview>> {
        let validated = self.validated(&self.vault_id)?;
        Ok(validated
            .requests
            .into_values()
            .filter(|request| !validated.identities.contains_key(&request.device_id))
            .map(|request| {
                let fingerprint = request.fingerprint();
                SyncEnrollmentReview {
                    device_id: request.device_id,
                    device_name: request.device_name,
                    requested_at: request.requested_at,
                    fingerprint,
                }
            })
            .collect())
    }

    /// Project authenticated Device identities without exposing their signing documents.
    pub fn review_devices(
        &self,
        current_device_id: &str,
    ) -> ReplicationResult<Vec<SyncVaultDevice>> {
        let validated = self.validated(&self.vault_id)?;
        let mut revoked = BTreeMap::<String, u32>::new();
        for generation in validated.generations.values() {
            for device_id in generation.revoked_devices.keys() {
                revoked.entry(device_id.clone()).or_insert(generation.generation);
            }
        }
        let mut devices = validated
            .identities
            .into_values()
            .map(|identity| SyncVaultDevice {
                fingerprint: vault::signing_key_fingerprint(&identity.signing_public_key),
                revoked_generation: revoked.get(&identity.device_id).copied(),
                is_genesis: identity.device_id == validated.vault.genesis_device_id,
                is_current: identity.device_id == current_device_id,
                device_id: identity.device_id,
                device_name: identity.device_name,
                enrolled_generation: identity.enrolled_generation,
            })
            .collect::<Vec<_>>();
        devices.sort_by(|left, right| {
            right
                .is_current
                .cmp(&left.is_current)
                .then(left.revoked_generation.is_some().cmp(&right.revoked_generation.is_some()))
                .then(left.device_name.cmp(&right.device_name))
                .then(left.device_id.cmp(&right.device_id))
        });
        Ok(devices)
    }

    /// Approve exactly the request whose fingerprint the user compared out of band.
    /// Signing the Device identity and wrapping every historical generation are one
    /// idempotent Rust lifecycle action; callers never handle either private key.
    pub fn approve_enrollment(
        &self,
        store: std::sync::Arc<AgeDirStore>,
        device_id: &str,
        expected_fingerprint: &str,
    ) -> ReplicationResult<SyncVaultBootstrap> {
        let current_vault_id = store.vault_document().vault_id;
        let validated = self.validated(&current_vault_id)?;
        let request = validated.requests.get(device_id).ok_or_else(|| {
            ReplicationError::Invalid(format!(
                "Vault bootstrap has no enrollment request for Device {device_id}"
            ))
        })?;
        let actual_fingerprint = request.fingerprint();
        if actual_fingerprint != expected_fingerprint {
            return Err(ReplicationError::Invalid(format!(
                "enrollment fingerprint changed for Device {device_id}"
            )));
        }
        let mut package = ReplicationPackage::for_store(std::sync::Arc::clone(&store))?;
        package.enroll_device(request.enrollment())?;
        SyncVaultBootstrap::capture(&store)
    }

    /// Revoke exactly the authenticated Device identity the user reviewed, rotate the Vault data
    /// key, and return the complete lifecycle ready for create-only publication.
    ///
    /// Existing ciphertext remains readable by that Device; key rotation fences it from every
    /// later version. Version 1 reserves the revocation sequence for the generic operation-log
    /// transport, so coordinated-record sync records zero here and relies on generation keys.
    pub fn revoke_device(
        &self,
        store: std::sync::Arc<AgeDirStore>,
        device_id: &str,
        expected_fingerprint: &str,
    ) -> ReplicationResult<SyncVaultBootstrap> {
        let current_vault_id = store.vault_document().vault_id;
        let validated = self.validated(&current_vault_id)?;
        verify_local_device_access(self, &validated, &store.device())?;
        if store.device().device_id() != validated.vault.genesis_device_id {
            return Err(ReplicationError::Invalid(
                "only the first Mac may remove another Mac in version 1".to_string(),
            ));
        }

        // Bring create-only lifecycle additions observed through CloudKit into the local Store
        // before rotating. Any route collision fails closed and leaves the current generation.
        materialize_lifecycle(self, &store.shared_root())?;
        store.refresh_shared_lifecycle(&current_vault_id)?;
        let current = SyncVaultBootstrap::capture(&store)?;
        let validated = current.validated(&current_vault_id)?;
        if device_id == validated.vault.genesis_device_id
            || device_id == store.device().device_id()
        {
            return Err(ReplicationError::Invalid(
                "the first Mac cannot remove itself in version 1".to_string(),
            ));
        }
        let target = validated.identities.get(device_id).ok_or_else(|| {
            ReplicationError::Invalid(format!("Device {device_id} is not enrolled"))
        })?;
        let actual_fingerprint = vault::signing_key_fingerprint(&target.signing_public_key);
        if actual_fingerprint != expected_fingerprint {
            return Err(ReplicationError::Invalid(format!(
                "Device fingerprint changed for Device {device_id}"
            )));
        }

        let revoked = validated
            .generations
            .values()
            .flat_map(|generation| generation.revoked_devices.keys().cloned())
            .collect::<BTreeSet<_>>();
        if revoked.contains(device_id) {
            return Err(ReplicationError::Invalid(format!(
                "Device {device_id} is already removed"
            )));
        }
        let recipients = validated
            .identities
            .iter()
            .filter(|(candidate_id, _)| {
                candidate_id.as_str() != device_id && !revoked.contains(candidate_id.as_str())
            })
            .map(|(candidate_id, identity)| {
                let recipient = x25519::Recipient::from_str(&identity.wrapping_recipient)
                    .map_err(|error| {
                        ReplicationError::Invalid(format!(
                            "invalid Device wrapping recipient for {candidate_id}: {error}"
                        ))
                    })?;
                Ok((candidate_id.clone(), recipient))
            })
            .collect::<ReplicationResult<BTreeMap<_, _>>>()?;
        store.rotate_generation(
            &recipients,
            BTreeMap::from([(device_id.to_string(), 0)]),
        )?;
        SyncVaultBootstrap::capture(&store)
    }

    /// Materialize and activate this authenticated lifecycle snapshot for the local Device.
    /// Swift/CloudKit remains an opaque transport; Rust owns every validation and the durable
    /// Store switch. A populated different Vault is reported for copy-and-verify instead.
    pub fn activate(
        &self,
        store: std::sync::Arc<AgeDirStore>,
        local_items: usize,
    ) -> ReplicationResult<SyncVaultActivation> {
        let validated = self.validated(&self.vault_id)?;
        let current_vault_id = store.vault_document().vault_id;
        if current_vault_id != validated.vault.vault_id && local_items > 0 {
            return Ok(SyncVaultActivation::MergeRequired {
                current_vault_id,
                target_vault_id: validated.vault.vault_id,
                local_items,
            });
        }

        let device = store.device();
        verify_local_device_access(self, &validated, &device)?;
        let key_generation = *validated.generations.keys().next_back().ok_or_else(|| {
            ReplicationError::Invalid("Vault bootstrap has no key generation".to_string())
        })?;
        let switching_vault = current_vault_id != validated.vault.vault_id;
        let target = if switching_vault {
            store
                .root()
                .join("cloudkit-vaults")
                .join(&validated.vault.vault_id)
                .join("shared")
        } else {
            store.shared_root()
        };
        materialize_lifecycle(self, &target)?;

        if switching_vault {
            store.activate_shared_location(&target, &validated.vault.vault_id)?;
        } else {
            store.refresh_shared_lifecycle(&validated.vault.vault_id)?;
        }
        Ok(SyncVaultActivation::Ready {
            vault_id: validated.vault.vault_id,
            key_generation,
            restart_required: switching_vault,
        })
    }

    /// Re-encrypt the complete local Store into an isolated target-Vault snapshot.
    ///
    /// The live Store is never changed. The caller supplies a new sibling path, consumes the
    /// returned Store to build a durable activation package, then lets the staging directory be
    /// removed on drop.
    pub fn prepare_merge(
        &self,
        store: std::sync::Arc<AgeDirStore>,
        target_root: PathBuf,
    ) -> ReplicationResult<PreparedVaultMerge> {
        let validated = self.validated(&self.vault_id)?;
        let current_vault_id = store.vault_document().vault_id;
        if current_vault_id == validated.vault.vault_id {
            return Err(ReplicationError::Invalid(
                "Vault merge requires a different target Vault".to_string(),
            ));
        }
        if target_root.exists() {
            return Err(ReplicationError::Invalid(format!(
                "Vault merge staging path already exists: {}",
                target_root.display()
            )));
        }
        verify_local_device_access(self, &validated, &store.device())?;

        let result = (|| {
            materialize_lifecycle(self, &target_root.join("shared"))?;
            let target = store.open_migration_target(
                target_root.clone(),
                &validated.vault.vault_id,
            )?;
            let verification = store.copy_logical_contents_to(&target)?;
            Ok(PreparedVaultMerge {
                vault_id: validated.vault.vault_id.clone(),
                store: target,
                verification,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&target_root);
        }
        result
    }
}

fn verify_local_device_access(
    bootstrap: &SyncVaultBootstrap,
    validated: &ValidatedBootstrap,
    device: &DeviceKeyMaterial,
) -> ReplicationResult<()> {
    let identity = validated.identities.get(device.device_id()).ok_or_else(|| {
        ReplicationError::Invalid(format!(
            "Device {} has not been approved for Vault {}",
            device.device_id(), validated.vault.vault_id
        ))
    })?;
    let local = device.enrollment();
    if identity.signing_public_key != local.signing_public_key
        || identity.wrapping_recipient != local.wrapping_recipient
    {
        return Err(ReplicationError::Invalid(format!(
            "approved Device {} does not match this installation's private keys",
            device.device_id()
        )));
    }

    let external = bootstrap
        .generation_envelopes
        .iter()
        .filter(|envelope| envelope.device_id == device.device_id())
        .map(|envelope| ((envelope.device_id.as_str(), envelope.generation), envelope))
        .collect::<BTreeMap<_, _>>();
    for (generation, document) in &validated.generations {
        let ciphertext = match document.envelopes.get(device.device_id()) {
            Some(encoded) => vault::decode("Vault key envelope", encoded)?,
            None => {
                let envelope = external
                    .get(&(device.device_id(), *generation))
                    .ok_or_else(|| {
                        ReplicationError::Invalid(format!(
                            "Device {} has no envelope for key generation {generation}",
                            device.device_id()
                        ))
                    })?;
                decode_bounded(
                    &envelope.ciphertext_base64,
                    "generation envelope",
                    MAX_DESCRIPTOR_BYTES as usize,
                )?
            }
        };
        let plaintext = vault::decrypt_with_identity(device.wrapping_identity(), &ciphertext)?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| {
            ReplicationError::Invalid(format!(
                "generation {generation} envelope is not text"
            ))
        })?;
        let generation_identity = x25519::Identity::from_str(text.trim()).map_err(|error| {
            ReplicationError::Invalid(format!(
                "parse generation {generation} identity: {error}"
            ))
        })?;
        if generation_identity.to_public().to_string() != document.generation_public {
            return Err(ReplicationError::Invalid(format!(
                "generation {generation} envelope does not match its signed public key"
            )));
        }
    }
    Ok(())
}

fn materialize_lifecycle(
    bootstrap: &SyncVaultBootstrap,
    target: &std::path::Path,
) -> ReplicationResult<()> {
    let layout = vault::SharedLayout::new(target);
    vault::ensure_private_directory(layout.root())?;
    vault::ensure_private_directory(&layout.objects_dir())?;
    vault::ensure_private_directory(&layout.devices_dir())?;
    vault::ensure_private_directory(&layout.generations_dir())?;
    vault::ensure_private_directory(&layout.operations_dir())?;
    vault::ensure_private_directory(&layout.checkpoints_dir())?;

    publish_json_immutable(
        &layout.vault_json(),
        &decode_bounded(
            &bootstrap.vault_document_base64,
            "Vault bootstrap document",
            MAX_DESCRIPTOR_BYTES as usize,
        )?,
    )?;
    for routed in &bootstrap.device_identities {
        vault::ensure_private_directory(&layout.device_dir(&routed.route))?;
        publish_json_immutable(
            &layout.device_identity(&routed.route),
            &decode_bounded(
                &routed.document_base64,
                "Device identity",
                MAX_DESCRIPTOR_BYTES as usize,
            )?,
        )?;
    }
    for routed in &bootstrap.enrollment_requests {
        vault::ensure_private_directory(&layout.device_dir(&routed.route))?;
        publish_json_immutable(
            &layout.enrollment_request(&routed.route),
            &decode_bounded(
                &routed.document_base64,
                "enrollment request",
                MAX_DESCRIPTOR_BYTES as usize,
            )?,
        )?;
    }

    // External envelopes must be visible before their generation document. A concurrent reader
    // therefore observes either the old complete chain or the new complete chain.
    for envelope in &bootstrap.generation_envelopes {
        vault::ensure_private_directory(&layout.envelopes_dir(&envelope.device_id))?;
        vault::publish_immutable(
            &layout.envelope(&envelope.device_id, envelope.generation),
            &decode_bounded(
                &envelope.ciphertext_base64,
                "generation envelope",
                MAX_DESCRIPTOR_BYTES as usize,
            )?,
        )?;
    }
    for routed in &bootstrap.key_generations {
        let generation = routed.route.parse::<u32>().map_err(|_| {
            ReplicationError::Invalid(format!(
                "key generation route {} is not an integer",
                routed.route
            ))
        })?;
        publish_json_immutable(
            &layout.generation_document(generation),
            &decode_bounded(
                &routed.document_base64,
                "key generation",
                MAX_DESCRIPTOR_BYTES as usize,
            )?,
        )?;
    }
    Ok(())
}

/// Publish signed JSON create-only while tolerating insignificant serialization differences.
/// Ciphertext and encrypted envelopes continue to use byte identity; only JSON whitespace and
/// object-key order are normalized here, after the complete bootstrap has already been verified.
fn publish_json_immutable(path: &Path, candidate: &[u8]) -> ReplicationResult<()> {
    let existing = match vault::read_untrusted_file(path, MAX_DESCRIPTOR_BYTES) {
        Ok(existing) => existing,
        Err(floria_store::StoreError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound =>
        {
            return vault::publish_immutable(path, candidate).map_err(Into::into);
        }
        Err(error) => return Err(error.into()),
    };
    let existing_value = serde_json::from_slice::<serde_json::Value>(&existing).map_err(|error| {
        ReplicationError::Invalid(format!(
            "existing signed document {} is invalid JSON: {error}",
            path.display()
        ))
    })?;
    let candidate_value =
        serde_json::from_slice::<serde_json::Value>(candidate).map_err(|error| {
            ReplicationError::Invalid(format!(
                "candidate signed document {} is invalid JSON: {error}",
                path.display()
            ))
        })?;
    if existing_value != candidate_value {
        return Err(ReplicationError::Invalid(format!(
            "signed document collision at {}",
            path.display()
        )));
    }
    Ok(())
}

fn enrollment_request_transport(
    request: &EnrollmentRequestDocument,
) -> ReplicationResult<SyncEnrollmentRequest> {
    Ok(SyncEnrollmentRequest {
        device_id: request.device_id.clone(),
        device_name: request.device_name.clone(),
        requested_at: request.requested_at.clone(),
        fingerprint: request.fingerprint(),
        document_base64: encode_json(request)?,
    })
}

fn decode_generations(
    documents: &[SyncBootstrapDocument],
    vault: &vault::VaultDocument,
) -> ReplicationResult<BTreeMap<u32, KeyGenerationDocument>> {
    let mut generations = BTreeMap::new();
    for routed in documents {
        let document: KeyGenerationDocument =
            decode_json(&routed.document_base64, "key generation")?;
        vault::validate_key_generation(&document, vault)?;
        if routed.route != document.generation.to_string() {
            return Err(ReplicationError::Invalid(format!(
                "key generation route {} does not match signed generation {}",
                routed.route, document.generation
            )));
        }
        if generations.insert(document.generation, document).is_some() {
            return Err(ReplicationError::Invalid(format!(
                "key generation route {} appears more than once",
                routed.route
            )));
        }
    }
    if generations.is_empty() {
        return Err(ReplicationError::Invalid(
            "Vault bootstrap has no key generation".to_string(),
        ));
    }
    for (index, (generation, document)) in generations.iter().enumerate() {
        let expected = u32::try_from(index + 1)
            .map_err(|_| ReplicationError::Invalid("key generation overflow".to_string()))?;
        if *generation != expected
            || document.previous_generation
                != generation.checked_sub(1).filter(|previous| *previous > 0)
        {
            return Err(ReplicationError::Invalid(format!(
                "Vault bootstrap key-generation history has a gap before {generation}"
            )));
        }
    }
    Ok(generations)
}

fn decode_routed_documents<T>(
    documents: &[SyncBootstrapDocument],
    label: &str,
    route: impl Fn(&T) -> &str,
    validate: impl Fn(&T) -> floria_store::StoreResult<()>,
) -> ReplicationResult<BTreeMap<String, T>>
where
    T: DeserializeOwned,
{
    let mut decoded = BTreeMap::new();
    for routed in documents {
        let document: T = decode_json(&routed.document_base64, label)?;
        validate(&document)?;
        let signed_route = route(&document);
        if routed.route != signed_route {
            return Err(ReplicationError::Invalid(format!(
                "{label} route {} does not match signed route {signed_route}",
                routed.route
            )));
        }
        if decoded.insert(routed.route.clone(), document).is_some() {
            return Err(ReplicationError::Invalid(format!(
                "{label} route {} appears more than once",
                routed.route
            )));
        }
    }
    Ok(decoded)
}

fn opaque_document<T: Serialize>(
    route: impl Into<String>,
    document: &T,
) -> ReplicationResult<SyncBootstrapDocument> {
    Ok(SyncBootstrapDocument {
        route: route.into(),
        document_base64: encode_json(document)?,
    })
}

fn encode_json<T: Serialize>(document: &T) -> ReplicationResult<String> {
    let bytes = serde_json::to_vec(document)?;
    if bytes.len() > MAX_DESCRIPTOR_BYTES as usize {
        return Err(ReplicationError::Invalid(format!(
            "Vault bootstrap document exceeds the {MAX_DESCRIPTOR_BYTES} byte format limit"
        )));
    }
    Ok(BASE64.encode(bytes))
}

fn decode_json<T: DeserializeOwned>(encoded: &str, label: &str) -> ReplicationResult<T> {
    let bytes = decode_bounded(encoded, label, MAX_DESCRIPTOR_BYTES as usize)?;
    serde_json::from_slice(&bytes).map_err(ReplicationError::from)
}

fn decode_bounded(encoded: &str, label: &str, maximum: usize) -> ReplicationResult<Vec<u8>> {
    let maximum_encoded = maximum.saturating_add(2) / 3 * 4;
    if encoded.len() > maximum_encoded {
        return Err(ReplicationError::Invalid(format!(
            "{label} exceeds the {maximum} byte format limit"
        )));
    }
    let decoded = BASE64
        .decode(encoded)
        .map_err(|error| ReplicationError::Invalid(format!("invalid {label} Base64: {error}")))?;
    if decoded.len() > maximum {
        return Err(ReplicationError::Invalid(format!(
            "{label} exceeds the {maximum} byte format limit"
        )));
    }
    Ok(decoded)
}

fn require_count(label: &str, count: usize, maximum: usize) -> ReplicationResult<()> {
    if count > maximum {
        return Err(ReplicationError::Invalid(format!(
            "Vault bootstrap contains {count} {label}, maximum is {maximum}"
        )));
    }
    Ok(())
}

fn replication_io(path: impl Into<std::path::PathBuf>, source: io::Error) -> ReplicationError {
    ReplicationError::Io { path: path.into(), source }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use age::secrecy::ExposeSecret;
    use age::x25519;
    use floria_store::{KeyProvider, NewSecret, SecretStore, StoreResult};

    use super::*;

    struct LocalKeys(x25519::Identity);

    impl KeyProvider for LocalKeys {
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.0.to_public())])
        }

        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    fn store(directory: &tempfile::TempDir) -> Arc<AgeDirStore> {
        Arc::new(
            AgeDirStore::open(
                directory.path().join("store"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        )
    }

    fn approved_bootstrap(
        genesis: &Arc<AgeDirStore>,
        joining: &Arc<AgeDirStore>,
    ) -> SyncVaultBootstrap {
        let mut bootstrap = SyncVaultBootstrap::capture(genesis).unwrap();
        let SyncEnrollmentPreparation::Request(request) = bootstrap
            .prepare_enrollment(
                &joining.device(),
                Some("Joining Mac".to_string()),
                "2026-08-08T00:00:00Z",
            )
            .unwrap()
        else {
            panic!("joining Device unexpectedly enrolled")
        };
        bootstrap.enrollment_requests.push(SyncBootstrapDocument {
            route: request.device_id.clone(),
            document_base64: request.document_base64.clone(),
        });
        bootstrap
            .approve_enrollment(
                Arc::clone(genesis),
                joining.device().device_id(),
                request.fingerprint(),
            )
            .unwrap()
    }

    #[test]
    fn captures_and_validates_a_genesis_vault_without_plaintext_keys() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(&directory);
        let snapshot = SyncVaultBootstrap::capture(&store).unwrap();

        assert_eq!(snapshot.vault_id(), store.vault_document().vault_id);
        assert_eq!(snapshot.device_identities().len(), 1);
        assert_eq!(snapshot.key_generations().len(), 1);
        assert!(snapshot.enrollment_requests().is_empty());
        assert!(snapshot.generation_envelopes().is_empty());
        snapshot.validate_for_vault(snapshot.vault_id()).unwrap();
        assert!(!snapshot.vault_document_base64().contains("AGE-SECRET-KEY"));
    }

    #[test]
    fn rejects_a_zone_route_that_does_not_match_the_signed_vault() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(&directory);
        let snapshot = SyncVaultBootstrap::capture(&store).unwrap();

        assert!(snapshot
            .validate_for_vault(&uuid::Uuid::new_v4().to_string())
            .unwrap_err()
            .to_string()
            .contains("selected Vault"));
    }

    #[test]
    fn includes_late_enrollment_identity_and_historical_generation_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(&directory);
        let mut package = crate::ReplicationPackage::for_store(Arc::clone(&store)).unwrap();
        let joining = floria_store::DeviceKeyMaterial::generate().unwrap();
        package.enroll_device(joining.enrollment()).unwrap();

        let snapshot = SyncVaultBootstrap::capture(&store).unwrap();

        assert_eq!(snapshot.device_identities().len(), 2);
        assert_eq!(snapshot.generation_envelopes().len(), 1);
        assert_eq!(snapshot.generation_envelopes()[0].device_id(), joining.device_id());
        assert_eq!(snapshot.generation_envelopes()[0].generation(), 1);
        snapshot.validate_for_vault(snapshot.vault_id()).unwrap();
    }

    #[test]
    fn rejects_tampered_signed_material_and_outer_routes() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(&directory);
        let snapshot = SyncVaultBootstrap::capture(&store).unwrap();
        let mut value = serde_json::to_value(&snapshot).unwrap();
        value["device_identities"][0]["route"] =
            serde_json::Value::String(uuid::Uuid::new_v4().to_string());
        let rerouted: SyncVaultBootstrap = serde_json::from_value(value).unwrap();
        assert!(rerouted
            .validate_for_vault(snapshot.vault_id())
            .unwrap_err()
            .to_string()
            .contains("does not match signed route"));

        let mut bytes = BASE64.decode(snapshot.vault_document_base64()).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 1;
        let mut tampered = snapshot.clone();
        tampered.vault_document_base64 = BASE64.encode(bytes);
        assert!(tampered.validate_for_vault(snapshot.vault_id()).is_err());
    }

    #[test]
    fn rejects_a_snapshot_that_cannot_fit_one_control_frame() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(&directory);
        let mut snapshot = SyncVaultBootstrap::capture(&store).unwrap();
        snapshot.vault_document_base64 = "A".repeat(MAX_BOOTSTRAP_WIRE_BYTES);

        assert!(snapshot
            .validate_for_vault(snapshot.vault_id())
            .unwrap_err()
            .to_string()
            .contains("maximum"));
    }

    #[test]
    fn enrollment_request_is_replayed_and_hidden_after_identity_arrives() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = store(&directory);
        let mut snapshot = SyncVaultBootstrap::capture(&genesis).unwrap();
        let joining = DeviceKeyMaterial::generate().unwrap();

        let prepared = snapshot
            .prepare_enrollment(
                &joining,
                Some("Joining Mac".to_string()),
                "2026-08-08T00:00:00Z",
            )
            .unwrap();
        let SyncEnrollmentPreparation::Request(request) = prepared else {
            panic!("new Device unexpectedly enrolled")
        };
        snapshot.enrollment_requests.push(SyncBootstrapDocument {
            route: request.device_id.clone(),
            document_base64: request.document_base64.clone(),
        });
        snapshot.validate_for_vault(snapshot.vault_id()).unwrap();

        let replayed = snapshot
            .prepare_enrollment(
                &joining,
                Some("Renamed Mac".to_string()),
                "2026-08-09T00:00:00Z",
            )
            .unwrap();
        let SyncEnrollmentPreparation::Request(replayed) = replayed else {
            panic!("pending Device unexpectedly enrolled")
        };
        assert_eq!(replayed.document_base64, request.document_base64);
        assert_eq!(replayed.requested_at, "2026-08-08T00:00:00Z");
        assert_eq!(snapshot.review_enrollments().unwrap().len(), 1);

        let approved = snapshot
            .approve_enrollment(
                Arc::clone(&genesis),
                joining.device_id(),
                request.fingerprint(),
            )
            .unwrap();
        assert_eq!(approved.device_identities().len(), 2);
        assert_eq!(approved.generation_envelopes().len(), 1);
        assert!(approved.review_enrollments().unwrap().is_empty());
        assert_eq!(
            approved
                .prepare_enrollment(&joining, None, "2026-08-10T00:00:00Z")
                .unwrap(),
            SyncEnrollmentPreparation::AlreadyEnrolled {
                device_id: joining.device_id().to_string(),
            }
        );
    }

    #[test]
    fn approval_requires_the_exact_reviewed_fingerprint_and_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = store(&directory);
        let mut snapshot = SyncVaultBootstrap::capture(&genesis).unwrap();
        let joining = DeviceKeyMaterial::generate().unwrap();
        let SyncEnrollmentPreparation::Request(request) = snapshot
            .prepare_enrollment(&joining, None, "2026-08-08T00:00:00Z")
            .unwrap()
        else {
            panic!("new Device unexpectedly enrolled")
        };
        snapshot.enrollment_requests.push(SyncBootstrapDocument {
            route: request.device_id.clone(),
            document_base64: request.document_base64.clone(),
        });

        assert!(snapshot
            .approve_enrollment(Arc::clone(&genesis), joining.device_id(), "00-00-00-00-00-00")
            .unwrap_err()
            .to_string()
            .contains("fingerprint changed"));
        assert_eq!(
            SyncVaultBootstrap::capture(&genesis)
                .unwrap()
                .device_identities()
                .len(),
            1
        );

        let first = snapshot
            .approve_enrollment(
                Arc::clone(&genesis),
                joining.device_id(),
                request.fingerprint(),
            )
            .unwrap();
        let second = snapshot
            .approve_enrollment(
                Arc::clone(&genesis),
                joining.device_id(),
                request.fingerprint(),
            )
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn device_review_is_authenticated_and_marks_the_current_mac() {
        let genesis_directory = tempfile::tempdir().unwrap();
        let joining_directory = tempfile::tempdir().unwrap();
        let genesis = store(&genesis_directory);
        let joining = store(&joining_directory);
        let approved = approved_bootstrap(&genesis, &joining);

        let devices = approved.review_devices(genesis.device().device_id()).unwrap();

        assert_eq!(devices.len(), 2);
        assert!(devices[0].is_current());
        assert!(devices[0].is_genesis());
        assert_eq!(devices[1].device_id(), joining.device().device_id());
        assert_eq!(devices[1].revoked_generation(), None);
    }

    #[test]
    fn revocation_requires_the_reviewed_fingerprint_and_rotates_the_generation() {
        let genesis_directory = tempfile::tempdir().unwrap();
        let joining_directory = tempfile::tempdir().unwrap();
        let genesis = store(&genesis_directory);
        let joining = store(&joining_directory);
        let approved = approved_bootstrap(&genesis, &joining);
        let target = approved
            .review_devices(genesis.device().device_id())
            .unwrap()
            .into_iter()
            .find(|device| device.device_id() == joining.device().device_id())
            .unwrap();

        let mismatched = approved
            .revoke_device(
                Arc::clone(&genesis),
                target.device_id(),
                "00-00-00-00-00-00",
            )
            .unwrap_err();
        assert!(
            mismatched.to_string().contains("fingerprint changed"),
            "unexpected revocation error: {mismatched}"
        );
        assert_eq!(genesis.current_generation().unwrap(), 1);

        let revoked = approved
            .revoke_device(
                Arc::clone(&genesis),
                target.device_id(),
                target.fingerprint(),
            )
            .unwrap();
        assert_eq!(genesis.current_generation().unwrap(), 2);
        let removed = revoked
            .review_devices(genesis.device().device_id())
            .unwrap()
            .into_iter()
            .find(|device| device.device_id() == joining.device().device_id())
            .unwrap();
        assert_eq!(removed.revoked_generation(), Some(2));
        assert!(revoked
            .generation_envelopes()
            .iter()
            .all(|envelope| {
                envelope.device_id() != joining.device().device_id()
                    || envelope.generation() != 2
            }));
        assert!(revoked
            .activate(Arc::clone(&joining), 0)
            .unwrap_err()
            .to_string()
            .contains("has no envelope"));
    }

    #[test]
    fn removed_mac_rotates_to_a_fresh_identity_and_keeps_old_generations_readable() {
        let genesis_directory = tempfile::tempdir().unwrap();
        let joining_directory = tempfile::tempdir().unwrap();
        let genesis = store(&genesis_directory);
        let joining = store(&joining_directory);
        let approved = approved_bootstrap(&genesis, &joining);
        approved.activate(Arc::clone(&joining), 0).unwrap();
        let target = approved
            .review_devices(genesis.device().device_id())
            .unwrap()
            .into_iter()
            .find(|device| device.device_id() == joining.device().device_id())
            .unwrap();
        let previous_device_id = joining.device().device_id().to_string();
        let generation_public = joining
            .generation_identity(1)
            .unwrap()
            .to_public()
            .to_string();

        let healthy = approved
            .prepare_reenrollment(
                Arc::clone(&joining),
                target.fingerprint(),
                Some("Joining Mac".to_string()),
                "2026-08-09T00:00:00Z",
            )
            .unwrap_err();
        assert!(healthy.to_string().contains("has not been removed"));
        assert_eq!(joining.device().device_id(), previous_device_id);

        let revoked = approved
            .revoke_device(
                Arc::clone(&genesis),
                target.device_id(),
                target.fingerprint(),
            )
            .unwrap();
        let mismatched = revoked
            .prepare_reenrollment(
                Arc::clone(&joining),
                "00-00-00-00-00-00",
                Some("Joining Mac".to_string()),
                "2026-08-09T00:00:00Z",
            )
            .unwrap_err();
        assert!(mismatched.to_string().contains("fingerprint changed"));
        assert_eq!(joining.device().device_id(), previous_device_id);

        let SyncEnrollmentPreparation::Request(request) = revoked
            .prepare_reenrollment(
                Arc::clone(&joining),
                target.fingerprint(),
                Some("Joining Mac".to_string()),
                "2026-08-09T00:00:00Z",
            )
            .unwrap()
        else {
            panic!("removed Device unexpectedly remained enrolled")
        };
        assert_ne!(request.device_id(), previous_device_id);
        assert_eq!(joining.device().device_id(), request.device_id());
        assert_eq!(
            joining.generation_identity(1).unwrap().to_public().to_string(),
            generation_public
        );
    }

    #[test]
    fn only_the_genesis_mac_can_revoke_another_device() {
        let genesis_directory = tempfile::tempdir().unwrap();
        let joining_directory = tempfile::tempdir().unwrap();
        let genesis = store(&genesis_directory);
        let joining = store(&joining_directory);
        let approved = approved_bootstrap(&genesis, &joining);
        approved.activate(Arc::clone(&joining), 0).unwrap();
        let genesis_device = approved
            .review_devices(joining.device().device_id())
            .unwrap()
            .into_iter()
            .find(|device| device.is_genesis())
            .unwrap();

        assert!(approved
            .revoke_device(
                Arc::clone(&joining),
                genesis_device.device_id(),
                genesis_device.fingerprint(),
            )
            .unwrap_err()
            .to_string()
            .contains("only the first Mac"));
        assert_eq!(joining.current_generation().unwrap(), 1);
    }

    #[test]
    fn activates_an_approved_vault_and_preserves_the_previous_shared_half() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Arc::new(
            AgeDirStore::open(
                directory.path().join("genesis"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let joining = Arc::new(
            AgeDirStore::open(
                directory.path().join("joining"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let previous_shared = joining.shared_root();
        let previous_vault_id = joining.vault_document().vault_id;
        let approved = approved_bootstrap(&genesis, &joining);

        let result = approved.activate(Arc::clone(&joining), 0).unwrap();

        assert_eq!(
            result,
            SyncVaultActivation::Ready {
                vault_id: genesis.vault_document().vault_id.clone(),
                key_generation: 1,
                restart_required: true,
            }
        );
        assert_eq!(joining.vault_document().vault_id, genesis.vault_document().vault_id);
        assert_ne!(joining.shared_root(), previous_shared);
        assert_eq!(
            joining.preserved_default_vault_id().unwrap().as_deref(),
            Some(previous_vault_id.as_str())
        );
        assert_eq!(
            vault::read_vault(&vault::SharedLayout::new(&previous_shared))
                .unwrap()
                .vault_id,
            previous_vault_id,
            "activation must retain the previous Vault as rollback evidence"
        );
        assert_eq!(
            joining.generation_identity(1).unwrap().to_public().to_string(),
            genesis.generation_identity(1).unwrap().to_public().to_string()
        );

        assert_eq!(
            approved.activate(Arc::clone(&joining), 0).unwrap(),
            SyncVaultActivation::Ready {
                vault_id: genesis.vault_document().vault_id,
                key_generation: 1,
                restart_required: false,
            }
        );
    }

    #[test]
    fn populated_different_vault_requires_merge_without_changing_the_store() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Arc::new(
            AgeDirStore::open(
                directory.path().join("genesis"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let joining = Arc::new(
            AgeDirStore::open(
                directory.path().join("joining"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        joining
            .put(NewSecret::managed("Local item"), b"fixture payload")
            .unwrap();
        let current_vault_id = joining.vault_document().vault_id;
        let current_shared = joining.shared_root();
        let approved = approved_bootstrap(&genesis, &joining);

        assert_eq!(
            approved.activate(Arc::clone(&joining), 1).unwrap(),
            SyncVaultActivation::MergeRequired {
                current_vault_id: current_vault_id.clone(),
                target_vault_id: genesis.vault_document().vault_id,
                local_items: 1,
            }
        );
        assert_eq!(joining.vault_document().vault_id, current_vault_id);
        assert_eq!(joining.shared_root(), current_shared);
        assert!(!joining.root().join("cloudkit-vaults").exists());
    }

    #[test]
    fn prepares_and_verifies_a_populated_store_without_changing_the_live_vault() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Arc::new(
            AgeDirStore::open(
                directory.path().join("genesis"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let joining = Arc::new(
            AgeDirStore::open(
                directory.path().join("joining"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let id = joining
            .put(NewSecret::managed("Local item"), b"first fixture")
            .unwrap();
        joining.append_version(&id, b"second fixture").unwrap();
        joining.set_head(&id, 1).unwrap();
        let source_versions = joining.version_refs(&id).unwrap();
        let current_vault_id = joining.vault_document().vault_id;
        let approved = approved_bootstrap(&genesis, &joining);
        let staging = directory.path().join("merge-staging");

        {
            let prepared = approved
                .prepare_merge(Arc::clone(&joining), staging.clone())
                .unwrap();

            assert_eq!(prepared.vault_id(), genesis.vault_document().vault_id);
            assert_eq!(prepared.verification().secrets, 1);
            assert_eq!(prepared.verification().versions, 2);
            assert_eq!(prepared.store().get(&id).unwrap().as_slice(), b"first fixture");
            let target_versions = prepared.store().version_refs(&id).unwrap();
            assert_eq!(
                target_versions
                    .iter()
                    .map(|version| &version.version_uuid)
                    .collect::<Vec<_>>(),
                source_versions
                    .iter()
                    .map(|version| &version.version_uuid)
                    .collect::<Vec<_>>()
            );
            assert!(target_versions
                .iter()
                .zip(&source_versions)
                .all(|(target, source)| target.digest != source.digest));
            assert_eq!(joining.vault_document().vault_id, current_vault_id);
            assert_eq!(joining.get(&id).unwrap().as_slice(), b"first fixture");
            assert!(staging.is_dir());
        }

        assert!(!staging.exists(), "dropping a prepared merge must remove staging");
    }

    #[test]
    fn rejects_an_envelope_that_does_not_match_the_signed_generation_key() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = Arc::new(
            AgeDirStore::open(
                directory.path().join("genesis"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let joining = Arc::new(
            AgeDirStore::open(
                directory.path().join("joining"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let mut approved = approved_bootstrap(&genesis, &joining);
        let wrong = x25519::Identity::generate();
        let ciphertext = vault::encrypt_to_recipient(
            &joining.device().wrapping_identity().to_public(),
            wrong.to_string().expose_secret().as_bytes(),
        )
        .unwrap();
        let envelope = approved
            .generation_envelopes
            .iter_mut()
            .find(|envelope| envelope.device_id == joining.device().device_id())
            .unwrap();
        envelope.ciphertext_base64 = BASE64.encode(ciphertext);

        let error = approved.activate(Arc::clone(&joining), 0).unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match its signed public key"));
        assert_ne!(joining.vault_document().vault_id, genesis.vault_document().vault_id);
    }
}
