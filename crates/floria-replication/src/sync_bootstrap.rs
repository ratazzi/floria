//! Authenticated Vault control material for transport bootstrap.
//!
//! A platform adapter moves these payloads as opaque bytes. Rust owns their routes, bounds,
//! signature validation, generation-chain validation, and create-only identity. This module does
//! not activate a downloaded Vault or replace the local Store; activation is a separate recovery
//! transaction so a partial bootstrap can never destroy the working Vault.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use floria_store::vault::{
    self, DeviceDocument, EnrollmentRequestDocument, KeyGenerationDocument, MAX_DESCRIPTOR_BYTES,
};
use floria_store::AgeDirStore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{ReplicationError, ReplicationResult};

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
        Ok(())
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

    use age::x25519;
    use floria_store::{KeyProvider, StoreResult};

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
}
