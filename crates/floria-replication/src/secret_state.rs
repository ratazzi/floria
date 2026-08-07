//! Portable current state for one encrypted Secret.
//!
//! Secret content is its own logical entity rather than part of a catalog Resource: one Secret
//! may be reused by several Resources, and a byte-preserving Managed File may not have a Resource
//! at all. Its portable descriptor can rebuild a Library item, while source paths and placement
//! declarations remain separate concerns.

use std::str::FromStr;

use floria_core::authz::Enforcement;
use floria_core::metadata::ItemMetadata;
use floria_store::{AgeDirStore, SecretId, SecretOrigin, SecretRecord, SecretStore};
use serde::{Deserialize, Serialize};

use crate::entity_document::EntityLifecycle;
use crate::record::ImmutableObjectRef;
use crate::{ReplicationError, ReplicationResult};

const SECRET_STATE_FORMAT_VERSION: u32 = 2;
const MAX_PORTABLE_LABEL_BYTES: usize = 255;

/// Portable settings required to reconstruct a local Secret head document on a new Device.
///
/// Source paths and placements are deliberately absent. A new Device initially creates a
/// library item with this label; machine-local reconciliation attaches it to local paths later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretDescriptorState {
    label: String,
    mode: u32,
    enforcement: Enforcement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    environment_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "ItemMetadata::is_empty")]
    metadata: ItemMetadata,
}

impl SecretDescriptorState {
    fn from_record(record: &SecretRecord) -> Self {
        let label = match &record.origin {
            SecretOrigin::Managed { label } => label.clone(),
            SecretOrigin::File { source_path } => source_path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("Managed file")
                .to_string(),
        };
        let mut environment_ids = record.environment_ids.clone();
        if let Some(ids) = &mut environment_ids {
            ids.sort();
        }
        Self {
            label,
            mode: record.mode,
            enforcement: record.enforcement,
            environment_ids,
            metadata: record.metadata.clone(),
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn mode(&self) -> u32 {
        self.mode
    }

    pub fn enforcement(&self) -> Enforcement {
        self.enforcement
    }

    pub fn environment_ids(&self) -> Option<&[String]> {
        self.environment_ids.as_deref()
    }

    pub fn metadata(&self) -> &ItemMetadata {
        &self.metadata
    }

    pub(crate) fn validate(&self) -> ReplicationResult<()> {
        if self.label.trim().is_empty()
            || self.label.len() > MAX_PORTABLE_LABEL_BYTES
            || self.label.contains('\0')
        {
            return Err(ReplicationError::Invalid(format!(
                "secret descriptor label must be 1..={MAX_PORTABLE_LABEL_BYTES} bytes without NUL"
            )));
        }
        if self.mode & !0o777 != 0 {
            return Err(ReplicationError::Invalid(format!(
                "secret descriptor mode must contain only permission bits: {:o}",
                self.mode
            )));
        }
        if let Some(environment_ids) = &self.environment_ids {
            if environment_ids.is_empty() {
                return Err(ReplicationError::Invalid(
                    "secret descriptor environment scope must be omitted instead of empty"
                        .to_string(),
                ));
            }
            let mut previous = None;
            for environment_id in environment_ids {
                let raw = environment_id.strip_prefix("environment-").ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "secret descriptor environment id is invalid: {environment_id:?}"
                    ))
                })?;
                uuid::Uuid::parse_str(raw).map_err(|_| {
                    ReplicationError::Invalid(format!(
                        "secret descriptor environment id is invalid: {environment_id:?}"
                    ))
                })?;
                if previous.is_some_and(|value| value >= environment_id.as_str()) {
                    return Err(ReplicationError::Invalid(
                        "secret descriptor environment ids must be sorted and unique".to_string(),
                    ));
                }
                previous = Some(environment_id.as_str());
            }
        }
        self.metadata
            .validate()
            .map_err(ReplicationError::Invalid)
    }
}

/// Transport-stable identity of one immutable encrypted Secret version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretVersionState {
    version_id: String,
    key_generation: u32,
    plaintext_size: u64,
    object: ImmutableObjectRef,
}

impl SecretVersionState {
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }

    pub fn plaintext_size(&self) -> u64 {
        self.plaintext_size
    }

    pub fn object(&self) -> &ImmutableObjectRef {
        &self.object
    }

    pub(crate) fn validate(&self) -> ReplicationResult<()> {
        uuid::Uuid::parse_str(&self.version_id).map_err(|_| {
            ReplicationError::Invalid(format!(
                "secret version id is not a UUID: {:?}",
                self.version_id
            ))
        })?;
        if self.key_generation == 0 {
            return Err(ReplicationError::Invalid(
                "secret version key generation must start at 1".to_string(),
            ));
        }
        ImmutableObjectRef::new(self.object.digest(), self.object.ciphertext_size())
            .map_err(|error| ReplicationError::Invalid(error.to_string()))?;
        Ok(())
    }
}

/// Complete encrypted-head state carried by a Secret's Entity Revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretEntityDocument {
    format_version: u32,
    entity_id: String,
    lifecycle: EntityLifecycle,
    descriptor: SecretDescriptorState,
    head: SecretVersionState,
}

impl SecretEntityDocument {
    /// Snapshot the already-committed store head without reading or copying plaintext.
    pub fn from_store(
        store: &AgeDirStore,
        id: &SecretId,
        lifecycle: EntityLifecycle,
    ) -> ReplicationResult<Self> {
        let version = store.head_version_ref(id)?;
        let record = store.record(id)?.ok_or_else(|| {
            ReplicationError::Invalid(format!("secret {id} disappeared while snapshotting"))
        })?;
        let document = Self {
            format_version: SECRET_STATE_FORMAT_VERSION,
            entity_id: id.to_string(),
            lifecycle,
            descriptor: SecretDescriptorState::from_record(&record),
            head: SecretVersionState {
                version_id: version.version_uuid,
                key_generation: version.generation,
                plaintext_size: version.size,
                object: ImmutableObjectRef::new(version.digest, version.ciphertext_size)
                    .map_err(|error| ReplicationError::Invalid(error.to_string()))?,
            },
        };
        document.validate()?;
        Ok(document)
    }

    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    pub fn lifecycle(&self) -> EntityLifecycle {
        self.lifecycle
    }

    pub fn head(&self) -> &SecretVersionState {
        &self.head
    }

    pub fn descriptor(&self) -> &SecretDescriptorState {
        &self.descriptor
    }

    pub fn archived(mut self) -> Self {
        self.lifecycle = EntityLifecycle::Archived;
        self
    }

    pub fn restored(mut self) -> Self {
        self.lifecycle = EntityLifecycle::Active;
        self
    }

    pub fn encode(&self) -> ReplicationResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(ReplicationError::from)
    }

    pub fn decode(bytes: &[u8]) -> ReplicationResult<Self> {
        let document: Self = serde_json::from_slice(bytes)?;
        document.validate()?;
        Ok(document)
    }

    pub(crate) fn validate(&self) -> ReplicationResult<()> {
        if self.format_version != SECRET_STATE_FORMAT_VERSION {
            return Err(ReplicationError::Invalid(format!(
                "unsupported secret entity state format {}",
                self.format_version
            )));
        }
        let secret_id = SecretId::from_str(&self.entity_id)?;
        if secret_id.as_str() != self.entity_id {
            return Err(ReplicationError::Invalid(format!(
                "secret entity id is not canonical: {:?}",
                self.entity_id
            )));
        }
        self.descriptor.validate()?;
        self.head.validate()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

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

    #[test]
    fn store_head_becomes_one_content_entity_without_copying_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let store = AgeDirStore::open(
            directory.path().join("store"),
            Arc::new(LocalKeys(x25519::Identity::generate())),
        )
        .unwrap();
        let id = store
            .put(NewSecret::managed("Fixture"), b"private fixture")
            .unwrap();

        let document =
            SecretEntityDocument::from_store(&store, &id, EntityLifecycle::Active).unwrap();
        let decoded = SecretEntityDocument::decode(&document.encode().unwrap()).unwrap();

        assert_eq!(decoded, document);
        assert_eq!(document.entity_id(), id.as_str());
        assert_eq!(document.head().plaintext_size(), 15);
        assert_eq!(document.descriptor().label(), "Fixture");
        assert_eq!(document.descriptor().mode(), 0o600);
        assert_eq!(document.descriptor().enforcement(), Enforcement::Prompt);
        assert_eq!(document.head().object().digest().len(), 64);
        assert!(!document
            .encode()
            .unwrap()
            .windows("private fixture".len())
            .any(|window| window == b"private fixture"));
    }

    #[test]
    fn file_descriptor_keeps_portable_settings_but_never_the_source_path() {
        let directory = tempfile::tempdir().unwrap();
        let store = AgeDirStore::open(
            directory.path().join("store"),
            Arc::new(LocalKeys(x25519::Identity::generate())),
        )
        .unwrap();
        let id = store
            .put(
                NewSecret::file(
                    PathBuf::from("/Users/private/workspace/fixture/.env"),
                    0o640,
                ),
                b"private fixture",
            )
            .unwrap();
        let first_environment = "environment-11111111-1111-4111-8111-111111111111".to_string();
        let second_environment = "environment-22222222-2222-4222-8222-222222222222".to_string();
        store
            .update_settings(
                &id,
                ItemMetadata::default(),
                Enforcement::TouchId,
                Some(vec![second_environment.clone(), first_environment.clone()]),
            )
            .unwrap();

        let document =
            SecretEntityDocument::from_store(&store, &id, EntityLifecycle::Active).unwrap();
        let encoded = document.encode().unwrap();

        assert_eq!(document.descriptor().label(), ".env");
        assert_eq!(document.descriptor().mode(), 0o640);
        assert_eq!(document.descriptor().enforcement(), Enforcement::TouchId);
        assert_eq!(
            document.descriptor().environment_ids(),
            Some([first_environment, second_environment].as_slice())
        );
        assert!(!encoded
            .windows("/Users/private".len())
            .any(|window| window == b"/Users/private"));
    }
}
