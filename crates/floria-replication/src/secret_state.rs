//! Portable current state for one encrypted Secret.
//!
//! Secret content is its own logical entity rather than part of a catalog Resource: one Secret
//! may be reused by several Resources, and a byte-preserving Managed File may not have a Resource
//! at all. Placement and display metadata remain separate entity concerns.

use std::str::FromStr;

use floria_store::{AgeDirStore, SecretId};
use serde::{Deserialize, Serialize};

use crate::entity_document::EntityLifecycle;
use crate::record::ImmutableObjectRef;
use crate::{ReplicationError, ReplicationResult};

const SECRET_STATE_FORMAT_VERSION: u32 = 1;

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
        let document = Self {
            format_version: SECRET_STATE_FORMAT_VERSION,
            entity_id: id.to_string(),
            lifecycle,
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
        self.head.validate()
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(document.head().object().digest().len(), 64);
        assert!(!document
            .encode()
            .unwrap()
            .windows("private fixture".len())
            .any(|window| window == b"private fixture"));
    }
}
