//! Authenticated encryption boundary for transport-neutral records.
//!
//! Age authenticates ciphertext but cannot authenticate the clear routing metadata beside it.
//! Every encrypted payload therefore repeats and binds that metadata. Opening a record succeeds
//! only when the decrypted binding exactly matches the outer envelope.

use std::sync::Arc;

use floria_store::AgeDirStore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use crate::entity_document::ReplicatedEntityDocument;
use crate::record::{EntityRevision, ImmutableObjectRef, RevisionCommit, RECORD_FORMAT_VERSION};
use crate::{ReplicationError, ReplicationResult};

const BINDING_FORMAT_VERSION: u32 = 1;

/// Encrypts and verifies records using the Vault's signed key-generation chain.
pub struct RecordCryptor {
    store: Arc<AgeDirStore>,
}

impl RecordCryptor {
    pub fn new(store: Arc<AgeDirStore>) -> Self {
        Self { store }
    }

    /// Seal one complete entity document. Its type tag stays encrypted and its reachable objects
    /// are derived from the document rather than supplied independently by the caller.
    pub fn seal_entity_revision(
        &self,
        document: &ReplicatedEntityDocument,
        revision_id: impl Into<String>,
        commit_id: impl Into<String>,
        parents: Vec<String>,
    ) -> ReplicationResult<EntityRevision> {
        document.validate()?;
        let state = Zeroizing::new(serde_json::to_vec(document)?);
        self.seal_revision(
            document.entity_id(),
            revision_id,
            commit_id,
            parents,
            &state,
            document.object_refs(),
        )
    }

    /// Open, type-dispatch, and validate one complete entity document. A state cannot be
    /// transplanted into another entity or attached to a different reachable object set.
    pub fn open_entity_revision(
        &self,
        revision: &EntityRevision,
    ) -> ReplicationResult<ReplicatedEntityDocument> {
        let state = self.open_revision(revision)?;
        let document: ReplicatedEntityDocument = serde_json::from_slice(&state)?;
        document.validate()?;
        if document.entity_id() != revision.entity_id()
            || revision.object_refs() != document.object_refs()
        {
            return Err(ReplicationError::Invalid(format!(
                "entity {} does not match revision {} metadata",
                document.entity_id(),
                revision.revision_id()
            )));
        }
        Ok(document)
    }

    pub fn seal_revision(
        &self,
        entity_id: impl Into<String>,
        revision_id: impl Into<String>,
        commit_id: impl Into<String>,
        parents: Vec<String>,
        state: &[u8],
        object_refs: Vec<ImmutableObjectRef>,
    ) -> ReplicationResult<EntityRevision> {
        if state.is_empty() {
            return Err(ReplicationError::Invalid(
                "entity revision state cannot be empty".to_string(),
            ));
        }
        let entity_id = entity_id.into();
        let revision_id = revision_id.into();
        let commit_id = commit_id.into();
        let vault_id = self.store.vault_document().vault_id;
        let (key_generation, recipients) = self.store.current_generation_recipients()?;
        let template = canonical_revision(
            entity_id,
            revision_id,
            commit_id,
            key_generation,
            parents,
            vec![0],
            object_refs,
        )?;
        let binding = RevisionBinding {
            binding_format_version: BINDING_FORMAT_VERSION,
            record_format_version: template.format_version(),
            vault_id,
            entity_id: template.entity_id().to_string(),
            revision_id: template.revision_id().to_string(),
            commit_id: template.commit_id().to_string(),
            key_generation,
            parents: template.parents().to_vec(),
            object_refs: template.object_refs().to_vec(),
            state: SensitiveBytes::new(state.to_vec()),
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&binding)?);
        let ciphertext = super::encrypt(recipients, &plaintext)?;
        canonical_revision(
            binding.entity_id,
            binding.revision_id,
            binding.commit_id,
            key_generation,
            binding.parents,
            ciphertext,
            binding.object_refs,
        )
    }

    pub fn open_revision(
        &self,
        revision: &EntityRevision,
    ) -> ReplicationResult<Zeroizing<Vec<u8>>> {
        let identity = self.store.generation_identity(revision.key_generation())?;
        let plaintext = super::decrypt(&identity, revision.ciphertext())?;
        let binding: RevisionBinding = serde_json::from_slice(&plaintext)?;
        binding.verify(&self.store.vault_document().vault_id, revision)?;
        Ok(binding.state.into_inner())
    }

    pub fn seal_commit(
        &self,
        commit_id: impl Into<String>,
        revision_ids: Vec<String>,
    ) -> ReplicationResult<RevisionCommit> {
        let commit_id = commit_id.into();
        let vault_id = self.store.vault_document().vault_id;
        let (key_generation, recipients) = self.store.current_generation_recipients()?;
        let template = canonical_commit(commit_id, key_generation, revision_ids, vec![0])?;
        let binding = CommitBinding {
            binding_format_version: BINDING_FORMAT_VERSION,
            record_format_version: template.format_version(),
            vault_id,
            commit_id: template.commit_id().to_string(),
            key_generation,
            revision_ids: template.revision_ids().to_vec(),
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&binding)?);
        let ciphertext = super::encrypt(recipients, &plaintext)?;
        canonical_commit(
            binding.commit_id,
            key_generation,
            binding.revision_ids,
            ciphertext,
        )
    }

    pub fn verify_commit(&self, commit: &RevisionCommit) -> ReplicationResult<()> {
        let identity = self.store.generation_identity(commit.key_generation())?;
        let plaintext = super::decrypt(&identity, commit.ciphertext())?;
        let binding: CommitBinding = serde_json::from_slice(&plaintext)?;
        binding.verify(&self.store.vault_document().vault_id, commit)
    }
}

#[derive(Serialize, Deserialize)]
struct RevisionBinding {
    binding_format_version: u32,
    record_format_version: u32,
    vault_id: String,
    entity_id: String,
    revision_id: String,
    commit_id: String,
    key_generation: u32,
    parents: Vec<String>,
    object_refs: Vec<ImmutableObjectRef>,
    state: SensitiveBytes,
}

impl RevisionBinding {
    fn verify(&self, vault_id: &str, outer: &EntityRevision) -> ReplicationResult<()> {
        if self.binding_format_version != BINDING_FORMAT_VERSION
            || self.record_format_version != RECORD_FORMAT_VERSION
            || self.vault_id != vault_id
            || self.entity_id != outer.entity_id()
            || self.revision_id != outer.revision_id()
            || self.commit_id != outer.commit_id()
            || self.key_generation != outer.key_generation()
            || self.parents != outer.parents()
            || self.object_refs != outer.object_refs()
        {
            return Err(ReplicationError::Invalid(format!(
                "entity revision {} does not match its encrypted binding",
                outer.revision_id()
            )));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct CommitBinding {
    binding_format_version: u32,
    record_format_version: u32,
    vault_id: String,
    commit_id: String,
    key_generation: u32,
    revision_ids: Vec<String>,
}

impl CommitBinding {
    fn verify(&self, vault_id: &str, outer: &RevisionCommit) -> ReplicationResult<()> {
        if self.binding_format_version != BINDING_FORMAT_VERSION
            || self.record_format_version != RECORD_FORMAT_VERSION
            || self.vault_id != vault_id
            || self.commit_id != outer.commit_id()
            || self.key_generation != outer.key_generation()
            || self.revision_ids != outer.revision_ids()
        {
            return Err(ReplicationError::Invalid(format!(
                "revision commit {} does not match its encrypted binding",
                outer.commit_id()
            )));
        }
        Ok(())
    }
}

struct SensitiveBytes(Zeroizing<Vec<u8>>);

impl SensitiveBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn into_inner(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl Serialize for SensitiveBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SensitiveBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer).map(Self::new)
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn canonical_revision(
    entity_id: String,
    revision_id: String,
    commit_id: String,
    key_generation: u32,
    parents: Vec<String>,
    ciphertext: Vec<u8>,
    object_refs: Vec<ImmutableObjectRef>,
) -> ReplicationResult<EntityRevision> {
    EntityRevision::new(
        entity_id,
        revision_id,
        commit_id,
        key_generation,
        parents,
        ciphertext,
        object_refs,
    )
    .map_err(|error| ReplicationError::Invalid(error.to_string()))
}

fn canonical_commit(
    commit_id: String,
    key_generation: u32,
    revision_ids: Vec<String>,
    ciphertext: Vec<u8>,
) -> ReplicationResult<RevisionCommit> {
    RevisionCommit::new(commit_id, key_generation, revision_ids, ciphertext)
        .map_err(|error| ReplicationError::Invalid(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519;
    use floria_catalog::ReplicatedProject;
    use floria_store::{KeyProvider, StoreResult};

    use crate::entity_document::EntityLifecycle;
    use crate::entity_state::{CatalogEntityDocument, CatalogEntityState};
    use crate::secret_state::SecretEntityDocument;

    struct LocalKeys(x25519::Identity);

    impl KeyProvider for LocalKeys {
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.0.to_public())])
        }

        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    fn id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn cryptor() -> (tempfile::TempDir, RecordCryptor) {
        let directory = tempfile::tempdir().unwrap();
        let keys = Arc::new(LocalKeys(x25519::Identity::generate()));
        let store = Arc::new(AgeDirStore::open(directory.path().join("store"), keys).unwrap());
        (directory, RecordCryptor::new(store))
    }

    #[test]
    fn revision_round_trip_binds_every_clear_metadata_field() {
        let (_directory, cryptor) = cryptor();
        let entity_id = id();
        let revision_id = id();
        let commit_id = id();
        let state = br#"{"name":"private fixture"}"#;
        let object = ImmutableObjectRef::new("ab".repeat(32), 41).unwrap();
        let revision = cryptor
            .seal_revision(
                &entity_id,
                &revision_id,
                &commit_id,
                Vec::new(),
                state,
                vec![object.clone()],
            )
            .unwrap();

        assert_eq!(cryptor.open_revision(&revision).unwrap().as_slice(), state);
        assert!(!revision
            .ciphertext()
            .windows("private fixture".len())
            .any(|window| window == b"private fixture"));

        let tampered = EntityRevision::new(
            id(),
            revision_id,
            commit_id,
            revision.key_generation(),
            Vec::new(),
            revision.ciphertext().to_vec(),
            vec![object],
        )
        .unwrap();
        assert!(cryptor
            .open_revision(&tampered)
            .unwrap_err()
            .to_string()
            .contains("does not match its encrypted binding"));
    }

    #[test]
    fn commit_round_trip_rejects_member_substitution() {
        let (_directory, cryptor) = cryptor();
        let commit = cryptor.seal_commit(id(), vec![id(), id()]).unwrap();
        cryptor.verify_commit(&commit).unwrap();

        let tampered = RevisionCommit::new(
            commit.commit_id(),
            commit.key_generation(),
            vec![id()],
            commit.ciphertext().to_vec(),
        )
        .unwrap();
        assert!(cryptor
            .verify_commit(&tampered)
            .unwrap_err()
            .to_string()
            .contains("does not match its encrypted binding"));
    }

    #[test]
    fn catalog_entity_round_trip_binds_state_identity_to_revision() {
        let (_directory, cryptor) = cryptor();
        let document = CatalogEntityDocument::active(CatalogEntityState::Project(
            ReplicatedProject {
                id: "project-11111111-1111-4111-8111-111111111111".to_string(),
                name: "Fixture".to_string(),
                default_environment_id: None,
            },
        ));
        let entity = ReplicatedEntityDocument::Catalog(document.clone());
        let revision = cryptor
            .seal_entity_revision(&entity, id(), id(), Vec::new())
            .unwrap();

        assert_eq!(cryptor.open_entity_revision(&revision).unwrap(), entity);
        assert_eq!(revision.entity_id(), document.entity_id());
    }

    #[test]
    fn secret_entity_round_trip_binds_the_reachable_object() {
        use floria_store::{NewSecret, SecretStore};

        let (_directory, cryptor) = cryptor();
        let store = cryptor.store.as_ref();
        let secret_id = store
            .put(NewSecret::managed("Fixture"), b"private fixture")
            .unwrap();
        let document = SecretEntityDocument::from_store(
            store,
            &secret_id,
            EntityLifecycle::Active,
        )
        .unwrap();
        let entity = ReplicatedEntityDocument::Secret(document.clone());
        let revision = cryptor
            .seal_entity_revision(&entity, id(), id(), Vec::new())
            .unwrap();

        assert_eq!(cryptor.open_entity_revision(&revision).unwrap(), entity);
        assert_eq!(revision.object_refs(), [document.head().object().clone()]);
    }
}
