//! Compile complete entity changes into one encrypted, atomically queued Revision Commit.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_document::ReplicatedEntityDocument;
use crate::record::{EntityRevision, RevisionCommit};
use crate::record_crypto::RecordCryptor;
use crate::record_journal::RecordJournal;
use crate::{ReplicationError, ReplicationResult};

/// One entity's complete next state and the optimistic head it replaces.
#[derive(Debug)]
pub struct EntityChange {
    document: ReplicatedEntityDocument,
    expected_heads: Vec<String>,
    parents: Vec<String>,
}

impl EntityChange {
    pub fn new(
        document: ReplicatedEntityDocument,
        mut expected_heads: Vec<String>,
        parents: Vec<String>,
    ) -> ReplicationResult<Self> {
        uuid::Uuid::parse_str(document.entity_id()).map_err(|_| {
            ReplicationError::Invalid(format!(
                "entity id is not a UUID: {:?}",
                document.entity_id()
            ))
        })?;
        let mut unique_parents = BTreeSet::new();
        for parent in &parents {
            uuid::Uuid::parse_str(parent).map_err(|_| {
                ReplicationError::Invalid(format!("parent revision id is not a UUID: {parent:?}"))
            })?;
            if !unique_parents.insert(parent) {
                return Err(ReplicationError::Invalid(format!(
                    "entity {} names parent {parent} more than once",
                    document.entity_id()
                )));
            }
        }
        expected_heads.sort();
        if expected_heads.windows(2).any(|window| window[0] == window[1]) {
            return Err(ReplicationError::Invalid(format!(
                "entity {} names one expected head more than once",
                document.entity_id()
            )));
        }
        for expected in &expected_heads {
            uuid::Uuid::parse_str(expected).map_err(|_| {
                ReplicationError::Invalid(format!(
                    "expected head revision id is not a UUID: {expected:?}"
                ))
            })?;
            if !unique_parents.contains(expected) {
                return Err(ReplicationError::Invalid(format!(
                    "expected head {expected} is not a parent of entity {}",
                    document.entity_id()
                )));
            }
        }
        let parent_set = parents.iter().cloned().collect::<BTreeSet<_>>();
        let expected_set = expected_heads.iter().cloned().collect::<BTreeSet<_>>();
        if parent_set != expected_set {
            return Err(ReplicationError::Invalid(format!(
                "entity {} expected heads must exactly match its parents",
                document.entity_id()
            )));
        }
        Ok(Self {
            document,
            expected_heads,
            parents,
        })
    }
}

/// Ciphertext-only result of one committed local transaction.
///
/// The exact bytes can be queued repeatedly after a crash; the authenticated journal deduplicates
/// them by immutable revision and commit IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRecordTransaction {
    commit: RevisionCommit,
    revisions: Vec<EntityRevision>,
    expected_heads: BTreeMap<String, Vec<String>>,
}

impl SealedRecordTransaction {
    pub fn seal(
        cryptor: &RecordCryptor,
        changes: impl IntoIterator<Item = EntityChange>,
    ) -> ReplicationResult<Self> {
        let mut changes_by_entity = BTreeMap::new();
        for change in changes {
            let entity_id = change.document.entity_id().to_string();
            if changes_by_entity.insert(entity_id.clone(), change).is_some() {
                return Err(ReplicationError::Invalid(format!(
                    "transaction changes entity {entity_id} more than once"
                )));
            }
        }
        if changes_by_entity.is_empty() {
            return Err(ReplicationError::Invalid(
                "record transaction must change at least one entity".to_string(),
            ));
        }

        let commit_id = uuid::Uuid::new_v4().to_string();
        let mut revisions = Vec::with_capacity(changes_by_entity.len());
        let mut expected_heads = BTreeMap::new();
        for (entity_id, change) in changes_by_entity {
            let revision = cryptor.seal_entity_revision(
                &change.document,
                uuid::Uuid::new_v4().to_string(),
                &commit_id,
                change.parents,
            )?;
            expected_heads.insert(entity_id, change.expected_heads);
            revisions.push(revision);
        }
        let commit = cryptor.seal_commit(
            commit_id,
            revisions
                .iter()
                .map(|revision| revision.revision_id().to_string())
                .collect(),
        )?;
        Ok(Self {
            commit,
            revisions,
            expected_heads,
        })
    }

    pub fn commit(&self) -> &RevisionCommit {
        &self.commit
    }

    pub fn revisions(&self) -> &[EntityRevision] {
        &self.revisions
    }

    pub fn expected_heads(&self) -> &BTreeMap<String, Vec<String>> {
        &self.expected_heads
    }

    pub fn queue(
        &self,
        journal: &RecordJournal,
        created_at: impl Into<String>,
    ) -> ReplicationResult<()> {
        journal.queue_outbound(
            self.commit.clone(),
            self.revisions.clone(),
            self.expected_heads.clone(),
            created_at,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use age::x25519;
    use floria_catalog::ReplicatedProject;
    use floria_integrity::StateAuthenticator;
    use floria_store::{AgeDirStore, KeyProvider, NewSecret, SecretStore, StoreResult};

    use super::*;
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

    #[test]
    fn catalog_and_secret_are_encrypted_and_queued_as_one_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            AgeDirStore::open(
                directory.path().join("store"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let secret_id = store
            .put(NewSecret::managed("Fixture"), b"private fixture")
            .unwrap();
        let secret = SecretEntityDocument::from_store(
            &store,
            &secret_id,
            EntityLifecycle::Active,
        )
        .unwrap();
        let project = CatalogEntityDocument::active(CatalogEntityState::Project(
            ReplicatedProject {
                id: "project-11111111-1111-4111-8111-111111111111".to_string(),
                name: "Fixture".to_string(),
                default_environment_id: None,
            },
        ));
        let cryptor = RecordCryptor::new(Arc::clone(&store));
        let transaction = SealedRecordTransaction::seal(
            &cryptor,
            [
                EntityChange::new(
                    ReplicatedEntityDocument::Catalog(project),
                    Vec::new(),
                    Vec::new(),
                )
                .unwrap(),
                EntityChange::new(
                    ReplicatedEntityDocument::Secret(secret),
                    Vec::new(),
                    Vec::new(),
                )
                .unwrap(),
            ],
        )
        .unwrap();

        assert_eq!(transaction.revisions().len(), 2);
        cryptor.verify_commit(transaction.commit()).unwrap();
        for revision in transaction.revisions() {
            cryptor.open_entity_revision(revision).unwrap();
        }

        let journal = RecordJournal::open(
            directory.path().join("records.sqlite"),
            &store.vault_document().vault_id,
            Arc::new(StateAuthenticator::for_tests([47; 32])),
        )
        .unwrap();
        transaction
            .queue(&journal, "2026-08-07T00:00:00Z")
            .unwrap();
        transaction
            .queue(&journal, "2026-08-07T00:00:00Z")
            .unwrap();

        let outbound = journal.outbound().unwrap();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].revisions().len(), 2);
        assert_eq!(outbound[0].expected_heads().len(), 2);
    }

    #[test]
    fn expected_heads_must_exactly_match_the_revision_parents() {
        let project = CatalogEntityDocument::active(CatalogEntityState::Project(
            ReplicatedProject {
                id: "project-11111111-1111-4111-8111-111111111111".to_string(),
                name: "Fixture".to_string(),
                default_environment_id: None,
            },
        ));
        let error = EntityChange::new(
            ReplicatedEntityDocument::Catalog(project),
            vec![uuid::Uuid::new_v4().to_string()],
            vec![uuid::Uuid::new_v4().to_string()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("is not a parent"));
    }
}
