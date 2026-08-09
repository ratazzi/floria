//! Authenticated review of concurrent entity heads.
//!
//! This module owns the decrypted, user-reviewable view of a record conflict. Platform adapters
//! receive structured metadata but never secret plaintext or authority to interpret revisions.

use std::sync::Arc;

use floria_catalog::Catalog;
use floria_store::AgeDirStore;
use serde::{Deserialize, Serialize};

use crate::entity_document::{EntityLifecycle, ReplicatedEntityDocument};
use crate::entity_state::CatalogEntityState;
use crate::record_crypto::RecordCryptor;
use crate::record_journal::RecordJournal;
use crate::record_publisher::capture_local_documents;
use crate::record_transaction::{EntityChange, SealedRecordTransaction};
use crate::{ReplicationError, ReplicationResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncConflictEntityKind {
    Project,
    Environment,
    Resource,
    Binding,
    Surface,
    Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConflictCandidate {
    revision_id: String,
    lifecycle: EntityLifecycle,
    kind: SyncConflictEntityKind,
    label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plaintext_size: Option<u64>,
    matches_local_state: bool,
}

impl SyncConflictCandidate {
    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    pub fn lifecycle(&self) -> EntityLifecycle {
        self.lifecycle
    }

    pub fn kind(&self) -> SyncConflictEntityKind {
        self.kind
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn version_id(&self) -> Option<&str> {
        self.version_id.as_deref()
    }

    pub fn plaintext_size(&self) -> Option<u64> {
        self.plaintext_size
    }

    pub fn matches_local_state(&self) -> bool {
        self.matches_local_state
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConflictReview {
    entity_id: String,
    candidates: Vec<SyncConflictCandidate>,
}

impl SyncConflictReview {
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    pub fn candidates(&self) -> &[SyncConflictCandidate] {
        &self.candidates
    }
}

/// Deep module for translating an authenticated revision graph into safe review metadata.
pub struct RecordConflictManager<'a> {
    journal: &'a RecordJournal,
    store: Arc<AgeDirStore>,
}

impl<'a> RecordConflictManager<'a> {
    pub fn new(journal: &'a RecordJournal, store: Arc<AgeDirStore>) -> Self {
        Self { journal, store }
    }

    pub fn review(&self, catalog: &Catalog) -> ReplicationResult<Vec<SyncConflictReview>> {
        let local_documents = capture_local_documents(catalog, &self.store)?;
        let cryptor = RecordCryptor::new(Arc::clone(&self.store));
        let mut reviews = Vec::new();
        for (entity_id, heads) in self.journal.conflicting_heads()? {
            let mut candidates = Vec::with_capacity(heads.len());
            let mut expected_kind = None;
            for head in heads {
                cryptor.verify_commit(head.commit())?;
                if !head
                    .commit()
                    .revision_ids()
                    .iter()
                    .any(|revision_id| revision_id == head.revision().revision_id())
                {
                    return Err(ReplicationError::Invalid(format!(
                        "conflict revision {} is absent from owning commit {}",
                        head.revision().revision_id(),
                        head.commit().commit_id()
                    )));
                }
                let document = cryptor.open_entity_revision(head.revision())?;
                if document.entity_id() != entity_id {
                    return Err(ReplicationError::Invalid(format!(
                        "conflict revision {} opened as a different entity {}",
                        head.revision().revision_id(),
                        document.entity_id()
                    )));
                }
                let candidate = candidate_from(
                    head.revision().revision_id(),
                    &document,
                    local_documents.get(&entity_id) == Some(&document),
                );
                match expected_kind {
                    Some(kind) if kind != candidate.kind => {
                        return Err(ReplicationError::Invalid(format!(
                            "conflicting entity {entity_id} changes type across revisions"
                        )))
                    }
                    None => expected_kind = Some(candidate.kind),
                    _ => {}
                }
                candidates.push(candidate);
            }
            candidates.sort_by(|left, right| {
                right
                    .matches_local_state
                    .cmp(&left.matches_local_state)
                    .then_with(|| left.revision_id.cmp(&right.revision_id))
            });
            reviews.push(SyncConflictReview {
                entity_id,
                candidates,
            });
        }
        Ok(reviews)
    }

    /// Resolve one exact concurrent-head set without discarding either branch's history.
    ///
    /// The chosen document becomes a new revision whose parents and acceptable transport CAS
    /// heads are every currently observed head. A stale review therefore fails instead of
    /// overwriting a conflict that changed while the user was deciding.
    pub fn resolve(
        &self,
        entity_id: &str,
        selected_revision_id: &str,
        resolved_at: impl Into<String>,
    ) -> ReplicationResult<()> {
        let heads = self
            .journal
            .conflicting_heads()?
            .remove(entity_id)
            .ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "entity {entity_id} no longer has a conflict to resolve"
                ))
            })?;
        let cryptor = RecordCryptor::new(Arc::clone(&self.store));
        let mut selected = None;
        let mut expected_kind = None;
        let mut parents = Vec::with_capacity(heads.len());
        for head in heads {
            cryptor.verify_commit(head.commit())?;
            if !head
                .commit()
                .revision_ids()
                .iter()
                .any(|revision_id| revision_id == head.revision().revision_id())
            {
                return Err(ReplicationError::Invalid(format!(
                    "conflict revision {} is absent from owning commit {}",
                    head.revision().revision_id(),
                    head.commit().commit_id()
                )));
            }
            let document = cryptor.open_entity_revision(head.revision())?;
            if document.entity_id() != entity_id {
                return Err(ReplicationError::Invalid(format!(
                    "conflict revision {} opened as a different entity {}",
                    head.revision().revision_id(),
                    document.entity_id()
                )));
            }
            let kind = candidate_from(head.revision().revision_id(), &document, false).kind;
            match expected_kind {
                Some(expected) if expected != kind => {
                    return Err(ReplicationError::Invalid(format!(
                        "conflicting entity {entity_id} changes type across revisions"
                    )))
                }
                None => expected_kind = Some(kind),
                _ => {}
            }
            if head.revision().revision_id() == selected_revision_id {
                selected = Some(document);
            }
            parents.push(head.revision().revision_id().to_string());
        }
        let selected = selected.ok_or_else(|| {
            ReplicationError::Invalid(format!(
                "selected revision {selected_revision_id} is not a current head of {entity_id}"
            ))
        })?;
        parents.sort();
        let transaction = SealedRecordTransaction::seal(
            &cryptor,
            [EntityChange::new(selected, parents.clone(), parents)?],
        )?;
        transaction.queue(self.journal, resolved_at)
    }
}

fn candidate_from(
    revision_id: &str,
    document: &ReplicatedEntityDocument,
    matches_local_state: bool,
) -> SyncConflictCandidate {
    let (kind, label, version_id, plaintext_size) = match document {
        ReplicatedEntityDocument::Catalog(document) => {
            let (kind, label) = match document.state() {
                CatalogEntityState::Project(project) => {
                    (SyncConflictEntityKind::Project, project.name.clone())
                }
                CatalogEntityState::Environment(environment) => {
                    (SyncConflictEntityKind::Environment, environment.name.clone())
                }
                CatalogEntityState::Resource(resource) => {
                    (SyncConflictEntityKind::Resource, resource.name.clone())
                }
                CatalogEntityState::Binding(_) => {
                    (SyncConflictEntityKind::Binding, "Binding".to_string())
                }
                CatalogEntityState::Surface(surface) => {
                    (SyncConflictEntityKind::Surface, surface.name.clone())
                }
            };
            (kind, label, None, None)
        }
        ReplicatedEntityDocument::Secret(secret) => (
            SyncConflictEntityKind::Secret,
            secret.descriptor().label().to_string(),
            Some(secret.head().version_id().to_string()),
            Some(secret.head().plaintext_size()),
        ),
    };
    SyncConflictCandidate {
        revision_id: revision_id.to_string(),
        lifecycle: document.lifecycle(),
        kind,
        label,
        version_id,
        plaintext_size,
        matches_local_state,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use age::x25519;
    use floria_integrity::StateAuthenticator;
    use floria_store::{KeyProvider, NewSecret, SecretStore, StoreResult};

    use super::*;
    use crate::entity_document::ReplicatedEntityDocument;
    use crate::record_publisher::RecordPublisher;
    use crate::record_transaction::{EntityChange, SealedRecordTransaction};

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
    fn review_identifies_the_local_candidate_without_exposing_secret_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = Arc::new(
            AgeDirStore::open(
                directory.path().join("store"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let journal = RecordJournal::open(
            directory.path().join("records.sqlite"),
            &store.vault_document().vault_id,
            Arc::new(StateAuthenticator::for_tests([72; 32])),
        )
        .unwrap();
        let secret_id = store
            .put(NewSecret::managed("Database password"), b"root payload")
            .unwrap();
        RecordPublisher::new(&journal, Arc::clone(&store))
            .capture(&catalog, "2026-08-09T00:00:00Z")
            .unwrap();
        let root_revision = journal.analysis().unwrap().heads_for(secret_id.as_str())[0].clone();

        store.append_version(&secret_id, b"left payload").unwrap();
        RecordPublisher::new(&journal, Arc::clone(&store))
            .capture(&catalog, "2026-08-09T00:00:01Z")
            .unwrap();
        store.append_version(&secret_id, b"right payload").unwrap();
        let local_document = ReplicatedEntityDocument::Secret(
            crate::secret_state::SecretEntityDocument::from_store(
                &store,
                &secret_id,
                EntityLifecycle::Active,
            )
            .unwrap(),
        );
        let concurrent = SealedRecordTransaction::seal(
            &RecordCryptor::new(Arc::clone(&store)),
            [EntityChange::new(
                local_document,
                vec![root_revision.clone()],
                vec![root_revision],
            )
            .unwrap()],
        )
        .unwrap();
        journal
            .receive_inbound(
                vec![concurrent.commit().clone()],
                concurrent.revisions().to_vec(),
                "2026-08-09T00:00:02Z",
            )
            .unwrap();

        let reviews = RecordConflictManager::new(&journal, Arc::clone(&store))
            .review(&catalog)
            .unwrap();

        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].entity_id(), secret_id.as_str());
        assert_eq!(reviews[0].candidates().len(), 2);
        assert_eq!(
            reviews[0]
                .candidates()
                .iter()
                .filter(|candidate| candidate.matches_local_state())
                .count(),
            1
        );
        assert!(reviews[0]
            .candidates()
            .iter()
            .all(|candidate| candidate.label() == "Database password"));
        let encoded = serde_json::to_string(&reviews).unwrap();
        assert!(!encoded.contains("left payload"));
        assert!(!encoded.contains("right payload"));

        let selected_revision = reviews[0]
            .candidates()
            .iter()
            .find(|candidate| candidate.matches_local_state())
            .unwrap()
            .revision_id()
            .to_string();
        RecordConflictManager::new(&journal, Arc::clone(&store))
            .resolve(
                secret_id.as_str(),
                &selected_revision,
                "2026-08-09T00:00:03Z",
            )
            .unwrap();

        let records = journal.projection_records().unwrap();
        assert_eq!(records.head_revision_ids().len(), 1);
        let merge_revision = records
            .revisions()
            .iter()
            .find(|revision| revision.revision_id() == records.head_revision_ids()[0])
            .unwrap();
        assert_eq!(merge_revision.parents().len(), 2);
        let outbound = journal.outbound().unwrap();
        let expected_heads = outbound.last().unwrap().expected_heads();
        assert_eq!(expected_heads[secret_id.as_str()].len(), 2);
        let selected_document = RecordCryptor::new(Arc::clone(&store))
            .open_entity_revision(merge_revision)
            .unwrap();
        let current_document = crate::secret_state::SecretEntityDocument::from_store(
            &store,
            &secret_id,
            EntityLifecycle::Active,
        )
        .unwrap();
        assert_eq!(
            selected_document,
            ReplicatedEntityDocument::Secret(current_document)
        );
    }
}
