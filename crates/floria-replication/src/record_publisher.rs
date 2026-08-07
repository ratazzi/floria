//! Capture one committed local state as an encrypted record transaction.
//!
//! The publisher compares authenticated Catalog/Store state with the unique heads already held by
//! the record journal. It emits complete entity state only for actual changes. Missing local
//! entities become archived revisions; immutable record history is never deleted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use floria_catalog::Catalog;
use floria_store::{AgeDirStore, SecretStore};

use crate::entity_document::{EntityLifecycle, ReplicatedEntityDocument};
use crate::entity_state::CatalogEntitySet;
use crate::record_crypto::RecordCryptor;
use crate::record_journal::RecordJournal;
use crate::record_transaction::{EntityChange, SealedRecordTransaction};
use crate::secret_state::SecretEntityDocument;
use crate::{ReplicationError, ReplicationResult};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordCaptureReport {
    changed_entities: usize,
    queued_transaction: bool,
}

impl RecordCaptureReport {
    pub fn changed_entities(&self) -> usize {
        self.changed_entities
    }

    pub fn queued_transaction(&self) -> bool {
        self.queued_transaction
    }
}

/// Owns the comparison and sealing rules for local-to-transport publication.
pub struct RecordPublisher<'a> {
    journal: &'a RecordJournal,
    store: Arc<AgeDirStore>,
}

impl<'a> RecordPublisher<'a> {
    pub fn new(journal: &'a RecordJournal, store: Arc<AgeDirStore>) -> Self {
        Self { journal, store }
    }

    /// Snapshot current committed state and enqueue at most one transaction.
    ///
    /// A conflict anywhere in the retained record graph blocks publication. Creating a new local
    /// child on top of an arbitrarily selected remote tip would silently resolve that conflict.
    pub fn capture(
        &self,
        catalog: &Catalog,
        created_at: impl Into<String>,
    ) -> ReplicationResult<RecordCaptureReport> {
        let current = self.current_documents(catalog)?;
        let previous = self.previous_heads()?;
        let mut entity_ids = current.keys().cloned().collect::<BTreeSet<_>>();
        entity_ids.extend(previous.keys().cloned());

        let mut changes = Vec::new();
        for entity_id in entity_ids {
            let current_document = current.get(&entity_id);
            let previous_head = previous.get(&entity_id);
            let next_document = match (current_document, previous_head) {
                (Some(current), Some((_, previous))) if current == previous => continue,
                (Some(current), _) => current.clone(),
                (None, Some((_, previous)))
                    if previous.lifecycle() == EntityLifecycle::Archived =>
                {
                    continue
                }
                (None, Some((_, previous))) => archived(previous.clone()),
                (None, None) => continue,
            };
            let expected_head = previous_head.map(|(revision_id, _)| revision_id.clone());
            let parents = expected_head.iter().cloned().collect();
            changes.push(EntityChange::new(next_document, expected_head, parents)?);
        }

        if changes.is_empty() {
            return Ok(RecordCaptureReport::default());
        }
        let changed_entities = changes.len();
        let cryptor = RecordCryptor::new(Arc::clone(&self.store));
        SealedRecordTransaction::seal(&cryptor, changes)?
            .queue(self.journal, created_at)?;
        Ok(RecordCaptureReport {
            changed_entities,
            queued_transaction: true,
        })
    }

    fn current_documents(
        &self,
        catalog: &Catalog,
    ) -> ReplicationResult<BTreeMap<String, ReplicatedEntityDocument>> {
        let catalog_state = CatalogEntitySet::from_catalog(&catalog.replicated_catalog()?)?;
        let mut documents = BTreeMap::new();
        for document in catalog_state.documents() {
            insert_document(
                &mut documents,
                ReplicatedEntityDocument::Catalog(document.clone()),
            )?;
        }
        for record in self.store.list()? {
            insert_document(
                &mut documents,
                ReplicatedEntityDocument::Secret(SecretEntityDocument::from_store(
                    &self.store,
                    &record.id,
                    EntityLifecycle::Active,
                )?),
            )?;
        }
        Ok(documents)
    }

    fn previous_heads(
        &self,
    ) -> ReplicationResult<BTreeMap<String, (String, ReplicatedEntityDocument)>> {
        let records = self.journal.projection_records()?;
        let by_revision = records
            .revisions()
            .iter()
            .map(|revision| (revision.revision_id(), revision))
            .collect::<BTreeMap<_, _>>();
        let cryptor = RecordCryptor::new(Arc::clone(&self.store));
        let mut heads = BTreeMap::new();
        for revision_id in records.head_revision_ids() {
            let revision = by_revision.get(revision_id.as_str()).ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "record head revision {revision_id} is missing from its projection"
                ))
            })?;
            let document = cryptor.open_entity_revision(revision)?;
            let entity_id = document.entity_id().to_string();
            if heads
                .insert(entity_id.clone(), (revision_id.clone(), document))
                .is_some()
            {
                return Err(ReplicationError::Invalid(format!(
                    "record projection contains multiple heads for entity {entity_id}"
                )));
            }
        }
        Ok(heads)
    }
}

fn archived(document: ReplicatedEntityDocument) -> ReplicatedEntityDocument {
    match document {
        ReplicatedEntityDocument::Catalog(document) => {
            ReplicatedEntityDocument::Catalog(document.archived())
        }
        ReplicatedEntityDocument::Secret(document) => {
            ReplicatedEntityDocument::Secret(document.archived())
        }
    }
}

fn insert_document(
    documents: &mut BTreeMap<String, ReplicatedEntityDocument>,
    document: ReplicatedEntityDocument,
) -> ReplicationResult<()> {
    let entity_id = document.entity_id().to_string();
    if documents.insert(entity_id.clone(), document).is_some() {
        return Err(ReplicationError::Invalid(format!(
            "local state contains duplicate entity {entity_id}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use age::x25519;
    use floria_catalog::{Catalog, Project};
    use floria_integrity::StateAuthenticator;
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

    struct Fixture {
        _directory: tempfile::TempDir,
        catalog: Catalog,
        store: Arc<AgeDirStore>,
        journal: RecordJournal,
    }

    impl Fixture {
        fn new() -> Self {
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
                Arc::new(StateAuthenticator::for_tests([81; 32])),
            )
            .unwrap();
            Self {
                _directory: directory,
                catalog,
                store,
                journal,
            }
        }

        fn publisher(&self) -> RecordPublisher<'_> {
            RecordPublisher::new(&self.journal, Arc::clone(&self.store))
        }
    }

    #[test]
    fn captures_only_changes_and_chains_consecutive_local_updates() {
        let fixture = Fixture::new();
        let secret_id = fixture
            .store
            .put(NewSecret::managed("Fixture"), b"first payload")
            .unwrap();

        let first = fixture
            .publisher()
            .capture(&fixture.catalog, "2026-08-07T00:00:00Z")
            .unwrap();
        assert_eq!(first.changed_entities(), 1);
        assert!(first.queued_transaction());
        let first_revision = fixture.journal.analysis().unwrap().heads_for(secret_id.as_str())[0]
            .clone();

        let unchanged = fixture
            .publisher()
            .capture(&fixture.catalog, "2026-08-07T00:00:01Z")
            .unwrap();
        assert_eq!(unchanged, RecordCaptureReport::default());

        fixture
            .store
            .append_version(&secret_id, b"second payload")
            .unwrap();
        let second = fixture
            .publisher()
            .capture(&fixture.catalog, "2026-08-07T00:00:02Z")
            .unwrap();
        assert_eq!(second.changed_entities(), 1);
        let outbound = fixture.journal.outbound().unwrap();
        assert_eq!(outbound.len(), 2);
        assert_eq!(
            outbound[1].expected_heads()[secret_id.as_str()].as_deref(),
            Some(first_revision.as_str())
        );
        assert_eq!(outbound[1].revisions()[0].parents(), &[first_revision]);
    }

    #[test]
    fn missing_local_entities_are_archived_once() {
        let fixture = Fixture::new();
        let secret_id = fixture
            .store
            .put(NewSecret::managed("Fixture"), b"private payload")
            .unwrap();
        fixture
            .publisher()
            .capture(&fixture.catalog, "2026-08-07T00:00:00Z")
            .unwrap();
        fixture.store.delete(&secret_id).unwrap();

        let archived = fixture
            .publisher()
            .capture(&fixture.catalog, "2026-08-07T00:00:01Z")
            .unwrap();
        assert_eq!(archived.changed_entities(), 1);
        let unchanged = fixture
            .publisher()
            .capture(&fixture.catalog, "2026-08-07T00:00:02Z")
            .unwrap();
        assert_eq!(unchanged, RecordCaptureReport::default());

        let records = fixture.journal.projection_records().unwrap();
        let head_id = records.head_revision_ids().first().unwrap();
        let revision = records
            .revisions()
            .iter()
            .find(|revision| revision.revision_id() == head_id)
            .unwrap();
        let document = RecordCryptor::new(Arc::clone(&fixture.store))
            .open_entity_revision(revision)
            .unwrap();
        assert_eq!(document.lifecycle(), EntityLifecycle::Archived);
    }

    #[test]
    fn catalog_rows_and_secrets_share_one_bootstrap_transaction() {
        let fixture = Fixture::new();
        fixture
            .catalog
            .upsert_project(&Project {
                id: "project-11111111-1111-4111-8111-111111111111".to_string(),
                name: "Fixture".to_string(),
                path: fixture._directory.path().to_path_buf(),
                default_environment_id: None,
            })
            .unwrap();
        fixture
            .store
            .put(NewSecret::managed("Fixture"), b"private payload")
            .unwrap();

        let report = fixture
            .publisher()
            .capture(&fixture.catalog, "2026-08-07T00:00:00Z")
            .unwrap();
        assert_eq!(report.changed_entities(), 2);
        let outbound = fixture.journal.outbound().unwrap();
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].revisions().len(), 2);
    }
}
