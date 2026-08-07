//! Pure validation and planning boundary between replicated records and machine-local state.
//!
//! Building a plan performs no catalog, store, filesystem, or network writes. A later applicator
//! can therefore durably record the exact plan before crossing the catalog/store transaction seam.

use std::collections::{BTreeMap, BTreeSet};

use floria_catalog::{ReplicatedCatalog, ResourceSource};

use crate::entity_document::{EntityLifecycle, ReplicatedEntityDocument};
use crate::entity_state::CatalogEntitySet;
use crate::record::ImmutableObjectRef;
use crate::record_crypto::RecordCryptor;
use crate::record_journal::ProjectionRecords;
use crate::secret_state::SecretEntityDocument;
use crate::{ReplicationError, ReplicationResult};

/// Fully authenticated desired state with no machine-local placement decisions applied yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalProjectionPlan {
    head_revisions: BTreeMap<String, String>,
    catalog_entities: CatalogEntitySet,
    active_catalog: ReplicatedCatalog,
    secrets: BTreeMap<String, SecretEntityDocument>,
    archived_entity_ids: BTreeSet<String>,
    object_refs: Vec<ImmutableObjectRef>,
}

impl LocalProjectionPlan {
    /// Authenticate the entire committed history and compile its conflict-free heads.
    ///
    /// Verifying only head ciphertext would leave ancestor routing metadata unauthenticated even
    /// though it determines causality. Every revision and commit in `records` is therefore opened
    /// or verified before any head becomes eligible for projection.
    pub fn build(
        cryptor: &RecordCryptor,
        records: &ProjectionRecords,
    ) -> ReplicationResult<Self> {
        let mut commits = BTreeMap::new();
        for commit in records.commits() {
            cryptor.verify_commit(commit)?;
            if commits
                .insert(commit.commit_id().to_string(), commit)
                .is_some()
            {
                return Err(ReplicationError::Invalid(format!(
                    "projection contains commit {} more than once",
                    commit.commit_id()
                )));
            }
        }

        let mut documents = BTreeMap::new();
        for revision in records.revisions() {
            let commit = commits.get(revision.commit_id()).ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "projection revision {} has no owning commit {}",
                    revision.revision_id(),
                    revision.commit_id()
                ))
            })?;
            if !commit
                .revision_ids()
                .iter()
                .any(|member| member == revision.revision_id())
            {
                return Err(ReplicationError::Invalid(format!(
                    "projection commit {} does not contain revision {}",
                    commit.commit_id(),
                    revision.revision_id()
                )));
            }
            let document = cryptor.open_entity_revision(revision)?;
            if documents
                .insert(
                    revision.revision_id().to_string(),
                    (revision.entity_id().to_string(), document),
                )
                .is_some()
            {
                return Err(ReplicationError::Invalid(format!(
                    "projection contains revision {} more than once",
                    revision.revision_id()
                )));
            }
        }

        let mut head_revisions = BTreeMap::new();
        let mut catalog_documents = Vec::new();
        let mut secrets = BTreeMap::new();
        let mut archived_entity_ids = BTreeSet::new();
        let mut objects = BTreeMap::<String, ImmutableObjectRef>::new();
        for revision_id in records.head_revision_ids() {
            let (entity_id, document) = documents.get(revision_id).ok_or_else(|| {
                ReplicationError::Invalid(format!(
                    "projection head revision {revision_id} is missing"
                ))
            })?;
            if head_revisions
                .insert(entity_id.clone(), revision_id.clone())
                .is_some()
            {
                return Err(ReplicationError::Invalid(format!(
                    "projection contains multiple heads for entity {entity_id}"
                )));
            }
            if document.lifecycle() == EntityLifecycle::Archived {
                archived_entity_ids.insert(entity_id.clone());
            }
            match document {
                ReplicatedEntityDocument::Catalog(document) => {
                    catalog_documents.push(document.clone())
                }
                ReplicatedEntityDocument::Secret(document) => {
                    index_object(&mut objects, document.head().object())?;
                    secrets.insert(entity_id.clone(), document.clone());
                }
            }
        }

        let catalog_entities = CatalogEntitySet::from_documents(catalog_documents)?;
        let active_catalog = catalog_entities.active_catalog()?;
        validate_secret_references(&active_catalog, &secrets)?;

        Ok(Self {
            head_revisions,
            catalog_entities,
            active_catalog,
            secrets,
            archived_entity_ids,
            object_refs: objects.into_values().collect(),
        })
    }

    pub fn head_revisions(&self) -> &BTreeMap<String, String> {
        &self.head_revisions
    }

    pub fn catalog_entities(&self) -> &CatalogEntitySet {
        &self.catalog_entities
    }

    pub fn active_catalog(&self) -> &ReplicatedCatalog {
        &self.active_catalog
    }

    /// All current Secret heads, including archived entities retained for restoration.
    pub fn secrets(&self) -> &BTreeMap<String, SecretEntityDocument> {
        &self.secrets
    }

    pub fn archived_entity_ids(&self) -> &BTreeSet<String> {
        &self.archived_entity_ids
    }

    pub fn object_refs(&self) -> &[ImmutableObjectRef] {
        &self.object_refs
    }
}

fn index_object(
    objects: &mut BTreeMap<String, ImmutableObjectRef>,
    object: &ImmutableObjectRef,
) -> ReplicationResult<()> {
    match objects.get(object.digest()) {
        Some(existing) if existing == object => Ok(()),
        Some(_) => Err(ReplicationError::Invalid(format!(
            "object {} has inconsistent ciphertext sizes",
            object.digest()
        ))),
        None => {
            objects.insert(object.digest().to_string(), object.clone());
            Ok(())
        }
    }
}

fn validate_secret_references(
    catalog: &ReplicatedCatalog,
    secrets: &BTreeMap<String, SecretEntityDocument>,
) -> ReplicationResult<()> {
    for resource in &catalog.resources {
        let ResourceSource::SecretRef { secret_id } = &resource.source else {
            continue;
        };
        let secret = secrets.get(secret_id).ok_or_else(|| {
            ReplicationError::Invalid(format!(
                "active resource {} references missing secret {secret_id}",
                resource.id
            ))
        })?;
        if secret.lifecycle() != EntityLifecycle::Active {
            return Err(ReplicationError::Invalid(format!(
                "active resource {} references archived secret {secret_id}",
                resource.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use age::x25519;
    use floria_catalog::{
        EntrySpec, ItemMetadata, Resource, ResourceCodec, ResourceKind, ResourceOrigin,
        ValueShape,
    };
    use floria_core::authz::Enforcement;
    use floria_integrity::StateAuthenticator;
    use floria_store::{AgeDirStore, KeyProvider, NewSecret, SecretStore, StoreResult};

    use super::*;
    use crate::entity_state::{CatalogEntityDocument, CatalogEntityState};
    use crate::record_journal::RecordJournal;
    use crate::record_transaction::{EntityChange, SealedRecordTransaction};
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

    fn fixture() -> (tempfile::TempDir, Arc<AgeDirStore>, RecordCryptor, RecordJournal) {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            AgeDirStore::open(
                directory.path().join("store"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let cryptor = RecordCryptor::new(Arc::clone(&store));
        let journal = RecordJournal::open(
            directory.path().join("records.sqlite"),
            &store.vault_document().vault_id,
            Arc::new(StateAuthenticator::for_tests([19; 32])),
        )
        .unwrap();
        (directory, store, cryptor, journal)
    }

    fn queue(
        cryptor: &RecordCryptor,
        journal: &RecordJournal,
        documents: Vec<ReplicatedEntityDocument>,
    ) {
        let changes = documents
            .into_iter()
            .map(|document| EntityChange::new(document, None, Vec::new()).unwrap())
            .collect::<Vec<_>>();
        SealedRecordTransaction::seal(cryptor, changes)
            .unwrap()
            .queue(journal, "2026-08-07T00:00:00Z")
            .unwrap();
    }

    fn resource(secret_id: String) -> CatalogEntityDocument {
        CatalogEntityDocument::active(CatalogEntityState::Resource(Resource {
            id: "resource-33333333-3333-4333-8333-333333333333".to_string(),
            name: "Fixture token".to_string(),
            kind: ResourceKind::SharedSecret,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: Some("FIXTURE_TOKEN".to_string()),
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: "FIXTURE_TOKEN".to_string(),
                key: Some("FIXTURE_TOKEN".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id },
            enforcement: Enforcement::Prompt,
            metadata: ItemMetadata::default(),
            origin: ResourceOrigin::default(),
        }))
    }

    #[test]
    fn plan_authenticates_and_compiles_catalog_and_secret_heads() {
        let (_directory, store, cryptor, journal) = fixture();
        let secret_id = store
            .put(NewSecret::managed("Fixture"), b"private fixture")
            .unwrap();
        let secret = SecretEntityDocument::from_store(
            &store,
            &secret_id,
            EntityLifecycle::Active,
        )
        .unwrap();
        queue(
            &cryptor,
            &journal,
            vec![
                ReplicatedEntityDocument::Catalog(resource(secret_id.to_string())),
                ReplicatedEntityDocument::Secret(secret),
            ],
        );

        let records = journal.projection_records().unwrap();
        let plan = LocalProjectionPlan::build(&cryptor, &records).unwrap();

        assert_eq!(plan.active_catalog().resources.len(), 1);
        assert_eq!(plan.secrets().len(), 1);
        assert_eq!(plan.object_refs().len(), 1);
        assert_eq!(plan.head_revisions().len(), 2);
        assert!(plan.archived_entity_ids().is_empty());
    }

    #[test]
    fn active_resource_cannot_project_without_its_secret_entity() {
        let (_directory, _store, cryptor, journal) = fixture();
        let missing_secret_id = uuid::Uuid::new_v4().to_string();
        queue(
            &cryptor,
            &journal,
            vec![ReplicatedEntityDocument::Catalog(resource(
                missing_secret_id.clone(),
            ))],
        );

        let records = journal.projection_records().unwrap();
        let error = LocalProjectionPlan::build(&cryptor, &records).unwrap_err();
        assert!(error.to_string().contains(&format!(
            "references missing secret {missing_secret_id}"
        )));
    }

    #[test]
    fn active_resource_cannot_project_an_archived_secret_entity() {
        let (_directory, store, cryptor, journal) = fixture();
        let secret_id = store
            .put(NewSecret::managed("Fixture"), b"private fixture")
            .unwrap();
        let secret = SecretEntityDocument::from_store(
            &store,
            &secret_id,
            EntityLifecycle::Active,
        )
        .unwrap()
        .archived();
        queue(
            &cryptor,
            &journal,
            vec![
                ReplicatedEntityDocument::Catalog(resource(secret_id.to_string())),
                ReplicatedEntityDocument::Secret(secret),
            ],
        );

        let records = journal.projection_records().unwrap();
        let error = LocalProjectionPlan::build(&cryptor, &records).unwrap_err();
        assert!(error.to_string().contains(&format!(
            "references archived secret {secret_id}"
        )));
    }
}
