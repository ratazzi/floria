//! Pure validation and planning boundary between replicated records and machine-local state.
//!
//! Building a plan performs no catalog, store, filesystem, or network writes. A later applicator
//! can therefore durably record the exact plan before crossing the catalog/store transaction seam.

use std::collections::{BTreeMap, BTreeSet};

use floria_catalog::{ReplicatedCatalog, ResourceSource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entity_document::{EntityLifecycle, ReplicatedEntityDocument};
use crate::entity_state::{CatalogEntityDocument, CatalogEntitySet};
use crate::record::ImmutableObjectRef;
use crate::record_crypto::RecordCryptor;
use crate::record_journal::ProjectionRecords;
use crate::secret_state::SecretEntityDocument;
use crate::{ReplicationError, ReplicationResult};

const LOCAL_PROJECTION_FORMAT_VERSION: u32 = 1;

/// Canonical, portable input to a local projection attempt.
///
/// Derived catalog and object indexes are deliberately omitted. Decoding must rebuild them so a
/// durable recovery intent cannot carry two disagreeing representations of desired state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LocalProjectionDocument {
    format_version: u32,
    head_revisions: BTreeMap<String, String>,
    catalog_documents: Vec<CatalogEntityDocument>,
    secrets: BTreeMap<String, SecretEntityDocument>,
}

/// Fully authenticated desired state with no machine-local placement decisions applied yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalProjectionPlan {
    document: LocalProjectionDocument,
    catalog_entities: CatalogEntitySet,
    active_catalog: ReplicatedCatalog,
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
            match document {
                ReplicatedEntityDocument::Catalog(document) => {
                    catalog_documents.push(document.clone())
                }
                ReplicatedEntityDocument::Secret(document) => {
                    secrets.insert(entity_id.clone(), document.clone());
                }
            }
        }

        catalog_documents.sort_by(|left, right| left.entity_id().cmp(right.entity_id()));
        Self::assemble(LocalProjectionDocument {
            format_version: LOCAL_PROJECTION_FORMAT_VERSION,
            head_revisions,
            catalog_documents,
            secrets,
        })
    }

    /// Encode the exact, validated desired state for durable replay.
    pub fn encode(&self) -> ReplicationResult<Vec<u8>> {
        serde_json::to_vec(&self.document).map_err(ReplicationError::from)
    }

    /// Decode and revalidate every derived projection invariant.
    pub fn decode(bytes: &[u8]) -> ReplicationResult<Self> {
        let document = serde_json::from_slice(bytes)?;
        Self::assemble(document)
    }

    /// Stable identity used to make preparing and completing a projection idempotent.
    pub fn plan_id(&self) -> ReplicationResult<String> {
        Ok(format!("{:x}", Sha256::digest(self.encode()?)))
    }

    fn assemble(document: LocalProjectionDocument) -> ReplicationResult<Self> {
        if document.format_version != LOCAL_PROJECTION_FORMAT_VERSION {
            return Err(ReplicationError::Invalid(format!(
                "unsupported local projection format {}",
                document.format_version
            )));
        }

        let mut entity_ids = BTreeSet::new();
        let mut previous_catalog_id = None;
        for catalog_document in &document.catalog_documents {
            catalog_document.validate()?;
            let entity_id = catalog_document.entity_id();
            if previous_catalog_id.is_some_and(|previous| previous >= entity_id) {
                return Err(ReplicationError::Invalid(
                    "local projection catalog documents must be sorted and unique".to_string(),
                ));
            }
            previous_catalog_id = Some(entity_id);
            entity_ids.insert(entity_id.to_string());
        }
        for (entity_id, secret) in &document.secrets {
            secret.validate()?;
            if secret.entity_id() != entity_id {
                return Err(ReplicationError::Invalid(format!(
                    "local projection secret key {entity_id} does not match document {}",
                    secret.entity_id()
                )));
            }
            if !entity_ids.insert(entity_id.clone()) {
                return Err(ReplicationError::Invalid(format!(
                    "local projection entity {entity_id} appears more than once"
                )));
            }
        }
        for (entity_id, revision_id) in &document.head_revisions {
            require_uuid("local projection entity id", entity_id)?;
            require_uuid("local projection head revision id", revision_id)?;
        }
        let head_entity_ids = document.head_revisions.keys().cloned().collect::<BTreeSet<_>>();
        if head_entity_ids != entity_ids {
            return Err(ReplicationError::Invalid(
                "local projection heads do not match its entity documents".to_string(),
            ));
        }

        let catalog_entities =
            CatalogEntitySet::from_documents(document.catalog_documents.clone())?;
        let active_catalog = catalog_entities.active_catalog()?;
        validate_secret_references(&active_catalog, &document.secrets)?;
        validate_secret_environment_scopes(&active_catalog, &document.secrets)?;

        let mut archived_entity_ids = BTreeSet::new();
        for catalog_document in &document.catalog_documents {
            if catalog_document.lifecycle() == EntityLifecycle::Archived {
                archived_entity_ids.insert(catalog_document.entity_id().to_string());
            }
        }
        let mut objects = BTreeMap::<String, ImmutableObjectRef>::new();
        for secret in document.secrets.values() {
            if secret.lifecycle() == EntityLifecycle::Archived {
                archived_entity_ids.insert(secret.entity_id().to_string());
            }
            index_object(&mut objects, secret.head().object())?;
        }

        Ok(Self {
            document,
            catalog_entities,
            active_catalog,
            archived_entity_ids,
            object_refs: objects.into_values().collect(),
        })
    }

    pub fn head_revisions(&self) -> &BTreeMap<String, String> {
        &self.document.head_revisions
    }

    pub fn catalog_entities(&self) -> &CatalogEntitySet {
        &self.catalog_entities
    }

    pub fn active_catalog(&self) -> &ReplicatedCatalog {
        &self.active_catalog
    }

    /// All current Secret heads, including archived entities retained for restoration.
    pub fn secrets(&self) -> &BTreeMap<String, SecretEntityDocument> {
        &self.document.secrets
    }

    pub fn archived_entity_ids(&self) -> &BTreeSet<String> {
        &self.archived_entity_ids
    }

    pub fn object_refs(&self) -> &[ImmutableObjectRef] {
        &self.object_refs
    }
}

fn require_uuid(label: &str, value: &str) -> ReplicationResult<()> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ReplicationError::Invalid(format!("{label} is not a UUID: {value:?}")))
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

fn validate_secret_environment_scopes(
    catalog: &ReplicatedCatalog,
    secrets: &BTreeMap<String, SecretEntityDocument>,
) -> ReplicationResult<()> {
    let environment_projects = catalog
        .environments
        .iter()
        .map(|environment| (environment.id.as_str(), environment.project_id.as_str()))
        .collect::<BTreeMap<_, _>>();
    let project_ids = catalog
        .projects
        .iter()
        .map(|project| project.id.as_str())
        .collect::<BTreeSet<_>>();
    for secret in secrets.values() {
        if secret.lifecycle() != EntityLifecycle::Active {
            continue;
        }
        if let Some(scope) = secret.descriptor().environment_ids() {
            for environment_id in scope {
                if !environment_projects.contains_key(environment_id.as_str()) {
                    return Err(ReplicationError::Invalid(format!(
                        "active secret {} references missing environment {environment_id}",
                        secret.entity_id()
                    )));
                }
            }
        }
        for placement in secret.descriptor().placements() {
            let floria_store::ManagedPlacement::Project {
                project_id,
                environment_ids,
                ..
            } = placement
            else {
                continue;
            };
            if !project_ids.contains(project_id.as_str()) {
                return Err(ReplicationError::Invalid(format!(
                    "active secret {} placement references missing project {project_id}",
                    secret.entity_id()
                )));
            }
            for environment_id in environment_ids {
                match environment_projects.get(environment_id.as_str()) {
                    Some(owner) if *owner == project_id.as_str() => {}
                    Some(_) => {
                        return Err(ReplicationError::Invalid(format!(
                            "active secret {} placement environment {environment_id} does not belong to project {project_id}",
                            secret.entity_id()
                        )));
                    }
                    None => {
                        return Err(ReplicationError::Invalid(format!(
                            "active secret {} placement references missing environment {environment_id}",
                            secret.entity_id()
                        )));
                    }
                }
            }
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
            .map(|document| EntityChange::new(document, Vec::new(), Vec::new()).unwrap())
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

        let encoded = plan.encode().unwrap();
        let decoded = LocalProjectionPlan::decode(&encoded).unwrap();
        assert_eq!(decoded, plan);
        assert_eq!(decoded.plan_id().unwrap(), plan.plan_id().unwrap());
        assert_eq!(plan.plan_id().unwrap().len(), 64);
        assert!(!String::from_utf8(encoded)
            .unwrap()
            .contains("private fixture"));
    }

    #[test]
    fn decoding_rejects_a_projection_whose_heads_do_not_match_documents() {
        let (_directory, store, cryptor, journal) = fixture();
        let secret_id = store
            .put(NewSecret::managed("Fixture"), b"private fixture")
            .unwrap();
        queue(
            &cryptor,
            &journal,
            vec![ReplicatedEntityDocument::Secret(
                SecretEntityDocument::from_store(
                    &store,
                    &secret_id,
                    EntityLifecycle::Active,
                )
                .unwrap(),
            )],
        );
        let plan =
            LocalProjectionPlan::build(&cryptor, &journal.projection_records().unwrap()).unwrap();
        let mut document = plan.document.clone();
        document.head_revisions.clear();

        let error = LocalProjectionPlan::decode(&serde_json::to_vec(&document).unwrap())
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("heads do not match its entity documents"));
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
