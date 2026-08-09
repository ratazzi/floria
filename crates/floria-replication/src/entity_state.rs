//! Portable entity states projected from the local catalog.
//!
//! The catalog remains one validated local projection, but replication addresses each logical
//! row independently. This module owns that conversion so transports and the daemon never need to
//! know reference ordering, archive filtering, or how prefixed catalog ids become record UUIDs.

use std::collections::BTreeMap;

use floria_catalog::{
    validate_replicated_catalog, Binding, Environment, ReplicatedCatalog, ReplicatedProject,
    ReplicatedSurface, Resource,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity_document::EntityLifecycle;
use crate::{ReplicationError, ReplicationResult};

const ENTITY_STATE_FORMAT_VERSION: u32 = 1;
const CATALOG_ENTITY_NAMESPACE: Uuid = Uuid::from_u128(0x87f289e7_9cbf_4ede_bca2_1f320e99a975);

/// One complete portable catalog row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CatalogEntityState {
    Project(ReplicatedProject),
    Environment(Environment),
    Resource(Resource),
    Binding(Binding),
    Surface(ReplicatedSurface),
}

impl CatalogEntityState {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Project(_) => "project",
            Self::Environment(_) => "environment",
            Self::Resource(_) => "resource",
            Self::Binding(_) => "binding",
            Self::Surface(_) => "surface",
        }
    }

    pub fn catalog_id(&self) -> &str {
        match self {
            Self::Project(project) => &project.id,
            Self::Environment(environment) => &environment.id,
            Self::Resource(resource) => &resource.id,
            Self::Binding(binding) => &binding.id,
            Self::Surface(surface) => &surface.id,
        }
    }

    /// Stable record identity derived from the existing portable catalog identity.
    pub fn entity_id(&self) -> String {
        let name = format!("{}/{}", self.kind(), self.catalog_id());
        Uuid::new_v5(&CATALOG_ENTITY_NAMESPACE, name.as_bytes()).to_string()
    }
}

/// The encrypted state carried by one [`crate::record::EntityRevision`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntityDocument {
    format_version: u32,
    entity_id: String,
    lifecycle: EntityLifecycle,
    state: CatalogEntityState,
}

impl CatalogEntityDocument {
    pub fn active(state: CatalogEntityState) -> Self {
        Self {
            format_version: ENTITY_STATE_FORMAT_VERSION,
            entity_id: state.entity_id(),
            lifecycle: EntityLifecycle::Active,
            state,
        }
    }

    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    pub fn lifecycle(&self) -> EntityLifecycle {
        self.lifecycle
    }

    pub fn state(&self) -> &CatalogEntityState {
        &self.state
    }

    /// Produce the complete archived state for a later revision of the same entity.
    pub fn archived(mut self) -> Self {
        self.lifecycle = EntityLifecycle::Archived;
        self
    }

    /// Produce the complete active state for a later restore revision.
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
        if self.format_version != ENTITY_STATE_FORMAT_VERSION {
            return Err(ReplicationError::Invalid(format!(
                "unsupported catalog entity state format {}",
                self.format_version
            )));
        }
        let expected = self.state.entity_id();
        if self.entity_id != expected {
            return Err(ReplicationError::Invalid(format!(
                "catalog entity {} does not match its {} state identity {}",
                self.entity_id,
                self.state.kind(),
                expected
            )));
        }
        Ok(())
    }
}

/// Validated current heads for portable catalog entities.
///
/// Construction validates both the retained full graph and its active projection. This lets an
/// archived entity keep restorable state while ensuring an active entity never refers to an
/// archived dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogEntitySet {
    documents: BTreeMap<String, CatalogEntityDocument>,
}

impl CatalogEntitySet {
    pub fn from_catalog(catalog: &ReplicatedCatalog) -> ReplicationResult<Self> {
        validate_replicated_catalog(catalog)?;
        let documents = catalog
            .projects
            .iter()
            .cloned()
            .map(CatalogEntityState::Project)
            .chain(
                catalog
                    .environments
                    .iter()
                    .cloned()
                    .map(CatalogEntityState::Environment),
            )
            .chain(
                catalog
                    .resources
                    .iter()
                    .cloned()
                    .map(CatalogEntityState::Resource),
            )
            .chain(
                catalog
                    .bindings
                    .iter()
                    .cloned()
                    .map(CatalogEntityState::Binding),
            )
            .chain(
                catalog
                    .surfaces
                    .iter()
                    .cloned()
                    .map(CatalogEntityState::Surface),
            )
            .map(CatalogEntityDocument::active)
            .collect::<Vec<_>>();
        Self::from_documents(documents)
    }

    pub fn from_documents(
        documents: impl IntoIterator<Item = CatalogEntityDocument>,
    ) -> ReplicationResult<Self> {
        let mut indexed = BTreeMap::new();
        for document in documents {
            document.validate()?;
            let entity_id = document.entity_id.clone();
            if indexed.insert(entity_id.clone(), document).is_some() {
                return Err(ReplicationError::Invalid(format!(
                    "catalog entity {entity_id} appears more than once"
                )));
            }
        }
        let entity_set = Self { documents: indexed };
        entity_set.validate_projection(false)?;
        entity_set.validate_projection(true)?;
        Ok(entity_set)
    }

    pub fn documents(&self) -> impl ExactSizeIterator<Item = &CatalogEntityDocument> {
        self.documents.values()
    }

    /// Rebuild the catalog state visible to this device from active entity heads.
    pub fn active_catalog(&self) -> ReplicationResult<ReplicatedCatalog> {
        self.project(true)
    }

    fn validate_projection(&self, active_only: bool) -> ReplicationResult<()> {
        let projection = self.project(active_only)?;
        validate_replicated_catalog(&projection)?;
        Ok(())
    }

    fn project(&self, active_only: bool) -> ReplicationResult<ReplicatedCatalog> {
        let mut catalog = ReplicatedCatalog::default();
        for document in self.documents.values() {
            if active_only && document.lifecycle == EntityLifecycle::Archived {
                continue;
            }
            match &document.state {
                CatalogEntityState::Project(project) => catalog.projects.push(project.clone()),
                CatalogEntityState::Environment(environment) => {
                    catalog.environments.push(environment.clone())
                }
                CatalogEntityState::Resource(resource) => catalog.resources.push(resource.clone()),
                CatalogEntityState::Binding(binding) => catalog.bindings.push(binding.clone()),
                CatalogEntityState::Surface(surface) => catalog.surfaces.push(surface.clone()),
            }
        }
        Ok(catalog)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use floria_catalog::{
        BindingScope, EntrySelection, EntrySpec, FileBacking, ItemMetadata, ResourceCodec,
        ResourceKind, ResourceOrigin, ResourceSource, SurfaceFormat, SurfaceInput, SurfaceKind,
        ValueShape,
    };
    use floria_core::authz::Enforcement;

    use super::*;

    fn source_catalog() -> ReplicatedCatalog {
        let project_id = "project-11111111-1111-4111-8111-111111111111".to_string();
        let environment_id = "environment-22222222-2222-4222-8222-222222222222".to_string();
        let resource_id = "resource-33333333-3333-4333-8333-333333333333".to_string();
        let binding_id = "binding-44444444-4444-4444-8444-444444444444".to_string();
        ReplicatedCatalog {
            format_version: 1,
            projects: vec![ReplicatedProject {
                id: project_id.clone(),
                name: "Fixture".to_string(),
                default_environment_id: Some(environment_id.clone()),
            }],
            environments: vec![Environment {
                id: environment_id.clone(),
                project_id: project_id.clone(),
                name: "Development".to_string(),
                position: 0,
            }],
            resources: vec![Resource {
                id: resource_id.clone(),
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
                source: ResourceSource::SecretRef {
                    secret_id: "55555555-5555-4555-8555-555555555555".to_string(),
                },
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
                origin: ResourceOrigin::default(),
            }],
            bindings: vec![Binding {
                id: binding_id.clone(),
                project_id,
                scope: BindingScope::Common,
                resource_id,
                selection: EntrySelection::All,
                key_override: None,
                enabled: true,
                allow_override: false,
                position: 0,
            }],
            surfaces: vec![ReplicatedSurface {
                id: "surface-66666666-6666-4666-8666-666666666666".to_string(),
                environment_id,
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                relative_path: Some(PathBuf::from(".env")),
                input: SurfaceInput::Bindings {
                    binding_ids: vec![binding_id],
                },
                enforcement: Enforcement::Prompt,
                position: 0,
            }],
        }
    }

    #[test]
    fn catalog_round_trip_is_split_into_stable_independent_entities() {
        let source = source_catalog();
        let entities = CatalogEntitySet::from_catalog(&source).unwrap();
        assert_eq!(entities.documents().len(), 5);
        assert_eq!(entities.active_catalog().unwrap(), source);

        let first = entities.documents().next().unwrap();
        let decoded = CatalogEntityDocument::decode(&first.encode().unwrap()).unwrap();
        assert_eq!(&decoded, first);
        assert_eq!(decoded.entity_id(), decoded.state().entity_id());
    }

    #[test]
    fn entity_identity_is_independent_of_order_and_device() {
        let source = source_catalog();
        let first = CatalogEntitySet::from_catalog(&source).unwrap();
        let second = CatalogEntitySet::from_catalog(&source).unwrap();
        assert_eq!(
            first.documents().map(|entity| entity.entity_id()).collect::<Vec<_>>(),
            second.documents().map(|entity| entity.entity_id()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn archived_unused_entity_is_retained_but_not_projected() {
        let mut source = source_catalog();
        source.bindings.clear();
        source.surfaces.clear();
        let mut documents = CatalogEntitySet::from_catalog(&source)
            .unwrap()
            .documents()
            .cloned()
            .collect::<Vec<_>>();
        let resource = documents
            .iter_mut()
            .find(|document| matches!(document.state(), CatalogEntityState::Resource(_)))
            .unwrap();
        *resource = resource.clone().archived();

        let entities = CatalogEntitySet::from_documents(documents).unwrap();
        assert_eq!(entities.documents().len(), 3);
        assert!(entities.active_catalog().unwrap().resources.is_empty());
    }

    #[test]
    fn active_entity_cannot_reference_an_archived_dependency() {
        let source = source_catalog();
        let documents = CatalogEntitySet::from_catalog(&source)
            .unwrap()
            .documents()
            .cloned()
            .map(|document| {
                if matches!(document.state(), CatalogEntityState::Resource(_)) {
                    document.archived()
                } else {
                    document
                }
            })
            .collect::<Vec<_>>();

        let error = CatalogEntitySet::from_documents(documents).unwrap_err();
        assert!(error.to_string().contains("invalid owner, resource"));
    }

    #[test]
    fn decode_rejects_entity_id_substitution() {
        let document = CatalogEntitySet::from_catalog(&source_catalog())
            .unwrap()
            .documents()
            .next()
            .unwrap()
            .clone();
        let mut encoded: serde_json::Value = serde_json::from_slice(&document.encode().unwrap()).unwrap();
        encoded["entity_id"] = serde_json::Value::String(Uuid::new_v4().to_string());
        let encoded = serde_json::to_vec(&encoded).unwrap();

        assert!(CatalogEntityDocument::decode(&encoded)
            .unwrap_err()
            .to_string()
            .contains("does not match"));
    }
}
