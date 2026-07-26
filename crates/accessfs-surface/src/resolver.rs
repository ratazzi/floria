use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use accessfs_catalog::{
    resolve_catalog_surface, Binding, BindingScope, Catalog, CatalogSnapshot, EntrySelection,
    FileBacking, FormatInputModel, FormatSpec, Resource, ResourceSource, SurfaceInput, SurfaceKind,
    ValueShape,
};
use accessfs_core::audit::AuditDependency;
use accessfs_store::{SecretId, SecretStore};

use crate::codec::{codec_capabilities, decode_resource as decode_resource_bytes, DecodedEntry};
use crate::error::{SurfaceError, SurfaceResult};
use crate::render::{
    renderer_for, ResolvedBindingEntry, ResolvedDocument, ResolvedEntryMeta,
    ResolvedEnvironmentEntry,
};

type FrozenSecretVersions = HashMap<String, (SecretId, u32)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenResourceVersion {
    pub resource_id: String,
    pub secret_id: String,
    pub version: u32,
}

/// The immutable result of resolving one composed surface for a process access session.
#[derive(Debug)]
pub struct SurfaceSnapshot {
    pub bytes: Vec<u8>,
    pub versions: Vec<FrozenResourceVersion>,
    pub entries: Vec<ResolvedEntryMeta>,
}

#[derive(Debug)]
pub struct DirectEnvFileSnapshot {
    pub bytes: Vec<u8>,
    pub resource_id: String,
    pub secret_id: String,
    pub version: u32,
    pub keys: Vec<String>,
}

impl SurfaceSnapshot {
    pub fn audit_dependencies(&self) -> Vec<AuditDependency> {
        let versions: HashMap<&str, &FrozenResourceVersion> = self
            .versions
            .iter()
            .map(|version| (version.resource_id.as_str(), version))
            .collect();
        self.entries
            .iter()
            .map(|entry| {
                let version = versions.get(entry.resource_id.as_str()).copied();
                AuditDependency {
                    key: entry.audit_key.clone(),
                    binding_id: entry.binding_id.clone(),
                    resource_id: entry.resource_id.clone(),
                    secret_id: version.map(|version| version.secret_id.clone()),
                    version: version.map(|version| version.version),
                }
            })
            .collect()
    }
}

impl DirectEnvFileSnapshot {
    pub fn audit_dependencies(&self, surface_id: &str) -> Vec<AuditDependency> {
        self.keys
            .iter()
            .map(|key| AuditDependency {
                key: key.clone(),
                binding_id: format!("direct:{surface_id}"),
                resource_id: self.resource_id.clone(),
                secret_id: Some(self.secret_id.clone()),
                version: Some(self.version),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectEnvFileCommit {
    pub resource_id: String,
    pub secret_id: String,
    pub version: u32,
}

struct DirectEnvFileTarget {
    resource: Resource,
    secret_id: String,
}

#[derive(Clone)]
pub struct SurfaceResolver {
    catalog: Catalog,
    store: Arc<dyn SecretStore>,
}

impl SurfaceResolver {
    pub fn new(catalog: Catalog, store: Arc<dyn SecretStore>) -> Self {
        SurfaceResolver { catalog, store }
    }

    /// Resolve any composed file surface into one process access-session snapshot. Every
    /// referenced secret head is frozen before the first secret is decrypted.
    pub fn render_surface(&self, surface_id: &str) -> SurfaceResult<SurfaceSnapshot> {
        let snapshot = self.catalog.snapshot()?;
        let surface = snapshot
            .surfaces
            .iter()
            .find(|surface| surface.id == surface_id)
            .ok_or_else(|| SurfaceError::NotFound(surface_id.to_string()))?;
        let SurfaceKind::File(FileBacking::Composed(format)) = surface.kind else {
            return Err(SurfaceError::UnsupportedSurface {
                surface_id: surface_id.to_string(),
                kind: format!("{:?}", surface.kind),
            });
        };
        let spec = format.spec();
        let (document, versions) = match spec.input {
            FormatInputModel::EnvironmentProjection => {
                self.resolve_environment_document(&snapshot, surface_id)?
            }
            FormatInputModel::StructuredEntries { .. }
            | FormatInputModel::KeylessScalars { .. } => {
                self.resolve_binding_document(&snapshot, surface, spec)?
            }
        };
        let rendered = renderer_for(format).render(document)?;
        Ok(SurfaceSnapshot {
            bytes: rendered.bytes,
            versions,
            entries: rendered.entries,
        })
    }

    fn resolve_environment_document(
        &self,
        snapshot: &CatalogSnapshot,
        surface_id: &str,
    ) -> SurfaceResult<(ResolvedDocument, Vec<FrozenResourceVersion>)> {
        let exports = resolve_catalog_surface(snapshot, surface_id)?;
        let resources: HashMap<&str, &Resource> = snapshot
            .resources
            .iter()
            .map(|resource| (resource.id.as_str(), resource))
            .collect();
        let (frozen, versions) = self.freeze_versions(
            snapshot,
            exports.iter().map(|export| export.resource_id.as_str()),
        )?;
        let mut resource_values: HashMap<String, Vec<DecodedEntry>> = HashMap::new();
        for export in &exports {
            if resource_values.contains_key(&export.resource_id) {
                continue;
            }
            let resource = resources
                .get(export.resource_id.as_str())
                .ok_or_else(|| SurfaceError::NotFound(format!("resource {}", export.resource_id)))?;
            let values = self.decode_resource(resource, frozen.get(&resource.id))?;
            resource_values.insert(resource.id.clone(), values);
        }

        let mut entries = Vec::with_capacity(exports.len());
        for export in exports {
            let value = resource_values
                .get(&export.resource_id)
                .and_then(|values| {
                    values.iter().find(|entry| entry.address == export.source_key)
                })
                .ok_or_else(|| SurfaceError::MissingKey {
                    resource_id: export.resource_id.clone(),
                    key: export.source_key.clone(),
                })?;
            entries.push(ResolvedEnvironmentEntry {
                export_key: export.key,
                source_address: export.source_key,
                binding_id: export.binding_id,
                resource_id: export.resource_id,
                value: value.value.clone(),
            });
        }
        Ok((ResolvedDocument::Environment(entries), versions))
    }

    fn resolve_binding_document(
        &self,
        snapshot: &CatalogSnapshot,
        surface: &accessfs_catalog::Surface,
        spec: FormatSpec,
    ) -> SurfaceResult<(ResolvedDocument, Vec<FrozenResourceVersion>)> {
        let environment = snapshot
            .environments
            .iter()
            .find(|environment| environment.id == surface.environment_id)
            .ok_or_else(|| {
                SurfaceError::NotFound(format!("environment {}", surface.environment_id))
            })?;
        let SurfaceInput::Bindings { binding_ids } = &surface.input else {
            return Err(SurfaceError::IncompatibleResource {
                resource_id: "<surface-input>".to_string(),
                reason: "composed file surface requires explicit binding input".to_string(),
            });
        };
        let resources: HashMap<&str, &Resource> = snapshot
            .resources
            .iter()
            .map(|resource| (resource.id.as_str(), resource))
            .collect();
        let mut bindings = Vec::new();
        for binding_id in binding_ids {
            let binding = snapshot
                .bindings
                .iter()
                .find(|binding| binding.id == *binding_id)
                .ok_or_else(|| SurfaceError::NotFound(format!("binding {binding_id}")))?;
            let applies = binding.project_id == environment.project_id
                && match &binding.scope {
                    BindingScope::Common => true,
                    BindingScope::Environment { environment_id } => {
                        environment_id == &environment.id
                    }
                };
            if !applies {
                return Err(SurfaceError::IncompatibleResource {
                    resource_id: binding.resource_id.clone(),
                    reason: format!("binding {binding_id:?} does not apply to this surface"),
                });
            }
            if !binding.enabled {
                continue;
            }
            let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
                SurfaceError::NotFound(format!("resource {}", binding.resource_id))
            })?;
            validate_binding_input(spec, binding, resource)?;
            bindings.push(binding);
        }
        bindings.sort_by_key(|binding| {
            let scope_order = match binding.scope {
                BindingScope::Common => 0,
                BindingScope::Environment { .. } => 1,
            };
            (scope_order, binding.position, binding.id.as_str())
        });

        let (frozen, versions) = self.freeze_versions(
            snapshot,
            bindings
                .iter()
                .map(|binding| binding.resource_id.as_str()),
        )?;
        let mut decoded_resources = HashMap::new();
        let mut entries = Vec::new();
        for binding in bindings {
            let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
                SurfaceError::NotFound(format!("resource {}", binding.resource_id))
            })?;
            if !decoded_resources.contains_key(&resource.id) {
                let decoded = self.decode_resource(resource, frozen.get(&resource.id))?;
                decoded_resources.insert(resource.id.clone(), decoded);
            }
            let decoded = decoded_resources.get(&resource.id).ok_or_else(|| {
                SurfaceError::NotFound(format!("decoded resource {}", resource.id))
            })?;
            for entry in decoded
                .iter()
                .filter(|entry| selection_contains(&binding.selection, &entry.address))
            {
                entries.push(ResolvedBindingEntry {
                    address: entry.address.clone(),
                    key: entry.key.clone(),
                    section: entry.section.clone(),
                    binding_id: binding.id.clone(),
                    resource_id: resource.id.clone(),
                    value: entry.value.clone(),
                });
            }
        }
        Ok((ResolvedDocument::Bindings(entries), versions))
    }

    /// Read one directly linked EnvFile from an immutable store version. Unlike a composed
    /// dotenv surface, the original bytes are preserved so comments and quoting survive edits.
    pub fn read_direct_env_file(&self, surface_id: &str) -> SurfaceResult<DirectEnvFileSnapshot> {
        let snapshot = self.catalog.snapshot()?;
        let target = direct_env_file_target(&snapshot, surface_id)?;
        let id: SecretId = target.secret_id.parse()?;
        let record = self
            .store
            .record(&id)?
            .ok_or_else(|| SurfaceError::NotFound(format!("secret {}", target.secret_id)))?;
        let plaintext = self.store.get_version(&id, record.current_version)?;
        let keys = validate_direct_env_file(&target.resource, &plaintext)?;
        Ok(DirectEnvFileSnapshot {
            bytes: plaintext.to_vec(),
            resource_id: target.resource.id,
            secret_id: target.secret_id,
            version: record.current_version,
            keys,
        })
    }

    /// Validate and append a new immutable version for a directly linked EnvFile. The catalog
    /// owns the key schema, so a normal file save may change values and formatting but cannot
    /// silently add or remove keys used by downstream bindings.
    pub fn commit_direct_env_file(
        &self,
        surface_id: &str,
        bytes: &[u8],
    ) -> SurfaceResult<DirectEnvFileCommit> {
        let snapshot = self.catalog.snapshot()?;
        let target = direct_env_file_target(&snapshot, surface_id)?;
        let id: SecretId = target.secret_id.parse()?;
        let version = crate::codec::commit_secret_version(
            Some(&self.catalog),
            self.store.as_ref(),
            &id,
            bytes,
        )?;
        Ok(DirectEnvFileCommit {
            resource_id: target.resource.id,
            secret_id: target.secret_id,
            version,
        })
    }

    fn freeze_versions<'a>(
        &self,
        snapshot: &CatalogSnapshot,
        resource_ids: impl IntoIterator<Item = &'a str>,
    ) -> SurfaceResult<(FrozenSecretVersions, Vec<FrozenResourceVersion>)> {
        let resources: HashMap<&str, &Resource> = snapshot
            .resources
            .iter()
            .map(|resource| (resource.id.as_str(), resource))
            .collect();
        let mut seen = HashSet::new();
        let mut frozen = HashMap::new();
        let mut versions = Vec::new();
        for resource_id in resource_ids {
            if !seen.insert(resource_id) {
                continue;
            }
            let resource = resources
                .get(resource_id)
                .ok_or_else(|| SurfaceError::NotFound(format!("resource {resource_id}")))?;
            let ResourceSource::SecretRef { secret_id } = &resource.source else {
                continue;
            };
            let id: SecretId = secret_id.parse()?;
            let record = self
                .store
                .record(&id)?
                .ok_or_else(|| SurfaceError::NotFound(format!("secret {secret_id}")))?;
            frozen.insert(resource.id.clone(), (id, record.current_version));
            versions.push(FrozenResourceVersion {
                resource_id: resource.id.clone(),
                secret_id: secret_id.clone(),
                version: record.current_version,
            });
        }
        Ok((frozen, versions))
    }

    fn decode_resource(
        &self,
        resource: &Resource,
        frozen: Option<&(SecretId, u32)>,
    ) -> SurfaceResult<Vec<DecodedEntry>> {
        match &resource.source {
            ResourceSource::SecretRef { .. } => {
                let (id, version) = frozen.ok_or_else(|| {
                    SurfaceError::NotFound(format!(
                        "frozen version for resource {}",
                        resource.id
                    ))
                })?;
                let plaintext = self.store.get_version(id, *version)?;
                decode_resource_bytes(resource, &plaintext)
            }
            ResourceSource::Literal { value } => decode_resource_bytes(resource, value.as_bytes()),
            _ => Err(SurfaceError::IncompatibleResource {
                resource_id: resource.id.clone(),
                reason: "source cannot be decoded by a file projection".to_string(),
            }),
        }
    }
}

fn validate_binding_input(
    spec: FormatSpec,
    binding: &Binding,
    resource: &Resource,
) -> SurfaceResult<()> {
    let compatible = match spec.input {
        FormatInputModel::EnvironmentProjection => false,
        FormatInputModel::StructuredEntries {
            required_kind,
            required_shape,
            required_codec,
            stored_only,
        } => {
            resource.kind == required_kind
                && resource.shape == required_shape
                && resource.codec == required_codec
                && (spec.allow_key_override || binding.key_override.is_none())
                && (!stored_only || matches!(resource.source, ResourceSource::SecretRef { .. }))
        }
        FormatInputModel::KeylessScalars {
            required_codec,
            allow_literal,
        } => {
            resource.shape == ValueShape::Scalar
                && resource.codec == required_codec
                && resource.entries.len() == 1
                && resource.entries[0].key.is_none()
                && (spec.allow_key_override || binding.key_override.is_none())
                && selection_contains(&binding.selection, &resource.entries[0].address)
                && matches!(
                    (&resource.source, allow_literal),
                    (ResourceSource::SecretRef { .. }, _)
                        | (ResourceSource::Literal { .. }, true)
                )
        }
    };
    if !compatible {
        return Err(SurfaceError::IncompatibleResource {
            resource_id: resource.id.clone(),
            reason: format!(
                "binding {:?} does not satisfy the surface format input contract",
                binding.id
            ),
        });
    }
    Ok(())
}

fn selection_contains(selection: &EntrySelection, address: &str) -> bool {
    match selection {
        EntrySelection::All => true,
        EntrySelection::Entries { addresses } => addresses.iter().any(|item| item == address),
    }
}

fn direct_env_file_target(
    snapshot: &CatalogSnapshot,
    surface_id: &str,
) -> SurfaceResult<DirectEnvFileTarget> {
    let surface = snapshot
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .ok_or_else(|| SurfaceError::NotFound(surface_id.to_string()))?;
    if surface.kind != SurfaceKind::File(FileBacking::EnvFileDirect) {
        return Err(SurfaceError::UnsupportedSurface {
            surface_id: surface_id.to_string(),
            kind: format!("{:?}", surface.kind),
        });
    }
    let SurfaceInput::Resource { resource_id } = &surface.input else {
        return Err(SurfaceError::IncompatibleResource {
            resource_id: "<surface-input>".to_string(),
            reason: "env_file_direct surface requires one resource input".to_string(),
        });
    };
    let resource = snapshot
        .resources
        .iter()
        .find(|resource| resource.id == *resource_id)
        .ok_or_else(|| SurfaceError::NotFound(format!("resource {resource_id}")))?
        .clone();
    let secret_id = match &resource.source {
        ResourceSource::SecretRef { secret_id } => secret_id.clone(),
        _ => {
            return Err(SurfaceError::IncompatibleResource {
                resource_id: resource.id.clone(),
                reason: "direct EnvFile must reference a stored secret".to_string(),
            });
        }
    };
    Ok(DirectEnvFileTarget { resource, secret_id })
}

fn validate_direct_env_file(resource: &Resource, bytes: &[u8]) -> SurfaceResult<Vec<String>> {
    if !codec_capabilities(resource.codec).raw_writeback {
        return Err(SurfaceError::IncompatibleResource {
            resource_id: resource.id.clone(),
            reason: format!("codec {:?} does not support raw writeback", resource.codec),
        });
    }
    let decoded = decode_resource_bytes(resource, bytes)?;
    Ok(decoded.into_iter().filter_map(|entry| entry.key).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use accessfs_catalog::{
        Binding, BindingScope, EntrySelection, EntrySpec, Environment, Project,
        ResourceCodec, ResourceKind, Surface, SurfaceFormat,
    };
    use accessfs_store::{NewSecret, SecretOrigin, SecretRecord, StoreResult, VersionRecord};
    use std::path::{Path, PathBuf};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    use zeroize::Zeroizing;

    const TOKEN_ID: &str = "00000000-0000-0000-0000-000000000001";
    const ENV_FILE_ID: &str = "00000000-0000-0000-0000-000000000002";
    const LINE_ONE_ID: &str = "00000000-0000-0000-0000-000000000003";
    const LINE_TWO_ID: &str = "00000000-0000-0000-0000-000000000004";
    const INI_FILE_ID: &str = "00000000-0000-0000-0000-000000000005";
    const INI_COMMON_ID: &str = "00000000-0000-0000-0000-000000000006";
    const INI_ROOT_ID: &str = "00000000-0000-0000-0000-000000000007";

    struct FixtureStore {
        entries: Mutex<HashMap<String, (u32, Vec<Vec<u8>>)>>,
        requested_versions: Mutex<Vec<(String, u32)>>,
    }

    impl FixtureStore {
        fn new() -> Self {
            FixtureStore {
                entries: Mutex::new(HashMap::from([
                    (
                        TOKEN_ID.to_string(),
                        (2, vec![b"old-fixture-value".to_vec(), b"fixture-token-value".to_vec()]),
                    ),
                    (
                        ENV_FILE_ID.to_string(),
                        (1, vec![b"API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n".to_vec()]),
                    ),
                    (
                        LINE_ONE_ID.to_string(),
                        (1, vec![b"db-one.fixture.invalid|5432|app|fixture-user|fixture-pass-one".to_vec()]),
                    ),
                    (
                        LINE_TWO_ID.to_string(),
                        (1, vec![b"db-two.fixture.invalid|5432|app|fixture-user|fixture-pass-two".to_vec()]),
                    ),
                    (
                        INI_FILE_ID.to_string(),
                        (
                            1,
                            vec![b"[fixture-development]\nREGION=fixture-region-one\nOUTPUT=fixture-json\n[fixture-staging]\nREGION=fixture-region-two\nOUTPUT=fixture-text\n".to_vec()],
                        ),
                    ),
                    (
                        INI_COMMON_ID.to_string(),
                        (
                            1,
                            vec![b"[common]\nCOMMON=common-value\n".to_vec()],
                        ),
                    ),
                    (
                        INI_ROOT_ID.to_string(),
                        (1, vec![b"ROOT=root-value\n".to_vec()]),
                    ),
                ])),
                requested_versions: Mutex::new(Vec::new()),
            }
        }
    }

    impl SecretStore for FixtureStore {
        fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
            self.requested_versions
                .lock()
                .unwrap()
                .push((id.to_string(), version));
            let entries = self.entries.lock().unwrap();
            let (_, versions) = entries.get(id.as_str()).unwrap();
            Ok(Zeroizing::new(versions[(version - 1) as usize].clone()))
        }

        fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            Ok(entries.get(id.as_str()).map(|(head, versions)| SecretRecord {
                id: id.clone(),
                origin: SecretOrigin::File {
                    source_path: PathBuf::from("/fixture/source"),
                },
                mode: 0o600,
                size: versions[(*head - 1) as usize].len() as u64,
                created: "fixture-time".to_string(),
                current_version: *head,
                enforcement: Default::default(),
                metadata: Default::default(),
            }))
        }

        fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            let (head, versions) = entries.get(id.as_str()).unwrap();
            Ok(Zeroizing::new(versions[(*head - 1) as usize].clone()))
        }
        fn put(&self, _meta: NewSecret, _plaintext: &[u8]) -> StoreResult<SecretId> {
            unimplemented!()
        }
        fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
            let mut entries = self.entries.lock().unwrap();
            let (head, versions) = entries.get_mut(id.as_str()).unwrap();
            versions.push(plaintext.to_vec());
            *head = versions.len() as u32;
            Ok(*head)
        }
        fn history(&self, _id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            unimplemented!()
        }
        fn set_head(&self, _id: &SecretId, _version: u32) -> StoreResult<()> {
            unimplemented!()
        }
        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            unimplemented!()
        }
        fn get_by_path(&self, _source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            unimplemented!()
        }
        fn update_settings(
            &self,
            _id: &SecretId,
            _metadata: accessfs_core::metadata::ItemMetadata,
            _enforcement: accessfs_core::authz::Enforcement,
        ) -> StoreResult<()> {
            unimplemented!()
        }
        fn delete(&self, _id: &SecretId) -> StoreResult<()> {
            unimplemented!()
        }
    }

    struct AdvancingStore {
        inner: FixtureStore,
        advanced: AtomicBool,
        events: Mutex<Vec<String>>,
    }

    impl AdvancingStore {
        fn new() -> Self {
            AdvancingStore {
                inner: FixtureStore::new(),
                advanced: AtomicBool::new(false),
                events: Mutex::new(Vec::new()),
            }
        }
    }

    impl SecretStore for AdvancingStore {
        fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("get_version:{id}:{version}"));
            if !self.advanced.swap(true, Ordering::SeqCst) {
                let mut entries = self.inner.entries.lock().unwrap();
                let (head, versions) = entries.get_mut(ENV_FILE_ID).unwrap();
                versions.push(b"API_HOST=http://advanced.invalid\nLOG_LEVEL=trace\n".to_vec());
                *head = versions.len() as u32;
            }
            self.inner.get_version(id, version)
        }

        fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            self.events.lock().unwrap().push(format!("record:{id}"));
            self.inner.record(id)
        }

        fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            self.inner.get(id)
        }

        fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId> {
            self.inner.put(meta, plaintext)
        }

        fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
            self.inner.append_version(id, plaintext)
        }

        fn history(&self, id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            self.inner.history(id)
        }

        fn set_head(&self, id: &SecretId, version: u32) -> StoreResult<()> {
            self.inner.set_head(id, version)
        }

        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            self.inner.list()
        }

        fn get_by_path(&self, source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            self.inner.get_by_path(source_path)
        }

        fn update_settings(
            &self,
            id: &SecretId,
            metadata: accessfs_core::metadata::ItemMetadata,
            enforcement: accessfs_core::authz::Enforcement,
        ) -> StoreResult<()> {
            self.inner.update_settings(id, metadata, enforcement)
        }

        fn delete(&self, id: &SecretId) -> StoreResult<()> {
            self.inner.delete(id)
        }
    }

    fn add_resource(catalog: &Catalog, resource: Resource) {
        catalog.upsert_resource(&resource).unwrap();
    }

    fn bind(catalog: &Catalog, id: &str, resource_id: &str, position: i64) {
        catalog
            .upsert_binding(&Binding {
                id: id.to_string(),
                project_id: "fixture-project".to_string(),
                scope: BindingScope::Environment {
                    environment_id: "fixture-development".to_string(),
                },
                resource_id: resource_id.to_string(),
                key_override: None,
                selection: EntrySelection::All,
                enabled: true,
                allow_override: false,
                position,
            })
            .unwrap();
    }

    fn fixture_catalog(path: &Path) -> Catalog {
        let catalog = Catalog::open(path).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture Project".to_string(),
                path: PathBuf::from("/fixture/project"),
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            })
            .unwrap();

        add_resource(
            &catalog,
            Resource {
                id: "fixture-token".to_string(),
                name: "Fixture Token".to_string(),
                kind: ResourceKind::SharedSecret,
                shape: ValueShape::Scalar,
                codec: ResourceCodec::Opaque,
                default_env_key: Some("SERVICE_TOKEN".to_string()),
                entries: vec![EntrySpec {
                    address: "value".to_string(),
                    label: "Fixture Token".to_string(),
                    key: Some("SERVICE_TOKEN".to_string()),
                    sensitive: true,
                }],
                source: ResourceSource::SecretRef { secret_id: TOKEN_ID.to_string() },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        add_resource(
            &catalog,
            Resource {
                id: "fixture-env-file".to_string(),
                name: "Fixture Env File".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Dotenv,
                default_env_key: None,
                entries: vec![
                    EntrySpec {
                        address: "keys/API_HOST".to_string(),
                        label: "API_HOST".to_string(),
                        key: Some("API_HOST".to_string()),
                        sensitive: false,
                    },
                    EntrySpec {
                        address: "keys/LOG_LEVEL".to_string(),
                        label: "LOG_LEVEL".to_string(),
                        key: Some("LOG_LEVEL".to_string()),
                        sensitive: false,
                    },
                ],
                source: ResourceSource::SecretRef { secret_id: ENV_FILE_ID.to_string() },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        add_resource(
            &catalog,
            Resource {
                id: "fixture-mode".to_string(),
                name: "Fixture Mode".to_string(),
                kind: ResourceKind::Literal,
                shape: ValueShape::Scalar,
                codec: ResourceCodec::Opaque,
                default_env_key: Some("APP_ENV".to_string()),
                entries: vec![EntrySpec {
                    address: "value".to_string(),
                    label: "APP_ENV".to_string(),
                    key: Some("APP_ENV".to_string()),
                    sensitive: false,
                }],
                source: ResourceSource::Literal { value: "development".to_string() },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        bind(&catalog, "fixture-token-binding", "fixture-token", 0);
        bind(&catalog, "fixture-env-binding", "fixture-env-file", 1);
        bind(&catalog, "fixture-mode-binding", "fixture-mode", 2);
        catalog
            .upsert_surface(&Surface {
                id: "fixture-dotenv".to_string(),
                environment_id: "fixture-development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: PathBuf::from("/fixture/project/.env"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec![
                        "fixture-token-binding".to_string(),
                        "fixture-env-binding".to_string(),
                        "fixture-mode-binding".to_string(),
                    ],
                },
                enforcement: accessfs_core::authz::Enforcement::Prompt,
                position: 0,
            })
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-direct-env".to_string(),
                environment_id: "fixture-development".to_string(),
                name: ".env.source".to_string(),
                kind: SurfaceKind::File(FileBacking::EnvFileDirect),
                path: PathBuf::from("/fixture/project/.env.source"),
                input: SurfaceInput::Resource {
                    resource_id: "fixture-env-file".to_string(),
                },
                enforcement: accessfs_core::authz::Enforcement::Prompt,
                position: 1,
            })
            .unwrap();
        catalog
    }

    #[test]
    fn renders_multiple_resources_in_binding_order_and_freezes_versions() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        catalog
            .upsert_surface(&Surface {
                id: "fixture-direnv".to_string(),
                environment_id: "fixture-development".to_string(),
                name: ".envrc".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv)),
                path: PathBuf::from("/fixture/project/.envrc"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec![
                        "fixture-token-binding".to_string(),
                        "fixture-env-binding".to_string(),
                        "fixture-mode-binding".to_string(),
                    ],
                },
                enforcement: accessfs_core::authz::Enforcement::Prompt,
                position: 2,
            })
            .unwrap();
        let store = Arc::new(FixtureStore::new());
        let resolver = SurfaceResolver::new(catalog, Arc::clone(&store) as Arc<dyn SecretStore>);

        let snapshot = resolver.render_surface("fixture-dotenv").unwrap();
        assert_eq!(
            std::str::from_utf8(&snapshot.bytes).unwrap(),
            "SERVICE_TOKEN=fixture-token-value\nAPI_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\nAPP_ENV=development\n"
        );
        assert_eq!(
            snapshot.versions,
            vec![
                FrozenResourceVersion {
                    resource_id: "fixture-token".to_string(),
                    secret_id: TOKEN_ID.to_string(),
                    version: 2,
                },
                FrozenResourceVersion {
                    resource_id: "fixture-env-file".to_string(),
                    secret_id: ENV_FILE_ID.to_string(),
                    version: 1,
                },
            ]
        );
        assert_eq!(
            store.requested_versions.lock().unwrap().as_slice(),
            &[(TOKEN_ID.to_string(), 2), (ENV_FILE_ID.to_string(), 1)]
        );
        let dependencies = snapshot.audit_dependencies();
        assert_eq!(dependencies[0].key, "SERVICE_TOKEN");
        assert_eq!(dependencies[0].version, Some(2));
        assert_eq!(dependencies.last().unwrap().resource_id, "fixture-mode");
        assert_eq!(dependencies.last().unwrap().version, None);

        let direnv = resolver.render_surface("fixture-direnv").unwrap();
        assert_eq!(
            std::str::from_utf8(&direnv.bytes).unwrap(),
            "export SERVICE_TOKEN='fixture-token-value'\nexport API_HOST='http://127.0.0.1:8787'\nexport LOG_LEVEL='debug'\nexport APP_ENV='development'\n"
        );
        assert_eq!(
            direnv.versions,
            vec![
                FrozenResourceVersion {
                    resource_id: "fixture-token".to_string(),
                    secret_id: TOKEN_ID.to_string(),
                    version: 2,
                },
                FrozenResourceVersion {
                    resource_id: "fixture-env-file".to_string(),
                    secret_id: ENV_FILE_ID.to_string(),
                    version: 1,
                },
            ]
        );
        assert_eq!(direnv.audit_dependencies().len(), 4);
    }

    #[test]
    fn freezes_all_resource_heads_before_reading_any_secret() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        let store = Arc::new(AdvancingStore::new());
        let resolver = SurfaceResolver::new(catalog, Arc::clone(&store) as Arc<dyn SecretStore>);

        let snapshot = resolver.render_surface("fixture-dotenv").unwrap();

        assert_eq!(
            snapshot.bytes,
            b"SERVICE_TOKEN=fixture-token-value\nAPI_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\nAPP_ENV=development\n"
        );
        assert_eq!(
            snapshot.versions,
            vec![
                FrozenResourceVersion {
                    resource_id: "fixture-token".to_string(),
                    secret_id: TOKEN_ID.to_string(),
                    version: 2,
                },
                FrozenResourceVersion {
                    resource_id: "fixture-env-file".to_string(),
                    secret_id: ENV_FILE_ID.to_string(),
                    version: 1,
                },
            ]
        );
        let events = store.events.lock().unwrap();
        let first_read = events
            .iter()
            .position(|event| event.starts_with("get_version:"))
            .unwrap();
        assert_eq!(
            &events[..first_read],
            &[format!("record:{TOKEN_ID}"), format!("record:{ENV_FILE_ID}")]
        );
    }

    #[test]
    fn render_entrypoint_rejects_non_composed_surfaces() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        let resolver =
            SurfaceResolver::new(catalog, Arc::new(FixtureStore::new()) as Arc<dyn SecretStore>);

        assert!(matches!(
            resolver.render_surface("fixture-direct-env"),
            Err(SurfaceError::UnsupportedSurface { .. })
        ));
        assert!(matches!(
            resolver.read_direct_env_file("fixture-dotenv"),
            Err(SurfaceError::UnsupportedSurface { .. })
        ));
    }

    #[test]
    fn executable_and_socket_sources_are_not_file_projection_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        let resolver =
            SurfaceResolver::new(catalog, Arc::new(FixtureStore::new()) as Arc<dyn SecretStore>);
        let resource = |id: &str, source| Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::Command,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: Some("FIXTURE".to_string()),
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: id.to_string(),
                key: Some("FIXTURE".to_string()),
                sensitive: true,
            }],
            source,
            enforcement: Default::default(),
            metadata: Default::default(),
            origin: Default::default(),
        };

        for resource in [
            resource(
                "fixture-command",
                ResourceSource::Command {
                    argv: vec!["/fixture/command".to_string()],
                },
            ),
            resource(
                "fixture-socket",
                ResourceSource::Socket {
                    endpoint: PathBuf::from("/fixture/agent.sock"),
                },
            ),
        ] {
            assert!(matches!(
                resolver.decode_resource(&resource, None),
                Err(SurfaceError::IncompatibleResource { .. })
            ));
        }
    }

    #[test]
    fn direct_writeback_rejects_codecs_without_raw_roundtrip_support() {
        for codec in [ResourceCodec::Ini, ResourceCodec::Opaque] {
            let resource = Resource {
                id: format!("fixture-{codec:?}"),
                name: "Fixture non-writeback resource".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec,
                default_env_key: None,
                entries: Vec::new(),
                source: ResourceSource::SecretRef {
                    secret_id: ENV_FILE_ID.to_string(),
                },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            };

            assert!(matches!(
                validate_direct_env_file(&resource, b"KEY=value\n"),
                Err(SurfaceError::IncompatibleResource { .. })
            ));
        }
    }

    #[test]
    fn direct_env_file_preserves_bytes_and_versions_value_only_edits() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        let store = Arc::new(FixtureStore::new());
        let resolver = SurfaceResolver::new(catalog, Arc::clone(&store) as Arc<dyn SecretStore>);

        let first = resolver.read_direct_env_file("fixture-direct-env").unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(
            first.bytes,
            b"API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n"
        );

        let edited = b"# values may change without changing schema\nAPI_HOST=http://127.0.0.1:9999\nLOG_LEVEL=trace\n";
        let commit = resolver
            .commit_direct_env_file("fixture-direct-env", edited)
            .unwrap();
        assert_eq!(commit.version, 2);
        let second = resolver.read_direct_env_file("fixture-direct-env").unwrap();
        assert_eq!(second.version, 2);
        assert_eq!(second.bytes, edited);

        let error = resolver
            .commit_direct_env_file("fixture-direct-env", b"API_HOST=http://127.0.0.1:9999\n")
            .unwrap_err();
        assert!(matches!(error, SurfaceError::ResourceEntriesChanged { .. }));
        assert_eq!(resolver.read_direct_env_file("fixture-direct-env").unwrap().version, 2);
    }

    #[test]
    fn selected_ini_section_entries_feed_dotenv_and_ini_without_exposing_other_sections() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        add_resource(
            &catalog,
            Resource {
                id: "fixture-ini-file".to_string(),
                name: "Fixture INI File".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Ini,
                default_env_key: None,
                entries: vec![
                    EntrySpec {
                        address: "sections/fixture-development/keys/REGION".to_string(),
                        label: "[fixture-development] REGION".to_string(),
                        key: Some("REGION".to_string()),
                        sensitive: true,
                    },
                    EntrySpec {
                        address: "sections/fixture-development/keys/OUTPUT".to_string(),
                        label: "[fixture-development] OUTPUT".to_string(),
                        key: Some("OUTPUT".to_string()),
                        sensitive: true,
                    },
                    EntrySpec {
                        address: "sections/fixture-staging/keys/REGION".to_string(),
                        label: "[fixture-staging] REGION".to_string(),
                        key: Some("REGION".to_string()),
                        sensitive: true,
                    },
                    EntrySpec {
                        address: "sections/fixture-staging/keys/OUTPUT".to_string(),
                        label: "[fixture-staging] OUTPUT".to_string(),
                        key: Some("OUTPUT".to_string()),
                        sensitive: true,
                    },
                ],
                source: ResourceSource::SecretRef { secret_id: INI_FILE_ID.to_string() },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        catalog
            .upsert_binding(&Binding {
                id: "fixture-ini-binding".to_string(),
                project_id: "fixture-project".to_string(),
                scope: BindingScope::Environment {
                    environment_id: "fixture-development".to_string(),
                },
                resource_id: "fixture-ini-file".to_string(),
                selection: EntrySelection::Entries {
                    addresses: vec![
                        "sections/fixture-staging/keys/REGION".to_string(),
                        "sections/fixture-staging/keys/OUTPUT".to_string(),
                    ],
                },
                key_override: None,
                enabled: true,
                allow_override: false,
                position: 3,
            })
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-ini-dotenv".to_string(),
                environment_id: "fixture-development".to_string(),
                name: ".env.staging-profile".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: PathBuf::from("/fixture/project/.env.staging-profile"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["fixture-ini-binding".to_string()],
                },
                enforcement: accessfs_core::authz::Enforcement::Prompt,
                position: 2,
            })
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-ini-output".to_string(),
                environment_id: "fixture-development".to_string(),
                name: "fixture-credentials.ini".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
                path: PathBuf::from("/fixture/project/fixture-credentials.ini"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["fixture-ini-binding".to_string()],
                },
                enforcement: accessfs_core::authz::Enforcement::Prompt,
                position: 3,
            })
            .unwrap();

        let store = Arc::new(FixtureStore::new());
        let resolver = SurfaceResolver::new(catalog, Arc::clone(&store) as Arc<dyn SecretStore>);
        let snapshot = resolver.render_surface("fixture-ini-dotenv").unwrap();

        assert_eq!(snapshot.bytes, b"REGION=fixture-region-two\nOUTPUT=fixture-text\n");
        assert!(!std::str::from_utf8(&snapshot.bytes).unwrap().contains("fixture-region-one"));

        let snapshot = resolver.render_surface("fixture-ini-output").unwrap();
        assert_eq!(
            snapshot.bytes,
            b"[fixture-staging]\nREGION = fixture-region-two\nOUTPUT = fixture-text\n"
        );
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(
            snapshot.entries[0].audit_key,
            "sections/fixture-staging/keys/REGION"
        );
        let dependencies = snapshot.audit_dependencies();
        assert_eq!(dependencies[0].key, "sections/fixture-staging/keys/REGION");
        assert_eq!(dependencies[0].secret_id.as_deref(), Some(INI_FILE_ID));
        assert_eq!(dependencies[0].version, Some(1));
    }

    #[test]
    fn catalog_rejects_incompatible_ini_and_lines_members_before_rendering() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));

        let incompatible_ini = Surface {
            id: "fixture-incompatible-ini".to_string(),
            environment_id: "fixture-development".to_string(),
            name: "incompatible.ini".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
            path: PathBuf::from("/fixture/project/incompatible.ini"),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["fixture-env-binding".to_string()],
            },
            enforcement: Default::default(),
            position: 2,
        };
        assert!(catalog.upsert_surface(&incompatible_ini).is_err());

        let incompatible_lines = Surface {
            id: "fixture-incompatible-lines".to_string(),
            environment_id: "fixture-development".to_string(),
            name: "incompatible.lines".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
            path: PathBuf::from("/fixture/project/incompatible.lines"),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["fixture-token-binding".to_string()],
            },
            enforcement: Default::default(),
            position: 3,
        };
        assert!(catalog.upsert_surface(&incompatible_lines).is_err());

        add_resource(
            &catalog,
            Resource {
                id: "fixture-multiline".to_string(),
                name: "Fixture Multiline".to_string(),
                kind: ResourceKind::Literal,
                shape: ValueShape::Scalar,
                codec: ResourceCodec::Opaque,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "value".to_string(),
                    label: "Fixture Multiline".to_string(),
                    key: None,
                    sensitive: true,
                }],
                source: ResourceSource::Literal {
                    value: "first\nsecond".to_string(),
                },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        let mut binding = Binding {
            id: "fixture-multiline-binding".to_string(),
            project_id: "fixture-project".to_string(),
            scope: BindingScope::Environment {
                environment_id: "fixture-development".to_string(),
            },
            resource_id: "fixture-multiline".to_string(),
            selection: EntrySelection::All,
            key_override: Some("MULTILINE".to_string()),
            enabled: true,
            allow_override: false,
            position: 3,
        };
        catalog.upsert_binding(&binding).unwrap();
        let multiline_surface = Surface {
            id: "fixture-multiline-lines".to_string(),
            environment_id: "fixture-development".to_string(),
            name: "multiline.lines".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
            path: PathBuf::from("/fixture/project/multiline.lines"),
            input: SurfaceInput::Bindings {
                binding_ids: vec![binding.id.clone()],
            },
            enforcement: Default::default(),
            position: 4,
        };
        assert!(catalog.upsert_surface(&multiline_surface).is_err());

        binding.key_override = None;
        catalog.upsert_binding(&binding).unwrap();
        catalog.upsert_surface(&multiline_surface).unwrap();
        let resolver =
            SurfaceResolver::new(catalog, Arc::new(FixtureStore::new()) as Arc<dyn SecretStore>);
        assert!(matches!(
            resolver.render_surface(&multiline_surface.id),
            Err(SurfaceError::InvalidLineValue { .. })
        ));
    }

    #[test]
    fn ini_orders_common_bindings_first_and_root_entries_before_sections() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        add_resource(
            &catalog,
            Resource {
                id: "fixture-ordered-ini".to_string(),
                name: "Fixture Ordered INI".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Ini,
                default_env_key: None,
                entries: vec![
                    EntrySpec {
                        address: "sections/fixture-development/keys/REGION".to_string(),
                        label: "[fixture-development] REGION".to_string(),
                        key: Some("REGION".to_string()),
                        sensitive: true,
                    },
                    EntrySpec {
                        address: "sections/fixture-development/keys/OUTPUT".to_string(),
                        label: "[fixture-development] OUTPUT".to_string(),
                        key: Some("OUTPUT".to_string()),
                        sensitive: true,
                    },
                    EntrySpec {
                        address: "sections/fixture-staging/keys/REGION".to_string(),
                        label: "[fixture-staging] REGION".to_string(),
                        key: Some("REGION".to_string()),
                        sensitive: true,
                    },
                    EntrySpec {
                        address: "sections/fixture-staging/keys/OUTPUT".to_string(),
                        label: "[fixture-staging] OUTPUT".to_string(),
                        key: Some("OUTPUT".to_string()),
                        sensitive: true,
                    },
                ],
                source: ResourceSource::SecretRef {
                    secret_id: INI_FILE_ID.to_string(),
                },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        add_resource(
            &catalog,
            Resource {
                id: "fixture-common-ini".to_string(),
                name: "Fixture Common INI".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Ini,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "sections/common/keys/COMMON".to_string(),
                    label: "[common] COMMON".to_string(),
                    key: Some("COMMON".to_string()),
                    sensitive: true,
                }],
                source: ResourceSource::SecretRef {
                    secret_id: INI_COMMON_ID.to_string(),
                },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        add_resource(
            &catalog,
            Resource {
                id: "fixture-root-ini".to_string(),
                name: "Fixture Root INI".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Ini,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "root/keys/ROOT".to_string(),
                    label: "ROOT".to_string(),
                    key: Some("ROOT".to_string()),
                    sensitive: true,
                }],
                source: ResourceSource::SecretRef {
                    secret_id: INI_ROOT_ID.to_string(),
                },
                enforcement: Default::default(),
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        let environment_binding = Binding {
            id: "fixture-ordered-ini-environment".to_string(),
            project_id: "fixture-project".to_string(),
            scope: BindingScope::Environment {
                environment_id: "fixture-development".to_string(),
            },
            resource_id: "fixture-ordered-ini".to_string(),
            selection: EntrySelection::Entries {
                addresses: vec![
                    "sections/fixture-development/keys/REGION".to_string(),
                ],
            },
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 0,
        };
        let common_binding = Binding {
            id: "fixture-ordered-ini-common".to_string(),
            project_id: "fixture-project".to_string(),
            scope: BindingScope::Common,
            resource_id: "fixture-common-ini".to_string(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 99,
        };
        let root_binding = Binding {
            id: "fixture-ordered-ini-root".to_string(),
            project_id: "fixture-project".to_string(),
            scope: BindingScope::Environment {
                environment_id: "fixture-development".to_string(),
            },
            resource_id: "fixture-root-ini".to_string(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 1,
        };
        for binding in [&environment_binding, &common_binding, &root_binding] {
            catalog.upsert_binding(binding).unwrap();
        }
        catalog
            .upsert_surface(&Surface {
                id: "fixture-common-first-ini".to_string(),
                environment_id: "fixture-development".to_string(),
                name: "common-first.ini".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
                path: PathBuf::from("/fixture/project/common-first.ini"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec![
                        environment_binding.id.clone(),
                        common_binding.id.clone(),
                    ],
                },
                enforcement: Default::default(),
                position: 2,
            })
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-root-first-ini".to_string(),
                environment_id: "fixture-development".to_string(),
                name: "root-first.ini".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
                path: PathBuf::from("/fixture/project/root-first.ini"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec![
                        environment_binding.id.clone(),
                        root_binding.id.clone(),
                    ],
                },
                enforcement: Default::default(),
                position: 3,
            })
            .unwrap();

        let resolver =
            SurfaceResolver::new(catalog, Arc::new(FixtureStore::new()) as Arc<dyn SecretStore>);
        let common_first = resolver
            .render_surface("fixture-common-first-ini")
            .unwrap();
        assert_eq!(
            common_first.bytes,
            b"[common]\nCOMMON = common-value\n\n[fixture-development]\nREGION = fixture-region-one\n"
        );
        assert_eq!(
            common_first.entries[0].binding_id,
            common_binding.id
        );

        let root_first = resolver
            .render_surface("fixture-root-first-ini")
            .unwrap();
        assert_eq!(
            root_first.bytes,
            b"ROOT = root-value\n\n[fixture-development]\nREGION = fixture-region-one\n"
        );
        assert_eq!(root_first.entries[0].audit_key, "root/keys/ROOT");
        assert_eq!(
            root_first.entries[1].audit_key,
            "sections/fixture-development/keys/REGION"
        );
    }

    #[test]
    fn lines_orders_common_bindings_before_environment_bindings() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        for (id, value) in [
            ("fixture-common-line", "common-line"),
            ("fixture-environment-line", "environment-line"),
        ] {
            add_resource(
                &catalog,
                Resource {
                    id: id.to_string(),
                    name: id.to_string(),
                    kind: ResourceKind::Literal,
                    shape: ValueShape::Scalar,
                    codec: ResourceCodec::Opaque,
                    default_env_key: None,
                    entries: vec![EntrySpec {
                        address: "value".to_string(),
                        label: id.to_string(),
                        key: None,
                        sensitive: true,
                    }],
                    source: ResourceSource::Literal {
                        value: value.to_string(),
                    },
                    enforcement: Default::default(),
                    metadata: Default::default(),
                    origin: Default::default(),
                },
            );
        }
        let environment_binding = Binding {
            id: "fixture-environment-line-binding".to_string(),
            project_id: "fixture-project".to_string(),
            scope: BindingScope::Environment {
                environment_id: "fixture-development".to_string(),
            },
            resource_id: "fixture-environment-line".to_string(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 0,
        };
        let common_binding = Binding {
            id: "fixture-common-line-binding".to_string(),
            project_id: "fixture-project".to_string(),
            scope: BindingScope::Common,
            resource_id: "fixture-common-line".to_string(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 99,
        };
        catalog.upsert_binding(&environment_binding).unwrap();
        catalog.upsert_binding(&common_binding).unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-common-first-lines".to_string(),
                environment_id: "fixture-development".to_string(),
                name: "common-first.lines".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
                path: PathBuf::from("/fixture/project/common-first.lines"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec![
                        environment_binding.id.clone(),
                        common_binding.id.clone(),
                    ],
                },
                enforcement: Default::default(),
                position: 2,
            })
            .unwrap();

        let resolver =
            SurfaceResolver::new(catalog, Arc::new(FixtureStore::new()) as Arc<dyn SecretStore>);
        let snapshot = resolver
            .render_surface("fixture-common-first-lines")
            .unwrap();
        assert_eq!(snapshot.bytes, b"common-line\nenvironment-line\n");
        assert_eq!(snapshot.entries[0].binding_id, common_binding.id);
        assert_eq!(snapshot.entries[1].binding_id, environment_binding.id);
    }

    #[test]
    fn lines_surface_renders_keyless_secrets_in_binding_order() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        for (resource_id, name, secret_id) in [
            ("fixture-line-one", "Fixture Line One", LINE_ONE_ID),
            ("fixture-line-two", "Fixture Line Two", LINE_TWO_ID),
        ] {
            add_resource(
                &catalog,
                Resource {
                    id: resource_id.to_string(),
                    name: name.to_string(),
                    kind: ResourceKind::SharedSecret,
                    shape: ValueShape::Scalar,
                    codec: ResourceCodec::Opaque,
                    default_env_key: None,
                    entries: vec![EntrySpec {
                        address: "value".to_string(),
                        label: name.to_string(),
                        key: None,
                        sensitive: true,
                    }],
                    source: ResourceSource::SecretRef { secret_id: secret_id.to_string() },
                    enforcement: Default::default(),
                    metadata: Default::default(),
                    origin: Default::default(),
                },
            );
        }
        bind(&catalog, "fixture-line-one-binding", "fixture-line-one", 3);
        bind(&catalog, "fixture-line-two-binding", "fixture-line-two", 4);
        catalog
            .upsert_surface(&Surface {
                id: "fixture-lines".to_string(),
                environment_id: "fixture-development".to_string(),
                name: ".pgpass".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
                path: PathBuf::from("/fixture/project/.pgpass"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec![
                        "fixture-line-one-binding".to_string(),
                        "fixture-line-two-binding".to_string(),
                    ],
                },
                enforcement: accessfs_core::authz::Enforcement::Prompt,
                position: 2,
            })
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-other-lines".to_string(),
                environment_id: "fixture-development".to_string(),
                name: "credentials.lines".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
                path: PathBuf::from("/fixture/project/credentials.lines"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["fixture-line-two-binding".to_string()],
                },
                enforcement: accessfs_core::authz::Enforcement::Prompt,
                position: 3,
            })
            .unwrap();

        let mut invalid = catalog.resource("fixture-line-one").unwrap();
        invalid.default_env_key = Some("DATABASE_LINE".to_string());
        invalid.entries[0].key = Some("DATABASE_LINE".to_string());
        assert!(catalog.upsert_resource(&invalid).is_err());
        assert!(catalog.resource("fixture-line-one").unwrap().entries[0].key.is_none());

        let store = Arc::new(FixtureStore::new());
        let resolver = SurfaceResolver::new(catalog, Arc::clone(&store) as Arc<dyn SecretStore>);

        let snapshot = resolver.render_surface("fixture-lines").unwrap();
        assert_eq!(
            snapshot.bytes,
            b"db-one.fixture.invalid|5432|app|fixture-user|fixture-pass-one\ndb-two.fixture.invalid|5432|app|fixture-user|fixture-pass-two\n"
        );
        assert_eq!(
            snapshot.versions,
            vec![
                FrozenResourceVersion {
                    resource_id: "fixture-line-one".to_string(),
                    secret_id: LINE_ONE_ID.to_string(),
                    version: 1,
                },
                FrozenResourceVersion {
                    resource_id: "fixture-line-two".to_string(),
                    secret_id: LINE_TWO_ID.to_string(),
                    version: 1,
                },
            ]
        );
        assert_eq!(snapshot.entries[0].audit_key, "value");
        let dependencies = snapshot.audit_dependencies();
        assert_eq!(dependencies[0].binding_id, "fixture-line-one-binding");
        assert_eq!(dependencies[0].version, Some(1));

        assert_eq!(
            resolver.render_surface("fixture-other-lines").unwrap().bytes,
            b"db-two.fixture.invalid|5432|app|fixture-user|fixture-pass-two\n"
        );
    }
}
