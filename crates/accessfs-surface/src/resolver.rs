use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use accessfs_catalog::{
    resolve_catalog_snapshot, Catalog, CatalogSnapshot, Resource, ResourceSource, SurfaceKind,
    ValueShape,
};
use accessfs_core::audit::AuditDependency;
use accessfs_store::{SecretId, SecretStore};
use zeroize::Zeroizing;

use crate::dotenv::{parse_dotenv, render_dotenv_refs};
use crate::error::{SurfaceError, SurfaceResult};

type FrozenSecretVersions = HashMap<String, (SecretId, u32)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenResourceVersion {
    pub resource_id: String,
    pub secret_id: String,
    pub version: u32,
}

#[derive(Debug)]
pub struct DotenvSnapshot {
    pub bytes: Vec<u8>,
    pub versions: Vec<FrozenResourceVersion>,
    pub exports: Vec<accessfs_catalog::ResolvedExport>,
}

#[derive(Debug)]
pub struct DirectEnvFileSnapshot {
    pub bytes: Vec<u8>,
    pub resource_id: String,
    pub secret_id: String,
    pub version: u32,
    pub keys: Vec<String>,
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

impl DotenvSnapshot {
    pub fn audit_dependencies(&self) -> Vec<AuditDependency> {
        let versions: HashMap<&str, &FrozenResourceVersion> = self
            .versions
            .iter()
            .map(|version| (version.resource_id.as_str(), version))
            .collect();
        self.exports
            .iter()
            .map(|export| {
                let version = versions.get(export.resource_id.as_str()).copied();
                AuditDependency {
                    key: export.key.clone(),
                    binding_id: export.binding_id.clone(),
                    resource_id: export.resource_id.clone(),
                    secret_id: version.map(|version| version.secret_id.clone()),
                    version: version.map(|version| version.version),
                }
            })
            .collect()
    }
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

    /// Resolve one catalog DotenvFile into a per-open byte snapshot. All referenced secret
    /// heads are captured before any decryption, and `get_version` reads those immutable heads.
    pub fn render_dotenv_surface(&self, surface_id: &str) -> SurfaceResult<DotenvSnapshot> {
        let snapshot = self.catalog.snapshot()?;
        let surface = snapshot
            .surfaces
            .iter()
            .find(|surface| surface.id == surface_id)
            .ok_or_else(|| SurfaceError::NotFound(surface_id.to_string()))?;
        if surface.kind != SurfaceKind::DotenvFile {
            return Err(SurfaceError::UnsupportedSurface {
                surface_id: surface_id.to_string(),
                kind: format!("{:?}", surface.kind),
            });
        }
        let environment = snapshot
            .environments
            .iter()
            .find(|environment| environment.id == surface.environment_id)
            .ok_or_else(|| SurfaceError::NotFound(format!("environment {}", surface.environment_id)))?;
        let resolved = resolve_catalog_snapshot(
            &snapshot,
            &environment.project_id,
            &environment.id,
        )?;
        let resources: HashMap<&str, &Resource> = snapshot
            .resources
            .iter()
            .map(|resource| (resource.id.as_str(), resource))
            .collect();

        let (frozen, versions) = self.freeze_versions(&snapshot, &resolved.exports)?;
        let mut resource_values: HashMap<String, BTreeMap<String, Zeroizing<String>>> =
            HashMap::new();
        for export in &resolved.exports {
            if resource_values.contains_key(&export.resource_id) {
                continue;
            }
            let resource = resources
                .get(export.resource_id.as_str())
                .ok_or_else(|| SurfaceError::NotFound(format!("resource {}", export.resource_id)))?;
            let values = self.resolve_resource(resource, frozen.get(&resource.id))?;
            resource_values.insert(resource.id.clone(), values);
        }

        let mut ordered = Vec::with_capacity(resolved.exports.len());
        for export in &resolved.exports {
            let value = resource_values
                .get(&export.resource_id)
                .and_then(|values| values.get(&export.source_key))
                .ok_or_else(|| SurfaceError::MissingKey {
                    resource_id: export.resource_id.clone(),
                    key: export.source_key.clone(),
                })?;
            ordered.push((export.key.as_str(), value.as_str()));
        }
        let bytes = render_dotenv_refs(ordered)?;
        Ok(DotenvSnapshot { bytes, versions, exports: resolved.exports })
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
        validate_direct_env_file(&target.resource, bytes)?;
        let id: SecretId = target.secret_id.parse()?;
        let version = self.store.append_version(&id, bytes)?;
        Ok(DirectEnvFileCommit {
            resource_id: target.resource.id,
            secret_id: target.secret_id,
            version,
        })
    }

    fn freeze_versions(
        &self,
        snapshot: &CatalogSnapshot,
        exports: &[accessfs_catalog::ResolvedExport],
    ) -> SurfaceResult<(FrozenSecretVersions, Vec<FrozenResourceVersion>)> {
        let resources: HashMap<&str, &Resource> = snapshot
            .resources
            .iter()
            .map(|resource| (resource.id.as_str(), resource))
            .collect();
        let mut seen = HashSet::new();
        let mut frozen = HashMap::new();
        let mut versions = Vec::new();
        for export in exports {
            if !seen.insert(export.resource_id.as_str()) {
                continue;
            }
            let resource = resources
                .get(export.resource_id.as_str())
                .ok_or_else(|| SurfaceError::NotFound(format!("resource {}", export.resource_id)))?;
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

    fn resolve_resource(
        &self,
        resource: &Resource,
        frozen: Option<&(SecretId, u32)>,
    ) -> SurfaceResult<BTreeMap<String, Zeroizing<String>>> {
        let mut values = BTreeMap::new();
        match (&resource.shape, &resource.source) {
            (ValueShape::Scalar, ResourceSource::SecretRef { .. }) => {
                let text = self.read_frozen_text(resource, frozen)?;
                values.insert(resource.exports[0].key.clone(), text);
            }
            (ValueShape::KeyValueSet, ResourceSource::SecretRef { .. }) => {
                let text = self.read_frozen_text(resource, frozen)?;
                let mut parsed = parse_dotenv(&text)?;
                for export in &resource.exports {
                    let value = parsed.remove(&export.key).ok_or_else(|| SurfaceError::MissingKey {
                        resource_id: resource.id.clone(),
                        key: export.key.clone(),
                    })?;
                    values.insert(export.key.clone(), Zeroizing::new(value));
                }
            }
            (ValueShape::Scalar, ResourceSource::Literal { value }) => {
                values.insert(resource.exports[0].key.clone(), Zeroizing::new(value.clone()));
            }
            (ValueShape::Socket, ResourceSource::Socket { endpoint }) => {
                values.insert(
                    resource.exports[0].key.clone(),
                    Zeroizing::new(endpoint.to_string_lossy().into_owned()),
                );
            }
            (ValueShape::Bytes, _) => {
                return Err(SurfaceError::IncompatibleResource {
                    resource_id: resource.id.clone(),
                    reason: "bytes cannot be rendered into dotenv".to_string(),
                })
            }
            (_, ResourceSource::Command { .. }) => {
                return Err(SurfaceError::IncompatibleResource {
                    resource_id: resource.id.clone(),
                    reason: "command resources are not enabled for dotenv yet".to_string(),
                })
            }
            _ => {
                return Err(SurfaceError::IncompatibleResource {
                    resource_id: resource.id.clone(),
                    reason: "shape and source do not produce dotenv values".to_string(),
                })
            }
        }
        Ok(values)
    }

    fn read_frozen_text(
        &self,
        resource: &Resource,
        frozen: Option<&(SecretId, u32)>,
    ) -> SurfaceResult<Zeroizing<String>> {
        let (id, version) = frozen.ok_or_else(|| SurfaceError::NotFound(format!(
            "frozen version for resource {}",
            resource.id
        )))?;
        let plaintext = self.store.get_version(id, *version)?;
        let text = String::from_utf8(plaintext.to_vec())
            .map_err(|_| SurfaceError::InvalidUtf8 { resource_id: resource.id.clone() })?;
        Ok(Zeroizing::new(text))
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
    if surface.kind != SurfaceKind::EnvFileDirect {
        return Err(SurfaceError::UnsupportedSurface {
            surface_id: surface_id.to_string(),
            kind: format!("{:?}", surface.kind),
        });
    }
    let resource_id = surface.resource_id.as_deref().ok_or_else(|| {
        SurfaceError::IncompatibleResource {
            resource_id: "<missing>".to_string(),
            reason: "env_file_direct surface requires resource_id".to_string(),
        }
    })?;
    let resource = snapshot
        .resources
        .iter()
        .find(|resource| resource.id == resource_id)
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
    if bytes.len() > crate::dotenv::DOTENV_MAX_SIZE {
        return Err(SurfaceError::TooLarge { limit: crate::dotenv::DOTENV_MAX_SIZE });
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| SurfaceError::InvalidUtf8 { resource_id: resource.id.clone() })?;
    let values = parse_dotenv(text)?;
    let actual = values.keys().cloned().collect::<Vec<_>>();
    let expected = resource
        .exports
        .iter()
        .map(|export| export.key.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(SurfaceError::EnvFileKeysChanged {
            resource_id: resource.id.clone(),
            expected,
            actual,
        });
    }
    Ok(values.into_keys().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use accessfs_catalog::{
        Binding, BindingScope, Environment, ExportSpec, Project, ResourceKind, Surface,
    };
    use accessfs_store::{NewSecret, SecretOrigin, SecretRecord, StoreResult, VersionRecord};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    const TOKEN_ID: &str = "00000000-0000-0000-0000-000000000001";
    const ENV_FILE_ID: &str = "00000000-0000-0000-0000-000000000002";

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
        fn delete(&self, _id: &SecretId) -> StoreResult<()> {
            unimplemented!()
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
                default_env_key: Some("SERVICE_TOKEN".to_string()),
                exports: vec![ExportSpec {
                    key: "SERVICE_TOKEN".to_string(),
                    sensitive: true,
                }],
                source: ResourceSource::SecretRef { secret_id: TOKEN_ID.to_string() },
                detail: None,
            },
        );
        add_resource(
            &catalog,
            Resource {
                id: "fixture-env-file".to_string(),
                name: "Fixture Env File".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                default_env_key: None,
                exports: vec![
                    ExportSpec { key: "API_HOST".to_string(), sensitive: false },
                    ExportSpec { key: "LOG_LEVEL".to_string(), sensitive: false },
                ],
                source: ResourceSource::SecretRef { secret_id: ENV_FILE_ID.to_string() },
                detail: None,
            },
        );
        add_resource(
            &catalog,
            Resource {
                id: "fixture-mode".to_string(),
                name: "Fixture Mode".to_string(),
                kind: ResourceKind::Literal,
                shape: ValueShape::Scalar,
                default_env_key: Some("APP_ENV".to_string()),
                exports: vec![ExportSpec { key: "APP_ENV".to_string(), sensitive: false }],
                source: ResourceSource::Literal { value: "development".to_string() },
                detail: None,
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
                kind: SurfaceKind::DotenvFile,
                path: PathBuf::from("/fixture/project/.env"),
                resource_id: None,
                position: 0,
            })
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-direct-env".to_string(),
                environment_id: "fixture-development".to_string(),
                name: ".env.source".to_string(),
                kind: SurfaceKind::EnvFileDirect,
                path: PathBuf::from("/fixture/project/.env.source"),
                resource_id: Some("fixture-env-file".to_string()),
                position: 1,
            })
            .unwrap();
        catalog
    }

    #[test]
    fn renders_multiple_resources_in_binding_order_and_freezes_versions() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = fixture_catalog(&dir.path().join("catalog.sqlite"));
        let store = Arc::new(FixtureStore::new());
        let resolver = SurfaceResolver::new(catalog, Arc::clone(&store) as Arc<dyn SecretStore>);

        let snapshot = resolver.render_dotenv_surface("fixture-dotenv").unwrap();
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
        assert!(matches!(error, SurfaceError::EnvFileKeysChanged { .. }));
        assert_eq!(resolver.read_direct_env_file("fixture-direct-env").unwrap().version, 2);
    }
}
