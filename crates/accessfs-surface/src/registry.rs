use std::collections::BTreeMap;
use std::sync::RwLock;

use accessfs_catalog::{
    CatalogSnapshot, FileBacking, ResourceSource, Surface, SurfaceFormat, SurfaceInput, SurfaceKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceBacking {
    Composed { format: SurfaceFormat },
    EnvFileDirect { resource_id: String, secret_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredSurface {
    pub surface: Surface,
    pub backing: SurfaceBacking,
}

/// In-memory metadata used by fast FUSE callbacks. Control-plane mutations replace this view,
/// so lookup/readdir/getattr never need to query SQLite or resolve secret values.
pub struct SurfaceRegistry {
    surfaces: RwLock<BTreeMap<String, RegisteredSurface>>,
}

impl SurfaceRegistry {
    pub fn from_snapshot(snapshot: &CatalogSnapshot) -> Self {
        SurfaceRegistry { surfaces: RwLock::new(file_surfaces(snapshot)) }
    }

    pub fn replace(&self, snapshot: &CatalogSnapshot) {
        *self.surfaces.write().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            file_surfaces(snapshot);
    }

    pub fn get(&self, id: &str) -> Option<RegisteredSurface> {
        self.surfaces
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(id)
            .cloned()
    }

    pub fn list(&self) -> Vec<RegisteredSurface> {
        self.surfaces
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.surfaces
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    }
}

fn file_surfaces(snapshot: &CatalogSnapshot) -> BTreeMap<String, RegisteredSurface> {
    snapshot
        .surfaces
        .iter()
        .filter_map(|surface| {
            let backing = match surface.kind {
                SurfaceKind::File(FileBacking::Composed(format)) => {
                    SurfaceBacking::Composed { format }
                }
                SurfaceKind::File(FileBacking::EnvFileDirect) => {
                    let SurfaceInput::Resource { resource_id } = &surface.input else {
                        tracing::warn!(
                            surface_id = %surface.id,
                            "surface dropped from registry: direct file has no resource input"
                        );
                        return None;
                    };
                    let Some(resource) = snapshot
                        .resources
                        .iter()
                        .find(|resource| resource.id == *resource_id)
                    else {
                        tracing::warn!(
                            surface_id = %surface.id,
                            resource_id,
                            "surface dropped from registry: resource is missing"
                        );
                        return None;
                    };
                    let ResourceSource::SecretRef { secret_id } = &resource.source else {
                        tracing::warn!(
                            surface_id = %surface.id,
                            resource_id,
                            "surface dropped from registry: resource is not store-backed"
                        );
                        return None;
                    };
                    SurfaceBacking::EnvFileDirect {
                        resource_id: resource_id.clone(),
                        secret_id: secret_id.clone(),
                    }
                }
                SurfaceKind::UnixSocket => return None,
            };
            Some((
                surface.id.clone(),
                RegisteredSurface { surface: surface.clone(), backing },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use accessfs_catalog::{
        EntrySpec, Resource, ResourceCodec, ResourceKind, SurfaceInput, ValueShape,
    };
    use std::path::PathBuf;

    fn surface(id: &str, kind: SurfaceKind) -> Surface {
        Surface {
            id: id.to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env".to_string(),
            kind,
            path: PathBuf::from(format!("/fixture/project/{id}")),
            input: SurfaceInput::Bindings { binding_ids: Vec::new() },
            enforcement: accessfs_core::authz::Enforcement::Prompt,
            position: 0,
        }
    }

    #[test]
    fn replacement_is_sorted_and_only_keeps_file_surfaces() {
        let direct = Surface {
            input: SurfaceInput::Resource {
                resource_id: "fixture-env-resource".to_string(),
            },
            ..surface("fixture-direct", SurfaceKind::File(FileBacking::EnvFileDirect))
        };
        let env_resource = Resource {
            id: "fixture-env-resource".to_string(),
            name: "Fixture Env File".to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Dotenv,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "keys/FIXTURE".to_string(),
                label: "FIXTURE".to_string(),
                key: Some("FIXTURE".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: "fixture-secret".to_string() },
            enforcement: Default::default(),
            metadata: Default::default(),
            origin: Default::default(),
        };
        let registry = SurfaceRegistry::from_snapshot(&CatalogSnapshot {
            surfaces: vec![
                surface("fixture-b", SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv))),
                surface("fixture-socket", SurfaceKind::UnixSocket),
                surface("fixture-a", SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv))),
                surface("fixture-direnv", SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv))),
                surface("fixture-ini", SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini))),
                surface("fixture-lines", SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines))),
                direct,
            ],
            resources: vec![env_resource],
            ..CatalogSnapshot::default()
        });
        assert_eq!(
            registry
                .list()
                .into_iter()
                .map(|registered| registered.surface.id)
                .collect::<Vec<_>>(),
            vec![
                "fixture-a",
                "fixture-b",
                "fixture-direct",
                "fixture-direnv",
                "fixture-ini",
                "fixture-lines",
            ]
        );
        assert_eq!(
            registry.get("fixture-ini").unwrap().backing,
            SurfaceBacking::Composed { format: SurfaceFormat::Ini }
        );
        assert_eq!(
            registry.get("fixture-direnv").unwrap().backing,
            SurfaceBacking::Composed { format: SurfaceFormat::Direnv }
        );
        assert!(matches!(
            registry.get("fixture-direct").unwrap().backing,
            SurfaceBacking::EnvFileDirect { .. }
        ));

        registry.replace(&CatalogSnapshot {
            surfaces: vec![surface("fixture-c", SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)))],
            ..CatalogSnapshot::default()
        });
        assert!(registry.get("fixture-a").is_none());
        assert_eq!(registry.get("fixture-c").unwrap().surface.id, "fixture-c");
    }
}
