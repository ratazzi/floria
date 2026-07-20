use std::collections::BTreeMap;
use std::sync::RwLock;

use accessfs_catalog::{CatalogSnapshot, Surface, SurfaceKind};

/// In-memory metadata used by fast FUSE callbacks. Control-plane mutations replace this view,
/// so lookup/readdir/getattr never need to query SQLite or resolve secret values.
pub struct SurfaceRegistry {
    surfaces: RwLock<BTreeMap<String, Surface>>,
}

impl SurfaceRegistry {
    pub fn from_snapshot(snapshot: &CatalogSnapshot) -> Self {
        SurfaceRegistry { surfaces: RwLock::new(dotenv_surfaces(snapshot)) }
    }

    pub fn replace(&self, snapshot: &CatalogSnapshot) {
        *self.surfaces.write().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            dotenv_surfaces(snapshot);
    }

    pub fn get(&self, id: &str) -> Option<Surface> {
        self.surfaces
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(id)
            .cloned()
    }

    pub fn list(&self) -> Vec<Surface> {
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

fn dotenv_surfaces(snapshot: &CatalogSnapshot) -> BTreeMap<String, Surface> {
    snapshot
        .surfaces
        .iter()
        .filter(|surface| surface.kind == SurfaceKind::DotenvFile)
        .map(|surface| (surface.id.clone(), surface.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn surface(id: &str, kind: SurfaceKind) -> Surface {
        Surface {
            id: id.to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env".to_string(),
            kind,
            path: PathBuf::from(format!("/fixture/project/{id}")),
            resource_id: None,
            position: 0,
        }
    }

    #[test]
    fn replacement_is_sorted_and_only_keeps_dotenv_surfaces() {
        let registry = SurfaceRegistry::from_snapshot(&CatalogSnapshot {
            surfaces: vec![
                surface("fixture-b", SurfaceKind::DotenvFile),
                surface("fixture-socket", SurfaceKind::UnixSocket),
                surface("fixture-a", SurfaceKind::DotenvFile),
            ],
            ..CatalogSnapshot::default()
        });
        assert_eq!(
            registry.list().into_iter().map(|surface| surface.id).collect::<Vec<_>>(),
            vec!["fixture-a", "fixture-b"]
        );

        registry.replace(&CatalogSnapshot {
            surfaces: vec![surface("fixture-c", SurfaceKind::DotenvFile)],
            ..CatalogSnapshot::default()
        });
        assert!(registry.get("fixture-a").is_none());
        assert_eq!(registry.get("fixture-c").unwrap().id, "fixture-c");
    }
}
