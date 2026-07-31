use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use accessfs_core::authz::Enforcement;
use rusqlite::{params, Connection, OptionalExtension};

use crate::domain::{
    Binding, BindingScope, CatalogSnapshot, EntrySelection, Environment, FileBacking,
    FormatInputModel, OriginSource, Project, ProjectCheckout, ProjectCheckoutKind,
    ResolvedEnvironment, ResolvedExport, Resource, ResourceBindingUsage, ResourceCodec,
    ResourceKind, ResourceOrigin, ResourceSource, ResourceUsage, Surface, SurfaceFormat,
    SurfaceInput, SurfaceKind, ValueShape,
};
use crate::error::{CatalogError, CatalogResult};

const SCHEMA_VERSION: i64 = 12;

#[derive(Debug, Clone)]
pub struct Catalog {
    path: PathBuf,
}

impl Catalog {
    /// Open or create a private SQLite metadata catalog.
    pub fn open(path: impl Into<PathBuf>) -> CatalogResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| CatalogError::io(parent, e))?;
            }
        }

        if !path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| CatalogError::io(&path, e))?;
        } else {
            let mode = std::fs::metadata(&path)
                .map_err(|e| CatalogError::io(&path, e))?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                return Err(CatalogError::Validation(format!(
                    "{} must not be accessible by group or others (mode {mode:04o})",
                    path.display()
                )));
            }
        }

        let catalog = Catalog { path };
        let mut conn = catalog.connection()?;
        migrate(&mut conn)?;
        Ok(catalog)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schema_version(&self) -> i64 {
        SCHEMA_VERSION
    }

    pub fn snapshot(&self) -> CatalogResult<CatalogSnapshot> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let snapshot = snapshot_from(&tx)?;
        tx.commit()?;
        Ok(snapshot)
    }
}

mod projects;
mod resources;
mod schema;
mod snapshot;
mod surfaces;
mod validation;

use schema::migrate;
use snapshot::{snapshot_from, validate_snapshot_conflicts};
pub use snapshot::{resolve_catalog_snapshot, resolve_catalog_surface};
use validation::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EntrySpec, SshRouteSpec};

    fn project() -> Project {
        Project {
            id: "floria".to_string(),
            name: "floria".to_string(),
            path: PathBuf::from("/workspace/floria"),
            default_environment_id: None,
        }
    }

    fn environment() -> Environment {
        Environment {
            id: "development".to_string(),
            project_id: "floria".to_string(),
            name: "Development".to_string(),
            position: 0,
        }
    }

    fn scalar_resource(id: &str, key: &str) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::SharedSecret,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: Some(key.to_string()),
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: key.to_string(),
                key: Some(key.to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: format!("secret-{id}") },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        }
    }

    fn env_file_resource(id: &str) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Dotenv,
            default_env_key: None,
            entries: vec![
                EntrySpec {
                    address: "keys/API_HOST".to_string(),
                    label: "API_HOST".to_string(),
                    key: Some("API_HOST".to_string()),
                    sensitive: true,
                },
                EntrySpec {
                    address: "keys/LOG_LEVEL".to_string(),
                    label: "LOG_LEVEL".to_string(),
                    key: Some("LOG_LEVEL".to_string()),
                    sensitive: true,
                },
            ],
            source: ResourceSource::SecretRef { secret_id: format!("secret-{id}") },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        }
    }

    fn socket_resource(id: &str) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::SshAgent,
            shape: ValueShape::Socket,
            codec: ResourceCodec::Opaque,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "ssh/sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                label: "Fleet key".to_string(),
                key: None,
                sensitive: false,
            }],
            source: ResourceSource::Socket,
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        }
    }

    fn binding(id: &str, resource_id: &str, scope: BindingScope) -> Binding {
        Binding {
            id: id.to_string(),
            project_id: "floria".to_string(),
            scope,
            resource_id: resource_id.to_string(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 0,
        }
    }

    fn catalog() -> (tempfile::TempDir, Catalog) {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog.upsert_project(&project()).unwrap();
        catalog.upsert_environment(&environment()).unwrap();
        (dir, catalog)
    }

    #[test]
    fn rejects_old_schema_during_development() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();

        let error = migrate(&mut conn).unwrap_err();
        assert!(matches!(
            error,
            CatalogError::UnsupportedSchema {
                found: 1,
                expected: SCHEMA_VERSION
            }
        ));
    }

    #[test]
    fn fresh_catalog_persists_current_schema_version_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite");

        let catalog = Catalog::open(&path).unwrap();
        assert_eq!(catalog.schema_version(), SCHEMA_VERSION);
        drop(catalog);

        let reopened = Catalog::open(&path).unwrap();
        let persisted: i64 = reopened
            .connection()
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(persisted, SCHEMA_VERSION);
    }

    #[test]
    fn append_resource_origin_deduplicates_by_path() {
        let (_dir, catalog) = catalog();
        catalog.upsert_resource(&scalar_resource("fixture-secret", "API_TOKEN")).unwrap();
        let source = OriginSource {
            path: PathBuf::from("/workspace/floria/.env"),
            project_id: Some("floria".to_string()),
            environment: Some("development".to_string()),
            imported_at: "2026-07-24T00:00:00Z".to_string(),
        };

        catalog.append_resource_origin("fixture-secret", &source).unwrap();
        catalog.append_resource_origin("fixture-secret", &source).unwrap();
        let other = OriginSource {
            path: PathBuf::from("/workspace/floria/.env.production"),
            ..source.clone()
        };
        catalog.append_resource_origin("fixture-secret", &other).unwrap();

        let snapshot = catalog.snapshot().unwrap();
        let resource =
            snapshot.resources.iter().find(|resource| resource.id == "fixture-secret").unwrap();
        assert_eq!(resource.origin.sources.len(), 2);
        assert_eq!(resource.origin.sources[0].path, Path::new("/workspace/floria/.env"));
        assert!(catalog
            .append_resource_origin("missing", &source)
            .is_err());
    }

    #[test]
    fn entry_selection_must_reference_exposed_entries() {
        let (_dir, catalog) = catalog();
        catalog.upsert_resource(&env_file_resource("fixture-env-file")).unwrap();
        let mut selected = binding(
            "env-file-binding",
            "fixture-env-file",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/API_HOST".to_string()],
        };
        catalog.upsert_binding(&selected).unwrap();

        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/MISSING".to_string()],
        };
        let error = catalog.upsert_binding(&selected).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("not exposed")));
    }

    #[test]
    fn entry_selection_projects_only_the_selected_named_values() {
        let (_dir, catalog) = catalog();
        catalog.upsert_resource(&env_file_resource("fixture-sections")).unwrap();
        let mut selected = binding(
            "section-binding",
            "fixture-sections",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/LOG_LEVEL".to_string()],
        };
        catalog.upsert_binding(&selected).unwrap();

        let resolved = catalog.resolve_environment("floria", "development").unwrap();
        assert_eq!(resolved.exports.len(), 1);
        assert_eq!(resolved.exports[0].key, "LOG_LEVEL");
        assert_eq!(resolved.exports[0].address, "keys/LOG_LEVEL");
    }

    #[test]
    fn ini_keys_are_generic_until_selected_for_a_dotenv_projection() {
        let (_dir, catalog) = catalog();
        let resource = Resource {
            id: "fixture-ini".to_string(),
            name: "Fixture INI".to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Ini,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "sections/fixture/keys/credential-process".to_string(),
                label: "[fixture] credential-process".to_string(),
                key: Some("credential-process".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: "fixture-ini-secret".to_string() },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        };
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding(
                "fixture-ini-binding",
                &resource.id,
                BindingScope::Environment { environment_id: "development".to_string() },
            ))
            .unwrap();

        let error = catalog
            .upsert_surface(&Surface {
                id: "fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: PathBuf::from("/workspace/floria/.env"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["fixture-ini-binding".to_string()],
                },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();

        assert!(matches!(error, CatalogError::Validation(message) if message.contains("cannot feed dotenv")));

        let mut ini_surface = Surface {
            id: "fixture-ini-output".to_string(),
            environment_id: "development".to_string(),
            name: "credentials.ini".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
            path: PathBuf::from("/workspace/floria/credentials.ini"),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["fixture-ini-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&ini_surface).unwrap();

        let mut duplicate = resource.clone();
        duplicate.id = "fixture-ini-duplicate".to_string();
        duplicate.source = ResourceSource::SecretRef {
            secret_id: "fixture-ini-secret-two".to_string(),
        };
        catalog.upsert_resource(&duplicate).unwrap();
        catalog
            .upsert_binding(&binding(
                "fixture-ini-binding-two",
                &duplicate.id,
                BindingScope::Environment { environment_id: "development".to_string() },
            ))
            .unwrap();
        ini_surface.input = SurfaceInput::Bindings {
            binding_ids: vec![
                "fixture-ini-binding".to_string(),
                "fixture-ini-binding-two".to_string(),
            ],
        };
        assert!(matches!(
            catalog.upsert_surface(&ini_surface),
            Err(CatalogError::Conflict { key, .. })
                if key == "sections/fixture/keys/credential-process"
        ));
    }

    #[test]
    fn snapshot_round_trips_typed_metadata_without_secret_values() {
        let (_dir, catalog) = catalog();
        let mut resource = scalar_resource("cloudflare", "CLOUDFLARE_API_TOKEN");
        resource.enforcement = Enforcement::TouchId;
        resource.metadata.note = Some("Deployment token for the documentation zone".to_string());
        resource.metadata.links.push(crate::domain::ItemLink {
            label: "Cloudflare dashboard".to_string(),
            url: "https://dash.cloudflare.com/example/tokens".to_string(),
        });
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("common-cloudflare", "cloudflare", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: PathBuf::from("/workspace/floria/.env"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["common-cloudflare".to_string()],
                },
                enforcement: Enforcement::Allow,
                position: 0,
            })
            .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects, vec![project()]);
        assert_eq!(
            snapshot.checkouts,
            vec![ProjectCheckout {
                id: "floria".to_string(),
                project_id: "floria".to_string(),
                path: PathBuf::from("/workspace/floria"),
                environment_id: None,
                kind: ProjectCheckoutKind::Primary,
                git_common_dir: None,
            }]
        );
        assert_eq!(snapshot.environments, vec![environment()]);
        assert_eq!(snapshot.resources, vec![resource]);
        assert_eq!(snapshot.bindings.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(snapshot.surfaces[0].enforcement, Enforcement::Allow);
        assert_eq!(snapshot.resources[0].enforcement, Enforcement::TouchId);
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("plaintext"));
    }

    #[test]
    fn worktree_checkout_requires_an_environment_from_the_same_project() {
        let (_dir, catalog) = catalog();
        let checkout = ProjectCheckout {
            id: "floria-feature".to_string(),
            project_id: "floria".to_string(),
            path: PathBuf::from("/workspace/floria-feature"),
            environment_id: Some("development".to_string()),
            kind: ProjectCheckoutKind::Worktree,
            git_common_dir: Some(PathBuf::from("/workspace/floria/.git")),
        };
        catalog.upsert_checkout(&checkout).unwrap();
        assert_eq!(catalog.snapshot().unwrap().checkouts[1], checkout);

        let mut without_environment = checkout.clone();
        without_environment.id = "floria-unassigned".to_string();
        without_environment.path = PathBuf::from("/workspace/floria-unassigned");
        without_environment.environment_id = None;
        assert!(matches!(
            catalog.upsert_checkout(&without_environment),
            Err(CatalogError::Validation(message))
                if message.contains("must select an environment")
        ));

        assert!(matches!(
            catalog.remove_checkout("floria"),
            Err(CatalogError::Validation(message))
                if message.contains("cannot be removed separately")
        ));
        catalog.remove_checkout(&checkout.id).unwrap();
        assert_eq!(catalog.snapshot().unwrap().checkouts.len(), 1);
    }

    #[test]
    fn surface_paths_are_persisted_relative_to_the_primary_checkout() {
        let (_dir, catalog) = catalog();
        let surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".config/dev.env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: PathBuf::from("/workspace/floria/.config/dev.env"),
            input: SurfaceInput::Bindings { binding_ids: Vec::new() },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();

        let relative: String = catalog
            .connection()
            .unwrap()
            .query_row(
                "SELECT relative_path FROM surfaces WHERE id = ?1",
                [&surface.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(relative, ".config/dev.env");
        assert_eq!(catalog.snapshot().unwrap().surfaces, vec![surface]);
    }

    #[test]
    fn create_resource_refuses_to_replace_existing_metadata() {
        let (_dir, catalog) = catalog();
        let resource = scalar_resource("fixture-shared", "FIXTURE_TOKEN");
        catalog.create_resource(&resource).unwrap();
        let mut replacement = resource.clone();
        replacement.name = "Replacement".to_string();

        assert!(matches!(
            catalog.create_resource(&replacement),
            Err(CatalogError::AlreadyExists { kind: "resource", .. })
        ));
        assert_eq!(catalog.resource(&resource.id).unwrap().name, resource.name);
    }

    #[test]
    fn resource_usage_expands_common_binding_to_affected_surfaces() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_environment(&Environment {
                id: "staging".to_string(),
                project_id: "floria".to_string(),
                name: "Staging".to_string(),
                position: 1,
            })
            .unwrap();
        let resource = scalar_resource("fixture-shared", "FIXTURE_TOKEN");
        catalog.create_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("fixture-common", &resource.id, BindingScope::Common))
            .unwrap();
        for (id, environment_id, path) in [
            ("fixture-dev-env", "development", "/workspace/floria/.env"),
            ("fixture-stage-env", "staging", "/workspace/floria/.env.staging"),
        ] {
            catalog
                .upsert_surface(&Surface {
                    id: id.to_string(),
                    environment_id: environment_id.to_string(),
                    name: ".env".to_string(),
                    kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                    path: PathBuf::from(path),
                    input: SurfaceInput::Bindings {
                        binding_ids: vec!["fixture-common".to_string()],
                    },
                    enforcement: Enforcement::Prompt,
                    position: 0,
                })
                .unwrap();
        }

        let usage = catalog.resource_usage(&resource.id).unwrap();
        assert_eq!(usage.bindings.len(), 1);
        assert_eq!(usage.bindings[0].environment_ids, vec!["development", "staging"]);
        assert_eq!(
            usage.bindings[0].surface_ids,
            vec!["fixture-dev-env", "fixture-stage-env"]
        );
        assert!(usage.direct_surface_ids.is_empty());
        assert!(matches!(
            catalog.remove_resource(&resource.id),
            Err(CatalogError::ResourceInUse { binding_ids, .. })
                if binding_ids == vec!["fixture-common"]
        ));
    }

    #[test]
    fn surface_path_must_stay_inside_its_project() {
        let (_dir, catalog) = catalog();
        let error = catalog
            .upsert_surface(&Surface {
                id: "fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: PathBuf::from("/workspace/other/.env"),
                input: SurfaceInput::Bindings { binding_ids: vec![] },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();
        assert!(matches!(error, CatalogError::Validation(_)));
    }

    #[test]
    fn surface_id_must_be_one_safe_path_component() {
        let (_dir, catalog) = catalog();
        let error = catalog
            .upsert_surface(&Surface {
                id: "../fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: PathBuf::from("/workspace/floria/.env"),
                input: SurfaceInput::Bindings { binding_ids: vec![] },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();
        assert!(matches!(error, CatalogError::Validation(_)));
    }

    #[test]
    fn direct_env_file_surface_requires_and_protects_its_env_file_resource() {
        let (_dir, catalog) = catalog();
        let resource = env_file_resource("fixture-env-file");
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-direct-env".to_string(),
                environment_id: "development".to_string(),
                name: ".env.local".to_string(),
                kind: SurfaceKind::File(FileBacking::EnvFileDirect),
                path: PathBuf::from("/workspace/floria/.env.local"),
                input: SurfaceInput::Resource { resource_id: resource.id.clone() },
                enforcement: Enforcement::Prompt,
                position: 1,
            })
            .unwrap();

        let usage = catalog.resource_usage(&resource.id).unwrap();
        assert_eq!(usage.direct_surface_ids, vec!["fixture-direct-env"]);

        let mut incompatible = resource.clone();
        incompatible.kind = ResourceKind::Command;
        incompatible.source = ResourceSource::Command { argv: vec!["fixture-command".to_string()] };
        assert!(matches!(
            catalog.upsert_resource(&incompatible),
            Err(CatalogError::Validation(_))
        ));
        assert_eq!(catalog.resource(&resource.id).unwrap(), resource);
    }

    #[test]
    fn direct_env_file_surface_rejects_missing_or_scalar_resource() {
        let (_dir, catalog) = catalog();
        let missing = Surface {
            id: "fixture-direct-env".to_string(),
            environment_id: "development".to_string(),
            name: ".env.local".to_string(),
            kind: SurfaceKind::File(FileBacking::EnvFileDirect),
            path: PathBuf::from("/workspace/floria/.env.local"),
            input: SurfaceInput::Bindings { binding_ids: vec![] },
            enforcement: Enforcement::Prompt,
            position: 1,
        };
        assert!(matches!(
            catalog.upsert_surface(&missing),
            Err(CatalogError::Validation(_))
        ));

        let scalar = scalar_resource("fixture-scalar", "FIXTURE_TOKEN");
        catalog.upsert_resource(&scalar).unwrap();
        assert!(matches!(
            catalog.upsert_surface(&Surface {
                input: SurfaceInput::Resource { resource_id: scalar.id },
                ..missing
            }),
            Err(CatalogError::Validation(_))
        ));
    }

    #[test]
    fn conflicting_surface_membership_is_rejected_and_transaction_rolls_back() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("first", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("second", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("first-binding", "first", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_binding(&binding("second-binding", "second", BindingScope::Common))
            .unwrap();
        let mut surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: PathBuf::from("/workspace/floria/.env"),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["first-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();

        surface.input = SurfaceInput::Bindings {
            binding_ids: vec!["first-binding".to_string(), "second-binding".to_string()],
        };
        let error = catalog.upsert_surface(&surface).unwrap_err();
        assert!(matches!(error, CatalogError::Conflict { ref key, .. } if key == "TOKEN"));
        assert_eq!(
            catalog.snapshot().unwrap().surfaces[0].input,
            SurfaceInput::Bindings {
                binding_ids: vec!["first-binding".to_string()]
            }
        );
    }

    #[test]
    fn the_same_key_can_belong_to_separate_surfaces() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("first", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("second", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("first-binding", "first", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_binding(&binding("second-binding", "second", BindingScope::Common))
            .unwrap();

        for (id, name, binding_id, kind) in [
            (
                "first-surface",
                ".env.first",
                "first-binding",
                SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            ),
            (
                "second-surface",
                ".envrc",
                "second-binding",
                SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv)),
            ),
        ] {
            catalog
                .upsert_surface(&Surface {
                    id: id.to_string(),
                    environment_id: "development".to_string(),
                    name: name.to_string(),
                    kind,
                    path: PathBuf::from("/workspace/floria").join(name),
                    input: SurfaceInput::Bindings {
                        binding_ids: vec![binding_id.to_string()],
                    },
                    enforcement: Enforcement::Prompt,
                    position: 0,
                })
                .unwrap();
        }

        assert_eq!(catalog.snapshot().unwrap().surfaces.len(), 2);
    }

    #[test]
    fn surface_rejects_unknown_members_and_binding_removal_detaches_membership() {
        let (_dir, catalog) = catalog();
        let resource = scalar_resource("fixture", "FIXTURE_TOKEN");
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("fixture-binding", &resource.id, BindingScope::Common))
            .unwrap();
        let mut surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: PathBuf::from("/workspace/floria/.env"),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["missing-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        assert!(matches!(
            catalog.upsert_surface(&surface),
            Err(CatalogError::NotFound(message)) if message.contains("missing-binding")
        ));

        surface.input = SurfaceInput::Bindings {
            binding_ids: vec!["fixture-binding".to_string()],
        };
        catalog.upsert_surface(&surface).unwrap();
        catalog.remove_binding("fixture-binding").unwrap();

        assert_eq!(
            catalog.snapshot().unwrap().surfaces[0].input,
            SurfaceInput::Bindings { binding_ids: Vec::new() }
        );
    }

    #[test]
    fn environment_binding_can_explicitly_override_common_key() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("common", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("development-token", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("common-binding", "common", BindingScope::Common))
            .unwrap();
        let mut environment_binding = binding(
            "development-binding",
            "development-token",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        environment_binding.allow_override = true;
        catalog.upsert_binding(&environment_binding).unwrap();

        let resolved = catalog.resolve_environment("floria", "development").unwrap();
        assert_eq!(resolved.exports.len(), 1);
        assert_eq!(resolved.exports[0].binding_id, "development-binding");
        assert_eq!(
            resolved.exports[0].overrides_binding_id.as_deref(),
            Some("common-binding")
        );
    }

    #[test]
    fn key_override_is_only_allowed_for_scalar_resources() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&Resource {
                id: "defaults".to_string(),
                name: "Defaults".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Dotenv,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "keys/LOG_LEVEL".to_string(),
                    label: "LOG_LEVEL".to_string(),
                    key: Some("LOG_LEVEL".to_string()),
                    sensitive: false,
                }],
                source: ResourceSource::SecretRef { secret_id: "secret-defaults".to_string() },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            })
            .unwrap();
        let mut binding = binding(
            "defaults-binding",
            "defaults",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        binding.key_override = Some("OTHER".to_string());
        let error = catalog.upsert_binding(&binding).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("scalar")));
    }

    #[test]
    fn socket_endpoint_is_machine_local_and_tracks_resource_atomically() {
        let (_dir, catalog) = catalog();
        let socket = socket_resource("fixture-agent-provider");

        assert!(matches!(
            catalog.upsert_resource(&socket),
            Err(CatalogError::Validation(message))
                if message.contains("machine-local endpoint")
        ));
        catalog
            .upsert_socket_resource(&socket, Path::new("/fixture/upstream-agent.sock"))
            .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources, vec![socket.clone()]);
        assert_eq!(
            snapshot.endpoints.get(&socket.id).map(PathBuf::as_path),
            Some(Path::new("/fixture/upstream-agent.sock"))
        );
        let source_json: String = catalog
            .connection()
            .unwrap()
            .query_row(
                "SELECT source_json FROM resources WHERE id = ?1",
                [&socket.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(source_json, r#"{"type":"socket"}"#);

        let scalar = scalar_resource(&socket.id, "FIXTURE_TOKEN");
        catalog.upsert_resource(&scalar).unwrap();
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources, vec![scalar]);
        assert!(!snapshot.endpoints.contains_key(&socket.id));
    }

    #[test]
    fn concurrent_snapshots_never_observe_a_socket_without_its_endpoint() {
        let (_dir, catalog) = catalog();
        let resource_id = "fixture-switching-provider";
        catalog
            .upsert_resource(&scalar_resource(resource_id, "FIXTURE_TOKEN"))
            .unwrap();

        let writer = catalog.clone();
        let writer_thread = std::thread::spawn(move || {
            for _ in 0..30 {
                writer
                    .upsert_socket_resource(
                        &socket_resource(resource_id),
                        Path::new("/fixture/upstream-agent.sock"),
                    )
                    .unwrap();
                writer
                    .upsert_resource(&scalar_resource(resource_id, "FIXTURE_TOKEN"))
                    .unwrap();
            }
        });
        for _ in 0..100 {
            let snapshot = catalog.snapshot().unwrap();
            let resource = snapshot
                .resources
                .iter()
                .find(|resource| resource.id == resource_id)
                .unwrap();
            assert_eq!(
                resource.source == ResourceSource::Socket,
                snapshot.endpoints.contains_key(resource_id)
            );
        }
        writer_thread.join().unwrap();
    }

    #[test]
    fn ssh_agent_surface_composes_managed_and_external_identity_bindings() {
        let (_dir, catalog) = catalog();
        let address =
            "ssh/sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let mut external = socket_resource("fixture-agent-provider");
        external.name = "Fixture Agent".to_string();
        external.entries[0].address = address.clone();
        catalog
            .upsert_socket_resource(&external, Path::new("/fixture/upstream-agent.sock"))
            .unwrap();
        let mut selected = binding(
            "fixture-agent-binding",
            "fixture-agent-provider",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec![address.clone()],
        };
        catalog.upsert_binding(&selected).unwrap();
        let managed_address =
            "ssh/sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string();
        catalog
            .upsert_resource(&Resource {
                id: "fixture-managed-identity".to_string(),
                name: "Fixture Managed Identity".to_string(),
                kind: ResourceKind::SshIdentity,
                shape: ValueShape::SshIdentity,
                codec: ResourceCodec::Opaque,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: managed_address,
                    label: "Managed fleet key".to_string(),
                    key: None,
                    sensitive: false,
                }],
                source: ResourceSource::SecretRef {
                    secret_id: "fixture-managed-private-key".to_string(),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            })
            .unwrap();
        let managed = binding(
            "fixture-managed-binding",
            "fixture-managed-identity",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        catalog.upsert_binding(&managed).unwrap();

        let surface = Surface {
            id: "fixture-agent-surface".to_string(),
            environment_id: "development".to_string(),
            name: "AWS fleet".to_string(),
            kind: SurfaceKind::UnixSocket,
            path: PathBuf::from("/workspace/floria/.floria/agent.sock"),
            input: SurfaceInput::SshAgent {
                binding_ids: vec![selected.id.clone(), managed.id],
                route: Some(SshRouteSpec {
                    host_patterns: vec!["ec2-*.example.internal".to_string()],
                    hostname: None,
                    user: Some("ubuntu".to_string()),
                    port: None,
                    forward_agent: true,
                }),
            },
            enforcement: Enforcement::TouchId,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();

        let conflicting_route = Surface {
            id: "fixture-agent-surface-two".to_string(),
            name: "Duplicate route".to_string(),
            path: PathBuf::from("/workspace/floria/.floria/agent-two.sock"),
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&conflicting_route).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("ec2-*.example.internal")));

        let invalid_route = Surface {
            input: SurfaceInput::SshAgent {
                binding_ids: vec!["fixture-agent-binding".to_string()],
                route: Some(SshRouteSpec {
                    host_patterns: vec!["fixture\nHost injected".to_string()],
                    hostname: None,
                    user: None,
                    port: None,
                    forward_agent: false,
                }),
            },
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&invalid_route).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("host pattern")));

        let direct = Surface {
            input: SurfaceInput::Resource {
                resource_id: "fixture-agent-provider".to_string(),
            },
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&direct).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("incompatible")));

        let duplicate = Binding {
            id: "fixture-agent-binding-duplicate".to_string(),
            ..selected
        };
        catalog.upsert_binding(&duplicate).unwrap();
        let duplicated_surface = Surface {
            input: SurfaceInput::Bindings {
                binding_ids: vec![
                    "fixture-agent-binding".to_string(),
                    "fixture-agent-binding-duplicate".to_string(),
                ],
            },
            ..surface
        };
        let error = catalog.upsert_surface(&duplicated_surface).unwrap_err();
        assert!(matches!(error, CatalogError::Conflict { key, .. } if key == address));
    }

    #[test]
    fn catalog_file_is_private() {
        let (dir, _catalog) = catalog();
        let mode = std::fs::metadata(dir.path().join("catalog.sqlite"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
