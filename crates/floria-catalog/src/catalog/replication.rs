use super::*;

const REPLICATED_CATALOG_FORMAT_VERSION: u32 = 1;

impl Catalog {
    /// Return only the stable, portable half of the catalog.
    pub fn replicated_catalog(&self) -> CatalogResult<ReplicatedCatalog> {
        self.with_authenticated_read(|tx, snapshot| {
            replicated_catalog_from(tx, &snapshot.catalog)
        })
    }

    /// Replace shared catalog state while retaining machine-local checkouts, endpoints, and
    /// resource origins. The complete projection is validated before one authenticated SQLite
    /// transaction becomes visible.
    pub fn apply_replicated_catalog(&self, projection: &ReplicatedCatalog) -> CatalogResult<()> {
        validate_replicated_catalog(projection)?;
        self.with_authenticated_mutation(|tx| {
            for project in &projection.projects {
                tx.execute(
                    "INSERT INTO projects (id, name, default_environment_id)
                     VALUES (?1, ?2, NULL)
                     ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                         default_environment_id = NULL,
                         updated_at = CURRENT_TIMESTAMP",
                    params![project.id, project.name],
                )?;
            }

            delete_rows_not_in(tx, "surfaces", projection.surfaces.iter().map(|row| &row.id))?;
            delete_rows_not_in(tx, "bindings", projection.bindings.iter().map(|row| &row.id))?;
            delete_rows_not_in(
                tx,
                "environments",
                projection.environments.iter().map(|row| &row.id),
            )?;
            delete_rows_not_in(tx, "projects", projection.projects.iter().map(|row| &row.id))?;
            delete_rows_not_in(tx, "resources", projection.resources.iter().map(|row| &row.id))?;

            for environment in &projection.environments {
                tx.execute(
                    "INSERT INTO environments (id, project_id, name, position)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                         name = excluded.name, position = excluded.position,
                         updated_at = CURRENT_TIMESTAMP",
                    params![
                        environment.id,
                        environment.project_id,
                        environment.name,
                        environment.position
                    ],
                )?;
            }

            for resource in &projection.resources {
                tx.execute(
                    "INSERT INTO resources
                        (id, name, kind, shape, codec, default_env_key, entries_json, source_json,
                         enforcement, metadata_json, origin_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                     ON CONFLICT(id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
                         shape = excluded.shape, codec = excluded.codec,
                         default_env_key = excluded.default_env_key,
                         entries_json = excluded.entries_json, source_json = excluded.source_json,
                         enforcement = excluded.enforcement, metadata_json = excluded.metadata_json,
                         updated_at = CURRENT_TIMESTAMP",
                    params![
                        resource.id,
                        resource.name,
                        resource.kind.as_str(),
                        resource.shape.as_str(),
                        resource.codec.as_str(),
                        resource.default_env_key,
                        serde_json::to_string(&resource.entries)?,
                        serde_json::to_string(&resource.source)?,
                        resource.enforcement.as_str(),
                        serde_json::to_string(&resource.metadata)?,
                        serde_json::to_string(&ResourceOrigin::default())?,
                    ],
                )?;
            }

            for binding in &projection.bindings {
                let environment_id = match &binding.scope {
                    BindingScope::Common => None,
                    BindingScope::Environment { environment_id } => Some(environment_id),
                };
                tx.execute(
                    "INSERT INTO bindings
                        (id, project_id, environment_id, resource_id, key_override, enabled,
                         allow_override, position, selection_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                         environment_id = excluded.environment_id,
                         resource_id = excluded.resource_id, key_override = excluded.key_override,
                         enabled = excluded.enabled, allow_override = excluded.allow_override,
                         position = excluded.position, selection_json = excluded.selection_json,
                         updated_at = CURRENT_TIMESTAMP",
                    params![
                        binding.id,
                        binding.project_id,
                        environment_id,
                        binding.resource_id,
                        binding.key_override,
                        binding.enabled,
                        binding.allow_override,
                        binding.position,
                        serde_json::to_string(&binding.selection)?,
                    ],
                )?;
            }

            for surface in &projection.surfaces {
                tx.execute(
                    "INSERT INTO surfaces
                        (id, environment_id, name, kind, relative_path, input_json, enforcement,
                         position)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(id) DO UPDATE SET environment_id = excluded.environment_id,
                         name = excluded.name, kind = excluded.kind,
                         relative_path = excluded.relative_path, input_json = excluded.input_json,
                         enforcement = excluded.enforcement, position = excluded.position,
                         updated_at = CURRENT_TIMESTAMP",
                    params![
                        surface.id,
                        surface.environment_id,
                        surface.name,
                        surface.kind.as_str(),
                        surface
                            .relative_path
                            .as_deref()
                            .map(path_string)
                            .unwrap_or_default(),
                        serde_json::to_string(&surface.input)?,
                        surface.enforcement.as_str(),
                        surface.position,
                    ],
                )?;
            }

            for project in &projection.projects {
                tx.execute(
                    "UPDATE projects SET default_environment_id = ?2,
                         updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
                    params![project.id, project.default_environment_id],
                )?;
            }
            Ok(())
        })
    }
}

pub(super) fn replicated_catalog_from(
    conn: &Connection,
    snapshot: &CatalogSnapshot,
) -> CatalogResult<ReplicatedCatalog> {
    let resources = snapshot
        .resources
        .iter()
        .cloned()
        .map(|mut resource| {
            resource.origin = ResourceOrigin::default();
            resource
        })
        .collect();
    Ok(ReplicatedCatalog {
        format_version: REPLICATED_CATALOG_FORMAT_VERSION,
        projects: replicated_projects_from(conn)?,
        environments: snapshot.environments.clone(),
        resources,
        bindings: snapshot.bindings.clone(),
        surfaces: replicated_surfaces_from(conn)?,
    })
}

fn replicated_projects_from(conn: &Connection) -> CatalogResult<Vec<ReplicatedProject>> {
    let mut statement = conn.prepare(
        "SELECT id, name, default_environment_id FROM projects ORDER BY name, id",
    )?;
    let projects = statement
        .query_map([], |row| {
            Ok(ReplicatedProject {
                id: row.get(0)?,
                name: row.get(1)?,
                default_environment_id: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(projects)
}

fn replicated_surfaces_from(conn: &Connection) -> CatalogResult<Vec<ReplicatedSurface>> {
    let mut statement = conn.prepare(
        "SELECT id, environment_id, name, kind, relative_path, input_json, enforcement, position
         FROM surfaces ORDER BY environment_id, position, name, id",
    )?;
    let surfaces = statement
        .query_map([], |row| {
            let kind_value: String = row.get(3)?;
            let kind = SurfaceKind::parse(&kind_value)
                .ok_or_else(|| invalid_value(3, kind_value))?;
            let enforcement_value: String = row.get(6)?;
            let relative_path: String = row.get(4)?;
            Ok(ReplicatedSurface {
                id: row.get(0)?,
                environment_id: row.get(1)?,
                name: row.get(2)?,
                kind,
                relative_path: kind.is_file().then(|| PathBuf::from(relative_path)),
                input: decode_json(5, &row.get::<_, String>(5)?)?,
                enforcement: Enforcement::parse(&enforcement_value)
                    .ok_or_else(|| invalid_value(6, enforcement_value))?,
                position: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(surfaces)
}

/// Validate a portable projection without writing it to the local catalog.
///
/// Replication uses this as the semantic gate after independent entity records are assembled.
pub fn validate_replicated_catalog(projection: &ReplicatedCatalog) -> CatalogResult<()> {
    if projection.format_version != REPLICATED_CATALOG_FORMAT_VERSION {
        return Err(CatalogError::Validation(format!(
            "unsupported replicated catalog format {}",
            projection.format_version
        )));
    }
    let mut project_ids = HashSet::new();
    let projects = projection
        .projects
        .iter()
        .enumerate()
        .map(|(index, project)| {
            require_id(&project.id, "replicated project id")?;
            require_name(&project.name, "replicated project name")?;
            if !project_ids.insert(project.id.as_str()) {
                return Err(CatalogError::Validation(format!(
                    "replicated project {:?} is duplicated",
                    project.id
                )));
            }
            Ok(Project {
                id: project.id.clone(),
                name: project.name.clone(),
                path: PathBuf::from(format!("/floria-replication-validation/{index}")),
                default_environment_id: project.default_environment_id.clone(),
            })
        })
        .collect::<CatalogResult<Vec<_>>>()?;

    let mut environment_ids = HashSet::new();
    for environment in &projection.environments {
        validate_environment(environment)?;
        if !project_ids.contains(environment.project_id.as_str())
            || !environment_ids.insert(environment.id.as_str())
        {
            return Err(CatalogError::Validation(format!(
                "replicated environment {:?} has an invalid or duplicate owner",
                environment.id
            )));
        }
    }
    for project in &projection.projects {
        if project.default_environment_id.as_ref().is_some_and(|environment_id| {
            !projection.environments.iter().any(|environment| {
                environment.id == *environment_id && environment.project_id == project.id
            })
        }) {
            return Err(CatalogError::Validation(format!(
                "replicated project {:?} has an invalid default environment",
                project.id
            )));
        }
    }

    let mut resource_ids = HashSet::new();
    for resource in &projection.resources {
        validate_resource(resource)?;
        if resource.origin != ResourceOrigin::default()
            || !resource_ids.insert(resource.id.as_str())
        {
            return Err(CatalogError::Validation(format!(
                "replicated resource {:?} contains machine-local origin data or is duplicated",
                resource.id
            )));
        }
    }

    let mut binding_ids = HashSet::new();
    for binding in &projection.bindings {
        validate_binding(binding)?;
        if !project_ids.contains(binding.project_id.as_str())
            || !resource_ids.contains(binding.resource_id.as_str())
            || !binding_ids.insert(binding.id.as_str())
        {
            return Err(CatalogError::Validation(format!(
                "replicated binding {:?} has an invalid owner, resource, or duplicate id",
                binding.id
            )));
        }
        if let BindingScope::Environment { environment_id } = &binding.scope {
            if !projection.environments.iter().any(|environment| {
                environment.id == *environment_id && environment.project_id == binding.project_id
            }) {
                return Err(CatalogError::Validation(format!(
                    "replicated binding {:?} has an invalid environment",
                    binding.id
                )));
            }
        }
    }

    let project_paths = projects
        .iter()
        .map(|project| (project.id.as_str(), project.path.as_path()))
        .collect::<HashMap<_, _>>();
    let environment_projects = projection
        .environments
        .iter()
        .map(|environment| (environment.id.as_str(), environment.project_id.as_str()))
        .collect::<HashMap<_, _>>();
    let mut surface_ids = HashSet::new();
    let surfaces = projection
        .surfaces
        .iter()
        .map(|surface| {
            let project_id = environment_projects
                .get(surface.environment_id.as_str())
                .ok_or_else(|| {
                    CatalogError::Validation(format!(
                        "replicated surface {:?} has an invalid environment",
                        surface.id
                    ))
                })?;
            let path = match (surface.kind.is_file(), surface.relative_path.as_deref()) {
                (true, Some(relative))
                    if !relative.as_os_str().is_empty()
                        && relative.components().all(|component| {
                            matches!(component, std::path::Component::Normal(_))
                        }) => Some(project_paths[project_id].join(relative)),
                (false, None) => None,
                _ => {
                    return Err(CatalogError::Validation(format!(
                        "replicated surface {:?} has an invalid relative path",
                        surface.id
                    )))
                }
            };
            let local = Surface {
                id: surface.id.clone(),
                environment_id: surface.environment_id.clone(),
                name: surface.name.clone(),
                kind: surface.kind,
                path,
                input: surface.input.clone(),
                enforcement: surface.enforcement,
                position: surface.position,
            };
            validate_surface(&local)?;
            if !surface_ids.insert(surface.id.as_str()) {
                return Err(CatalogError::Validation(format!(
                    "replicated surface {:?} is duplicated",
                    surface.id
                )));
            }
            Ok(local)
        })
        .collect::<CatalogResult<Vec<_>>>()?;

    validate_snapshot_conflicts(&CatalogSnapshot {
        projects,
        checkouts: Vec::new(),
        environments: projection.environments.clone(),
        resources: projection.resources.clone(),
        endpoints: HashMap::new(),
        bindings: projection.bindings.clone(),
        surfaces,
    })
}

fn delete_rows_not_in<'a>(
    tx: &Transaction<'_>,
    table: &str,
    retained: impl Iterator<Item = &'a String>,
) -> CatalogResult<()> {
    let retained = retained.map(String::as_str).collect::<HashSet<_>>();
    let mut statement = tx.prepare(&format!("SELECT id FROM {table}"))?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for id in ids.into_iter().filter(|id| !retained.contains(id.as_str())) {
        tx.execute(&format!("DELETE FROM {table} WHERE id = ?1"), [&id])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::EntrySpec;

    fn project(path: &str) -> Project {
        Project {
            id: "project-1".to_string(),
            name: "Example".to_string(),
            path: PathBuf::from(path),
            default_environment_id: None,
        }
    }

    fn environment() -> Environment {
        Environment {
            id: "development".to_string(),
            project_id: "project-1".to_string(),
            name: "Development".to_string(),
            position: 0,
        }
    }

    fn resource(origin_path: &str) -> Resource {
        Resource {
            id: "resource-1".to_string(),
            name: "API token".to_string(),
            kind: ResourceKind::SharedSecret,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: Some("API_TOKEN".to_string()),
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: "API_TOKEN".to_string(),
                key: Some("API_TOKEN".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef {
                secret_id: "11111111-1111-4111-8111-111111111111".to_string(),
                managed_source_ids: Vec::new(),
            },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: ResourceOrigin {
                kind: OriginKind::Discovered,
                sources: vec![OriginSource {
                    path: PathBuf::from(origin_path),
                    project_id: Some("project-1".to_string()),
                    environment: Some("Development".to_string()),
                    imported_at: "2026-08-06T00:00:00Z".to_string(),
                }],
            },
        }
    }

    fn binding() -> Binding {
        Binding {
            id: "binding-1".to_string(),
            project_id: "project-1".to_string(),
            scope: BindingScope::Common,
            resource_id: "resource-1".to_string(),
            ..Default::default()
        }
    }

    fn surface(path: &str) -> Surface {
        Surface {
            id: "env-file".to_string(),
            environment_id: "development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: Some(PathBuf::from(path)),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["binding-1".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        }
    }

    fn source_catalog() -> (tempfile::TempDir, Catalog) {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        catalog.upsert_project(&project("/source/example")).unwrap();
        catalog.upsert_environment(&environment()).unwrap();
        catalog
            .upsert_resource(&resource("/source/example/.env"))
            .unwrap();
        catalog.upsert_binding(&binding()).unwrap();
        catalog.upsert_surface(&surface("/source/example/.env")).unwrap();
        (directory, catalog)
    }

    #[test]
    fn projection_omits_machine_local_paths_and_attaches_to_a_new_checkout() {
        let (_source_directory, source) = source_catalog();
        let projection = source.replicated_catalog().unwrap();
        assert_eq!(projection.surfaces[0].relative_path, Some(PathBuf::from(".env")));
        assert_eq!(projection.resources[0].origin, ResourceOrigin::default());

        let target_directory = tempfile::tempdir().unwrap();
        let target = Catalog::open(target_directory.path().join("catalog.sqlite")).unwrap();
        target.apply_replicated_catalog(&projection).unwrap();
        assert_eq!(target.replicated_catalog().unwrap(), projection);
        assert!(target.snapshot().unwrap().projects.is_empty());

        target.upsert_project(&project("/target/example")).unwrap();
        let snapshot = target.snapshot().unwrap();
        assert_eq!(snapshot.projects[0].path, PathBuf::from("/target/example"));
        assert_eq!(snapshot.surfaces[0].path, Some(PathBuf::from("/target/example/.env")));
    }

    #[test]
    fn applying_projection_preserves_existing_machine_local_resource_origin() {
        let (_source_directory, source) = source_catalog();
        let projection = source.replicated_catalog().unwrap();

        let target_directory = tempfile::tempdir().unwrap();
        let target = Catalog::open(target_directory.path().join("catalog.sqlite")).unwrap();
        target.upsert_project(&project("/target/example")).unwrap();
        target.upsert_environment(&environment()).unwrap();
        let local_resource = resource("/target/example/.env");
        target.upsert_resource(&local_resource).unwrap();

        target.apply_replicated_catalog(&projection).unwrap();
        let snapshot = target.snapshot().unwrap();
        assert_eq!(snapshot.resources[0].origin, local_resource.origin);
        assert_eq!(snapshot.projects[0].path, PathBuf::from("/target/example"));
    }

    #[test]
    fn projection_preserves_stable_ssh_identity_source_ids_without_local_paths() {
        let (_source_directory, source) = source_catalog();
        let identity = Resource {
            id: "ssh-identity-1".to_string(),
            name: "Personal SSH".to_string(),
            kind: ResourceKind::SshIdentity,
            shape: ValueShape::SshIdentity,
            codec: ResourceCodec::Opaque,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: format!("ssh/sha256/{}", "a".repeat(43)),
                label: "Personal SSH".to_string(),
                key: None,
                sensitive: false,
            }],
            source: ResourceSource::SecretRef {
                secret_id: "22222222-2222-4222-8222-222222222222".to_string(),
                managed_source_ids: vec![
                    "33333333-3333-4333-8333-333333333333".to_string(),
                ],
            },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: ResourceOrigin {
                kind: OriginKind::SshImport,
                sources: vec![OriginSource {
                    path: PathBuf::from("/source/.ssh/id_ed25519"),
                    project_id: None,
                    environment: None,
                    imported_at: "2026-08-16T00:00:00Z".to_string(),
                }],
            },
        };
        source.upsert_resource(&identity).unwrap();

        let projection = source.replicated_catalog().unwrap();
        let projected = projection
            .resources
            .iter()
            .find(|resource| resource.id == identity.id)
            .unwrap();
        assert_eq!(projected.origin, ResourceOrigin::default());
        assert_eq!(projected.source, identity.source);

        let target_directory = tempfile::tempdir().unwrap();
        let target = Catalog::open(target_directory.path().join("catalog.sqlite")).unwrap();
        target.apply_replicated_catalog(&projection).unwrap();
        assert_eq!(target.resource(&identity.id).unwrap().source, identity.source);
    }
}
