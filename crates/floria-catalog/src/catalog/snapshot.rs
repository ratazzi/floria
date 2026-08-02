use super::*;
use sha2::{Digest, Sha256};

pub(super) fn snapshot_from(conn: &Connection) -> CatalogResult<CatalogSnapshot> {
    let projects = {
        let mut stmt = conn.prepare(
            "SELECT projects.id, projects.name, project_checkouts.path,
                    projects.default_environment_id
             FROM projects
             JOIN project_checkouts
               ON project_checkouts.project_id = projects.id
              AND project_checkouts.kind = 'primary'
             ORDER BY projects.name, projects.id",
        )?;
        let values = stmt.query_map([], |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                path: PathBuf::from(row.get::<_, String>(2)?),
                default_environment_id: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let checkouts = {
        let mut stmt = conn.prepare(
            "SELECT id, project_id, path, environment_id, kind, git_common_dir
             FROM project_checkouts
             ORDER BY project_id, kind = 'primary' DESC, path, id",
        )?;
        let values = stmt
            .query_map([], |row| {
                let kind: String = row.get(4)?;
                Ok(ProjectCheckout {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    path: PathBuf::from(row.get::<_, String>(2)?),
                    environment_id: row.get(3)?,
                    kind: ProjectCheckoutKind::parse(&kind)
                        .ok_or_else(|| invalid_value(4, kind))?,
                    git_common_dir: row.get::<_, Option<String>>(5)?.map(PathBuf::from),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let environments = {
        let mut stmt = conn.prepare(
            "SELECT id, project_id, name, position
             FROM environments ORDER BY project_id, position, name, id",
        )?;
        let values = stmt.query_map([], |row| {
            Ok(Environment {
                id: row.get(0)?,
                project_id: row.get(1)?,
                name: row.get(2)?,
                position: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let resources = {
        let mut stmt = conn.prepare(
            "SELECT id, name, kind, shape, codec, default_env_key, entries_json, source_json, enforcement, metadata_json, origin_json
             FROM resources ORDER BY name, id",
        )?;
        let values = stmt.query_map([], |row| {
            let kind: String = row.get(2)?;
            let shape: String = row.get(3)?;
            let codec: String = row.get(4)?;
            let enforcement: String = row.get(8)?;
            Ok(Resource {
                id: row.get(0)?,
                name: row.get(1)?,
                kind: ResourceKind::parse(&kind).ok_or_else(|| invalid_value(2, kind))?,
                shape: ValueShape::parse(&shape).ok_or_else(|| invalid_value(3, shape))?,
                codec: ResourceCodec::parse(&codec).ok_or_else(|| invalid_value(4, codec))?,
                default_env_key: row.get(5)?,
                entries: decode_json(6, &row.get::<_, String>(6)?)?,
                source: decode_json(7, &row.get::<_, String>(7)?)?,
                enforcement: Enforcement::parse(&enforcement)
                    .ok_or_else(|| invalid_value(8, enforcement))?,
                metadata: decode_json(9, &row.get::<_, String>(9)?)?,
                origin: decode_json(10, &row.get::<_, String>(10)?)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let endpoints = {
        let mut stmt = conn.prepare(
            "SELECT resource_id, endpoint FROM resource_endpoints ORDER BY resource_id",
        )?;
        let values = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, PathBuf::from(row.get::<_, String>(1)?)))
            })?
            .collect::<Result<HashMap<_, _>, _>>()?;
        values
    };

    let bindings = {
        let mut stmt = conn.prepare(
            "SELECT id, project_id, environment_id, resource_id, key_override,
                    enabled, allow_override, position, selection_json
             FROM bindings
             ORDER BY project_id, environment_id IS NOT NULL, environment_id, position, id",
        )?;
        let values = stmt.query_map([], |row| {
            let environment_id: Option<String> = row.get(2)?;
            Ok(Binding {
                id: row.get(0)?,
                project_id: row.get(1)?,
                scope: match environment_id {
                    Some(environment_id) => BindingScope::Environment { environment_id },
                    None => BindingScope::Common,
                },
                resource_id: row.get(3)?,
                key_override: row.get(4)?,
                enabled: row.get(5)?,
                allow_override: row.get(6)?,
                position: row.get(7)?,
                selection: decode_json(8, &row.get::<_, String>(8)?)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let surfaces = {
        let mut stmt = conn.prepare(
            "SELECT surfaces.id, surfaces.environment_id, surfaces.name, surfaces.kind,
                    project_checkouts.path, surfaces.relative_path, surfaces.input_json,
                    surfaces.enforcement, surfaces.position
             FROM surfaces
             JOIN environments ON environments.id = surfaces.environment_id
             JOIN project_checkouts
               ON project_checkouts.project_id = environments.project_id
              AND project_checkouts.kind = 'primary'
             ORDER BY surfaces.environment_id, surfaces.position, surfaces.name, surfaces.id",
        )?;
        let values = stmt.query_map([], |row| {
            let kind: String = row.get(3)?;
            let enforcement: String = row.get(7)?;
            let primary_path = PathBuf::from(row.get::<_, String>(4)?);
            let relative_path = PathBuf::from(row.get::<_, String>(5)?);
            let kind = SurfaceKind::parse(&kind).ok_or_else(|| invalid_value(3, kind))?;
            Ok(Surface {
                id: row.get(0)?,
                environment_id: row.get(1)?,
                name: row.get(2)?,
                kind,
                path: kind.is_file().then(|| primary_path.join(relative_path)),
                input: decode_json(6, &row.get::<_, String>(6)?)?,
                enforcement: Enforcement::parse(&enforcement)
                    .ok_or_else(|| invalid_value(7, enforcement))?,
                position: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    Ok(CatalogSnapshot {
        projects,
        checkouts,
        environments,
        resources,
        endpoints,
        bindings,
        surfaces,
    })
}

/// Stable digest of every catalog object that can change what one surface reads or signs with.
///
/// Store head versions are deliberately excluded: rotating the value behind the same resource
/// does not change the authorization object. Rebinding the surface, changing its format/policy,
/// changing a selected resource, or redirecting a machine-local endpoint does.
pub fn catalog_surface_semantic_revision(
    snapshot: &CatalogSnapshot,
    surface_id: &str,
) -> CatalogResult<String> {
    let surface = snapshot
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .ok_or_else(|| CatalogError::NotFound(format!("surface {surface_id}")))?;
    let environment = snapshot
        .environments
        .iter()
        .find(|environment| environment.id == surface.environment_id)
        .ok_or_else(|| {
            CatalogError::NotFound(format!("environment {}", surface.environment_id))
        })?;
    let project = snapshot
        .projects
        .iter()
        .find(|project| project.id == environment.project_id)
        .ok_or_else(|| CatalogError::NotFound(format!("project {}", environment.project_id)))?;

    let binding_ids = surface.input.binding_ids().unwrap_or(&[]);
    let mut bindings = Vec::with_capacity(binding_ids.len());
    let mut resource_ids = std::collections::BTreeSet::new();
    for binding_id in binding_ids {
        let binding = snapshot
            .bindings
            .iter()
            .find(|binding| binding.id == *binding_id)
            .ok_or_else(|| CatalogError::NotFound(format!("binding {binding_id}")))?;
        resource_ids.insert(binding.resource_id.as_str());
        bindings.push(binding);
    }
    if let SurfaceInput::Resource { resource_id } = &surface.input {
        resource_ids.insert(resource_id);
    }

    let mut resources = Vec::with_capacity(resource_ids.len());
    let mut endpoints = Vec::new();
    for resource_id in resource_ids {
        let resource = snapshot
            .resources
            .iter()
            .find(|resource| resource.id == resource_id)
            .ok_or_else(|| CatalogError::NotFound(format!("resource {resource_id}")))?;
        resources.push(resource);
        if let Some(endpoint) = snapshot.endpoints.get(resource_id) {
            endpoints.push((resource_id, endpoint));
        }
    }

    let canonical = serde_json::to_vec(&(
        surface,
        environment,
        project,
        bindings,
        resources,
        endpoints,
    ))?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

pub fn resolve_catalog_snapshot(
    snapshot: &CatalogSnapshot,
    project_id: &str,
    environment_id: &str,
) -> CatalogResult<ResolvedEnvironment> {
    if !snapshot.projects.iter().any(|project| project.id == project_id) {
        return Err(CatalogError::NotFound(format!("project {project_id}")));
    }
    let environment = snapshot
        .environments
        .iter()
        .find(|environment| environment.id == environment_id)
        .ok_or_else(|| CatalogError::NotFound(format!("environment {environment_id}")))?;
    if environment.project_id != project_id {
        return Err(CatalogError::Validation(format!(
            "environment {environment_id:?} does not belong to project {project_id:?}"
        )));
    }

    Ok(ResolvedEnvironment {
        project_id: project_id.to_string(),
        environment_id: environment_id.to_string(),
        exports: resolve_exports(snapshot, project_id, Some(environment_id), None)?,
    })
}

pub fn resolve_catalog_surface(
    snapshot: &CatalogSnapshot,
    surface_id: &str,
) -> CatalogResult<Vec<ResolvedExport>> {
    let surface = snapshot
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .ok_or_else(|| CatalogError::NotFound(format!("surface {surface_id}")))?;
    if !matches!(
        surface.kind.composed_format(),
        Some(SurfaceFormat::Dotenv | SurfaceFormat::Direnv)
    ) {
        return Err(CatalogError::Validation(format!(
            "surface {surface_id:?} is not a keyed environment projection"
        )));
    }
    let environment = snapshot
        .environments
        .iter()
        .find(|environment| environment.id == surface.environment_id)
        .ok_or_else(|| CatalogError::NotFound(format!("environment {}", surface.environment_id)))?;
    let SurfaceInput::Bindings { binding_ids } = &surface.input else {
        return Err(CatalogError::Validation(format!(
            "dotenv surface {surface_id:?} requires binding input"
        )));
    };
    let included = binding_ids.iter().map(String::as_str).collect::<HashSet<_>>();
    resolve_exports(
        snapshot,
        &environment.project_id,
        Some(&environment.id),
        Some(&included),
    )
}

pub(super) fn resolve_exports(
    snapshot: &CatalogSnapshot,
    project_id: &str,
    environment_id: Option<&str>,
    included: Option<&HashSet<&str>>,
) -> CatalogResult<Vec<ResolvedExport>> {
    let resources: HashMap<&str, &Resource> = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    let mut bindings: Vec<&Binding> = snapshot
        .bindings
        .iter()
        .filter(|binding| {
            binding.enabled
                && included.is_none_or(|ids| ids.contains(binding.id.as_str()))
                && binding.project_id == project_id
                && match &binding.scope {
                    BindingScope::Common => true,
                    BindingScope::Environment { environment_id: binding_environment } => {
                        environment_id.is_some_and(|id| binding_environment == id)
                    }
                }
        })
        .collect();
    bindings.sort_by_key(|binding| {
        let scope_order = match binding.scope {
            BindingScope::Common => 0,
            BindingScope::Environment { .. } => 1,
        };
        (scope_order, binding.position, binding.id.as_str())
    });

    let mut exports: Vec<ResolvedExport> = Vec::new();
    let mut by_key: HashMap<String, (usize, bool)> = HashMap::new();
    for binding in bindings {
        let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("resource {}", binding.resource_id))
        })?;
        for entry in resource.entries.iter().filter(|entry| {
            match &binding.selection {
                EntrySelection::All => true,
                EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
            }
        }) {
            let key = if resource.shape == ValueShape::Scalar {
                binding.key_override.as_ref().or(entry.key.as_ref())
            } else {
                entry.key.as_ref()
            };
            let Some(key) = key.cloned() else { continue };
            let current_is_environment = matches!(binding.scope, BindingScope::Environment { .. });
            let resolved = ResolvedExport {
                key: key.clone(),
                address: entry.address.clone(),
                binding_id: binding.id.clone(),
                resource_id: resource.id.clone(),
                resource_name: resource.name.clone(),
                sensitive: entry.sensitive,
                overrides_binding_id: None,
            };

            if let Some((existing_index, existing_is_environment)) = by_key.get(&key).copied() {
                if current_is_environment && !existing_is_environment && binding.allow_override {
                    let mut resolved = resolved;
                    resolved.overrides_binding_id = Some(exports[existing_index].binding_id.clone());
                    exports[existing_index] = resolved;
                    by_key.insert(key, (existing_index, true));
                    continue;
                }
                return Err(CatalogError::Conflict {
                    key,
                    binding_ids: vec![
                        exports[existing_index].binding_id.clone(),
                        binding.id.clone(),
                    ],
                });
            }

            let resolved_index = exports.len();
            exports.push(resolved);
            by_key.insert(key, (resolved_index, current_is_environment));
        }
    }

    Ok(exports)
}

pub(super) fn validate_snapshot_conflicts(snapshot: &CatalogSnapshot) -> CatalogResult<()> {
    validate_binding_selections(snapshot)?;
    validate_surface_inputs(snapshot)?;
    validate_ssh_route_conflicts(snapshot)?;
    for surface in &snapshot.surfaces {
        match surface.kind {
            SurfaceKind::File(FileBacking::Composed(
                SurfaceFormat::Dotenv | SurfaceFormat::Direnv,
            )) => {
                resolve_catalog_surface(snapshot, &surface.id)?;
            }
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)) => {
                validate_ini_surface_conflicts(snapshot, surface)?
            }
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines))
            | SurfaceKind::File(FileBacking::EnvFileDirect) => {}
            SurfaceKind::UnixSocket => validate_ssh_agent_surface_conflicts(snapshot, surface)?,
        }
    }
    Ok(())
}

pub(super) fn validate_binding_selections(snapshot: &CatalogSnapshot) -> CatalogResult<()> {
    let resources: HashMap<&str, &Resource> = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    for binding in &snapshot.bindings {
        let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("resource {}", binding.resource_id))
        })?;
        let selected = match &binding.selection {
            EntrySelection::All => continue,
            EntrySelection::Entries { addresses } => addresses
                .iter()
                .all(|address| resource.entries.iter().any(|entry| entry.address == *address)),
        };
        if !selected {
            return Err(CatalogError::Validation(format!(
                "binding {:?} selects entries not exposed by resource {:?}",
                binding.id, resource.id
            )));
        }
        if resource.entries.is_empty() {
            return Err(CatalogError::Validation(format!(
                "binding {:?} cannot select entries from flat resource {:?}",
                binding.id, resource.id
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_surface_inputs(snapshot: &CatalogSnapshot) -> CatalogResult<()> {
    let resources: HashMap<&str, &Resource> = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    let bindings: HashMap<&str, &Binding> = snapshot
        .bindings
        .iter()
        .map(|binding| (binding.id.as_str(), binding))
        .collect();
    let environments: HashMap<&str, &Environment> = snapshot
        .environments
        .iter()
        .map(|environment| (environment.id.as_str(), environment))
        .collect();
    for surface in &snapshot.surfaces {
        let environment = environments.get(surface.environment_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("environment {}", surface.environment_id))
        })?;
        match (&surface.kind, &surface.input) {
            (
                SurfaceKind::File(FileBacking::Composed(_)),
                SurfaceInput::Bindings { binding_ids },
            )
            | (
                SurfaceKind::UnixSocket,
                SurfaceInput::Bindings { binding_ids }
                | SurfaceInput::SshAgent { binding_ids, .. },
            ) => {
                let mut unique = HashSet::new();
                for binding_id in binding_ids {
                    if !unique.insert(binding_id) {
                        return Err(CatalogError::Validation(format!(
                            "surface {:?} includes duplicate binding {:?}",
                            surface.id, binding_id
                        )));
                    }
                    let binding = bindings.get(binding_id.as_str()).ok_or_else(|| {
                        CatalogError::NotFound(format!("binding {binding_id}"))
                    })?;
                    let applies = binding.project_id == environment.project_id
                        && match &binding.scope {
                            BindingScope::Common => true,
                            BindingScope::Environment { environment_id } => {
                                environment_id == &surface.environment_id
                            }
                        };
                    if !applies {
                        return Err(CatalogError::Validation(format!(
                            "binding {binding_id:?} does not apply to surface {:?}",
                            surface.id
                        )));
                    }
                    let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
                        CatalogError::NotFound(format!("resource {}", binding.resource_id))
                    })?;
                    validate_composed_surface_member(surface, binding, resource)?;
                }
            }
            (SurfaceKind::File(FileBacking::EnvFileDirect), SurfaceInput::Resource { resource_id }) => {
                let resource = resources.get(resource_id.as_str()).ok_or_else(|| {
                    CatalogError::NotFound(format!("resource {resource_id}"))
                })?;
                if resource.kind != ResourceKind::EnvFile
                    || resource.shape != ValueShape::KeyValueSet
                    || resource.codec != ResourceCodec::Dotenv
                    || !matches!(resource.source, ResourceSource::SecretRef { .. })
                {
                    return Err(CatalogError::Validation(format!(
                        "env_file_direct surface {:?} requires an env_file resource",
                        surface.id
                    )));
                }
            }
            _ => {
                return Err(CatalogError::Validation(format!(
                    "surface kind {} is incompatible with its input",
                    surface.kind.as_str()
                )))
            }
        }
    }
    Ok(())
}

pub(super) fn validate_composed_surface_member(
    surface: &Surface,
    binding: &Binding,
    resource: &Resource,
) -> CatalogResult<()> {
    let entries = resource.entries.iter().filter(|entry| match &binding.selection {
        EntrySelection::All => true,
        EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
    });
    let compatible = match surface.kind {
        SurfaceKind::File(FileBacking::Composed(format)) => {
            let spec = format.spec();
            match spec.input {
                FormatInputModel::EnvironmentProjection => {
                    let compatible_source = matches!(
                        (&resource.shape, &resource.codec, &resource.source),
                        (
                            ValueShape::Scalar,
                            ResourceCodec::Opaque,
                            ResourceSource::SecretRef { .. } | ResourceSource::Literal { .. }
                        ) | (
                            ValueShape::KeyValueSet,
                            ResourceCodec::Dotenv | ResourceCodec::Ini,
                            ResourceSource::SecretRef { .. }
                        )
                    );
                    compatible_source
                        && entries.into_iter().all(|entry| {
                            !(resource.shape != ValueShape::Scalar && entry.key.is_none()
                                || resource.shape == ValueShape::Scalar
                                    && binding
                                        .key_override
                                        .as_ref()
                                        .or(entry.key.as_ref())
                                        .is_none()
                                || binding
                                    .key_override
                                    .as_ref()
                                    .or(entry.key.as_ref())
                                    .is_some_and(|key| require_env_key(key).is_err()))
                        })
                }
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
                        && entries.into_iter().all(|entry| entry.key.is_some())
                        && (!stored_only
                            || matches!(resource.source, ResourceSource::SecretRef { .. }))
                }
                FormatInputModel::KeylessScalars {
                    required_codec,
                    allow_literal,
                } => {
                    resource.shape == ValueShape::Scalar
                        && resource.codec == required_codec
                        && (spec.allow_key_override || binding.key_override.is_none())
                        && entries.into_iter().all(|entry| entry.key.is_none())
                        && matches!(
                            (&resource.source, allow_literal),
                            (ResourceSource::SecretRef { .. }, _)
                                | (ResourceSource::Literal { .. }, true)
                        )
                }
            }
        }
        SurfaceKind::UnixSocket => {
            matches!(
                (&resource.kind, &resource.shape, &resource.source),
                (
                    ResourceKind::SshIdentity,
                    ValueShape::SshIdentity,
                    ResourceSource::SecretRef { .. }
                ) | (
                    ResourceKind::SshAgent,
                    ValueShape::Socket,
                    ResourceSource::Socket
                )
            ) && resource.codec == ResourceCodec::Opaque
                && binding.key_override.is_none()
                && entries.into_iter().all(|entry| entry.key.is_none())
        }
        SurfaceKind::File(FileBacking::EnvFileDirect) => {
            unreachable!("direct file surfaces do not have binding members")
        }
    };
    if !compatible {
        return Err(CatalogError::Validation(format!(
            "binding {:?} cannot feed {} surface {:?}",
            binding.id,
            surface.kind.as_str(),
            surface.id
        )));
    }
    Ok(())
}

pub(super) fn validate_ssh_agent_surface_conflicts(
    snapshot: &CatalogSnapshot,
    surface: &Surface,
) -> CatalogResult<()> {
    let Some(binding_ids) = surface.input.binding_ids() else {
        return Err(CatalogError::Validation(format!(
            "SSH agent surface {:?} requires binding input",
            surface.id
        )));
    };
    let bindings: HashMap<&str, &Binding> = snapshot
        .bindings
        .iter()
        .map(|binding| (binding.id.as_str(), binding))
        .collect();
    let resources: HashMap<&str, &Resource> = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    let mut addresses: HashMap<&str, &str> = HashMap::new();

    for binding_id in binding_ids {
        let binding = bindings
            .get(binding_id.as_str())
            .ok_or_else(|| CatalogError::NotFound(format!("binding {binding_id}")))?;
        let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("resource {}", binding.resource_id))
        })?;
        for entry in resource.entries.iter().filter(|entry| match &binding.selection {
            EntrySelection::All => true,
            EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
        }) {
            if let Some(existing) = addresses.insert(&entry.address, binding.id.as_str()) {
                return Err(CatalogError::Conflict {
                    key: entry.address.clone(),
                    binding_ids: vec![existing.to_string(), binding.id.clone()],
                });
            }
        }
    }
    Ok(())
}

pub(super) fn validate_ini_surface_conflicts(
    snapshot: &CatalogSnapshot,
    surface: &Surface,
) -> CatalogResult<()> {
    let SurfaceInput::Bindings { binding_ids } = &surface.input else {
        return Err(CatalogError::Validation(format!(
            "INI surface {:?} requires binding input",
            surface.id
        )));
    };
    let resources = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect::<HashMap<_, _>>();
    let bindings = snapshot
        .bindings
        .iter()
        .map(|binding| (binding.id.as_str(), binding))
        .collect::<HashMap<_, _>>();
    let mut addresses: HashMap<&str, &str> = HashMap::new();
    for binding_id in binding_ids {
        let binding = bindings
            .get(binding_id.as_str())
            .ok_or_else(|| CatalogError::NotFound(format!("binding {binding_id}")))?;
        if !binding.enabled {
            continue;
        }
        let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("resource {}", binding.resource_id))
        })?;
        for entry in resource.entries.iter().filter(|entry| match &binding.selection {
            EntrySelection::All => true,
            EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
        }) {
            if let Some(existing_binding) = addresses.insert(&entry.address, &binding.id) {
                return Err(CatalogError::Conflict {
                    key: entry.address.clone(),
                    binding_ids: vec![existing_binding.to_string(), binding.id.clone()],
                });
            }
        }
    }
    Ok(())
}
