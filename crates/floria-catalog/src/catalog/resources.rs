use super::*;

impl Catalog {
    /// Promote routed legacy SSH socket surfaces into project-optional Library capabilities.
    ///
    /// The resource reuses the surface id, so runtime socket paths and OpenSSH routes stay stable.
    /// Unrouted capability surfaces remain untouched.
    pub fn promote_legacy_ssh_accesses(&self) -> CatalogResult<usize> {
        self.with_authenticated_mutation(|tx| {
            let snapshot = snapshot_from(tx)?;
            let bindings = snapshot
                .bindings
                .iter()
                .map(|binding| (binding.id.as_str(), binding))
                .collect::<std::collections::HashMap<_, _>>();
            let environments = snapshot
                .environments
                .iter()
                .map(|environment| (environment.id.as_str(), environment))
                .collect::<std::collections::HashMap<_, _>>();
            let resource_ids = snapshot
                .resources
                .iter()
                .map(|resource| resource.id.as_str())
                .collect::<std::collections::HashSet<_>>();
            let mut migrated_surface_ids = std::collections::HashSet::new();
            let mut candidate_binding_ids = std::collections::HashSet::new();
            let mut migrated = 0;

            for surface in snapshot
                .surfaces
                .iter()
                .filter(|surface| surface.kind == SurfaceKind::UnixSocket)
            {
                let SurfaceInput::SshAgent {
                    binding_ids,
                    route: Some(route),
                } = &surface.input
                else {
                    continue;
                };
                if resource_ids.contains(surface.id.as_str()) {
                    return Err(CatalogError::AlreadyExists {
                        kind: "resource",
                        id: surface.id.clone(),
                    });
                }
                let environment = environments
                    .get(surface.environment_id.as_str())
                    .ok_or_else(|| {
                        CatalogError::NotFound(format!(
                            "environment {}",
                            surface.environment_id
                        ))
                    })?;
                let identities = binding_ids
                    .iter()
                    .filter_map(|binding_id| bindings.get(binding_id.as_str()).copied())
                    .filter(|binding| binding.enabled)
                    .map(|binding| SshIdentitySelection {
                        resource_id: binding.resource_id.clone(),
                        selection: binding.selection.clone(),
                    })
                    .collect::<Vec<_>>();
                if identities.is_empty() {
                    continue;
                }
                let access = Resource {
                    id: surface.id.clone(),
                    name: surface.name.clone(),
                    kind: ResourceKind::SshAccess,
                    shape: ValueShape::SshAccess,
                    codec: ResourceCodec::Opaque,
                    default_env_key: None,
                    entries: Vec::new(),
                    source: ResourceSource::SshAccess(Box::new(SshAccessSpec {
                        identities,
                        route: route.clone(),
                        project_ids: vec![environment.project_id.clone()],
                    })),
                    enforcement: surface.enforcement,
                    metadata: ItemMetadata::default(),
                    origin: ResourceOrigin::default(),
                };
                validate_resource(&access)?;
                upsert_resource_row(tx, &access)?;
                tx.execute("DELETE FROM surfaces WHERE id = ?1", [&surface.id])?;
                migrated_surface_ids.insert(surface.id.as_str());
                candidate_binding_ids.extend(binding_ids.iter().map(String::as_str));
                migrated += 1;
            }

            let retained_binding_ids = snapshot
                .surfaces
                .iter()
                .filter(|surface| !migrated_surface_ids.contains(surface.id.as_str()))
                .filter_map(|surface| surface.input.binding_ids())
                .flatten()
                .map(String::as_str)
                .collect::<std::collections::HashSet<_>>();
            for binding_id in candidate_binding_ids
                .into_iter()
                .filter(|binding_id| !retained_binding_ids.contains(binding_id))
            {
                tx.execute("DELETE FROM bindings WHERE id = ?1", [binding_id])?;
            }
            Ok(migrated)
        })
    }

    pub fn upsert_resource(&self, resource: &Resource) -> CatalogResult<()> {
        validate_resource(resource)?;
        if resource.source == ResourceSource::Socket {
            return Err(CatalogError::Validation(
                "socket resources require an atomic machine-local endpoint".to_string(),
            ));
        }
        self.with_authenticated_mutation(|tx| {
            upsert_resource_row(tx, resource)?;
            tx.execute(
                "DELETE FROM resource_endpoints WHERE resource_id = ?1",
                [&resource.id],
            )?;
            Ok(())
        })
    }

    /// Atomically persist a syncable socket resource and its machine-local endpoint.
    pub fn upsert_socket_resource(
        &self,
        resource: &Resource,
        endpoint: &Path,
    ) -> CatalogResult<()> {
        validate_resource(resource)?;
        if resource.source != ResourceSource::Socket {
            return Err(CatalogError::Validation(
                "machine-local endpoints are only valid for socket resources".to_string(),
            ));
        }
        require_absolute_path(endpoint, "ssh agent endpoint")?;
        self.with_authenticated_mutation(|tx| {
            upsert_resource_row(tx, resource)?;
            tx.execute(
                "INSERT INTO resource_endpoints (resource_id, endpoint)
                 VALUES (?1, ?2)
                 ON CONFLICT(resource_id) DO UPDATE SET endpoint = excluded.endpoint,
                     updated_at = CURRENT_TIMESTAMP",
                params![resource.id, path_string(endpoint)],
            )?;
            Ok(())
        })
    }

    /// Record one more source file on a resource's origin, keyed by path.
    ///
    /// The origin kind is left untouched: reusing a manual secret from discovery
    /// keeps it manual while still remembering where it is used from. Rediscovery refreshes
    /// project/environment attribution for an existing path instead of adding a duplicate.
    pub fn append_resource_origin(&self, id: &str, source: &OriginSource) -> CatalogResult<()> {
        require_id(id, "resource id")?;
        self.with_authenticated_mutation(|tx| {
            let origin_json: String = tx
                .query_row(
                    "SELECT origin_json FROM resources WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or_else(|| CatalogError::NotFound(format!("resource {id}")))?;
            let mut origin: ResourceOrigin = serde_json::from_str(&origin_json)?;
            if let Some(existing) =
                origin.sources.iter_mut().find(|existing| existing.path == source.path)
            {
                if source.project_id.is_some() {
                    existing.project_id = source.project_id.clone();
                }
                if source.environment.is_some() {
                    existing.environment = source.environment.clone();
                }
                existing.imported_at.clone_from(&source.imported_at);
            } else {
                origin.sources.push(source.clone());
            }
            tx.execute(
                "UPDATE resources SET origin_json = ?2, updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
                params![id, serde_json::to_string(&origin)?],
            )?;
            Ok(())
        })
    }

    pub fn validate_resource(&self, resource: &Resource) -> CatalogResult<()> {
        validate_resource(resource)
    }

    pub fn create_resource(&self, resource: &Resource) -> CatalogResult<()> {
        validate_resource(resource)?;
        if resource.source == ResourceSource::Socket {
            return Err(CatalogError::Validation(
                "socket resources require an atomic machine-local endpoint".to_string(),
            ));
        }
        self.with_authenticated_mutation(|tx| {
            validate_ssh_access_projects(tx, resource)?;
            let exists = tx
                .query_row("SELECT 1 FROM resources WHERE id = ?1", [&resource.id], |_| Ok(()))
                .optional()?
                .is_some();
            if exists {
                return Err(CatalogError::AlreadyExists {
                    kind: "resource",
                    id: resource.id.clone(),
                });
            }
            tx.execute(
                "INSERT INTO resources
                    (id, name, kind, shape, codec, default_env_key, entries_json, source_json, enforcement, metadata_json, origin_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                    serde_json::to_string(&resource.origin)?,
                ],
            )?;
            Ok(())
        })
    }

    pub fn remove_resource(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "resource id")?;
        self.with_authenticated_mutation(|tx| {
            let snapshot = snapshot_from(tx)?;
            let usage = resource_usage_from_snapshot(&snapshot, id)?;
            let binding_ids = usage
                .bindings
                .iter()
                .map(|binding| binding.binding_id.clone())
                .collect::<Vec<_>>();
            if !binding_ids.is_empty() || !usage.direct_surface_ids.is_empty() {
                return Err(CatalogError::ResourceInUse {
                    resource_id: id.to_string(),
                    binding_ids,
                    surface_ids: usage.direct_surface_ids,
                });
            }
            remove_one(tx, "resources", id, "resource")
        })
    }

    pub fn resource(&self, id: &str) -> CatalogResult<Resource> {
        require_id(id, "resource id")?;
        self.snapshot()?
            .resources
            .into_iter()
            .find(|resource| resource.id == id)
            .ok_or_else(|| CatalogError::NotFound(format!("resource {id}")))
    }

    pub fn resource_usage(&self, id: &str) -> CatalogResult<ResourceUsage> {
        require_id(id, "resource id")?;
        let snapshot = self.snapshot()?;
        resource_usage_from_snapshot(&snapshot, id)
    }

}

fn resource_usage_from_snapshot(
    snapshot: &CatalogSnapshot,
    id: &str,
) -> CatalogResult<ResourceUsage> {
        if !snapshot.resources.iter().any(|resource| resource.id == id) {
            return Err(CatalogError::NotFound(format!("resource {id}")));
        }
        let mut bindings = Vec::new();
        for binding in snapshot.bindings.iter().filter(|binding| binding.resource_id == id) {
            let environment_ids = match &binding.scope {
                BindingScope::Common => snapshot
                    .environments
                    .iter()
                    .filter(|environment| environment.project_id == binding.project_id)
                    .map(|environment| environment.id.clone())
                    .collect::<Vec<_>>(),
                BindingScope::Environment { environment_id } => vec![environment_id.clone()],
            };
            let surface_ids = snapshot
                .surfaces
                .iter()
                .filter(|surface| {
                    environment_ids.contains(&surface.environment_id)
                        && surface
                            .input
                            .binding_ids()
                            .is_some_and(|binding_ids| binding_ids.contains(&binding.id))
                })
                .map(|surface| surface.id.clone())
                .collect();
            bindings.push(ResourceBindingUsage {
                binding_id: binding.id.clone(),
                project_id: binding.project_id.clone(),
                scope: binding.scope.clone(),
                environment_ids,
                surface_ids,
            });
        }
        let mut direct_surface_ids = snapshot
            .surfaces
            .iter()
            .filter(|surface| {
                matches!(
                    &surface.input,
                    SurfaceInput::Resource { resource_id } if resource_id == id
                )
            })
            .map(|surface| surface.id.clone())
            .collect::<Vec<_>>();
        direct_surface_ids.extend(snapshot.resources.iter().filter_map(|resource| {
            let ResourceSource::SshAccess(spec) = &resource.source else {
                return None;
            };
            spec.identities
                .iter()
                .any(|identity| identity.resource_id == id)
                .then(|| resource.id.clone())
        }));
        direct_surface_ids.sort();
        direct_surface_ids.dedup();
        Ok(ResourceUsage { resource_id: id.to_string(), bindings, direct_surface_ids })
}

pub(super) fn upsert_resource_row(
    tx: &rusqlite::Transaction<'_>,
    resource: &Resource,
) -> CatalogResult<()> {
    validate_ssh_access_projects(tx, resource)?;
    tx.execute(
        "INSERT INTO resources
            (id, name, kind, shape, codec, default_env_key, entries_json, source_json, enforcement, metadata_json, origin_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
             shape = excluded.shape, codec = excluded.codec,
             default_env_key = excluded.default_env_key,
             entries_json = excluded.entries_json,
             source_json = excluded.source_json, enforcement = excluded.enforcement,
             metadata_json = excluded.metadata_json,
             origin_json = excluded.origin_json,
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
            serde_json::to_string(&resource.origin)?,
        ],
    )?;
    Ok(())
}

fn validate_ssh_access_projects(
    tx: &rusqlite::Transaction<'_>,
    resource: &Resource,
) -> CatalogResult<()> {
    let ResourceSource::SshAccess(spec) = &resource.source else {
        return Ok(());
    };
    for project_id in &spec.project_ids {
        require_exists(tx, "projects", project_id, "project")?;
    }
    Ok(())
}
