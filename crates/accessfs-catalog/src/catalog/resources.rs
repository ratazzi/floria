use super::*;

impl Catalog {
    pub fn upsert_resource(&self, resource: &Resource) -> CatalogResult<()> {
        validate_resource(resource)?;
        if resource.source == ResourceSource::Socket {
            return Err(CatalogError::Validation(
                "socket resources require an atomic machine-local endpoint".to_string(),
            ));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        upsert_resource_row(&tx, resource)?;
        tx.execute(
            "DELETE FROM resource_endpoints WHERE resource_id = ?1",
            [&resource.id],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
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
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        upsert_resource_row(&tx, resource)?;
        tx.execute(
            "INSERT INTO resource_endpoints (resource_id, endpoint)
             VALUES (?1, ?2)
             ON CONFLICT(resource_id) DO UPDATE SET endpoint = excluded.endpoint,
                 updated_at = CURRENT_TIMESTAMP",
            params![resource.id, path_string(endpoint)],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    /// Record one more source file on a resource's origin, deduplicated by path.
    ///
    /// The origin kind is left untouched: reusing a manual secret from discovery
    /// keeps it manual while still remembering where it is used from.
    pub fn append_resource_origin(&self, id: &str, source: &OriginSource) -> CatalogResult<()> {
        require_id(id, "resource id")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let origin_json: String = tx
            .query_row("SELECT origin_json FROM resources WHERE id = ?1", [id], |row| row.get(0))
            .optional()?
            .ok_or_else(|| CatalogError::NotFound(format!("resource {id}")))?;
        let mut origin: ResourceOrigin = serde_json::from_str(&origin_json)?;
        if origin.sources.iter().any(|existing| existing.path == source.path) {
            return Ok(());
        }
        origin.sources.push(source.clone());
        tx.execute(
            "UPDATE resources SET origin_json = ?2, updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
            params![id, serde_json::to_string(&origin)?],
        )?;
        tx.commit()?;
        Ok(())
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
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_resource(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "resource id")?;
        let usage = self.resource_usage(id)?;
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
        remove_one(&self.connection()?, "resources", id, "resource")
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
        let direct_surface_ids = snapshot
            .surfaces
            .iter()
            .filter(|surface| {
                matches!(
                    &surface.input,
                    SurfaceInput::Resource { resource_id } if resource_id == id
                )
            })
            .map(|surface| surface.id.clone())
            .collect();
        Ok(ResourceUsage { resource_id: id.to_string(), bindings, direct_surface_ids })
    }

}

fn upsert_resource_row(
    tx: &rusqlite::Transaction<'_>,
    resource: &Resource,
) -> CatalogResult<()> {
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
