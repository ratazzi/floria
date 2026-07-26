use super::*;

impl Catalog {
    pub fn upsert_binding(&self, binding: &Binding) -> CatalogResult<()> {
        validate_binding(binding)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        require_exists(&tx, "projects", &binding.project_id, "project")?;
        require_exists(&tx, "resources", &binding.resource_id, "resource")?;

        let environment_id = match &binding.scope {
            BindingScope::Common => None,
            BindingScope::Environment { environment_id } => {
                let owner: Option<String> = tx
                    .query_row(
                        "SELECT project_id FROM environments WHERE id = ?1",
                        [environment_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                match owner {
                    Some(owner) if owner == binding.project_id => Some(environment_id.as_str()),
                    Some(_) => {
                        return Err(CatalogError::Validation(format!(
                            "environment {environment_id:?} does not belong to project {:?}",
                            binding.project_id
                        )))
                    }
                    None => {
                        return Err(CatalogError::NotFound(format!(
                            "environment {environment_id}"
                        )))
                    }
                }
            }
        };

        if binding.key_override.is_some() {
            let shape: String = tx.query_row(
                "SELECT shape FROM resources WHERE id = ?1",
                [&binding.resource_id],
                |row| row.get(0),
            )?;
            if shape != ValueShape::Scalar.as_str() {
                return Err(CatalogError::Validation(
                    "key_override is only valid for scalar resources".to_string(),
                ));
            }
        }

        tx.execute(
            "INSERT INTO bindings
                (id, project_id, environment_id, resource_id, key_override, enabled,
                 allow_override, position, selection_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                 environment_id = excluded.environment_id, resource_id = excluded.resource_id,
                 key_override = excluded.key_override, enabled = excluded.enabled,
                 allow_override = excluded.allow_override, position = excluded.position,
                 selection_json = excluded.selection_json,
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
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_binding(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "binding id")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let snapshot = snapshot_from(&tx)?;
        if !snapshot.bindings.iter().any(|binding| binding.id == id) {
            return Err(CatalogError::NotFound(format!("binding {id}")));
        }
        for surface in &snapshot.surfaces {
            let Some(binding_ids) = surface.input.binding_ids() else { continue };
            if !binding_ids.iter().any(|binding_id| binding_id == id) {
                continue;
            }
            let retained = binding_ids
                .iter()
                .filter(|binding_id| binding_id.as_str() != id)
                .cloned()
                .collect();
            let input = match &surface.input {
                SurfaceInput::Bindings { .. } => {
                    SurfaceInput::Bindings { binding_ids: retained }
                }
                SurfaceInput::SshAgent { route, .. } => SurfaceInput::SshAgent {
                    binding_ids: retained,
                    route: route.clone(),
                },
                SurfaceInput::Resource { .. } => unreachable!("binding input checked above"),
            };
            tx.execute(
                "UPDATE surfaces SET input_json = ?2, updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
                params![surface.id, serde_json::to_string(&input)?],
            )?;
        }
        tx.execute("DELETE FROM bindings WHERE id = ?1", [id])?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_surface(&self, surface: &Surface) -> CatalogResult<()> {
        validate_surface(surface)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        require_exists(&tx, "environments", &surface.environment_id, "environment")?;
        let project_path = PathBuf::from(tx.query_row(
            "SELECT project_checkouts.path
             FROM environments
             JOIN project_checkouts
               ON project_checkouts.project_id = environments.project_id
              AND project_checkouts.kind = 'primary'
             WHERE environments.id = ?1",
            [&surface.environment_id],
            |row| row.get::<_, String>(0),
        )?);
        let relative_path = surface_relative_path(&surface.path, &project_path)?;
        tx.execute(
            "INSERT INTO surfaces
                (id, environment_id, name, kind, relative_path, input_json, enforcement, position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET environment_id = excluded.environment_id,
                 name = excluded.name, kind = excluded.kind,
                 relative_path = excluded.relative_path,
                 input_json = excluded.input_json, enforcement = excluded.enforcement,
                 position = excluded.position,
                 updated_at = CURRENT_TIMESTAMP",
            params![
                surface.id,
                surface.environment_id,
                surface.name,
                surface.kind.as_str(),
                path_string(relative_path),
                serde_json::to_string(&surface.input)?,
                surface.enforcement.as_str(),
                surface.position,
            ],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_surface(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "surface id")?;
        remove_one(&self.connection()?, "surfaces", id, "surface")
    }

    /// Resolve enabled common and environment bindings to export metadata with provenance.
    /// No secret value is decrypted or returned.
    pub fn resolve_environment(
        &self,
        project_id: &str,
        environment_id: &str,
    ) -> CatalogResult<ResolvedEnvironment> {
        resolve_catalog_snapshot(&self.snapshot()?, project_id, environment_id)
    }

    pub(super) fn connection(&self) -> CatalogResult<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(2))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(conn)
    }
}
