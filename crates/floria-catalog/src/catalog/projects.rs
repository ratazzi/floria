use super::*;

impl Catalog {
    pub fn upsert_project(&self, project: &Project) -> CatalogResult<()> {
        validate_project(project)?;
        self.with_authenticated_mutation(|tx| {
            tx.execute(
                "INSERT INTO projects (id, name) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                     updated_at = CURRENT_TIMESTAMP",
                params![project.id, project.name],
            )?;
            tx.execute(
                "INSERT INTO project_checkouts
                    (id, project_id, path, environment_id, kind, git_common_dir)
                 VALUES (?1, ?1, ?2, NULL, 'primary', NULL)
                 ON CONFLICT(id) DO UPDATE SET path = excluded.path,
                     updated_at = CURRENT_TIMESTAMP",
                params![project.id, path_string(&project.path)],
            )?;
            Ok(())
        })
    }

    /// A dedicated setter (not part of `upsert_project`) so idempotent project
    /// re-upserts from discovery can never wipe a user-configured default.
    pub fn set_project_default_environment(
        &self,
        project_id: &str,
        environment_id: Option<&str>,
    ) -> CatalogResult<()> {
        require_id(project_id, "project id")?;
        self.with_authenticated_mutation(|tx| {
            require_exists(tx, "projects", project_id, "project")?;
            if let Some(environment_id) = environment_id {
                let owner = tx
                    .query_row(
                        "SELECT project_id FROM environments WHERE id = ?1",
                        [environment_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                match owner {
                    Some(owner) if owner == project_id => {}
                    Some(_) => {
                        return Err(CatalogError::Validation(format!(
                            "environment {environment_id:?} does not belong to project {project_id:?}"
                        )))
                    }
                    None => {
                        return Err(CatalogError::NotFound(format!(
                            "environment {environment_id}"
                        )))
                    }
                }
            }
            tx.execute(
                "UPDATE projects SET default_environment_id = ?2,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?1",
                params![project_id, environment_id],
            )?;
            Ok(())
        })
    }

    pub fn remove_project(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "project id")?;
        self.with_authenticated_mutation(|tx| remove_one(tx, "projects", id, "project"))
    }

    pub fn upsert_checkout(&self, checkout: &ProjectCheckout) -> CatalogResult<()> {
        validate_checkout(checkout)?;
        self.with_authenticated_mutation(|tx| {
        require_exists(tx, "projects", &checkout.project_id, "project")?;
        if let Some(environment_id) = &checkout.environment_id {
            let owner = tx
                .query_row(
                    "SELECT project_id FROM environments WHERE id = ?1",
                    [environment_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            match owner {
                Some(owner) if owner == checkout.project_id => {}
                Some(_) => {
                    return Err(CatalogError::Validation(format!(
                        "environment {environment_id:?} does not belong to project {:?}",
                        checkout.project_id
                    )))
                }
                None => {
                    return Err(CatalogError::NotFound(format!(
                        "environment {environment_id}"
                    )))
                }
            }
        }
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT project_id, kind FROM project_checkouts WHERE id = ?1",
                [&checkout.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if existing
            .as_ref()
            .is_some_and(|(project_id, kind)| {
                project_id != &checkout.project_id || kind != checkout.kind.as_str()
            })
        {
            return Err(CatalogError::Validation(format!(
                "checkout {:?} cannot move between projects or change kind",
                checkout.id
            )));
        }
        tx.execute(
            "INSERT INTO project_checkouts
                (id, project_id, path, environment_id, kind, git_common_dir)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET path = excluded.path,
                 environment_id = excluded.environment_id,
                 git_common_dir = excluded.git_common_dir,
                 updated_at = CURRENT_TIMESTAMP",
            params![
                checkout.id,
                checkout.project_id,
                path_string(&checkout.path),
                checkout.environment_id,
                checkout.kind.as_str(),
                checkout.git_common_dir.as_deref().map(path_string),
            ],
        )?;
        Ok(())
        })
    }

    pub fn remove_checkout(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "checkout id")?;
        self.with_authenticated_mutation(|tx| {
        let kind = tx
            .query_row(
                "SELECT kind FROM project_checkouts WHERE id = ?1",
                [id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| CatalogError::NotFound(format!("checkout {id}")))?;
        if kind == ProjectCheckoutKind::Primary.as_str() {
            return Err(CatalogError::Validation(
                "primary checkout is owned by its project and cannot be removed separately"
                    .to_string(),
            ));
        }
        remove_one(tx, "project_checkouts", id, "checkout")
        })
    }

    pub fn upsert_environment(&self, environment: &Environment) -> CatalogResult<()> {
        validate_environment(environment)?;
        self.with_authenticated_mutation(|tx| {
        require_exists(tx, "projects", &environment.project_id, "project")?;
        let existing_owner: Option<String> = tx
            .query_row(
                "SELECT project_id FROM environments WHERE id = ?1",
                [&environment.id],
                |row| row.get(0),
            )
            .optional()?;
        if existing_owner.as_deref().is_some_and(|owner| owner != environment.project_id) {
            return Err(CatalogError::Validation(format!(
                "environment {:?} cannot move between projects",
                environment.id
            )));
        }
        tx.execute(
            "INSERT INTO environments (id, project_id, name, position) VALUES (?1, ?2, ?3, ?4)
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
        Ok(())
        })
    }

    pub fn remove_environment(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "environment id")?;
        self.with_authenticated_mutation(|tx| remove_one(tx, "environments", id, "environment"))
    }

}
