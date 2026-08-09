use super::*;

pub(super) fn create_project_workspace(
    catalog: &Catalog,
    project: floria_catalog::Project,
    environment: floria_catalog::Environment,
    surface: floria_catalog::Surface,
) -> Result<ControlResult, DispatchError> {
    if environment.project_id != project.id {
        return Err(DispatchError::Validation(format!(
            "environment project {:?} does not match project {:?}",
            environment.project_id, project.id
        )));
    }
    if surface.environment_id != environment.id {
        return Err(DispatchError::Validation(format!(
            "surface environment {:?} does not match environment {:?}",
            surface.environment_id, environment.id
        )));
    }

    let snapshot = catalog.snapshot()?;
    for (kind, id, exists) in [
        ("project", &project.id, snapshot.projects.iter().any(|item| item.id == project.id)),
        (
            "environment",
            &environment.id,
            snapshot.environments.iter().any(|item| item.id == environment.id),
        ),
        ("surface", &surface.id, snapshot.surfaces.iter().any(|item| item.id == surface.id)),
    ] {
        if exists {
            return Err(DispatchError::Catalog(CatalogError::AlreadyExists {
                kind,
                id: id.clone(),
            }));
        }
    }

    catalog.upsert_project(&project)?;
    if let Err(error) = catalog.upsert_environment(&environment) {
        rollback_project_create(catalog, &project.id);
        return Err(DispatchError::Catalog(error));
    }
    if let Err(error) = catalog.upsert_surface(&surface) {
        rollback_project_create(catalog, &project.id);
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::Empty)
}

pub(super) fn rollback_project_create(catalog: &Catalog, project_id: &str) {
    if let Err(error) = catalog.remove_project(project_id) {
        tracing::warn!(%project_id, %error, "rolling back project create failed");
    }
}

/// Attach a replicated Project to one existing folder on this Mac without rewriting any of the
/// Project's shared fields. The Project must still be unplaced when the request is handled so a
/// stale UI action cannot silently move a checkout that was attached elsewhere in the meantime.
pub(super) fn attach_replicated_project(
    catalog: &Catalog,
    project_id: &str,
    path: &Path,
) -> Result<ControlResult, DispatchError> {
    let path = std::fs::canonicalize(path).map_err(|source| DispatchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !path.is_dir() {
        return Err(DispatchError::Validation(format!(
            "project folder is not a directory: {}",
            path.display()
        )));
    }

    let replicated = catalog.replicated_catalog()?;
    if !replicated.projects.iter().any(|project| project.id == project_id) {
        return Err(DispatchError::Validation(format!(
            "synced project {project_id:?} is no longer in this Library"
        )));
    }
    let snapshot = catalog.snapshot()?;
    if snapshot.projects.iter().any(|project| project.id == project_id) {
        return Err(DispatchError::Validation(format!(
            "synced project {project_id:?} already has a folder on this Mac"
        )));
    }

    catalog.upsert_checkout(&ProjectCheckout {
        id: project_id.to_string(),
        project_id: project_id.to_string(),
        path,
        environment_id: None,
        kind: ProjectCheckoutKind::Primary,
        git_common_dir: None,
    })?;
    Ok(ControlResult::Empty)
}
