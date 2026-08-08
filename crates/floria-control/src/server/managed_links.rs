use super::*;

pub(super) fn workspace_snapshot(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let local_project_ids = snapshot
        .projects
        .iter()
        .map(|project| project.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let unplaced_projects = catalog
        .replicated_catalog()?
        .projects
        .into_iter()
        .filter(|project| !local_project_ids.contains(project.id.as_str()))
        .collect();
    let managed_links = configured_managed_links(&snapshot, store, mount_path)?
    .into_iter()
    .map(|link| {
        let status = match link.status() {
            Ok(SurfaceManagedLinkStatus::Ready) => ManagedLinkStatus::Linked,
            Ok(SurfaceManagedLinkStatus::Missing) => ManagedLinkStatus::Missing,
            Ok(SurfaceManagedLinkStatus::Replaced) | Err(_) => ManagedLinkStatus::Replaced,
        };
        ManagedLink { path: link.path().to_path_buf(), status }
    })
    .collect();
    Ok(ControlResult::Snapshot(WorkspaceSnapshot {
        catalog: snapshot,
        managed_links,
        unplaced_projects,
    }))
}

pub(super) fn repair_managed_path_link(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
    path: &Path,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    configured_managed_links(&snapshot, store, mount_path)?
        .into_iter()
        .find(|link| link.path() == path)
        .ok_or_else(|| {
            DispatchError::Validation(format!("{} is not a managed link", path.display()))
        })?
        .repair()
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    Ok(ControlResult::Empty)
}

fn configured_managed_links(
    snapshot: &CatalogSnapshot,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
) -> Result<Vec<ManagedSymlink>, DispatchError> {
    let mut links = match (store, mount_path) {
        (Some(store), Some(mount_path)) => {
            managed_file_links(snapshot, &store.list()?, mount_path)
                .map_err(|error| DispatchError::Validation(error.to_string()))?
        }
        _ => Vec::new(),
    };
    links.sort_by(|left, right| left.path().cmp(right.path()));
    for pair in links.windows(2) {
        if pair[0].path() == pair[1].path()
            && pair[0].expected_target() != pair[1].expected_target()
        {
            return Err(DispatchError::Validation(format!(
                "{} resolves to more than one managed target",
                pair[0].path().display()
            )));
        }
    }
    links.dedup_by(|left, right| left.path() == right.path());
    Ok(links)
}
