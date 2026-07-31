use super::*;

pub(super) fn workspace_snapshot(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
    ssh_runtime_dir: Option<&Path>,
) -> Result<ControlResult, DispatchError> {
    let catalog = catalog.snapshot()?;
    let managed_links = configured_managed_links(
        &catalog,
        store,
        mount_path,
        ssh_runtime_dir,
    )?
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
    Ok(ControlResult::Snapshot(WorkspaceSnapshot { catalog, managed_links }))
}

pub(super) fn repair_managed_path_link(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
    ssh_runtime_dir: Option<&Path>,
    path: &Path,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    configured_managed_links(&snapshot, store, mount_path, ssh_runtime_dir)?
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
    ssh_runtime_dir: Option<&Path>,
) -> Result<Vec<ManagedSymlink>, DispatchError> {
    let mut links = match (store, mount_path) {
        (Some(store), Some(mount_path)) => {
            managed_file_links(snapshot, &store.list()?, mount_path)
                .map_err(|error| DispatchError::Validation(error.to_string()))?
        }
        _ => Vec::new(),
    };
    if let Some(runtime_dir) = ssh_runtime_dir {
        links.extend(
            snapshot
                .surfaces
                .iter()
                .filter(|surface| surface.kind == SurfaceKind::UnixSocket)
                .map(|surface| {
                    ManagedSymlink::new(
                        &surface.path,
                        agent_runtime_socket_path(runtime_dir, &surface.id),
                    )
                }),
        );
    }
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
