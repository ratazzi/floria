use super::*;

pub(super) fn discover_project_checkouts(
    catalog: &Catalog,
    project_id: &str,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let records = store.map(SecretStore::list).transpose()?;
    let project = snapshot
        .projects
        .iter()
        .find(|project| project.id == project_id)
        .ok_or_else(|| CatalogError::NotFound(format!("project {project_id}")))?;
    let discovered = discover_git_checkouts(&project.path)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    Ok(ControlResult::ProjectCheckoutDiscovery(
        checkout_discovery(
            &snapshot,
            project_id,
            discovered,
            records.as_deref(),
            mount_path,
        )?,
    ))
}
pub(super) fn project_checkout_inventory(
    catalog: &Catalog,
    monitor: Option<&GitCheckoutMonitor>,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let records = store.map(SecretStore::list).transpose()?;
    let (revision, projects) = if let Some(monitor) = monitor {
        let inventory = monitor.inventory();
        let mut projects = Vec::new();
        for project in &snapshot.projects {
            if let Some(MonitoredGitCheckout::Ready(discovered)) =
                inventory.projects.get(&project.id)
            {
                projects.push(checkout_discovery(
                    &snapshot,
                    &project.id,
                    discovered.clone(),
                    records.as_deref(),
                    mount_path,
                )?);
            }
        }
        (inventory.revision, projects)
    } else {
        let mut projects = Vec::new();
        for project in &snapshot.projects {
            if let Ok(discovered) = discover_git_checkouts(&project.path) {
                projects.push(checkout_discovery(
                    &snapshot,
                    &project.id,
                    discovered,
                    records.as_deref(),
                    mount_path,
                )?);
            }
        }
        (0, projects)
    };
    Ok(ControlResult::ProjectCheckoutInventory(
        ProjectCheckoutInventory { revision, projects },
    ))
}

pub(super) fn checkout_discovery(
    snapshot: &CatalogSnapshot,
    project_id: &str,
    discovered: GitCheckoutDiscovery,
    records: Option<&[SecretRecord]>,
    mount_path: Option<&Path>,
) -> Result<ProjectCheckoutDiscovery, DispatchError> {
    let checkouts = discovered
        .checkouts
        .into_iter()
        .map(|candidate| {
            let managed = snapshot
                .checkouts
                .iter()
                .find(|checkout| {
                    checkout.project_id == project_id && checkout.path == candidate.path
                });
            let link_issues = match (managed, records, mount_path) {
                (Some(checkout), Some(records), Some(mount_path))
                    if checkout.kind == ProjectCheckoutKind::Worktree =>
                {
                    checkout_link_issues(snapshot, records, mount_path, checkout)
                        .map_err(|error| DispatchError::Validation(error.to_string()))?
                }
                _ => Vec::new(),
            };
            Ok(ProjectCheckoutCandidate {
                managed_checkout_id: managed.map(|checkout| checkout.id.clone()),
                path: candidate.path,
                git_primary: candidate.git_primary,
                link_issues,
            })
        })
        .collect::<Result<Vec<_>, DispatchError>>()?;
    Ok(ProjectCheckoutDiscovery {
        project_id: project_id.to_string(),
        common_dir: discovered.common_dir,
        checkouts,
    })
}
