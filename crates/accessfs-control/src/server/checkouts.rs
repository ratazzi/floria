use super::*;

pub(super) fn discover_project_checkouts(
    catalog: &Catalog,
    project_id: &str,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let project = snapshot
        .projects
        .iter()
        .find(|project| project.id == project_id)
        .ok_or_else(|| CatalogError::NotFound(format!("project {project_id}")))?;
    let discovered = discover_git_checkouts(&project.path)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    Ok(ControlResult::ProjectCheckoutDiscovery(
        checkout_discovery(&snapshot, project_id, discovered),
    ))
}
pub(super) fn project_checkout_inventory(
    catalog: &Catalog,
    monitor: Option<&GitCheckoutMonitor>,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let (revision, projects) = if let Some(monitor) = monitor {
        let inventory = monitor.inventory();
        let projects = snapshot
            .projects
            .iter()
            .filter_map(|project| match inventory.projects.get(&project.id) {
                Some(MonitoredGitCheckout::Ready(discovered)) => Some(checkout_discovery(
                    &snapshot,
                    &project.id,
                    discovered.clone(),
                )),
                Some(MonitoredGitCheckout::Unavailable(_)) | None => None,
            })
            .collect();
        (inventory.revision, projects)
    } else {
        let projects = snapshot
            .projects
            .iter()
            .filter_map(|project| {
                discover_git_checkouts(&project.path)
                    .ok()
                    .map(|discovered| checkout_discovery(&snapshot, &project.id, discovered))
            })
            .collect();
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
) -> ProjectCheckoutDiscovery {
    let checkouts = discovered
        .checkouts
        .into_iter()
        .map(|candidate| ProjectCheckoutCandidate {
            managed_checkout_id: snapshot
                .checkouts
                .iter()
                .find(|checkout| {
                    checkout.project_id == project_id && checkout.path == candidate.path
                })
                .map(|checkout| checkout.id.clone()),
            path: candidate.path,
            git_primary: candidate.git_primary,
        })
        .collect();
    ProjectCheckoutDiscovery {
        project_id: project_id.to_string(),
        common_dir: discovered.common_dir,
        checkouts,
    }
}
