use super::*;

pub(super) fn access_history(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    audit_log: &AuditLog,
    limit: usize,
) -> Result<ControlResult, DispatchError> {
    let records = audit_log.read_recent_verified(limit).map_err(|source| DispatchError::Io {
        path: audit_log.path().to_path_buf(),
        source,
    })?;
    let snapshot = catalog.snapshot()?;
    let stored = match store {
        Some(store) => store.list()?,
        None => Vec::new(),
    };
    let events = records
        .into_iter()
        .map(|record| {
            let display = history_display(&record.path, &snapshot, &stored);
            let ssh = history_ssh(&record, &snapshot);
            AccessHistoryEvent {
                ts: record.ts,
                path: record.path,
                display,
                operation: record.operation,
                decision: record.decision,
                rule_id: record.rule_id,
                policy: record.policy,
                ssh,
                identity: history_identity(&record.identity),
            }
        })
        .collect();
    Ok(ControlResult::AccessHistory(events))
}

pub(super) fn history_display(
    path: &str,
    snapshot: &CatalogSnapshot,
    stored: &[SecretRecord],
) -> Option<String> {
    if let Some(surface_id) = path.strip_prefix("surfaces/") {
        return snapshot
            .surfaces
            .iter()
            .find(|surface| surface.id == surface_id)
            .map(|surface| {
                surface
                    .path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| surface.name.clone())
            });
    }
    path.strip_prefix("secrets/").and_then(|secret_id| {
        stored
            .iter()
            .find(|record| record.id.as_str() == secret_id)
            .map(SecretRecord::display_name)
    })
}

pub(super) fn history_ssh(record: &AuditAccessRecord, snapshot: &CatalogSnapshot) -> Option<AccessHistorySsh> {
    let surface_id = record.surface_id.as_ref()?;
    let resource_id = record.resource_id.as_ref()?;
    let key_fingerprint = record.key_fingerprint.as_ref()?;
    let session = record.ssh_session.as_ref();
    Some(AccessHistorySsh {
        surface_id: surface_id.clone(),
        surface_name: snapshot
            .surfaces
            .iter()
            .find(|surface| surface.id == *surface_id)
            .map(|surface| surface.name.clone())
            .or_else(|| {
                snapshot
                    .resources
                    .iter()
                    .find(|resource| {
                        resource.id == *surface_id && resource.kind == ResourceKind::SshAccess
                    })
                    .map(|resource| resource.name.clone())
            })
            .unwrap_or_else(|| surface_id.clone()),
        resource_id: resource_id.clone(),
        key_fingerprint: key_fingerprint.clone(),
        key_label: record
            .key_label
            .clone()
            .or_else(|| {
                snapshot
                    .resources
                    .iter()
                    .find(|resource| resource.id == *resource_id)
                    .map(|resource| resource.name.clone())
            })
            .unwrap_or_else(|| resource_id.clone()),
        identity_source: record
            .identity_source
            .clone()
            .or_else(|| history_ssh_identity_source(resource_id, snapshot)),
        requested_destination: session.and_then(|value| value.requested_destination.clone()),
        verified_host_key_fingerprint: session
            .and_then(|value| value.verified_host_key_fingerprint.clone()),
        ssh_user: session.and_then(|value| value.ssh_user.clone()),
        forwarding_hops: session.map_or(0, |value| value.forwarding_hops),
    })
}

fn history_ssh_identity_source(
    resource_id: &str,
    snapshot: &CatalogSnapshot,
) -> Option<String> {
    let resource = snapshot
        .resources
        .iter()
        .find(|resource| resource.id == resource_id)?;
    if resource.kind == ResourceKind::SshAgent {
        return snapshot
            .endpoints
            .get(resource_id)
            .map(|path| path.display().to_string());
    }
    resource
        .origin
        .sources
        .first()
        .map(|source| source.path.display().to_string())
}

pub(super) fn history_identity(identity: &floria_core::identity::ProcessIdentity) -> AccessHistoryIdentity {
    AccessHistoryIdentity {
        pid: identity.pid,
        uid: identity.uid,
        exe: identity.exe_path.as_ref().map(|path| path.display().to_string()),
        cwd: identity.cwd.as_ref().map(|path| path.display().to_string()),
        cmdline: identity.cmdline.clone(),
        bundle_id: identity.bundle_id.clone(),
        team_id: identity.team_id.clone(),
        parent_chain: identity
            .parent_chain
            .iter()
            .rev()
            .map(|process| AccessHistoryProcess {
                pid: process.pid,
                name: process.name.clone(),
                exe: process.exe_path.as_ref().map(|path| path.display().to_string()),
            })
            .collect(),
        chain: identity.chain_display(),
    }
}
