use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn import_ssh_identity_from_file(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    resource_id: String,
    name: String,
    path: &Path,
    passphrase: Option<&crate::protocol::SecretValue>,
    manage_source: bool,
    settings: ManagedItemSettings,
    mut origin: ResourceOrigin,
) -> Result<ControlResult, DispatchError> {
    let path = canonical_source_path(path).map_err(|source| DispatchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for source in &mut origin.sources {
        source.path.clone_from(&path);
    }
    let enforcement = settings.enforcement;
    let imported = import_ssh_identity(
        catalog,
        store,
        resource_id,
        name,
        &path,
        passphrase,
        settings,
        origin,
    )?;
    if !manage_source {
        return Ok(imported);
    }

    let protected = match protect_file_with_initial_enforcement(
        catalog,
        store,
        mount_path,
        &path,
        enforcement,
    ) {
        Ok(protected) => protected,
        Err(error) => {
            let ControlResult::SshIdentityCreated { resource } = &imported else {
                unreachable!("SSH identity import returned an unexpected result");
            };
            if let Err(cleanup_error) = delete_ssh_identity(catalog, store, resource.clone()) {
                tracing::error!(
                    resource_id = %resource.id,
                    ?error,
                    ?cleanup_error,
                    "source protection failed and imported SSH identity cleanup also failed"
                );
            }
            return Err(error);
        }
    };
    let ControlResult::FileProtected { file, created } = protected else {
        return Err(DispatchError::Validation(
            "protecting an SSH identity source returned an unexpected result".to_string(),
        ));
    };
    let ControlResult::SshIdentityCreated { mut resource } = imported else {
        unreachable!("SSH identity import returned an unexpected result");
    };
    if let Err(error) = attach_managed_source(catalog, &mut resource, &file.id) {
        if created {
            if let Err(cleanup_error) = restore_file(catalog, store, mount_path, &file.id) {
                tracing::error!(
                    resource_id = %resource.id,
                    managed_source_id = %file.id,
                    ?error,
                    ?cleanup_error,
                    "SSH identity association failed and managed source cleanup also failed"
                );
            }
        }
        if let Err(cleanup_error) = delete_ssh_identity(catalog, store, resource.clone()) {
            tracing::error!(
                resource_id = %resource.id,
                ?error,
                ?cleanup_error,
                "SSH identity association failed and imported identity cleanup also failed"
            );
        }
        return Err(error);
    }
    Ok(ControlResult::SshIdentityCreated { resource })
}

pub(super) fn attach_managed_source(
    catalog: &Catalog,
    resource: &mut Resource,
    managed_source_id: &str,
) -> Result<(), DispatchError> {
    // Discovery can refresh machine-local origin immediately before this association. Reload the
    // authoritative row so attaching a portable store id cannot overwrite that newer provenance.
    let mut current = catalog.resource(&resource.id)?;
    let ResourceSource::SecretRef { managed_source_ids, .. } = &mut current.source else {
        return Err(DispatchError::Validation(format!(
            "resource {:?} does not reference a stored private key",
            resource.id
        )));
    };
    if !managed_source_ids.iter().any(|id| id == managed_source_id) {
        managed_source_ids.push(managed_source_id.to_string());
        catalog.upsert_resource(&current)?;
    }
    *resource = current;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn import_ssh_identity(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    path: &Path,
    passphrase: Option<&crate::protocol::SecretValue>,
    settings: ManagedItemSettings,
    origin: ResourceOrigin,
) -> Result<ControlResult, DispatchError> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(DispatchError::Validation(
            "SSH identity name cannot be empty".to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(DispatchError::Validation(format!(
            "SSH private key path {} must be absolute",
            path.display()
        )));
    }
    floria_core::config::check_secure_perms(path)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    let encoded = zeroize::Zeroizing::new(
        std::fs::read(path).map_err(|source| DispatchError::Io {
            path: path.to_path_buf(),
            source,
        })?,
    );
    let imported = floria_ssh::import_private_key(
        &encoded,
        passphrase.map(crate::protocol::SecretValue::as_bytes),
    )?;
    let ManagedItemSettings { enforcement, metadata } = settings;
    let mut resource = Resource {
        id: resource_id,
        name: name.clone(),
        kind: ResourceKind::SshIdentity,
        shape: ValueShape::SshIdentity,
        codec: ResourceCodec::Opaque,
        default_env_key: None,
        entries: vec![EntrySpec {
            address: imported.identity.address.clone(),
            label: name.clone(),
            key: None,
            sensitive: false,
        }],
        source: ResourceSource::SecretRef {
            secret_id: "pending-managed-private-key".to_string(),
            managed_source_ids: Vec::new(),
        },
        enforcement,
        metadata,
        origin,
    };
    catalog.validate_resource(&resource)?;
    match catalog.resource(&resource.id) {
        Ok(_) => {
            return Err(DispatchError::Catalog(CatalogError::AlreadyExists {
                kind: "resource",
                id: resource.id.clone(),
            }))
        }
        Err(CatalogError::NotFound(_)) => {}
        Err(error) => return Err(DispatchError::Catalog(error)),
    }

    let secret_id = store.put(
        NewSecret::managed(name).with_enforcement(enforcement),
        imported.as_bytes(),
    )?;
    resource.source = ResourceSource::SecretRef {
        secret_id: secret_id.to_string(),
        managed_source_ids: Vec::new(),
    };
    if let Err(error) = catalog.create_resource(&resource) {
        if let Err(cleanup_error) = store.delete(&secret_id) {
            tracing::warn!(%secret_id, %cleanup_error, "cleaning up unreferenced SSH private key failed");
        }
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::SshIdentityCreated { resource })
}

pub(super) fn remove_ssh_identity(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    resource_id: String,
) -> Result<ControlResult, DispatchError> {
    let mut resource = catalog.resource(&resource_id)?;
    if resource.kind != ResourceKind::SshIdentity {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a managed SSH identity"
        )));
    }
    let usage = catalog.resource_usage(&resource_id)?;
    if !usage.bindings.is_empty() || !usage.direct_surface_ids.is_empty() {
        return Err(DispatchError::Catalog(CatalogError::ResourceInUse {
            resource_id: resource_id.clone(),
            binding_ids: usage.bindings.into_iter().map(|usage| usage.binding_id).collect(),
            surface_ids: usage.direct_surface_ids,
        }));
    }
    let ResourceSource::SecretRef { managed_source_ids, .. } = &resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored private key"
        )));
    };
    let managed_source_ids = managed_source_ids.clone();
    for managed_source_id in managed_source_ids {
        let id: SecretId = managed_source_id.parse()?;
        if store.record(&id)?.is_some() {
            restore_file(catalog, store, mount_path, &managed_source_id)?;
        }
        let ResourceSource::SecretRef { managed_source_ids, .. } = &mut resource.source else {
            unreachable!("SSH identity source was validated above");
        };
        managed_source_ids.retain(|id| id != &managed_source_id);
        catalog.upsert_resource(&resource)?;
    }

    delete_ssh_identity(catalog, store, resource)
}

fn delete_ssh_identity(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource: Resource,
) -> Result<ControlResult, DispatchError> {
    let ResourceSource::SecretRef { secret_id, .. } = &resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {:?} does not reference a stored private key",
            resource.id
        )));
    };
    let secret_id: SecretId = secret_id.parse()?;
    catalog.remove_resource(&resource.id)?;
    if let Err(error) = store.delete(&secret_id) {
        if let Err(restore_error) = catalog.create_resource(&resource) {
            tracing::error!(
                resource_id = %resource.id,
                %error,
                %restore_error,
                "SSH identity storage deletion failed and catalog rollback also failed"
            );
        }
        return Err(DispatchError::Store(error));
    }
    Ok(ControlResult::Empty)
}
