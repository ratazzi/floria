use super::*;

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
    resource.source = ResourceSource::SecretRef { secret_id: secret_id.to_string() };
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
    resource_id: String,
) -> Result<ControlResult, DispatchError> {
    let resource = catalog.resource(&resource_id)?;
    if resource.kind != ResourceKind::SshIdentity {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a managed SSH identity"
        )));
    }
    let ResourceSource::SecretRef { secret_id } = &resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored private key"
        )));
    };
    let secret_id: SecretId = secret_id.parse()?;
    catalog.remove_resource(&resource_id)?;
    if let Err(error) = store.delete(&secret_id) {
        if let Err(restore_error) = catalog.create_resource(&resource) {
            tracing::error!(
                %resource_id,
                %error,
                %restore_error,
                "SSH identity storage deletion failed and catalog rollback also failed"
            );
        }
        return Err(DispatchError::Store(error));
    }
    Ok(ControlResult::Empty)
}
