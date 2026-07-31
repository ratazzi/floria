use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn create_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    default_env_key: Option<String>,
    value: crate::protocol::SecretValue,
    settings: ManagedItemSettings,
    origin: ResourceOrigin,
) -> Result<ControlResult, DispatchError> {
    let ManagedItemSettings { enforcement, metadata } = settings;
    if value.as_bytes().is_empty() {
        return Err(DispatchError::Validation(
            "shared secret value cannot be empty".to_string(),
        ));
    }
    let entry_label = name.clone();
    let mut resource = Resource {
        id: resource_id,
        name,
        kind: ResourceKind::SharedSecret,
        shape: ValueShape::Scalar,
        codec: ResourceCodec::Opaque,
        default_env_key: default_env_key.clone(),
        entries: vec![EntrySpec {
            address: "value".to_string(),
            label: entry_label,
            key: default_env_key,
            sensitive: true,
        }],
        source: ResourceSource::SecretRef { secret_id: "pending-secret-id".to_string() },
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
        NewSecret::managed(resource.name.clone()).with_enforcement(enforcement),
        value.as_bytes(),
    )?;
    resource.source = ResourceSource::SecretRef { secret_id: secret_id.to_string() };
    if let Err(error) = catalog.create_resource(&resource) {
        if let Err(cleanup_error) = store.delete(&secret_id) {
            tracing::warn!(%secret_id, %cleanup_error, "cleaning up unreferenced shared secret failed");
        }
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::SharedSecretCreated { resource, version: 1 })
}

pub(super) fn validate_resource_value(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    resource: &Resource,
) -> Result<(), DispatchError> {
    let (Some(_), ResourceSource::SecretRef { .. }) = (store, &resource.source) else {
        return Ok(());
    };
    let mut snapshot = catalog.snapshot()?;
    if let Some(existing) = snapshot.resources.iter_mut().find(|item| item.id == resource.id) {
        *existing = resource.clone();
    } else {
        snapshot.resources.push(resource.clone());
    }
    validate_snapshot_values(&snapshot, store)
}

pub(super) fn update_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    default_env_key: Option<String>,
    value: Option<crate::protocol::SecretValue>,
    settings: ManagedItemSettings,
) -> Result<ControlResult, DispatchError> {
    let ManagedItemSettings { enforcement, metadata } = settings;
    if value.as_ref().is_some_and(|value| value.as_bytes().is_empty()) {
        return Err(DispatchError::Validation(
            "shared secret value cannot be empty".to_string(),
        ));
    }
    let original = catalog.resource(&resource_id)?;
    let mut resource = original.clone();
    if resource.kind != ResourceKind::SharedSecret {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a shared secret"
        )));
    }
    if resource.entries.len() != 1 || resource.entries[0].address != "value" {
        return Err(DispatchError::Validation(format!(
            "shared secret {resource_id:?} does not have exactly one value entry"
        )));
    }

    resource.name = name;
    resource.default_env_key = default_env_key.clone();
    resource.entries[0].label = resource.name.clone();
    resource.entries[0].key = default_env_key;
    resource.enforcement = enforcement;
    resource.metadata = metadata;
    catalog.validate_resource(&resource)?;
    validate_resource_value(catalog, Some(store), &resource)?;
    let ResourceSource::SecretRef { secret_id } = &resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored secret"
        )));
    };
    let secret_id: SecretId = secret_id.parse()?;
    if let Some(value) = &value {
        let mut snapshot = catalog.snapshot()?;
        let existing = snapshot
            .resources
            .iter_mut()
            .find(|item| item.id == resource.id)
            .expect("the updated shared secret was loaded from this catalog");
        *existing = resource.clone();
        validate_secret_bytes(&snapshot, secret_id.as_str(), value.as_bytes())
            .map_err(|error| DispatchError::Validation(error.to_string()))?;
    }

    catalog.upsert_resource(&resource)?;
    if let Some(value) = value {
        if let Err(error) = store.append_version(&secret_id, value.as_bytes()) {
            if let Err(restore_error) = catalog.upsert_resource(&original) {
                tracing::error!(
                    %resource_id,
                    %error,
                    %restore_error,
                    "shared secret rotation failed and catalog rollback also failed"
                );
            }
            return Err(DispatchError::Store(error));
        }
    }
    Ok(ControlResult::Empty)
}

pub(super) fn remove_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
) -> Result<ControlResult, DispatchError> {
    let resource = catalog.resource(&resource_id)?;
    if resource.kind != ResourceKind::SharedSecret {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a shared secret"
        )));
    }
    let ResourceSource::SecretRef { secret_id } = &resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored secret"
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
                "shared secret storage deletion failed and catalog rollback also failed"
            );
        }
        return Err(DispatchError::Store(error));
    }
    Ok(ControlResult::Empty)
}

pub(super) fn validate_snapshot_values(
    snapshot: &CatalogSnapshot,
    store: Option<&dyn SecretStore>,
) -> Result<(), DispatchError> {
    let Some(store) = store else { return Ok(()) };
    let mut validated = std::collections::HashSet::new();
    for resource in &snapshot.resources {
        if resource.kind == ResourceKind::SshIdentity {
            continue;
        }
        let ResourceSource::SecretRef { secret_id } = &resource.source else { continue };
        if !validated.insert(secret_id) {
            continue;
        }
        let id: SecretId = secret_id.parse()?;
        let plaintext = store.get(&id)?;
        validate_secret_bytes(snapshot, id.as_str(), &plaintext)
            .map_err(|error| DispatchError::Validation(error.to_string()))?;
    }
    Ok(())
}

pub(super) fn rotate_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    value: crate::protocol::SecretValue,
) -> Result<ControlResult, DispatchError> {
    if value.as_bytes().is_empty() {
        return Err(DispatchError::Validation(
            "shared secret value cannot be empty".to_string(),
        ));
    }
    let resource = catalog.resource(&resource_id)?;
    if resource.kind != ResourceKind::SharedSecret {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a shared secret"
        )));
    }
    let ResourceSource::SecretRef { secret_id } = resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored secret"
        )));
    };
    let secret_id: SecretId = secret_id.parse()?;
    let snapshot = catalog.snapshot()?;
    validate_secret_bytes(&snapshot, secret_id.as_str(), value.as_bytes())
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    let version = store.append_version(&secret_id, value.as_bytes())?;
    Ok(ControlResult::SharedSecretRotated { resource_id, version })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn create_env_file(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    codec: ResourceCodec,
    value: crate::protocol::SecretValue,
    settings: ManagedItemSettings,
    origin: ResourceOrigin,
) -> Result<ControlResult, DispatchError> {
    let ManagedItemSettings { enforcement, metadata } = settings;
    if !matches!(codec, ResourceCodec::Dotenv | ResourceCodec::Ini) {
        return Err(DispatchError::Validation(format!(
            "env file codec {codec:?} is not supported"
        )));
    }
    let values = decode_source(codec, &resource_id, value.as_bytes())
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    if values.is_empty() {
        return Err(DispatchError::Validation(
            "env file must contain at least one entry".to_string(),
        ));
    }
    let mut resource = Resource {
        id: resource_id,
        name,
        kind: ResourceKind::EnvFile,
        shape: ValueShape::KeyValueSet,
        codec,
        default_env_key: None,
        entries: values
            .into_iter()
            .map(|entry| EntrySpec {
                address: entry.address,
                label: match (&entry.section, &entry.key) {
                    (Some(section), Some(key)) => format!("[{section}] {key}"),
                    (_, Some(key)) => key.clone(),
                    _ => "Value".to_string(),
                },
                key: entry.key,
                sensitive: true,
            })
            .collect(),
        source: ResourceSource::SecretRef { secret_id: "pending-secret-id".to_string() },
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
            }));
        }
        Err(CatalogError::NotFound(_)) => {}
        Err(error) => return Err(DispatchError::Catalog(error)),
    }

    let secret_id = store.put(
        NewSecret::managed(resource.name.clone()).with_enforcement(enforcement),
        value.as_bytes(),
    )?;
    resource.source = ResourceSource::SecretRef { secret_id: secret_id.to_string() };
    if let Err(error) = catalog.create_resource(&resource) {
        if let Err(cleanup_error) = store.delete(&secret_id) {
            tracing::warn!(%secret_id, %cleanup_error, "cleaning up unreferenced env file failed");
        }
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::EnvFileCreated { resource, version: 1 })
}

pub(super) fn update_resource_metadata(
    catalog: &Catalog,
    resource_id: &str,
    name: String,
    enforcement: Enforcement,
    metadata: ItemMetadata,
) -> Result<ControlResult, DispatchError> {
    let mut resource = catalog.resource(resource_id)?;
    resource.name = name;
    resource.enforcement = enforcement;
    resource.metadata = metadata;
    if resource.kind == ResourceKind::SharedSecret && resource.entries.len() == 1 {
        resource.entries[0].label = resource.name.clone();
    }
    if resource.source == ResourceSource::Socket {
        let endpoint = catalog
            .snapshot()?
            .endpoints
            .get(resource_id)
            .cloned()
            .ok_or_else(|| {
                DispatchError::Validation(format!(
                    "socket resource {resource_id:?} has no machine-local endpoint"
                ))
            })?;
        catalog.upsert_socket_resource(&resource, &endpoint)?;
    } else {
        catalog.upsert_resource(&resource)?;
    }
    Ok(ControlResult::Empty)
}
