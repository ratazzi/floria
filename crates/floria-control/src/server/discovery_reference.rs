use super::*;

pub(super) fn resolve_discovery_reference(
    catalog: &Catalog,
    store: &dyn SecretStore,
    surface_id: &str,
    key: &str,
    source: DiscoveryReferenceSource,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let surface = snapshot
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .ok_or_else(|| DispatchError::Validation(format!("surface {surface_id:?} was not found")))?
        .clone();
    if !matches!(
        surface.kind.composed_format(),
        Some(SurfaceFormat::Dotenv | SurfaceFormat::Direnv)
    ) {
        return Err(DispatchError::Validation(
            "reference values can only be attached to dotenv or direnv outputs".to_string(),
        ));
    }
    let binding_ids = match &surface.input {
        SurfaceInput::Bindings { binding_ids } => binding_ids.clone(),
        _ => {
            return Err(DispatchError::Validation(
                "reference target must be a composed environment output".to_string(),
            ))
        }
    };
    if resolve_catalog_surface(&snapshot, surface_id)?
        .iter()
        .any(|export| export.key == key)
    {
        return Err(DispatchError::Validation(format!(
            "{key:?} is already exported by this output"
        )));
    }
    let environment = snapshot
        .environments
        .iter()
        .find(|environment| environment.id == surface.environment_id)
        .ok_or_else(|| {
            DispatchError::Validation(format!(
                "environment {:?} was not found",
                surface.environment_id
            ))
        })?;

    let mut mutation = DiscoveryMutationGuard::new(catalog, store);
    let (resource_id, default_env_key) = match source {
        DiscoveryReferenceSource::NewSharedSecret {
            name,
            value,
            enforcement,
            metadata,
        } => {
            let resource_id = generated_id("shared-secret");
            create_shared_secret(
                catalog,
                store,
                resource_id.clone(),
                name,
                Some(key.to_string()),
                value,
                ManagedItemSettings { enforcement, metadata },
                ResourceOrigin {
                    kind: OriginKind::Manual,
                    sources: Vec::new(),
                },
            )?;
            mutation.track_resource(resource_id.clone());
            (resource_id, Some(key.to_string()))
        }
        DiscoveryReferenceSource::ExistingSharedSecret { resource_id } => {
            let resource = catalog.resource(&resource_id)?;
            if resource.kind != ResourceKind::SharedSecret || resource.shape != ValueShape::Scalar {
                return Err(DispatchError::Validation(
                    "choose a scalar Shared Secret for this reference value".to_string(),
                ));
            }
            (resource_id, resource.default_env_key)
        }
    };

    let key_override = (default_env_key.as_deref() != Some(key)).then(|| key.to_string());
    let reusable_binding = snapshot
        .bindings
        .iter()
        .filter(|binding| {
            binding.project_id == environment.project_id
                && binding.resource_id == resource_id
                && binding.selection == EntrySelection::All
                && binding.key_override == key_override
                && binding.enabled
                && match &binding.scope {
                    BindingScope::Common => true,
                    BindingScope::Environment { environment_id } => {
                        environment_id == &environment.id
                    }
                }
        })
        .min_by_key(|binding| matches!(&binding.scope, BindingScope::Common));
    let binding_id = if let Some(binding) = reusable_binding {
        binding.id.clone()
    } else {
        let binding_id = generated_id("binding");
        catalog.upsert_binding(&Binding {
            id: binding_id.clone(),
            project_id: environment.project_id.clone(),
            scope: BindingScope::Environment {
                environment_id: environment.id.clone(),
            },
            resource_id: resource_id.clone(),
            selection: EntrySelection::All,
            key_override,
            enabled: true,
            allow_override: false,
            position: snapshot
                .bindings
                .iter()
                .filter(|binding| {
                    binding.project_id == environment.project_id
                        && binding.scope
                            == (BindingScope::Environment {
                                environment_id: environment.id.clone(),
                            })
                })
                .count() as i64,
        })?;
        mutation.track_binding(binding_id.clone());
        binding_id
    };

    let mut updated_surface = surface;
    updated_surface.input = SurfaceInput::Bindings {
        binding_ids: binding_ids
            .into_iter()
            .chain(std::iter::once(binding_id.clone()))
            .collect(),
    };
    catalog.upsert_surface(&updated_surface)?;
    mutation.commit();

    Ok(ControlResult::DiscoveryReferenceResolved(
        DiscoveryReferenceResolution {
            surface_id: surface_id.to_string(),
            resource_id,
            binding_id,
            key: key.to_string(),
        },
    ))
}
