use super::*;

pub(super) fn dispatch(
    catalog: &Catalog,
    services: DispatchServices<'_>,
    command: ControlCommand,
) -> Result<ControlResult, DispatchError> {
    let DispatchServices {
        store,
        store_arc,
        mount_path,
        policy,
        ssh_discovery,
        ssh_config,
        checkout_monitor,
        audit_log,
        discovery_jobs,
    } = services;
    match command {
        ControlCommand::Ping => {
            Ok(ControlResult::Pong { schema_version: catalog.schema_version() })
        }
        ControlCommand::PolicyModeGet => policy
            .map(|controller| ControlResult::PolicyMode(controller.policy_mode()))
            .ok_or_else(|| {
                DispatchError::Validation(
                    "runtime policy is unavailable on this control server".to_string(),
                )
            }),
        ControlCommand::PolicyModeSet { mode, duration_secs } => {
            let controller = policy.ok_or_else(|| {
                DispatchError::Validation(
                    "runtime policy is unavailable on this control server".to_string(),
                )
            })?;
            controller
                .set_policy_mode(mode, duration_secs)
                .map(ControlResult::PolicyMode)
                .map_err(DispatchError::Policy)
        }
        ControlCommand::GrantList => policy
            .ok_or_else(|| {
                DispatchError::Validation(
                    "authorization grants are unavailable on this control server".to_string(),
                )
            })?
            .active_grants()
            .map(ControlResult::ActiveGrants)
            .map_err(DispatchError::Policy),
        ControlCommand::GrantRevoke { id } => {
            let controller = policy.ok_or_else(|| {
                DispatchError::Validation(
                    "authorization grants are unavailable on this control server".to_string(),
                )
            })?;
            controller.revoke_grant(&id).map_err(DispatchError::Policy)?;
            controller
                .active_grants()
                .map(ControlResult::ActiveGrants)
                .map_err(DispatchError::Policy)
        }
        ControlCommand::GrantClear => {
            let controller = policy.ok_or_else(|| {
                DispatchError::Validation(
                    "authorization grants are unavailable on this control server".to_string(),
                )
            })?;
            controller.clear_grants().map_err(DispatchError::Policy)?;
            controller
                .active_grants()
                .map(ControlResult::ActiveGrants)
                .map_err(DispatchError::Policy)
        }
        ControlCommand::AccessHistory { limit } => access_history(
            catalog,
            store,
            audit_log.ok_or_else(|| {
                DispatchError::Validation(
                    "access history is unavailable on this control server".to_string(),
                )
            })?,
            limit.min(500),
        ),
        ControlCommand::Snapshot => Ok(ControlResult::Snapshot(catalog.snapshot()?)),
        ControlCommand::Discover { paths } => {
            let store = store.ok_or(DispatchError::StoreUnavailable)?;
            let discovery = discover_many(&paths)
                .map_err(|error| DispatchError::Validation(error.to_string()))?;
            let candidate_keys = discovery.shared_secret_candidate_keys();
            let existing = existing_discovery_secrets(catalog, store, &candidate_keys)?;
            let managed_projects =
                existing_discovery_projects(catalog, discovery.projects())?;
            discovery_review_plan(
                catalog,
                store,
                mount_path,
                discovery.plan_with_projects(&existing, &managed_projects),
            )
            .map(ControlResult::Discovery)
        }
        ControlCommand::DiscoverStart { paths } => discovery_jobs
            .ok_or_else(|| {
                DispatchError::Validation(
                    "asynchronous discovery is unavailable on this control server".to_string(),
                )
            })?
            .start(paths)
            .map(ControlResult::DiscoveryJob)
            .map_err(DispatchError::Validation),
        ControlCommand::DiscoverStatus { id } => discovery_jobs
            .ok_or_else(|| {
                DispatchError::Validation(
                    "asynchronous discovery is unavailable on this control server".to_string(),
                )
            })?
            .status(&id)
            .map(ControlResult::DiscoveryJob)
            .map_err(DispatchError::Validation),
        ControlCommand::DiscoverCancel { id } => discovery_jobs
            .ok_or_else(|| {
                DispatchError::Validation(
                    "asynchronous discovery is unavailable on this control server".to_string(),
                )
            })?
            .cancel(&id)
            .map(ControlResult::DiscoveryJob)
            .map_err(DispatchError::Validation),
        ControlCommand::DiscoverApply {
            paths,
            imports,
            separate_entries,
            promote_entries,
            demote_entries,
        } => apply_discovery(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            &paths,
            imports.as_deref(),
            &separate_entries,
            &promote_entries,
            &demote_entries,
        ),
        ControlCommand::DiscoverReferenceResolve { surface_id, key, source } => {
            resolve_discovery_reference(
                catalog,
                store.ok_or(DispatchError::StoreUnavailable)?,
                &surface_id,
                &key,
                source,
            )
        }
        ControlCommand::ProjectCheckoutInventory => {
            project_checkout_inventory(catalog, checkout_monitor)
        }
        ControlCommand::ProjectCheckoutDiscover { project_id } => {
            discover_project_checkouts(catalog, &project_id)
        }
        ControlCommand::ProjectCheckoutUpsert { checkout } => {
            catalog.upsert_checkout(&checkout)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ProjectCheckoutRemove { id } => {
            catalog.remove_checkout(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::SshAgentDiscover { endpoint } => {
            if !endpoint.is_absolute() {
                return Err(DispatchError::Validation(
                    "SSH agent endpoint must be absolute".to_string(),
                ));
            }
            let discovery = ssh_discovery.ok_or_else(|| {
                DispatchError::Validation(
                    "SSH agent discovery is unavailable on this control server".to_string(),
                )
            })?;
            discovery
                .discover(&endpoint)
                .map(ControlResult::SshAgentIdentities)
                .map_err(|source| DispatchError::Io { path: endpoint, source })
        }
        ControlCommand::SshIdentityImport {
            resource_id,
            name,
            path,
            passphrase,
            enforcement,
            metadata,
        } => import_ssh_identity(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            name,
            &path,
            passphrase.as_ref(),
            ManagedItemSettings { enforcement, metadata },
            ResourceOrigin {
                kind: OriginKind::SshImport,
                sources: vec![OriginSource {
                    path: path.clone(),
                    project_id: None,
                    environment: None,
                    imported_at: now_rfc3339(),
                }],
            },
        ),
        ControlCommand::SshIdentityRemove { resource_id } => remove_ssh_identity(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
        ),
        ControlCommand::SshConfigStatus => ssh_config
            .ok_or_else(|| {
                DispatchError::Validation(
                    "SSH config integration is unavailable on this control server".to_string(),
                )
            })?
            .status()
            .map(ControlResult::SshConfig)
            .map_err(DispatchError::SshConfig),
        ControlCommand::SshConfigInstall => ssh_config
            .ok_or_else(|| {
                DispatchError::Validation(
                    "SSH config integration is unavailable on this control server".to_string(),
                )
            })?
            .install()
            .map(ControlResult::SshConfig)
            .map_err(DispatchError::SshConfig),
        ControlCommand::SshConfigRemove => ssh_config
            .ok_or_else(|| {
                DispatchError::Validation(
                    "SSH config integration is unavailable on this control server".to_string(),
                )
            })?
            .remove()
            .map(ControlResult::SshConfig)
            .map_err(DispatchError::SshConfig),
        ControlCommand::ProtectedFiles => protected_files(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
        ),
        ControlCommand::FileProtect { path } => protect_file(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            &path,
        ),
        ControlCommand::ProtectedFileHistory { id } => protected_file_history(
            store.ok_or(DispatchError::StoreUnavailable)?,
            &id,
        ),
        ControlCommand::ProtectedFileRollback { id, version } => {
            rollback_protected_file(
                catalog,
                store.ok_or(DispatchError::StoreUnavailable)?,
                mount_path.ok_or(DispatchError::StoreUnavailable)?,
                &id,
                version,
            )
        }
        ControlCommand::ProtectedFileMetadataUpdate { id, enforcement, metadata } => {
            update_protected_file_metadata(
                store.ok_or(DispatchError::StoreUnavailable)?,
                &id,
                enforcement,
                metadata,
            )
        }
        ControlCommand::ManagedFileConfigure { id, project_id, environment_id } => {
            configure_managed_file(
                catalog,
                store.ok_or(DispatchError::StoreUnavailable)?,
                mount_path.ok_or(DispatchError::StoreUnavailable)?,
                &id,
                &project_id,
                environment_id.as_deref(),
            )
        }
        ControlCommand::ManagedFileRestore { id } => restore_managed_file(
            catalog,
            store_arc.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            &id,
        ),
        ControlCommand::FileRestore { id } => restore_file(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            &id,
        ),
        ControlCommand::ResolveEnvironment { project_id, environment_id } => Ok(
            ControlResult::ResolvedEnvironment(
                catalog.resolve_environment(&project_id, &environment_id)?,
            ),
        ),
        ControlCommand::ResourceUsage { resource_id } => {
            Ok(ControlResult::ResourceUsage(catalog.resource_usage(&resource_id)?))
        }
        ControlCommand::SharedSecretCreate {
            resource_id,
            name,
            default_env_key,
            value,
            enforcement,
            metadata,
        } => create_shared_secret(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            name,
            default_env_key,
            value,
            ManagedItemSettings { enforcement, metadata },
            ResourceOrigin { kind: OriginKind::Manual, sources: Vec::new() },
        ),
        ControlCommand::SharedSecretUpdate {
            resource_id,
            name,
            default_env_key,
            value,
            enforcement,
            metadata,
        } => {
            update_shared_secret(
                catalog,
                store.ok_or(DispatchError::StoreUnavailable)?,
                resource_id,
                name,
                default_env_key,
                value,
                ManagedItemSettings { enforcement, metadata },
            )
        }
        ControlCommand::SharedSecretRemove { resource_id } => remove_shared_secret(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
        ),
        ControlCommand::SharedSecretRotate { resource_id, value } => rotate_shared_secret(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            value,
        ),
        ControlCommand::EnvFileCreate { resource_id, name, codec, value, enforcement, metadata } => create_env_file(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            name,
            codec,
            value,
            ManagedItemSettings { enforcement, metadata },
            ResourceOrigin { kind: OriginKind::Manual, sources: Vec::new() },
        ),
        ControlCommand::ResourceMetadataUpdate { resource_id, name, enforcement, metadata } => {
            update_resource_metadata(catalog, &resource_id, name, enforcement, metadata)
        }
        ControlCommand::ProjectCreate { project, environment, surface } => {
            create_project_workspace(catalog, project, environment, surface)
        }
        ControlCommand::ProjectUpsert { project } => {
            catalog.upsert_project(&project)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ProjectDefaultEnvironmentSet { project_id, environment_id } => {
            catalog.set_project_default_environment(&project_id, environment_id.as_deref())?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ProjectRemove { id } => {
            catalog.remove_project(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::EnvironmentUpsert { environment } => {
            catalog.upsert_environment(&environment)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::EnvironmentRemove { id } => {
            catalog.remove_environment(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ResourceUpsert { resource, endpoint } => {
            catalog.validate_resource(&resource)?;
            validate_resource_value(catalog, store, &resource)?;
            match (&resource.source, endpoint) {
                (ResourceSource::Socket, Some(endpoint)) => {
                    catalog.upsert_socket_resource(&resource, &endpoint)?;
                }
                (ResourceSource::Socket, None) => {
                    return Err(DispatchError::Validation(
                        "socket resource requires a machine-local endpoint".to_string(),
                    ));
                }
                (_, Some(_)) => {
                    return Err(DispatchError::Validation(
                        "machine-local endpoint is only valid for a socket resource".to_string(),
                    ));
                }
                (_, None) => catalog.upsert_resource(&resource)?,
            }
            Ok(ControlResult::Empty)
        }
        ControlCommand::ResourceRemove { id } => {
            catalog.remove_resource(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::BindingUpsert { binding } => {
            let mut snapshot = catalog.snapshot()?;
            if let Some(existing) = snapshot.bindings.iter_mut().find(|item| item.id == binding.id) {
                *existing = binding.clone();
            } else {
                snapshot.bindings.push(binding.clone());
            }
            validate_snapshot_values(&snapshot, store)?;
            catalog.upsert_binding(&binding)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::BindingRemove { id } => {
            catalog.remove_binding(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::SurfaceUpsert { surface } => {
            let mut snapshot = catalog.snapshot()?;
            if let Some(existing) = snapshot.surfaces.iter_mut().find(|item| item.id == surface.id) {
                *existing = surface.clone();
            } else {
                snapshot.surfaces.push(surface.clone());
            }
            validate_snapshot_values(&snapshot, store)?;
            catalog.upsert_surface(&surface)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::SurfaceRemove { id } => {
            catalog.remove_surface(&id)?;
            Ok(ControlResult::Empty)
        }
    }
}
