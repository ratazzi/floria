use super::*;

#[cfg(test)]
pub(super) fn dispatch(
    catalog: &Catalog,
    services: DispatchServices<'_>,
    command: ControlCommand,
) -> Result<ControlResult, DispatchError> {
    dispatch_observed(catalog, services, command, None)
}

pub(super) fn dispatch_observed(
    catalog: &Catalog,
    services: DispatchServices<'_>,
    command: ControlCommand,
    observer: Option<&dyn CatalogObserver>,
) -> Result<ControlResult, DispatchError> {
    let mutating = !is_read_only(&command);
    let self_coordinated = is_self_coordinated(&command);
    let operation = || {
        let result = dispatch_uncoordinated(catalog, services, command);
        if result.is_ok() && mutating {
            notify_observer(catalog, observer);
        }
        result
    };
    if mutating && !self_coordinated {
        if let Some(mutations) = services.mutations {
            return mutations.run_committed(operation);
        }
    }
    operation()
}

/// Commands whose runtime service already holds the shared catalog/store mutation gate.
///
/// Wrapping these in `run_committed` would attempt to acquire the same non-recursive mutex twice
/// on one control request. They still notify the catalog observer after the service releases the
/// gate so FUSE surfaces, links, policy, and SSH runtime see the newly projected state.
pub(super) fn is_self_coordinated(command: &ControlCommand) -> bool {
    matches!(
        command,
        ControlCommand::ReplicationCreate { .. }
            | ControlCommand::ReplicationOpen { .. }
            | ControlCommand::ReplicationSync
            | ControlCommand::ReplicationResolveWithCurrent
            | ControlCommand::ReplicationRevokeDevice { .. }
            | ControlCommand::ReplicationRequestReenrollment
            | ControlCommand::ReplicationDisable
            | ControlCommand::ReplicationEnroll { .. }
            | ControlCommand::ReplicationApprove { .. }
            | ControlCommand::RecordSyncResolveConflict { .. }
            | ControlCommand::RecordSyncPrepareVaultReenrollment { .. }
            | ControlCommand::RecordSyncApproveVaultEnrollment { .. }
            | ControlCommand::RecordSyncRevokeVaultDevice { .. }
            | ControlCommand::RecordSyncActivateVault { .. }
            | ControlCommand::RecordSyncApplyInbound { .. }
    )
}

fn dispatch_uncoordinated(
    catalog: &Catalog,
    services: DispatchServices<'_>,
    command: ControlCommand,
) -> Result<ControlResult, DispatchError> {
    let DispatchServices {
        store,
        store_arc,
        mount_path,
        mutations: _,
        policy,
        ssh_discovery,
        ssh_config,
        backup,
        recovery_key,
        health,
        diagnostics,
        replication,
        record_sync,
        checkout_monitor,
        audit_log,
        discovery_jobs,
    } = services;
    match command {
        ControlCommand::Ping => Ok(ControlResult::Pong {
            protocol_version: crate::protocol::CONTROL_PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: catalog.schema_version(),
            minimum_schema_version: floria_catalog::Catalog::minimum_supported_schema_version(),
            store_format_version: floria_store::STORE_FORMAT_VERSION,
            minimum_store_format_version: floria_store::MIN_SUPPORTED_STORE_FORMAT_VERSION,
        }),
        ControlCommand::Health => health
            .map(|reporter| ControlResult::Health(reporter.report()))
            .ok_or_else(|| {
                DispatchError::Validation(
                    "runtime health is unavailable on this control server".to_string(),
                )
            }),
        ControlCommand::DiagnosticsExport { destination, include_paths } => {
            if !destination.is_absolute() {
                return Err(DispatchError::Validation(
                    "diagnostics destination must be absolute".to_string(),
                ));
            }
            diagnostics
                .ok_or_else(|| {
                    DispatchError::Validation(
                        "diagnostics export is unavailable on this control server".to_string(),
                    )
                })?
                .export(&destination, include_paths)
                .map(ControlResult::Diagnostics)
                .map_err(DispatchError::Diagnostics)
        }
        ControlCommand::ReplicationStatus => replication
            .map(|service| ControlResult::ReplicationStatus(service.status()))
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            }),
        ControlCommand::ReplicationCreate { directory } => {
            if !directory.is_absolute() {
                return Err(DispatchError::Validation(
                    "replication directory must be absolute".to_string(),
                ));
            }
            replication
                .ok_or_else(|| {
                    DispatchError::Validation(
                        "replication is unavailable on this control server".to_string(),
                    )
                })?
                .create(&directory)
                .map(ControlResult::ReplicationStatus)
                .map_err(DispatchError::Replication)
        }
        ControlCommand::ReplicationOpen { directory } => {
            if !directory.is_absolute() {
                return Err(DispatchError::Validation(
                    "replication directory must be absolute".to_string(),
                ));
            }
            replication
                .ok_or_else(|| {
                    DispatchError::Validation(
                        "replication is unavailable on this control server".to_string(),
                    )
                })?
                .open(&directory)
                .map(ControlResult::ReplicationStatus)
                .map_err(DispatchError::Replication)
        }
        ControlCommand::ReplicationSync => replication
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            })?
            .sync()
            .map(ControlResult::ReplicationStatus)
            .map_err(DispatchError::Replication),
        ControlCommand::ReplicationResolveWithCurrent => replication
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            })?
            .resolve_with_current()
            .map(ControlResult::ReplicationStatus)
            .map_err(DispatchError::Replication),
        ControlCommand::ReplicationRevokeDevice { device_id } => replication
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            })?
            .revoke_device(&device_id)
            .map(ControlResult::ReplicationStatus)
            .map_err(DispatchError::Replication),
        ControlCommand::ReplicationRequestReenrollment => replication
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            })?
            .request_reenrollment()
            .map(ControlResult::ReplicationStatus)
            .map_err(DispatchError::Replication),
        ControlCommand::ReplicationDisable => replication
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            })?
            .disable()
            .map(ControlResult::ReplicationStatus)
            .map_err(DispatchError::Replication),
        ControlCommand::ReplicationEnrollment => replication
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            })?
            .enrollment()
            .map(ControlResult::ReplicationEnrollment)
            .map_err(DispatchError::Replication),
        ControlCommand::ReplicationEnroll { enrollment } => replication
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            })?
            .enroll(enrollment)
            .map(ControlResult::ReplicationStatus)
            .map_err(DispatchError::Replication),
        ControlCommand::ReplicationApprove { device_id } => replication
            .ok_or_else(|| {
                DispatchError::Validation(
                    "replication is unavailable on this control server".to_string(),
                )
            })?
            .approve(&device_id)
            .map(ControlResult::ReplicationStatus)
            .map_err(DispatchError::Replication),
        ControlCommand::RecordSyncStatus => record_sync
            .ok_or_else(record_sync_unavailable)?
            .status()
            .map(ControlResult::RecordSyncStatus)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncReviewConflicts => record_sync
            .ok_or_else(record_sync_unavailable)?
            .review_conflicts()
            .map(ControlResult::RecordSyncConflicts)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncResolveConflict {
            entity_id,
            selected_revision_id,
            resolved_at,
        } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .resolve_conflict(&entity_id, &selected_revision_id, &resolved_at)
            .map(ControlResult::RecordSyncStatus)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncVaultBootstrap => record_sync
            .ok_or_else(record_sync_unavailable)?
            .vault_bootstrap()
            .map(ControlResult::RecordSyncVaultBootstrap)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncValidateVaultBootstrap {
            expected_vault_id,
            bootstrap,
        } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .validate_vault_bootstrap(&expected_vault_id, bootstrap)
            .map(ControlResult::RecordSyncVaultBootstrap)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncPrepareVaultEnrollment {
            bootstrap,
            device_name,
            requested_at,
        } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .prepare_vault_enrollment(bootstrap, device_name, &requested_at)
            .map(ControlResult::RecordSyncEnrollmentPreparation)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncPrepareVaultReenrollment {
            bootstrap,
            expected_fingerprint,
            device_name,
            requested_at,
        } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .prepare_vault_reenrollment(
                bootstrap,
                &expected_fingerprint,
                device_name,
                &requested_at,
            )
            .map(ControlResult::RecordSyncEnrollmentPreparation)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncReviewVaultEnrollments { bootstrap } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .review_vault_enrollments(bootstrap)
            .map(ControlResult::RecordSyncEnrollmentReviews)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncReviewVaultDevices { bootstrap } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .review_vault_devices(bootstrap)
            .map(ControlResult::RecordSyncVaultDevices)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncApproveVaultEnrollment {
            bootstrap,
            device_id,
            expected_fingerprint,
        } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .approve_vault_enrollment(bootstrap, &device_id, &expected_fingerprint)
            .map(ControlResult::RecordSyncVaultBootstrap)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncRevokeVaultDevice {
            bootstrap,
            device_id,
            expected_fingerprint,
        } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .revoke_vault_device(bootstrap, &device_id, &expected_fingerprint)
            .map(ControlResult::RecordSyncVaultBootstrap)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncActivateVault { bootstrap } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .activate_vault(bootstrap)
            .map(ControlResult::RecordSyncVaultActivation)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncNextOutbound { limit } => {
            let batch = record_sync
                .ok_or_else(record_sync_unavailable)?
                .next_outbound(limit)
                .map_err(DispatchError::RecordSync)?;
            let encoded_size = serde_json::to_vec(&batch)
                .map_err(|error| DispatchError::RecordSync(error.to_string()))?
                .len();
            if encoded_size > crate::protocol::MAX_RECORD_SYNC_BATCH_BYTES {
                return Err(DispatchError::Validation(format!(
                    "outbound record sync batch is {encoded_size} bytes; retry with a smaller limit"
                )));
            }
            Ok(ControlResult::RecordSyncOutbound(batch))
        }
        ControlCommand::RecordSyncSettleOutbound { outcomes } => record_sync
            .ok_or_else(record_sync_unavailable)?
            .settle_outbound(&outcomes)
            .map(ControlResult::RecordSyncSettlement)
            .map_err(DispatchError::RecordSync),
        ControlCommand::RecordSyncApplyInbound { batch, observed_at } => {
            if batch.objects().iter().any(|object| !object.file().is_absolute()) {
                return Err(DispatchError::Validation(
                    "inbound record sync object paths must be absolute".to_string(),
                ));
            }
            record_sync
                .ok_or_else(record_sync_unavailable)?
                .apply_inbound(catalog, batch, &observed_at)
                .map(ControlResult::RecordSyncInbound)
                .map_err(DispatchError::RecordSync)
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
        ControlCommand::BackupCreate { destination } => {
            if !destination.is_absolute() {
                return Err(DispatchError::Validation(
                    "backup destination must be absolute".to_string(),
                ));
            }
            backup
                .ok_or_else(|| {
                    DispatchError::Validation(
                        "backup service is unavailable on this control server".to_string(),
                    )
                })?
                .create(catalog, &destination)
                .map(ControlResult::Backup)
                .map_err(DispatchError::Backup)
        }
        ControlCommand::BackupVerify { backup: backup_path } => {
            if !backup_path.is_absolute() {
                return Err(DispatchError::Validation(
                    "backup path must be absolute".to_string(),
                ));
            }
            backup
                .ok_or_else(|| {
                    DispatchError::Validation(
                        "backup service is unavailable on this control server".to_string(),
                    )
                })?
                .verify(&backup_path)
                .map(ControlResult::Backup)
                .map_err(DispatchError::Backup)
        }
        ControlCommand::RecoveryKeyExport { destination, passphrase } => {
            if !destination.is_absolute() {
                return Err(DispatchError::Validation(
                    "recovery key destination must be absolute".to_string(),
                ));
            }
            recovery_key
                .ok_or_else(|| {
                    DispatchError::Validation(
                        "recovery key export is unavailable on this control server".to_string(),
                    )
                })?
                .export(&destination, passphrase.as_str())
                .map(ControlResult::RecoveryKey)
                .map_err(DispatchError::RecoveryKey)
        }
        ControlCommand::Snapshot => {
            workspace_snapshot(catalog, store, mount_path)
        }
        ControlCommand::Discover { paths } => {
            let store = store.ok_or(DispatchError::StoreUnavailable)?;
            let discovery = discover_many(&paths)
                .map_err(|error| DispatchError::Validation(error.to_string()))?;
            let candidate_keys = discovery.shared_secret_candidate_keys();
            let existing = existing_discovery_secrets(catalog, store, &candidate_keys)?;
            let managed_projects =
                existing_discovery_projects(catalog, discovery.projects())?;
            let portable_projects = portable_discovery_project_candidates(catalog)?;
            discovery_review_plan(
                catalog,
                store,
                mount_path,
                discovery.plan_with_project_context(
                    &existing,
                    &managed_projects,
                    &portable_projects,
                ),
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
            project_checkout_inventory(catalog, checkout_monitor, store, mount_path, None)
        }
        ControlCommand::ProjectCheckoutInventoryIfChanged { revision } => {
            project_checkout_inventory(
                catalog,
                checkout_monitor,
                store,
                mount_path,
                Some(revision),
            )
        }
        ControlCommand::ProjectCheckoutDiscover { project_id } => {
            discover_project_checkouts(catalog, &project_id, store, mount_path)
        }
        ControlCommand::ProjectCheckoutUpsert { checkout } => {
            catalog.upsert_checkout(&checkout)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ProjectCheckoutRemove { id } => {
            catalog.remove_checkout(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ManagedLinkRepair { path } => {
            repair_managed_path_link(catalog, store, mount_path, &path)
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
            manage_source,
            enforcement,
            metadata,
        } => import_ssh_identity_from_file(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            name,
            &path,
            passphrase.as_ref(),
            manage_source,
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
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
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
        ControlCommand::ProtectedFileLookup { id, path } => lookup_protected_file(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            id.as_deref(),
            path.as_deref(),
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
        ControlCommand::ProtectedFileContentsUpdate { id, path } => {
            update_protected_file_contents(
                catalog,
                store.ok_or(DispatchError::StoreUnavailable)?,
                mount_path.ok_or(DispatchError::StoreUnavailable)?,
                &id,
                &path,
            )
        }
        ControlCommand::ProtectedFileMetadataUpdate {
            id,
            enforcement,
            environment_ids,
            metadata,
        } => {
            update_protected_file_metadata(
                catalog,
                store.ok_or(DispatchError::StoreUnavailable)?,
                mount_path.ok_or(DispatchError::StoreUnavailable)?,
                &id,
                enforcement,
                environment_ids,
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
            update_resource_metadata(catalog, store, &resource_id, name, enforcement, metadata)
        }
        ControlCommand::ProjectCreate { project, environment, surface } => {
            create_project_workspace(catalog, project, environment, surface)
        }
        ControlCommand::ProjectUpsert { project } => {
            catalog.upsert_project(&project)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ProjectAttach { project_id, path } => {
            attach_replicated_project(catalog, &project_id, &path)
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

fn record_sync_unavailable() -> DispatchError {
    DispatchError::Validation(
        "coordinated record sync is unavailable on this control server".to_string(),
    )
}
