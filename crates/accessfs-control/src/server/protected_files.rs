use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn protected_files(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let catalog_secret_ids = snapshot
        .resources
        .iter()
        .filter_map(|resource| match &resource.source {
            ResourceSource::SecretRef { secret_id } => Some(secret_id.as_str()),
            ResourceSource::Literal { .. }
            | ResourceSource::Command { .. }
            | ResourceSource::Socket => None,
        })
        .collect::<HashSet<_>>();
    let mut files = store
        .list()?
        .into_iter()
        .filter(|record| !catalog_secret_ids.contains(record.id.as_str()))
        .filter_map(|record| protected_file(record, mount_path, &snapshot))
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.source_path.cmp(&right.source_path));
    Ok(ControlResult::ProtectedFiles(files))
}

pub(super) fn configure_managed_file(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    id: &str,
    project_id: &str,
    environment_id: Option<&str>,
) -> Result<ControlResult, DispatchError> {
    let (secret_id, record) = file_record(store, id)?;
    let SecretOrigin::File { source_path } = &record.origin else { unreachable!() };
    let snapshot = catalog.snapshot()?;
    let project = snapshot
        .projects
        .iter()
        .find(|project| project.id == project_id)
        .ok_or_else(|| DispatchError::Validation(format!("project {project_id:?} was not found")))?;
    if !source_path.starts_with(&project.path) {
        return Err(DispatchError::Validation(format!(
            "{} is outside project {}",
            source_path.display(),
            project.path.display()
        )));
    }
    if snapshot.resources.iter().any(|resource| {
        matches!(
            &resource.source,
            ResourceSource::SecretRef { secret_id: existing } if existing == id
        )
    }) {
        return Err(DispatchError::Validation(format!(
            "{} is already configured",
            source_path.display()
        )));
    }
    let expected = mount_path
        .join(accessfs_core::config::SECRETS_DIR)
        .join(secret_id.to_string());
    let actual = std::fs::read_link(source_path).map_err(|source| DispatchError::Io {
        path: source_path.clone(),
        source,
    })?;
    if actual != expected {
        return Err(DispatchError::Validation(format!(
            "{} no longer points to its managed file",
            source_path.display()
        )));
    }

    let (codec, format) = configurable_file_format(source_path)?;
    let plaintext = store.get(&secret_id)?;
    let decoded = decode_source(codec, id, &plaintext)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    if decoded.is_empty() {
        return Err(DispatchError::Validation(format!(
            "{} has no configurable entries",
            source_path.display()
        )));
    }

    let existing_environment = match environment_id {
        Some(id) => {
            let environment = snapshot
                .environments
                .iter()
                .find(|environment| environment.id == id)
                .ok_or_else(|| {
                    DispatchError::Validation(format!("environment {id:?} was not found"))
                })?;
            if environment.project_id != project_id {
                return Err(DispatchError::Validation(format!(
                    "environment {id:?} does not belong to project {project_id:?}"
                )));
            }
            Some(environment)
        }
        None => project
            .default_environment_id
            .as_deref()
            .and_then(|id| {
                snapshot.environments.iter().find(|environment| environment.id == id)
            })
            .or_else(|| {
                snapshot
                    .environments
                    .iter()
                    .find(|environment| environment.project_id == project_id)
            }),
    };
    let (environment_id, created_environment) = match existing_environment {
        Some(environment) => (environment.id.clone(), false),
        None => ensure_discovered_environment(catalog, project_id, "development")?,
    };
    let environment_name = catalog
        .snapshot()?
        .environments
        .into_iter()
        .find(|environment| environment.id == environment_id)
        .map(|environment| environment.name)
        .unwrap_or_else(|| "Development".to_string());

    let resource_id = generated_id("env-file");
    let binding_id = generated_id("binding");
    let name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("Environment")
        .to_string();
    let resource = Resource {
        id: resource_id.clone(),
        name: name.clone(),
        kind: ResourceKind::EnvFile,
        shape: ValueShape::KeyValueSet,
        codec,
        default_env_key: None,
        entries: decoded
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
        source: ResourceSource::SecretRef { secret_id: secret_id.to_string() },
        enforcement: record.enforcement,
        metadata: record.metadata.clone(),
        origin: ResourceOrigin {
            kind: OriginKind::Discovered,
            sources: vec![OriginSource {
                path: source_path.clone(),
                project_id: Some(project_id.to_string()),
                environment: Some(environment_name),
                imported_at: now_rfc3339(),
            }],
        },
    };
    let binding = Binding {
        id: binding_id.clone(),
        project_id: project_id.to_string(),
        scope: BindingScope::Environment { environment_id: environment_id.clone() },
        resource_id: resource_id.clone(),
        selection: EntrySelection::All,
        key_override: None,
        enabled: true,
        allow_override: false,
        position: 0,
    };
    let surface = Surface {
        id: generated_id("surface"),
        environment_id,
        name,
        kind: SurfaceKind::File(FileBacking::Composed(format)),
        path: source_path.clone(),
        input: SurfaceInput::Bindings { binding_ids: vec![binding_id.clone()] },
        enforcement: record.enforcement,
        position: 0,
    };

    catalog.create_resource(&resource)?;
    if let Err(error) = catalog.upsert_binding(&binding) {
        let _ = catalog.remove_resource(&resource_id);
        if created_environment {
            let _ = catalog.remove_environment(&surface.environment_id);
        }
        return Err(DispatchError::Catalog(error));
    }
    if let Err(error) = replace_discovered_file_with_surface(catalog, mount_path, &surface) {
        let _ = catalog.remove_binding(&binding_id);
        let _ = catalog.remove_resource(&resource_id);
        if created_environment {
            let _ = catalog.remove_environment(&surface.environment_id);
        }
        return Err(error);
    }

    Ok(ControlResult::ManagedFileConfigured { surface })
}

pub(super) fn restore_managed_file(
    catalog: &Catalog,
    store: &Arc<dyn SecretStore>,
    mount_path: &Path,
    surface_id: &str,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let surface = snapshot
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .cloned()
        .ok_or_else(|| DispatchError::Validation(format!("managed file {surface_id:?} was not found")))?;
    if !surface.kind.is_file() {
        return Err(DispatchError::Validation(format!(
            "{} is not a managed file",
            surface.path.display()
        )));
    }

    let mut origins = Vec::new();
    for resource in snapshot.resources.iter().filter(|resource| {
        resource.origin.kind == OriginKind::Discovered
            && resource.origin.sources.len() == 1
            && resource.origin.sources[0].path == surface.path
    }) {
        let ResourceSource::SecretRef { secret_id } = &resource.source else { continue };
        let parsed: SecretId = secret_id.parse()?;
        let Some(record) = store.record(&parsed)? else { continue };
        if matches!(&record.origin, SecretOrigin::File { source_path } if source_path == &surface.path)
        {
            origins.push((resource, parsed, record));
        }
    }
    if origins.len() > 1 {
        return Err(DispatchError::Validation(format!(
            "{} has {} discovered backing resources; expected at most one",
            surface.path.display(),
            origins.len()
        )));
    }
    let cleanup = if let Some((resource, secret_id, record)) = origins.pop() {
        let binding_ids = surface.input.binding_ids().unwrap_or_default();
        let origin_bindings = snapshot
            .bindings
            .iter()
            .filter(|binding| binding.resource_id == resource.id)
            .collect::<Vec<_>>();
        let included_origin_bindings = origin_bindings
            .iter()
            .copied()
            .filter(|binding| binding_ids.contains(&binding.id))
            .collect::<Vec<_>>();
        let binding = match (included_origin_bindings.as_slice(), origin_bindings.as_slice()) {
            ([binding], _) | ([], [binding]) => *binding,
            ([], []) => {
                return Err(DispatchError::Validation(format!(
                    "{} no longer has a binding to its discovered backing resource",
                    surface.path.display()
                )));
            }
            _ => {
                return Err(DispatchError::Validation(format!(
                    "{} has ambiguous bindings to its discovered backing resource",
                    surface.path.display()
                )));
            }
        };
        Some((resource, binding, secret_id, record))
    } else {
        None
    };
    let resolver = SurfaceResolver::new(catalog.clone(), Arc::clone(store));
    let plaintext = zeroize::Zeroizing::new(match surface.kind {
        SurfaceKind::File(FileBacking::Composed(_)) => resolver
            .render_surface(surface_id)
            .map_err(|error| DispatchError::Validation(error.to_string()))?
            .bytes,
        SurfaceKind::File(FileBacking::EnvFileDirect) => resolver
            .read_direct_env_file(surface_id)
            .map_err(|error| DispatchError::Validation(error.to_string()))?
            .bytes,
        SurfaceKind::UnixSocket => unreachable!("file surface checked above"),
    });
    let mode = cleanup.as_ref().map_or(0o600, |(_, _, _, record)| record.mode);
    let restored_paths =
        restore_configured_file_links(&snapshot, &surface, mount_path, &plaintext, mode)?;

    let resource_removed = match cleanup.as_ref() {
        Some((resource, binding, _, _)) => {
            match catalog.remove_managed_file_configuration(
                surface_id,
                &binding.id,
                &resource.id,
            ) {
                Ok(removal) => removal.resource_removed,
                Err(error) => {
                    rollback_configured_file_links(
                        &restored_paths,
                        mount_path,
                        surface_id,
                        &plaintext,
                    );
                    return Err(DispatchError::Catalog(error));
                }
            }
        }
        None => {
            if let Err(error) = catalog.remove_surface(surface_id) {
                rollback_configured_file_links(
                    &restored_paths,
                    mount_path,
                    surface_id,
                    &plaintext,
                );
                return Err(DispatchError::Catalog(error));
            }
            false
        }
    };

    let storage_deleted = if resource_removed {
        let secret_id = &cleanup
            .as_ref()
            .expect("removed resource has a discovered backing")
            .2;
        match store.delete(secret_id) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    id = %secret_id,
                    %error,
                    "restored configured plaintext but could not delete encrypted history"
                );
                false
            }
        }
    } else {
        false
    };
    Ok(ControlResult::FileRestored {
        path: surface.path,
        storage_deleted,
    })
}

fn restore_configured_file_links(
    snapshot: &CatalogSnapshot,
    surface: &Surface,
    mount_path: &Path,
    plaintext: &[u8],
    mode: u32,
) -> Result<Vec<PathBuf>, DispatchError> {
    let target = mount_path
        .join(accessfs_core::config::SURFACES_DIR)
        .join(&surface.id);
    let instances = file_surface_instances(snapshot)
        .map_err(|error| DispatchError::Validation(error.to_string()))?
        .into_iter()
        .filter(|instance| instance.id == surface.id)
        .collect::<Vec<_>>();
    let mut restored = Vec::new();
    for instance in instances {
        match replace_symlink_with_file_if_target(&instance.path, &target, plaintext, mode) {
            Ok(true) => restored.push(instance.path),
            Ok(false) if instance.path == surface.path => {
                rollback_configured_file_links(
                    &restored,
                    mount_path,
                    &surface.id,
                    plaintext,
                );
                return Err(DispatchError::Validation(format!(
                    "{} no longer points to its configured managed file",
                    surface.path.display()
                )));
            }
            Ok(false) => {}
            Err(source) => {
                rollback_configured_file_links(
                    &restored,
                    mount_path,
                    &surface.id,
                    plaintext,
                );
                return Err(DispatchError::Io {
                    path: instance.path,
                    source,
                });
            }
        }
    }
    Ok(restored)
}

fn rollback_configured_file_links(
    restored_paths: &[PathBuf],
    mount_path: &Path,
    surface_id: &str,
    plaintext: &[u8],
) {
    let target = mount_path
        .join(accessfs_core::config::SURFACES_DIR)
        .join(surface_id);
    for path in restored_paths.iter().rev() {
        match replace_regular_file_with_symlink_if_matches(path, &target, plaintext) {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                path = %path.display(),
                "configured file changed before rollback; preserving its plaintext"
            ),
            Err(error) => tracing::warn!(
                path = %path.display(),
                %error,
                "rolling back configured file restore failed"
            ),
        }
    }
}

fn configurable_file_format(
    path: &Path,
) -> Result<(ResourceCodec, SurfaceFormat), DispatchError> {
    let name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default();
    if name == ".envrc" {
        return Ok((ResourceCodec::Dotenv, SurfaceFormat::Direnv));
    }
    if name == "credentials"
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|parent| parent == ".aws")
    {
        return Ok((ResourceCodec::Ini, SurfaceFormat::Ini));
    }
    if name == ".env"
        || name.starts_with(".env.")
        || name == ".dev.vars"
        || name.starts_with(".dev.vars.")
    {
        return Ok((ResourceCodec::Dotenv, SurfaceFormat::Dotenv));
    }
    Err(DispatchError::Validation(format!(
        "{} is managed unchanged and has no configurable format",
        path.display()
    )))
}

pub(super) fn protected_file(
    record: SecretRecord,
    mount_path: &Path,
    snapshot: &CatalogSnapshot,
) -> Option<ProtectedFile> {
    let SecretOrigin::File { source_path } = record.origin else { return None };
    let expected = mount_path
        .join(accessfs_core::config::SECRETS_DIR)
        .join(record.id.to_string());
    let linked = ManagedSymlink::new(&source_path, expected)
        .is_ready()
        .unwrap_or(false);
    let environment_ids = effective_file_environment_ids(
        snapshot,
        &source_path,
        record.environment_ids.as_deref(),
    );
    Some(ProtectedFile {
        id: record.id.to_string(),
        source_path,
        mode: record.mode,
        size: record.size,
        current_version: record.current_version,
        linked,
        enforcement: record.enforcement,
        environment_ids,
        metadata: record.metadata,
    })
}

fn effective_file_environment_ids(
    snapshot: &CatalogSnapshot,
    source_path: &Path,
    configured: Option<&[String]>,
) -> Vec<String> {
    let Some(project) = snapshot
        .projects
        .iter()
        .filter(|project| source_path.starts_with(&project.path))
        .max_by_key(|project| project.path.components().count())
    else {
        return Vec::new();
    };
    let configured =
        configured.map(|ids| ids.iter().map(String::as_str).collect::<HashSet<_>>());
    let mut environments = snapshot
        .environments
        .iter()
        .filter(|environment| environment.project_id == project.id)
        .filter(|environment| {
            configured
                .as_ref()
                .is_none_or(|ids| ids.contains(environment.id.as_str()))
        })
        .collect::<Vec<_>>();
    environments.sort_by_key(|environment| environment.position);
    environments.into_iter().map(|environment| environment.id.clone()).collect()
}

pub(super) fn protect_file(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    path: &Path,
) -> Result<ControlResult, DispatchError> {
    if !path.is_absolute() {
        return Err(DispatchError::Validation(format!(
            "protected file path {} must be absolute",
            path.display()
        )));
    }

    let path = canonical_source_path(path).map_err(|source| DispatchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|source| DispatchError::Io {
        path: path.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        let snapshot = catalog.snapshot()?;
        let record = store.get_by_path(&path)?.ok_or_else(|| {
            DispatchError::Validation(format!(
                "{} is a symlink not managed by Floria",
                path.display()
            ))
        })?;
        let expected = mount_path
            .join(accessfs_core::config::SECRETS_DIR)
            .join(record.id.to_string());
        let actual = std::fs::read_link(&path).map_err(|source| DispatchError::Io {
            path: path.clone(),
            source,
        })?;
        if actual != expected {
            return Err(DispatchError::Validation(format!(
                "{} points to {}, not the managed target {}",
                path.display(),
                actual.display(),
                expected.display()
            )));
        }
        return Ok(ControlResult::FileProtected {
            file: protected_file(record, mount_path, &snapshot)
                .expect("file lookup returns a file-origin record"),
            created: false,
        });
    }
    if !metadata.is_file() {
        return Err(DispatchError::Validation(format!(
            "{} is not a regular file",
            path.display()
        )));
    }

    let absolute = std::fs::canonicalize(&path).map_err(|source| DispatchError::Io {
        path: path.clone(),
        source,
    })?;
    let plaintext = zeroize::Zeroizing::new(
        std::fs::read(&absolute).map_err(|source| DispatchError::Io {
            path: absolute.clone(),
            source,
        })?,
    );
    let mode = (metadata.mode() & 0o7777) as u32;
    let existing = store.get_by_path(&absolute)?;
    let (id, created) = match existing {
        Some(record) => {
            let current = store.get(&record.id)?;
            if current.as_slice() != plaintext.as_slice() {
                let snapshot = catalog.snapshot()?;
                validate_secret_bytes(&snapshot, record.id.as_str(), &plaintext)
                    .map_err(|error| DispatchError::Validation(error.to_string()))?;
                store.append_version(&record.id, &plaintext)?;
            }
            (record.id, false)
        }
        None => (store.put(NewSecret::file(absolute.clone(), mode), &plaintext)?, true),
    };

    let target = mount_path
        .join(accessfs_core::config::SECRETS_DIR)
        .join(id.to_string());
    if let Err(source) = replace_file_with_symlink(&absolute, &target) {
        if created {
            if let Err(cleanup_error) = store.delete(&id) {
                tracing::warn!(%id, %cleanup_error, "cleaning up failed file protection failed");
            }
        }
        return Err(DispatchError::Io { path: absolute, source });
    }
    let record = store
        .record(&id)?
        .ok_or_else(|| DispatchError::Validation(format!("protected file {id} disappeared")))?;
    let snapshot = catalog.snapshot()?;
    Ok(ControlResult::FileProtected {
        file: protected_file(record, mount_path, &snapshot)
            .expect("new file protection has file-origin metadata"),
        created,
    })
}

pub(super) fn protected_file_history(
    store: &dyn SecretStore,
    id: &str,
) -> Result<ControlResult, DispatchError> {
    let (id, record) = file_record(store, id)?;
    let versions = store
        .history(&id)?
        .into_iter()
        .map(|version| ProtectedFileVersion {
            version: version.version,
            size: version.size,
            created: version.created,
            note: version.note,
            current: version.version == record.current_version,
        })
        .collect();
    Ok(ControlResult::ProtectedFileHistory { id: id.to_string(), versions })
}

pub(super) fn update_protected_file_metadata(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    id: &str,
    enforcement: Enforcement,
    environment_ids: Vec<String>,
    metadata: ItemMetadata,
) -> Result<ControlResult, DispatchError> {
    let (id, record) = file_record(store, id)?;
    let source_path = record.source_path().expect("validated file record");
    let snapshot = catalog.snapshot()?;
    let project = snapshot
        .projects
        .iter()
        .filter(|project| source_path.starts_with(&project.path))
        .max_by_key(|project| project.path.components().count());
    let environment_ids = match project {
        None if environment_ids.is_empty() => None,
        None => {
            return Err(DispatchError::Validation(format!(
                "{} is not inside a project and cannot have an Environment Scope",
                source_path.display()
            )));
        }
        Some(project) => {
            let mut available = snapshot
                .environments
                .iter()
                .filter(|environment| environment.project_id == project.id)
                .collect::<Vec<_>>();
            available.sort_by_key(|environment| environment.position);
            if !available.is_empty() && environment_ids.is_empty() {
                return Err(DispatchError::Validation(
                    "choose at least one Environment".to_string(),
                ));
            }
            let available_ids =
                available.iter().map(|environment| environment.id.as_str()).collect::<HashSet<_>>();
            if let Some(unknown) =
                environment_ids.iter().find(|id| !available_ids.contains(id.as_str()))
            {
                return Err(DispatchError::Validation(format!(
                    "environment {unknown:?} does not belong to project {:?}",
                    project.id
                )));
            }
            Some(
                available
                    .into_iter()
                    .filter(|environment| environment_ids.contains(&environment.id))
                    .map(|environment| environment.id.clone())
                    .collect(),
            )
        }
    };
    let current_links =
        protected_checkout_links(&snapshot, std::slice::from_ref(&record), mount_path);
    let mut updated_record = record.clone();
    updated_record.environment_ids = environment_ids.clone();
    let next_links =
        protected_checkout_links(&snapshot, std::slice::from_ref(&updated_record), mount_path);
    remove_excluded_protected_checkout_links(&current_links, &next_links).map_err(|source| {
        DispatchError::Io {
            path: source_path.to_path_buf(),
            source,
        }
    })?;
    store.update_settings(&id, metadata, enforcement, environment_ids)?;
    Ok(ControlResult::Empty)
}

pub(super) fn rollback_protected_file(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    id: &str,
    version: u32,
) -> Result<ControlResult, DispatchError> {
    let (id, _) = file_record(store, id)?;
    let plaintext = store.get_version(&id, version)?;
    let snapshot = catalog.snapshot()?;
    validate_secret_bytes(&snapshot, id.as_str(), &plaintext)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    store.set_head(&id, version)?;
    let record = store
        .record(&id)?
        .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
    Ok(ControlResult::ProtectedFileRolledBack {
        file: protected_file(record, mount_path, &snapshot)
            .expect("validated file record remains file-origin"),
    })
}

pub(super) fn update_protected_file_contents(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    id: &str,
    path: &Path,
) -> Result<ControlResult, DispatchError> {
    if !path.is_absolute() {
        return Err(DispatchError::Validation(format!(
            "replacement file path {} must be absolute",
            path.display()
        )));
    }

    let (id, record) = file_record(store, id)?;
    let metadata = std::fs::metadata(path).map_err(|source| DispatchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(DispatchError::Validation(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let absolute = std::fs::canonicalize(path).map_err(|source| DispatchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let plaintext = zeroize::Zeroizing::new(
        std::fs::read(&absolute).map_err(|source| DispatchError::Io {
            path: absolute.clone(),
            source,
        })?,
    );
    let snapshot = catalog.snapshot()?;
    validate_secret_bytes(&snapshot, id.as_str(), &plaintext)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    let current = store.get(&id)?;
    if current.as_slice() != plaintext.as_slice() {
        store.append_version(&id, &plaintext)?;
    }
    let record = if current.as_slice() == plaintext.as_slice() {
        record
    } else {
        store
            .record(&id)?
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?
    };
    Ok(ControlResult::ProtectedFileUpdated {
        file: protected_file(record, mount_path, &snapshot)
            .expect("validated file record remains file-origin"),
    })
}

pub(super) fn restore_file(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    id: &str,
) -> Result<ControlResult, DispatchError> {
    let (id, record) = file_record(store, id)?;
    let snapshot = catalog.snapshot()?;
    let references = snapshot
        .resources
        .iter()
        .filter_map(|resource| match &resource.source {
            ResourceSource::SecretRef { secret_id } if secret_id == id.as_str() => {
                Some(resource.name.as_str())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if !references.is_empty() {
        return Err(DispatchError::Validation(format!(
            "protected file {id} is still used by catalog resources: {}; remove those resources before restoring it",
            references.join(", ")
        )));
    }
    let SecretOrigin::File { source_path } = &record.origin else { unreachable!() };
    let expected = mount_path
        .join(accessfs_core::config::SECRETS_DIR)
        .join(id.to_string());
    let metadata = std::fs::symlink_metadata(source_path).map_err(|source| DispatchError::Io {
        path: source_path.clone(),
        source,
    })?;
    if !metadata.file_type().is_symlink() {
        return Err(DispatchError::Validation(format!(
            "{} is no longer a symlink; refusing to overwrite it",
            source_path.display()
        )));
    }
    let actual = std::fs::read_link(source_path).map_err(|source| DispatchError::Io {
        path: source_path.clone(),
        source,
    })?;
    if actual != expected {
        return Err(DispatchError::Validation(format!(
            "{} points to {}, not the managed target {}",
            source_path.display(),
            actual.display(),
            expected.display()
        )));
    }

    let plaintext = store.get(&id)?;
    restore_protected_checkout_links(&snapshot, &record, &plaintext, mount_path).map_err(
        |source| DispatchError::Io {
            path: source_path.clone(),
            source,
        },
    )?;
    let restored =
        replace_symlink_with_file_if_target(source_path, &expected, &plaintext, record.mode)
            .map_err(|source| DispatchError::Io {
                path: source_path.clone(),
                source,
            })?;
    if !restored {
        return Err(DispatchError::Validation(format!(
            "{} changed while it was being restored; no file was overwritten",
            source_path.display()
        )));
    }
    let storage_deleted = match store.delete(&id) {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(%id, %error, "restored plaintext but could not delete encrypted history");
            false
        }
    };
    Ok(ControlResult::FileRestored { path: source_path.clone(), storage_deleted })
}

pub(super) fn file_record(
    store: &dyn SecretStore,
    id: &str,
) -> Result<(SecretId, SecretRecord), DispatchError> {
    let id: SecretId = id.parse()?;
    let record = store
        .record(&id)?
        .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
    if !matches!(&record.origin, SecretOrigin::File { .. }) {
        return Err(DispatchError::Validation(format!(
            "secret {id} is not a protected file"
        )));
    }
    Ok((id, record))
}

pub(super) fn canonical_source_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "protected file path has no file name")
    })?;
    Ok(std::fs::canonicalize(parent)?.join(name))
}

pub(super) use accessfs_surface::replace_file_with_symlink;
