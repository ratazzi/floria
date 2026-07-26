use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_discovery(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    paths: &[PathBuf],
    selected_files: Option<&[PathBuf]>,
    project_assignments: &[crate::protocol::DiscoveryProjectAssignment],
    separate_entries: &[crate::protocol::DiscoveryEntryRef],
    promote_entries: &[crate::protocol::DiscoveryEntryRef],
    demote_entries: &[crate::protocol::DiscoveryEntryRef],
) -> Result<ControlResult, DispatchError> {
    let discovery = discover_many(paths)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    let candidate_keys = discovery.shared_secret_candidate_keys();
    let mut existing = existing_discovery_secrets(catalog, store, &candidate_keys)?;
    let plan = discovery.plan(&existing);
    let mut contents = discovery.into_contents();
    if let Some(selected_files) = selected_files {
        if selected_files.is_empty() {
            return Err(DispatchError::Validation(
                "select at least one discovered file to import".to_string(),
            ));
        }
        let mut selected = selected_files.iter().cloned().collect::<HashSet<_>>();
        contents.retain(|file| selected.remove(&file.path));
        if !selected.is_empty() {
            return Err(DispatchError::Validation(format!(
                "selected file was not part of the reviewed discovery: {}",
                selected
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    let valid_project_paths = plan
        .projects
        .iter()
        .map(|project| project.path.clone())
        .collect::<HashSet<_>>();
    let valid_file_paths =
        contents.iter().map(|file| file.path.clone()).collect::<HashSet<_>>();
    let mut explicit_assignments = HashMap::<PathBuf, PathBuf>::new();
    for assignment in project_assignments {
        if !valid_file_paths.contains(&assignment.path) {
            return Err(DispatchError::Validation(format!(
                "project assignment file was not part of the reviewed discovery: {}",
                assignment.path.display()
            )));
        }
        if !valid_project_paths.contains(&assignment.project_path) {
            return Err(DispatchError::Validation(format!(
                "project assignment target was not part of the reviewed discovery: {}",
                assignment.project_path.display()
            )));
        }
        if explicit_assignments
            .insert(assignment.path.clone(), assignment.project_path.clone())
            .is_some()
        {
            return Err(DispatchError::Validation(format!(
                "project assignment was provided more than once: {}",
                assignment.path.display()
            )));
        }
    }
    for file in &mut contents {
        if let Some(project_path) = explicit_assignments.get(&file.path) {
            file.assignment.project_path = Some(project_path.clone());
            file.assignment.state = accessfs_discover::ProjectAssignmentState::Assigned;
        }
        if file.action == DiscoveredFileAction::Compose
            && file.assignment.project_path.is_none()
        {
            return Err(DispatchError::Validation(format!(
                "choose a project for {} before importing it",
                file.path.display()
            )));
        }
    }
    let valid_override_entries = contents
        .iter()
        .filter(|file| {
            file.action == DiscoveredFileAction::Compose
                && matches!(
                    file.kind,
                    DiscoveredFileKind::Dotenv | DiscoveredFileKind::Direnv
                )
        })
        .flat_map(|file| {
            file.entries
                .iter()
                .map(|entry| (file.path.clone(), entry.address.clone()))
        })
        .collect::<HashSet<_>>();
    let as_entry_set = |entries: &[crate::protocol::DiscoveryEntryRef]| {
        entries
            .iter()
            .map(|entry| (entry.path.clone(), entry.address.clone()))
            .collect::<HashSet<_>>()
    };
    let separate_entries = as_entry_set(separate_entries);
    let promote_entries = as_entry_set(promote_entries);
    let demote_entries = as_entry_set(demote_entries);
    for (label, entries) in [
        ("separate-secret", &separate_entries),
        ("promote", &promote_entries),
        ("demote", &demote_entries),
    ] {
        if let Some((path, address)) =
            entries.iter().find(|entry| !valid_override_entries.contains(*entry))
        {
            return Err(DispatchError::Validation(format!(
                "{label} choice was not part of the reviewed discovery: {} ({address})",
                path.display()
            )));
        }
    }
    let required_project_paths = contents
        .iter()
        .filter(|file| file.action == DiscoveredFileAction::Compose)
        .filter_map(|file| file.assignment.project_path.clone())
        .collect::<HashSet<_>>();
    let mut project_states = HashMap::<PathBuf, (String, bool)>::new();
    for project_path in &required_project_paths {
        let project = plan
            .projects
            .iter()
            .find(|project| &project.path == project_path)
            .ok_or_else(|| {
                DispatchError::Validation(format!(
                    "assigned project was not part of discovery: {}",
                    project_path.display()
                ))
            })?;
        let state = ensure_discovered_project(catalog, project)?;
        project_states.insert(project_path.clone(), state);
    }
    let mut project_ids = project_states
        .values()
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    project_ids.sort();
    project_ids.dedup();
    let mut result = DiscoveryApplyResult {
        project_id: (project_ids.len() == 1).then(|| project_ids[0].clone()),
        project_ids,
        created_resources: 0,
        reused_resources: 0,
        protected_files: 0,
        imported_ssh_identities: 0,
        files: Vec::new(),
    };
    let mut composed_success = HashSet::<PathBuf>::new();

    for file in contents {
        if file.action == DiscoveredFileAction::Compose && !file.warnings.is_empty() {
            result.files.push(DiscoveryAppliedFile {
                path: file.path,
                outcome: DiscoveryApplyOutcome::Skipped,
                detail: "Skipped because the file contains unsupported or invalid content"
                    .to_string(),
            });
            continue;
        }

        let file_path = file.path.clone();
        let assigned_project_path = file.assignment.project_path.clone();
        let assigned_project_id = assigned_project_path
            .as_ref()
            .and_then(|path| project_states.get(path))
            .map(|(id, _)| id.clone());
        let existing_len = existing.len();
        let applied = (|| -> Result<bool, DispatchError> {
            match file.action {
                DiscoveredFileAction::Protect => {
                    let protected = protect_file(catalog, store, mount_path, &file.path)?;
                    if !matches!(protected, ControlResult::FileProtected { .. }) {
                        Err(DispatchError::Validation(
                            "protecting a discovered file returned an unexpected result".to_string(),
                        ))
                    } else {
                        result.protected_files += 1;
                        result.files.push(DiscoveryAppliedFile {
                            path: file.path,
                            outcome: DiscoveryApplyOutcome::Protected,
                            detail: "Protected as a read-only audited file".to_string(),
                        });
                        Ok(false)
                    }
                }
                DiscoveredFileAction::ImportSshIdentity => {
                    let resource_id = generated_id("ssh-identity");
                    let name = file
                        .path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("SSH identity")
                        .to_string();
                    import_ssh_identity(
                        catalog,
                        store,
                        resource_id,
                        name,
                        &file.path,
                        None,
                        ManagedItemSettings {
                            enforcement: Enforcement::Prompt,
                            metadata: ItemMetadata::default(),
                        },
                        ResourceOrigin {
                            kind: OriginKind::Discovered,
                            sources: vec![OriginSource {
                                path: file.path.clone(),
                                project_id: assigned_project_id.clone(),
                                environment: None,
                                imported_at: now_rfc3339(),
                            }],
                        },
                    )?;
                    result.imported_ssh_identities += 1;
                    result.files.push(DiscoveryAppliedFile {
                        path: file.path,
                        outcome: DiscoveryApplyOutcome::Imported,
                        detail: "Imported as a managed SSH identity".to_string(),
                    });
                    Ok(false)
                }
                DiscoveredFileAction::Compose => {
                    let Some(project_id) = assigned_project_id.as_deref() else {
                        return Err(DispatchError::Validation(
                            "discovery composition requires a project".to_string(),
                        ));
                    };
                    apply_composed_discovery(
                        catalog,
                        store,
                        mount_path,
                        project_id,
                        DiscoveryReuseState {
                            existing: &mut existing,
                            separate_entries: &separate_entries,
                            promote_entries: &promote_entries,
                            demote_entries: &demote_entries,
                        },
                        &mut result,
                        file,
                    )
                }
                DiscoveredFileAction::Review => {
                    result.files.push(DiscoveryAppliedFile {
                        path: file.path,
                        outcome: DiscoveryApplyOutcome::Skipped,
                        detail: "Detected for review; automatic import is not supported yet"
                            .to_string(),
                    });
                    Ok(false)
                }
                DiscoveredFileAction::Reference => {
                    result.files.push(DiscoveryAppliedFile {
                        path: file.path,
                        outcome: DiscoveryApplyOutcome::Skipped,
                        detail: "Reference configuration left unchanged".to_string(),
                    });
                    Ok(false)
                }
            }
        })();
        match applied {
            Ok(true) => {
                if let Some(project_path) = assigned_project_path {
                    composed_success.insert(project_path);
                }
            }
            Ok(false) => {}
            Err(error) => {
                existing.truncate(existing_len);
                result.files.push(DiscoveryAppliedFile {
                    path: file_path,
                    outcome: DiscoveryApplyOutcome::Failed,
                    detail: error.body().message,
                });
            }
        }
    }

    for (project_path, (project_id, created)) in &project_states {
        if *created && !composed_success.contains(project_path) {
            catalog.remove_project(project_id)?;
        }
    }
    result.project_ids = project_states
        .iter()
        .filter(|(path, _)| composed_success.contains(*path))
        .map(|(_, (id, _))| id.clone())
        .collect();
    result.project_ids.sort();
    result.project_ids.dedup();
    result.project_id =
        (result.project_ids.len() == 1).then(|| result.project_ids[0].clone());
    Ok(ControlResult::DiscoveryApplied(result))
}

struct DiscoveryReuseState<'a> {
    existing: &'a mut Vec<ExistingSecret>,
    separate_entries: &'a HashSet<(PathBuf, String)>,
    promote_entries: &'a HashSet<(PathBuf, String)>,
    demote_entries: &'a HashSet<(PathBuf, String)>,
}

fn apply_composed_discovery(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    project_id: &str,
    reuse: DiscoveryReuseState<'_>,
    result: &mut DiscoveryApplyResult,
    file: DiscoveredContent,
) -> Result<bool, DispatchError> {
    if file.entries.is_empty() {
        result.files.push(DiscoveryAppliedFile {
            path: file.path,
            outcome: DiscoveryApplyOutcome::Skipped,
            detail: "No statically importable values were found".to_string(),
        });
        return Ok(false);
    }

    let environment_name = file.environment.as_deref().unwrap_or("development");
    let mut binding_ids = Vec::new();
    let mut mutation = DiscoveryMutationGuard::new(catalog, store);
    let (environment_id, environment_created) =
        ensure_discovered_environment(catalog, project_id, environment_name)?;
    if environment_created {
        mutation.track_environment(environment_id.clone());
    }

    match file.kind {
        DiscoveredFileKind::Dotenv | DiscoveredFileKind::Direnv => {
            let source = discovered_source(&file, project_id, environment_name);
            let mut plain_entries: Vec<(usize, &accessfs_discover::DiscoveredValue)> = Vec::new();
            for (position, entry) in file.entries.iter().enumerate() {
                let entry_ref = (file.path.clone(), entry.address.clone());
                let import_as_secret = match classify_key(&entry.key) {
                    KeyClass::Secret => !reuse.demote_entries.contains(&entry_ref),
                    KeyClass::Plain => reuse.promote_entries.contains(&entry_ref),
                };
                if !import_as_secret {
                    plain_entries.push((position, entry));
                    continue;
                }
                let force_separate = reuse.separate_entries.contains(&entry_ref);
                let reusable = (!force_separate).then(|| {
                    reuse.existing.iter().find(|candidate| {
                        candidate.key == entry.key
                            && candidate.value.as_slice() == entry.value.as_bytes()
                    })
                });
                let resource_id = if let Some(candidate) = reusable.flatten() {
                    result.reused_resources += 1;
                    let resource_id = candidate.resource_id.clone();
                    catalog.append_resource_origin(&resource_id, &source)?;
                    resource_id
                } else {
                    let resource_id = generated_id("secret");
                    create_shared_secret(
                        catalog,
                        store,
                        resource_id.clone(),
                        entry.key.clone(),
                        Some(entry.key.clone()),
                        SecretValue::new(entry.value.as_str().to_string()),
                        ManagedItemSettings {
                            enforcement: Enforcement::Prompt,
                            metadata: ItemMetadata::default(),
                        },
                        ResourceOrigin {
                            kind: OriginKind::Discovered,
                            sources: vec![source.clone()],
                        },
                    )?;
                    mutation.track_resource(resource_id.clone());
                    if !force_separate {
                        reuse.existing.push(ExistingSecret {
                            resource_id: resource_id.clone(),
                            name: entry.key.clone(),
                            key: entry.key.clone(),
                            value: zeroize::Zeroizing::new(entry.value.as_bytes().to_vec()),
                        });
                    }
                    result.created_resources += 1;
                    resource_id
                };
                let binding_id = generated_id("binding");
                catalog.upsert_binding(&Binding {
                    id: binding_id.clone(),
                    project_id: project_id.to_string(),
                    scope: BindingScope::Environment {
                        environment_id: environment_id.clone(),
                    },
                    resource_id,
                    selection: EntrySelection::All,
                    key_override: None,
                    enabled: true,
                    allow_override: false,
                    position: position as i64,
                })?;
                mutation.track_binding(binding_id.clone());
                binding_ids.push(binding_id);
            }
            if !plain_entries.is_empty() {
                let values = plain_entries
                    .iter()
                    .map(|(_, entry)| (entry.key.clone(), entry.value.as_str().to_string()))
                    .collect::<Vec<_>>();
                let rendered = accessfs_surface::render_dotenv(&values)
                    .map_err(|error| DispatchError::Validation(error.to_string()))?;
                let content = String::from_utf8(rendered).map_err(|_| {
                    DispatchError::Validation(format!(
                        "{} produced non-UTF-8 env values",
                        file.path.display()
                    ))
                })?;
                let resource_id = generated_id("env-file");
                create_env_file(
                    catalog,
                    store,
                    resource_id.clone(),
                    file.relative_path.display().to_string(),
                    ResourceCodec::Dotenv,
                    SecretValue::new(content),
                    ManagedItemSettings {
                        enforcement: Enforcement::Allow,
                        metadata: ItemMetadata::default(),
                    },
                    ResourceOrigin {
                        kind: OriginKind::Discovered,
                        sources: vec![source.clone()],
                    },
                )?;
                mutation.track_resource(resource_id.clone());
                result.created_resources += 1;
                let binding_id = generated_id("binding");
                catalog.upsert_binding(&Binding {
                    id: binding_id.clone(),
                    project_id: project_id.to_string(),
                    scope: BindingScope::Environment {
                        environment_id: environment_id.clone(),
                    },
                    resource_id,
                    selection: EntrySelection::All,
                    key_override: None,
                    enabled: true,
                    allow_override: false,
                    position: plain_entries[0].0 as i64,
                })?;
                mutation.track_binding(binding_id.clone());
                binding_ids.push(binding_id);
            }
        }
        DiscoveredFileKind::AwsCredentials => {
            let bytes = zeroize::Zeroizing::new(std::fs::read(&file.path).map_err(|source| {
                DispatchError::Io { path: file.path.clone(), source }
            })?);
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                DispatchError::Validation(format!(
                    "{} is not valid UTF-8",
                    file.path.display()
                ))
            })?;
            let resource_id = generated_id("env-file");
            create_env_file(
                catalog,
                store,
                resource_id.clone(),
                file.path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("AWS credentials")
                    .to_string(),
                ResourceCodec::Ini,
                SecretValue::new(text.to_string()),
                ManagedItemSettings {
                    enforcement: Enforcement::Prompt,
                    metadata: ItemMetadata::default(),
                },
                ResourceOrigin {
                    kind: OriginKind::Discovered,
                    sources: vec![discovered_source(&file, project_id, environment_name)],
                },
            )?;
            mutation.track_resource(resource_id.clone());
            result.created_resources += 1;
            let binding_id = generated_id("binding");
            catalog.upsert_binding(&Binding {
                id: binding_id.clone(),
                project_id: project_id.to_string(),
                scope: BindingScope::Environment {
                    environment_id: environment_id.clone(),
                },
                resource_id,
                selection: EntrySelection::All,
                key_override: None,
                enabled: true,
                allow_override: false,
                position: 0,
            })?;
            mutation.track_binding(binding_id.clone());
            binding_ids.push(binding_id);
        }
        _ => {
            result.files.push(DiscoveryAppliedFile {
                path: file.path,
                outcome: DiscoveryApplyOutcome::Skipped,
                detail: "This discovered format is not composable yet".to_string(),
            });
            return Ok(false);
        }
    }

    let surface_kind = match file.kind {
        DiscoveredFileKind::Dotenv => SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
        DiscoveredFileKind::Direnv => SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv)),
        DiscoveredFileKind::AwsCredentials => SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
        _ => unreachable!("non-composable kinds returned above"),
    };
    let surface = Surface {
        id: generated_id("surface"),
        environment_id,
        name: file
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("environment")
            .to_string(),
        kind: surface_kind,
        path: file.path.clone(),
        input: SurfaceInput::Bindings { binding_ids },
        enforcement: Enforcement::Prompt,
        position: 0,
    };
    replace_discovered_file_with_surface(catalog, mount_path, &surface)?;
    mutation.commit();
    result.files.push(DiscoveryAppliedFile {
        path: file.path,
        outcome: DiscoveryApplyOutcome::Imported,
        detail: match file.kind {
            DiscoveredFileKind::AwsCredentials => {
                "Imported as a section-aware INI environment file".to_string()
            }
            _ => "Imported as reusable secrets and a composed output".to_string(),
        },
    });
    Ok(true)
}

pub(super) struct DiscoveryMutationGuard<'a> {
    catalog: &'a Catalog,
    store: &'a dyn SecretStore,
    created_resources: Vec<String>,
    created_bindings: Vec<String>,
    created_environments: Vec<String>,
    committed: bool,
}

impl<'a> DiscoveryMutationGuard<'a> {
    pub(super) fn new(catalog: &'a Catalog, store: &'a dyn SecretStore) -> Self {
        DiscoveryMutationGuard {
            catalog,
            store,
            created_resources: Vec::new(),
            created_bindings: Vec::new(),
            created_environments: Vec::new(),
            committed: false,
        }
    }

    pub(super) fn track_resource(&mut self, resource_id: String) {
        self.created_resources.push(resource_id);
    }

    pub(super) fn track_binding(&mut self, binding_id: String) {
        self.created_bindings.push(binding_id);
    }

    fn track_environment(&mut self, environment_id: String) {
        self.created_environments.push(environment_id);
    }

    pub(super) fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for DiscoveryMutationGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for binding_id in self.created_bindings.iter().rev() {
            if let Err(error) = self.catalog.remove_binding(binding_id) {
                tracing::warn!(%binding_id, %error, "discovery rollback could not remove binding");
            }
        }
        for environment_id in self.created_environments.iter().rev() {
            if let Err(error) = self.catalog.remove_environment(environment_id) {
                tracing::warn!(
                    %environment_id,
                    %error,
                    "discovery rollback could not remove environment"
                );
            }
        }
        for resource_id in self.created_resources.iter().rev() {
            let secret_id = self
                .catalog
                .resource(resource_id)
                .ok()
                .and_then(|resource| match resource.source {
                    ResourceSource::SecretRef { secret_id } => secret_id.parse::<SecretId>().ok(),
                    ResourceSource::Literal { .. }
                    | ResourceSource::Command { .. }
                    | ResourceSource::Socket => None,
                });
            if let Err(error) = self.catalog.remove_resource(resource_id) {
                tracing::warn!(%resource_id, %error, "discovery rollback could not remove resource");
                continue;
            }
            if let Some(secret_id) = secret_id {
                if let Err(error) = self.store.delete(&secret_id) {
                    tracing::warn!(
                        %resource_id,
                        %error,
                        "discovery rollback could not remove stored secret"
                    );
                }
            }
        }
    }
}

pub(super) fn ensure_discovered_project(
    catalog: &Catalog,
    project: &accessfs_discover::DiscoveredProject,
) -> Result<(String, bool), DispatchError> {
    if let Some(existing) = catalog
        .snapshot()?
        .projects
        .into_iter()
        .find(|candidate| candidate.path == project.path)
    {
        return Ok((existing.id, false));
    }
    let id = generated_id("project");
    catalog.upsert_project(&Project {
        id: id.clone(),
        name: project.name.clone(),
        path: project.path.clone(),
    })?;
    Ok((id, true))
}

pub(super) fn ensure_discovered_environment(
    catalog: &Catalog,
    project_id: &str,
    name: &str,
) -> Result<(String, bool), DispatchError> {
    let snapshot = catalog.snapshot()?;
    if let Some(existing) = snapshot.environments.iter().find(|candidate| {
        candidate.project_id == project_id && candidate.name.eq_ignore_ascii_case(name)
    }) {
        return Ok((existing.id.clone(), false));
    }
    let id = generated_id("environment");
    let display_name = name
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ");
    catalog.upsert_environment(&Environment {
        id: id.clone(),
        project_id: project_id.to_string(),
        name: display_name,
        position: snapshot.environments.len() as i64,
    })?;
    Ok((id, true))
}

pub(super) fn replace_discovered_file_with_surface(
    catalog: &Catalog,
    mount_path: &Path,
    surface: &Surface,
) -> Result<(), DispatchError> {
    let file_name = surface
        .path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("environment");
    let backup = surface.path.with_file_name(format!(
        ".{file_name}.floria-import-{}",
        SecretId::generate()
    ));
    std::fs::rename(&surface.path, &backup).map_err(|source| DispatchError::Io {
        path: surface.path.clone(),
        source,
    })?;
    if let Err(error) = catalog.upsert_surface(surface) {
        let _ = std::fs::rename(&backup, &surface.path);
        return Err(DispatchError::Catalog(error));
    }
    if let Err(error) = ensure_file_surface_link(surface, mount_path) {
        let _ = catalog.remove_surface(&surface.id);
        let _ = std::fs::rename(&backup, &surface.path);
        return Err(DispatchError::Validation(error.to_string()));
    }
    if let Err(source) = std::fs::remove_file(&backup) {
        let _ = std::fs::remove_file(&surface.path);
        let _ = catalog.remove_surface(&surface.id);
        let _ = std::fs::rename(&backup, &surface.path);
        return Err(DispatchError::Io { path: backup, source });
    }
    Ok(())
}

pub(super) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub(super) fn discovered_source(
    file: &DiscoveredContent,
    project_id: &str,
    environment: &str,
) -> OriginSource {
    OriginSource {
        path: file.path.clone(),
        project_id: Some(project_id.to_string()),
        environment: Some(environment.to_string()),
        imported_at: now_rfc3339(),
    }
}

pub(super) fn generated_id(prefix: &str) -> String {
    format!("{prefix}-{}", SecretId::generate())
}

pub(super) fn existing_discovery_projects(
    catalog: &Catalog,
    discovered: &[accessfs_discover::DiscoveredProject],
) -> Result<Vec<ExistingProject>, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let mut existing = Vec::new();
    for discovered_project in discovered {
        let Some(project) = snapshot
            .projects
            .iter()
            .find(|project| project.path == discovered_project.path)
        else {
            continue;
        };
        let environments = snapshot
            .environments
            .iter()
            .filter(|environment| environment.project_id == project.id)
            .map(|environment| {
                let surfaces = snapshot
                    .surfaces
                    .iter()
                    .filter(|surface| {
                        surface.environment_id == environment.id
                            && matches!(
                                surface.kind.composed_format(),
                                Some(SurfaceFormat::Dotenv | SurfaceFormat::Direnv)
                            )
                    })
                    .map(|surface| {
                        Ok(ExistingSurface {
                            id: surface.id.clone(),
                            path: surface.path.clone(),
                            keys: resolve_catalog_surface(&snapshot, &surface.id)?
                                .into_iter()
                                .map(|export| export.key)
                                .collect(),
                        })
                    })
                    .collect::<Result<Vec<_>, CatalogError>>()?;
                Ok(ExistingEnvironment {
                    name: environment.name.clone(),
                    surfaces,
                })
            })
            .collect::<Result<Vec<_>, CatalogError>>()?;
        existing.push(ExistingProject {
            id: project.id.clone(),
            path: project.path.clone(),
            environments,
        });
    }
    Ok(existing)
}

pub(super) fn existing_discovery_secrets(
    catalog: &Catalog,
    store: &dyn SecretStore,
    candidate_keys: &HashSet<String>,
) -> Result<Vec<ExistingSecret>, DispatchError> {
    if candidate_keys.is_empty() {
        return Ok(Vec::new());
    }
    let snapshot = catalog.snapshot()?;
    let mut existing = Vec::new();
    for resource in snapshot.resources {
        if resource.kind != ResourceKind::SharedSecret || resource.shape != ValueShape::Scalar {
            continue;
        }
        let Some(key) = resource.default_env_key else { continue };
        if !candidate_keys.contains(&key) {
            continue;
        }
        let ResourceSource::SecretRef { secret_id } = resource.source else { continue };
        let id = match secret_id.parse::<SecretId>() {
            Ok(id) => id,
            Err(error) => {
                tracing::warn!(
                    resource_id = %resource.id,
                    %error,
                    "ignoring invalid shared-secret reference during discovery"
                );
                continue;
            }
        };
        let value = match store.get(&id) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(
                    resource_id = %resource.id,
                    %error,
                    "shared secret was unavailable for discovery matching"
                );
                continue;
            }
        };
        existing.push(ExistingSecret {
            resource_id: resource.id,
            name: resource.name,
            key,
            value,
        });
    }
    Ok(existing)
}
