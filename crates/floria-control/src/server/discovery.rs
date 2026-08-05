use super::*;
use super::security_defaults::SecurityDefaults;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_discovery(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    paths: &[PathBuf],
    reviewed_imports: Option<&[DiscoveryImport]>,
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
    let imports = resolve_discovery_imports(&contents, reviewed_imports)?;
    let valid_project_paths = plan
        .projects
        .iter()
        .map(|project| project.path.clone())
        .collect::<HashSet<_>>();
    let valid_file_paths =
        contents.iter().map(|file| file.path.clone()).collect::<HashSet<_>>();
    let mut imports_by_path = HashMap::<PathBuf, DiscoveryImport>::new();
    for import in imports {
        if !valid_file_paths.contains(&import.path) {
            return Err(DispatchError::Validation(format!(
                "import file was not part of the reviewed discovery: {}",
                import.path.display()
            )));
        }
        let file = contents
            .iter()
            .find(|file| file.path == import.path)
            .expect("validated discovered file");
        validate_discovery_import(file, &import, &valid_project_paths)?;
        if imports_by_path.insert(import.path.clone(), import).is_some() {
            return Err(DispatchError::Validation(format!(
                "import destination was provided more than once: {}",
                file.path.display()
            )));
        }
    }
    contents.retain(|file| imports_by_path.contains_key(&file.path));
    let valid_override_entries = contents
        .iter()
        .filter(|file| {
            file.action == DiscoveredFileAction::Compose
                && imports_by_path.get(&file.path).is_some_and(|import| {
                    matches!(
                        &import.destination,
                        DiscoveryImportDestination::ProjectOutput { .. }
                            | DiscoveryImportDestination::ProjectOutputs { .. }
                    )
                })
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
    let required_project_paths = imports_by_path
        .values()
        .flat_map(|import| import_project_paths(&import.destination))
        .cloned()
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
        let import = imports_by_path
            .remove(&file.path)
            .expect("selected discovery import");
        let configures_output = matches!(
            &import.destination,
            DiscoveryImportDestination::ProjectOutput { .. }
                | DiscoveryImportDestination::ProjectOutputs { .. }
        );
        if file.action == DiscoveredFileAction::Compose
            && configures_output
            && !file.warnings.is_empty()
        {
            result.files.push(DiscoveryAppliedFile {
                path: file.path,
                outcome: DiscoveryApplyOutcome::Skipped,
                detail: "Skipped because the file contains unsupported or invalid content"
                    .to_string(),
            });
            continue;
        }

        let file_path = file.path.clone();
        let existing_len = existing.len();
        let applied = (|| -> Result<Vec<PathBuf>, DispatchError> {
            match file.action {
                DiscoveredFileAction::Protect => {
                    let protected =
                        protect_discovered_file(catalog, store, mount_path, &file)?;
                    if !matches!(protected, ControlResult::FileProtected { .. }) {
                        Err(DispatchError::Validation(
                            "protecting a discovered file returned an unexpected result".to_string(),
                        ))
                    } else {
                        if let DiscoveryImportDestination::ProjectFile { project_path } =
                            &import.destination
                        {
                            let project_id = &project_states[project_path].0;
                            apply_protected_file_environment_scope(
                                catalog,
                                store,
                                &protected,
                                project_id,
                                file.environment.as_deref(),
                            )?;
                        }
                        result.protected_files += 1;
                        result.files.push(DiscoveryAppliedFile {
                            path: file.path,
                            outcome: DiscoveryApplyOutcome::Protected,
                            detail: "Managed unchanged at its original path".to_string(),
                        });
                        Ok(import_project_paths(&import.destination)
                            .into_iter()
                            .cloned()
                            .collect())
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
                    let imported = import_ssh_identity(
                        catalog,
                        store,
                        resource_id,
                        name,
                        &file.path,
                        None,
                        ManagedItemSettings {
                            enforcement: SecurityDefaults::discovered_resource(file.kind),
                            metadata: ItemMetadata::default(),
                        },
                        ResourceOrigin {
                            kind: OriginKind::Discovered,
                            sources: vec![OriginSource {
                                path: file.path.clone(),
                                project_id: None,
                                environment: None,
                                imported_at: now_rfc3339(),
                            }],
                        },
                    );
                    match imported {
                        Ok(_) => {
                            result.imported_ssh_identities += 1;
                            if import.source_disposition
                                == DiscoverySourceDisposition::ProtectInPlace
                            {
                                protect_discovered_file(catalog, store, mount_path, &file)?;
                                result.protected_files += 1;
                            }
                            result.files.push(DiscoveryAppliedFile {
                                path: file.path,
                                outcome: DiscoveryApplyOutcome::Imported,
                                detail: "Imported as a managed SSH identity".to_string(),
                            });
                        }
                        // The private-key heuristic can misread other PEM credentials (JWT/TLS
                        // keys) as SSH keys; protect those as opaque files instead of failing
                        // the file. An encrypted SSH key stays an error: it is importable once
                        // the user supplies its passphrase.
                        Err(DispatchError::SshKey(error))
                            if !matches!(
                                error,
                                ManagedKeyError::PassphraseRequired
                                    | ManagedKeyError::DecryptionFailed
                            ) =>
                        {
                            protect_discovered_file(catalog, store, mount_path, &file)?;
                            result.protected_files += 1;
                            result.files.push(DiscoveryAppliedFile {
                                path: file.path,
                                outcome: DiscoveryApplyOutcome::Protected,
                                detail: format!(
                                    "Protected as a read-only audited file; \
                                     not imported as an SSH identity ({error})"
                                ),
                            });
                        }
                        Err(error) => return Err(error),
                    }
                    Ok(Vec::new())
                }
                DiscoveredFileAction::Compose => match import.destination {
                    DiscoveryImportDestination::ProjectFile { project_path } => {
                        let protected =
                            protect_discovered_file(catalog, store, mount_path, &file)?;
                        if !matches!(protected, ControlResult::FileProtected { .. }) {
                            return Err(DispatchError::Validation(
                                "managing a discovered file returned an unexpected result"
                                    .to_string(),
                            ));
                        }
                        let project_id = &project_states[&project_path].0;
                        apply_protected_file_environment_scope(
                            catalog,
                            store,
                            &protected,
                            project_id,
                            file.environment.as_deref(),
                        )?;
                        result.protected_files += 1;
                        result.files.push(DiscoveryAppliedFile {
                            path: file.path,
                            outcome: DiscoveryApplyOutcome::Protected,
                            detail: "Managed unchanged; this file type can be configured later"
                                .to_string(),
                        });
                        Ok(vec![project_path])
                    }
                    DiscoveryImportDestination::ProjectOutput {
                        project_path,
                        output_path,
                    } => {
                        let project_id = &project_states[&project_path].0;
                        let imported = apply_project_output_discovery(
                            catalog,
                            store,
                            mount_path,
                            project_id,
                            &output_path,
                            DiscoveryReuseState {
                                existing: &mut existing,
                                separate_entries: &separate_entries,
                                promote_entries: &promote_entries,
                                demote_entries: &demote_entries,
                            },
                            &mut result,
                            file,
                        )?;
                        Ok(imported.then_some(project_path).into_iter().collect())
                    }
                    DiscoveryImportDestination::Library => {
                        apply_library_discovery(
                            catalog,
                            store,
                            mount_path,
                            import.source_disposition,
                            DiscoveryReuseState {
                                existing: &mut existing,
                                separate_entries: &separate_entries,
                                promote_entries: &promote_entries,
                                demote_entries: &demote_entries,
                            },
                            &mut result,
                            file,
                        )?;
                        Ok(Vec::new())
                    }
                    DiscoveryImportDestination::ProjectOutputs { outputs } => {
                        let resolved = outputs
                            .iter()
                            .map(|output| ResolvedProjectOutput {
                                project_id: project_states[&output.project_path].0.clone(),
                                output_path: output.output_path.clone(),
                            })
                            .collect::<Vec<_>>();
                        let imported = apply_project_outputs_discovery(
                            catalog,
                            store,
                            mount_path,
                            &resolved,
                            import.source_disposition,
                            DiscoveryReuseState {
                                existing: &mut existing,
                                separate_entries: &separate_entries,
                                promote_entries: &promote_entries,
                                demote_entries: &demote_entries,
                            },
                            &mut result,
                            file,
                        )?;
                        Ok(if imported {
                            outputs.into_iter().map(|output| output.project_path).collect()
                        } else {
                            Vec::new()
                        })
                    }
                },
                DiscoveredFileAction::Review | DiscoveredFileAction::Reference => {
                    unreachable!("review-only files cannot have an Import Destination")
                }
            }
        })();
        match applied {
            Ok(project_paths) => composed_success.extend(project_paths),
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

fn resolve_discovery_imports(
    contents: &[DiscoveredContent],
    reviewed: Option<&[DiscoveryImport]>,
) -> Result<Vec<DiscoveryImport>, DispatchError> {
    if let Some(reviewed) = reviewed {
        if reviewed.is_empty() {
            return Err(DispatchError::Validation(
                "select at least one discovered file to import".to_string(),
            ));
        }
        return Ok(reviewed.to_vec());
    }

    contents
        .iter()
        .filter_map(|file| {
            let import = match file.action {
                DiscoveredFileAction::Compose => {
                    let Some(project_path) = file.assignment.project_path.clone() else {
                        return Some(Err(DispatchError::Validation(format!(
                            "choose an import destination for {} before importing it",
                            file.path.display()
                        ))));
                    };
                    DiscoveryImport {
                        path: file.path.clone(),
                        destination: DiscoveryImportDestination::ProjectFile { project_path },
                        source_disposition: DiscoverySourceDisposition::ProtectInPlace,
                    }
                }
                DiscoveredFileAction::Protect => {
                    let destination = file
                        .assignment
                        .project_path
                        .clone()
                        .map(|project_path| {
                            DiscoveryImportDestination::ProjectFile { project_path }
                        })
                        .unwrap_or(DiscoveryImportDestination::Library);
                    DiscoveryImport {
                        path: file.path.clone(),
                        destination,
                        source_disposition: DiscoverySourceDisposition::ProtectInPlace,
                    }
                }
                DiscoveredFileAction::ImportSshIdentity => DiscoveryImport {
                    path: file.path.clone(),
                    destination: DiscoveryImportDestination::Library,
                    source_disposition: DiscoverySourceDisposition::LeaveUnchanged,
                },
                DiscoveredFileAction::Review | DiscoveredFileAction::Reference => return None,
            };
            Some(Ok(import))
        })
        .collect()
}

fn import_project_paths(
    destination: &DiscoveryImportDestination,
) -> Vec<&PathBuf> {
    match destination {
        DiscoveryImportDestination::ProjectFile { project_path } => vec![project_path],
        DiscoveryImportDestination::ProjectOutput { project_path, .. } => vec![project_path],
        DiscoveryImportDestination::Library => Vec::new(),
        DiscoveryImportDestination::ProjectOutputs { outputs } => {
            outputs.iter().map(|output| &output.project_path).collect()
        }
    }
}

fn validate_discovery_import(
    file: &DiscoveredContent,
    import: &DiscoveryImport,
    valid_project_paths: &HashSet<PathBuf>,
) -> Result<(), DispatchError> {
    let invalid = |message: String| DispatchError::Validation(format!(
        "{}: {message}",
        file.path.display()
    ));
    match (&import.destination, import.source_disposition) {
        (
            DiscoveryImportDestination::ProjectFile { project_path },
            DiscoverySourceDisposition::ProtectInPlace,
        ) if matches!(
            file.action,
            DiscoveredFileAction::Compose | DiscoveredFileAction::Protect
        ) => {
            if !valid_project_paths.contains(project_path) {
                return Err(invalid(format!(
                    "assigned project was not part of discovery: {}",
                    project_path.display()
                )));
            }
        }
        (
            DiscoveryImportDestination::ProjectOutput {
                project_path,
                output_path,
            },
            DiscoverySourceDisposition::ReplaceWithSurface,
        ) if file.action == DiscoveredFileAction::Compose => {
            validate_project_output(project_path, output_path, valid_project_paths)?;
            if output_path != &file.path {
                return Err(invalid(
                    "a single Project Output must replace the discovered source path".to_string(),
                ));
            }
        }
        (
            DiscoveryImportDestination::Library,
            DiscoverySourceDisposition::ProtectInPlace
            | DiscoverySourceDisposition::LeaveUnchanged,
        ) if matches!(
            file.action,
            DiscoveredFileAction::Compose | DiscoveredFileAction::ImportSshIdentity
        ) => {}
        (
            DiscoveryImportDestination::Library,
            DiscoverySourceDisposition::ProtectInPlace,
        ) if file.action == DiscoveredFileAction::Protect => {}
        (
            DiscoveryImportDestination::ProjectOutputs { outputs },
            source_disposition,
        ) if file.action == DiscoveredFileAction::Compose => {
            if outputs.is_empty() {
                return Err(invalid("choose at least one Project Output".to_string()));
            }
            let mut project_paths = HashSet::new();
            let mut output_paths = HashSet::new();
            for output in outputs {
                validate_project_output(
                    &output.project_path,
                    &output.output_path,
                    valid_project_paths,
                )?;
                if !project_paths.insert(&output.project_path) {
                    return Err(invalid(format!(
                        "project output was selected more than once: {}",
                        output.project_path.display()
                    )));
                }
                if !output_paths.insert(&output.output_path) {
                    return Err(invalid(format!(
                        "output path was selected more than once: {}",
                        output.output_path.display()
                    )));
                }
            }
            let replaces_source =
                outputs.iter().filter(|output| output.output_path == file.path).count();
            match source_disposition {
                DiscoverySourceDisposition::ReplaceWithSurface if replaces_source == 1 => {}
                DiscoverySourceDisposition::ReplaceWithSurface => {
                    return Err(invalid(
                        "replace-with-surface requires exactly one output at the source path"
                            .to_string(),
                    ));
                }
                DiscoverySourceDisposition::ProtectInPlace
                | DiscoverySourceDisposition::LeaveUnchanged
                    if replaces_source == 0 => {}
                DiscoverySourceDisposition::ProtectInPlace
                | DiscoverySourceDisposition::LeaveUnchanged => {
                    return Err(invalid(
                        "the source path cannot also be a Project Output when it is protected or left unchanged"
                            .to_string(),
                    ));
                }
            }
        }
        _ => {
            return Err(invalid(
                "the selected Import Destination and Source Disposition are incompatible"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_project_output(
    project_path: &Path,
    output_path: &Path,
    valid_project_paths: &HashSet<PathBuf>,
) -> Result<(), DispatchError> {
    if !valid_project_paths.contains(project_path) {
        return Err(DispatchError::Validation(format!(
            "project output target was not part of discovery: {}",
            project_path.display()
        )));
    }
    if !output_path.is_absolute()
        || output_path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        || !output_path.starts_with(project_path)
    {
        return Err(DispatchError::Validation(format!(
            "project output must be an absolute path inside {}: {}",
            project_path.display(),
            output_path.display()
        )));
    }
    let canonical_project =
        std::fs::canonicalize(project_path).map_err(|source| DispatchError::Io {
            path: project_path.to_path_buf(),
            source,
        })?;
    let mut existing_parent = output_path.parent();
    let canonical_parent = loop {
        let parent = existing_parent.ok_or_else(|| {
            DispatchError::Validation(format!(
                "project output has no existing parent: {}",
                output_path.display()
            ))
        })?;
        match std::fs::canonicalize(parent) {
            Ok(path) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing_parent = parent.parent();
            }
            Err(source) => {
                return Err(DispatchError::Io {
                    path: parent.to_path_buf(),
                    source,
                });
            }
        }
    };
    if !canonical_parent.starts_with(&canonical_project) {
        return Err(DispatchError::Validation(format!(
            "project output resolves outside {}: {}",
            project_path.display(),
            output_path.display()
        )));
    }
    Ok(())
}

struct DiscoveryReuseState<'a> {
    existing: &'a mut Vec<ExistingSecret>,
    separate_entries: &'a HashSet<(PathBuf, String)>,
    promote_entries: &'a HashSet<(PathBuf, String)>,
    demote_entries: &'a HashSet<(PathBuf, String)>,
}

#[derive(Clone)]
struct MaterializedResource {
    resource_id: String,
    enforcement: Enforcement,
    position: i64,
}

struct ResolvedProjectOutput {
    project_id: String,
    output_path: PathBuf,
}

#[allow(clippy::too_many_arguments)]
fn apply_project_output_discovery(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    project_id: &str,
    output_path: &Path,
    reuse: DiscoveryReuseState<'_>,
    result: &mut DiscoveryApplyResult,
    file: DiscoveredContent,
) -> Result<bool, DispatchError> {
    if !discovery_file_has_importable_content(&file, result) {
        return Ok(false);
    }

    let environment_name = file.environment.as_deref().unwrap_or("development");
    let mut mutation = DiscoveryMutationGuard::new(catalog, store);
    let (environment_id, environment_created) =
        ensure_discovered_environment(catalog, project_id, environment_name)?;
    if environment_created {
        mutation.track_environment(environment_id.clone());
    }
    let source = discovered_source(&file, Some(project_id), Some(environment_name));
    let resources = materialize_discovered_resources(
        catalog,
        store,
        reuse,
        result,
        &file,
        source,
        &mut mutation,
    )?;
    let binding_ids = bind_materialized_resources(
        catalog,
        project_id,
        &environment_id,
        &resources,
        &mut mutation,
    )?;
    let surface =
        discovered_surface(&file, environment_id, output_path, &resources, binding_ids)?;
    replace_discovered_file_with_surface(catalog, mount_path, &surface)?;
    mutation.commit();
    result.files.push(DiscoveryAppliedFile {
        path: file.path,
        outcome: DiscoveryApplyOutcome::Imported,
        detail: project_output_detail(file.kind),
    });
    Ok(true)
}

fn apply_library_discovery(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    source_disposition: DiscoverySourceDisposition,
    reuse: DiscoveryReuseState<'_>,
    result: &mut DiscoveryApplyResult,
    file: DiscoveredContent,
) -> Result<bool, DispatchError> {
    if !discovery_file_has_importable_content(&file, result) {
        return Ok(false);
    }

    let mut mutation = DiscoveryMutationGuard::new(catalog, store);
    let source = discovered_source(&file, None, None);
    materialize_discovered_resources(
        catalog,
        store,
        reuse,
        result,
        &file,
        source,
        &mut mutation,
    )?;
    apply_source_disposition(
        catalog,
        store,
        mount_path,
        source_disposition,
        &file,
        result,
    )?;
    mutation.commit();
    result.files.push(DiscoveryAppliedFile {
        path: file.path,
        outcome: DiscoveryApplyOutcome::Imported,
        detail: match source_disposition {
            DiscoverySourceDisposition::ProtectInPlace => {
                "Imported into Library and protected the original file".to_string()
            }
            DiscoverySourceDisposition::LeaveUnchanged => {
                "Imported into Library and left the original file unchanged".to_string()
            }
            DiscoverySourceDisposition::ReplaceWithSurface => {
                unreachable!("validated Library source disposition")
            }
        },
    });
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn apply_project_outputs_discovery(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    outputs: &[ResolvedProjectOutput],
    source_disposition: DiscoverySourceDisposition,
    reuse: DiscoveryReuseState<'_>,
    result: &mut DiscoveryApplyResult,
    file: DiscoveredContent,
) -> Result<bool, DispatchError> {
    if !discovery_file_has_importable_content(&file, result) {
        return Ok(false);
    }

    let environment_name = file.environment.as_deref().unwrap_or("development");
    let mut mutation = DiscoveryMutationGuard::new(catalog, store);
    let source = discovered_source(&file, None, None);
    let resources = materialize_discovered_resources(
        catalog,
        store,
        reuse,
        result,
        &file,
        source,
        &mut mutation,
    )?;
    let mut source_surface = None;
    for output in outputs {
        let (environment_id, environment_created) =
            ensure_discovered_environment(catalog, &output.project_id, environment_name)?;
        if environment_created {
            mutation.track_environment(environment_id.clone());
        }
        let binding_ids = bind_materialized_resources(
            catalog,
            &output.project_id,
            &environment_id,
            &resources,
            &mut mutation,
        )?;
        let surface = discovered_surface(
            &file,
            environment_id,
            &output.output_path,
            &resources,
            binding_ids,
        )?;
        if output.output_path == file.path {
            source_surface = Some(surface);
        } else {
            create_discovered_surface(catalog, mount_path, &surface)?;
            mutation.track_surface(
                surface.id.clone(),
                surface.path.clone().expect("discovered file surface has a path"),
            );
        }
    }
    if let Some(surface) = source_surface {
        replace_discovered_file_with_surface(catalog, mount_path, &surface)?;
    } else {
        apply_source_disposition(
            catalog,
            store,
            mount_path,
            source_disposition,
            &file,
            result,
        )?;
    }
    mutation.commit();
    result.files.push(DiscoveryAppliedFile {
        path: file.path,
        outcome: DiscoveryApplyOutcome::Imported,
        detail: format!(
            "Imported once and created {} Project Output{}",
            outputs.len(),
            if outputs.len() == 1 { "" } else { "s" }
        ),
    });
    Ok(true)
}

fn materialize_discovered_resources(
    catalog: &Catalog,
    store: &dyn SecretStore,
    reuse: DiscoveryReuseState<'_>,
    result: &mut DiscoveryApplyResult,
    file: &DiscoveredContent,
    source: OriginSource,
    mutation: &mut DiscoveryMutationGuard<'_>,
) -> Result<Vec<MaterializedResource>, DispatchError> {
    let mut resources = Vec::new();
    match file.kind {
        DiscoveredFileKind::Dotenv | DiscoveredFileKind::Direnv => {
            let mut plain_entries: Vec<(usize, &floria_discover::DiscoveredValue)> = Vec::new();
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
                let (resource_id, enforcement) = if let Some(candidate) = reusable.flatten() {
                    result.reused_resources += 1;
                    let resource_id = candidate.resource_id.clone();
                    catalog.append_resource_origin(&resource_id, &source)?;
                    let enforcement = catalog.resource(&resource_id)?.enforcement;
                    (resource_id, enforcement)
                } else {
                    let resource_id = generated_id("secret");
                    let enforcement = SecurityDefaults::discovered_resource(file.kind);
                    create_shared_secret(
                        catalog,
                        store,
                        resource_id.clone(),
                        entry.key.clone(),
                        Some(entry.key.clone()),
                        SecretValue::new(entry.value.as_str().to_string()),
                        ManagedItemSettings {
                            enforcement,
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
                    (resource_id, enforcement)
                };
                resources.push(MaterializedResource {
                    resource_id,
                    enforcement,
                    position: position as i64,
                });
            }
            if !plain_entries.is_empty() {
                let values = plain_entries
                    .iter()
                    .map(|(_, entry)| (entry.key.clone(), entry.value.as_str().to_string()))
                    .collect::<Vec<_>>();
                let rendered = floria_surface::render_dotenv(&values)
                    .map_err(|error| DispatchError::Validation(error.to_string()))?;
                let content = String::from_utf8(rendered).map_err(|_| {
                    DispatchError::Validation(format!(
                        "{} produced non-UTF-8 env values",
                        file.path.display()
                    ))
                })?;
                let resource_id = generated_id("env-file");
                let enforcement = SecurityDefaults::discovered_resource(file.kind);
                create_env_file(
                    catalog,
                    store,
                    resource_id.clone(),
                    file.relative_path.display().to_string(),
                    ResourceCodec::Dotenv,
                    SecretValue::new(content),
                    ManagedItemSettings {
                        enforcement,
                        metadata: ItemMetadata::default(),
                    },
                    ResourceOrigin {
                        kind: OriginKind::Discovered,
                        sources: vec![source.clone()],
                    },
                )?;
                mutation.track_resource(resource_id.clone());
                result.created_resources += 1;
                resources.push(MaterializedResource {
                    resource_id,
                    enforcement,
                    position: plain_entries[0].0 as i64,
                });
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
            let enforcement = SecurityDefaults::discovered_resource(file.kind);
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
                    enforcement,
                    metadata: ItemMetadata::default(),
                },
                ResourceOrigin {
                    kind: OriginKind::Discovered,
                    sources: vec![source],
                },
            )?;
            mutation.track_resource(resource_id.clone());
            result.created_resources += 1;
            resources.push(MaterializedResource {
                resource_id,
                enforcement,
                position: 0,
            });
        }
        _ => unreachable!("validated composable discovery kind"),
    }
    resources.sort_by_key(|resource| resource.position);
    Ok(resources)
}

fn bind_materialized_resources(
    catalog: &Catalog,
    project_id: &str,
    environment_id: &str,
    resources: &[MaterializedResource],
    mutation: &mut DiscoveryMutationGuard<'_>,
) -> Result<Vec<String>, DispatchError> {
    let mut binding_ids = Vec::with_capacity(resources.len());
    for resource in resources {
        let binding_id = generated_id("binding");
        catalog.upsert_binding(&Binding {
            id: binding_id.clone(),
            project_id: project_id.to_string(),
            scope: BindingScope::Environment {
                environment_id: environment_id.to_string(),
            },
            resource_id: resource.resource_id.clone(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: resource.position,
        })?;
        mutation.track_binding(binding_id.clone());
        binding_ids.push(binding_id);
    }
    Ok(binding_ids)
}

fn discovered_surface(
    file: &DiscoveredContent,
    environment_id: String,
    output_path: &Path,
    resources: &[MaterializedResource],
    binding_ids: Vec<String>,
) -> Result<Surface, DispatchError> {
    let kind = match file.kind {
        DiscoveredFileKind::Dotenv => {
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv))
        }
        DiscoveredFileKind::Direnv => {
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv))
        }
        DiscoveredFileKind::AwsCredentials => {
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini))
        }
        _ => {
            return Err(DispatchError::Validation(format!(
                "{} is not a composable discovery format",
                file.path.display()
            )));
        }
    };
    Ok(Surface {
        id: generated_id("surface"),
        environment_id,
        name: output_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("environment")
            .to_string(),
        kind,
        path: Some(output_path.to_path_buf()),
        input: SurfaceInput::Bindings { binding_ids },
        enforcement: SecurityDefaults::composed_surface(
            resources.iter().map(|resource| resource.enforcement),
        ),
        position: 0,
    })
}

fn discovery_file_has_importable_content(
    file: &DiscoveredContent,
    result: &mut DiscoveryApplyResult,
) -> bool {
    if file.entries.is_empty() {
        result.files.push(DiscoveryAppliedFile {
            path: file.path.clone(),
            outcome: DiscoveryApplyOutcome::Skipped,
            detail: "No statically importable values were found".to_string(),
        });
        return false;
    }
    matches!(
        file.kind,
        DiscoveredFileKind::Dotenv
            | DiscoveredFileKind::Direnv
            | DiscoveredFileKind::AwsCredentials
    )
}

fn project_output_detail(kind: DiscoveredFileKind) -> String {
    match kind {
        DiscoveredFileKind::AwsCredentials => {
            "Imported as a section-aware INI environment file".to_string()
        }
        _ => "Imported as reusable secrets and a composed output".to_string(),
    }
}

fn apply_source_disposition(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    disposition: DiscoverySourceDisposition,
    file: &DiscoveredContent,
    result: &mut DiscoveryApplyResult,
) -> Result<(), DispatchError> {
    match disposition {
        DiscoverySourceDisposition::ProtectInPlace => {
            let protected = protect_discovered_file(catalog, store, mount_path, file)?;
            if !matches!(protected, ControlResult::FileProtected { .. }) {
                return Err(DispatchError::Validation(
                    "protecting a discovered source returned an unexpected result".to_string(),
                ));
            }
            result.protected_files += 1;
        }
        DiscoverySourceDisposition::LeaveUnchanged => {}
        DiscoverySourceDisposition::ReplaceWithSurface => {
            return Err(DispatchError::Validation(
                "replace-with-surface requires a Project Output at the source path".to_string(),
            ));
        }
    }
    Ok(())
}

fn create_discovered_surface(
    catalog: &Catalog,
    mount_path: &Path,
    surface: &Surface,
) -> Result<(), DispatchError> {
    let path = surface.path.as_deref().ok_or_else(|| {
        DispatchError::Validation(format!("file surface {:?} has no path", surface.id))
    })?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(DispatchError::Validation(format!(
                "project output already exists: {}",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DispatchError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    catalog.upsert_surface(surface)?;
    let snapshot = catalog.snapshot()?;
    if let Err(error) = ensure_file_surface_link_in_snapshot(&snapshot, surface, mount_path) {
        let _ = catalog.remove_surface(&surface.id);
        let _ = std::fs::remove_file(path);
        return Err(DispatchError::Validation(error.to_string()));
    }
    Ok(())
}

pub(super) struct DiscoveryMutationGuard<'a> {
    catalog: &'a Catalog,
    store: &'a dyn SecretStore,
    created_resources: Vec<String>,
    created_bindings: Vec<String>,
    created_environments: Vec<String>,
    created_surfaces: Vec<(String, PathBuf)>,
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
            created_surfaces: Vec::new(),
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

    fn track_surface(&mut self, surface_id: String, path: PathBuf) {
        self.created_surfaces.push((surface_id, path));
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
        for (surface_id, path) in self.created_surfaces.iter().rev() {
            if let Err(error) = self.catalog.remove_surface(surface_id) {
                tracing::warn!(
                    %surface_id,
                    %error,
                    "discovery rollback could not remove surface"
                );
            }
            if std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                if let Err(error) = std::fs::remove_file(path) {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "discovery rollback could not remove surface link"
                    );
                }
            }
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
    project: &floria_discover::DiscoveredProject,
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
        default_environment_id: None,
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

fn apply_protected_file_environment_scope(
    catalog: &Catalog,
    store: &dyn SecretStore,
    protected: &ControlResult,
    project_id: &str,
    suggested_environment: Option<&str>,
) -> Result<(), DispatchError> {
    let ControlResult::FileProtected { file, .. } = protected else {
        return Err(DispatchError::Validation(
            "environment scope requires a protected file".to_string(),
        ));
    };
    let snapshot = catalog.snapshot()?;
    let project = snapshot
        .projects
        .iter()
        .find(|project| project.id == project_id)
        .ok_or_else(|| {
            DispatchError::Validation(format!("project {project_id:?} was not found"))
        })?;
    let default_environment_id = project.default_environment_id.as_ref().and_then(|id| {
        snapshot
            .environments
            .iter()
            .any(|environment| environment.project_id == project_id && environment.id == *id)
            .then(|| id.clone())
    });
    let environment_id = if let Some(name) = suggested_environment {
        ensure_discovered_environment(catalog, project_id, name)?.0
    } else if let Some(id) = default_environment_id {
        id
    } else if let Some(environment) = snapshot
        .environments
        .iter()
        .filter(|environment| environment.project_id == project_id)
        .min_by_key(|environment| {
            (
                !environment.name.eq_ignore_ascii_case("development"),
                environment.position,
            )
        })
    {
        environment.id.clone()
    } else {
        ensure_discovered_environment(catalog, project_id, "development")?.0
    };
    let secret_id: SecretId = file
        .id
        .parse()
        .map_err(|error| DispatchError::Validation(format!("invalid protected file id: {error}")))?;
    let record = store
        .record(&secret_id)?
        .ok_or_else(|| StoreError::NotFound(file.id.clone()))?;
    store.update_settings(
        &secret_id,
        record.metadata,
        record.enforcement,
        Some(vec![environment_id]),
    )?;
    Ok(())
}

pub(super) fn replace_discovered_file_with_surface(
    catalog: &Catalog,
    mount_path: &Path,
    surface: &Surface,
) -> Result<(), DispatchError> {
    let path = surface.path.as_deref().ok_or_else(|| {
        DispatchError::Validation(format!("file surface {:?} has no path", surface.id))
    })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("environment");
    let backup = path.with_file_name(format!(
        ".{file_name}.floria-import-{}",
        SecretId::generate()
    ));
    std::fs::rename(path, &backup).map_err(|source| DispatchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if let Err(error) = catalog.upsert_surface(surface) {
        let _ = std::fs::rename(&backup, path);
        return Err(DispatchError::Catalog(error));
    }
    let snapshot = catalog.snapshot()?;
    if let Err(error) = ensure_file_surface_link_in_snapshot(&snapshot, surface, mount_path) {
        let _ = catalog.remove_surface(&surface.id);
        let _ = std::fs::rename(&backup, path);
        return Err(DispatchError::Validation(error.to_string()));
    }
    if let Err(source) = std::fs::remove_file(&backup) {
        let _ = std::fs::remove_file(path);
        let _ = catalog.remove_surface(&surface.id);
        let _ = std::fs::rename(&backup, path);
        return Err(DispatchError::Io { path: backup, source });
    }
    Ok(())
}

pub(super) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub(super) fn discovered_source(
    file: &DiscoveredContent,
    project_id: Option<&str>,
    environment: Option<&str>,
) -> OriginSource {
    OriginSource {
        path: file.path.clone(),
        project_id: project_id.map(str::to_string),
        environment: environment.map(str::to_string),
        imported_at: now_rfc3339(),
    }
}

pub(super) fn generated_id(prefix: &str) -> String {
    format!("{prefix}-{}", SecretId::generate())
}

pub(super) fn existing_discovery_projects(
    catalog: &Catalog,
    discovered: &[floria_discover::DiscoveredProject],
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
                            path: surface
                                .path
                                .clone()
                                .expect("composed file surface has a path"),
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

pub(super) fn discovery_review_plan(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: Option<&Path>,
    discovery: DiscoveryPlan,
) -> Result<DiscoveryReviewPlan, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let configured_secret_ids = snapshot.file_surface_secret_ids();
    let records = store.list()?;
    let managed_links = match mount_path {
        Some(mount_path) => managed_file_links(&snapshot, &records, mount_path)
            .map_err(|error| DispatchError::Validation(error.to_string()))?,
        None => Vec::new(),
    };
    let mut managed_items = Vec::new();

    for surface in snapshot.surfaces.iter().filter(|surface| surface.kind.is_file()) {
        let path = surface.path.as_deref().expect("validated file surface has a path");
        if !discovery_path_is_in_scope(path, &discovery.paths) {
            continue;
        }
        let Some(environment) = snapshot
            .environments
            .iter()
            .find(|environment| environment.id == surface.environment_id)
        else {
            continue;
        };
        let project_path = snapshot
            .projects
            .iter()
            .find(|project| project.id == environment.project_id)
            .map(|project| project.path.clone());
        let managed_link = managed_links.iter().find(|link| link.path() == path);
        managed_items.push(DiscoveryManagedItem {
            id: surface.id.clone(),
            path: path.to_path_buf(),
            relative_path: discovery_relative_path(
                path,
                project_path.as_deref(),
                &discovery.paths,
            ),
            project_path,
            environment: Some(environment.name.clone()),
            kind: DiscoveryManagedItemKind::Surface,
            status: discovery_managed_path_status(path, managed_link),
        });
    }

    for record in records {
        let SecretOrigin::File { source_path } = &record.origin else { continue };
        let source_path = source_path.clone();
        if configured_secret_ids.contains(record.id.as_str()) {
            continue;
        }
        if !discovery_path_is_in_scope(&source_path, &discovery.paths) {
            continue;
        }
        let normalized_source_path = discovery_normalized_path(&source_path);
        let project_path = snapshot
            .projects
            .iter()
            .filter(|project| {
                normalized_source_path.starts_with(discovery_normalized_path(&project.path))
            })
            .max_by_key(|project| project.path.components().count())
            .map(|project| project.path.clone());
        let managed_link = managed_links.iter().find(|link| link.path() == source_path);
        let status = discovery_managed_path_status(&source_path, managed_link);
        managed_items.push(DiscoveryManagedItem {
            id: record.id.to_string(),
            relative_path: discovery_relative_path(
                &source_path,
                project_path.as_deref(),
                &discovery.paths,
            ),
            path: source_path,
            project_path,
            environment: None,
            kind: DiscoveryManagedItemKind::ProtectedFile,
            status,
        });
    }

    managed_items.sort_by(|left, right| {
        left.project_path
            .cmp(&right.project_path)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(DiscoveryReviewPlan { discovery, managed_items })
}

fn discovery_path_is_in_scope(path: &Path, inputs: &[PathBuf]) -> bool {
    let normalized_path = discovery_normalized_path(path);
    inputs.iter().any(|input| {
        if path == input {
            return true;
        }
        std::fs::symlink_metadata(input).is_ok_and(|metadata| {
            metadata.is_dir()
                && normalized_path.starts_with(discovery_normalized_path(input))
        })
    })
}

fn discovery_relative_path(
    path: &Path,
    project_path: Option<&Path>,
    inputs: &[PathBuf],
) -> PathBuf {
    let normalized_path = discovery_normalized_path(path);
    project_path
        .map(discovery_normalized_path)
        .and_then(|project_path| {
            normalized_path
                .strip_prefix(project_path)
                .ok()
                .map(Path::to_path_buf)
        })
        .or_else(|| {
            inputs
                .iter()
                .map(|input| discovery_normalized_path(input))
                .filter(|input| normalized_path.starts_with(input))
                .max_by_key(|input| input.components().count())
                .and_then(|input| {
                    normalized_path
                        .strip_prefix(input)
                        .ok()
                        .map(Path::to_path_buf)
                })
        })
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or_else(|| {
            path.file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| path.to_path_buf())
        })
}

fn discovery_normalized_path(path: &Path) -> PathBuf {
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
        return std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    }
    let Some(parent) = path.parent() else { return path.to_path_buf() };
    let Some(name) = path.file_name() else { return path.to_path_buf() };
    std::fs::canonicalize(parent)
        .unwrap_or_else(|_| parent.to_path_buf())
        .join(name)
}

fn discovery_managed_path_status(
    path: &Path,
    managed_link: Option<&ManagedSymlink>,
) -> ManagedLinkStatus {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = std::fs::read_link(path).ok();
            if managed_link.is_none_or(|link| {
                target.as_deref().is_some_and(|target| link.owns_target(target))
            }) {
                ManagedLinkStatus::Linked
            } else {
                ManagedLinkStatus::Replaced
            }
        }
        Ok(_) => ManagedLinkStatus::Replaced,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ManagedLinkStatus::Missing
        }
        Err(_) => ManagedLinkStatus::Replaced,
    }
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
    let mut candidates = Vec::new();
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
        candidates.push((resource.id, resource.name, key, id));
    }
    let ids = candidates
        .iter()
        .map(|(_, _, _, id)| id.clone())
        .collect::<Vec<_>>();
    let values = match store.get_many(&ids) {
        Ok(values) => values.into_iter().map(Some).collect::<Vec<_>>(),
        Err(batch_error) => {
            tracing::warn!(
                %batch_error,
                count = ids.len(),
                "batch shared-secret loading failed; retrying individually"
            );
            ids.iter()
                .map(|id| match store.get(id) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        tracing::warn!(
                            secret_id = %id,
                            %error,
                            "shared secret was unavailable for discovery matching"
                        );
                        None
                    }
                })
                .collect()
        }
    };
    let existing = candidates
        .into_iter()
        .zip(values)
        .filter_map(|((resource_id, name, key, _), value)| {
            value.map(|value| ExistingSecret {
                resource_id,
                name,
                key,
                value,
            })
        })
        .collect();
    Ok(existing)
}
