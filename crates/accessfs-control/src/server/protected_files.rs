use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn protected_files(
    store: &dyn SecretStore,
    mount_path: &Path,
) -> Result<ControlResult, DispatchError> {
    let mut files = store
        .list()?
        .into_iter()
        .filter_map(|record| protected_file(record, mount_path))
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.source_path.cmp(&right.source_path));
    Ok(ControlResult::ProtectedFiles(files))
}

pub(super) fn protected_file(record: SecretRecord, mount_path: &Path) -> Option<ProtectedFile> {
    let SecretOrigin::File { source_path } = record.origin else { return None };
    let expected = mount_path
        .join(accessfs_core::config::SECRETS_DIR)
        .join(record.id.to_string());
    let linked = std::fs::symlink_metadata(&source_path)
        .ok()
        .filter(|metadata| metadata.file_type().is_symlink())
        .and_then(|_| std::fs::read_link(&source_path).ok())
        .is_some_and(|target| target == expected);
    Some(ProtectedFile {
        id: record.id.to_string(),
        source_path,
        mode: record.mode,
        size: record.size,
        current_version: record.current_version,
        linked,
        enforcement: record.enforcement,
        metadata: record.metadata,
    })
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
            file: protected_file(record, mount_path)
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
    Ok(ControlResult::FileProtected {
        file: protected_file(record, mount_path)
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
    store: &dyn SecretStore,
    id: &str,
    enforcement: Enforcement,
    metadata: ItemMetadata,
) -> Result<ControlResult, DispatchError> {
    let (id, _) = file_record(store, id)?;
    store.update_settings(&id, metadata, enforcement)?;
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
        file: protected_file(record, mount_path)
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
    replace_symlink_with_file(source_path, &plaintext, record.mode).map_err(|source| {
        DispatchError::Io { path: source_path.clone(), source }
    })?;
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

pub(super) fn replace_symlink_with_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let mut temporary = None;
    for counter in 0..100 {
        let candidate = parent.join(format!(
            ".{name}.floria-restore-{}-{counter}.tmp",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(mut file) => {
                if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
                    let _ = std::fs::remove_file(&candidate);
                    return Err(error);
                }
                if let Err(error) =
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(mode))
                {
                    let _ = std::fs::remove_file(&candidate);
                    return Err(error);
                }
                temporary = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let temporary = temporary.ok_or_else(|| {
        io::Error::new(io::ErrorKind::AlreadyExists, "could not allocate a restore file name")
    })?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

pub(super) fn replace_file_with_symlink(path: &Path, target: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let mut temporary = None;
    for counter in 0..100 {
        let candidate = parent.join(format!(
            ".{name}.floria-{}-{counter}.tmp",
            std::process::id()
        ));
        match std::os::unix::fs::symlink(target, &candidate) {
            Ok(()) => {
                temporary = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let temporary = temporary.ok_or_else(|| {
        io::Error::new(io::ErrorKind::AlreadyExists, "could not allocate a temporary symlink name")
    })?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}
