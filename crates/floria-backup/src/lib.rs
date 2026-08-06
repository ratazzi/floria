//! Consistent, encrypted Floria backups.
//!
//! The public interface intentionally stays small: create a backup from the catalog and store,
//! or verify an existing backup with the live store's key provider. The module owns temporary
//! paths, SQLite snapshotting, ciphertext copying, checksums, permissions, and cleanup.

mod activation;

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use floria_catalog::{Catalog, ResourceSource};
use floria_store::{AgeDirStore, StoreMaintenanceGuard, StoreVerification};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use activation::{
    activate_restored_data, recover_interrupted_activation, ActivationReport,
};

const BACKUP_FORMAT: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const CATALOG_FILE: &str = "catalog.sqlite";
const STORE_DIRECTORY: &str = "store";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub path: PathBuf,
    pub catalog_schema: i64,
    pub projects: usize,
    pub resources: usize,
    pub secrets: usize,
    pub versions: usize,
    pub plaintext_bytes: u64,
    pub files: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("backup io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("catalog backup failed: {0}")]
    Catalog(#[from] floria_catalog::CatalogError),
    #[error("encrypted store backup failed: {0}")]
    Store(#[from] floria_store::StoreError),
    #[error("restore authorization state failed: {0}")]
    Integrity(#[from] floria_integrity::IntegrityError),
    #[error("backup manifest is invalid: {0}")]
    Manifest(String),
    #[error("backup manifest encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
}

pub type BackupResult<T> = Result<T, BackupError>;

#[derive(Debug, Serialize, Deserialize)]
struct BackupManifest {
    format: u32,
    created_at: String,
    catalog_schema: i64,
    projects: usize,
    resources: usize,
    secrets: usize,
    versions: usize,
    plaintext_bytes: u64,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestFile {
    path: String,
    size: u64,
    sha256: String,
}

/// Create a new backup directory and verify it before publishing it at `destination`.
///
/// `destination` is never overwritten. A failed attempt removes only its private temporary
/// sibling; the live catalog and store are read-only from this module's perspective.
pub fn create(
    catalog: &Catalog,
    store: &AgeDirStore,
    destination: &Path,
) -> BackupResult<BackupReport> {
    let store_lock = store.lock_for_maintenance()?;
    create_with_locked_store(catalog, store, &store_lock, destination)
}

fn create_with_locked_store(
    catalog: &Catalog,
    store: &AgeDirStore,
    store_lock: &StoreMaintenanceGuard,
    destination: &Path,
) -> BackupResult<BackupReport> {
    create_with_manifest_writer(catalog, store, store_lock, destination, write_manifest)
}

fn create_with_manifest_writer(
    catalog: &Catalog,
    store: &AgeDirStore,
    store_lock: &StoreMaintenanceGuard,
    destination: &Path,
    manifest_writer: impl FnOnce(&Path, &BackupManifest) -> BackupResult<()>,
) -> BackupResult<BackupReport> {
    let destination = normalized_new_destination(destination)?;
    if destination.exists() {
        return Err(BackupError::Manifest(format!(
            "destination already exists: {}",
            destination.display()
        )));
    }
    let store_root = std::fs::canonicalize(store.root())
        .map_err(|source| BackupError::io(store.root(), source))?;
    if destination.starts_with(&store_root) {
        return Err(BackupError::Manifest(format!(
            "destination cannot be inside the encrypted store: {}",
            store.root().display()
        )));
    }

    let mut temporary = TemporaryBackup::create(&destination)?;
    catalog.backup_to(&temporary.path().join(CATALOG_FILE))?;
    store_lock.backup_to(&temporary.path().join(STORE_DIRECTORY))?;

    let snapshot = Catalog::inspect_backup(&temporary.path().join(CATALOG_FILE))?;
    let store_report = store.verify_backup(&temporary.path().join(STORE_DIRECTORY))?;
    validate_catalog_store_references(&snapshot, &store_report)?;
    let files = inventory_files(temporary.path())?;
    let manifest = BackupManifest {
        format: BACKUP_FORMAT,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        catalog_schema: catalog.schema_version(),
        projects: snapshot.projects.len(),
        resources: snapshot.resources.len(),
        secrets: store_report.secrets,
        versions: store_report.versions,
        plaintext_bytes: store_report.plaintext_bytes,
        files,
    };
    manifest_writer(temporary.path(), &manifest)?;
    let report = verify(temporary.path(), store)?;
    publish_without_overwrite(temporary.path(), &destination)?;
    temporary.publish();
    Ok(BackupReport { path: destination, ..report })
}

/// Verify checksums, catalog integrity, catalog/store references, and every encrypted version.
///
/// Verification writes no plaintext and does not modify the backup.
pub fn verify(backup: &Path, store: &AgeDirStore) -> BackupResult<BackupReport> {
    check_private_directory(backup)?;
    let verified_path =
        std::fs::canonicalize(backup).map_err(|source| BackupError::io(backup, source))?;
    let manifest_path = backup.join(MANIFEST_FILE);
    let manifest: BackupManifest = serde_json::from_slice(
        &std::fs::read(&manifest_path)
            .map_err(|source| BackupError::io(&manifest_path, source))?,
    )?;
    if manifest.format != BACKUP_FORMAT {
        return Err(BackupError::Manifest(format!(
            "format {} is unsupported; expected {}",
            manifest.format, BACKUP_FORMAT
        )));
    }

    let actual_files = inventory_files(backup)?;
    if actual_files != manifest.files {
        return Err(BackupError::Manifest(
            "file inventory or checksum does not match".to_string(),
        ));
    }

    let snapshot = Catalog::inspect_backup(&backup.join(CATALOG_FILE))?;
    let store_report = store.verify_backup(&backup.join(STORE_DIRECTORY))?;
    validate_catalog_store_references(&snapshot, &store_report)?;
    if manifest.catalog_schema != Catalog::current_schema_version()
        || manifest.projects != snapshot.projects.len()
        || manifest.resources != snapshot.resources.len()
        || manifest.secrets != store_report.secrets
        || manifest.versions != store_report.versions
        || manifest.plaintext_bytes != store_report.plaintext_bytes
    {
        return Err(BackupError::Manifest(
            "declared catalog or store counts do not match verified contents".to_string(),
        ));
    }

    Ok(BackupReport {
        path: verified_path,
        catalog_schema: manifest.catalog_schema,
        projects: manifest.projects,
        resources: manifest.resources,
        secrets: manifest.secrets,
        versions: manifest.versions,
        plaintext_bytes: manifest.plaintext_bytes,
        files: manifest.files.len(),
    })
}

/// Restore a verified backup into a newly created standalone data directory.
///
/// The restored directory contains `catalog.sqlite` and `store/`, ready for a later active-data
/// switch. The destination is never overwritten, and no partially restored directory is
/// published.
pub fn restore(
    backup: &Path,
    store: &AgeDirStore,
    destination: &Path,
) -> BackupResult<BackupReport> {
    let verified = verify(backup, store)?;
    let destination = normalized_new_destination(destination)?;
    if destination.exists() {
        return Err(BackupError::Manifest(format!(
            "restore destination already exists: {}",
            destination.display()
        )));
    }
    let backup_root =
        std::fs::canonicalize(backup).map_err(|source| BackupError::io(backup, source))?;
    if destination.starts_with(&backup_root) {
        return Err(BackupError::Manifest(format!(
            "restore destination cannot be inside the backup: {}",
            backup_root.display()
        )));
    }
    let store_root = std::fs::canonicalize(store.root())
        .map_err(|source| BackupError::io(store.root(), source))?;
    if destination.starts_with(&store_root) {
        return Err(BackupError::Manifest(format!(
            "restore destination cannot be inside the active encrypted store: {}",
            store_root.display()
        )));
    }

    let mut temporary = TemporaryBackup::create(&destination)?;
    copy_private_file(
        &backup_root.join(CATALOG_FILE),
        &temporary.path().join(CATALOG_FILE),
    )?;
    copy_private_directory(
        &backup_root.join(STORE_DIRECTORY),
        &temporary.path().join(STORE_DIRECTORY),
    )?;

    let snapshot = Catalog::inspect_backup(&temporary.path().join(CATALOG_FILE))?;
    let restored_store = store.verify_backup(&temporary.path().join(STORE_DIRECTORY))?;
    validate_catalog_store_references(&snapshot, &restored_store)?;
    if snapshot.projects.len() != verified.projects
        || snapshot.resources.len() != verified.resources
        || restored_store.secrets != verified.secrets
        || restored_store.versions != verified.versions
        || restored_store.plaintext_bytes != verified.plaintext_bytes
    {
        return Err(BackupError::Manifest(
            "restored data does not match the verified backup".to_string(),
        ));
    }

    publish_without_overwrite(temporary.path(), &destination)?;
    temporary.publish();
    Ok(BackupReport { path: destination, files: verified.files, ..verified })
}

/// Verify a standalone restored data directory without trusting an earlier restore result.
pub fn verify_restored_data(
    restored: &Path,
    store: &AgeDirStore,
) -> BackupResult<BackupReport> {
    check_private_directory(restored)?;
    let path =
        std::fs::canonicalize(restored).map_err(|source| BackupError::io(restored, source))?;
    let snapshot = Catalog::inspect_backup(&path.join(CATALOG_FILE))?;
    let store_report = store.verify_backup(&path.join(STORE_DIRECTORY))?;
    validate_catalog_store_references(&snapshot, &store_report)?;
    Ok(BackupReport {
        files: inventory_files(&path)?.len(),
        path,
        catalog_schema: Catalog::current_schema_version(),
        projects: snapshot.projects.len(),
        resources: snapshot.resources.len(),
        secrets: store_report.secrets,
        versions: store_report.versions,
        plaintext_bytes: store_report.plaintext_bytes,
    })
}

fn validate_catalog_store_references(
    snapshot: &floria_catalog::CatalogSnapshot,
    store: &StoreVerification,
) -> BackupResult<()> {
    let stored = store.secret_ids.iter().map(String::as_str).collect::<HashSet<_>>();
    let missing = snapshot
        .resources
        .iter()
        .filter_map(|resource| match &resource.source {
            ResourceSource::SecretRef { secret_id } if !stored.contains(secret_id.as_str()) => {
                Some(format!("{} -> {}", resource.id, secret_id))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(BackupError::Manifest(format!(
            "catalog resources reference missing encrypted secrets: {}",
            missing.join(", ")
        )))
    }
}

fn inventory_files(root: &Path) -> BackupResult<Vec<ManifestFile>> {
    let mut files = Vec::new();
    inventory_directory(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn inventory_directory(
    root: &Path,
    directory: &Path,
    files: &mut Vec<ManifestFile>,
) -> BackupResult<()> {
    let entries =
        std::fs::read_dir(directory).map_err(|source| BackupError::io(directory, source))?;
    for entry in entries {
        let entry = entry.map_err(|source| BackupError::io(directory, source))?;
        if directory == root && entry.file_name() == MANIFEST_FILE {
            continue;
        }
        let path = entry.path();
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|source| BackupError::io(&path, source))?;
        check_private_mode(&path, &metadata)?;
        if metadata.is_dir() {
            inventory_directory(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root).expect("inventory path stays below root");
            let mut input = File::open(&path).map_err(|source| BackupError::io(&path, source))?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count =
                    input.read(&mut buffer).map_err(|source| BackupError::io(&path, source))?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            files.push(ManifestFile {
                path: relative.to_string_lossy().into_owned(),
                size: metadata.len(),
                sha256: format!("{:x}", hasher.finalize()),
            });
        } else {
            return Err(BackupError::Manifest(format!(
                "unsupported filesystem entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn write_manifest(root: &Path, manifest: &BackupManifest) -> BackupResult<()> {
    let path = root.join(MANIFEST_FILE);
    let bytes = serde_json::to_vec_pretty(manifest)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|source| BackupError::io(&path, source))?;
    file.write_all(&bytes).map_err(|source| BackupError::io(&path, source))?;
    file.sync_all().map_err(|source| BackupError::io(&path, source))
}

fn copy_private_directory(source: &Path, destination: &Path) -> BackupResult<()> {
    let metadata =
        std::fs::symlink_metadata(source).map_err(|error| BackupError::io(source, error))?;
    if !metadata.is_dir() {
        return Err(BackupError::Manifest(format!(
            "backup entry is not a directory: {}",
            source.display()
        )));
    }
    DirBuilder::new()
        .mode(0o700)
        .create(destination)
        .map_err(|error| BackupError::io(destination, error))?;
    let entries = std::fs::read_dir(source).map_err(|error| BackupError::io(source, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| BackupError::io(source, error))?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata =
            std::fs::symlink_metadata(&from).map_err(|error| BackupError::io(&from, error))?;
        if metadata.is_dir() {
            copy_private_directory(&from, &to)?;
        } else if metadata.is_file() {
            copy_private_file(&from, &to)?;
        } else {
            return Err(BackupError::Manifest(format!(
                "backup contains unsupported filesystem entry: {}",
                from.display()
            )));
        }
    }
    File::open(destination)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| BackupError::io(destination, error))
}

fn copy_private_file(source: &Path, destination: &Path) -> BackupResult<()> {
    let metadata =
        std::fs::symlink_metadata(source).map_err(|error| BackupError::io(source, error))?;
    if !metadata.is_file() {
        return Err(BackupError::Manifest(format!(
            "backup entry is not a file: {}",
            source.display()
        )));
    }
    let mut input = File::open(source).map_err(|error| BackupError::io(source, error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|error| BackupError::io(destination, error))?;
    std::io::copy(&mut input, &mut output)
        .map_err(|error| BackupError::io(destination, error))?;
    output
        .sync_all()
        .map_err(|error| BackupError::io(destination, error))
}

fn check_private_directory(path: &Path) -> BackupResult<()> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| BackupError::io(path, source))?;
    if !metadata.is_dir() {
        return Err(BackupError::Manifest(format!(
            "backup is not a directory: {}",
            path.display()
        )));
    }
    check_private_mode(path, &metadata)
}

fn check_private_mode(path: &Path, metadata: &std::fs::Metadata) -> BackupResult<()> {
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(BackupError::Manifest(format!(
            "{} is accessible by group or others (mode {mode:04o})",
            path.display()
        )))
    }
}

impl BackupError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        BackupError::Io { path: path.into(), source }
    }
}

fn normalized_new_destination(destination: &Path) -> BackupResult<PathBuf> {
    let name = destination.file_name().ok_or_else(|| {
        BackupError::Manifest(format!(
            "backup destination must name a new directory: {}",
            destination.display()
        ))
    })?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|source| BackupError::io(parent, source))?;
    Ok(parent.join(name))
}

fn publish_without_overwrite(source: &Path, destination: &Path) -> BackupResult<()> {
    let source_c = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        BackupError::Manifest(format!("temporary path contains NUL: {}", source.display()))
    })?;
    let destination_c = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        BackupError::Manifest(format!("destination path contains NUL: {}", destination.display()))
    })?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the syscall. RENAME_EXCL is
    // the macOS atomic no-replace operation, closing the race between the initial existence check
    // and publication.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source_c.as_ptr(),
            libc::AT_FDCWD,
            destination_c.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(BackupError::io(destination, std::io::Error::last_os_error()))
    }
}

struct TemporaryBackup {
    path: PathBuf,
    published: bool,
}

impl TemporaryBackup {
    fn create(destination: &Path) -> BackupResult<Self> {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let name = destination.file_name().and_then(|name| name.to_str()).unwrap_or("backup");
        for attempt in 0..100u32 {
            let path = parent.join(format!(".{name}.floria-tmp-{}-{attempt}", std::process::id()));
            let result = DirBuilder::new().mode(0o700).create(&path);
            match result {
                Ok(()) => return Ok(Self { path, published: false }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(BackupError::io(&path, source)),
            }
        }
        Err(BackupError::Manifest(
            "could not allocate a temporary backup directory".to_string(),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn publish(&mut self) {
        self.published = true;
    }
}

impl Drop for TemporaryBackup {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use floria_catalog::{
        EntrySpec, Project, Resource, ResourceCodec, ResourceKind, ResourceOrigin, ResourceSource,
        ValueShape,
    };
    use floria_core::authz::Enforcement;
    use floria_core::metadata::ItemMetadata;
    use floria_store::{KeyProvider, NewSecret, SecretStore, StoreError, StoreResult};
    use std::sync::Arc;

    struct TestKeys(age::x25519::Identity);

    impl KeyProvider for TestKeys {
        #[allow(clippy::type_complexity)]
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.0.to_public())])
        }

        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    struct MissingIdentityKeys(age::x25519::Identity);

    impl KeyProvider for MissingIdentityKeys {
        #[allow(clippy::type_complexity)]
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.0.to_public())])
        }

        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            Err(StoreError::Key("fixture decryption key is unavailable".to_string()))
        }
    }

    fn fixture_store(root: &Path) -> AgeDirStore {
        AgeDirStore::open(
            root.to_path_buf(),
            Arc::new(TestKeys(age::x25519::Identity::generate())),
        )
        .unwrap()
    }

    /// The single digest-named version object of a backed-up store (format 5: objects live in
    /// the shared half, flat and content-addressed).
    fn version_blob_in(store_backup: &Path) -> PathBuf {
        let objects = store_backup.join("shared/objects");
        std::fs::read_dir(&objects)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| path.extension().is_some_and(|ext| ext == "age"))
            .expect("backup store has a version object")
    }

    fn fixture_resource(secret_id: String) -> Resource {
        Resource {
            id: "fixture-resource".to_string(),
            name: "Fixture".to_string(),
            kind: ResourceKind::SharedSecret,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: Some("FIXTURE_KEY".to_string()),
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: "FIXTURE_KEY".to_string(),
                key: Some("FIXTURE_KEY".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id },
            enforcement: Enforcement::Prompt,
            metadata: ItemMetadata::default(),
            origin: ResourceOrigin::default(),
        }
    }

    #[test]
    fn creates_and_reverifies_a_private_backup_without_plaintext() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: directory.path().join("project"),
                default_environment_id: None,
            })
            .unwrap();
        let store = fixture_store(&directory.path().join("store"));
        let id = store
            .put(NewSecret::managed("Fixture"), b"BACKUP_FIXTURE_VALUE=one\n")
            .unwrap();
        store.append_version(&id, b"BACKUP_FIXTURE_VALUE=two\n").unwrap();
        catalog.create_resource(&fixture_resource(id.to_string())).unwrap();
        let destination = directory.path().join("backup");

        let created = create(&catalog, &store, &destination).unwrap();
        let verified = verify(&destination, &store).unwrap();

        assert_eq!(created, verified);
        assert_eq!(verified.projects, 1);
        assert_eq!(verified.resources, 1);
        assert_eq!(verified.secrets, 1);
        assert_eq!(verified.versions, 2);
        assert_eq!(
            std::fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in inventory_files(&destination).unwrap() {
            let bytes = std::fs::read(destination.join(file.path)).unwrap();
            assert!(!bytes.windows(b"BACKUP_FIXTURE_VALUE".len()).any(|window| {
                window == b"BACKUP_FIXTURE_VALUE"
            }));
        }
    }

    #[test]
    fn checksum_rejects_a_tampered_ciphertext_before_it_is_trusted() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = fixture_store(&directory.path().join("store"));
        store.put(NewSecret::managed("Fixture"), b"fixture-value").unwrap();
        let destination = directory.path().join("backup");
        create(&catalog, &store, &destination).unwrap();
        let blob = version_blob_in(&destination.join(STORE_DIRECTORY));
        std::fs::write(&blob, b"tampered-ciphertext").unwrap();

        let error = verify(&destination, &store).unwrap_err();

        assert!(error.to_string().contains("checksum does not match"));
    }

    #[test]
    fn verification_requires_the_matching_decryption_key() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = fixture_store(&directory.path().join("store"));
        store.put(NewSecret::managed("Fixture"), b"fixture-value").unwrap();
        let destination = directory.path().join("backup");
        create(&catalog, &store, &destination).unwrap();
        let wrong_key_store = fixture_store(&directory.path().join("wrong-key-store"));

        let error = verify(&destination, &wrong_key_store).unwrap_err();

        assert!(matches!(error, BackupError::Store(_)));
    }

    #[test]
    fn verification_fails_closed_when_the_decryption_key_is_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = fixture_store(&directory.path().join("store"));
        store.put(NewSecret::managed("Fixture"), b"fixture-value").unwrap();
        let destination = directory.path().join("backup");
        create(&catalog, &store, &destination).unwrap();
        let unavailable_key_store = AgeDirStore::open(
            directory.path().join("unavailable-key-store"),
            Arc::new(MissingIdentityKeys(age::x25519::Identity::generate())),
        )
        .unwrap();

        let error = verify(&destination, &unavailable_key_store).unwrap_err();

        assert!(matches!(error, BackupError::Store(StoreError::Key(_))));
    }

    #[test]
    fn checksum_rejects_a_corrupted_catalog() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = fixture_store(&directory.path().join("store"));
        let destination = directory.path().join("backup");
        create(&catalog, &store, &destination).unwrap();
        std::fs::write(destination.join(CATALOG_FILE), b"corrupted-catalog").unwrap();

        let error = verify(&destination, &store).unwrap_err();

        assert!(error.to_string().contains("checksum does not match"));
    }

    #[test]
    fn storage_exhaustion_does_not_publish_or_leave_a_temporary_backup() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = fixture_store(&directory.path().join("store"));
        store.put(NewSecret::managed("Fixture"), b"fixture-value").unwrap();
        let destination = directory.path().join("backup");
        let store_lock = store.lock_for_maintenance().unwrap();

        let error = create_with_manifest_writer(
            &catalog,
            &store,
            &store_lock,
            &destination,
            |temporary, _| {
                Err(BackupError::io(
                    temporary.join(MANIFEST_FILE),
                    std::io::Error::from_raw_os_error(libc::ENOSPC),
                ))
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            BackupError::Io { source, .. } if source.raw_os_error() == Some(libc::ENOSPC)
        ));
        assert!(!destination.exists());
        assert!(!std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains("floria-tmp")));
    }

    #[test]
    fn missing_catalog_secret_aborts_without_publishing_a_partial_backup() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        catalog
            .create_resource(&fixture_resource(
                "00000000-0000-4000-8000-000000000001".to_string(),
            ))
            .unwrap();
        let store = fixture_store(&directory.path().join("store"));
        let destination = directory.path().join("backup");

        let error = create(&catalog, &store, &destination).unwrap_err();

        assert!(error.to_string().contains("reference missing encrypted secrets"));
        assert!(!destination.exists());
        assert!(!std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains("floria-tmp")));
    }

    #[test]
    fn existing_destination_is_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = fixture_store(&directory.path().join("store"));
        let destination = directory.path().join("backup");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("keep"), b"unchanged").unwrap();

        let error = create(&catalog, &store, &destination).unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read(destination.join("keep")).unwrap(), b"unchanged");
    }

    #[test]
    fn atomic_publication_refuses_a_destination_created_after_the_initial_check() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("temporary");
        let destination = directory.path().join("backup");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("new"), b"new").unwrap();
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("keep"), b"unchanged").unwrap();

        let error = publish_without_overwrite(&source, &destination).unwrap_err();

        assert!(matches!(error, BackupError::Io { .. }));
        assert!(source.exists());
        assert_eq!(std::fs::read(destination.join("keep")).unwrap(), b"unchanged");
    }

    #[test]
    fn refuses_to_create_a_backup_inside_the_live_store() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = fixture_store(&directory.path().join("store"));
        let destination = store.root().join("backups/fixture");
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();

        let error = create(&catalog, &store, &destination).unwrap_err();

        assert!(error.to_string().contains("inside the encrypted store"));
        assert!(!destination.exists());
    }

    #[test]
    fn restores_verified_data_into_a_new_standalone_directory() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: directory.path().join("project"),
                default_environment_id: None,
            })
            .unwrap();
        let store = fixture_store(&directory.path().join("store"));
        let id = store.put(NewSecret::managed("Fixture"), b"fixture-value").unwrap();
        catalog.create_resource(&fixture_resource(id.to_string())).unwrap();
        let backup = directory.path().join("backup");
        create(&catalog, &store, &backup).unwrap();
        let destination = directory.path().join("restored");

        let report = restore(&backup, &store, &destination).unwrap();

        assert_eq!(report.path, std::fs::canonicalize(&destination).unwrap());
        let snapshot = Catalog::inspect_backup(&destination.join(CATALOG_FILE)).unwrap();
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.resources.len(), 1);
        let restored = store.verify_backup(&destination.join(STORE_DIRECTORY)).unwrap();
        assert_eq!(restored.secrets, 1);
        assert_eq!(restored.versions, 1);
        assert!(!destination.join(MANIFEST_FILE).exists());
    }

    #[test]
    fn failed_restore_never_publishes_a_partial_destination() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let store = fixture_store(&directory.path().join("store"));
        store.put(NewSecret::managed("Fixture"), b"fixture-value").unwrap();
        let backup = directory.path().join("backup");
        create(&catalog, &store, &backup).unwrap();
        let blob = version_blob_in(&backup.join(STORE_DIRECTORY));
        std::fs::write(blob, b"tampered").unwrap();
        let destination = directory.path().join("restored");

        assert!(restore(&backup, &store, &destination).is_err());
        assert!(!destination.exists());
    }
}
