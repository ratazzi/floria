use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use floria_catalog::Catalog;
use floria_store::AgeDirStore;
use serde::{Deserialize, Serialize};

use super::{
    copy_private_directory, copy_private_file, create_with_locked_store,
    validate_catalog_store_references, verify, verify_restored_data, BackupError, BackupReport,
    BackupResult, CATALOG_FILE, STORE_DIRECTORY,
};

const ACTIVATION_FORMAT: u32 = 1;
const ACTIVATION_JOURNAL: &str = ".restore-state.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationReport {
    pub active: BackupReport,
    pub safety_backup: BackupReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ActivationJournal {
    format: u32,
    active_catalog: PathBuf,
    staged_catalog: PathBuf,
    old_catalog: FileIdentity,
    restored_catalog: FileIdentity,
    active_store: PathBuf,
    staged_store: PathBuf,
    old_store: FileIdentity,
    restored_store: FileIdentity,
    safety_backup: PathBuf,
}

/// Replace the inactive catalog and encrypted store with a verified standalone restore.
///
/// The caller must prevent the daemon from starting and ensure the mount is inactive. This
/// function additionally holds the store's cross-process mutation lock, creates a verified safety
/// backup, and records enough inode identity to finish an interrupted two-path switch.
pub fn activate_restored_data(
    restored: &Path,
    active_catalog: &Path,
    store: &AgeDirStore,
    safety_backup: &Path,
) -> BackupResult<ActivationReport> {
    let expected = verify_restored_data(restored, store)?;
    let active_catalog = canonical_existing_file(active_catalog)?;
    let active_store = canonical_existing_directory(store.root())?;
    let journal_path = activation_journal_path(&active_catalog)?;
    if journal_path.exists() {
        return Err(BackupError::Manifest(format!(
            "an interrupted restore must be recovered first: {}",
            journal_path.display()
        )));
    }

    let store_lock = store.lock_for_maintenance()?;
    let safety = {
        let catalog = Catalog::open(&active_catalog)?;
        create_with_locked_store(&catalog, store, &store_lock, safety_backup)?
    };

    let mut staged = StagedActivation::new(&active_catalog, &active_store)?;
    copy_private_file(
        &expected.path.join(CATALOG_FILE),
        staged.catalog_path(),
    )?;
    copy_private_directory(
        &expected.path.join(STORE_DIRECTORY),
        staged.store_path(),
    )?;
    let active_store_lock = staged.active_store().join(".lock");
    let staged_store_lock = staged.store_path().join(".lock");
    std::fs::hard_link(&active_store_lock, &staged_store_lock)
        .map_err(|source| BackupError::io(&staged_store_lock, source))?;
    let staged_report = verify_components(staged.catalog_path(), staged.store_path(), store)?;
    ensure_same_data(&expected, &staged_report)?;

    let journal = ActivationJournal {
        format: ACTIVATION_FORMAT,
        active_catalog,
        staged_catalog: staged.catalog_path().to_path_buf(),
        old_catalog: file_identity(staged.active_catalog())?,
        restored_catalog: file_identity(staged.catalog_path())?,
        active_store,
        staged_store: staged.store_path().to_path_buf(),
        old_store: file_identity(staged.active_store())?,
        restored_store: file_identity(staged.store_path())?,
        safety_backup: safety.path.clone(),
    };
    write_journal(&journal_path, &journal)?;
    staged.keep_for_recovery();

    match finish_activation(&journal, store) {
        Ok(active) => {
            finalize_activation(&journal_path, &journal)?;
            Ok(ActivationReport {
                active,
                safety_backup: safety,
            })
        }
        Err(activation_error) => {
            let rollback = rollback_activation(&journal, store);
            if rollback.is_ok() {
                remove_journal(&journal_path)?;
            }
            match rollback {
                Ok(()) => Err(BackupError::Manifest(format!(
                    "restore activation failed and the previous data was restored: \
                     {activation_error}"
                ))),
                Err(rollback_error) => Err(BackupError::Manifest(format!(
                    "restore activation failed ({activation_error}); automatic rollback also \
                     failed ({rollback_error}); keep the safety backup at {} and restart Floria \
                     to retry recovery",
                    journal.safety_backup.display()
                ))),
            }
        }
    }
}

/// Finish a restore transaction left by an interrupted activation.
///
/// Returns `None` when no journal exists. Recovery always moves both paths toward the explicitly
/// requested restored data, verifies the resulting pair, and rolls back both paths if that
/// verification fails.
pub fn recover_interrupted_activation(
    active_catalog: &Path,
    store: &AgeDirStore,
) -> BackupResult<Option<ActivationReport>> {
    let active_catalog = canonical_existing_file(active_catalog)?;
    let active_store = canonical_existing_directory(store.root())?;
    let journal_path = activation_journal_path(&active_catalog)?;
    if !journal_path.exists() {
        return Ok(None);
    }
    let journal = read_journal(&journal_path)?;
    validate_journal_paths(&journal, &active_catalog, &active_store)?;
    let _store_lock = store.lock_for_maintenance()?;

    match finish_activation(&journal, store) {
        Ok(active) => {
            let safety_backup = verify(&journal.safety_backup, store)?;
            finalize_activation(&journal_path, &journal)?;
            Ok(Some(ActivationReport {
                active,
                safety_backup,
            }))
        }
        Err(activation_error) => {
            let rollback = rollback_activation(&journal, store);
            if rollback.is_ok() {
                remove_journal(&journal_path)?;
            }
            match rollback {
                Ok(()) => Err(BackupError::Manifest(format!(
                    "interrupted restore could not be completed; previous data was restored: \
                     {activation_error}"
                ))),
                Err(rollback_error) => Err(BackupError::Manifest(format!(
                    "interrupted restore failed ({activation_error}) and rollback failed \
                     ({rollback_error}); recover from {} before starting Floria",
                    journal.safety_backup.display()
                ))),
            }
        }
    }
}

fn finish_activation(
    journal: &ActivationJournal,
    store: &AgeDirStore,
) -> BackupResult<BackupReport> {
    ensure_restored_at_active_path(
        &journal.active_catalog,
        &journal.staged_catalog,
        journal.old_catalog,
        journal.restored_catalog,
    )?;
    ensure_restored_at_active_path(
        &journal.active_store,
        &journal.staged_store,
        journal.old_store,
        journal.restored_store,
    )?;
    verify_components(&journal.active_catalog, &journal.active_store, store)
}

fn finalize_activation(
    journal_path: &Path,
    journal: &ActivationJournal,
) -> BackupResult<()> {
    remove_old_staged_data(journal)?;
    remove_journal(journal_path)
}

fn rollback_activation(
    journal: &ActivationJournal,
    store: &AgeDirStore,
) -> BackupResult<()> {
    ensure_old_at_active_path(
        &journal.active_catalog,
        &journal.staged_catalog,
        journal.old_catalog,
        journal.restored_catalog,
    )?;
    ensure_old_at_active_path(
        &journal.active_store,
        &journal.staged_store,
        journal.old_store,
        journal.restored_store,
    )?;
    verify_components(&journal.active_catalog, &journal.active_store, store)?;
    remove_restored_staged_data(journal)
}

fn ensure_restored_at_active_path(
    active: &Path,
    staged: &Path,
    old: FileIdentity,
    restored: FileIdentity,
) -> BackupResult<()> {
    match file_identity(active)? {
        identity if identity == restored => Ok(()),
        identity if identity == old => {
            if file_identity(staged)? != restored {
                return Err(BackupError::Manifest(format!(
                    "restore staging identity changed: {}",
                    staged.display()
                )));
            }
            rename_swap(active, staged)
        }
        _ => Err(BackupError::Manifest(format!(
            "active restore path changed unexpectedly: {}",
            active.display()
        ))),
    }
}

fn ensure_old_at_active_path(
    active: &Path,
    staged: &Path,
    old: FileIdentity,
    restored: FileIdentity,
) -> BackupResult<()> {
    match file_identity(active)? {
        identity if identity == old => Ok(()),
        identity if identity == restored => {
            if file_identity(staged)? != old {
                return Err(BackupError::Manifest(format!(
                    "previous data staging identity changed: {}",
                    staged.display()
                )));
            }
            rename_swap(active, staged)
        }
        _ => Err(BackupError::Manifest(format!(
            "active restore path changed unexpectedly: {}",
            active.display()
        ))),
    }
}

fn rename_swap(left: &Path, right: &Path) -> BackupResult<()> {
    let left_c = std::ffi::CString::new(left.as_os_str().as_bytes()).map_err(|_| {
        BackupError::Manifest(format!("restore path contains NUL: {}", left.display()))
    })?;
    let right_c = std::ffi::CString::new(right.as_os_str().as_bytes()).map_err(|_| {
        BackupError::Manifest(format!("restore path contains NUL: {}", right.display()))
    })?;
    // SAFETY: both C strings remain valid for the syscall. RENAME_SWAP atomically exchanges the
    // two entries on their shared volume.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            left_c.as_ptr(),
            libc::AT_FDCWD,
            right_c.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result != 0 {
        return Err(BackupError::io(
            left,
            std::io::Error::last_os_error(),
        ));
    }
    sync_parent(left)?;
    if left.parent() != right.parent() {
        sync_parent(right)?;
    }
    Ok(())
}

fn verify_components(
    catalog_path: &Path,
    store_path: &Path,
    store: &AgeDirStore,
) -> BackupResult<BackupReport> {
    let snapshot = Catalog::inspect_backup(catalog_path)?;
    let store_report = store.verify_backup(store_path)?;
    validate_catalog_store_references(&snapshot, &store_report)?;
    Ok(BackupReport {
        path: catalog_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf(),
        catalog_schema: Catalog::current_schema_version(),
        projects: snapshot.projects.len(),
        resources: snapshot.resources.len(),
        secrets: store_report.secrets,
        versions: store_report.versions,
        plaintext_bytes: store_report.plaintext_bytes,
        files: 1 + count_store_files(store_path)?,
    })
}

fn count_store_files(directory: &Path) -> BackupResult<usize> {
    let mut files = 0usize;
    for entry in
        std::fs::read_dir(directory).map_err(|source| BackupError::io(directory, source))?
    {
        let entry = entry.map_err(|source| BackupError::io(directory, source))?;
        if entry.file_name() == ".lock" {
            continue;
        }
        let path = entry.path();
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|source| BackupError::io(&path, source))?;
        if metadata.is_dir() {
            files = files.saturating_add(count_store_files(&path)?);
        } else if metadata.is_file() {
            files = files.saturating_add(1);
        } else {
            return Err(BackupError::Manifest(format!(
                "active store contains unsupported filesystem entry: {}",
                path.display()
            )));
        }
    }
    Ok(files)
}

fn ensure_same_data(expected: &BackupReport, actual: &BackupReport) -> BackupResult<()> {
    if expected.catalog_schema == actual.catalog_schema
        && expected.projects == actual.projects
        && expected.resources == actual.resources
        && expected.secrets == actual.secrets
        && expected.versions == actual.versions
        && expected.plaintext_bytes == actual.plaintext_bytes
    {
        Ok(())
    } else {
        Err(BackupError::Manifest(
            "staged restore does not match the verified standalone data".to_string(),
        ))
    }
}

fn activation_journal_path(active_catalog: &Path) -> BackupResult<PathBuf> {
    let parent = active_catalog.parent().ok_or_else(|| {
        BackupError::Manifest(format!(
            "active catalog has no parent directory: {}",
            active_catalog.display()
        ))
    })?;
    Ok(parent.join(ACTIVATION_JOURNAL))
}

fn write_journal(path: &Path, journal: &ActivationJournal) -> BackupResult<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(journal)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|source| BackupError::io(&temporary, source))?;
    output
        .write_all(&bytes)
        .map_err(|source| BackupError::io(&temporary, source))?;
    output
        .sync_all()
        .map_err(|source| BackupError::io(&temporary, source))?;
    std::fs::rename(&temporary, path).map_err(|source| BackupError::io(path, source))?;
    sync_parent(path)
}

fn read_journal(path: &Path) -> BackupResult<ActivationJournal> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| BackupError::io(path, source))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(BackupError::Manifest(format!(
            "restore journal must be a private regular file: {}",
            path.display()
        )));
    }
    let journal: ActivationJournal = serde_json::from_slice(
        &std::fs::read(path).map_err(|source| BackupError::io(path, source))?,
    )?;
    if journal.format != ACTIVATION_FORMAT {
        return Err(BackupError::Manifest(format!(
            "restore journal format {} is unsupported",
            journal.format
        )));
    }
    Ok(journal)
}

fn validate_journal_paths(
    journal: &ActivationJournal,
    active_catalog: &Path,
    active_store: &Path,
) -> BackupResult<()> {
    let catalog_parent = active_catalog.parent();
    let store_parent = active_store.parent();
    let catalog_stage_valid = journal.staged_catalog.parent() == catalog_parent
        && journal
            .staged_catalog
            .file_name()
            .is_some_and(|name| name.as_bytes().starts_with(b".catalog.sqlite.floria-restore-"));
    let store_stage_valid = journal.staged_store.parent() == store_parent
        && journal
            .staged_store
            .file_name()
            .is_some_and(|name| name.as_bytes().starts_with(b".store.floria-restore-"));
    if journal.active_catalog == active_catalog
        && journal.active_store == active_store
        && catalog_stage_valid
        && store_stage_valid
    {
        Ok(())
    } else {
        Err(BackupError::Manifest(
            "restore journal paths do not match the configured active data".to_string(),
        ))
    }
}

fn remove_old_staged_data(journal: &ActivationJournal) -> BackupResult<()> {
    remove_file_if_present(&journal.staged_catalog)?;
    remove_directory_if_present(&journal.staged_store)
}

fn remove_restored_staged_data(journal: &ActivationJournal) -> BackupResult<()> {
    remove_file_if_present(&journal.staged_catalog)?;
    remove_directory_if_present(&journal.staged_store)
}

fn remove_file_if_present(path: &Path) -> BackupResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BackupError::io(path, error)),
    }
}

fn remove_directory_if_present(path: &Path) -> BackupResult<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BackupError::io(path, error)),
    }
}

fn remove_journal(path: &Path) -> BackupResult<()> {
    remove_file_if_present(path)
}

fn sync_parent(path: &Path) -> BackupResult<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| BackupError::io(parent, source))
}

fn file_identity(path: &Path) -> BackupResult<FileIdentity> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| BackupError::io(path, source))?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn canonical_existing_file(path: &Path) -> BackupResult<PathBuf> {
    let path = std::fs::canonicalize(path).map_err(|source| BackupError::io(path, source))?;
    if path.is_file() {
        Ok(path)
    } else {
        Err(BackupError::Manifest(format!(
            "active catalog is not a regular file: {}",
            path.display()
        )))
    }
}

fn canonical_existing_directory(path: &Path) -> BackupResult<PathBuf> {
    let path = std::fs::canonicalize(path).map_err(|source| BackupError::io(path, source))?;
    if path.is_dir() {
        Ok(path)
    } else {
        Err(BackupError::Manifest(format!(
            "active store is not a directory: {}",
            path.display()
        )))
    }
}

struct StagedActivation {
    active_catalog: PathBuf,
    active_store: PathBuf,
    catalog: PathBuf,
    store: PathBuf,
    keep: bool,
}

impl StagedActivation {
    fn new(active_catalog: &Path, active_store: &Path) -> BackupResult<Self> {
        let catalog_parent = active_catalog.parent().ok_or_else(|| {
            BackupError::Manifest("active catalog has no parent directory".to_string())
        })?;
        let store_parent = active_store.parent().ok_or_else(|| {
            BackupError::Manifest("active store has no parent directory".to_string())
        })?;
        for attempt in 0..100u32 {
            let suffix = format!("{}-{attempt}", std::process::id());
            let catalog =
                catalog_parent.join(format!(".catalog.sqlite.floria-restore-{suffix}"));
            let store = store_parent.join(format!(".store.floria-restore-{suffix}"));
            if !catalog.exists() && !store.exists() {
                return Ok(Self {
                    active_catalog: active_catalog.to_path_buf(),
                    active_store: active_store.to_path_buf(),
                    catalog,
                    store,
                    keep: false,
                });
            }
        }
        Err(BackupError::Manifest(
            "could not allocate restore staging paths".to_string(),
        ))
    }

    fn active_catalog(&self) -> &Path {
        &self.active_catalog
    }

    fn active_store(&self) -> &Path {
        &self.active_store
    }

    fn catalog_path(&self) -> &Path {
        &self.catalog
    }

    fn store_path(&self) -> &Path {
        &self.store
    }

    fn keep_for_recovery(&mut self) {
        self.keep = true;
    }
}

impl Drop for StagedActivation {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.catalog);
            let _ = std::fs::remove_dir_all(&self.store);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use floria_catalog::Project;
    use floria_store::{
        KeyProvider, NewSecret, SecretStore, StoreResult,
    };

    use super::*;
    use crate::{create, restore};

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

    fn open_store(root: &Path, keys: &Arc<dyn KeyProvider>) -> AgeDirStore {
        AgeDirStore::open(root.to_path_buf(), Arc::clone(keys)).unwrap()
    }

    fn project(id: &str, root: &Path) -> Project {
        Project {
            id: id.to_string(),
            name: id.to_string(),
            path: root.join(id),
            default_environment_id: None,
        }
    }

    struct ActivationFixture {
        _directory: tempfile::TempDir,
        active_catalog: PathBuf,
        active_store: AgeDirStore,
        restored: PathBuf,
        safety_backup: PathBuf,
    }

    fn fixture() -> ActivationFixture {
        let directory = tempfile::tempdir().unwrap();
        let keys: Arc<dyn KeyProvider> =
            Arc::new(TestKeys(age::x25519::Identity::generate()));
        let active_catalog = directory.path().join("support/catalog.sqlite");
        std::fs::create_dir_all(active_catalog.parent().unwrap()).unwrap();
        Catalog::open(&active_catalog)
            .unwrap()
            .upsert_project(&project("old-project", directory.path()))
            .unwrap();
        let active_store = open_store(&directory.path().join("active-store"), &keys);
        active_store
            .put(NewSecret::managed("Old"), b"old-fixture-value")
            .unwrap();

        std::fs::create_dir_all(directory.path().join("source")).unwrap();
        let source_catalog = Catalog::open(directory.path().join("source/catalog.sqlite")).unwrap();
        source_catalog
            .upsert_project(&project("restored-project", directory.path()))
            .unwrap();
        let source_store = open_store(&directory.path().join("source/store"), &keys);
        source_store
            .put(NewSecret::managed("Restored"), b"restored-fixture-value")
            .unwrap();
        let backup = directory.path().join("source-backup");
        create(&source_catalog, &source_store, &backup).unwrap();
        let restored = directory.path().join("standalone-restored");
        restore(&backup, &active_store, &restored).unwrap();

        let safety_backup = directory.path().join("safety-backup");
        ActivationFixture {
            _directory: directory,
            active_catalog,
            active_store,
            restored,
            safety_backup,
        }
    }

    #[test]
    fn activates_both_paths_and_keeps_a_verified_safety_backup() {
        let fixture = fixture();

        let report = activate_restored_data(
            &fixture.restored,
            &fixture.active_catalog,
            &fixture.active_store,
            &fixture.safety_backup,
        )
        .unwrap();

        let active = Catalog::inspect_backup(&fixture.active_catalog).unwrap();
        assert_eq!(active.projects[0].id, "restored-project");
        assert_eq!(
            fixture.active_store.list().unwrap()[0].display_name(),
            "Restored"
        );
        assert_eq!(report.safety_backup.projects, 1);
        assert_eq!(
            verify(&fixture.safety_backup, &fixture.active_store)
                .unwrap()
                .projects,
            1
        );
        assert!(!activation_journal_path(&fixture.active_catalog)
            .unwrap()
            .exists());
    }

    #[test]
    fn recovery_finishes_a_crash_after_only_the_catalog_swap() {
        let fixture = fixture();
        let expected = verify_restored_data(&fixture.restored, &fixture.active_store).unwrap();
        let safety = {
            let catalog = Catalog::open(&fixture.active_catalog).unwrap();
            create(
                &catalog,
                &fixture.active_store,
                &fixture.safety_backup,
            )
            .unwrap()
        };
        let active_catalog = std::fs::canonicalize(&fixture.active_catalog).unwrap();
        let active_store = std::fs::canonicalize(fixture.active_store.root()).unwrap();
        let journal_path = activation_journal_path(&active_catalog).unwrap();
        let staged_catalog =
            active_catalog.parent().unwrap().join(".catalog.sqlite.floria-restore-test");
        let staged_store =
            active_store.parent().unwrap().join(".store.floria-restore-test");
        let store_lock = fixture.active_store.lock_for_maintenance().unwrap();
        copy_private_file(
            &expected.path.join(CATALOG_FILE),
            &staged_catalog,
        )
        .unwrap();
        copy_private_directory(
            &expected.path.join(STORE_DIRECTORY),
            &staged_store,
        )
        .unwrap();
        std::fs::hard_link(active_store.join(".lock"), staged_store.join(".lock")).unwrap();
        let journal = ActivationJournal {
            format: ACTIVATION_FORMAT,
            active_catalog: active_catalog.clone(),
            staged_catalog: staged_catalog.clone(),
            old_catalog: file_identity(&active_catalog).unwrap(),
            restored_catalog: file_identity(&staged_catalog).unwrap(),
            active_store: active_store.clone(),
            staged_store: staged_store.clone(),
            old_store: file_identity(&active_store).unwrap(),
            restored_store: file_identity(&staged_store).unwrap(),
            safety_backup: safety.path,
        };
        write_journal(&journal_path, &journal).unwrap();
        rename_swap(&active_catalog, &staged_catalog).unwrap();
        drop(store_lock);

        let report = recover_interrupted_activation(
            &fixture.active_catalog,
            &fixture.active_store,
        )
        .unwrap()
        .unwrap();

        assert_eq!(report.active.projects, 1);
        assert_eq!(
            Catalog::inspect_backup(&fixture.active_catalog)
                .unwrap()
                .projects[0]
                .id,
            "restored-project"
        );
        assert_eq!(
            fixture.active_store.list().unwrap()[0].display_name(),
            "Restored"
        );
        assert!(!journal_path.exists());
        assert!(!staged_catalog.exists());
        assert!(!staged_store.exists());
    }
}
