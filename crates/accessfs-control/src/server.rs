use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use accessfs_catalog::{
    Catalog, CatalogError, CatalogSnapshot, EntrySpec, Resource, ResourceCodec, ResourceKind,
    ResourceSource, ValueShape,
};
use accessfs_store::{NewSecret, SecretId, SecretOrigin, SecretRecord, SecretStore, StoreError};
use accessfs_surface::{decode_source, validate_secret_bytes};

use crate::protocol::{
    read_msg, write_msg, ControlCommand, ControlErrorBody, ControlOutcome, ControlRequest,
    ControlResponse, ControlResult, ProtectedFile,
};

pub struct ControlServer {
    socket_path: PathBuf,
}

pub trait CatalogObserver: Send + Sync + 'static {
    fn catalog_changed(&self, snapshot: &CatalogSnapshot);
}

impl ControlServer {
    /// Start the catalog control socket. Each connection gets a dedicated request loop;
    /// authorization prompts continue to use the separate agent socket.
    pub fn start(path: &Path, catalog: Catalog) -> io::Result<Self> {
        Self::start_inner(path, catalog, None, None, None)
    }

    pub fn start_observed(
        path: &Path,
        catalog: Catalog,
        observer: Arc<dyn CatalogObserver>,
    ) -> io::Result<Self> {
        Self::start_inner(path, catalog, None, None, Some(observer))
    }

    pub fn start_runtime(
        path: &Path,
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        mount_path: PathBuf,
        observer: Arc<dyn CatalogObserver>,
    ) -> io::Result<Self> {
        Self::start_inner(path, catalog, Some(store), Some(mount_path), Some(observer))
    }

    fn start_inner(
        path: &Path,
        catalog: Catalog,
        store: Option<Arc<dyn SecretStore>>,
        mount_path: Option<PathBuf>,
        observer: Option<Arc<dyn CatalogObserver>>,
    ) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

        let catalog = Arc::new(catalog);
        std::thread::Builder::new()
            .name("accessfs-control-accept".to_string())
            .spawn(move || accept_loop(listener, catalog, store, mount_path, observer))?;

        Ok(ControlServer { socket_path: path.to_path_buf() })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

fn accept_loop(
    listener: UnixListener,
    catalog: Arc<Catalog>,
    store: Option<Arc<dyn SecretStore>>,
    mount_path: Option<PathBuf>,
    observer: Option<Arc<dyn CatalogObserver>>,
) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "control socket accept failed");
                continue;
            }
        };
        if !same_uid(&stream) {
            tracing::warn!("rejecting control connection from a different uid");
            continue;
        }
        let catalog = Arc::clone(&catalog);
        let store = store.clone();
        let mount_path = mount_path.clone();
        let observer = observer.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("accessfs-control-conn".to_string())
            .spawn(move || handle_connection(stream, catalog, store, mount_path, observer))
        {
            tracing::warn!(%error, "spawning control connection failed");
        }
    }
}

fn handle_connection(
    mut stream: UnixStream,
    catalog: Arc<Catalog>,
    store: Option<Arc<dyn SecretStore>>,
    mount_path: Option<PathBuf>,
    observer: Option<Arc<dyn CatalogObserver>>,
) {
    loop {
        let request: ControlRequest = match read_msg(&mut stream) {
            Ok(request) => request,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                tracing::warn!(%error, "invalid control request");
                break;
            }
        };
        let mutates_catalog = mutates_catalog(&request.command);
        let outcome = match dispatch(
            &catalog,
            store.as_deref(),
            mount_path.as_deref(),
            request.command,
        ) {
            Ok(result) => {
                if mutates_catalog {
                    notify_observer(&catalog, observer.as_deref());
                }
                ControlOutcome::Ok { result }
            }
            Err(error) => ControlOutcome::Error { error: error.body() },
        };
        if let Err(error) = write_msg(
            &mut stream,
            &ControlResponse { request_id: request.request_id, outcome },
        ) {
            tracing::warn!(%error, "writing control response failed");
            break;
        }
    }
}

fn mutates_catalog(command: &ControlCommand) -> bool {
    matches!(
        command,
        ControlCommand::ProjectUpsert { .. }
            | ControlCommand::ProjectCreate { .. }
            | ControlCommand::ProjectRemove { .. }
            | ControlCommand::EnvironmentUpsert { .. }
            | ControlCommand::EnvironmentRemove { .. }
            | ControlCommand::ResourceUpsert { .. }
            | ControlCommand::ResourceRemove { .. }
            | ControlCommand::BindingUpsert { .. }
            | ControlCommand::BindingRemove { .. }
            | ControlCommand::SurfaceUpsert { .. }
            | ControlCommand::SurfaceRemove { .. }
            | ControlCommand::SharedSecretCreate { .. }
            | ControlCommand::EnvFileCreate { .. }
    )
}

fn notify_observer(catalog: &Catalog, observer: Option<&dyn CatalogObserver>) {
    let Some(observer) = observer else { return };
    match catalog.snapshot() {
        Ok(snapshot) => observer.catalog_changed(&snapshot),
        Err(error) => tracing::warn!(%error, "loading catalog snapshot for observer failed"),
    }
}

#[derive(Debug)]
enum DispatchError {
    Catalog(CatalogError),
    Store(StoreError),
    Io { path: PathBuf, source: io::Error },
    Validation(String),
    StoreUnavailable,
}

impl DispatchError {
    fn body(&self) -> ControlErrorBody {
        match self {
            DispatchError::Catalog(error) => ControlErrorBody::from(error),
            DispatchError::Store(error) => ControlErrorBody::from(error),
            DispatchError::Io { path, source } => ControlErrorBody {
                code: "io".to_string(),
                message: format!("I/O error on {}: {source}", path.display()),
            },
            DispatchError::Validation(message) => ControlErrorBody {
                code: "validation".to_string(),
                message: message.clone(),
            },
            DispatchError::StoreUnavailable => ControlErrorBody {
                code: "secret_store_unavailable".to_string(),
                message: "secret store is unavailable on this control server".to_string(),
            },
        }
    }
}

impl From<CatalogError> for DispatchError {
    fn from(error: CatalogError) -> Self {
        DispatchError::Catalog(error)
    }
}

impl From<StoreError> for DispatchError {
    fn from(error: StoreError) -> Self {
        DispatchError::Store(error)
    }
}

fn dispatch(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
    command: ControlCommand,
) -> Result<ControlResult, DispatchError> {
    match command {
        ControlCommand::Ping => {
            Ok(ControlResult::Pong { schema_version: catalog.schema_version() })
        }
        ControlCommand::Snapshot => Ok(ControlResult::Snapshot(catalog.snapshot()?)),
        ControlCommand::ProtectedFiles => protected_files(
            store.ok_or(DispatchError::StoreUnavailable)?,
        ),
        ControlCommand::FileProtect { path } => protect_file(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            &path,
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
        } => create_shared_secret(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            name,
            default_env_key,
            value,
        ),
        ControlCommand::SharedSecretRotate { resource_id, value } => rotate_shared_secret(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            value,
        ),
        ControlCommand::EnvFileCreate { resource_id, name, codec, value } => create_env_file(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            name,
            codec,
            value,
        ),
        ControlCommand::ProjectCreate { project, environment, surface } => {
            create_project_workspace(catalog, project, environment, surface)
        }
        ControlCommand::ProjectUpsert { project } => {
            catalog.upsert_project(&project)?;
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
        ControlCommand::ResourceUpsert { resource } => {
            catalog.validate_resource(&resource)?;
            validate_resource_value(catalog, store, &resource)?;
            catalog.upsert_resource(&resource)?;
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

fn create_project_workspace(
    catalog: &Catalog,
    project: accessfs_catalog::Project,
    environment: accessfs_catalog::Environment,
    surface: accessfs_catalog::Surface,
) -> Result<ControlResult, DispatchError> {
    if environment.project_id != project.id {
        return Err(DispatchError::Validation(format!(
            "environment project {:?} does not match project {:?}",
            environment.project_id, project.id
        )));
    }
    if surface.environment_id != environment.id {
        return Err(DispatchError::Validation(format!(
            "surface environment {:?} does not match environment {:?}",
            surface.environment_id, environment.id
        )));
    }

    let snapshot = catalog.snapshot()?;
    for (kind, id, exists) in [
        ("project", &project.id, snapshot.projects.iter().any(|item| item.id == project.id)),
        (
            "environment",
            &environment.id,
            snapshot.environments.iter().any(|item| item.id == environment.id),
        ),
        ("surface", &surface.id, snapshot.surfaces.iter().any(|item| item.id == surface.id)),
    ] {
        if exists {
            return Err(DispatchError::Catalog(CatalogError::AlreadyExists {
                kind,
                id: id.clone(),
            }));
        }
    }

    catalog.upsert_project(&project)?;
    if let Err(error) = catalog.upsert_environment(&environment) {
        rollback_project_create(catalog, &project.id);
        return Err(DispatchError::Catalog(error));
    }
    if let Err(error) = catalog.upsert_surface(&surface) {
        rollback_project_create(catalog, &project.id);
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::Empty)
}

fn protected_files(store: &dyn SecretStore) -> Result<ControlResult, DispatchError> {
    let mut files = store
        .list()?
        .into_iter()
        .filter_map(protected_file)
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left.source_path.cmp(&right.source_path));
    Ok(ControlResult::ProtectedFiles(files))
}

fn protected_file(record: SecretRecord) -> Option<ProtectedFile> {
    let SecretOrigin::File { source_path } = record.origin else { return None };
    Some(ProtectedFile {
        id: record.id.to_string(),
        source_path,
        mode: record.mode,
        size: record.size,
        current_version: record.current_version,
    })
}

fn protect_file(
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
            file: protected_file(record).expect("file lookup returns a file-origin record"),
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
        file: protected_file(record).expect("new file protection has file-origin metadata"),
        created,
    })
}

fn canonical_source_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "protected file path has no file name")
    })?;
    Ok(std::fs::canonicalize(parent)?.join(name))
}

fn replace_file_with_symlink(path: &Path, target: &Path) -> io::Result<()> {
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

fn rollback_project_create(catalog: &Catalog, project_id: &str) {
    if let Err(error) = catalog.remove_project(project_id) {
        tracing::warn!(%project_id, %error, "rolling back project create failed");
    }
}

fn create_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    default_env_key: Option<String>,
    value: crate::protocol::SecretValue,
) -> Result<ControlResult, DispatchError> {
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
        detail: None,
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

    let secret_id = store.put(NewSecret::managed(resource.name.clone()), value.as_bytes())?;
    resource.source = ResourceSource::SecretRef { secret_id: secret_id.to_string() };
    if let Err(error) = catalog.create_resource(&resource) {
        if let Err(cleanup_error) = store.delete(&secret_id) {
            tracing::warn!(%secret_id, %cleanup_error, "cleaning up unreferenced shared secret failed");
        }
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::SharedSecretCreated { resource, version: 1 })
}

fn validate_resource_value(
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

fn validate_snapshot_values(
    snapshot: &CatalogSnapshot,
    store: Option<&dyn SecretStore>,
) -> Result<(), DispatchError> {
    let Some(store) = store else { return Ok(()) };
    let mut validated = std::collections::HashSet::new();
    for resource in &snapshot.resources {
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

fn rotate_shared_secret(
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

fn create_env_file(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    codec: ResourceCodec,
    value: crate::protocol::SecretValue,
) -> Result<ControlResult, DispatchError> {
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
        detail: None,
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

    let secret_id = store.put(NewSecret::managed(resource.name.clone()), value.as_bytes())?;
    resource.source = ResourceSource::SecretRef { secret_id: secret_id.to_string() };
    if let Err(error) = catalog.create_resource(&resource) {
        if let Err(cleanup_error) = store.delete(&secret_id) {
            tracing::warn!(%secret_id, %cleanup_error, "cleaning up unreferenced env file failed");
        }
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::EnvFileCreated { resource, version: 1 })
}

fn same_uid(stream: &UnixStream) -> bool {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: valid socket fd and writable stack out-parameters.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    // SAFETY: geteuid has no preconditions.
    result == 0 && uid == unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use accessfs_catalog::SurfaceInput;
    use crate::client::ControlClient;
    use accessfs_catalog::{Environment, Project, Surface, SurfaceKind};
    use accessfs_store::{
        SecretOrigin, SecretRecord, StoreResult, VersionRecord,
    };
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    const FIXTURE_SECRET_ID: &str = "00000000-0000-0000-0000-000000000101";

    struct FixtureStore {
        entries: Mutex<HashMap<String, Vec<Vec<u8>>>>,
        metadata: Mutex<HashMap<String, (SecretOrigin, u32)>>,
    }

    impl FixtureStore {
        fn new() -> Self {
            FixtureStore {
                entries: Mutex::new(HashMap::new()),
                metadata: Mutex::new(HashMap::new()),
            }
        }
    }

    impl SecretStore for FixtureStore {
        fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId> {
            if let SecretOrigin::Managed { label } = &meta.origin {
                assert!(matches!(
                    label.as_str(),
                    "Fixture Shared Secret" | "Fixture Env File" | "Fixture INI File"
                ));
            }
            let id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
            self.entries
                .lock()
                .unwrap()
                .insert(id.to_string(), vec![plaintext.to_vec()]);
            self.metadata
                .lock()
                .unwrap()
                .insert(id.to_string(), (meta.origin, meta.mode));
            Ok(id)
        }

        fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            Ok(Zeroizing::new(entries[id.as_str()].last().unwrap().clone()))
        }

        fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            Ok(Zeroizing::new(entries[id.as_str()][(version - 1) as usize].clone()))
        }

        fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
            let mut entries = self.entries.lock().unwrap();
            let versions = entries.get_mut(id.as_str()).unwrap();
            versions.push(plaintext.to_vec());
            Ok(versions.len() as u32)
        }

        fn history(&self, _id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            unimplemented!()
        }

        fn set_head(&self, _id: &SecretId, _version: u32) -> StoreResult<()> {
            unimplemented!()
        }

        fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            let metadata = self.metadata.lock().unwrap();
            Ok(entries.get(id.as_str()).map(|versions| SecretRecord {
                id: id.clone(),
                origin: metadata[id.as_str()].0.clone(),
                mode: metadata[id.as_str()].1,
                size: versions.last().unwrap().len() as u64,
                created: "fixture-time".to_string(),
                current_version: versions.len() as u32,
            }))
        }

        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            let metadata = self.metadata.lock().unwrap();
            Ok(entries
                .iter()
                .map(|(id, versions)| SecretRecord {
                    id: id.parse().unwrap(),
                    origin: metadata[id].0.clone(),
                    mode: metadata[id].1,
                    size: versions.last().unwrap().len() as u64,
                    created: "fixture-time".to_string(),
                    current_version: versions.len() as u32,
                })
                .collect())
        }

        fn get_by_path(&self, source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            let id = self
                .metadata
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, (origin, _))| match origin {
                    SecretOrigin::File { source_path: candidate }
                        if candidate == source_path => Some(id.clone()),
                    _ => None,
                });
            match id {
                Some(id) => self.record(&id.parse().unwrap()),
                None => Ok(None),
            }
        }

        fn delete(&self, id: &SecretId) -> StoreResult<()> {
            self.entries.lock().unwrap().remove(id.as_str());
            self.metadata.lock().unwrap().remove(id.as_str());
            Ok(())
        }
    }

    struct SnapshotObserver {
        notifications: AtomicUsize,
        latest: Mutex<Option<CatalogSnapshot>>,
    }

    impl CatalogObserver for SnapshotObserver {
        fn catalog_changed(&self, snapshot: &CatalogSnapshot) {
            self.notifications.fetch_add(1, Ordering::Relaxed);
            *self.latest.lock().unwrap() = Some(snapshot.clone());
        }
    }

    #[test]
    fn client_can_mutate_and_snapshot_catalog_over_separate_socket() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let server = ControlServer::start(&socket, catalog).unwrap();
        assert_eq!(
            std::fs::metadata(server.socket_path()).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut client = ControlClient::connect(&socket).unwrap();
        assert_eq!(
            client.request(ControlCommand::Ping).unwrap(),
            ControlResult::Pong { schema_version: 4 }
        );
        client
            .request(ControlCommand::ProjectUpsert {
                project: Project {
                    id: "floria".to_string(),
                    name: "floria".to_string(),
                    path: PathBuf::from("/workspace/floria"),
                },
            })
            .unwrap();
        client
            .request(ControlCommand::EnvironmentUpsert {
                environment: Environment {
                    id: "development".to_string(),
                    project_id: "floria".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                },
            })
            .unwrap();

        let ControlResult::Snapshot(snapshot) =
            client.request(ControlCommand::Snapshot).unwrap()
        else {
            panic!("expected snapshot");
        };
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.environments.len(), 1);
    }

    #[test]
    fn project_create_builds_workspace_with_one_observer_notification() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_observed(
            &socket,
            catalog.clone(),
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        client
            .request(ControlCommand::ProjectCreate {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                },
                environment: Environment {
                    id: "fixture-development".to_string(),
                    project_id: "fixture-project".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                },
                surface: Surface {
                    id: "fixture-dotenv".to_string(),
                    environment_id: "fixture-development".to_string(),
                    name: ".env".to_string(),
                    kind: SurfaceKind::DotenvFile,
                    path: PathBuf::from("/fixture/project/.env"),
                    input: SurfaceInput::Bindings { binding_ids: Vec::new() },
                    position: 0,
                },
            })
            .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.environments.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn project_create_rolls_back_when_surface_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let _server = ControlServer::start(&socket, catalog.clone()).unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let error = client
            .request(ControlCommand::ProjectCreate {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                },
                environment: Environment {
                    id: "fixture-development".to_string(),
                    project_id: "fixture-project".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                },
                surface: Surface {
                    id: "fixture-dotenv".to_string(),
                    environment_id: "fixture-development".to_string(),
                    name: ".env".to_string(),
                    kind: SurfaceKind::DotenvFile,
                    path: PathBuf::from("/outside/.env"),
                    input: SurfaceInput::Bindings { binding_ids: Vec::new() },
                    position: 0,
                },
            })
            .unwrap_err();

        assert!(error.to_string().contains("validation"));
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.projects.is_empty());
        assert!(snapshot.environments.is_empty());
        assert!(snapshot.surfaces.is_empty());
    }

    #[test]
    fn validation_error_returns_structured_control_error() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let _server = ControlServer::start(&socket, catalog).unwrap();
        let mut stream = UnixStream::connect(&socket).unwrap();
        write_msg(
            &mut stream,
            &ControlRequest {
                request_id: 11,
                command: ControlCommand::ProjectUpsert {
                    project: Project {
                        id: "bad project".to_string(),
                        name: "Bad".to_string(),
                        path: PathBuf::from("relative"),
                    },
                },
            },
        )
        .unwrap();
        let response: ControlResponse = read_msg(&mut stream).unwrap();
        assert_eq!(response.request_id, 11);
        match response.outcome {
            ControlOutcome::Error { error } => assert_eq!(error.code, "validation"),
            ControlOutcome::Ok { .. } => panic!("expected validation error"),
        }
    }

    #[test]
    fn successful_mutation_refreshes_observer_but_queries_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_observed(
            &socket,
            catalog,
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        client.request(ControlCommand::Ping).unwrap();
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 0);
        client
            .request(ControlCommand::ProjectUpsert {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                },
            })
            .unwrap();
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
        assert_eq!(
            observer.latest.lock().unwrap().as_ref().unwrap().projects[0].id,
            "fixture-project"
        );
    }

    #[test]
    fn shared_secret_create_and_rotate_over_ipc_only_store_reference_in_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        let observer: Arc<dyn CatalogObserver> = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            dir.path().join("mount"),
            observer,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::SharedSecretCreate {
                resource_id: "fixture-shared-secret".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("FIXTURE_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("fixture-value-one"),
            })
            .unwrap();
        assert!(matches!(
            created,
            ControlResult::SharedSecretCreated { version: 1, .. }
        ));
        let resource = catalog.resource("fixture-shared-secret").unwrap();
        assert_eq!(
            resource.source,
            ResourceSource::SecretRef { secret_id: FIXTURE_SECRET_ID.to_string() }
        );
        assert!(!serde_json::to_string(&catalog.snapshot().unwrap())
            .unwrap()
            .contains("fixture-value-one"));

        let rotated = client
            .request(ControlCommand::SharedSecretRotate {
                resource_id: "fixture-shared-secret".to_string(),
                value: crate::protocol::SecretValue::new("fixture-value-two"),
            })
            .unwrap();
        assert_eq!(
            rotated,
            ControlResult::SharedSecretRotated {
                resource_id: "fixture-shared-secret".to_string(),
                version: 2,
            }
        );
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(store.get_version(&secret_id, 1).unwrap().as_slice(), b"fixture-value-one");
        assert_eq!(store.get_version(&secret_id, 2).unwrap().as_slice(), b"fixture-value-two");
    }

    #[test]
    fn protects_an_existing_file_at_its_original_path_and_lists_it() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let mount = dir.path().join("mount");
        let source = dir.path().join(".envrc");
        std::fs::write(&source, "export FIXTURE_VALUE='fixture-value'\n").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let canonical_source = canonical_source_path(&source).unwrap();
        let store = Arc::new(FixtureStore::new());
        let observer: Arc<dyn CatalogObserver> = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog,
            Arc::clone(&store) as Arc<dyn SecretStore>,
            mount.clone(),
            observer,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let protected = client
            .request(ControlCommand::FileProtect { path: source.clone() })
            .unwrap();
        let ControlResult::FileProtected { file, created } = protected else {
            panic!("expected protected file result");
        };
        assert!(created);
        assert_eq!(file.source_path, canonical_source);
        assert_eq!(file.mode, 0o600);
        assert_eq!(file.current_version, 1);
        assert!(std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(&source).unwrap(),
            mount.join(accessfs_core::config::SECRETS_DIR).join(FIXTURE_SECRET_ID)
        );
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(
            store.get(&secret_id).unwrap().as_slice(),
            b"export FIXTURE_VALUE='fixture-value'\n"
        );

        let listed = client.request(ControlCommand::ProtectedFiles).unwrap();
        let ControlResult::ProtectedFiles(files) = listed else {
            panic!("expected protected files result");
        };
        assert_eq!(files, vec![file.clone()]);

        assert_eq!(
            client
                .request(ControlCommand::FileProtect { path: source })
                .unwrap(),
            ControlResult::FileProtected { file, created: false }
        );
    }

    #[test]
    fn env_file_create_parses_keys_and_only_stores_a_reference_in_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        let observer: Arc<dyn CatalogObserver> = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            dir.path().join("mount"),
            observer,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::EnvFileCreate {
                resource_id: "fixture-env-file".to_string(),
                name: "Fixture Env File".to_string(),
                codec: ResourceCodec::Dotenv,
                value: crate::protocol::SecretValue::new(
                    "API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n",
                ),
            })
            .unwrap();
        let ControlResult::EnvFileCreated { resource, version } = created else {
            panic!("expected env file creation result");
        };
        assert_eq!(version, 1);
        assert_eq!(resource.kind, ResourceKind::EnvFile);
        assert_eq!(resource.codec, ResourceCodec::Dotenv);
        assert_eq!(
            resource.entries.iter().filter_map(|entry| entry.key.as_deref()).collect::<Vec<_>>(),
            vec!["API_HOST", "LOG_LEVEL"]
        );
        let ResourceSource::SecretRef { secret_id } = resource.source else {
            panic!("expected a store reference");
        };
        let id: SecretId = secret_id.parse().unwrap();
        assert_eq!(
            store.get(&id).unwrap().as_slice(),
            b"API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n"
        );
        let encoded = serde_json::to_string(&catalog.snapshot().unwrap()).unwrap();
        assert!(!encoded.contains("127.0.0.1"));
        assert!(!encoded.contains("LOG_LEVEL=debug"));
    }

    #[test]
    fn ini_env_file_create_exposes_ordered_section_entries_without_storing_values_in_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        let observer: Arc<dyn CatalogObserver> = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            dir.path().join("mount"),
            observer,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::EnvFileCreate {
                resource_id: "fixture-ini-file".to_string(),
                name: "Fixture INI File".to_string(),
                codec: ResourceCodec::Ini,
                value: crate::protocol::SecretValue::new(
                    "[fixture-one]\nregion=fixture-region\noutput=fixture-output\n[fixture-two]\nregion=fixture-region-two\n",
                ),
            })
            .unwrap();
        let ControlResult::EnvFileCreated { resource, version } = created else {
            panic!("expected env file creation result");
        };

        assert_eq!(version, 1);
        assert_eq!(resource.codec, ResourceCodec::Ini);
        assert_eq!(
            resource.entries.iter().map(|entry| entry.address.as_str()).collect::<Vec<_>>(),
            vec![
                "sections/fixture-one/keys/region",
                "sections/fixture-one/keys/output",
                "sections/fixture-two/keys/region",
            ]
        );
        assert_eq!(resource.entries[0].label, "[fixture-one] region");
        let encoded = serde_json::to_string(&catalog.snapshot().unwrap()).unwrap();
        assert!(!encoded.contains("fixture-region-two"));
        assert!(!encoded.contains("fixture-output"));
    }

}
