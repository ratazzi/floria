use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use accessfs_catalog::{
    Catalog, CatalogError, CatalogSnapshot, EntrySpec, ItemMetadata, Resource, ResourceCodec,
    ResourceKind, ResourceSource, ValueShape,
};
use accessfs_core::authz::{Enforcement, PolicyMode, PolicyModeStatus};
use accessfs_ssh::ManagedKeyError;
use accessfs_store::{NewSecret, SecretId, SecretOrigin, SecretRecord, SecretStore, StoreError};
use accessfs_surface::{decode_source, validate_secret_bytes};

use crate::protocol::{
    read_msg, write_msg, ControlCommand, ControlErrorBody, ControlOutcome, ControlRequest,
    ControlResponse, ControlResult, ProtectedFile, ProtectedFileVersion, SshConfigStatus,
    SshIdentity,
};

pub struct ControlServer {
    socket_path: PathBuf,
}

pub trait CatalogObserver: Send + Sync + 'static {
    fn catalog_changed(&self, snapshot: &CatalogSnapshot);
}

/// Runtime policy seam used by the local control plane. Production adapts the live
/// `SocketAgent`; tests can supply an in-memory adapter without starting FUSE or an agent socket.
pub trait RuntimePolicyController: Send + Sync + 'static {
    fn policy_mode(&self) -> PolicyModeStatus;
    fn set_policy_mode(
        &self,
        mode: PolicyMode,
        duration_secs: Option<u64>,
    ) -> io::Result<PolicyModeStatus>;
}

/// Read-only seam for enumerating public keys from an upstream SSH agent. The protocol and server
/// own the public DTO while production delegates SSH framing to `accessfs-agent`.
pub trait SshIdentityDiscovery: Send + Sync + 'static {
    fn discover(&self, endpoint: &Path) -> io::Result<Vec<SshIdentity>>;
}

/// Narrow seam for the explicit, user-triggered integration with `~/.ssh/config`.
pub trait SshConfigManager: Send + Sync + 'static {
    fn status(&self) -> io::Result<SshConfigStatus>;
    fn install(&self) -> io::Result<SshConfigStatus>;
    fn remove(&self) -> io::Result<SshConfigStatus>;
}

pub struct ControlRuntimeServices {
    pub observer: Arc<dyn CatalogObserver>,
    pub policy: Arc<dyn RuntimePolicyController>,
    pub ssh_discovery: Arc<dyn SshIdentityDiscovery>,
    pub ssh_config: Arc<dyn SshConfigManager>,
}

#[derive(Clone, Default)]
struct ControlDependencies {
    store: Option<Arc<dyn SecretStore>>,
    mount_path: Option<PathBuf>,
    observer: Option<Arc<dyn CatalogObserver>>,
    policy: Option<Arc<dyn RuntimePolicyController>>,
    ssh_discovery: Option<Arc<dyn SshIdentityDiscovery>>,
    ssh_config: Option<Arc<dyn SshConfigManager>>,
}

impl ControlServer {
    /// Start the catalog control socket. Each connection gets a dedicated request loop;
    /// authorization prompts continue to use the separate agent socket.
    pub fn start(path: &Path, catalog: Catalog) -> io::Result<Self> {
        Self::start_inner(path, catalog, ControlDependencies::default())
    }

    pub fn start_observed(
        path: &Path,
        catalog: Catalog,
        observer: Arc<dyn CatalogObserver>,
    ) -> io::Result<Self> {
        Self::start_inner(
            path,
            catalog,
            ControlDependencies { observer: Some(observer), ..ControlDependencies::default() },
        )
    }

    pub fn start_runtime(
        path: &Path,
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        mount_path: PathBuf,
        observer: Arc<dyn CatalogObserver>,
    ) -> io::Result<Self> {
        Self::start_inner(
            path,
            catalog,
            ControlDependencies {
                store: Some(store),
                mount_path: Some(mount_path),
                observer: Some(observer),
                ..ControlDependencies::default()
            },
        )
    }

    pub fn start_runtime_with_policy(
        path: &Path,
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        mount_path: PathBuf,
        observer: Arc<dyn CatalogObserver>,
        policy: Arc<dyn RuntimePolicyController>,
    ) -> io::Result<Self> {
        Self::start_inner(
            path,
            catalog,
            ControlDependencies {
                store: Some(store),
                mount_path: Some(mount_path),
                observer: Some(observer),
                policy: Some(policy),
                ..ControlDependencies::default()
            },
        )
    }


    pub fn start_runtime_with_services(
        path: &Path,
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        mount_path: PathBuf,
        services: ControlRuntimeServices,
    ) -> io::Result<Self> {
        Self::start_inner(
            path,
            catalog,
            ControlDependencies {
                store: Some(store),
                mount_path: Some(mount_path),
                observer: Some(services.observer),
                policy: Some(services.policy),
                ssh_discovery: Some(services.ssh_discovery),
                ssh_config: Some(services.ssh_config),
            },
        )
    }

    fn start_inner(
        path: &Path,
        catalog: Catalog,
        dependencies: ControlDependencies,
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
            .spawn(move || {
                accept_loop(listener, catalog, dependencies)
            })?;

        Ok(ControlServer { socket_path: path.to_path_buf() })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

fn accept_loop(
    listener: UnixListener,
    catalog: Arc<Catalog>,
    dependencies: ControlDependencies,
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
        let dependencies = dependencies.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("accessfs-control-conn".to_string())
            .spawn(move || {
                handle_connection(stream, catalog, dependencies)
            })
        {
            tracing::warn!(%error, "spawning control connection failed");
        }
    }
}

fn handle_connection(
    mut stream: UnixStream,
    catalog: Arc<Catalog>,
    dependencies: ControlDependencies,
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
        let changes_runtime = changes_runtime(&request.command);
        let outcome = match dispatch(
            &catalog,
            dependencies.store.as_deref(),
            dependencies.mount_path.as_deref(),
            dependencies.policy.as_deref(),
            dependencies.ssh_discovery.as_deref(),
            dependencies.ssh_config.as_deref(),
            request.command,
        ) {
            Ok(result) => {
                if changes_runtime {
                    notify_observer(&catalog, dependencies.observer.as_deref());
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

fn changes_runtime(command: &ControlCommand) -> bool {
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
            | ControlCommand::SharedSecretUpdate { .. }
            | ControlCommand::SharedSecretRemove { .. }
            | ControlCommand::SshIdentityImport { .. }
            | ControlCommand::SshIdentityRemove { .. }
            | ControlCommand::EnvFileCreate { .. }
            | ControlCommand::ResourceMetadataUpdate { .. }
            | ControlCommand::FileProtect { .. }
            | ControlCommand::ProtectedFileMetadataUpdate { .. }
            | ControlCommand::FileRestore { .. }
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
    SshKey(ManagedKeyError),
    Io { path: PathBuf, source: io::Error },
    Policy(io::Error),
    SshConfig(io::Error),
    Validation(String),
    StoreUnavailable,
}

struct ManagedItemSettings {
    enforcement: Enforcement,
    metadata: ItemMetadata,
}

impl DispatchError {
    fn body(&self) -> ControlErrorBody {
        match self {
            DispatchError::Catalog(error) => ControlErrorBody::from(error),
            DispatchError::Store(error) => ControlErrorBody::from(error),
            DispatchError::SshKey(error) => ControlErrorBody {
                code: "ssh_key".to_string(),
                message: error.to_string(),
            },
            DispatchError::Io { path, source } => ControlErrorBody {
                code: "io".to_string(),
                message: format!("I/O error on {}: {source}", path.display()),
            },
            DispatchError::Validation(message) => ControlErrorBody {
                code: "validation".to_string(),
                message: message.clone(),
            },
            DispatchError::Policy(error) => ControlErrorBody {
                code: if error.kind() == io::ErrorKind::InvalidInput {
                    "validation".to_string()
                } else {
                    "policy_io".to_string()
                },
                message: error.to_string(),
            },
            DispatchError::SshConfig(error) => ControlErrorBody {
                code: if error.kind() == io::ErrorKind::InvalidInput {
                    "validation".to_string()
                } else {
                    "ssh_config_io".to_string()
                },
                message: error.to_string(),
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

impl From<ManagedKeyError> for DispatchError {
    fn from(error: ManagedKeyError) -> Self {
        DispatchError::SshKey(error)
    }
}

fn dispatch(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    mount_path: Option<&Path>,
    policy: Option<&dyn RuntimePolicyController>,
    ssh_discovery: Option<&dyn SshIdentityDiscovery>,
    ssh_config: Option<&dyn SshConfigManager>,
    command: ControlCommand,
) -> Result<ControlResult, DispatchError> {
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
        ControlCommand::Snapshot => Ok(ControlResult::Snapshot(catalog.snapshot()?)),
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

fn protected_files(
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

fn protected_file(record: SecretRecord, mount_path: &Path) -> Option<ProtectedFile> {
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

fn protected_file_history(
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

fn update_protected_file_metadata(
    store: &dyn SecretStore,
    id: &str,
    enforcement: Enforcement,
    metadata: ItemMetadata,
) -> Result<ControlResult, DispatchError> {
    let (id, _) = file_record(store, id)?;
    store.update_settings(&id, metadata, enforcement)?;
    Ok(ControlResult::Empty)
}

fn rollback_protected_file(
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

fn restore_file(
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

fn file_record(
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

fn canonical_source_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "protected file path has no file name")
    })?;
    Ok(std::fs::canonicalize(parent)?.join(name))
}

fn replace_symlink_with_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
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

fn import_ssh_identity(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    path: &Path,
    passphrase: Option<&crate::protocol::SecretValue>,
    settings: ManagedItemSettings,
) -> Result<ControlResult, DispatchError> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(DispatchError::Validation(
            "SSH identity name cannot be empty".to_string(),
        ));
    }
    if !path.is_absolute() {
        return Err(DispatchError::Validation(format!(
            "SSH private key path {} must be absolute",
            path.display()
        )));
    }
    accessfs_core::config::check_secure_perms(path)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    let encoded = zeroize::Zeroizing::new(
        std::fs::read(path).map_err(|source| DispatchError::Io {
            path: path.to_path_buf(),
            source,
        })?,
    );
    let imported = accessfs_ssh::import_private_key(
        &encoded,
        passphrase.map(crate::protocol::SecretValue::as_bytes),
    )?;
    let ManagedItemSettings { enforcement, metadata } = settings;
    let mut resource = Resource {
        id: resource_id,
        name: name.clone(),
        kind: ResourceKind::SshIdentity,
        shape: ValueShape::SshIdentity,
        codec: ResourceCodec::Opaque,
        default_env_key: None,
        entries: vec![EntrySpec {
            address: imported.identity.address.clone(),
            label: name.clone(),
            key: None,
            sensitive: false,
        }],
        source: ResourceSource::SecretRef {
            secret_id: "pending-managed-private-key".to_string(),
        },
        enforcement,
        metadata,
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

    let secret_id = store.put(NewSecret::managed(name), imported.as_bytes())?;
    resource.source = ResourceSource::SecretRef { secret_id: secret_id.to_string() };
    if let Err(error) = catalog.create_resource(&resource) {
        if let Err(cleanup_error) = store.delete(&secret_id) {
            tracing::warn!(%secret_id, %cleanup_error, "cleaning up unreferenced SSH private key failed");
        }
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::SshIdentityCreated { resource })
}

fn remove_ssh_identity(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
) -> Result<ControlResult, DispatchError> {
    let resource = catalog.resource(&resource_id)?;
    if resource.kind != ResourceKind::SshIdentity {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a managed SSH identity"
        )));
    }
    let ResourceSource::SecretRef { secret_id } = &resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored private key"
        )));
    };
    let secret_id: SecretId = secret_id.parse()?;
    catalog.remove_resource(&resource_id)?;
    if let Err(error) = store.delete(&secret_id) {
        if let Err(restore_error) = catalog.create_resource(&resource) {
            tracing::error!(
                %resource_id,
                %error,
                %restore_error,
                "SSH identity storage deletion failed and catalog rollback also failed"
            );
        }
        return Err(DispatchError::Store(error));
    }
    Ok(ControlResult::Empty)
}

fn create_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    default_env_key: Option<String>,
    value: crate::protocol::SecretValue,
    settings: ManagedItemSettings,
) -> Result<ControlResult, DispatchError> {
    let ManagedItemSettings { enforcement, metadata } = settings;
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
        enforcement,
        metadata,
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

fn update_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    default_env_key: Option<String>,
    value: Option<crate::protocol::SecretValue>,
    settings: ManagedItemSettings,
) -> Result<ControlResult, DispatchError> {
    let ManagedItemSettings { enforcement, metadata } = settings;
    if value.as_ref().is_some_and(|value| value.as_bytes().is_empty()) {
        return Err(DispatchError::Validation(
            "shared secret value cannot be empty".to_string(),
        ));
    }
    let original = catalog.resource(&resource_id)?;
    let mut resource = original.clone();
    if resource.kind != ResourceKind::SharedSecret {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a shared secret"
        )));
    }
    if resource.entries.len() != 1 || resource.entries[0].address != "value" {
        return Err(DispatchError::Validation(format!(
            "shared secret {resource_id:?} does not have exactly one value entry"
        )));
    }

    resource.name = name;
    resource.default_env_key = default_env_key.clone();
    resource.entries[0].label = resource.name.clone();
    resource.entries[0].key = default_env_key;
    resource.enforcement = enforcement;
    resource.metadata = metadata;
    catalog.validate_resource(&resource)?;
    validate_resource_value(catalog, Some(store), &resource)?;
    let ResourceSource::SecretRef { secret_id } = &resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored secret"
        )));
    };
    let secret_id: SecretId = secret_id.parse()?;
    if let Some(value) = &value {
        let mut snapshot = catalog.snapshot()?;
        let existing = snapshot
            .resources
            .iter_mut()
            .find(|item| item.id == resource.id)
            .expect("the updated shared secret was loaded from this catalog");
        *existing = resource.clone();
        validate_secret_bytes(&snapshot, secret_id.as_str(), value.as_bytes())
            .map_err(|error| DispatchError::Validation(error.to_string()))?;
    }

    catalog.upsert_resource(&resource)?;
    if let Some(value) = value {
        if let Err(error) = store.append_version(&secret_id, value.as_bytes()) {
            if let Err(restore_error) = catalog.upsert_resource(&original) {
                tracing::error!(
                    %resource_id,
                    %error,
                    %restore_error,
                    "shared secret rotation failed and catalog rollback also failed"
                );
            }
            return Err(DispatchError::Store(error));
        }
    }
    Ok(ControlResult::Empty)
}

fn remove_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
) -> Result<ControlResult, DispatchError> {
    let resource = catalog.resource(&resource_id)?;
    if resource.kind != ResourceKind::SharedSecret {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a shared secret"
        )));
    }
    let ResourceSource::SecretRef { secret_id } = &resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored secret"
        )));
    };
    let secret_id: SecretId = secret_id.parse()?;

    catalog.remove_resource(&resource_id)?;
    if let Err(error) = store.delete(&secret_id) {
        if let Err(restore_error) = catalog.create_resource(&resource) {
            tracing::error!(
                %resource_id,
                %error,
                %restore_error,
                "shared secret storage deletion failed and catalog rollback also failed"
            );
        }
        return Err(DispatchError::Store(error));
    }
    Ok(ControlResult::Empty)
}

fn validate_snapshot_values(
    snapshot: &CatalogSnapshot,
    store: Option<&dyn SecretStore>,
) -> Result<(), DispatchError> {
    let Some(store) = store else { return Ok(()) };
    let mut validated = std::collections::HashSet::new();
    for resource in &snapshot.resources {
        if resource.kind == ResourceKind::SshIdentity {
            continue;
        }
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
    settings: ManagedItemSettings,
) -> Result<ControlResult, DispatchError> {
    let ManagedItemSettings { enforcement, metadata } = settings;
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
        enforcement,
        metadata,
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

fn update_resource_metadata(
    catalog: &Catalog,
    resource_id: &str,
    name: String,
    enforcement: Enforcement,
    metadata: ItemMetadata,
) -> Result<ControlResult, DispatchError> {
    let mut resource = catalog.resource(resource_id)?;
    resource.name = name;
    resource.enforcement = enforcement;
    resource.metadata = metadata;
    if resource.kind == ResourceKind::SharedSecret && resource.entries.len() == 1 {
        resource.entries[0].label = resource.name.clone();
    }
    catalog.upsert_resource(&resource)?;
    Ok(ControlResult::Empty)
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
    use accessfs_catalog::{
        Binding, BindingScope, EntrySelection, Environment, ItemLink, Project, Surface, SurfaceKind,
    };
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
        metadata: Mutex<HashMap<String, (SecretOrigin, u32, ItemMetadata)>>,
        heads: Mutex<HashMap<String, u32>>,
    }

    impl FixtureStore {
        fn new() -> Self {
            FixtureStore {
                entries: Mutex::new(HashMap::new()),
                metadata: Mutex::new(HashMap::new()),
                heads: Mutex::new(HashMap::new()),
            }
        }
    }

    impl SecretStore for FixtureStore {
        fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId> {
            if let SecretOrigin::Managed { label } = &meta.origin {
                assert!(matches!(
                    label.as_str(),
                    "Fixture Shared Secret"
                        | "Fixture Env File"
                        | "Fixture INI File"
                        | "Fixture SSH Identity"
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
                .insert(id.to_string(), (meta.origin, meta.mode, ItemMetadata::default()));
            self.heads.lock().unwrap().insert(id.to_string(), 1);
            Ok(id)
        }

        fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            let head = self.heads.lock().unwrap()[id.as_str()];
            Ok(Zeroizing::new(entries[id.as_str()][(head - 1) as usize].clone()))
        }

        fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            Ok(Zeroizing::new(entries[id.as_str()][(version - 1) as usize].clone()))
        }

        fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
            let mut entries = self.entries.lock().unwrap();
            let versions = entries.get_mut(id.as_str()).unwrap();
            versions.push(plaintext.to_vec());
            let version = versions.len() as u32;
            self.heads.lock().unwrap().insert(id.to_string(), version);
            Ok(version)
        }

        fn history(&self, id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            let entries = self.entries.lock().unwrap();
            Ok(entries[id.as_str()]
                .iter()
                .enumerate()
                .map(|(index, value)| VersionRecord {
                    version: index as u32 + 1,
                    size: value.len() as u64,
                    created: format!("fixture-time-{}", index + 1),
                    note: None,
                })
                .collect())
        }

        fn set_head(&self, id: &SecretId, version: u32) -> StoreResult<()> {
            let entries = self.entries.lock().unwrap();
            if version == 0 || version as usize > entries[id.as_str()].len() {
                return Err(StoreError::NotFound(format!("version {version}")));
            }
            drop(entries);
            self.heads.lock().unwrap().insert(id.to_string(), version);
            Ok(())
        }

        fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            let metadata = self.metadata.lock().unwrap();
            let heads = self.heads.lock().unwrap();
            Ok(entries.get(id.as_str()).map(|versions| SecretRecord {
                id: id.clone(),
                origin: metadata[id.as_str()].0.clone(),
                mode: metadata[id.as_str()].1,
                size: versions[(heads[id.as_str()] - 1) as usize].len() as u64,
                created: "fixture-time".to_string(),
                current_version: heads[id.as_str()],
                enforcement: Enforcement::Prompt,
                metadata: metadata[id.as_str()].2.clone(),
            }))
        }

        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            let metadata = self.metadata.lock().unwrap();
            let heads = self.heads.lock().unwrap();
            Ok(entries
                .iter()
                .map(|(id, versions)| SecretRecord {
                    id: id.parse().unwrap(),
                    origin: metadata[id].0.clone(),
                    mode: metadata[id].1,
                    size: versions[(heads[id] - 1) as usize].len() as u64,
                    created: "fixture-time".to_string(),
                    current_version: heads[id],
                    enforcement: Enforcement::Prompt,
                    metadata: metadata[id].2.clone(),
                })
                .collect())
        }

        fn get_by_path(&self, source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            let id = self
                .metadata
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, (origin, _, _))| match origin {
                    SecretOrigin::File { source_path: candidate }
                        if candidate == source_path => Some(id.clone()),
                    _ => None,
                });
            match id {
                Some(id) => self.record(&id.parse().unwrap()),
                None => Ok(None),
            }
        }

        fn update_settings(
            &self,
            id: &SecretId,
            item_metadata: ItemMetadata,
            _enforcement: Enforcement,
        ) -> StoreResult<()> {
            self.metadata.lock().unwrap().get_mut(id.as_str()).unwrap().2 = item_metadata;
            Ok(())
        }

        fn delete(&self, id: &SecretId) -> StoreResult<()> {
            self.entries.lock().unwrap().remove(id.as_str());
            self.metadata.lock().unwrap().remove(id.as_str());
            self.heads.lock().unwrap().remove(id.as_str());
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

    struct FixturePolicy {
        status: Mutex<PolicyModeStatus>,
    }

    struct FixtureSshDiscovery;

    impl SshIdentityDiscovery for FixtureSshDiscovery {
        fn discover(&self, endpoint: &Path) -> io::Result<Vec<SshIdentity>> {
            Ok(vec![SshIdentity {
                address: "ssh/sha256/fixture-address".to_string(),
                fingerprint: "SHA256:fixture-fingerprint".to_string(),
                comment: endpoint.display().to_string(),
            }])
        }
    }

    impl RuntimePolicyController for FixturePolicy {
        fn policy_mode(&self) -> PolicyModeStatus {
            *self.status.lock().unwrap()
        }

        fn set_policy_mode(
            &self,
            mode: PolicyMode,
            duration_secs: Option<u64>,
        ) -> io::Result<PolicyModeStatus> {
            let status = PolicyModeStatus {
                mode,
                expires_at: duration_secs.map(|seconds| 1_800_000_000 + seconds as i64),
            };
            *self.status.lock().unwrap() = status;
            Ok(status)
        }
    }

    #[test]
    fn policy_mode_roundtrips_through_the_control_seam() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let policy: Arc<dyn RuntimePolicyController> = Arc::new(FixturePolicy {
            status: Mutex::new(PolicyModeStatus::default()),
        });
        let _server = ControlServer::start_inner(
            &socket,
            catalog,
            ControlDependencies { policy: Some(policy), ..ControlDependencies::default() },
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        assert_eq!(
            client.request(ControlCommand::PolicyModeGet).unwrap(),
            ControlResult::PolicyMode(PolicyModeStatus::default())
        );
        assert_eq!(
            client
                .request(ControlCommand::PolicyModeSet {
                    mode: PolicyMode::AuditOnly,
                    duration_secs: Some(3600),
                })
                .unwrap(),
            ControlResult::PolicyMode(PolicyModeStatus {
                mode: PolicyMode::AuditOnly,
                expires_at: Some(1_800_003_600),
            })
        );
    }

    #[test]
    fn ssh_identity_discovery_roundtrips_public_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let discovery: Arc<dyn SshIdentityDiscovery> = Arc::new(FixtureSshDiscovery);
        let _server = ControlServer::start_inner(
            &socket,
            catalog,
            ControlDependencies {
                ssh_discovery: Some(discovery),
                ..ControlDependencies::default()
            },
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();
        let endpoint = dir.path().join("upstream.sock");

        assert_eq!(
            client
                .request(ControlCommand::SshAgentDiscover { endpoint: endpoint.clone() })
                .unwrap(),
            ControlResult::SshAgentIdentities(vec![SshIdentity {
                address: "ssh/sha256/fixture-address".to_string(),
                fingerprint: "SHA256:fixture-fingerprint".to_string(),
                comment: endpoint.display().to_string(),
            }])
        );
    }

    #[test]
    fn managed_ssh_identity_lifecycle_keeps_private_key_out_of_catalog() {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, LineEnding, PrivateKey};

        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("fixture-id_ed25519");
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        std::fs::write(
            &source_path,
            private_key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&source_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            dir.path().join("mount"),
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::SshIdentityImport {
                resource_id: "fixture-ssh-identity".to_string(),
                name: "Fixture SSH Identity".to_string(),
                path: source_path,
                passphrase: None,
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            })
            .unwrap();
        let ControlResult::SshIdentityCreated { resource } = created else {
            panic!("expected managed SSH identity result");
        };
        assert_eq!(resource.kind, ResourceKind::SshIdentity);
        assert_eq!(resource.shape, ValueShape::SshIdentity);
        assert_eq!(resource.entries.len(), 1);
        assert!(resource.entries[0].address.starts_with("ssh/sha256/"));
        assert_eq!(
            resource.source,
            ResourceSource::SecretRef { secret_id: FIXTURE_SECRET_ID.to_string() }
        );
        let catalog_json = serde_json::to_string(&catalog.snapshot().unwrap()).unwrap();
        assert!(!catalog_json.contains("OPENSSH PRIVATE KEY"));
        let stored = store.get(&FIXTURE_SECRET_ID.parse().unwrap()).unwrap();
        let stored_identity = accessfs_ssh::identity_from_private_key(&stored).unwrap();
        assert_eq!(stored_identity.address, resource.entries[0].address);
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);

        assert_eq!(
            client
                .request(ControlCommand::SshIdentityRemove {
                    resource_id: resource.id,
                })
                .unwrap(),
            ControlResult::Empty
        );
        assert!(catalog.snapshot().unwrap().resources.is_empty());
        assert!(store.record(&FIXTURE_SECRET_ID.parse().unwrap()).unwrap().is_none());
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn ssh_config_integration_roundtrips_through_the_control_seam() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let user_config = dir.path().join(".ssh/config");
        let generated_config = dir.path().join("floria/ssh/config");
        let manager: Arc<dyn SshConfigManager> = Arc::new(crate::ManagedSshConfig::new(
            &user_config,
            &generated_config,
        ));
        let _server = ControlServer::start_inner(
            &socket,
            catalog,
            ControlDependencies {
                ssh_config: Some(manager),
                ..ControlDependencies::default()
            },
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let status = client.request(ControlCommand::SshConfigStatus).unwrap();
        assert!(matches!(
            status,
            ControlResult::SshConfig(SshConfigStatus {
                state: crate::SshConfigState::Disabled,
                writable: true,
                ..
            })
        ));
        let status = client.request(ControlCommand::SshConfigInstall).unwrap();
        assert!(matches!(
            status,
            ControlResult::SshConfig(SshConfigStatus {
                state: crate::SshConfigState::Managed,
                ..
            })
        ));
        assert!(std::fs::read_to_string(&user_config)
            .unwrap()
            .contains(&generated_config.display().to_string()));

        let status = client.request(ControlCommand::SshConfigRemove).unwrap();
        assert!(matches!(
            status,
            ControlResult::SshConfig(SshConfigStatus {
                state: crate::SshConfigState::Disabled,
                ..
            })
        ));
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
            ControlResult::Pong { schema_version: 7 }
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
                    enforcement: Enforcement::Prompt,
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
                    enforcement: Enforcement::Prompt,
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
    fn shared_secret_lifecycle_over_ipc_keeps_plaintext_out_of_catalog() {
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
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata {
                    note: Some("Documentation deployment token".to_string()),
                    links: vec![ItemLink {
                        label: "Token dashboard".to_string(),
                        url: "https://example.invalid/tokens".to_string(),
                    }],
                },
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
        assert_eq!(resource.metadata.note.as_deref(), Some("Documentation deployment token"));
        assert_eq!(resource.metadata.links[0].label, "Token dashboard");
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

        assert_eq!(
            client
                .request(ControlCommand::SharedSecretUpdate {
                    resource_id: "fixture-shared-secret".to_string(),
                    name: "Renamed Shared Secret".to_string(),
                    default_env_key: Some("RENAMED_TOKEN".to_string()),
                    value: Some(crate::protocol::SecretValue::new("fixture-value-three")),
                    enforcement: Enforcement::TouchId,
                    metadata: ItemMetadata {
                        note: Some("Renamed deployment token".to_string()),
                        links: Vec::new(),
                    },
                })
                .unwrap(),
            ControlResult::Empty
        );
        let resource = catalog.resource("fixture-shared-secret").unwrap();
        assert_eq!(resource.name, "Renamed Shared Secret");
        assert_eq!(resource.default_env_key.as_deref(), Some("RENAMED_TOKEN"));
        assert_eq!(resource.entries[0].label, "Renamed Shared Secret");
        assert_eq!(resource.entries[0].key.as_deref(), Some("RENAMED_TOKEN"));
        assert_eq!(resource.enforcement, Enforcement::TouchId);
        assert_eq!(resource.metadata.note.as_deref(), Some("Renamed deployment token"));
        assert_eq!(store.get(&secret_id).unwrap().as_slice(), b"fixture-value-three");
        assert_eq!(store.record(&secret_id).unwrap().unwrap().current_version, 3);

        client
            .request(ControlCommand::SharedSecretUpdate {
                resource_id: "fixture-shared-secret".to_string(),
                name: "Metadata Only Rename".to_string(),
                default_env_key: Some("RENAMED_TOKEN".to_string()),
                value: None,
                enforcement: Enforcement::Allow,
                metadata: ItemMetadata {
                    note: Some("Metadata-only edit".to_string()),
                    links: Vec::new(),
                },
            })
            .unwrap();
        assert_eq!(store.record(&secret_id).unwrap().unwrap().current_version, 3);
        assert_eq!(
            catalog.resource("fixture-shared-secret").unwrap().metadata.note.as_deref(),
            Some("Metadata-only edit")
        );

        assert_eq!(
            client
                .request(ControlCommand::SharedSecretRemove {
                    resource_id: "fixture-shared-secret".to_string(),
                })
                .unwrap(),
            ControlResult::Empty
        );
        assert!(matches!(
            catalog.resource("fixture-shared-secret"),
            Err(CatalogError::NotFound(_))
        ));
        assert!(store.record(&secret_id).unwrap().is_none());
    }

    #[test]
    fn shared_secret_remove_refuses_to_orphan_project_bindings() {
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

        client
            .request(ControlCommand::SharedSecretCreate {
                resource_id: "fixture-shared-secret".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("FIXTURE_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("fixture-bound-value"),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            })
            .unwrap();
        client
            .request(ControlCommand::ProjectUpsert {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                },
            })
            .unwrap();
        client
            .request(ControlCommand::BindingUpsert {
                binding: Binding {
                    id: "fixture-binding".to_string(),
                    project_id: "fixture-project".to_string(),
                    scope: BindingScope::Common,
                    resource_id: "fixture-shared-secret".to_string(),
                    selection: EntrySelection::All,
                    key_override: None,
                    enabled: true,
                    allow_override: false,
                    position: 0,
                },
            })
            .unwrap();

        let error = client
            .request(ControlCommand::SharedSecretRemove {
                resource_id: "fixture-shared-secret".to_string(),
            })
            .unwrap_err();
        assert!(error.to_string().contains("resource_in_use"));
        assert!(catalog.resource("fixture-shared-secret").is_ok());
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert!(store.record(&secret_id).unwrap().is_some());
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
        assert!(file.linked);
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

        let file_metadata = ItemMetadata {
            note: Some("Loaded automatically by direnv".to_string()),
            links: vec![ItemLink {
                label: "Project documentation".to_string(),
                url: "https://example.invalid/docs/local-env".to_string(),
            }],
        };
        assert_eq!(
            client
                .request(ControlCommand::ProtectedFileMetadataUpdate {
                    id: FIXTURE_SECRET_ID.to_string(),
                    enforcement: Enforcement::TouchId,
                    metadata: file_metadata.clone(),
                })
                .unwrap(),
            ControlResult::Empty
        );
        let ControlResult::ProtectedFiles(files) =
            client.request(ControlCommand::ProtectedFiles).unwrap()
        else {
            panic!("expected protected files result");
        };
        assert_eq!(files[0].metadata, file_metadata);
        assert_eq!(files[0].current_version, 1);

        let mut expected_file = file.clone();
        expected_file.metadata = file_metadata;
        assert_eq!(
            client
                .request(ControlCommand::FileProtect { path: source.clone() })
                .unwrap(),
            ControlResult::FileProtected { file: expected_file, created: false }
        );

        store
            .append_version(&secret_id, b"export FIXTURE_VALUE='fixture-updated'\n")
            .unwrap();
        let history = client
            .request(ControlCommand::ProtectedFileHistory {
                id: FIXTURE_SECRET_ID.to_string(),
            })
            .unwrap();
        let ControlResult::ProtectedFileHistory { versions, .. } = history else {
            panic!("expected protected file history");
        };
        assert_eq!(versions.len(), 2);
        assert!(!versions[0].current);
        assert!(versions[1].current);

        let rolled_back = client
            .request(ControlCommand::ProtectedFileRollback {
                id: FIXTURE_SECRET_ID.to_string(),
                version: 1,
            })
            .unwrap();
        let ControlResult::ProtectedFileRolledBack { file } = rolled_back else {
            panic!("expected protected file rollback");
        };
        assert_eq!(file.current_version, 1);

        client
            .request(ControlCommand::ResourceUpsert {
                resource: Resource {
                    id: "fixture-protected-file-resource".to_string(),
                    name: "Fixture Protected File".to_string(),
                    kind: ResourceKind::Secret,
                    shape: ValueShape::Bytes,
                    codec: ResourceCodec::Opaque,
                    default_env_key: None,
                    entries: Vec::new(),
                    source: ResourceSource::SecretRef {
                        secret_id: FIXTURE_SECRET_ID.to_string(),
                    },
                    enforcement: Enforcement::Prompt,
                    metadata: Default::default(),
                },
            })
            .unwrap();
        let restore_error = client
            .request(ControlCommand::FileRestore {
                id: FIXTURE_SECRET_ID.to_string(),
            })
            .unwrap_err();
        assert!(restore_error.to_string().contains("still used by catalog resources"));
        assert!(std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        client
            .request(ControlCommand::ResourceRemove {
                id: "fixture-protected-file-resource".to_string(),
            })
            .unwrap();

        assert_eq!(
            client
                .request(ControlCommand::FileRestore {
                    id: FIXTURE_SECRET_ID.to_string(),
                })
                .unwrap(),
            ControlResult::FileRestored { path: canonical_source, storage_deleted: true }
        );
        assert!(!std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_to_string(&source).unwrap(),
            "export FIXTURE_VALUE='fixture-value'\n"
        );
        assert_eq!(
            std::fs::metadata(&source).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(store.record(&secret_id).unwrap().is_none());
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
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata {
                    note: Some("Local application defaults".to_string()),
                    links: Vec::new(),
                },
            })
            .unwrap();
        let ControlResult::EnvFileCreated { resource, version } = created else {
            panic!("expected env file creation result");
        };
        assert_eq!(version, 1);
        assert_eq!(resource.kind, ResourceKind::EnvFile);
        assert_eq!(resource.codec, ResourceCodec::Dotenv);
        assert_eq!(resource.metadata.note.as_deref(), Some("Local application defaults"));
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

        client
            .request(ControlCommand::ResourceMetadataUpdate {
                resource_id: "fixture-env-file".to_string(),
                name: "Renamed Env File".to_string(),
                enforcement: Enforcement::TouchId,
                metadata: ItemMetadata {
                    note: Some("Values imported from the local stack".to_string()),
                    links: Vec::new(),
                },
            })
            .unwrap();
        let updated = catalog.resource("fixture-env-file").unwrap();
        assert_eq!(updated.name, "Renamed Env File");
        assert_eq!(
            updated.metadata.note.as_deref(),
            Some("Values imported from the local stack")
        );
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
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
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
