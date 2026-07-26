use std::collections::HashSet;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use accessfs_catalog::{
    resolve_catalog_surface, Binding, BindingScope, Catalog, CatalogError, CatalogSnapshot,
    EntrySelection, EntrySpec, Environment, FileBacking, ItemMetadata, OriginKind, OriginSource,
    Project, Resource, ResourceCodec, ResourceKind, ResourceOrigin, ResourceSource, Surface,
    SurfaceFormat, SurfaceInput, SurfaceKind, ValueShape,
};
use accessfs_core::audit::{read_recent_access, AuditAccessRecord};
use accessfs_core::authz::{Enforcement, PolicyMode, PolicyModeStatus};
use accessfs_discover::{
    classify_key, discover, discover_git_checkouts, DiscoveredContent, DiscoveredFileAction,
    DiscoveredFileKind, ExistingEnvironment, ExistingProject, ExistingSecret, ExistingSurface,
    GitCheckoutDiscovery, GitCheckoutMonitor, KeyClass, MonitoredGitCheckout,
};
use accessfs_platform::SocketPeerVerifier;
use accessfs_ssh::ManagedKeyError;
use accessfs_store::{NewSecret, SecretId, SecretOrigin, SecretRecord, SecretStore, StoreError};
use accessfs_surface::{decode_source, ensure_file_surface_link, validate_secret_bytes};

use crate::protocol::{
    read_msg, write_msg, AccessHistoryEvent, AccessHistoryIdentity, AccessHistoryProcess,
    AccessHistorySsh, ActiveGrant, ControlCommand, ControlErrorBody, ControlOutcome, ControlRequest,
    ControlResponse, ControlResult, DiscoveryAppliedFile, DiscoveryApplyOutcome,
    DiscoveryApplyResult, DiscoveryReferenceResolution, DiscoveryReferenceSource,
    ProjectCheckoutCandidate, ProjectCheckoutDiscovery, ProjectCheckoutInventory, ProtectedFile,
    ProtectedFileVersion, SecretValue, SshConfigStatus, SshIdentity,
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
    fn active_grants(&self) -> io::Result<Vec<ActiveGrant>>;
    fn revoke_grant(&self, id: &str) -> io::Result<bool>;
    fn clear_grants(&self) -> io::Result<()>;
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
    pub checkout_monitor: Arc<GitCheckoutMonitor>,
    pub policy: Arc<dyn RuntimePolicyController>,
    pub ssh_discovery: Arc<dyn SshIdentityDiscovery>,
    pub ssh_config: Arc<dyn SshConfigManager>,
    pub audit_log: PathBuf,
    pub peer_verifier: Arc<dyn SocketPeerVerifier>,
}

#[derive(Clone, Default)]
struct ControlDependencies {
    store: Option<Arc<dyn SecretStore>>,
    mount_path: Option<PathBuf>,
    observer: Option<Arc<dyn CatalogObserver>>,
    checkout_monitor: Option<Arc<GitCheckoutMonitor>>,
    policy: Option<Arc<dyn RuntimePolicyController>>,
    ssh_discovery: Option<Arc<dyn SshIdentityDiscovery>>,
    ssh_config: Option<Arc<dyn SshConfigManager>>,
    audit_log: Option<PathBuf>,
}

impl ControlServer {
    /// Start the catalog control socket. Each connection gets a dedicated request loop;
    /// authorization prompts continue to use the separate agent socket.
    pub fn start(
        path: &Path,
        catalog: Catalog,
        peer_verifier: Arc<dyn SocketPeerVerifier>,
    ) -> io::Result<Self> {
        Self::start_inner(path, catalog, ControlDependencies::default(), peer_verifier)
    }

    pub fn start_observed(
        path: &Path,
        catalog: Catalog,
        observer: Arc<dyn CatalogObserver>,
        peer_verifier: Arc<dyn SocketPeerVerifier>,
    ) -> io::Result<Self> {
        Self::start_inner(
            path,
            catalog,
            ControlDependencies { observer: Some(observer), ..ControlDependencies::default() },
            peer_verifier,
        )
    }

    pub fn start_runtime(
        path: &Path,
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        mount_path: PathBuf,
        observer: Arc<dyn CatalogObserver>,
        peer_verifier: Arc<dyn SocketPeerVerifier>,
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
            peer_verifier,
        )
    }

    pub fn start_runtime_with_policy(
        path: &Path,
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        mount_path: PathBuf,
        observer: Arc<dyn CatalogObserver>,
        policy: Arc<dyn RuntimePolicyController>,
        peer_verifier: Arc<dyn SocketPeerVerifier>,
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
            peer_verifier,
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
                checkout_monitor: Some(services.checkout_monitor),
                policy: Some(services.policy),
                ssh_discovery: Some(services.ssh_discovery),
                ssh_config: Some(services.ssh_config),
                audit_log: Some(services.audit_log),
            },
            services.peer_verifier,
        )
    }

    fn start_inner(
        path: &Path,
        catalog: Catalog,
        dependencies: ControlDependencies,
        peer_verifier: Arc<dyn SocketPeerVerifier>,
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
            .spawn(move || accept_loop(listener, catalog, dependencies, peer_verifier))?;

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
    peer_verifier: Arc<dyn SocketPeerVerifier>,
) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "control socket accept failed");
                continue;
            }
        };
        let peer = match peer_verifier.verify(&stream) {
            Ok(peer) => peer,
            Err(error) => {
                tracing::warn!(%error, "rejecting untrusted control connection");
                continue;
            }
        };
        tracing::debug!(
            pid = peer.identity.pid,
            executable = ?peer.identity.exe_path,
            bundle_id = ?peer.identity.bundle_id,
            team_id = ?peer.identity.team_id,
            "trusted control client connected"
        );
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
        let is_read_only = is_read_only(&request.command);
        let services = DispatchServices {
            store: dependencies.store.as_deref(),
            mount_path: dependencies.mount_path.as_deref(),
            policy: dependencies.policy.as_deref(),
            ssh_discovery: dependencies.ssh_discovery.as_deref(),
            ssh_config: dependencies.ssh_config.as_deref(),
            checkout_monitor: dependencies.checkout_monitor.as_deref(),
            audit_log: dependencies.audit_log.as_deref(),
        };
        let outcome = match dispatch(&catalog, services, request.command) {
            Ok(result) => {
                if !is_read_only {
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

/// Commands known not to mutate catalog, store, generated files, or runtime policy state.
/// New commands deliberately default to mutating so a missed classification causes only an
/// idempotent refresh rather than leaving the daemon on stale policy.
fn is_read_only(command: &ControlCommand) -> bool {
    matches!(
        command,
        ControlCommand::Ping
            | ControlCommand::PolicyModeGet
            | ControlCommand::GrantList
            | ControlCommand::AccessHistory { .. }
            | ControlCommand::Snapshot
            | ControlCommand::Discover { .. }
            | ControlCommand::ProjectCheckoutInventory
            | ControlCommand::ProjectCheckoutDiscover { .. }
            | ControlCommand::SshAgentDiscover { .. }
            | ControlCommand::SshConfigStatus
            | ControlCommand::ProtectedFiles
            | ControlCommand::ProtectedFileHistory { .. }
            | ControlCommand::ResolveEnvironment { .. }
            | ControlCommand::ResourceUsage { .. }
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

#[derive(Clone, Copy, Default)]
struct DispatchServices<'a> {
    store: Option<&'a dyn SecretStore>,
    mount_path: Option<&'a Path>,
    policy: Option<&'a dyn RuntimePolicyController>,
    ssh_discovery: Option<&'a dyn SshIdentityDiscovery>,
    ssh_config: Option<&'a dyn SshConfigManager>,
    checkout_monitor: Option<&'a GitCheckoutMonitor>,
    audit_log: Option<&'a Path>,
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
    services: DispatchServices<'_>,
    command: ControlCommand,
) -> Result<ControlResult, DispatchError> {
    let DispatchServices {
        store,
        mount_path,
        policy,
        ssh_discovery,
        ssh_config,
        checkout_monitor,
        audit_log,
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
        ControlCommand::Discover { path } => {
            let store = store.ok_or(DispatchError::StoreUnavailable)?;
            let discovery =
                discover(&path).map_err(|error| DispatchError::Validation(error.to_string()))?;
            let existing = existing_discovery_secrets(catalog, store)?;
            let managed_project = existing_discovery_project(catalog, discovery.project())?;
            Ok(ControlResult::Discovery(
                discovery.plan_with_project(&existing, managed_project.as_ref()),
            ))
        }
        ControlCommand::DiscoverApply {
            path,
            files,
            separate_entries,
            promote_entries,
            demote_entries,
        } => apply_discovery(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            &path,
            files.as_deref(),
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

fn access_history(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    audit_log: &Path,
    limit: usize,
) -> Result<ControlResult, DispatchError> {
    let records = read_recent_access(audit_log, limit).map_err(|source| DispatchError::Io {
        path: audit_log.to_path_buf(),
        source,
    })?;
    let snapshot = catalog.snapshot()?;
    let stored = match store {
        Some(store) => store.list()?,
        None => Vec::new(),
    };
    let events = records
        .into_iter()
        .map(|record| {
            let display = history_display(&record.path, &snapshot, &stored);
            let ssh = history_ssh(&record, &snapshot);
            AccessHistoryEvent {
                ts: record.ts,
                path: record.path,
                display,
                operation: record.operation,
                decision: record.decision,
                rule_id: record.rule_id,
                policy: record.policy,
                ssh,
                identity: history_identity(&record.identity),
            }
        })
        .collect();
    Ok(ControlResult::AccessHistory(events))
}

fn history_display(
    path: &str,
    snapshot: &CatalogSnapshot,
    stored: &[SecretRecord],
) -> Option<String> {
    if let Some(surface_id) = path.strip_prefix("surfaces/") {
        return snapshot
            .surfaces
            .iter()
            .find(|surface| surface.id == surface_id)
            .map(|surface| surface.path.display().to_string());
    }
    path.strip_prefix("secrets/").and_then(|secret_id| {
        stored
            .iter()
            .find(|record| record.id.as_str() == secret_id)
            .map(SecretRecord::display_name)
    })
}

fn history_ssh(record: &AuditAccessRecord, snapshot: &CatalogSnapshot) -> Option<AccessHistorySsh> {
    let surface_id = record.surface_id.as_ref()?;
    let resource_id = record.resource_id.as_ref()?;
    let key_fingerprint = record.key_fingerprint.as_ref()?;
    let session = record.ssh_session.as_ref();
    Some(AccessHistorySsh {
        surface_id: surface_id.clone(),
        surface_name: snapshot
            .surfaces
            .iter()
            .find(|surface| surface.id == *surface_id)
            .map(|surface| surface.name.clone())
            .unwrap_or_else(|| surface_id.clone()),
        resource_id: resource_id.clone(),
        key_fingerprint: key_fingerprint.clone(),
        key_label: snapshot
            .resources
            .iter()
            .find(|resource| resource.id == *resource_id)
            .map(|resource| resource.name.clone())
            .unwrap_or_else(|| resource_id.clone()),
        requested_destination: session.and_then(|value| value.requested_destination.clone()),
        verified_host_key_fingerprint: session
            .and_then(|value| value.verified_host_key_fingerprint.clone()),
        ssh_user: session.and_then(|value| value.ssh_user.clone()),
        forwarding_hops: session.map_or(0, |value| value.forwarding_hops),
    })
}

fn history_identity(identity: &accessfs_core::identity::ProcessIdentity) -> AccessHistoryIdentity {
    AccessHistoryIdentity {
        pid: identity.pid,
        uid: identity.uid,
        exe: identity.exe_path.as_ref().map(|path| path.display().to_string()),
        cwd: identity.cwd.as_ref().map(|path| path.display().to_string()),
        cmdline: identity.cmdline.clone(),
        bundle_id: identity.bundle_id.clone(),
        team_id: identity.team_id.clone(),
        parent_chain: identity
            .parent_chain
            .iter()
            .rev()
            .map(|process| AccessHistoryProcess {
                pid: process.pid,
                name: process.name.clone(),
                exe: process.exe_path.as_ref().map(|path| path.display().to_string()),
            })
            .collect(),
        chain: identity.chain_display(),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_discovery(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    path: &Path,
    selected_files: Option<&[PathBuf]>,
    separate_entries: &[crate::protocol::DiscoveryEntryRef],
    promote_entries: &[crate::protocol::DiscoveryEntryRef],
    demote_entries: &[crate::protocol::DiscoveryEntryRef],
) -> Result<ControlResult, DispatchError> {
    let discovery =
        discover(path).map_err(|error| DispatchError::Validation(error.to_string()))?;
    let mut existing = existing_discovery_secrets(catalog, store)?;
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
    let needs_project = contents
        .iter()
        .any(|file| file.action == DiscoveredFileAction::Compose);
    let (project_id, project_created) = if needs_project {
        let (id, created) = ensure_discovered_project(catalog, &plan.project)?;
        (Some(id), created)
    } else {
        (None, false)
    };
    let mut result = DiscoveryApplyResult {
        project_id: project_id.clone(),
        created_resources: 0,
        reused_resources: 0,
        protected_files: 0,
        imported_ssh_identities: 0,
        files: Vec::new(),
    };
    let mut composed_success = false;

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
                                project_id: project_id.clone(),
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
                    let Some(project_id) = project_id.as_deref() else {
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
            Ok(imported_composed_file) => composed_success |= imported_composed_file,
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

    if project_created && !composed_success {
        if let Some(project_id) = project_id {
            catalog.remove_project(&project_id)?;
            result.project_id = None;
        }
    }
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
        mutation.created_environments.push(environment_id.clone());
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
                    mutation.created_resources.push(resource_id.clone());
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
                mutation.created_bindings.push(binding_id.clone());
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
                mutation.created_resources.push(resource_id.clone());
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
                mutation.created_bindings.push(binding_id.clone());
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
            mutation.created_resources.push(resource_id.clone());
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
            mutation.created_bindings.push(binding_id.clone());
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
    mutation.committed = true;
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

struct DiscoveryMutationGuard<'a> {
    catalog: &'a Catalog,
    store: &'a dyn SecretStore,
    created_resources: Vec<String>,
    created_bindings: Vec<String>,
    created_environments: Vec<String>,
    committed: bool,
}

impl<'a> DiscoveryMutationGuard<'a> {
    fn new(catalog: &'a Catalog, store: &'a dyn SecretStore) -> Self {
        DiscoveryMutationGuard {
            catalog,
            store,
            created_resources: Vec::new(),
            created_bindings: Vec::new(),
            created_environments: Vec::new(),
            committed: false,
        }
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

fn discover_project_checkouts(
    catalog: &Catalog,
    project_id: &str,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let project = snapshot
        .projects
        .iter()
        .find(|project| project.id == project_id)
        .ok_or_else(|| CatalogError::NotFound(format!("project {project_id}")))?;
    let discovered = discover_git_checkouts(&project.path)
        .map_err(|error| DispatchError::Validation(error.to_string()))?;
    Ok(ControlResult::ProjectCheckoutDiscovery(
        checkout_discovery(&snapshot, project_id, discovered),
    ))
}

fn project_checkout_inventory(
    catalog: &Catalog,
    monitor: Option<&GitCheckoutMonitor>,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let (revision, projects) = if let Some(monitor) = monitor {
        let inventory = monitor.inventory();
        let projects = snapshot
            .projects
            .iter()
            .filter_map(|project| match inventory.projects.get(&project.id) {
                Some(MonitoredGitCheckout::Ready(discovered)) => Some(checkout_discovery(
                    &snapshot,
                    &project.id,
                    discovered.clone(),
                )),
                Some(MonitoredGitCheckout::Unavailable(_)) | None => None,
            })
            .collect();
        (inventory.revision, projects)
    } else {
        let projects = snapshot
            .projects
            .iter()
            .filter_map(|project| {
                discover_git_checkouts(&project.path)
                    .ok()
                    .map(|discovered| checkout_discovery(&snapshot, &project.id, discovered))
            })
            .collect();
        (0, projects)
    };
    Ok(ControlResult::ProjectCheckoutInventory(
        ProjectCheckoutInventory { revision, projects },
    ))
}

fn checkout_discovery(
    snapshot: &CatalogSnapshot,
    project_id: &str,
    discovered: GitCheckoutDiscovery,
) -> ProjectCheckoutDiscovery {
    let checkouts = discovered
        .checkouts
        .into_iter()
        .map(|candidate| ProjectCheckoutCandidate {
            managed_checkout_id: snapshot
                .checkouts
                .iter()
                .find(|checkout| {
                    checkout.project_id == project_id && checkout.path == candidate.path
                })
                .map(|checkout| checkout.id.clone()),
            path: candidate.path,
            git_primary: candidate.git_primary,
        })
        .collect();
    ProjectCheckoutDiscovery {
        project_id: project_id.to_string(),
        common_dir: discovered.common_dir,
        checkouts,
    }
}

fn ensure_discovered_project(
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

fn ensure_discovered_environment(
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

fn replace_discovered_file_with_surface(
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

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn discovered_source(
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

fn generated_id(prefix: &str) -> String {
    format!("{prefix}-{}", SecretId::generate())
}

fn existing_discovery_project(
    catalog: &Catalog,
    discovered: &accessfs_discover::DiscoveredProject,
) -> Result<Option<ExistingProject>, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let Some(project) = snapshot
        .projects
        .iter()
        .find(|project| project.path == discovered.path)
    else {
        return Ok(None);
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
    Ok(Some(ExistingProject {
        id: project.id.clone(),
        environments,
    }))
}

fn existing_discovery_secrets(
    catalog: &Catalog,
    store: &dyn SecretStore,
) -> Result<Vec<ExistingSecret>, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let mut existing = Vec::new();
    for resource in snapshot.resources {
        if resource.kind != ResourceKind::SharedSecret || resource.shape != ValueShape::Scalar {
            continue;
        }
        let Some(key) = resource.default_env_key else { continue };
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

fn resolve_discovery_reference(
    catalog: &Catalog,
    store: &dyn SecretStore,
    surface_id: &str,
    key: &str,
    source: DiscoveryReferenceSource,
) -> Result<ControlResult, DispatchError> {
    let snapshot = catalog.snapshot()?;
    let surface = snapshot
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .ok_or_else(|| DispatchError::Validation(format!("surface {surface_id:?} was not found")))?
        .clone();
    if !matches!(
        surface.kind.composed_format(),
        Some(SurfaceFormat::Dotenv | SurfaceFormat::Direnv)
    ) {
        return Err(DispatchError::Validation(
            "reference values can only be attached to dotenv or direnv outputs".to_string(),
        ));
    }
    let binding_ids = match &surface.input {
        SurfaceInput::Bindings { binding_ids } => binding_ids.clone(),
        _ => {
            return Err(DispatchError::Validation(
                "reference target must be a composed environment output".to_string(),
            ))
        }
    };
    if resolve_catalog_surface(&snapshot, surface_id)?
        .iter()
        .any(|export| export.key == key)
    {
        return Err(DispatchError::Validation(format!(
            "{key:?} is already exported by this output"
        )));
    }
    let environment = snapshot
        .environments
        .iter()
        .find(|environment| environment.id == surface.environment_id)
        .ok_or_else(|| {
            DispatchError::Validation(format!(
                "environment {:?} was not found",
                surface.environment_id
            ))
        })?;

    let mut mutation = DiscoveryMutationGuard::new(catalog, store);
    let (resource_id, default_env_key) = match source {
        DiscoveryReferenceSource::NewSharedSecret {
            name,
            value,
            enforcement,
            metadata,
        } => {
            let resource_id = generated_id("shared-secret");
            create_shared_secret(
                catalog,
                store,
                resource_id.clone(),
                name,
                Some(key.to_string()),
                value,
                ManagedItemSettings { enforcement, metadata },
                ResourceOrigin { kind: OriginKind::Manual, sources: Vec::new() },
            )?;
            mutation.created_resources.push(resource_id.clone());
            (resource_id, Some(key.to_string()))
        }
        DiscoveryReferenceSource::ExistingSharedSecret { resource_id } => {
            let resource = catalog.resource(&resource_id)?;
            if resource.kind != ResourceKind::SharedSecret || resource.shape != ValueShape::Scalar {
                return Err(DispatchError::Validation(
                    "choose a scalar Shared Secret for this reference value".to_string(),
                ));
            }
            (resource_id, resource.default_env_key)
        }
    };

    let key_override = (default_env_key.as_deref() != Some(key)).then(|| key.to_string());
    let reusable_binding = snapshot
        .bindings
        .iter()
        .filter(|binding| {
            binding.project_id == environment.project_id
                && binding.resource_id == resource_id
                && binding.selection == EntrySelection::All
                && binding.key_override == key_override
                && binding.enabled
                && match &binding.scope {
                    BindingScope::Common => true,
                    BindingScope::Environment { environment_id } => {
                        environment_id == &environment.id
                    }
                }
        })
        .min_by_key(|binding| matches!(&binding.scope, BindingScope::Common));
    let binding_id = if let Some(binding) = reusable_binding {
        binding.id.clone()
    } else {
        let binding_id = generated_id("binding");
        catalog.upsert_binding(&Binding {
            id: binding_id.clone(),
            project_id: environment.project_id.clone(),
            scope: BindingScope::Environment {
                environment_id: environment.id.clone(),
            },
            resource_id: resource_id.clone(),
            selection: EntrySelection::All,
            key_override,
            enabled: true,
            allow_override: false,
            position: snapshot
                .bindings
                .iter()
                .filter(|binding| {
                    binding.project_id == environment.project_id
                        && binding.scope
                            == (BindingScope::Environment {
                                environment_id: environment.id.clone(),
                            })
                })
                .count() as i64,
        })?;
        mutation.created_bindings.push(binding_id.clone());
        binding_id
    };

    let mut updated_surface = surface;
    updated_surface.input = SurfaceInput::Bindings {
        binding_ids: binding_ids
            .into_iter()
            .chain(std::iter::once(binding_id.clone()))
            .collect(),
    };
    catalog.upsert_surface(&updated_surface)?;
    mutation.committed = true;

    Ok(ControlResult::DiscoveryReferenceResolved(
        DiscoveryReferenceResolution {
            surface_id: surface_id.to_string(),
            resource_id,
            binding_id,
            key: key.to_string(),
        },
    ))
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

#[allow(clippy::too_many_arguments)]
fn import_ssh_identity(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    path: &Path,
    passphrase: Option<&crate::protocol::SecretValue>,
    settings: ManagedItemSettings,
    origin: ResourceOrigin,
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
        origin,
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

#[allow(clippy::too_many_arguments)]
fn create_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    default_env_key: Option<String>,
    value: crate::protocol::SecretValue,
    settings: ManagedItemSettings,
    origin: ResourceOrigin,
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
        origin,
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

#[allow(clippy::too_many_arguments)]
fn create_env_file(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    codec: ResourceCodec,
    value: crate::protocol::SecretValue,
    settings: ManagedItemSettings,
    origin: ResourceOrigin,
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
        origin,
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
    if resource.source == ResourceSource::Socket {
        let endpoint = catalog
            .snapshot()?
            .endpoints
            .get(resource_id)
            .cloned()
            .ok_or_else(|| {
                DispatchError::Validation(format!(
                    "socket resource {resource_id:?} has no machine-local endpoint"
                ))
            })?;
        catalog.upsert_socket_resource(&resource, &endpoint)?;
    } else {
        catalog.upsert_resource(&resource)?;
    }
    Ok(ControlResult::Empty)
}

#[cfg(test)]
mod tests;
