use std::collections::HashSet;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use accessfs_catalog::{
    resolve_catalog_surface, Binding, BindingScope, Catalog, CatalogError, CatalogSnapshot,
    EntrySelection, EntrySpec, Environment, ItemMetadata, Project, Resource, ResourceCodec,
    ResourceKind, ResourceSource, Surface, SurfaceInput, SurfaceKind, ValueShape,
};
use accessfs_core::audit::{read_recent_access, AuditAccessRecord};
use accessfs_core::authz::{Enforcement, PolicyMode, PolicyModeStatus};
use accessfs_discover::{
    discover, DiscoveredContent, DiscoveredFileAction, DiscoveredFileKind, ExistingEnvironment,
    ExistingProject, ExistingSecret, ExistingSurface,
};
use accessfs_platform::SocketPeerVerifier;
use accessfs_ssh::ManagedKeyError;
use accessfs_store::{NewSecret, SecretId, SecretOrigin, SecretRecord, SecretStore, StoreError};
use accessfs_surface::{decode_source, ensure_file_surface_link, validate_secret_bytes};

use crate::protocol::{
    read_msg, write_msg, AccessHistoryEvent, AccessHistoryIdentity, AccessHistoryProcess,
    AccessHistorySsh, ControlCommand, ControlErrorBody, ControlOutcome, ControlRequest,
    ControlResponse, ControlResult, DiscoveryAppliedFile, DiscoveryApplyOutcome,
    DiscoveryApplyResult, DiscoveryReferenceResolution, DiscoveryReferenceSource, ProtectedFile,
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
    pub audit_log: PathBuf,
    pub peer_verifier: Arc<dyn SocketPeerVerifier>,
}

#[derive(Clone, Default)]
struct ControlDependencies {
    store: Option<Arc<dyn SecretStore>>,
    mount_path: Option<PathBuf>,
    observer: Option<Arc<dyn CatalogObserver>>,
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
        tracing::info!(
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
        let changes_runtime = changes_runtime(&request.command);
        let services = DispatchServices {
            store: dependencies.store.as_deref(),
            mount_path: dependencies.mount_path.as_deref(),
            policy: dependencies.policy.as_deref(),
            ssh_discovery: dependencies.ssh_discovery.as_deref(),
            ssh_config: dependencies.ssh_config.as_deref(),
            audit_log: dependencies.audit_log.as_deref(),
        };
        let outcome = match dispatch(&catalog, services, request.command) {
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
            | ControlCommand::DiscoverApply { .. }
            | ControlCommand::DiscoverReferenceResolve { .. }
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
        ControlCommand::DiscoverApply { path, files, separate_entries } => apply_discovery(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            mount_path.ok_or(DispatchError::StoreUnavailable)?,
            &path,
            files.as_deref(),
            &separate_entries,
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

fn apply_discovery(
    catalog: &Catalog,
    store: &dyn SecretStore,
    mount_path: &Path,
    path: &Path,
    selected_files: Option<&[PathBuf]>,
    separate_entries: &[crate::protocol::DiscoveryEntryRef],
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
    let valid_separate_entries = contents
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
    let separate_entries = separate_entries
        .iter()
        .map(|entry| (entry.path.clone(), entry.address.clone()))
        .collect::<HashSet<_>>();
    if let Some((path, address)) = separate_entries
        .iter()
        .find(|entry| !valid_separate_entries.contains(*entry))
    {
        return Err(DispatchError::Validation(format!(
            "separate-secret choice was not part of the reviewed discovery: {} ({address})",
            path.display()
        )));
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
                            metadata: discovered_metadata(&file),
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
            for (position, entry) in file.entries.iter().enumerate() {
                let force_separate =
                    reuse
                        .separate_entries
                        .contains(&(file.path.clone(), entry.address.clone()));
                let reusable = (!force_separate).then(|| {
                    reuse.existing.iter().find(|candidate| {
                        candidate.key == entry.key
                            && candidate.value.as_slice() == entry.value.as_bytes()
                    })
                });
                let resource_id = if let Some(candidate) = reusable.flatten() {
                    result.reused_resources += 1;
                    candidate.resource_id.clone()
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
                            metadata: discovered_metadata(&file),
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
                    metadata: discovered_metadata(&file),
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
        DiscoveredFileKind::Dotenv => SurfaceKind::DotenvFile,
        DiscoveredFileKind::Direnv => SurfaceKind::DirenvFile,
        DiscoveredFileKind::AwsCredentials => SurfaceKind::IniFile,
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
                    | ResourceSource::Socket { .. } => None,
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

fn discovered_metadata(file: &DiscoveredContent) -> ItemMetadata {
    ItemMetadata {
        note: Some(format!("Discovered from {}", file.relative_path.display())),
        links: Vec::new(),
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
                            surface.kind,
                            SurfaceKind::DotenvFile | SurfaceKind::DirenvFile
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
    if !matches!(surface.kind, SurfaceKind::DotenvFile | SurfaceKind::DirenvFile) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use accessfs_catalog::SurfaceInput;
    use accessfs_core::audit::AuditLog;
    use accessfs_core::identity::{ProcSummary, ProcessIdentity};
    use accessfs_platform::{
        PeerVerificationError, SameUserPeerVerifier, SocketPeerVerifier, VerifiedPeer,
    };
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

    fn test_peer_verifier() -> Arc<dyn SocketPeerVerifier> {
        Arc::new(SameUserPeerVerifier)
    }

    struct RejectAllPeers;

    impl SocketPeerVerifier for RejectAllPeers {
        fn verify(&self, _stream: &UnixStream) -> Result<VerifiedPeer, PeerVerificationError> {
            Err(PeerVerificationError::UntrustedCode {
                pid: std::process::id() as i32,
                executable: "fixture client".to_string(),
                trusted: "fixture trusted app".to_string(),
            })
        }
    }

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
                        | "DISCOVERED_TOKEN"
                        | "OPTIONAL_NEW_TOKEN"
                        | "credentials"
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
            test_peer_verifier(),
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
    fn access_history_returns_persisted_reader_metadata_with_surface_display_path() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture Project".to_string(),
                path: dir.path().join("project"),
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-environment".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            })
            .unwrap();
        let display_path = dir.path().join("project/.env");
        catalog
            .upsert_surface(&Surface {
                id: "fixture-surface".to_string(),
                environment_id: "fixture-environment".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::DotenvFile,
                path: display_path.clone(),
                input: SurfaceInput::Bindings { binding_ids: Vec::new() },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap();

        let audit_path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&audit_path).unwrap();
        let mut identity = ProcessIdentity::bare(42, 501, 20);
        identity.exe_path = Some(PathBuf::from("/usr/bin/fixture-reader"));
        identity.cwd = Some(dir.path().join("project"));
        identity.parent_chain = vec![
            ProcSummary {
                pid: 42,
                ppid: 41,
                name: "fixture-reader".to_string(),
                exe_path: Some(PathBuf::from("/usr/bin/fixture-reader")),
            },
            ProcSummary {
                pid: 41,
                ppid: 1,
                name: "fixture-shell".to_string(),
                exe_path: Some(PathBuf::from("/bin/sh")),
            },
        ];
        audit.log_open(
            "surfaces/fixture-surface",
            "read",
            &identity,
            "allowed",
            Some("fixture-rule"),
            None,
            "sha256:fixture-content",
            7,
            32,
            None,
        );

        let result = dispatch(
            &catalog,
            DispatchServices { audit_log: Some(&audit_path), ..DispatchServices::default() },
            ControlCommand::AccessHistory { limit: 500 },
        )
        .unwrap();
        let ControlResult::AccessHistory(events) = result else {
            panic!("expected access history");
        };
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].display.as_deref(), display_path.to_str());
        assert_eq!(events[0].identity.exe.as_deref(), Some("/usr/bin/fixture-reader"));
        assert_eq!(events[0].identity.chain, "fixture-shell -> fixture-reader");
        assert_eq!(
            events[0]
                .identity
                .parent_chain
                .iter()
                .map(|process| process.name.as_str())
                .collect::<Vec<_>>(),
            vec!["fixture-shell", "fixture-reader"]
        );
    }

    #[test]
    fn discovery_reuses_only_an_exact_shared_secret_without_returning_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        std::fs::create_dir(&project_path).unwrap();
        std::fs::write(
            project_path.join(".env"),
            "API_TOKEN=fixture-shared-value\nOTHER=fixture-other-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::SharedSecretCreate {
                resource_id: "fixture-shared-api-token".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("API_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("fixture-shared-value"),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            },
        )
        .unwrap();

        let result = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover { path: project_path },
        )
        .unwrap();
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("fixture-shared-value"));
        assert!(!serialized.contains("fixture-other-value"));

        let ControlResult::Discovery(plan) = result else {
            panic!("expected discovery result");
        };
        assert_eq!(plan.summary.reused_secrets, 1);
        assert_eq!(plan.summary.new_secrets, 1);
        assert!(matches!(
            plan.files[0].entries[0].action,
            accessfs_discover::DiscoveredEntryAction::ReuseSharedSecret {
                ref resource_id,
                ..
            }
                if resource_id == "fixture-shared-api-token"
        ));
    }

    #[test]
    fn discovery_apply_replaces_dotenv_with_a_composed_surface() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &source_path,
            "DISCOVERED_TOKEN=fixture-discovered-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                path: project_path.clone(),
                files: Some(vec![source_path.clone()]),
                separate_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 1);
        assert_eq!(result.reused_resources, 0);
        assert_eq!(result.files[0].outcome, DiscoveryApplyOutcome::Imported);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.environments.len(), 1);
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.bindings.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(
            std::fs::read_link(&source_path).unwrap(),
            mount_path
                .join(accessfs_core::config::SURFACES_DIR)
                .join(&snapshot.surfaces[0].id)
        );
        assert!(!project_path
            .read_dir()
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().contains("floria-import")));
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(
            store.get(&secret_id).unwrap().as_slice(),
            b"fixture-discovered-value"
        );
    }

    #[test]
    fn discovery_apply_mutates_only_reviewed_files() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let development_path = project_path.join(".env");
        let production_path = project_path.join(".env.production");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&development_path, "DEVELOPMENT_TOKEN=fixture-development\n").unwrap();
        std::fs::write(&production_path, "DISCOVERED_TOKEN=fixture-production\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                path: project_path,
                files: Some(vec![production_path.clone()]),
                separate_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, production_path);
        assert!(std::fs::symlink_metadata(&development_path).unwrap().is_file());
        assert!(std::fs::symlink_metadata(&production_path)
            .unwrap()
            .file_type()
            .is_symlink());
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(snapshot.environments[0].name, "Production");
    }

    #[test]
    fn discovery_apply_leaves_dotenv_reference_files_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let reference_path = project_path.join(".env.example");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&source_path, "DISCOVERED_TOKEN=fixture-real-value\n").unwrap();
        let reference_bytes = b"DISCOVERED_TOKEN=replace-me\n\
            OPTIONAL_REUSED_TOKEN=replace-me\n\
            OPTIONAL_NEW_TOKEN=replace-me\n";
        std::fs::write(&reference_path, reference_bytes).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                path: project_path.clone(),
                files: None,
                separate_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert!(std::fs::symlink_metadata(&source_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::symlink_metadata(&reference_path).unwrap().is_file());
        assert_eq!(std::fs::read(&reference_path).unwrap(), reference_bytes);
        assert!(result.files.iter().any(|file| {
            file.path == reference_path && file.outcome == DiscoveryApplyOutcome::Skipped
        }));
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);

        let rediscovered = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover { path: project_path.clone() },
        )
        .unwrap();
        let ControlResult::Discovery(plan) = rediscovered else {
            panic!("expected discovery result");
        };
        assert_eq!(
            plan.project.managed_project_id.as_deref(),
            Some(snapshot.projects[0].id.as_str())
        );
        assert_eq!(plan.summary.missing_reference_entries, 2);
        let reference = plan
            .files
            .iter()
            .find(|file| file.path == reference_path)
            .expect("reference file");
        assert!(reference.entries.iter().any(|entry| {
            entry.key == "DISCOVERED_TOKEN"
                && entry.action
                    == accessfs_discover::DiscoveredEntryAction::ReferenceEntry { matched: true }
        }));
        assert!(reference.entries.iter().any(|entry| {
            entry.key == "OPTIONAL_REUSED_TOKEN"
                && entry.action
                    == accessfs_discover::DiscoveredEntryAction::ReferenceEntry { matched: false }
        }));
        let surface_id = reference.managed_surface_id.clone().expect("managed surface");

        let reused = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::DiscoverReferenceResolve {
                surface_id: surface_id.clone(),
                key: "OPTIONAL_REUSED_TOKEN".to_string(),
                source: DiscoveryReferenceSource::ExistingSharedSecret {
                    resource_id: snapshot.resources[0].id.clone(),
                },
            },
        )
        .unwrap();
        let ControlResult::DiscoveryReferenceResolved(reused) = reused else {
            panic!("expected resolved reference");
        };
        assert_eq!(reused.surface_id, snapshot.surfaces[0].id);
        assert_eq!(reused.resource_id, snapshot.resources[0].id);
        assert_eq!(reused.key, "OPTIONAL_REUSED_TOKEN");

        let mut secondary_surface = snapshot.surfaces[0].clone();
        secondary_surface.id = "fixture-secondary-surface".to_string();
        secondary_surface.name = ".env.secondary".to_string();
        secondary_surface.path = project_path.join(".env.secondary");
        secondary_surface.input = SurfaceInput::Bindings { binding_ids: Vec::new() };
        secondary_surface.position = 1;
        catalog.upsert_surface(&secondary_surface).unwrap();
        let reused_again = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::DiscoverReferenceResolve {
                surface_id: secondary_surface.id.clone(),
                key: "OPTIONAL_REUSED_TOKEN".to_string(),
                source: DiscoveryReferenceSource::ExistingSharedSecret {
                    resource_id: snapshot.resources[0].id.clone(),
                },
            },
        )
        .unwrap();
        let ControlResult::DiscoveryReferenceResolved(reused_again) = reused_again else {
            panic!("expected resolved reference");
        };
        assert_eq!(reused_again.binding_id, reused.binding_id);
        assert_eq!(catalog.snapshot().unwrap().bindings.len(), 2);

        dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::DiscoverReferenceResolve {
                surface_id,
                key: "OPTIONAL_NEW_TOKEN".to_string(),
                source: DiscoveryReferenceSource::NewSharedSecret {
                    name: "OPTIONAL_NEW_TOKEN".to_string(),
                    value: SecretValue::new("fixture-new-reference-value"),
                    enforcement: Enforcement::Prompt,
                    metadata: ItemMetadata::default(),
                },
            },
        )
        .unwrap();

        let resolved_snapshot = catalog.snapshot().unwrap();
        assert_eq!(resolved_snapshot.resources.len(), 2);
        assert_eq!(resolved_snapshot.bindings.len(), 3);
        assert_eq!(
            resolved_snapshot.surfaces[0].input.binding_ids().unwrap().len(),
            3
        );
        let rediscovered = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover { path: project_path },
        )
        .unwrap();
        let ControlResult::Discovery(resolved_plan) = rediscovered else {
            panic!("expected discovery result");
        };
        assert_eq!(resolved_plan.summary.missing_reference_entries, 0);
    }

    #[test]
    fn discovery_apply_shares_exact_matches_within_the_import() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let development_path = project_path.join(".env");
        let production_path = project_path.join(".env.production");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &development_path,
            "DISCOVERED_TOKEN=fixture-shared-value\n",
        )
        .unwrap();
        std::fs::write(
            &production_path,
            "DISCOVERED_TOKEN=fixture-shared-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                path: project_path,
                files: Some(vec![development_path, production_path]),
                separate_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 1);
        assert_eq!(result.reused_resources, 1);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.bindings.len(), 2);
        assert_eq!(snapshot.surfaces.len(), 2);
    }

    #[test]
    fn discovery_apply_can_keep_an_exact_match_as_a_separate_secret() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let development_path = project_path.join(".env");
        let production_path = project_path.join(".env.production");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &development_path,
            "DISCOVERED_TOKEN=fixture-shared-value\n",
        )
        .unwrap();
        std::fs::write(
            &production_path,
            "DISCOVERED_TOKEN=fixture-shared-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                path: project_path,
                files: Some(vec![development_path, production_path.clone()]),
                separate_entries: vec![crate::protocol::DiscoveryEntryRef {
                    path: production_path,
                    address: "keys/DISCOVERED_TOKEN".to_string(),
                }],
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 2);
        assert_eq!(result.reused_resources, 0);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 2);
        assert_eq!(snapshot.bindings.len(), 2);
        assert_eq!(snapshot.surfaces.len(), 2);
    }

    #[test]
    fn discovery_apply_rejects_unreviewed_files_before_mutating_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&source_path, "DISCOVERED_TOKEN=fixture-value\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let error = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                path: project_path.clone(),
                files: Some(vec![project_path.join(".env.not-reviewed")]),
                separate_entries: Vec::new(),
            },
        )
        .unwrap_err();

        assert!(error.body().message.contains("not part of the reviewed discovery"));
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.projects.is_empty());
        assert!(snapshot.resources.is_empty());
        assert!(std::fs::symlink_metadata(source_path).unwrap().is_file());
    }

    #[test]
    fn discovery_apply_reports_a_later_file_failure_without_hiding_successes() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let dotenv_path = project_path.join(".env");
        let ssh_path = project_path.join(".ssh/id_fixture");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(ssh_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&dotenv_path, "DISCOVERED_TOKEN=fixture-value\n").unwrap();
        std::fs::write(
            &ssh_path,
            concat!(
                "-----BEGIN OPENSSH ",
                "PRIVATE KEY-----\ninvalid\n-----END OPENSSH ",
                "PRIVATE KEY-----\n"
            ),
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                path: project_path,
                files: Some(vec![dotenv_path.clone(), ssh_path.clone()]),
                separate_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.files.len(), 2);
        assert!(result
            .files
            .iter()
            .any(|file| file.path == dotenv_path
                && file.outcome == DiscoveryApplyOutcome::Imported));
        assert!(result
            .files
            .iter()
            .any(|file| file.path == ssh_path
                && file.outcome == DiscoveryApplyOutcome::Failed));
        assert!(result.project_id.is_some());
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
    }

    #[test]
    fn discovery_apply_keeps_aws_credentials_section_aware() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".aws/credentials");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &source_path,
            "[default]\naws_access_key_id=fixture-access-id\n\
             aws_secret_access_key=fixture-secret-value\n\
             [staging]\naws_access_key_id=fixture-staging-id\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                path: project_path,
                files: Some(vec![source_path.clone()]),
                separate_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 1);
        assert_eq!(result.files[0].outcome, DiscoveryApplyOutcome::Imported);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.resources[0].kind, ResourceKind::EnvFile);
        assert_eq!(snapshot.resources[0].codec, ResourceCodec::Ini);
        assert!(snapshot.resources[0]
            .entries
            .iter()
            .any(|entry| entry.address.contains("default")));
        assert!(snapshot.resources[0]
            .entries
            .iter()
            .any(|entry| entry.address.contains("staging")));
        assert_eq!(snapshot.surfaces[0].kind, SurfaceKind::IniFile);
        assert!(std::fs::symlink_metadata(source_path)
            .unwrap()
            .file_type()
            .is_symlink());
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
            test_peer_verifier(),
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
            test_peer_verifier(),
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
            test_peer_verifier(),
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
        let server = ControlServer::start(&socket, catalog, test_peer_verifier()).unwrap();
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
    fn untrusted_client_cannot_issue_control_commands() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let _server =
            ControlServer::start(&socket, catalog, Arc::new(RejectAllPeers)).unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        assert!(client.request(ControlCommand::Ping).is_err());
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
            test_peer_verifier(),
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
        let _server =
            ControlServer::start(&socket, catalog.clone(), test_peer_verifier()).unwrap();
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
        let _server = ControlServer::start(&socket, catalog, test_peer_verifier()).unwrap();
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
            test_peer_verifier(),
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
            test_peer_verifier(),
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
            test_peer_verifier(),
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
            test_peer_verifier(),
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
            test_peer_verifier(),
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
            test_peer_verifier(),
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
