use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use accessfs_catalog::{
    resolve_catalog_surface, Binding, BindingScope, Catalog, CatalogError, CatalogSnapshot,
    EntrySelection, EntrySpec, Environment, FileBacking, ItemMetadata, OriginKind, OriginSource,
    Project, ProjectCheckoutKind, Resource, ResourceCodec, ResourceKind, ResourceOrigin,
    ResourceSource, Surface, SurfaceFormat, SurfaceInput, SurfaceKind, ValueShape,
};
use accessfs_core::audit::{read_recent_access, AuditAccessRecord};
use accessfs_core::authz::{Enforcement, PolicyMode, PolicyModeStatus};
use accessfs_discover::{
    classify_key, discover_git_checkouts, discover_many, DiscoveredContent, DiscoveredFileAction,
    DiscoveredFileKind, DiscoveryPlan, ExistingEnvironment, ExistingProject, ExistingSecret,
    ExistingSurface, GitCheckoutDiscovery, GitCheckoutMonitor, KeyClass, MonitoredGitCheckout,
};
use accessfs_platform::SocketPeerVerifier;
use accessfs_ssh::{agent_runtime_socket_path, ManagedKeyError};
use accessfs_store::{NewSecret, SecretId, SecretOrigin, SecretRecord, SecretStore, StoreError};
use accessfs_surface::{
    checkout_link_issues, decode_source, ensure_file_surface_link, file_surface_instances,
    managed_file_links, protected_checkout_links, remove_excluded_protected_checkout_links,
    replace_regular_file_with_symlink_if_matches,
    replace_regular_file_with_symlink_if_unchanged,
    replace_symlink_with_file_if_target, restore_protected_checkout_links,
    validate_secret_bytes, ManagedLinkStatus as SurfaceManagedLinkStatus, ManagedSymlink,
    SurfaceResolver,
};

use crate::protocol::{
    read_msg, write_msg, AccessHistoryEvent, AccessHistoryIdentity, AccessHistoryProcess,
    AccessHistorySsh, ActiveGrant, ControlCommand, ControlErrorBody, ControlOutcome, ControlRequest,
    ControlResponse, ControlResult, DiscoveryAppliedFile, DiscoveryApplyOutcome, DiscoveryApplyResult,
    DiscoveryImport, DiscoveryImportDestination, DiscoveryJobPhase, DiscoveryJobProgress,
    DiscoveryJobState, DiscoveryJobStatus, DiscoveryManagedItem, DiscoveryManagedItemKind,
    DiscoveryReferenceResolution, DiscoveryReferenceSource, DiscoveryReviewPlan,
    DiscoverySourceDisposition, ManagedLink, ManagedLinkStatus,
    ProjectCheckoutCandidate, ProjectCheckoutDiscovery, ProjectCheckoutInventory, ProtectedFile,
    ProtectedFileVersion, SecretValue, SshConfigStatus, SshIdentity, WorkspaceSnapshot,
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
    pub ssh_runtime_dir: PathBuf,
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
    ssh_runtime_dir: Option<PathBuf>,
    discovery_jobs: Option<Arc<DiscoveryJobManager>>,
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
                ssh_runtime_dir: Some(services.ssh_runtime_dir),
                discovery_jobs: None,
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
        let discovery_jobs = dependencies
            .store
            .as_ref()
            .zip(dependencies.mount_path.as_ref())
            .map(|(store, mount_path)| {
                Arc::new(DiscoveryJobManager::new(
                    Arc::clone(&catalog),
                    Arc::clone(store),
                    mount_path.clone(),
                ))
            });
        let dependencies = ControlDependencies { discovery_jobs, ..dependencies };
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
            store_arc: dependencies.store.as_ref(),
            mount_path: dependencies.mount_path.as_deref(),
            policy: dependencies.policy.as_deref(),
            ssh_discovery: dependencies.ssh_discovery.as_deref(),
            ssh_config: dependencies.ssh_config.as_deref(),
            checkout_monitor: dependencies.checkout_monitor.as_deref(),
            audit_log: dependencies.audit_log.as_deref(),
            ssh_runtime_dir: dependencies.ssh_runtime_dir.as_deref(),
            discovery_jobs: dependencies.discovery_jobs.as_deref(),
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
            | ControlCommand::DiscoverStart { .. }
            | ControlCommand::DiscoverStatus { .. }
            | ControlCommand::DiscoverCancel { .. }
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
    store_arc: Option<&'a Arc<dyn SecretStore>>,
    mount_path: Option<&'a Path>,
    policy: Option<&'a dyn RuntimePolicyController>,
    ssh_discovery: Option<&'a dyn SshIdentityDiscovery>,
    ssh_config: Option<&'a dyn SshConfigManager>,
    checkout_monitor: Option<&'a GitCheckoutMonitor>,
    audit_log: Option<&'a Path>,
    ssh_runtime_dir: Option<&'a Path>,
    discovery_jobs: Option<&'a DiscoveryJobManager>,
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

mod checkouts;
mod discovery;
mod discovery_jobs;
mod discovery_reference;
mod dispatch;
mod history;
mod managed_links;
mod projects;
mod protected_files;
mod resources;
mod ssh;

use checkouts::*;
use discovery::*;
use discovery_jobs::*;
use discovery_reference::*;
use dispatch::*;
use history::*;
use managed_links::*;
use projects::*;
use protected_files::*;
use resources::*;
use ssh::*;

#[cfg(test)]
mod tests;
