//! Filtered SSH agent surfaces.
//!
//! One runtime socket represents one catalog Identity Set. Callers supply a catalog snapshot;
//! this deep module owns listener reconciliation, peer attribution, identity filtering, policy,
//! and audit. Private keys, signature payloads, and signatures are never persisted or logged.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use accessfs_catalog::{
    Binding, CatalogSnapshot, EntrySelection, Resource, ResourceKind, ResourceSource, SshRouteSpec,
    SurfaceInput, SurfaceKind, ValueShape,
};
use accessfs_core::audit::{AuditLog, SshSessionAudit};
use accessfs_core::authz::{
    AccessContext, AuthRequest, Authorizer, Operation, SshSignContext,
};
use accessfs_core::identity::ProcessIdentity;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_AGENT_FRAME: usize = 1 << 20;
const DOWNSTREAM_POLL: Duration = Duration::from_secs(1);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECTION_THREADS: usize = 16;
const RUNTIME_SOCKET_HASH_BYTES: usize = 12;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
const SSH_AGENT_EXTENSION_RESPONSE: u8 = 29;
const SSH_AGENT_SUCCESS: u8 = 6;
const SESSION_BIND_EXTENSION: &[u8] = b"session-bind@openssh.com";
const MAX_SESSION_BINDINGS: usize = 16;
const MAX_SESSION_ID_LEN: usize = 128;

/// Public metadata advertised by an upstream SSH agent. Key blobs are intentionally converted to
/// stable addresses/fingerprints here so callers never need to persist protocol payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredSshIdentity {
    pub address: String,
    pub fingerprint: String,
    pub comment: String,
}

/// The only storage capability needed by managed SSH identities. The runtime deliberately has no
/// access to catalog mutation, secret enumeration, or version history.
pub trait ManagedKeyReader: Send + Sync + 'static {
    fn read_private_key(&self, secret_id: &str) -> io::Result<Zeroizing<Vec<u8>>>;
}

/// Query one upstream agent without changing it. This is the discovery seam used by the control
/// plane before a Resource and its selectable identity entries are persisted in the catalog.
pub fn discover_identities(endpoint: &Path) -> io::Result<Vec<DiscoveredSshIdentity>> {
    if !endpoint.is_absolute() {
        return Err(invalid("SSH agent endpoint must be absolute"));
    }
    let mut stream = UnixStream::connect(endpoint)?;
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
    write_frame(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES])?;
    decode_identities_answer(&read_frame(&mut stream)?)
        .map(|identities| {
            identities
                .into_iter()
                .map(|identity| DiscoveredSshIdentity {
                    address: identity.address,
                    fingerprint: identity.fingerprint,
                    comment: String::from_utf8_lossy(&identity.comment).into_owned(),
                })
                .collect()
        })
}

/// Live manager for every catalog-backed SSH Agent Surface.
pub struct SshAgentRuntime {
    runtime_dir: PathBuf,
    config_path: PathBuf,
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<AuditLog>,
    managed_keys: Arc<dyn ManagedKeyReader>,
    connections: Arc<threadpool::ThreadPool>,
    running: Mutex<HashMap<String, RunningSurface>>,
}

impl SshAgentRuntime {
    pub fn new(
        runtime_dir: impl Into<PathBuf>,
        config_path: impl Into<PathBuf>,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<AuditLog>,
        managed_keys: Arc<dyn ManagedKeyReader>,
    ) -> io::Result<Self> {
        let runtime_dir = runtime_dir.into();
        let config_path = config_path.into();
        fs::create_dir_all(&runtime_dir)?;
        fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))?;
        Ok(SshAgentRuntime {
            runtime_dir,
            config_path,
            authorizer,
            audit,
            managed_keys,
            connections: Arc::new(threadpool::ThreadPool::new(CONNECTION_THREADS)),
            running: Mutex::new(HashMap::new()),
        })
    }

    /// Reconcile listeners against a complete catalog snapshot. Unchanged surfaces keep their
    /// listener and active sessions; changed/removed surfaces stop accepting immediately.
    pub fn replace(&self, snapshot: &CatalogSnapshot) -> io::Result<()> {
        let desired = compile_surface_specs(snapshot, &self.runtime_dir)?;
        let desired_ids = desired
            .iter()
            .map(|spec| spec.id.as_str())
            .collect::<HashSet<_>>();
        let mut running = self.running.lock().expect("SSH agent runtime poisoned");

        let removed = running
            .keys()
            .filter(|id| !desired_ids.contains(id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for id in removed {
            if let Some(mut server) = running.remove(&id) {
                server.stop();
            }
        }

        let mut first_error = None;
        for spec in desired.iter().cloned() {
            if running.get(&spec.id).is_some_and(|server| server.spec == spec) {
                if let Err(error) = ensure_project_link(&spec.project_path, &spec.socket_path) {
                    tracing::warn!(surface = %spec.id, path = %spec.project_path.display(), %error, "SSH agent project link needs attention");
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                continue;
            }
            if let Some(mut previous) = running.remove(&spec.id) {
                previous.stop();
            }
            match RunningSurface::start(
                spec,
                Arc::clone(&self.authorizer),
                Arc::clone(&self.audit),
                Arc::clone(&self.connections),
                Arc::clone(&self.managed_keys),
            ) {
                Ok(server) => {
                    tracing::info!(surface = %server.spec.id, socket = %server.spec.socket_path.display(), "SSH agent surface listening");
                    running.insert(server.spec.id.clone(), server);
                }
                Err(error) => {
                    tracing::warn!(%error, "starting SSH agent surface failed");
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => write_generated_config(&self.config_path, &desired),
        }
    }

    pub fn socket_path(&self, surface_id: &str) -> PathBuf {
        runtime_socket_path(&self.runtime_dir, surface_id)
    }
}

impl Drop for SshAgentRuntime {
    fn drop(&mut self) {
        let running = match self.running.get_mut() {
            Ok(running) => running,
            Err(poisoned) => poisoned.into_inner(),
        };
        for server in running.values_mut() {
            server.stop();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SurfaceSpec {
    id: String,
    name: String,
    socket_path: PathBuf,
    project_path: PathBuf,
    providers: Vec<ProviderSpec>,
    identities: Vec<SelectedIdentity>,
    route: Option<SshRouteSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderSpec {
    ManagedPrivateKey {
        resource_id: String,
        secret_id: String,
    },
    ExternalAgent {
        resource_id: String,
        endpoint: PathBuf,
    },
}

impl ProviderSpec {
    fn resource_id(&self) -> &str {
        match self {
            ProviderSpec::ManagedPrivateKey { resource_id, .. }
            | ProviderSpec::ExternalAgent { resource_id, .. } => resource_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedIdentity {
    provider_index: usize,
    address: String,
    label: String,
}

fn compile_surface_specs(
    snapshot: &CatalogSnapshot,
    runtime_dir: &Path,
) -> io::Result<Vec<SurfaceSpec>> {
    let bindings = snapshot
        .bindings
        .iter()
        .map(|binding| (binding.id.as_str(), binding))
        .collect::<HashMap<_, _>>();
    let resources = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect::<HashMap<_, _>>();
    let mut specs = Vec::new();

    for surface in snapshot
        .surfaces
        .iter()
        .filter(|surface| surface.kind == SurfaceKind::UnixSocket)
    {
        let (binding_ids, route) = match &surface.input {
            SurfaceInput::Bindings { binding_ids } => (binding_ids, None),
            SurfaceInput::SshAgent { binding_ids, route } => (binding_ids, route.clone()),
            SurfaceInput::Resource { .. } => {
                return Err(invalid(format!(
                    "SSH agent surface {:?} requires binding input",
                    surface.id
                )))
            }
        };
        let socket_path = runtime_socket_path(runtime_dir, &surface.id);
        let mut providers = Vec::<ProviderSpec>::new();
        let mut provider_indexes = HashMap::<&str, usize>::new();
        let mut identities = Vec::new();
        let mut addresses = HashSet::new();

        for binding_id in binding_ids {
            let binding = bindings
                .get(binding_id.as_str())
                .ok_or_else(|| invalid(format!("missing binding {binding_id:?}")))?;
            if !binding.enabled {
                continue;
            }
            let resource = resources
                .get(binding.resource_id.as_str())
                .ok_or_else(|| invalid(format!("missing resource {:?}", binding.resource_id)))?;
            let provider = ssh_provider(resource)?;
            if let ProviderSpec::ExternalAgent { endpoint, .. } = &provider {
                if endpoint == &socket_path || endpoint == &surface.path {
                    return Err(invalid(format!(
                        "SSH agent resource {:?} points back to surface {:?}",
                        resource.id, surface.id
                    )));
                }
            }
            let provider_index = match provider_indexes.get(resource.id.as_str()).copied() {
                Some(index) => index,
                None => {
                    let index = providers.len();
                    providers.push(provider);
                    provider_indexes.insert(resource.id.as_str(), index);
                    index
                }
            };

            for entry in selected_entries(binding, resource) {
                if !addresses.insert(entry.address.as_str()) {
                    return Err(invalid(format!(
                        "SSH agent surface {:?} selects duplicate identity {:?}",
                        surface.id, entry.address
                    )));
                }
                identities.push(SelectedIdentity {
                    provider_index,
                    address: entry.address.clone(),
                    label: entry.label.clone(),
                });
            }
        }

        specs.push(SurfaceSpec {
            id: surface.id.clone(),
            name: surface.name.clone(),
            socket_path,
            project_path: surface.path.clone(),
            providers,
            identities,
            route,
        });
    }
    Ok(specs)
}

fn runtime_socket_path(runtime_dir: &Path, surface_id: &str) -> PathBuf {
    let digest = Sha256::digest(surface_id.as_bytes());
    let name = URL_SAFE_NO_PAD.encode(&digest[..RUNTIME_SOCKET_HASH_BYTES]);
    runtime_dir.join(format!("{name}.sock"))
}

fn write_generated_config(path: &Path, specs: &[SurfaceSpec]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("generated SSH config has no parent directory"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;

    let mut body = String::from(
        "# Generated by Floria. Do not edit.\n# Include this file near the top of ~/.ssh/config.\n",
    );
    for spec in specs {
        let Some(route) = &spec.route else { continue };
        body.push_str("\n# ");
        body.push_str(&spec.name.replace(['\n', '\r'], " "));
        body.push_str("\nHost ");
        body.push_str(&route.host_patterns.join(" "));
        body.push_str("\n    IdentityAgent ");
        body.push_str(&ssh_config_quote(&spec.socket_path));
        body.push('\n');
        // A routed host must not fall back to ~/.ssh/id_* and sign outside Floria's
        // authorization and audit boundary. Agent identities remain available.
        body.push_str("    IdentityFile none\n");
        if let Some(hostname) = &route.hostname {
            body.push_str("    HostName ");
            body.push_str(&ssh_config_quote(Path::new(hostname)));
            body.push('\n');
        }
        if let Some(user) = &route.user {
            body.push_str("    User ");
            body.push_str(&ssh_config_quote(Path::new(user)));
            body.push('\n');
        }
        if let Some(port) = route.port {
            body.push_str(&format!("    Port {port}\n"));
        }
        if route.forward_agent {
            body.push_str("    ForwardAgent yes\n");
        }
    }

    let temp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn ssh_config_quote(value: &Path) -> String {
    let value = value.to_string_lossy();
    format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""))
}

fn ssh_provider(resource: &Resource) -> io::Result<ProviderSpec> {
    match (&resource.kind, &resource.shape, &resource.source) {
        (
            ResourceKind::SshIdentity,
            ValueShape::SshIdentity,
            ResourceSource::SecretRef { secret_id },
        ) => Ok(ProviderSpec::ManagedPrivateKey {
            resource_id: resource.id.clone(),
            secret_id: secret_id.clone(),
        }),
        (
            ResourceKind::SshAgent,
            ValueShape::Socket,
            ResourceSource::Socket { endpoint },
        ) => Ok(ProviderSpec::ExternalAgent {
            resource_id: resource.id.clone(),
            endpoint: endpoint.clone(),
        }),
        _ => Err(invalid(format!(
            "resource {:?} is not an SSH identity provider",
            resource.id
        ))),
    }
}

fn selected_entries<'a>(
    binding: &'a Binding,
    resource: &'a Resource,
) -> impl Iterator<Item = &'a accessfs_catalog::EntrySpec> {
    resource.entries.iter().filter(|entry| match &binding.selection {
        EntrySelection::All => true,
        EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
    })
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

struct RunningSurface {
    spec: SurfaceSpec,
    stop: Arc<AtomicBool>,
    socket_inode: u64,
    accept_thread: Option<JoinHandle<()>>,
}

impl RunningSurface {
    fn start(
        spec: SurfaceSpec,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<AuditLog>,
        connections: Arc<threadpool::ThreadPool>,
        managed_keys: Arc<dyn ManagedKeyReader>,
    ) -> io::Result<Self> {
        remove_stale_socket(&spec.socket_path)?;
        let listener = UnixListener::bind(&spec.socket_path)?;
        fs::set_permissions(&spec.socket_path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let socket_inode = fs::symlink_metadata(&spec.socket_path)?.ino();
        if let Err(error) = ensure_project_link(&spec.project_path, &spec.socket_path) {
            tracing::warn!(surface = %spec.id, path = %spec.project_path.display(), %error, "SSH agent project link needs attention");
        }

        let stop = Arc::new(AtomicBool::new(false));
        let loop_stop = Arc::clone(&stop);
        let loop_spec = spec.clone();
        let thread = std::thread::Builder::new()
            .name(format!("accessfs-ssh-agent-{}", spec.id))
            .spawn(move || {
                accept_loop(
                    listener,
                    loop_spec,
                    authorizer,
                    audit,
                    connections,
                    managed_keys,
                    loop_stop,
                )
            })?;

        Ok(RunningSurface {
            spec,
            stop,
            socket_inode,
            accept_thread: Some(thread),
        })
    }

    fn stop(&mut self) {
        if self.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = UnixStream::connect(&self.spec.socket_path);
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
        remove_exact_project_link(&self.spec.project_path, &self.spec.socket_path);
        remove_exact_socket(&self.spec.socket_path, self.socket_inode);
    }
}

fn accept_loop(
    listener: UnixListener,
    spec: SurfaceSpec,
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<AuditLog>,
    connections: Arc<threadpool::ThreadPool>,
    managed_keys: Arc<dyn ManagedKeyReader>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let Some(identity) = peer_identity(&stream) else {
                    tracing::warn!(surface = %spec.id, "rejecting SSH agent peer from another uid");
                    continue;
                };
                let connection_spec = spec.clone();
                let connection_authorizer = Arc::clone(&authorizer);
                let connection_audit = Arc::clone(&audit);
                let connection_stop = Arc::clone(&stop);
                let connection_managed_keys = Arc::clone(&managed_keys);
                connections.execute(move || {
                    if let Err(error) = serve_connection(
                        stream,
                        connection_spec,
                        identity,
                        connection_authorizer,
                        connection_audit,
                        connection_managed_keys,
                        connection_stop,
                    ) {
                        tracing::debug!(%error, "SSH agent connection closed");
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                tracing::warn!(surface = %spec.id, %error, "accepting SSH agent connection failed");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn peer_identity(stream: &UnixStream) -> Option<ProcessIdentity> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: valid socket fd and stack out-parameters.
    let peer_ok = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0;
    // SAFETY: geteuid has no preconditions.
    if !peer_ok || uid != unsafe { libc::geteuid() } {
        return None;
    }
    match peer_pid(stream) {
        Some(pid) => Some(accessfs_platform::enrich(pid, uid, gid)),
        None => Some(ProcessIdentity::bare(-1, uid, gid)),
    }
}

#[cfg(target_os = "macos")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: valid socket fd; pid/len are correctly sized writable out-parameters.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    (rc == 0 && pid > 0).then_some(pid)
}

#[cfg(not(target_os = "macos"))]
fn peer_pid(_stream: &UnixStream) -> Option<i32> {
    None
}

struct ProviderSession {
    spec: ProviderSpec,
    stream: Option<UnixStream>,
    managed_keys: Arc<dyn ManagedKeyReader>,
}

impl ProviderSession {
    fn external_round_trip(&mut self, request: &[u8]) -> io::Result<Vec<u8>> {
        let ProviderSpec::ExternalAgent { endpoint, .. } = &self.spec else {
            return Err(invalid("managed SSH key has no upstream agent"));
        };
        if self.stream.is_none() {
            let stream = UnixStream::connect(endpoint)?;
            stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
            stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
            self.stream = Some(stream);
        }
        let stream = self.stream.as_mut().expect("provider stream initialized");
        if let Err(error) = write_frame(stream, request) {
            self.stream = None;
            return Err(error);
        }
        match read_frame(stream) {
            Ok(response) => Ok(response),
            Err(error) => {
                self.stream = None;
                Err(error)
            }
        }
    }

    fn identities(&mut self) -> io::Result<HashMap<String, ParsedIdentity>> {
        match &self.spec {
            ProviderSpec::ManagedPrivateKey { secret_id, .. } => {
                let encoded = self.managed_keys.read_private_key(secret_id)?;
                let identity = accessfs_ssh::identity_from_private_key(&encoded)
                    .map_err(|error| invalid(error.to_string()))?;
                Ok([(
                    identity.address,
                    ParsedIdentity {
                        key_blob: identity.key_blob,
                        fingerprint: identity.fingerprint,
                    },
                )]
                .into_iter()
                .collect())
            }
            ProviderSpec::ExternalAgent { .. } => {
                let response = self.external_round_trip(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
                parse_identities_answer(&response)
            }
        }
    }

    fn sign(&mut self, request: &[u8], parsed: &ParsedSignRequest<'_>) -> io::Result<Vec<u8>> {
        match &self.spec {
            ProviderSpec::ManagedPrivateKey { secret_id, .. } => {
                let encoded = self.managed_keys.read_private_key(secret_id)?;
                let signature = accessfs_ssh::sign(&encoded, parsed.data, parsed.flags)
                    .map_err(|error| invalid(error.to_string()))?;
                let mut response = vec![SSH_AGENT_SIGN_RESPONSE];
                put_string(&mut response, &signature);
                Ok(response)
            }
            ProviderSpec::ExternalAgent { .. } => self.external_round_trip(request),
        }
    }
}

struct AvailableIdentity {
    provider_index: usize,
    resource_id: String,
    fingerprint: String,
    label: String,
}

struct ConnectionState {
    providers: Vec<ProviderSession>,
    available: HashMap<Vec<u8>, AvailableIdentity>,
    session_bindings: SessionBindings,
}

fn serve_connection(
    mut downstream: UnixStream,
    spec: SurfaceSpec,
    identity: ProcessIdentity,
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<AuditLog>,
    managed_keys: Arc<dyn ManagedKeyReader>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    downstream.set_read_timeout(Some(DOWNSTREAM_POLL))?;
    downstream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
    let mut state = ConnectionState {
        providers: spec
            .providers
            .iter()
            .cloned()
            .map(|spec| ProviderSession {
                spec,
                stream: None,
                managed_keys: Arc::clone(&managed_keys),
            })
            .collect(),
        available: HashMap::new(),
        session_bindings: SessionBindings::default(),
    };

    while !stop.load(Ordering::Acquire) {
        let request = match read_frame_interruptible(&mut downstream, &stop) {
            Ok(request) => request,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
            Err(error) => return Err(error),
        };
        let response = match request.first().copied() {
            Some(SSH_AGENTC_REQUEST_IDENTITIES) if request.len() == 1 => {
                match refresh_identities(
                    &spec,
                    &mut state.providers,
                    &mut state.available,
                ) {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::warn!(surface = %spec.id, %error, "refreshing SSH identities failed");
                        vec![SSH_AGENT_FAILURE]
                    }
                }
            }
            Some(SSH_AGENTC_SIGN_REQUEST) => handle_sign(
                &spec,
                &identity,
                &authorizer,
                &audit,
                &request,
                &mut state,
            ),
            Some(SSH_AGENTC_EXTENSION) => {
                match handle_extension(&request, &mut state.session_bindings) {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::warn!(surface = %spec.id, %error, "SSH agent extension failed");
                        vec![SSH_AGENT_EXTENSION_FAILURE]
                    }
                }
            }
            _ => vec![SSH_AGENT_FAILURE],
        };
        write_frame(&mut downstream, &response)?;
    }
    Ok(())
}

fn refresh_identities(
    spec: &SurfaceSpec,
    providers: &mut [ProviderSession],
    available: &mut HashMap<Vec<u8>, AvailableIdentity>,
) -> io::Result<Vec<u8>> {
    let mut upstream = Vec::<HashMap<String, ParsedIdentity>>::with_capacity(providers.len());
    for provider in providers.iter_mut() {
        upstream.push(provider.identities()?);
    }

    let mut answer = Vec::new();
    available.clear();
    for selected in &spec.identities {
        let parsed = upstream
            .get_mut(selected.provider_index)
            .and_then(|identities| identities.remove(&selected.address))
            .ok_or_else(|| {
                invalid(format!(
                    "selected SSH identity {:?} is unavailable",
                    selected.address
                ))
            })?;
        if available.contains_key(&parsed.key_blob) {
            return Err(invalid(format!(
                "SSH identity {:?} is supplied by multiple providers",
                selected.address
            )));
        }
        let resource_id = providers[selected.provider_index]
            .spec
            .resource_id()
            .to_string();
        answer.push((parsed.key_blob.clone(), selected.label.as_bytes().to_vec()));
        available.insert(
            parsed.key_blob,
            AvailableIdentity {
                provider_index: selected.provider_index,
                resource_id,
                fingerprint: parsed.fingerprint,
                label: selected.label.clone(),
            },
        );
    }
    Ok(encode_identities_answer(&answer))
}

fn handle_sign(
    spec: &SurfaceSpec,
    identity: &ProcessIdentity,
    authorizer: &Arc<dyn Authorizer>,
    audit: &AuditLog,
    request: &[u8],
    state: &mut ConnectionState,
) -> Vec<u8> {
    let parsed = match parse_sign_request(request) {
        Ok(parsed) => parsed,
        Err(_) => return vec![SSH_AGENT_FAILURE],
    };
    if state.available.is_empty()
        && refresh_identities(spec, &mut state.providers, &mut state.available).is_err()
    {
        return vec![SSH_AGENT_FAILURE];
    }
    let Some(selected) = state.available.get(parsed.key) else {
        let (_, fingerprint) = identity_names(parsed.key);
        audit.log_ssh_sign(
            &format!("surfaces/{}", spec.id),
            identity,
            "denied",
            Some("identity-set"),
            "identity is not exposed by this SSH agent surface",
            None,
            &spec.id,
            "unselected",
            &fingerprint,
            "identity_not_selected",
            None,
        );
        return vec![SSH_AGENT_FAILURE];
    };

    let path = format!("surfaces/{}", spec.id);
    let requested_destination = identity
        .cmdline
        .as_deref()
        .and_then(ssh_requested_destination);
    let verified_session = state.session_bindings.context_for_sign(&parsed);
    let ssh_session_audit = SshSessionAudit {
        requested_destination,
        verified_host_key_fingerprint: verified_session
            .as_ref()
            .map(|session| session.host_key_fingerprint),
        ssh_user: verified_session.as_ref().map(|session| session.ssh_user),
        forwarding_hops: verified_session
            .as_ref()
            .map_or(0, |session| session.forwarding_hops),
    };
    let context = AccessContext::SshSign(SshSignContext {
        surface_id: &spec.id,
        surface_name: &spec.name,
        resource_id: &selected.resource_id,
        key_fingerprint: &selected.fingerprint,
        key_label: &selected.label,
        requested_destination,
        verified_host_key_fingerprint: verified_session
            .as_ref()
            .map(|session| session.host_key_fingerprint),
        ssh_user: verified_session.as_ref().map(|session| session.ssh_user),
        forwarding_hops: verified_session
            .as_ref()
            .map_or(0, |session| session.forwarding_hops),
    });
    let decision = authorizer.authorize(&AuthRequest {
        path: &path,
        display: Some(&spec.name),
        operation: Operation::Sign,
        context: Some(context),
        identity,
    });
    if !decision.is_allowed() {
        audit.log_ssh_sign(
            &path,
            identity,
            decision.decision_str(),
            decision.rule_id.as_deref(),
            &decision.reason,
            decision.policy.as_ref(),
            &spec.id,
            &selected.resource_id,
            &selected.fingerprint,
            "authorization_denied",
            Some(ssh_session_audit),
        );
        return vec![SSH_AGENT_FAILURE];
    }

    let (response, result) = match state.providers[selected.provider_index].sign(request, &parsed) {
        Ok(response) if response.first() == Some(&SSH_AGENT_SIGN_RESPONSE) => (response, "signed"),
        Ok(response) if response.first() == Some(&SSH_AGENT_FAILURE) => {
            (response, "upstream_refused")
        }
        Ok(_) => (vec![SSH_AGENT_FAILURE], "invalid_upstream_response"),
        Err(error) => {
            tracing::warn!(surface = %spec.id, resource = %selected.resource_id, %error, "SSH signature provider failed");
            (vec![SSH_AGENT_FAILURE], "upstream_error")
        }
    };
    audit.log_ssh_sign(
        &path,
        identity,
        decision.decision_str(),
        decision.rule_id.as_deref(),
        &decision.reason,
        decision.policy.as_ref(),
        &spec.id,
        &selected.resource_id,
        &selected.fingerprint,
        result,
        Some(ssh_session_audit),
    );
    response
}

/// Extract the destination token from a direct OpenSSH invocation for display. This intentionally
/// does not resolve aliases or claim the name is verified; session-bind authenticates a host key,
/// not the hostname that the user typed.
fn ssh_requested_destination(cmdline: &[String]) -> Option<&str> {
    let program = Path::new(cmdline.first()?).file_name()?.to_str()?;
    if program != "ssh" {
        return None;
    }

    let mut options = true;
    let mut skip_next = false;
    for argument in &cmdline[1..] {
        if skip_next {
            skip_next = false;
            continue;
        }
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options && argument.starts_with('-') && argument != "-" {
            skip_next = ssh_option_consumes_next(argument);
            continue;
        }
        return Some(argument);
    }
    None
}

fn ssh_option_consumes_next(argument: &str) -> bool {
    const WITH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";

    argument
        .char_indices()
        .skip(1)
        .find(|(_, option)| WITH_VALUE.contains(*option))
        .is_some_and(|(index, option)| index + option.len_utf8() == argument.len())
}

struct ParsedIdentity {
    key_blob: Vec<u8>,
    fingerprint: String,
}

fn parse_identities_answer(response: &[u8]) -> io::Result<HashMap<String, ParsedIdentity>> {
    let decoded = decode_identities_answer(response)?;
    Ok(decoded
        .into_iter()
        .map(|identity| {
            (
                identity.address,
                ParsedIdentity {
                    key_blob: identity.key_blob,
                    fingerprint: identity.fingerprint,
                },
            )
        })
        .collect())
}

struct DecodedIdentity {
    key_blob: Vec<u8>,
    address: String,
    fingerprint: String,
    comment: Vec<u8>,
}

fn decode_identities_answer(response: &[u8]) -> io::Result<Vec<DecodedIdentity>> {
    let mut reader = WireReader::new(response);
    if reader.byte()? != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(invalid("upstream did not return an identities answer"));
    }
    let count = reader.u32()? as usize;
    let mut identities = Vec::with_capacity(count);
    let mut addresses = HashSet::with_capacity(count);
    for _ in 0..count {
        let key_blob = reader.string()?.to_vec();
        let comment = reader.string()?.to_vec();
        let (address, fingerprint) = identity_names(&key_blob);
        if !addresses.insert(address.clone()) {
            return Err(invalid(format!(
                "upstream returned duplicate identity {address:?}"
            )));
        }
        identities.push(DecodedIdentity {
            key_blob,
            address,
            fingerprint,
            comment,
        });
    }
    reader.finish()?;
    Ok(identities)
}

struct ParsedSignRequest<'a> {
    key: &'a [u8],
    data: &'a [u8],
    flags: u32,
}

#[derive(Default)]
struct SessionBindings {
    entries: Vec<SessionBinding>,
}

struct SessionBinding {
    host_key: Vec<u8>,
    host_key_fingerprint: String,
    session_id: Vec<u8>,
    forwarded: bool,
}

struct VerifiedSshSession<'a> {
    host_key_fingerprint: &'a str,
    ssh_user: &'a str,
    forwarding_hops: usize,
}

impl SessionBindings {
    fn bind(&mut self, request: &[u8]) -> io::Result<()> {
        let mut reader = WireReader::new(request);
        if reader.byte()? != SSH_AGENTC_EXTENSION
            || reader.string()? != SESSION_BIND_EXTENSION
        {
            return Err(invalid("not an OpenSSH session-bind request"));
        }
        let host_key = reader.string()?;
        let session_id = reader.string()?;
        let signature = reader.string()?;
        let forwarded = reader.byte()? != 0;
        reader.finish()?;

        if session_id.is_empty() {
            return Err(invalid("SSH session identifier is empty"));
        }
        if session_id.len() > MAX_SESSION_ID_LEN {
            return Err(invalid("SSH session identifier is too long"));
        }
        accessfs_ssh::verify_public_signature(host_key, session_id, signature)
            .map_err(|error| invalid(error.to_string()))?;

        for existing in &self.entries {
            if !existing.forwarded {
                return Err(invalid(
                    "agent connection was already bound for authentication",
                ));
            }
            if existing.session_id == session_id {
                if existing.host_key == host_key {
                    return Ok(());
                }
                return Err(invalid(
                    "SSH session identifier was already bound to another host key",
                ));
            }
        }
        if self.entries.len() >= MAX_SESSION_BINDINGS {
            return Err(invalid("too many SSH session bindings"));
        }

        let (_, host_key_fingerprint) = identity_names(host_key);
        self.entries.push(SessionBinding {
            host_key: host_key.to_vec(),
            host_key_fingerprint,
            session_id: session_id.to_vec(),
            forwarded,
        });
        Ok(())
    }

    fn context_for_sign<'a>(
        &'a self,
        request: &ParsedSignRequest<'a>,
    ) -> Option<VerifiedSshSession<'a>> {
        let binding = self.entries.last()?;
        if binding.forwarded {
            return None;
        }

        let mut reader = WireReader::new(request.data);
        let session_id = reader.string().ok()?;
        if reader.byte().ok()? != 50 {
            return None;
        }
        let ssh_user = std::str::from_utf8(reader.string().ok()?).ok()?;
        if reader.string().ok()? != b"ssh-connection" {
            return None;
        }
        let method = reader.string().ok()?;
        if reader.byte().ok()? != 1 {
            return None;
        }
        let _algorithm = reader.string().ok()?;
        if reader.string().ok()? != request.key {
            return None;
        }
        let signed_host_key = match method {
            b"publickey" => None,
            b"publickey-hostbound-v00@openssh.com" => Some(reader.string().ok()?),
            _ => return None,
        };
        reader.finish().ok()?;

        if session_id != binding.session_id {
            return None;
        }
        if self.entries.len() > 1 && signed_host_key.is_none() {
            return None;
        }
        if signed_host_key.is_some_and(|host_key| host_key != binding.host_key) {
            return None;
        }
        Some(VerifiedSshSession {
            host_key_fingerprint: &binding.host_key_fingerprint,
            ssh_user,
            forwarding_hops: self.entries.len().saturating_sub(1),
        })
    }
}

fn handle_extension(
    request: &[u8],
    session_bindings: &mut SessionBindings,
) -> io::Result<Vec<u8>> {
    let mut reader = WireReader::new(request);
    if reader.byte()? != SSH_AGENTC_EXTENSION {
        return Err(invalid("not an SSH agent extension request"));
    }
    match reader.string()? {
        b"query" => {
            reader.finish()?;
            let mut response = vec![SSH_AGENT_EXTENSION_RESPONSE];
            put_string(&mut response, b"query");
            put_string(&mut response, SESSION_BIND_EXTENSION);
            Ok(response)
        }
        SESSION_BIND_EXTENSION => {
            session_bindings.bind(request)?;
            Ok(vec![SSH_AGENT_SUCCESS])
        }
        _ => Ok(vec![SSH_AGENT_EXTENSION_FAILURE]),
    }
}

fn parse_sign_request(request: &[u8]) -> io::Result<ParsedSignRequest<'_>> {
    let mut reader = WireReader::new(request);
    if reader.byte()? != SSH_AGENTC_SIGN_REQUEST {
        return Err(invalid("not an SSH sign request"));
    }
    let key = reader.string()?;
    let data = reader.string()?;
    let flags = reader.u32()?;
    reader.finish()?;
    Ok(ParsedSignRequest { key, data, flags })
}

fn identity_names(key_blob: &[u8]) -> (String, String) {
    let digest = Sha256::digest(key_blob);
    (
        format!("ssh/sha256/{}", URL_SAFE_NO_PAD.encode(digest)),
        format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)),
    )
}

fn encode_identities_answer(identities: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut response = vec![SSH_AGENT_IDENTITIES_ANSWER];
    response.extend_from_slice(&(identities.len() as u32).to_be_bytes());
    for (key_blob, comment) in identities {
        put_string(&mut response, key_blob);
        put_string(&mut response, comment);
    }
    response
}

fn put_string(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buffer.extend_from_slice(value);
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        WireReader { bytes, offset: 0 }
    }

    fn byte(&mut self) -> io::Result<u8> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| invalid("truncated SSH agent message"))?;
        self.offset += 1;
        Ok(byte)
    }

    fn u32(&mut self) -> io::Result<u32> {
        let end = self
            .offset
            .checked_add(4)
            .ok_or_else(|| invalid("SSH agent length overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated SSH agent uint32"))?;
        self.offset = end;
        Ok(u32::from_be_bytes(bytes.try_into().expect("four-byte slice")))
    }

    fn string(&mut self) -> io::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| invalid("SSH agent string length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated SSH agent string"))?;
        self.offset = end;
        Ok(value)
    }

    fn finish(&self) -> io::Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid("trailing bytes in SSH agent message"))
        }
    }
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    read_frame_body(stream, u32::from_be_bytes(len) as usize)
}

fn read_frame_interruptible(
    stream: &mut UnixStream,
    stop: &AtomicBool,
) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    read_exact_interruptible(stream, &mut len, stop)?;
    let size = u32::from_be_bytes(len) as usize;
    if size == 0 || size > MAX_AGENT_FRAME {
        return Err(invalid("invalid SSH agent frame length"));
    }
    let mut body = vec![0u8; size];
    read_exact_interruptible(stream, &mut body, stop)?;
    Ok(body)
}

fn read_exact_interruptible(
    stream: &mut UnixStream,
    buffer: &mut [u8],
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        if stop.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "surface stopped"));
        }
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "agent EOF")),
            Ok(read) => offset += read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_frame_body(stream: &mut UnixStream, size: usize) -> io::Result<Vec<u8>> {
    if size == 0 || size > MAX_AGENT_FRAME {
        return Err(invalid("invalid SSH agent frame length"));
    }
    let mut body = vec![0u8; size];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn write_frame(stream: &mut UnixStream, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| invalid("SSH agent frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} is not a stale socket", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn ensure_project_link(path: &Path, target: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let actual = fs::read_link(path)?;
            if actual == target {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} points to {}", path.display(), actual.display()),
                ))
            }
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} is occupied by a non-symlink", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => symlink(target, path),
        Err(error) => Err(error),
    }
}

fn remove_exact_project_link(path: &Path, target: &Path) {
    let exact = fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.file_type().is_symlink())
        .and_then(|_| fs::read_link(path).ok())
        .is_some_and(|actual| actual == target);
    if exact {
        let _ = fs::remove_file(path);
    }
}

fn remove_exact_socket(path: &Path, inode: u64) {
    let exact = fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.file_type().is_socket() && metadata.ino() == inode)
        .is_some();
    if exact {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use accessfs_catalog::{
        BindingScope, EntrySpec, Environment, Project, ResourceCodec, SshRouteSpec, Surface,
    };
    use accessfs_core::authz::{Decision, Enforcement};

    const KEY_A: &[u8] = b"fixture-public-identity-a-v1";
    const KEY_B: &[u8] = b"fixture-public-identity-b-v1";

    struct NoManagedKeys;

    impl ManagedKeyReader for NoManagedKeys {
        fn read_private_key(&self, _secret_id: &str) -> io::Result<Zeroizing<Vec<u8>>> {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "fixture has no managed keys",
            ))
        }
    }

    struct FixtureManagedKeys {
        entries: HashMap<String, Vec<u8>>,
    }

    impl ManagedKeyReader for FixtureManagedKeys {
        fn read_private_key(&self, secret_id: &str) -> io::Result<Zeroizing<Vec<u8>>> {
            self.entries
                .get(secret_id)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "fixture key not found"))
        }
    }

    #[test]
    fn runtime_socket_path_fits_unix_socket_address_for_catalog_surface_ids() {
        let runtime_dir = Path::new(
            "/Users/fixture-account/Library/Application Support/floria/runtime/sockets",
        );
        let surface_id = "ssh-agent-d56d57b2-3503-40e9-86d0-48a6ca9168fd";
        let path = runtime_socket_path(runtime_dir, surface_id);
        let address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };

        assert_eq!(path.file_name().unwrap(), "3YUjhPR-lx4my6EW.sock");
        assert!(
            path.as_os_str().as_bytes().len() < address.sun_path.len(),
            "{} uses {} bytes but sockaddr_un.sun_path only has {}",
            path.display(),
            path.as_os_str().as_bytes().len(),
            address.sun_path.len(),
        );
    }

    #[test]
    fn extracts_display_destination_from_common_openssh_arguments() {
        let arguments = [
            "/usr/bin/ssh",
            "-vvv",
            "-o",
            "BatchMode=yes",
            "-p2222",
            "git@fixture.example",
            "git-upload-pack",
        ]
        .map(str::to_string);
        assert_eq!(
            ssh_requested_destination(&arguments),
            Some("git@fixture.example")
        );

        let separated_port = ["ssh", "-p", "2222", "fixture.example"].map(str::to_string);
        assert_eq!(
            ssh_requested_destination(&separated_port),
            Some("fixture.example")
        );

        let other_program = ["ssh-add", "-T", "fixture.pub"].map(str::to_string);
        assert_eq!(ssh_requested_destination(&other_program), None);
    }

    struct RecordingAuthorizer {
        allow: AtomicBool,
        requests: Mutex<Vec<(String, String, String)>>,
    }

    impl RecordingAuthorizer {
        fn allowing() -> Self {
            RecordingAuthorizer {
                allow: AtomicBool::new(true),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl Authorizer for RecordingAuthorizer {
        fn authorize(&self, request: &AuthRequest) -> Decision {
            let fingerprint = match request.context {
                Some(AccessContext::SshSign(context)) => context.key_fingerprint.to_string(),
                None => String::new(),
            };
            self.requests.lock().unwrap().push((
                request.operation.as_str().to_string(),
                request.path.to_string(),
                fingerprint,
            ));
            if self.allow.load(Ordering::Acquire) {
                Decision::allow("fixture policy allowed").with_rule("fixture-allow")
            } else {
                Decision::deny("fixture policy denied").with_rule("fixture-deny")
            }
        }
    }

    struct FakeUpstream {
        path: PathBuf,
        stop: Arc<AtomicBool>,
        signs: Arc<AtomicUsize>,
        thread: Option<JoinHandle<()>>,
    }

    impl FakeUpstream {
        fn start(path: PathBuf) -> Self {
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let signs = Arc::new(AtomicUsize::new(0));
            let thread_stop = Arc::clone(&stop);
            let thread_signs = Arc::clone(&signs);
            let thread = std::thread::spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(value) => value,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => break,
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    loop {
                        if thread_stop.load(Ordering::Acquire) {
                            break;
                        }
                        let request = match read_frame_interruptible(&mut stream, &thread_stop) {
                            Ok(request) => request,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
                            Err(_) => break,
                        };
                        let response = match request.first().copied() {
                            Some(SSH_AGENTC_REQUEST_IDENTITIES) => encode_identities_answer(&[
                                (KEY_A.to_vec(), b"upstream-a".to_vec()),
                                (KEY_B.to_vec(), b"upstream-b".to_vec()),
                            ]),
                            Some(SSH_AGENTC_SIGN_REQUEST) => {
                                thread_signs.fetch_add(1, Ordering::AcqRel);
                                let mut response = vec![SSH_AGENT_SIGN_RESPONSE];
                                put_string(&mut response, b"fixture-signature-response");
                                response
                            }
                            _ => vec![SSH_AGENT_FAILURE],
                        };
                        if write_frame(&mut stream, &response).is_err() {
                            break;
                        }
                    }
                }
            });
            FakeUpstream { path, stop, signs, thread: Some(thread) }
        }
    }

    impl Drop for FakeUpstream {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = UnixStream::connect(&self.path);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn snapshot(project: &Path, upstream: &Path) -> CatalogSnapshot {
        let (address_a, _) = identity_names(KEY_A);
        let (address_b, _) = identity_names(KEY_B);
        CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: project.to_path_buf(),
            }],
            checkouts: vec![],
            environments: vec![Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            }],
            resources: vec![Resource {
                id: "fixture-upstream".to_string(),
                name: "Fixture upstream".to_string(),
                kind: ResourceKind::SshAgent,
                shape: ValueShape::Socket,
                codec: ResourceCodec::Opaque,
                default_env_key: None,
                entries: vec![
                    EntrySpec {
                        address: address_a.clone(),
                        label: "Fleet key".to_string(),
                        key: None,
                        sensitive: false,
                    },
                    EntrySpec {
                        address: address_b,
                        label: "Unselected key".to_string(),
                        key: None,
                        sensitive: false,
                    },
                ],
                source: ResourceSource::Socket { endpoint: upstream.to_path_buf() },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            }],
            bindings: vec![Binding {
                id: "fixture-binding".to_string(),
                project_id: "fixture-project".to_string(),
                scope: BindingScope::Environment {
                    environment_id: "fixture-development".to_string(),
                },
                resource_id: "fixture-upstream".to_string(),
                selection: EntrySelection::Entries { addresses: vec![address_a] },
                key_override: None,
                enabled: true,
                allow_override: false,
                position: 0,
            }],
            surfaces: vec![Surface {
                id: "fixture-agent".to_string(),
                environment_id: "fixture-development".to_string(),
                name: "AWS fleet".to_string(),
                kind: SurfaceKind::UnixSocket,
                path: project.join("agent.sock"),
                input: SurfaceInput::SshAgent {
                    binding_ids: vec!["fixture-binding".to_string()],
                    route: Some(SshRouteSpec {
                        host_patterns: vec![
                            "fixture-*.internal".to_string(),
                            "fixture-alias".to_string(),
                        ],
                        hostname: Some("fixture.internal".to_string()),
                        user: Some("fixture-user".to_string()),
                        port: Some(2222),
                        forward_agent: true,
                    }),
                },
                enforcement: Enforcement::Prompt,
                position: 0,
            }],
        }
    }

    fn managed_snapshot(
        project: &Path,
        identity: &accessfs_ssh::PublicIdentity,
    ) -> CatalogSnapshot {
        let mut snapshot = snapshot(project, Path::new("/fixture/unused-external-agent.sock"));
        snapshot.resources = vec![Resource {
            id: "fixture-managed-identity".to_string(),
            name: "Fixture managed identity".to_string(),
            kind: ResourceKind::SshIdentity,
            shape: ValueShape::SshIdentity,
            codec: ResourceCodec::Opaque,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: identity.address.clone(),
                label: "Managed fleet key".to_string(),
                key: None,
                sensitive: false,
            }],
            source: ResourceSource::SecretRef {
                secret_id: "fixture-managed-key".to_string(),
            },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
            origin: Default::default(),
        }];
        snapshot.bindings[0].resource_id = "fixture-managed-identity".to_string();
        snapshot.bindings[0].selection = EntrySelection::Entries {
            addresses: vec![identity.address.clone()],
        };
        snapshot
    }

    fn sign_request(key: &[u8]) -> Vec<u8> {
        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut request, key);
        put_string(&mut request, b"fixture-data-to-sign");
        request.extend_from_slice(&0u32.to_be_bytes());
        request
    }

    fn session_bind_request(
        host_key: &ssh_key::PrivateKey,
        session_id: &[u8],
        forwarded: bool,
    ) -> Vec<u8> {
        use signature::Signer as _;

        let signature = host_key.try_sign(session_id).unwrap();
        let mut request = vec![SSH_AGENTC_EXTENSION];
        put_string(&mut request, SESSION_BIND_EXTENSION);
        put_string(&mut request, &host_key.public_key().to_bytes().unwrap());
        put_string(&mut request, session_id);
        put_string(&mut request, &Vec::<u8>::try_from(signature).unwrap());
        request.push(u8::from(forwarded));
        request
    }

    fn userauth_sign_request(
        identity_key: &[u8],
        host_key: &[u8],
        session_id: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        put_string(&mut data, session_id);
        data.push(50);
        put_string(&mut data, b"fixture-user");
        put_string(&mut data, b"ssh-connection");
        put_string(&mut data, b"publickey-hostbound-v00@openssh.com");
        data.push(1);
        put_string(&mut data, b"ssh-ed25519");
        put_string(&mut data, identity_key);
        put_string(&mut data, host_key);

        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut request, identity_key);
        put_string(&mut request, &data);
        request.extend_from_slice(&0u32.to_be_bytes());
        request
    }

    #[test]
    fn verifies_session_bind_and_ties_prompt_context_to_userauth_payload() {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, PrivateKey};

        let first_host = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let final_host = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut bindings = SessionBindings::default();
        let mut query = vec![SSH_AGENTC_EXTENSION];
        put_string(&mut query, b"query");
        let query_response = handle_extension(&query, &mut bindings).unwrap();
        let mut query_reader = WireReader::new(&query_response);
        assert_eq!(query_reader.byte().unwrap(), SSH_AGENT_EXTENSION_RESPONSE);
        assert_eq!(query_reader.string().unwrap(), b"query");
        assert_eq!(query_reader.string().unwrap(), SESSION_BIND_EXTENSION);
        query_reader.finish().unwrap();

        let first_session = b"fixture-forwarded-session";
        let final_session = b"fixture-authentication-session";
        bindings
            .bind(&session_bind_request(&first_host, first_session, true))
            .unwrap();
        bindings
            .bind(&session_bind_request(&final_host, final_session, false))
            .unwrap();

        let final_host_blob = final_host.public_key().to_bytes().unwrap();
        let request = userauth_sign_request(KEY_A, &final_host_blob, final_session);
        let parsed = parse_sign_request(&request).unwrap();
        let context = bindings.context_for_sign(&parsed).unwrap();
        assert_eq!(context.ssh_user, "fixture-user");
        assert_eq!(context.forwarding_hops, 1);
        assert_eq!(
            context.host_key_fingerprint,
            identity_names(&final_host_blob).1
        );

        let wrong_session = userauth_sign_request(KEY_A, &final_host_blob, b"wrong-session");
        assert!(bindings
            .context_for_sign(&parse_sign_request(&wrong_session).unwrap())
            .is_none());
    }

    #[test]
    fn rejects_tampered_and_conflicting_session_bindings() {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, PrivateKey};

        let host = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut tampered = session_bind_request(&host, b"fixture-session", false);
        let session_offset = tampered
            .windows(b"fixture-session".len())
            .position(|window| window == b"fixture-session")
            .unwrap();
        tampered[session_offset] ^= 1;
        assert!(SessionBindings::default().bind(&tampered).is_err());

        let mut bindings = SessionBindings::default();
        bindings
            .bind(&session_bind_request(&host, b"fixture-session", false))
            .unwrap();
        assert!(bindings
            .bind(&session_bind_request(&host, b"second-session", false))
            .is_err());
    }

    #[test]
    fn surface_filters_identities_and_authorizes_each_signature() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir(&project).unwrap();
        let upstream = FakeUpstream::start(dir.path().join("upstream.sock"));
        let discovered = discover_identities(&upstream.path).unwrap();
        assert_eq!(discovered.len(), 2);
        assert_eq!(discovered[0].comment, "upstream-a");
        assert_eq!(discovered[0].address, identity_names(KEY_A).0);
        assert_eq!(discovered[0].fingerprint, identity_names(KEY_A).1);
        let audit_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
        let policy = Arc::new(RecordingAuthorizer::allowing());
        let runtime = SshAgentRuntime::new(
            dir.path().join("runtime"),
            dir.path().join("ssh/config"),
            Arc::clone(&policy) as Arc<dyn Authorizer>,
            audit,
            Arc::new(NoManagedKeys),
        )
        .unwrap();
        runtime.replace(&snapshot(&project, &upstream.path)).unwrap();

        let config = fs::read_to_string(dir.path().join("ssh/config")).unwrap();
        assert!(config.contains("Host fixture-*.internal fixture-alias"));
        assert!(config.contains("IdentityAgent \""));
        assert!(config.contains("IdentityFile none"));
        assert!(config.contains("HostName \"fixture.internal\""));
        assert!(config.contains("User \"fixture-user\""));
        assert!(config.contains("Port 2222"));
        assert!(config.contains("ForwardAgent yes"));
        assert_eq!(
            fs::metadata(dir.path().join("ssh/config"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        assert_eq!(
            fs::read_link(project.join("agent.sock")).unwrap(),
            runtime.socket_path("fixture-agent")
        );
        fs::remove_file(project.join("agent.sock")).unwrap();
        runtime.replace(&snapshot(&project, &upstream.path)).unwrap();
        assert_eq!(
            fs::read_link(project.join("agent.sock")).unwrap(),
            runtime.socket_path("fixture-agent")
        );
        let mut client = UnixStream::connect(project.join("agent.sock")).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        write_frame(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        let answer = read_frame(&mut client).unwrap();
        let mut reader = WireReader::new(&answer);
        assert_eq!(reader.byte().unwrap(), SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.string().unwrap(), KEY_A);
        assert_eq!(reader.string().unwrap(), b"Fleet key");
        reader.finish().unwrap();

        write_frame(&mut client, &sign_request(KEY_A)).unwrap();
        assert_eq!(read_frame(&mut client).unwrap()[0], SSH_AGENT_SIGN_RESPONSE);
        assert_eq!(upstream.signs.load(Ordering::Acquire), 1);

        policy.allow.store(false, Ordering::Release);
        write_frame(&mut client, &sign_request(KEY_A)).unwrap();
        assert_eq!(read_frame(&mut client).unwrap(), vec![SSH_AGENT_FAILURE]);
        assert_eq!(upstream.signs.load(Ordering::Acquire), 1);

        write_frame(&mut client, &sign_request(KEY_B)).unwrap();
        assert_eq!(read_frame(&mut client).unwrap(), vec![SSH_AGENT_FAILURE]);
        assert_eq!(upstream.signs.load(Ordering::Acquire), 1);

        let requests = policy.requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "unselected identities do not reach policy");
        assert!(requests.iter().all(|request| request.0 == "sign"));
        assert!(requests.iter().all(|request| request.1 == "surfaces/fixture-agent"));

        let audit = fs::read_to_string(audit_path).unwrap();
        let (_, fingerprint_a) = identity_names(KEY_A);
        assert!(audit.contains(&fingerprint_a));
        assert!(audit.contains("\"result\":\"signed\""));
        assert!(audit.contains("authorization_denied"));
        assert!(audit.contains("identity_not_selected"));
        assert!(!audit.contains("fixture-data-to-sign"));
        assert!(!audit.contains("fixture-signature-response"));

        drop(client);
        drop(runtime);
        assert!(!project.join("agent.sock").exists());
    }

    #[test]
    fn managed_private_key_advertises_and_signs_without_an_upstream_agent() {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, LineEnding, PrivateKey, Signature};

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir(&project).unwrap();
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let source = private_key.to_openssh(LineEnding::LF).unwrap();
        let imported = accessfs_ssh::import_private_key(source.as_bytes(), None).unwrap();
        let key_blob = imported.identity.key_blob.clone();
        let managed_keys: Arc<dyn ManagedKeyReader> = Arc::new(FixtureManagedKeys {
            entries: [(
                "fixture-managed-key".to_string(),
                imported.as_bytes().to_vec(),
            )]
            .into_iter()
            .collect(),
        });
        let policy = Arc::new(RecordingAuthorizer::allowing());
        let audit_path = dir.path().join("audit.jsonl");
        let runtime = SshAgentRuntime::new(
            dir.path().join("runtime"),
            dir.path().join("ssh/config"),
            Arc::clone(&policy) as Arc<dyn Authorizer>,
            Arc::new(AuditLog::open(&audit_path).unwrap()),
            managed_keys,
        )
        .unwrap();
        runtime
            .replace(&managed_snapshot(&project, &imported.identity))
            .unwrap();

        #[cfg(target_os = "macos")]
        {
            let public_key_path = dir.path().join("fixture-managed-key.pub");
            fs::write(
                &public_key_path,
                private_key.public_key().to_openssh().unwrap(),
            )
            .unwrap();
            let output = std::process::Command::new("/usr/bin/ssh-add")
                .arg("-T")
                .arg(&public_key_path)
                .env("SSH_AUTH_SOCK", project.join("agent.sock"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "OpenSSH rejected the managed signer: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let mut client = UnixStream::connect(project.join("agent.sock")).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_frame(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        let answer = read_frame(&mut client).unwrap();
        let mut identities = WireReader::new(&answer);
        assert_eq!(identities.byte().unwrap(), SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(identities.u32().unwrap(), 1);
        assert_eq!(identities.string().unwrap(), key_blob);
        assert_eq!(identities.string().unwrap(), b"Managed fleet key");
        identities.finish().unwrap();

        let message = b"fixture managed SSH user-auth payload";
        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut request, &key_blob);
        put_string(&mut request, message);
        request.extend_from_slice(&0u32.to_be_bytes());
        write_frame(&mut client, &request).unwrap();
        let response = read_frame(&mut client).unwrap();
        let mut response_reader = WireReader::new(&response);
        assert_eq!(response_reader.byte().unwrap(), SSH_AGENT_SIGN_RESPONSE);
        let signature_blob = response_reader.string().unwrap();
        response_reader.finish().unwrap();
        let mut signature_reader = WireReader::new(signature_blob);
        assert_eq!(signature_reader.string().unwrap(), b"ssh-ed25519");
        let signature = Signature::new(
            Algorithm::Ed25519,
            signature_reader.string().unwrap().to_vec(),
        )
        .unwrap();
        signature_reader.finish().unwrap();
        signature::Verifier::verify(private_key.public_key(), message, &signature).unwrap();

        let expected_signatures = if cfg!(target_os = "macos") { 2 } else { 1 };
        assert_eq!(policy.requests.lock().unwrap().len(), expected_signatures);
        let audit = fs::read_to_string(audit_path).unwrap();
        assert!(audit.contains("\"result\":\"signed\""));
        assert!(!audit.contains("fixture managed SSH user-auth payload"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn managed_ec2_style_rsa_key_signs_for_the_openssh_client() {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding as PemLineEnding};
        use ssh_key::rand_core::OsRng;
        use ssh_key::PrivateKey;

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir(&project).unwrap();
        let rsa_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let source = rsa_key.to_pkcs1_pem(PemLineEnding::LF).unwrap();
        let imported = accessfs_ssh::import_private_key(source.as_bytes(), None).unwrap();
        let managed_keys: Arc<dyn ManagedKeyReader> = Arc::new(FixtureManagedKeys {
            entries: [(
                "fixture-managed-key".to_string(),
                imported.as_bytes().to_vec(),
            )]
            .into_iter()
            .collect(),
        });
        let policy = Arc::new(RecordingAuthorizer::allowing());
        let runtime = SshAgentRuntime::new(
            dir.path().join("runtime"),
            dir.path().join("ssh/config"),
            Arc::clone(&policy) as Arc<dyn Authorizer>,
            Arc::new(AuditLog::open(&dir.path().join("audit.jsonl")).unwrap()),
            managed_keys,
        )
        .unwrap();
        runtime
            .replace(&managed_snapshot(&project, &imported.identity))
            .unwrap();
        let public_key_path = dir.path().join("fixture-rsa-key.pub");
        let canonical = PrivateKey::from_openssh(imported.as_bytes()).unwrap();
        fs::write(
            &public_key_path,
            canonical.public_key().to_openssh().unwrap(),
        )
        .unwrap();

        let output = std::process::Command::new("/usr/bin/ssh-add")
            .arg("-T")
            .arg(&public_key_path)
            .env("SSH_AUTH_SOCK", project.join("agent.sock"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "OpenSSH rejected the managed RSA signer: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(policy.requests.lock().unwrap().len(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn openssh_accepts_the_session_bind_response() {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, LineEnding, PrivateKey};
        use std::net::{TcpListener, TcpStream};
        use std::process::{Command, Stdio};
        use std::time::Instant;

        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir(&project).unwrap();
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let source = private_key.to_openssh(LineEnding::LF).unwrap();
        let imported = accessfs_ssh::import_private_key(source.as_bytes(), None).unwrap();
        let managed_keys: Arc<dyn ManagedKeyReader> = Arc::new(FixtureManagedKeys {
            entries: [(
                "fixture-managed-key".to_string(),
                imported.as_bytes().to_vec(),
            )]
            .into_iter()
            .collect(),
        });
        let runtime = SshAgentRuntime::new(
            dir.path().join("runtime"),
            dir.path().join("ssh/config"),
            Arc::new(RecordingAuthorizer::allowing()),
            Arc::new(AuditLog::open(&dir.path().join("audit.jsonl")).unwrap()),
            managed_keys,
        )
        .unwrap();
        runtime
            .replace(&managed_snapshot(&project, &imported.identity))
            .unwrap();

        let host_key = dir.path().join("sshd-host-key");
        let keygen = Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host_key)
            .output()
            .unwrap();
        assert!(
            keygen.status.success(),
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&keygen.stderr)
        );

        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut sshd = Command::new("/usr/sbin/sshd")
            .args(["-D", "-e", "-f", "/dev/null", "-h"])
            .arg(&host_key)
            .args(["-p", &port.to_string()])
            .args(["-o", "ListenAddress=127.0.0.1"])
            .args(["-o", "PasswordAuthentication=no"])
            .args(["-o", "KbdInteractiveAuthentication=no"])
            .args(["-o", "UsePAM=no"])
            .args(["-o", "AuthorizedKeysFile=none"])
            .args(["-o", "StrictModes=no"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            if let Some(status) = sshd.try_wait().unwrap() {
                let output = sshd.wait_with_output().unwrap();
                panic!(
                    "sshd exited with {status}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert!(Instant::now() < deadline, "sshd did not start");
            std::thread::sleep(Duration::from_millis(10));
        }

        let output = Command::new("/usr/bin/ssh")
            .args(["-vvv", "-F", "/dev/null"])
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "ConnectTimeout=3"])
            .args(["-o", "IdentityFile=none"])
            .arg("-o")
            .arg(format!(
                "IdentityAgent={}",
                project.join("agent.sock").display()
            ))
            .args(["-o", "PreferredAuthentications=publickey"])
            .args(["-o", "StrictHostKeyChecking=no"])
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .args(["-p", &port.to_string(), "nobody@127.0.0.1", "true"])
            .output()
            .unwrap();
        let _ = sshd.kill();
        let _ = sshd.wait();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("get_agent_identities: agent returned 1 keys"),
            "OpenSSH did not reach the agent identity request:\n{stderr}"
        );
        assert!(
            !stderr.contains("ssh_agent_bind_hostkey: invalid format"),
            "OpenSSH rejected Floria's session-bind response:\n{stderr}"
        );
    }
}
