//! Filtered SSH agent surfaces.
//!
//! One runtime socket represents one catalog Identity Set. Callers supply a catalog snapshot;
//! this deep module owns listener reconciliation, peer attribution, identity filtering, policy,
//! and audit. Private keys, signature payloads, and signatures are never persisted or logged.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use accessfs_catalog::{
    Binding, CatalogSnapshot, EntrySelection, Resource, ResourceKind, ResourceSource, SurfaceInput,
    SurfaceKind, ValueShape,
};
use accessfs_core::audit::AuditLog;
use accessfs_core::authz::{
    AccessContext, AuthRequest, Authorizer, Operation, SshSignContext,
};
use accessfs_core::identity::ProcessIdentity;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

const MAX_AGENT_FRAME: usize = 1 << 20;
const DOWNSTREAM_POLL: Duration = Duration::from_secs(1);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECTION_THREADS: usize = 16;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

/// Live manager for every catalog-backed SSH Agent Surface.
pub struct SshAgentRuntime {
    runtime_dir: PathBuf,
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<AuditLog>,
    connections: Arc<threadpool::ThreadPool>,
    running: Mutex<HashMap<String, RunningSurface>>,
}

impl SshAgentRuntime {
    pub fn new(
        runtime_dir: impl Into<PathBuf>,
        authorizer: Arc<dyn Authorizer>,
        audit: Arc<AuditLog>,
    ) -> io::Result<Self> {
        let runtime_dir = runtime_dir.into();
        fs::create_dir_all(&runtime_dir)?;
        fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))?;
        Ok(SshAgentRuntime {
            runtime_dir,
            authorizer,
            audit,
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
        for spec in desired {
            if running.get(&spec.id).is_some_and(|server| server.spec == spec) {
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
            None => Ok(()),
        }
    }

    pub fn socket_path(&self, surface_id: &str) -> PathBuf {
        self.runtime_dir.join(format!("{surface_id}.sock"))
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderSpec {
    resource_id: String,
    endpoint: PathBuf,
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
        let SurfaceInput::Bindings { binding_ids } = &surface.input else {
            return Err(invalid(format!(
                "SSH agent surface {:?} requires binding input",
                surface.id
            )));
        };
        let socket_path = runtime_dir.join(format!("{}.sock", surface.id));
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
            let endpoint = ssh_agent_endpoint(resource)?;
            if endpoint == socket_path || endpoint == surface.path {
                return Err(invalid(format!(
                    "SSH agent resource {:?} points back to surface {:?}",
                    resource.id, surface.id
                )));
            }
            let provider_index = match provider_indexes.get(resource.id.as_str()).copied() {
                Some(index) => index,
                None => {
                    let index = providers.len();
                    providers.push(ProviderSpec {
                        resource_id: resource.id.clone(),
                        endpoint: endpoint.to_path_buf(),
                    });
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
        });
    }
    Ok(specs)
}

fn ssh_agent_endpoint(resource: &Resource) -> io::Result<&Path> {
    let ResourceSource::Socket { endpoint } = &resource.source else {
        return Err(invalid(format!(
            "SSH agent resource {:?} has no socket endpoint",
            resource.id
        )));
    };
    if resource.kind != ResourceKind::SshAgent || resource.shape != ValueShape::Socket {
        return Err(invalid(format!(
            "resource {:?} is not an SSH agent",
            resource.id
        )));
    }
    Ok(endpoint)
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
                accept_loop(listener, loop_spec, authorizer, audit, connections, loop_stop)
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
                connections.execute(move || {
                    if let Err(error) = serve_connection(
                        stream,
                        connection_spec,
                        identity,
                        connection_authorizer,
                        connection_audit,
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
}

impl ProviderSession {
    fn round_trip(&mut self, request: &[u8]) -> io::Result<Vec<u8>> {
        if self.stream.is_none() {
            let stream = UnixStream::connect(&self.spec.endpoint)?;
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
}

struct AvailableIdentity {
    provider_index: usize,
    resource_id: String,
    fingerprint: String,
    label: String,
}

fn serve_connection(
    mut downstream: UnixStream,
    spec: SurfaceSpec,
    identity: ProcessIdentity,
    authorizer: Arc<dyn Authorizer>,
    audit: Arc<AuditLog>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    downstream.set_read_timeout(Some(DOWNSTREAM_POLL))?;
    downstream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
    let mut providers = spec
        .providers
        .iter()
        .cloned()
        .map(|spec| ProviderSession { spec, stream: None })
        .collect::<Vec<_>>();
    let mut available = HashMap::<Vec<u8>, AvailableIdentity>::new();

    while !stop.load(Ordering::Acquire) {
        let request = match read_frame_interruptible(&mut downstream, &stop) {
            Ok(request) => request,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
            Err(error) => return Err(error),
        };
        let response = match request.first().copied() {
            Some(SSH_AGENTC_REQUEST_IDENTITIES) if request.len() == 1 => {
                match refresh_identities(&spec, &mut providers, &mut available) {
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
                &mut providers,
                &mut available,
            ),
            // Destination constraints arrive through this extension. Phase one fails closed
            // instead of pretending to verify session-bind; verified forwarding support lands
            // as a separate protocol capability.
            Some(SSH_AGENTC_EXTENSION) => vec![SSH_AGENT_EXTENSION_FAILURE],
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
        let response = provider.round_trip(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        upstream.push(parse_identities_answer(&response)?);
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
        let resource_id = providers[selected.provider_index].spec.resource_id.clone();
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
    providers: &mut [ProviderSession],
    available: &mut HashMap<Vec<u8>, AvailableIdentity>,
) -> Vec<u8> {
    let key_blob = match parse_sign_key(request) {
        Ok(key_blob) => key_blob,
        Err(_) => return vec![SSH_AGENT_FAILURE],
    };
    if available.is_empty() && refresh_identities(spec, providers, available).is_err() {
        return vec![SSH_AGENT_FAILURE];
    }
    let Some(selected) = available.get(key_blob) else {
        let (_, fingerprint) = identity_names(key_blob);
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
        );
        return vec![SSH_AGENT_FAILURE];
    };

    let path = format!("surfaces/{}", spec.id);
    let context = AccessContext::SshSign(SshSignContext {
        surface_id: &spec.id,
        surface_name: &spec.name,
        resource_id: &selected.resource_id,
        key_fingerprint: &selected.fingerprint,
        key_label: &selected.label,
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
        );
        return vec![SSH_AGENT_FAILURE];
    }

    let (response, result) = match providers[selected.provider_index].round_trip(request) {
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
    );
    response
}

struct ParsedIdentity {
    key_blob: Vec<u8>,
    fingerprint: String,
}

fn parse_identities_answer(response: &[u8]) -> io::Result<HashMap<String, ParsedIdentity>> {
    let mut reader = WireReader::new(response);
    if reader.byte()? != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(invalid("upstream did not return an identities answer"));
    }
    let count = reader.u32()? as usize;
    let mut identities = HashMap::with_capacity(count);
    for _ in 0..count {
        let key_blob = reader.string()?.to_vec();
        let _comment = reader.string()?;
        let (address, fingerprint) = identity_names(&key_blob);
        if identities
            .insert(address.clone(), ParsedIdentity { key_blob, fingerprint })
            .is_some()
        {
            return Err(invalid(format!(
                "upstream returned duplicate identity {address:?}"
            )));
        }
    }
    reader.finish()?;
    Ok(identities)
}

fn parse_sign_key(request: &[u8]) -> io::Result<&[u8]> {
    let mut reader = WireReader::new(request);
    if reader.byte()? != SSH_AGENTC_SIGN_REQUEST {
        return Err(invalid("not an SSH sign request"));
    }
    let key = reader.string()?;
    let _data = reader.string()?;
    let _flags = reader.u32()?;
    reader.finish()?;
    Ok(key)
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use accessfs_catalog::{
        BindingScope, EntrySpec, Environment, Project, ResourceCodec, Surface,
    };
    use accessfs_core::authz::{Decision, Enforcement};

    const KEY_A: &[u8] = b"fixture-public-identity-a-v1";
    const KEY_B: &[u8] = b"fixture-public-identity-b-v1";

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
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["fixture-binding".to_string()],
                },
                enforcement: Enforcement::Prompt,
                position: 0,
            }],
        }
    }

    fn sign_request(key: &[u8]) -> Vec<u8> {
        let mut request = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut request, key);
        put_string(&mut request, b"fixture-data-to-sign");
        request.extend_from_slice(&0u32.to_be_bytes());
        request
    }

    #[test]
    fn surface_filters_identities_and_authorizes_each_signature() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir(&project).unwrap();
        let upstream = FakeUpstream::start(dir.path().join("upstream.sock"));
        let audit_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
        let policy = Arc::new(RecordingAuthorizer::allowing());
        let runtime = SshAgentRuntime::new(
            dir.path().join("runtime"),
            Arc::clone(&policy) as Arc<dyn Authorizer>,
            audit,
        )
        .unwrap();
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
}
