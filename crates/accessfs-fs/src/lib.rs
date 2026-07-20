//! accessfs-fs: macFUSE backend. Exposes the virtual file tree from
//! [`ResolvedConfig`] as a FUSE volume: config files are read-only, store-backed
//! secrets are also writable (every committed close appends a store version).
//!
//! Key semantics (see the product brief):
//! - `stat/readdir/getattr` never generate content, and attributes stay constant
//!   for the mount's lifetime → dev tools don't trigger accidentally.
//! - `open()` identifies the reading process, generates a single per-open snapshot,
//!   and writes an audit record.
//! - Repeated `read`s on the same fd return the same bytes; different fds get
//!   independent snapshots.
//! - A write-open on a secret buffers in memory and commits at flush/release as a
//!   new immutable version — concurrent writers append, nobody destroys anything.

mod reply;
mod tree;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use accessfs_catalog::Catalog;
use accessfs_core::audit::AuditLog;
use accessfs_core::authz::{AuthRequest, Authorizer, Operation};
use accessfs_core::config::{ResolvedConfig, SECRETS_DIR, SURFACES_DIR};
use accessfs_core::handler::{ContentHandler, HandlerCtx};
use accessfs_core::snapshot::{content_version_of, SnapshotTable};
use accessfs_core::writebuf::{WriteBufTable, WriteErr};
use accessfs_store::{SecretId, SecretStore};
use accessfs_surface::{SurfaceRegistry, SurfaceResolver, DOTENV_MAX_SIZE};
use dashmap::DashMap;
use fuser::{
    AccessFlags, Errno, FileHandle, FileType, INodeNo, KernelConfig, OpenFlags, ReplyAttr,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
    ReplyXattr, Request,
};

use reply::{dir_attr, file_attr, mount_config, TTL};
use tree::{NodeKind, Tree};

/// Worker threads for open() work. Each pending authorization prompt ties up one thread
/// (bounded by the 30s prompt timeout); everything else keeps flowing because the fuser
/// event loop and the fast callbacks never wait on them.
const OPEN_POOL_THREADS: usize = 32;

/// The dynamic `secrets/<id>` namespace: a live view over the store, resolved on every
/// lookup/readdir/open so a freshly `protect`ed file appears without remounting. inodes are
/// allocated lazily per secret id and stay stable for the mount's lifetime.
struct SecretsNs {
    store: Arc<dyn SecretStore>,
    /// Inode of the `secrets/` directory whose children this namespace owns.
    dir_ino: u64,
    id_to_ino: DashMap<String, u64>,
    ino_to_id: DashMap<u64, String>,
    next_ino: Arc<AtomicU64>,
}

impl SecretsNs {
    fn new(store: Arc<dyn SecretStore>, dir_ino: u64, next_ino: Arc<AtomicU64>) -> Self {
        SecretsNs {
            store,
            dir_ino,
            id_to_ino: DashMap::new(),
            ino_to_id: DashMap::new(),
            next_ino,
        }
    }

    /// Get or allocate the stable inode for a secret id.
    fn ino_for(&self, id: &str) -> u64 {
        use dashmap::mapref::entry::Entry;
        // The entry lock serializes concurrent allocations for the same id, so no double-assign.
        match self.id_to_ino.entry(id.to_string()) {
            Entry::Occupied(e) => *e.get(),
            Entry::Vacant(e) => {
                let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
                self.ino_to_id.insert(ino, id.to_string());
                e.insert(ino);
                ino
            }
        }
    }

    fn id_for_ino(&self, ino: u64) -> Option<String> {
        self.ino_to_id.get(&ino).map(|s| s.clone())
    }
}

/// Dynamic `surfaces/<id>` metadata. The registry is replaced by control-plane notifications;
/// FUSE callbacks only clone in-memory metadata and never touch SQLite.
struct SurfaceNs {
    registry: Arc<SurfaceRegistry>,
    resolver: SurfaceResolver,
    dir_ino: u64,
    id_to_ino: DashMap<String, u64>,
    ino_to_id: DashMap<u64, String>,
    next_ino: Arc<AtomicU64>,
}

impl SurfaceNs {
    fn new(
        registry: Arc<SurfaceRegistry>,
        resolver: SurfaceResolver,
        dir_ino: u64,
        next_ino: Arc<AtomicU64>,
    ) -> Self {
        SurfaceNs {
            registry,
            resolver,
            dir_ino,
            id_to_ino: DashMap::new(),
            ino_to_id: DashMap::new(),
            next_ino,
        }
    }

    fn ino_for(&self, id: &str) -> u64 {
        use dashmap::mapref::entry::Entry;
        match self.id_to_ino.entry(id.to_string()) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
                self.ino_to_id.insert(ino, id.to_string());
                entry.insert(ino);
                ino
            }
        }
    }

    fn surface_for_ino(&self, ino: u64) -> Option<accessfs_catalog::Surface> {
        self.id_for_ino(ino).and_then(|id| self.registry.get(&id))
    }

    fn id_for_ino(&self, ino: u64) -> Option<String> {
        self.ino_to_id.get(&ino).map(|id| id.clone())
    }
}

/// Shared, thread-movable filesystem state. Behind an `Arc` so open() work can run on a
/// worker thread — fuser's event loop is single-threaded on macOS, so a blocking open()
/// on the event-loop thread would freeze the whole mount.
struct Shared {
    tree: Tree,
    snapshots: SnapshotTable,
    /// Per-open write buffers for store-backed secrets (fh >= WRITE_FH_BASE); committed as a
    /// new store version on flush/release.
    writes: WriteBufTable,
    audit: Arc<AuditLog>,
    /// Authorization decision boundary. Supplied by the agent (or AllowAll in monitor mode).
    authorizer: Arc<dyn Authorizer>,
    /// Dynamic `secrets/<id>` namespace over the store; `None` if no store is configured.
    secrets: Option<SecretsNs>,
    /// Live catalog-backed dotenv namespace. Metadata comes from an in-memory registry; values
    /// and secret versions are resolved only after authorization on each open.
    surfaces: Option<SurfaceNs>,
    /// Stable timestamp used for all attributes (captured at mount time, never changes),
    /// so watchers don't trigger accidentally.
    mount_epoch: SystemTime,
    mount_uid: u32,
    mount_gid: u32,
}

/// FUSE filesystem instance. Fast callbacks run inline on the event loop; open() (which may
/// block on an authorization prompt or a slow handler) is dispatched to `pool` and replies
/// from there, so a slow open never freezes the single-threaded event loop.
pub struct AccessFs {
    inner: Arc<Shared>,
    pool: threadpool::ThreadPool,
}

impl AccessFs {
    pub fn new(
        cfg: &ResolvedConfig,
        audit: Arc<AuditLog>,
        authorizer: Arc<dyn Authorizer>,
        store: Option<Arc<dyn SecretStore>>,
        catalog: Option<Catalog>,
        surface_registry: Option<Arc<SurfaceRegistry>>,
    ) -> anyhow::Result<Self> {
        // SAFETY: geteuid/getegid take no arguments, have no side effects, and always succeed.
        let (mount_uid, mount_gid) = unsafe { (libc::geteuid(), libc::getegid()) };

        let surface_registry = match (surface_registry, catalog.as_ref()) {
            (Some(registry), _) => Some(registry),
            (None, Some(catalog)) => {
                Some(Arc::new(SurfaceRegistry::from_snapshot(&catalog.snapshot()?)))
            }
            (None, None) => None,
        };

        // The static tree only owns config files and the two namespace directories. Secret and
        // surface children allocate from one shared inode sequence, so their numbers never clash.
        let tree = Tree::build(&cfg.files);
        let next_ino = Arc::new(AtomicU64::new(tree.next_ino()));
        let surfaces = match (catalog, store.as_ref(), surface_registry) {
            (Some(catalog), Some(store), Some(registry)) => Some(SurfaceNs::new(
                registry,
                SurfaceResolver::new(catalog, Arc::clone(store)),
                tree.surfaces_dir_ino(),
                Arc::clone(&next_ino),
            )),
            (Some(_), None, Some(registry)) if !registry.is_empty() => {
                anyhow::bail!("catalog contains dotenv surfaces but no secret store is configured")
            }
            _ => None,
        };
        let secrets = store
            .map(|store| SecretsNs::new(store, tree.secrets_dir_ino(), Arc::clone(&next_ino)));

        let inner = Arc::new(Shared {
            tree,
            snapshots: SnapshotTable::new(),
            writes: WriteBufTable::new(),
            audit,
            authorizer,
            secrets,
            surfaces,
            mount_epoch: SystemTime::now(),
            mount_uid,
            mount_gid,
        });
        let pool = threadpool::Builder::new()
            .num_threads(OPEN_POOL_THREADS)
            .thread_name("accessfs-open".into())
            .build();
        Ok(AccessFs { inner, pool })
    }
}

impl Shared {
    fn attr_for(&self, ino: u64) -> Option<fuser::FileAttr> {
        let node = self.tree.get(ino)?;
        let attr = match &node.kind {
            NodeKind::Dir => dir_attr(ino, node.mode, self.mount_epoch, self.mount_uid, self.mount_gid),
            NodeKind::File(f) => {
                file_attr(ino, f.report_size, node.mode, self.mount_epoch, self.mount_uid, self.mount_gid)
            }
        };
        Some(attr)
    }

    /// Attr for a dynamic secret inode, reading current metadata from the store.
    /// `None` if the secret no longer exists (e.g. deleted since it was looked up).
    fn secret_attr(&self, ino: u64, id: &str) -> Option<fuser::FileAttr> {
        let ns = self.secrets.as_ref()?;
        let sid: SecretId = id.parse().ok()?;
        let rec = ns.store.record(&sid).ok().flatten()?;
        Some(file_attr(
            ino,
            rec.size,
            rec.mode as u16,
            self.mount_epoch,
            self.mount_uid,
            self.mount_gid,
        ))
    }

    fn surface_attr(&self, ino: u64) -> fuser::FileAttr {
        file_attr(
            ino,
            DOTENV_MAX_SIZE as u64,
            0o400,
            self.mount_epoch,
            self.mount_uid,
            self.mount_gid,
        )
    }

    /// Resolve an inode to what `open()` should serve: a dynamic surface/secret or static file.
    fn resolve_open_target(&self, ino: u64) -> Result<OpenTarget, Errno> {
        if let Some(ns) = &self.surfaces {
            if let Some(surface) = ns.surface_for_ino(ino) {
                return Ok(OpenTarget {
                    virtual_path: format!("{SURFACES_DIR}/{}", surface.id),
                    display: Some(surface.path.display().to_string()),
                    direct_io: true,
                    kind: OpenKind::DotenvSurface(surface.id),
                });
            }
        }
        if let Some(ns) = &self.secrets {
            if let Some(id) = ns.id_for_ino(ino) {
                let sid: SecretId = id.parse().map_err(|_| Errno::ENOENT)?;
                // Confirm it still exists (may have been deleted since lookup).
                ns.store
                    .record(&sid)
                    .map_err(|_| errno(libc::EIO))?
                    .ok_or(Errno::ENOENT)?;
                return Ok(OpenTarget {
                    virtual_path: format!("{SECRETS_DIR}/{id}"),
                    display: self.secret_display(&id),
                    direct_io: true,
                    kind: OpenKind::Secret(id),
                });
            }
        }
        let node = self.tree.get(ino).ok_or(Errno::ENOENT)?;
        let NodeKind::File(file) = &node.kind else {
            return Err(Errno::EISDIR);
        };
        Ok(OpenTarget {
            virtual_path: file.virtual_path.clone(),
            display: None,
            direct_io: file.direct_io,
            kind: OpenKind::Handler(file.handler.clone()),
        })
    }

    /// Decrypt a store-backed secret's bytes for a snapshot. Errors are stringified for logging;
    /// the caller maps any failure to EIO.
    fn decrypt_secret(&self, id: &str) -> std::result::Result<Vec<u8>, String> {
        let ns = self.secrets.as_ref().ok_or("no secret store configured")?;
        let sid: SecretId = id.parse().map_err(|_| format!("invalid secret id {id}"))?;
        let plain = ns.store.get(&sid).map_err(|e| e.to_string())?;
        Ok(plain.to_vec())
    }

    /// A secret's original source path from store metadata, for display purposes.
    fn secret_display(&self, id: &str) -> Option<String> {
        let ns = self.secrets.as_ref()?;
        let sid: SecretId = id.parse().ok()?;
        let record = ns.store.record(&sid).ok().flatten()?;
        Some(record.display_name())
    }

    /// The virtual path of a dynamic secret inode, or `None` if it isn't one.
    fn secret_path(&self, ino: u64) -> Option<String> {
        self.secrets
            .as_ref()
            .and_then(|ns| ns.id_for_ino(ino))
            .map(|id| format!("{SECRETS_DIR}/{id}"))
    }

    /// Commit a dirty write buffer: append it to the store as a new immutable version and move
    /// the head. `Ok(false)` = buffer clean, nothing to commit. On failure the buffer is
    /// re-marked dirty so a later flush (or the release fallback) retries.
    ///
    /// Serialized per fh via `commit_guard`: overlapping fsync/flush/release commits run one at
    /// a time, each taking the buffer's *current* content, so the store head always ends at the
    /// newest snapshot — an older one can never land after (and shadow) a newer one. release
    /// runs through here too, so it inherently waits out any in-flight commit before teardown.
    fn commit_write(&self, fh: u64) -> std::result::Result<bool, String> {
        let Some(lock) = self.writes.commit_guard(fh) else {
            return Ok(false); // fh already torn down
        };
        let _serialized = lock.lock().map_err(|_| "commit lock poisoned".to_string())?;
        let Some(bytes) = self.writes.take_dirty(fh) else {
            return Ok(false);
        };
        let result = (|| {
            let ino = self.writes.ino_of(fh).ok_or("write fh vanished")?;
            let ns = self.secrets.as_ref().ok_or("no secret store configured")?;
            let id = ns.id_for_ino(ino).ok_or("not a secret inode")?;
            let sid: SecretId = id.parse().map_err(|_| format!("invalid secret id {id}"))?;
            let version = ns
                .store
                .append_version(&sid, &bytes)
                .map_err(|e| e.to_string())?;
            Ok::<_, String>((format!("{SECRETS_DIR}/{id}"), version))
        })();
        match result {
            Ok((path, version)) => {
                let content_version = content_version_of(&bytes);
                tracing::info!(path = %path, fh, version, size = bytes.len(), "write commit");
                self.audit
                    .log_write_commit(&path, fh, version, &content_version, bytes.len() as u64);
                Ok(true)
            }
            Err(e) => {
                self.writes.mark_dirty(fh);
                Err(e)
            }
        }
    }

    /// Runs on a pool thread: validation + identity + authorization + content generation,
    /// then replies. May block on an authorization prompt without stalling the event loop.
    fn handle_open(&self, ino: u64, flags: i32, uid: u32, gid: u32, pid: i32, reply: ReplyOpen) {
        let target = match self.resolve_open_target(ino) {
            Ok(t) => t,
            Err(e) => {
                reply.error(e);
                return;
            }
        };
        // Only store-backed secrets are writable (each committed close appends a version);
        // everything else stays read-only.
        let wants_write = flags & libc::O_ACCMODE != libc::O_RDONLY;
        let write_id = match (&target.kind, wants_write) {
            (OpenKind::Secret(id), true) => Some(id.clone()),
            (_, true) => {
                reply.error(errno(libc::EROFS));
                return;
            }
            _ => None,
        };
        let operation = if wants_write { Operation::Write } else { Operation::Read };

        let identity = Arc::new(accessfs_platform::enrich(pid, uid, gid));

        // Authorization boundary: decide after resolving the identity, before generating content.
        let decision = self.authorizer.authorize(&AuthRequest {
            path: &target.virtual_path,
            display: target.display.as_deref(),
            operation,
            identity: &identity,
        });
        if !decision.is_allowed() {
            tracing::info!(
                path = %target.virtual_path,
                op = operation.as_str(),
                chain = %identity.chain_display(),
                reason = %decision.reason,
                "deny"
            );
            self.audit.log_denied(
                &target.virtual_path,
                operation.as_str(),
                &identity,
                decision.rule_id.as_deref(),
                &decision.reason,
            );
            reply.error(errno(libc::EACCES));
            return;
        }

        if let Some(id) = write_id {
            // Write session: seed the buffer with the decrypted head so partial writes and
            // O_APPEND merge correctly; O_TRUNC starts empty. Mutations stay in memory until
            // flush/release commits them as a new immutable version.
            let initial = if flags & libc::O_TRUNC != 0 {
                Vec::new()
            } else {
                match self.decrypt_secret(&id) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(path = %target.virtual_path, writer = %identity.chain_display(), "secret decrypt failed: {e}");
                        reply.error(errno(libc::EIO));
                        return;
                    }
                }
            };
            let size = initial.len() as u64;
            let fh = self.writes.insert(ino, Arc::clone(&identity), initial);
            tracing::info!(
                path = %target.virtual_path,
                uid, pid,
                chain = %identity.chain_display(),
                decision = decision.decision_str(),
                rule = decision.rule_id.as_deref().unwrap_or("-"),
                fh,
                "open for write"
            );
            // The written content isn't known yet; the commit is audited separately
            // as a write_commit event carrying the new version's hash.
            self.audit.log_open(
                &target.virtual_path,
                operation.as_str(),
                &identity,
                decision.decision_str(),
                decision.rule_id.as_deref(),
                "-",
                fh,
                size,
                None,
            );
            reply.opened(FileHandle(fh), fuser::FopenFlags::FOPEN_DIRECT_IO);
            return;
        }

        // open boundary: produce the snapshot bytes once. Secrets decrypt through the store;
        // other handlers generate their content inline.
        let (bytes, dependencies) = match &target.kind {
            OpenKind::Secret(id) => match self.decrypt_secret(id) {
                Ok(bytes) => (bytes, None),
                Err(e) => {
                    tracing::warn!(path = %target.virtual_path, reader = %identity.chain_display(), "secret decrypt failed: {e}");
                    reply.error(errno(libc::EIO));
                    return;
                }
            },
            OpenKind::Handler(handler) => {
                let ctx = HandlerCtx {
                    virtual_path: target.virtual_path.clone(),
                    request_uid: uid,
                    request_pid: pid,
                };
                match handler.generate(&ctx) {
                    Ok(bytes) => (bytes, None),
                    Err(e) => {
                        tracing::warn!(path = %target.virtual_path, reader = %identity.chain_display(), "handler failed: {e}");
                        reply.error(errno(libc::EIO));
                        return;
                    }
                }
            }
            OpenKind::DotenvSurface(surface_id) => {
                let Some(surfaces) = &self.surfaces else {
                    tracing::warn!(path = %target.virtual_path, "surface resolver is unavailable");
                    reply.error(errno(libc::EIO));
                    return;
                };
                match surfaces.resolver.render_dotenv_surface(surface_id) {
                    Ok(snapshot) => {
                        tracing::debug!(
                            path = %target.virtual_path,
                            resources = snapshot.versions.len(),
                            exports = snapshot.exports.len(),
                            "dotenv surface resolved"
                        );
                        let dependencies = snapshot.audit_dependencies();
                        (snapshot.bytes, Some(dependencies))
                    }
                    Err(error) => {
                        tracing::warn!(path = %target.virtual_path, reader = %identity.chain_display(), %error, "dotenv surface failed");
                        reply.error(errno(libc::EIO));
                        return;
                    }
                }
            }
        };

        let opened = self.snapshots.insert(ino, Arc::clone(&identity), bytes);
        tracing::info!(
            path = %target.virtual_path,
            uid, pid,
            exe = ?identity.exe_path,
            chain = %identity.chain_display(),
            decision = decision.decision_str(),
            rule = decision.rule_id.as_deref().unwrap_or("-"),
            fh = opened.fh,
            size = opened.size,
            "open"
        );
        self.audit.log_open(
            &target.virtual_path,
            operation.as_str(),
            &identity,
            decision.decision_str(),
            decision.rule_id.as_deref(),
            &opened.content_version,
            opened.fh,
            opened.size,
            dependencies.as_deref(),
        );

        // Dynamic (script/secret) files use direct-io: the kernel won't truncate to attr size
        // or cache across opens, so the fd returns the snapshot's real bytes and EOF.
        // Constant files take the default cached path (mmap-able).
        let fopen = if target.direct_io {
            fuser::FopenFlags::FOPEN_DIRECT_IO
        } else {
            fuser::FopenFlags::empty()
        };
        reply.opened(FileHandle(opened.fh), fopen);
    }
}

/// What `open()` should serve for a resolved inode.
struct OpenTarget {
    virtual_path: String,
    display: Option<String>,
    direct_io: bool,
    kind: OpenKind,
}

enum OpenKind {
    Handler(ContentHandler),
    Secret(String),
    DotenvSurface(String),
}

/// Build error codes that fuser doesn't provide constants for (EROFS/ENOATTR, etc.) from libc.
fn errno(code: i32) -> Errno {
    Errno::from_i32(code)
}

/// What to do with a `setattr` request.
#[derive(Debug, PartialEq, Eq)]
enum SetattrPlan {
    /// Nothing we'd have to fake: truncate the write buffer if asked, then reply the attr.
    Apply { truncate_to: Option<u64> },
    /// Asks for a change this FS cannot make true — refuse (EPERM) instead of lying.
    Refuse,
}

/// Classify a `setattr` request against what this FS can honestly do.
/// - Ownership (chown) and BSD flags (chflags) never change, anywhere: always refused.
/// - Size needs an open write fd to buffer into; a path truncate has none.
/// - mode and every timestamp facet (atime/mtime/ctime/crtime/chgtime/bkuptime) are refused
///   outside a write session; within one they are a *documented no-op* (saving editors call
///   fchmod/futimes on the fd — the store keeps its own mode, attributes stay frozen).
fn plan_setattr(
    has_write_fh: bool,
    size: Option<u64>,
    wants_mode: bool,
    wants_owner: bool,
    wants_times: bool,
    wants_flags: bool,
) -> SetattrPlan {
    if wants_owner || wants_flags {
        return SetattrPlan::Refuse;
    }
    if !has_write_fh && (size.is_some() || wants_mode || wants_times) {
        return SetattrPlan::Refuse;
    }
    SetattrPlan::Apply { truncate_to: size }
}

impl fuser::Filesystem for AccessFs {
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> std::io::Result<()> {
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        // Any name not in the tree (including macOS noise like .DS_Store / ._*) returns ENOENT; never generates content.
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        // Surface children resolve from the control-plane-maintained in-memory registry.
        if let Some(ns) = &self.inner.surfaces {
            if parent.0 == ns.dir_ino {
                match ns.registry.get(name) {
                    Some(_) => {
                        let ino = ns.ino_for(name);
                        let attr = self.inner.surface_attr(ino);
                        reply.entry(&TTL, &attr, fuser::Generation(0));
                    }
                    None => reply.error(Errno::ENOENT),
                }
                return;
            }
        }
        // Children of the secrets directory resolve dynamically against the store.
        if let Some(ns) = &self.inner.secrets {
            if parent.0 == ns.dir_ino {
                match name
                    .parse::<SecretId>()
                    .ok()
                    .and_then(|sid| ns.store.record(&sid).ok().flatten())
                {
                    Some(rec) => {
                        let ino = ns.ino_for(name);
                        let attr = file_attr(
                            ino,
                            rec.size,
                            rec.mode as u16,
                            self.inner.mount_epoch,
                            self.inner.mount_uid,
                            self.inner.mount_gid,
                        );
                        reply.entry(&TTL, &attr, fuser::Generation(0));
                    }
                    None => reply.error(Errno::ENOENT),
                }
                return;
            }
        }
        match self
            .inner
            .tree
            .lookup_child(parent.0, name)
            .and_then(|ino| self.inner.attr_for(ino))
        {
            Some(attr) => reply.entry(&TTL, &attr, fuser::Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        if let Some(ns) = &self.inner.surfaces {
            if let Some(id) = ns.id_for_ino(ino.0) {
                if ns.registry.get(&id).is_some() {
                    reply.attr(&TTL, &self.inner.surface_attr(ino.0));
                } else {
                    reply.error(Errno::ENOENT);
                }
                return;
            }
        }
        // A dynamic secret inode reads its attributes live from the store; fstat on an open
        // write fd sees the in-progress buffer's size instead of the committed head's.
        if let Some(ns) = &self.inner.secrets {
            if let Some(id) = ns.id_for_ino(ino.0) {
                match self.inner.secret_attr(ino.0, &id) {
                    Some(mut attr) => {
                        if let Some(len) = fh
                            .map(|f| f.0)
                            .filter(|&f| self.inner.writes.owns(f))
                            .and_then(|f| self.inner.writes.len(f))
                        {
                            attr.size = len;
                        }
                        reply.attr(&TTL, &attr)
                    }
                    None => reply.error(Errno::ENOENT),
                }
                return;
            }
        }
        match self.inner.attr_for(ino.0) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.inner.tree.get(ino.0).map(|n| &n.kind) {
            Some(NodeKind::Dir) => reply.opened(FileHandle(0), fuser::FopenFlags::empty()),
            Some(_) => reply.error(Errno::ENOTDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(node) = self.inner.tree.get(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !matches!(node.kind, NodeKind::Dir) {
            reply.error(Errno::ENOTDIR);
            return;
        }

        if let Some(ns) = &self.inner.surfaces {
            if ino.0 == ns.dir_ino {
                let mut entries: Vec<(u64, FileType, String)> = vec![
                    (ino.0, FileType::Directory, ".".to_string()),
                    (node.parent, FileType::Directory, "..".to_string()),
                ];
                for surface in ns.registry.list() {
                    let child_ino = ns.ino_for(&surface.id);
                    entries.push((child_ino, FileType::RegularFile, surface.id));
                }
                for (index, (child_ino, kind, name)) in
                    entries.iter().enumerate().skip(offset as usize)
                {
                    if reply.add(INodeNo(*child_ino), (index + 1) as u64, *kind, name.as_str()) {
                        break;
                    }
                }
                reply.ok();
                return;
            }
        }

        // The secrets directory lists the store's current contents dynamically.
        if let Some(ns) = &self.inner.secrets {
            if ino.0 == ns.dir_ino {
                let mut entries: Vec<(u64, FileType, String)> = vec![
                    (ino.0, FileType::Directory, ".".to_string()),
                    (node.parent, FileType::Directory, "..".to_string()),
                ];
                for r in ns.store.list().unwrap_or_default() {
                    let id = r.id.to_string();
                    let cino = ns.ino_for(&id);
                    entries.push((cino, FileType::RegularFile, id));
                }
                for (i, (cino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
                    let next = (i + 1) as u64;
                    if reply.add(INodeNo(*cino), next, *kind, name.as_str()) {
                        break;
                    }
                }
                reply.ok();
                return;
            }
        }

        // . and .. always come first, then child nodes. offset is the "next" cursor.
        let mut entries: Vec<(u64, FileType, &str)> = vec![
            (ino.0, FileType::Directory, "."),
            (node.parent, FileType::Directory, ".."),
        ];
        for &child_ino in self.inner.tree.children(ino.0) {
            if let Some(child) = self.inner.tree.get(child_ino) {
                let kind = match child.kind {
                    NodeKind::Dir => FileType::Directory,
                    NodeKind::File(_) => FileType::RegularFile,
                };
                entries.push((child_ino, kind, child.name.as_str()));
            }
        }

        for (i, (cino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            let next = (i + 1) as u64;
            if reply.add(INodeNo(*cino), next, *kind, name) {
                break; // buffer full
            }
        }
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        // Dispatch to the pool so a blocking authorization prompt (or slow handler) never
        // stalls the single-threaded event loop. The reply is Send and completed there.
        let (uid, gid, pid) = (req.uid(), req.gid(), req.pid() as i32);
        let shared = Arc::clone(&self.inner);
        let (ino, flags) = (ino.0, flags.0);
        self.pool
            .execute(move || shared.handle_open(ino, flags, uid, gid, pid, reply));
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        // An O_RDWR writer reads back its own uncommitted buffer; read snapshots are immutable.
        let slice = if self.inner.writes.owns(fh.0) {
            self.inner.writes.read_slice(fh.0, offset, size)
        } else {
            self.inner.snapshots.read_slice(fh.0, offset, size)
        };
        match slice {
            Some(slice) => reply.data(&slice),
            None => reply.error(Errno::EBADF),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        // Pure memory mutation — runs inline on the event loop; the store isn't touched
        // until flush/release commits.
        match self.inner.writes.write_at(fh.0, offset, data) {
            Ok(n) => reply.written(n),
            Err(WriteErr::BadHandle) => reply.error(Errno::EBADF),
            Err(WriteErr::TooBig) => reply.error(errno(libc::EFBIG)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let write_fh = fh.map(|f| f.0).filter(|&f| self.inner.writes.owns(f));
        let wants_times = atime.is_some()
            || mtime.is_some()
            || ctime.is_some()
            || crtime.is_some()
            || chgtime.is_some()
            || bkuptime.is_some();
        let plan = plan_setattr(
            write_fh.is_some(),
            size,
            mode.is_some(),
            uid.is_some() || gid.is_some(),
            wants_times,
            flags.is_some(),
        );
        match plan {
            SetattrPlan::Refuse => {
                reply.error(errno(libc::EPERM));
                return;
            }
            SetattrPlan::Apply {
                truncate_to: Some(new_size),
            } => {
                // ftruncate, or the kernel's follow-up to O_TRUNC.
                match self.inner.writes.truncate(write_fh.expect("plan requires write fh"), new_size)
                {
                    Ok(()) => {}
                    Err(WriteErr::BadHandle) => {
                        reply.error(Errno::EBADF);
                        return;
                    }
                    Err(WriteErr::TooBig) => {
                        reply.error(errno(libc::EFBIG));
                        return;
                    }
                }
            }
            SetattrPlan::Apply { truncate_to: None } => {}
        }
        // Reply with the current attr, sized from the write buffer if one is open on this fd.
        let mut attr = match self
            .inner
            .secrets
            .as_ref()
            .and_then(|ns| ns.id_for_ino(ino.0))
            .and_then(|id| self.inner.secret_attr(ino.0, &id))
            .or_else(|| self.inner.attr_for(ino.0))
        {
            Some(a) => a,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        if let Some(len) = write_fh.and_then(|f| self.inner.writes.len(f)) {
            attr.size = len;
        }
        reply.attr(&TTL, &attr);
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        // fsync is exactly our commit point: "make it durable now". Editors (vim/nvim) call it
        // right after writing and before close — commit here so their durability assumption
        // holds and an encrypt/store failure surfaces as their fsync error, not at close.
        if self.inner.writes.owns(fh.0) {
            let shared = Arc::clone(&self.inner);
            self.pool.execute(move || match shared.commit_write(fh.0) {
                Ok(_) => reply.ok(),
                Err(e) => {
                    tracing::warn!(fh = fh.0, "write commit failed: {e}");
                    reply.error(errno(libc::EIO));
                }
            });
            return;
        }
        // Read fds have nothing to sync.
        reply.ok();
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        // flush maps to the writer's close(2) return value: commit the buffer here so a failed
        // encrypt/store write surfaces as EIO to the writer. Commit does crypto + store I/O
        // (may wait on the store lock), so it runs on the pool like open().
        if self.inner.writes.owns(fh.0) {
            let shared = Arc::clone(&self.inner);
            self.pool.execute(move || match shared.commit_write(fh.0) {
                Ok(_) => reply.ok(),
                Err(e) => {
                    tracing::warn!(fh = fh.0, "write commit failed: {e}");
                    reply.error(errno(libc::EIO));
                }
            });
            return;
        }
        // Nothing to flush for read fds; return ok to avoid the default ENOSYS warning noise.
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // Write fd: last-chance commit (flush normally already did it), then audit the close.
        if self.inner.writes.owns(fh.0) {
            let shared = Arc::clone(&self.inner);
            self.pool.execute(move || {
                let commit_err = shared.commit_write(fh.0).err();
                if let Some(closed) = shared.writes.remove(fh.0) {
                    let path = shared.secret_path(closed.ino).unwrap_or_default();
                    if closed.dirty_bytes.is_some() {
                        // Commit failed even at release; the fd is gone, the content is lost.
                        tracing::error!(path = %path, fh = fh.0, "uncommitted write dropped at close");
                    }
                    tracing::debug!(path = %path, fh = fh.0, bytes = closed.size, "close (write)");
                    shared.audit.log_close(
                        &path,
                        fh.0,
                        closed.duration.as_millis(),
                        closed.size,
                        commit_err.as_deref(),
                    );
                }
                reply.ok();
            });
            return;
        }
        if let Some(info) = self.inner.snapshots.remove(fh.0) {
            let path = self
                .inner
                .tree
                .get(info.ino)
                .map(|n| n.virtual_path())
                .filter(|p| !p.is_empty())
                .or_else(|| self.inner.secret_path(info.ino))
                .unwrap_or_default();
            tracing::debug!(path = %path, fh = fh.0, bytes = info.bytes_served, "close");
            self.inner.audit.log_close(
                &path,
                fh.0,
                info.duration.as_millis(),
                info.bytes_served,
                None,
            );
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        // Synthesize a volume that "looks empty and large" so tools don't think the disk is full.
        reply.statfs(1 << 20, 1 << 20, 1 << 20, 1 << 16, 1 << 16, 512, 255, 512);
    }

    fn getxattr(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _name: &std::ffi::OsStr,
        _size: u32,
        reply: ReplyXattr,
    ) {
        // No extended attributes. macOS's ENOATTR tells Finder/Spotlight there are "none".
        reply.error(errno(libc::ENOATTR));
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, size: u32, reply: ReplyXattr) {
        if size == 0 {
            reply.size(0);
        } else {
            reply.data(&[]);
        }
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        // Read-only single user: allow; actual permissions are decided by DefaultPermissions + the mode from getattr.
        reply.ok();
    }
}

/// Foreground mount; blocks until Ctrl-C / SIGTERM, then **unmounts cleanly** before exiting.
///
/// Uses `spawn_mount2` (session runs on a background thread) plus a signal wait, rather than
/// the blocking `mount2`: the latter has no chance to unmount when killed by a signal, leaving
/// a zombie macFUSE mount at the mount point. `BackgroundSession` unmounts automatically on drop.
pub fn mount(
    cfg: ResolvedConfig,
    authorizer: Arc<dyn Authorizer>,
    store: Option<Arc<dyn SecretStore>>,
    catalog: Option<Catalog>,
    surface_registry: Option<Arc<SurfaceRegistry>>,
) -> anyhow::Result<()> {
    let audit = Arc::new(AuditLog::open(&cfg.audit_log)?);
    let mount_point = cfg.mount_path.clone();
    let config = mount_config(&cfg.volname);
    let fs = AccessFs::new(&cfg, audit, authorizer, store, catalog, surface_registry)?;

    tracing::info!(
        mount = %mount_point.display(),
        files = cfg.files.len(),
        "mounting accessfs"
    );
    let session = fuser::spawn_mount2(fs, &mount_point, &config)?;

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .map_err(|e| anyhow::anyhow!("install signal handler: {e}"))?;

    tracing::info!("mounted; press Ctrl-C to unmount");
    let _ = rx.recv();

    tracing::info!(mount = %mount_point.display(), "unmounting");
    drop(session); // BackgroundSession unmounts on drop
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use accessfs_catalog::{CatalogSnapshot, Surface, SurfaceKind};
    use accessfs_core::authz::AllowAll;
    use accessfs_core::identity::ProcessIdentity;
    use accessfs_store::{NewSecret, SecretRecord, StoreResult, VersionRecord};
    use std::path::Path;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::time::Duration;
    use zeroize::Zeroizing;

    #[test]
    fn plan_setattr_refuses_every_mutation_without_a_write_fd() {
        use SetattrPlan::*;
        // Each mutation facet alone — size, chmod, chown, any timestamp (incl. the macOS
        // ctime/crtime/chgtime/bkuptime extensions), chflags — is refused, never faked.
        assert_eq!(plan_setattr(false, Some(0), false, false, false, false), Refuse);
        assert_eq!(plan_setattr(false, None, true, false, false, false), Refuse);
        assert_eq!(plan_setattr(false, None, false, true, false, false), Refuse);
        assert_eq!(plan_setattr(false, None, false, false, true, false), Refuse);
        assert_eq!(plan_setattr(false, None, false, false, false, true), Refuse);
        // A request that changes nothing is a harmless attr reply.
        assert_eq!(
            plan_setattr(false, None, false, false, false, false),
            Apply { truncate_to: None }
        );
    }

    #[test]
    fn plan_setattr_write_session_scope() {
        use SetattrPlan::*;
        // ftruncate on the write fd mutates the buffer.
        assert_eq!(
            plan_setattr(true, Some(5), false, false, false, false),
            Apply { truncate_to: Some(5) }
        );
        // fchmod/futimes from a saving editor: documented no-op.
        assert_eq!(
            plan_setattr(true, None, true, false, true, false),
            Apply { truncate_to: None }
        );
        // chown and chflags are refused even within a write session.
        assert_eq!(plan_setattr(true, None, false, true, false, false), Refuse);
        assert_eq!(plan_setattr(true, None, false, false, false, true), Refuse);
    }

    #[test]
    fn live_surface_registry_adds_and_removes_without_inode_collisions() {
        let tmp = tempfile::tempdir().unwrap();
        let tree = Tree::build(&[]);
        let next_ino = Arc::new(AtomicU64::new(tree.next_ino()));
        let (entered_tx, _entered_rx) = mpsc::channel();
        let (_gate_tx, gate_rx) = mpsc::channel();
        let store = Arc::new(FakeStore {
            appended: Mutex::new(Vec::new()),
            entered_tx,
            gate_rx: Mutex::new(Some(gate_rx)),
        });
        let secret_ns = SecretsNs::new(
            Arc::clone(&store) as Arc<dyn SecretStore>,
            tree.secrets_dir_ino(),
            Arc::clone(&next_ino),
        );
        let surface = Surface {
            id: "fixture-dotenv-a".to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::DotenvFile,
            path: tmp.path().join("project/.env"),
            resource_id: None,
            position: 0,
        };
        let registry = Arc::new(SurfaceRegistry::from_snapshot(&CatalogSnapshot {
            surfaces: vec![surface.clone()],
            ..CatalogSnapshot::default()
        }));
        let catalog = Catalog::open(tmp.path().join("catalog.sqlite")).unwrap();
        let surface_ns = SurfaceNs::new(
            Arc::clone(&registry),
            SurfaceResolver::new(catalog, store as Arc<dyn SecretStore>),
            tree.surfaces_dir_ino(),
            next_ino,
        );

        let secret_ino = secret_ns.ino_for("fixture-secret");
        let first_surface_ino = surface_ns.ino_for(&surface.id);
        assert_ne!(secret_ino, first_surface_ino);
        assert_eq!(surface_ns.surface_for_ino(first_surface_ino), Some(surface));

        let replacement = Surface {
            id: "fixture-dotenv-b".to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env.local".to_string(),
            kind: SurfaceKind::DotenvFile,
            path: tmp.path().join("project/.env.local"),
            resource_id: None,
            position: 0,
        };
        registry.replace(&CatalogSnapshot {
            surfaces: vec![replacement.clone()],
            ..CatalogSnapshot::default()
        });
        assert!(surface_ns.surface_for_ino(first_surface_ino).is_none());
        let replacement_ino = surface_ns.ino_for(&replacement.id);
        assert_ne!(replacement_ino, first_surface_ino);
        assert_eq!(surface_ns.surface_for_ino(replacement_ino), Some(replacement));
    }

    /// Store double whose first `append_version` blocks until released, to force commit overlap.
    struct FakeStore {
        appended: Mutex<Vec<Vec<u8>>>,
        entered_tx: mpsc::Sender<()>,
        gate_rx: Mutex<Option<mpsc::Receiver<()>>>,
    }

    impl SecretStore for FakeStore {
        fn append_version(&self, _id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
            let _ = self.entered_tx.send(());
            if let Some(rx) = self.gate_rx.lock().unwrap().take() {
                let _ = rx.recv(); // first append parks here until the test releases it
            }
            let mut v = self.appended.lock().unwrap();
            v.push(plaintext.to_vec());
            Ok(v.len() as u32)
        }

        fn put(&self, _meta: NewSecret, _plaintext: &[u8]) -> StoreResult<SecretId> {
            unimplemented!()
        }
        fn get(&self, _id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            unimplemented!()
        }
        fn get_version(&self, _id: &SecretId, _version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
            unimplemented!()
        }
        fn history(&self, _id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            unimplemented!()
        }
        fn set_head(&self, _id: &SecretId, _version: u32) -> StoreResult<()> {
            unimplemented!()
        }
        fn record(&self, _id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            unimplemented!()
        }
        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            unimplemented!()
        }
        fn get_by_path(&self, _source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            unimplemented!()
        }
        fn delete(&self, _id: &SecretId) -> StoreResult<()> {
            unimplemented!()
        }
    }

    fn shared_with_store(store: Arc<dyn SecretStore>, tmp: &Path) -> Arc<Shared> {
        let tree = Tree::build(&[]);
        let next_ino = Arc::new(AtomicU64::new(tree.next_ino()));
        let secrets = SecretsNs::new(store, tree.secrets_dir_ino(), next_ino);
        Arc::new(Shared {
            tree,
            snapshots: SnapshotTable::new(),
            writes: WriteBufTable::new(),
            audit: Arc::new(AuditLog::open(&tmp.join("audit.jsonl")).unwrap()),
            authorizer: Arc::new(AllowAll),
            secrets: Some(secrets),
            surfaces: None,
            mount_epoch: SystemTime::now(),
            mount_uid: 501,
            mount_gid: 20,
        })
    }

    /// The P1 scenario: an older snapshot's commit is still in flight inside the store when a
    /// newer snapshot is written and a second commit fires. The per-fh commit lock must order
    /// them so the newest content lands last (and thus becomes the store head).
    #[test]
    fn overlapping_commits_are_serialized_newest_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (gate_tx, gate_rx) = mpsc::channel();
        let store = Arc::new(FakeStore {
            appended: Mutex::new(Vec::new()),
            entered_tx,
            gate_rx: Mutex::new(Some(gate_rx)),
        });
        let shared = shared_with_store(Arc::clone(&store) as Arc<dyn SecretStore>, tmp.path());

        let id = "00000000-0000-0000-0000-000000000000";
        let ino = shared.secrets.as_ref().unwrap().ino_for(id);
        let fh = shared
            .writes
            .insert(ino, Arc::new(ProcessIdentity::bare(1, 501, 20)), Vec::new());
        shared.writes.write_at(fh, 0, b"old").unwrap();

        // A commits "old" and parks inside the store append.
        let sa = Arc::clone(&shared);
        let a = std::thread::spawn(move || sa.commit_write(fh).unwrap());
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("A never reached the store");

        // Newer content lands while A's commit is in flight; B fires a second commit.
        shared.writes.write_at(fh, 0, b"newer").unwrap();
        let sb = Arc::clone(&shared);
        let b = std::thread::spawn(move || sb.commit_write(fh).unwrap());

        // B must wait on the per-fh lock: nothing may reach the store while A is parked.
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            store.appended.lock().unwrap().is_empty(),
            "second commit overtook the in-flight one"
        );

        gate_tx.send(()).unwrap(); // release A
        assert!(a.join().unwrap());
        assert!(b.join().unwrap());

        let versions = store.appended.lock().unwrap();
        assert_eq!(
            versions.as_slice(),
            &[b"old".to_vec(), b"newer".to_vec()],
            "newest snapshot must land last — it becomes the head"
        );
    }
}
