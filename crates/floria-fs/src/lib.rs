//! floria-fs: macFUSE backend. Exposes the virtual file tree from
//! [`ResolvedConfig`] as a FUSE volume: config files are read-only, store-backed
//! secrets are also writable (every committed close appends a store version).
//!
//! Key semantics (see the product brief):
//! - `stat/readdir/getattr` never generate content, and attributes stay constant
//!   for the mount's lifetime → dev tools don't trigger accidentally.
//! - Each process lifetime observed at `open()` or `read()` is identified, authorized, audited,
//!   and receives an isolated snapshot. The `read()` boundary is required because macFUSE can
//!   reuse one vnode-scoped FUSE handle for POSIX opens from several processes.
//! - Repeated reads in the same process access session return the same bytes.
//! - A write-open on a secret buffers in memory and commits at flush/release as a
//!   new immutable version — concurrent writers append, nobody destroys anything.

mod reply;
mod read_session;
mod tree;
#[cfg(all(target_os = "macos", not(feature = "macos-no-mount")))]
mod macos_mount;

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use floria_catalog::Catalog;
use floria_core::audit::{AuditDependency, AuditLog};
use floria_core::authz::{AuthRequest, Authorizer, Decision, Operation};
use floria_core::config::{ResolvedConfig, ITEMS_DIR, SECRETS_DIR, SURFACES_DIR};
use floria_core::identity::ProcessIdentity;
use floria_core::snapshot::content_version_of;
use floria_core::source::{ContentSource, SourceCtx};
use floria_core::writebuf::{WriteBufTable, WriteErr};
use floria_store::{SecretId, SecretRecord, SecretStore};
use floria_surface::{
    commit_secret_version, renderer_for, ManagedMutationCoordinator, ResolvedAccessPlan,
    SurfaceBacking, SurfaceError, SurfaceRegistry, SurfaceResolver,
};
use dashmap::DashMap;
use fuser::{
    AccessFlags, Errno, FileHandle, FileType, INodeNo, KernelConfig, OpenFlags, ReplyAttr,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite,
    ReplyXattr, Request,
};

use reply::{dir_attr, file_attr, mount_config, TTL};
use read_session::{ExistingRead, ReadSessionError, ReadSessionTable};
use tree::{NodeKind, Tree};

/// Worker threads for authorization work. Each pending prompt ties up one thread
/// (bounded by the 30s prompt timeout); everything else keeps flowing because the fuser
/// event loop and the fast callbacks never wait on them.
const AUTH_POOL_THREADS: usize = 32;

/// Keep the foreground daemon responsive to a mount session that disappears outside of its
/// normal shutdown path (for example when Finder ejects the volume). The process must exit so
/// launchd can restart it instead of leaving a live daemon lock with no mounted filesystem.
const MOUNT_SESSION_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Eq, PartialEq)]
enum MountStopReason {
    ShutdownRequested,
    SessionEnded,
}

fn wait_for_mount_stop(
    shutdown: &std::sync::mpsc::Receiver<()>,
    session_finished: impl Fn() -> bool,
    poll_interval: Duration,
) -> MountStopReason {
    loop {
        if session_finished() {
            return MountStopReason::SessionEnded;
        }
        match shutdown.recv_timeout(poll_interval) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return MountStopReason::ShutdownRequested;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

/// Lazily allocated, mount-stable inode registry for one dynamic namespace.
struct InoMap {
    dir_ino: u64,
    id_to_ino: DashMap<String, u64>,
    ino_to_id: DashMap<u64, String>,
    next_ino: Arc<AtomicU64>,
}

impl InoMap {
    fn new(dir_ino: u64, next_ino: Arc<AtomicU64>) -> Self {
        InoMap {
            dir_ino,
            id_to_ino: DashMap::new(),
            ino_to_id: DashMap::new(),
            next_ino,
        }
    }

    fn ino_for(&self, id: &str) -> u64 {
        use dashmap::mapref::entry::Entry;
        // The entry lock serializes concurrent allocations for the same id, so no double-assign.
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

    fn id_for_ino(&self, ino: u64) -> Option<String> {
        self.ino_to_id.get(&ino).map(|id| id.clone())
    }
}

/// The dynamic `secrets/<id>` namespace: a live view over the store, resolved on every
/// lookup/readdir/open so a freshly `protect`ed file appears without remounting. inodes are
/// allocated lazily per secret id and stay stable for the mount's lifetime.
struct SecretsNs {
    store: Arc<dyn SecretStore>,
    catalog: Option<Catalog>,
    mutations: Arc<ManagedMutationCoordinator>,
    inos: InoMap,
}

impl SecretsNs {
    fn new(
        store: Arc<dyn SecretStore>,
        catalog: Option<Catalog>,
        mutations: Arc<ManagedMutationCoordinator>,
        dir_ino: u64,
        next_ino: Arc<AtomicU64>,
    ) -> Self {
        SecretsNs {
            store,
            catalog,
            mutations,
            inos: InoMap::new(dir_ino, next_ino),
        }
    }

    fn ino_for(&self, id: &str) -> u64 {
        self.inos.ino_for(id)
    }

    fn id_for_ino(&self, ino: u64) -> Option<String> {
        self.inos.id_for_ino(ino)
    }
}

/// Dynamic `surfaces/<id>` metadata. The registry is replaced by control-plane notifications;
/// FUSE callbacks only clone in-memory metadata and never touch SQLite.
struct SurfaceNs {
    registry: Arc<SurfaceRegistry>,
    resolver: SurfaceResolver,
    inos: InoMap,
}

/// One stable public Managed Item. The item id survives a byte-preserving file becoming a direct
/// configurable Env File because both representations use the backing Secret id.
#[derive(Clone)]
struct ManagedItem {
    id: String,
    basename: OsString,
    backing: ManagedItemBacking,
}

#[derive(Clone)]
enum ManagedItemBacking {
    Secret(String),
    Surface(String),
}

/// Dynamic `items/<managed-item-id>/<basename>` namespace.
///
/// This is an Adapter over the existing store and surface registry, not a third source of truth:
/// no bytes or catalog rows are copied when the public namespace is introduced.
struct ItemsNs {
    store: Arc<dyn SecretStore>,
    registry: Option<Arc<SurfaceRegistry>>,
    root_ino: u64,
    dir_inos: InoMap,
    file_inos: InoMap,
    inventory: DashMap<String, ManagedItem>,
}

impl ItemsNs {
    fn new(
        store: Arc<dyn SecretStore>,
        registry: Option<Arc<SurfaceRegistry>>,
        root_ino: u64,
        next_ino: Arc<AtomicU64>,
    ) -> Self {
        ItemsNs {
            store,
            registry,
            root_ino,
            dir_inos: InoMap::new(root_ino, Arc::clone(&next_ino)),
            file_inos: InoMap::new(root_ino, next_ino),
            inventory: DashMap::new(),
        }
    }

    fn item_id_for_surface(plan: &ResolvedAccessPlan) -> String {
        plan.catalog_snapshot()
            .managed_item_id_for_surface(&plan.surface)
            .to_string()
    }

    fn surface_item(plan: ResolvedAccessPlan) -> Option<ManagedItem> {
        let basename = plan
            .surface
            .path
            .as_deref()
            .and_then(std::path::Path::file_name)
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_else(|| OsString::from(&plan.surface.name));
        if basename.is_empty() {
            return None;
        }
        Some(ManagedItem {
            id: Self::item_id_for_surface(&plan),
            basename,
            backing: ManagedItemBacking::Surface(plan.surface.id),
        })
    }

    fn secret_item(record: SecretRecord) -> Option<ManagedItem> {
        let basename = record
            .source_path()
            .and_then(|path| path.file_name())
            .or_else(|| record.placements.first()?.relative_path().file_name())?
            .to_os_string();
        Some(ManagedItem {
            id: record.id.to_string(),
            basename,
            backing: ManagedItemBacking::Secret(record.id.to_string()),
        })
    }

    fn list(&self) -> Vec<ManagedItem> {
        let mut items = BTreeMap::new();
        let mut configured_secret_ids = HashSet::new();
        if let Some(registry) = &self.registry {
            let plans = registry.list();
            if let Some(plan) = plans.first() {
                configured_secret_ids.extend(
                    plan.catalog_snapshot()
                        .file_surface_secret_ids()
                        .into_iter()
                        .map(str::to_string),
                );
            }
            for plan in plans {
                if let Some(item) = Self::surface_item(plan) {
                    items.insert(item.id.clone(), item);
                }
            }
        }
        for record in self.store.list().unwrap_or_default() {
            if configured_secret_ids.contains(record.id.as_str()) {
                continue;
            }
            if let Some(item) = Self::secret_item(record) {
                // A direct file Surface is the configured view of the same Managed Item and
                // therefore takes precedence over its raw Secret adapter.
                items.entry(item.id.clone()).or_insert(item);
            }
        }
        let items = items.into_values().collect::<Vec<_>>();
        self.inventory.clear();
        for item in &items {
            self.inventory.insert(item.id.clone(), item.clone());
        }
        items
    }

    fn get(&self, id: &str) -> Option<ManagedItem> {
        if let Some(item) = self.inventory.get(id).map(|item| item.clone()) {
            if let Some(current) = self.current_item(&item) {
                return Some(current);
            }
            self.inventory.remove(id);
        }
        self.list().into_iter().find(|item| item.id == id)
    }

    /// Resolve a cached descriptor against the live store/registry before it can affect an open.
    /// The cache only avoids full inventory scans; it is never an authority for content.
    fn current_item(&self, item: &ManagedItem) -> Option<ManagedItem> {
        let current = match &item.backing {
            ManagedItemBacking::Secret(id) => {
                let secret_id = id.parse::<SecretId>().ok()?;
                let record = self.store.record(&secret_id).ok().flatten()?;
                if self.configured_secret_ids().contains(id) {
                    return None;
                }
                Self::secret_item(record)?
            }
            ManagedItemBacking::Surface(surface_id) => {
                Self::surface_item(self.surface_plan(surface_id)?)?
            }
        };
        (current.id == item.id).then_some(current)
    }

    fn configured_secret_ids(&self) -> HashSet<String> {
        self.registry
            .as_ref()
            .and_then(|registry| registry.list().into_iter().next())
            .map(|plan| {
                plan.catalog_snapshot()
                    .file_surface_secret_ids()
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn surface_plan(&self, surface_id: &str) -> Option<ResolvedAccessPlan> {
        self.registry.as_ref()?.get(surface_id)
    }

    fn dir_ino_for(&self, id: &str) -> u64 {
        self.dir_inos.ino_for(id)
    }

    fn file_ino_for(&self, id: &str) -> u64 {
        self.file_inos.ino_for(id)
    }

    fn item_for_dir_ino(&self, ino: u64) -> Option<ManagedItem> {
        self.dir_inos.id_for_ino(ino).and_then(|id| self.get(&id))
    }

    fn owns_dir_ino(&self, ino: u64) -> bool {
        self.dir_inos.id_for_ino(ino).is_some()
    }

    fn item_for_file_ino(&self, ino: u64) -> Option<ManagedItem> {
        self.file_inos.id_for_ino(ino).and_then(|id| self.get(&id))
    }
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
            inos: InoMap::new(dir_ino, next_ino),
        }
    }

    fn ino_for(&self, id: &str) -> u64 {
        self.inos.ino_for(id)
    }

    fn surface_for_ino(&self, ino: u64) -> Option<ResolvedAccessPlan> {
        self.id_for_ino(ino).and_then(|id| self.registry.get(&id))
    }

    fn id_for_ino(&self, ino: u64) -> Option<String> {
        self.inos.id_for_ino(ino)
    }
}

/// Shared, thread-movable filesystem state. Behind an `Arc` so authorization at `open()` or
/// `read()` can run on a worker thread — fuser's event loop is single-threaded on macOS, so a
/// blocking prompt on the event-loop thread would freeze the whole mount.
struct Shared {
    tree: Tree,
    reads: ReadSessionTable,
    /// Per-open write buffers for store-backed secrets (fh >= WRITE_FH_BASE); committed as a
    /// new store version on flush/release.
    writes: WriteBufTable,
    /// The exact backing graph approved when each write fd was opened. Inode lookup is live and
    /// must never be used to rediscover a write target after authorization.
    write_targets: DashMap<u64, WriteOpenTarget>,
    audit: Arc<AuditLog>,
    /// Authorization decision boundary. Supplied by the agent (or AllowAll in monitor mode).
    authorizer: Arc<dyn Authorizer>,
    /// Dynamic `secrets/<id>` namespace over the store; `None` if no store is configured.
    secrets: Option<SecretsNs>,
    /// Live catalog-backed dotenv namespace. Metadata comes from an in-memory registry; values
    /// and secret versions are resolved only after authorization on each open.
    surfaces: Option<SurfaceNs>,
    /// Stable public namespace for persistent Managed Links. The legacy namespaces stay live
    /// alongside it so existing installations can roll back without moving any encrypted data.
    items: Option<ItemsNs>,
    /// Stable timestamp used for all attributes (captured at mount time, never changes),
    /// so watchers don't trigger accidentally.
    mount_epoch: SystemTime,
    mount_uid: u32,
    mount_gid: u32,
}

/// FUSE filesystem instance. Fast callbacks run inline on the event loop; callbacks that may
/// authorize or generate content are dispatched to `pool` and reply from there.
pub struct Floria {
    inner: Arc<Shared>,
    pool: threadpool::ThreadPool,
}

impl Floria {
    pub fn new(
        cfg: &ResolvedConfig,
        audit: Arc<AuditLog>,
        authorizer: Arc<dyn Authorizer>,
        store: Option<Arc<dyn SecretStore>>,
        catalog: Option<Catalog>,
        surface_registry: Option<Arc<SurfaceRegistry>>,
        mutations: Arc<ManagedMutationCoordinator>,
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

        // The static tree only owns config files and namespace roots. Dynamic children allocate
        // from one shared inode sequence, so their numbers never clash.
        let tree = Tree::build(&cfg.files);
        let next_ino = Arc::new(AtomicU64::new(tree.next_ino()));
        let secret_catalog = catalog.clone();
        let item_registry = surface_registry.clone();
        let surfaces = match (catalog, store.as_ref(), surface_registry) {
            (Some(catalog), Some(store), Some(registry)) => Some(SurfaceNs::new(
                registry,
                SurfaceResolver::with_mutation_coordinator(
                    catalog,
                    Arc::clone(store),
                    Arc::clone(&mutations),
                ),
                tree.surfaces_dir_ino(),
                Arc::clone(&next_ino),
            )),
            (Some(_), None, Some(registry)) if !registry.is_empty() => {
                anyhow::bail!("catalog contains dotenv surfaces but no secret store is configured")
            }
            _ => None,
        };
        let items = store.as_ref().map(|store| {
            ItemsNs::new(
                Arc::clone(store),
                item_registry,
                tree.items_dir_ino(),
                Arc::clone(&next_ino),
            )
        });
        let secrets = store.map(|store| {
            SecretsNs::new(
                store,
                secret_catalog,
                Arc::clone(&mutations),
                tree.secrets_dir_ino(),
                Arc::clone(&next_ino),
            )
        });

        let inner = Arc::new(Shared {
            tree,
            reads: ReadSessionTable::new(),
            writes: WriteBufTable::new(),
            write_targets: DashMap::new(),
            audit,
            authorizer,
            secrets,
            surfaces,
            items,
            mount_epoch: SystemTime::now(),
            mount_uid,
            mount_gid,
        });
        let pool = threadpool::Builder::new()
            .num_threads(AUTH_POOL_THREADS)
            .thread_name("floria-auth".into())
            .build();
        Ok(Floria { inner, pool })
    }
}

impl Shared {
    fn setattr_attr(&self, ino: u64, write_fh: Option<u64>) -> Option<fuser::FileAttr> {
        // Managed item aliases have their own inodes, distinct from legacy surface/secret inodes.
        let mut attr = self.items.as_ref()
            .and_then(|items| items.item_for_file_ino(ino))
            .and_then(|item| self.item_file_attr(ino, &item))
            .or_else(|| self.surfaces.as_ref()
                .and_then(|ns| ns.surface_for_ino(ino))
                .and_then(|registered| self.surface_attr(ino, &registered)))
            .or_else(|| self.secrets.as_ref()
                .and_then(|ns| ns.id_for_ino(ino))
                .and_then(|id| self.secret_attr(ino, &id)))
            .or_else(|| self.attr_for(ino))?;
        if let Some(len) = write_fh.and_then(|fh| self.writes.len(fh)) {
            attr.size = len;
        }
        Some(attr)
    }

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
        if !exposed_as_raw_secret(&rec) {
            return None;
        }
        Some(file_attr(
            ino,
            rec.size,
            rec.mode as u16,
            self.mount_epoch,
            self.mount_uid,
            self.mount_gid,
        ))
    }

    fn surface_attr(&self, ino: u64, registered: &ResolvedAccessPlan) -> Option<fuser::FileAttr> {
        let (size, mode) = match &registered.backing {
            // Composed surfaces are always read-only; only their byte-layout upper bound belongs
            // to the renderer.
            SurfaceBacking::Composed { format } => {
                (renderer_for(*format).max_size() as u64, 0o400)
            }
            SurfaceBacking::EnvFileDirect { secret_id, .. } => {
                let ns = self.secrets.as_ref()?;
                let id: SecretId = secret_id.parse().ok()?;
                let record = ns.store.record(&id).ok().flatten()?;
                (record.size, record.mode as u16)
            }
        };
        Some(file_attr(
            ino,
            size,
            mode,
            self.mount_epoch,
            self.mount_uid,
            self.mount_gid,
        ))
    }

    fn item_file_attr(&self, ino: u64, item: &ManagedItem) -> Option<fuser::FileAttr> {
        match &item.backing {
            ManagedItemBacking::Secret(id) => self.secret_attr(ino, id),
            ManagedItemBacking::Surface(surface_id) => self.surface_attr(
                ino,
                &self.items.as_ref()?.surface_plan(surface_id)?,
            ),
        }
    }

    fn item_open_target(&self, item: ManagedItem) -> Option<OpenTarget> {
        let virtual_path = format!(
            "{ITEMS_DIR}/{}/{}",
            item.id,
            item.basename.to_string_lossy()
        );
        match item.backing {
            ManagedItemBacking::Secret(id) => Some(OpenTarget {
                virtual_path,
                display: self.secret_display(&id),
                object_revision: None,
                direct_io: true,
                kind: OpenKind::Secret(id),
            }),
            ManagedItemBacking::Surface(surface_id) => {
                let plan = self.items.as_ref()?.surface_plan(&surface_id)?;
                let kind = match &plan.backing {
                    SurfaceBacking::Composed { .. } => OpenKind::ComposedSurface(plan.clone()),
                    SurfaceBacking::EnvFileDirect { .. } => {
                        OpenKind::DirectEnvFileSurface(plan.clone())
                    }
                };
                Some(OpenTarget {
                    virtual_path,
                    display: plan.surface.path.as_ref().map(|path| path.display().to_string()),
                    object_revision: Some(plan.semantic_revision().to_string()),
                    direct_io: true,
                    kind,
                })
            }
        }
    }

    /// Resolve an inode to what `open()` should serve: a dynamic surface/secret or static file.
    fn resolve_open_target(&self, ino: u64) -> Result<OpenTarget, Errno> {
        if let Some(item) = self
            .items
            .as_ref()
            .and_then(|items| items.item_for_file_ino(ino))
        {
            return self.item_open_target(item).ok_or(Errno::ENOENT);
        }
        if let Some(ns) = &self.surfaces {
            if let Some(registered) = ns.surface_for_ino(ino) {
                let kind = match &registered.backing {
                    SurfaceBacking::Composed { .. } => {
                        OpenKind::ComposedSurface(registered.clone())
                    }
                    SurfaceBacking::EnvFileDirect { .. } => {
                        OpenKind::DirectEnvFileSurface(registered.clone())
                    }
                };
                return Ok(OpenTarget {
                    virtual_path: format!("{SURFACES_DIR}/{}", registered.surface.id),
                    display: registered
                        .surface
                        .path
                        .as_ref()
                        .map(|path| path.display().to_string()),
                    object_revision: Some(registered.semantic_revision().to_string()),
                    direct_io: true,
                    kind,
                });
            }
        }
        if let Some(ns) = &self.secrets {
            if let Some(id) = ns.id_for_ino(ino) {
                let sid: SecretId = id.parse().map_err(|_| Errno::ENOENT)?;
                // Confirm it still exists (may have been deleted since lookup).
                let record = ns.store
                    .record(&sid)
                    .map_err(|_| errno(libc::EIO))?
                    .ok_or(Errno::ENOENT)?;
                if !exposed_as_raw_secret(&record) {
                    return Err(Errno::ENOENT);
                }
                return Ok(OpenTarget {
                    virtual_path: format!("{SECRETS_DIR}/{id}"),
                    display: self.secret_display(&id),
                    object_revision: None,
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
            object_revision: None,
            direct_io: file.direct_io,
            kind: OpenKind::Static(Arc::clone(&file.source)),
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

    fn surface_path(&self, ino: u64) -> Option<String> {
        self.surfaces
            .as_ref()
            .and_then(|ns| ns.id_for_ino(ino))
            .map(|id| format!("{SURFACES_DIR}/{id}"))
    }

    fn dynamic_path(&self, ino: u64) -> Option<String> {
        self.items
            .as_ref()
            .and_then(|items| items.item_for_file_ino(ino))
            .map(|item| {
                format!(
                    "{ITEMS_DIR}/{}/{}",
                    item.id,
                    item.basename.to_string_lossy()
                )
            })
            .or_else(|| self.surface_path(ino))
            .or_else(|| self.secret_path(ino))
    }

    /// Commit a dirty write buffer: append it to the store as a new immutable version and move
    /// the head. `Ok(false)` = buffer clean, nothing to commit. On failure the buffer is
    /// re-marked dirty so a later flush (or the release fallback) retries.
    ///
    /// Serialized per fh via `commit_guard`: overlapping fsync/flush/release commits run one at
    /// a time, each taking the buffer's *current* content, so the store head always ends at the
    /// newest snapshot — an older one can never land after (and shadow) a newer one. release
    /// runs through here too, so it inherently waits out any in-flight commit before teardown.
    fn commit_write(&self, fh: u64) -> std::result::Result<bool, CommitFailure> {
        let Some(lock) = self.writes.commit_guard(fh) else {
            return Ok(false); // fh already torn down
        };
        let _serialized = lock.lock().map_err(|_| CommitFailure::io("commit lock poisoned"))?;
        let Some(bytes) = self.writes.take_dirty(fh) else {
            return Ok(false);
        };
        let result = (|| {
            let target = self
                .write_targets
                .get(&fh)
                .map(|target| target.clone())
                .ok_or_else(|| CommitFailure::io("write authorization plan vanished"))?;
            match target {
                WriteOpenTarget::Secret { id, virtual_path } => {
                    let ns = self
                        .secrets
                        .as_ref()
                        .ok_or_else(|| CommitFailure::io("secret namespace is unavailable"))?;
                    let sid: SecretId = id
                        .parse()
                        .map_err(|_| CommitFailure::io(format!("invalid secret id {id}")))?;
                    let version = commit_secret_version(
                        ns.catalog.as_ref(),
                        ns.store.as_ref(),
                        ns.mutations.as_ref(),
                        &sid,
                        &bytes,
                    )
                    .map_err(CommitFailure::surface)?;
                    Ok((virtual_path, version))
                }
                WriteOpenTarget::DirectEnvFile { plan, virtual_path } => {
                    let ns = self
                        .surfaces
                        .as_ref()
                        .ok_or_else(|| CommitFailure::io("surface resolver is unavailable"))?;
                    let committed = ns
                        .resolver
                        .commit_direct_env_file_plan(&plan, &bytes)
                        .map_err(CommitFailure::surface)?;
                    Ok((virtual_path, committed.version))
                }
            }
        })();
        match result {
            Ok((path, version)) => {
                let content_version = content_version_of(&bytes);
                tracing::info!(path = %path, fh, version, size = bytes.len(), "write commit");
                self.audit
                    .log_write_commit(&path, fh, version, &content_version, bytes.len() as u64)
                    .map_err(|error| {
                        CommitFailure::io(format!(
                            "content committed but audit checkpoint failed: {error}"
                        ))
                    })?;
                Ok(true)
            }
            Err(error) => {
                self.writes.mark_dirty(fh);
                Err(error)
            }
        }
    }

    fn authorize_access(
        &self,
        target: &OpenTarget,
        operation: Operation,
        identity: &ProcessIdentity,
    ) -> Result<Decision, Errno> {
        self.audit.ensure_healthy().map_err(|error| {
            tracing::error!(%error, "refusing access while audit logging is degraded");
            errno(libc::EIO)
        })?;
        let decision = self.authorizer.authorize(&AuthRequest {
            path: &target.virtual_path,
            display: target.display.as_deref(),
            object_revision: target.object_revision.as_deref(),
            operation,
            context: None,
            identity,
        });
        if decision.is_allowed() {
            return Ok(decision);
        }

        tracing::info!(
            path = %target.virtual_path,
            op = operation.as_str(),
            chain = %identity.chain_display(),
            reason = %decision.reason,
            "deny"
        );
        let _ = self.audit.log_denied(
            &target.virtual_path,
            operation.as_str(),
            identity,
            decision.rule_id.as_deref(),
            &decision.reason,
            decision.policy.as_ref(),
        );
        Err(errno(libc::EACCES))
    }

    /// Generate bytes only after the caller has authorized `identity` for this target.
    fn generate_read(
        &self,
        target: &OpenTarget,
        identity: &ProcessIdentity,
    ) -> Result<GeneratedRead, Errno> {
        let generated = match &target.kind {
            OpenKind::Secret(id) => match self.decrypt_secret(id) {
                Ok(bytes) => GeneratedRead { bytes, dependencies: None },
                Err(error) => {
                    tracing::warn!(path = %target.virtual_path, reader = %identity.chain_display(), "secret decrypt failed: {error}");
                    return Err(errno(libc::EIO));
                }
            },
            OpenKind::Static(source) => {
                let ctx = SourceCtx {
                    virtual_path: &target.virtual_path,
                    request_uid: identity.uid,
                    request_pid: identity.pid,
                    operation: Operation::Read,
                };
                match source.pin(&ctx).and_then(|pinned| pinned.read()) {
                    Ok(snapshot) => {
                        let mut bytes = snapshot.bytes;
                        GeneratedRead {
                            bytes: std::mem::take(&mut *bytes),
                            dependencies: None,
                        }
                    }
                    Err(error) => {
                        tracing::warn!(path = %target.virtual_path, reader = %identity.chain_display(), "content source failed: {error}");
                        return Err(errno(libc::EIO));
                    }
                }
            }
            OpenKind::ComposedSurface(plan) => {
                let Some(surfaces) = &self.surfaces else {
                    tracing::warn!(path = %target.virtual_path, "surface resolver is unavailable");
                    return Err(errno(libc::EIO));
                };
                match surfaces.resolver.render_access_plan(plan) {
                    Ok(snapshot) => {
                        tracing::debug!(
                            path = %target.virtual_path,
                            resources = snapshot.versions.len(),
                            entries = snapshot.entries.len(),
                            "composed surface resolved"
                        );
                        GeneratedRead {
                            dependencies: Some(snapshot.audit_dependencies()),
                            bytes: snapshot.bytes,
                        }
                    }
                    Err(error) => {
                        tracing::warn!(path = %target.virtual_path, reader = %identity.chain_display(), %error, "composed surface failed");
                        return Err(errno(libc::EIO));
                    }
                }
            }
            OpenKind::DirectEnvFileSurface(plan) => {
                let Some(surfaces) = &self.surfaces else {
                    tracing::warn!(path = %target.virtual_path, "surface resolver is unavailable");
                    return Err(errno(libc::EIO));
                };
                match surfaces.resolver.read_direct_env_file_plan(plan) {
                    Ok(snapshot) => GeneratedRead {
                        dependencies: Some(snapshot.audit_dependencies(&plan.surface.id)),
                        bytes: snapshot.bytes,
                    },
                    Err(error) => {
                        tracing::warn!(path = %target.virtual_path, reader = %identity.chain_display(), %error, "direct env file surface failed");
                        return Err(errno(libc::EIO));
                    }
                }
            }
        };
        Ok(generated)
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
        // Store-backed secrets and direct EnvFile surfaces are writable. Composed surfaces and
        // Generated static sources stay read-only.
        let wants_write = flags & libc::O_ACCMODE != libc::O_RDONLY;
        let write_target = match (&target.kind, wants_write) {
            (OpenKind::Secret(id), true) => Some(WriteOpenTarget::Secret {
                id: id.clone(),
                virtual_path: target.virtual_path.clone(),
            }),
            (OpenKind::DirectEnvFileSurface(plan), true) => {
                Some(WriteOpenTarget::DirectEnvFile {
                    plan: Box::new(plan.clone()),
                    virtual_path: target.virtual_path.clone(),
                })
            }
            (_, true) => {
                reply.error(errno(libc::EROFS));
                return;
            }
            _ => None,
        };
        let operation = if wants_write { Operation::Write } else { Operation::Read };

        let identity = Arc::new(floria_platform::enrich(pid, uid, gid));

        // Authorization boundary: decide after resolving the identity, before generating content.
        let decision = match self.authorize_access(&target, operation, &identity) {
            Ok(decision) => decision,
            Err(error) => {
                reply.error(error);
                return;
            }
        };

        if let Some(write_target) = write_target {
            // Write session: seed the buffer with the decrypted head so partial writes and
            // O_APPEND merge correctly; O_TRUNC starts empty. Mutations stay in memory until
            // flush/release commits them as a new immutable version.
            let initial = if flags & libc::O_TRUNC != 0 {
                Vec::new()
            } else {
                let result = match &write_target {
                    WriteOpenTarget::Secret { id, .. } => self.decrypt_secret(id),
                    WriteOpenTarget::DirectEnvFile { plan, .. } => self
                        .surfaces
                        .as_ref()
                        .ok_or_else(|| "surface resolver is unavailable".to_string())
                        .and_then(|surfaces| {
                            surfaces
                                .resolver
                                .read_direct_env_file_plan(plan)
                                .map(|snapshot| snapshot.bytes)
                                .map_err(|error| error.to_string())
                        }),
                };
                match result {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(path = %target.virtual_path, writer = %identity.chain_display(), "write seed failed: {e}");
                        reply.error(errno(libc::EIO));
                        return;
                    }
                }
            };
            let size = initial.len() as u64;
            let fh = self.writes.insert(ino, Arc::clone(&identity), initial);
            self.write_targets.insert(fh, write_target);
            if flags & libc::O_TRUNC != 0 {
                // Opening with O_TRUNC is itself a mutation even when the caller writes no
                // bytes afterwards; mark the empty buffer dirty so close cannot silently keep
                // the previous head.
                let _ = self.writes.truncate(fh, 0);
            }
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
            if let Err(error) = self.audit.log_open(
                &target.virtual_path,
                operation.as_str(),
                &identity,
                decision.decision_str(),
                decision.rule_id.as_deref(),
                decision.policy.as_ref(),
                "-",
                fh,
                size,
                None,
            ) {
                self.write_targets.remove(&fh);
                self.writes.remove(fh);
                tracing::error!(%error, "refusing write open because it could not be audited");
                reply.error(errno(libc::EIO));
                return;
            }
            reply.opened(FileHandle(fh), fuser::FopenFlags::FOPEN_DIRECT_IO);
            return;
        }

        let generated = match self.generate_read(&target, &identity) {
            Ok(generated) => generated,
            Err(error) => {
                reply.error(error);
                return;
            }
        };

        let opened = self
            .reads
            .insert(ino, Arc::clone(&identity), generated.bytes);
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
        if let Err(error) = self.audit.log_open(
            &target.virtual_path,
            operation.as_str(),
            &identity,
            decision.decision_str(),
            decision.rule_id.as_deref(),
            decision.policy.as_ref(),
            &opened.content_version,
            opened.fh,
            opened.size,
            generated.dependencies.as_deref(),
        ) {
            self.reads.remove(opened.fh);
            tracing::error!(%error, "refusing read open because it could not be audited");
            reply.error(errno(libc::EIO));
            return;
        }

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

    /// Authorize and freeze a snapshot for a process whose POSIX open was hidden by macFUSE's
    /// vnode-level handle reuse. Called once by [`ReadSessionTable`] for each process lifetime.
    fn create_read_session(
        &self,
        ino: u64,
        fh: u64,
        identity: &ProcessIdentity,
    ) -> Result<Vec<u8>, Errno> {
        let target = self.resolve_open_target(ino)?;
        let decision = self.authorize_access(&target, Operation::Read, identity)?;
        let generated = self.generate_read(&target, identity)?;
        let content_version = content_version_of(&generated.bytes);
        let size = generated.bytes.len() as u64;

        tracing::info!(
            path = %target.virtual_path,
            uid = identity.uid,
            pid = identity.pid,
            exe = ?identity.exe_path,
            chain = %identity.chain_display(),
            decision = decision.decision_str(),
            rule = decision.rule_id.as_deref().unwrap_or("-"),
            fh,
            size,
            "read session"
        );
        self.audit.log_open(
            &target.virtual_path,
            Operation::Read.as_str(),
            identity,
            decision.decision_str(),
            decision.rule_id.as_deref(),
            decision.policy.as_ref(),
            &content_version,
            fh,
            size,
            generated.dependencies.as_deref(),
        )
        .map_err(|error| {
            tracing::error!(%error, "refusing read session because it could not be audited");
            errno(libc::EIO)
        })?;
        Ok(generated.bytes)
    }

    fn is_write_owner(&self, fh: u64, pid: i32) -> bool {
        self.writes
            .is_owner(fh, floria_platform::process_instance(pid))
    }

    fn log_cross_process_write_denied(&self, ino: u64, uid: u32, gid: u32, pid: i32) {
        let identity = floria_platform::enrich(pid, uid, gid);
        let path = self
            .dynamic_path(ino)
            .or_else(|| {
                self.tree
                    .get(ino)
                    .map(|node| node.virtual_path())
                    .filter(|path| !path.is_empty())
            })
            .unwrap_or_default();
        let reason = "macFUSE reused a write session owned by another process";
        tracing::warn!(path = %path, pid, chain = %identity.chain_display(), reason, "deny cross-process write");
        let _ = self
            .audit
            .log_denied(&path, Operation::Write.as_str(), &identity, None, reason, None);
    }

    /// Runs on the authorization pool after the event-loop fast path found no snapshot for this
    /// process. It may prompt and generate when macFUSE hid the corresponding `open()` callback.
    fn handle_uncached_read(
        &self,
        request: PendingRead,
        reply: ReplyData,
    ) {
        let identity = floria_platform::enrich(request.pid, request.uid, request.gid);
        let result = if self.writes.owns(request.fh) {
            let Some(writer) = self.writes.get_identity(request.fh) else {
                reply.error(Errno::EBADF);
                return;
            };
            if writer.instance() == identity.instance() {
                self.writes
                    .read_slice(request.fh, request.offset, request.size)
                    .ok_or(ReadSessionError::BadHandle)
            } else {
                // Never expose another process's uncommitted writer buffer. A reader attached
                // to the same vnode gets its own authorized snapshot of committed backing data.
                self.reads
                    .read_secondary(request.fh, &identity, request.offset, request.size, || {
                        self.create_read_session(request.ino, request.fh, &identity)
                            .map_err(Errno::code)
                    })
            }
        } else {
            self.reads
                .read_or_create(request.fh, &identity, request.offset, request.size, || {
                    self.create_read_session(request.ino, request.fh, &identity)
                        .map_err(Errno::code)
                })
        };

        match result {
            Ok(slice) => reply.data(&slice),
            Err(ReadSessionError::BadHandle) => reply.error(Errno::EBADF),
            Err(ReadSessionError::Generate(error)) => reply.error(Errno::from_i32(error)),
        }
    }
}

/// What `open()` should serve for a resolved inode.
struct OpenTarget {
    virtual_path: String,
    display: Option<String>,
    object_revision: Option<String>,
    direct_io: bool,
    kind: OpenKind,
}

struct GeneratedRead {
    bytes: Vec<u8>,
    dependencies: Option<Vec<AuditDependency>>,
}

struct PendingRead {
    ino: u64,
    fh: u64,
    offset: u64,
    size: u32,
    uid: u32,
    gid: u32,
    pid: i32,
}

enum OpenKind {
    Static(Arc<dyn ContentSource>),
    Secret(String),
    ComposedSurface(ResolvedAccessPlan),
    DirectEnvFileSurface(ResolvedAccessPlan),
}

#[derive(Clone)]
enum WriteOpenTarget {
    Secret { id: String, virtual_path: String },
    DirectEnvFile { plan: Box<ResolvedAccessPlan>, virtual_path: String },
}

impl WriteOpenTarget {
    fn virtual_path(&self) -> String {
        match self {
            WriteOpenTarget::Secret { virtual_path, .. }
            | WriteOpenTarget::DirectEnvFile { virtual_path, .. } => virtual_path.clone(),
        }
    }
}

#[derive(Debug)]
struct CommitFailure {
    errno: Errno,
    message: String,
}

impl CommitFailure {
    fn io(message: impl Into<String>) -> Self {
        CommitFailure { errno: errno(libc::EIO), message: message.into() }
    }

    fn surface(error: SurfaceError) -> Self {
        let code = match &error {
            SurfaceError::TooLarge { .. } => libc::EFBIG,
            SurfaceError::InvalidUtf8 { .. }
            | SurfaceError::DotenvParse { .. }
            | SurfaceError::ResourceEntriesChanged { .. } => libc::EINVAL,
            _ => libc::EIO,
        };
        CommitFailure { errno: errno(code), message: error.to_string() }
    }
}

impl std::fmt::Display for CommitFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// Build error codes that fuser doesn't provide constants for (EROFS/ENOATTR, etc.) from libc.
fn errno(code: i32) -> Errno {
    Errno::from_i32(code)
}

/// Only user-protected files are addressable through `secrets/<id>`. Managed values (shared
/// secrets, env documents, SSH private keys) stay behind their typed surface or capability.
fn exposed_as_raw_secret(record: &SecretRecord) -> bool {
    record.source_path().is_some() || !record.placements.is_empty()
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

impl fuser::Filesystem for Floria {
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> std::io::Result<()> {
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        // Any name not in the tree (including macOS noise like .DS_Store / ._*) returns ENOENT; never generates content.
        if let Some(items) = &self.inner.items {
            if parent.0 == items.root_ino {
                let Some(id) = name.to_str() else {
                    reply.error(Errno::ENOENT);
                    return;
                };
                match items.get(id) {
                    Some(_) => {
                        let ino = items.dir_ino_for(id);
                        let attr = dir_attr(
                            ino,
                            0o555,
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
            if let Some(item) = items.item_for_dir_ino(parent.0) {
                if name != item.basename.as_os_str() {
                    reply.error(Errno::ENOENT);
                    return;
                }
                let ino = items.file_ino_for(&item.id);
                match self.inner.item_file_attr(ino, &item) {
                    Some(attr) => reply.entry(&TTL, &attr, fuser::Generation(0)),
                    None => reply.error(Errno::ENOENT),
                }
                return;
            }
        }
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        // Surface children resolve from the control-plane-maintained in-memory registry.
        if let Some(ns) = &self.inner.surfaces {
            if parent.0 == ns.inos.dir_ino {
                match ns.registry.get(name) {
                    Some(registered) => {
                        let ino = ns.ino_for(name);
                        match self.inner.surface_attr(ino, &registered) {
                            Some(attr) => reply.entry(&TTL, &attr, fuser::Generation(0)),
                            None => reply.error(Errno::ENOENT),
                        }
                    }
                    None => reply.error(Errno::ENOENT),
                }
                return;
            }
        }
        // Children of the secrets directory resolve dynamically against the store.
        if let Some(ns) = &self.inner.secrets {
            if parent.0 == ns.inos.dir_ino {
                match name
                    .parse::<SecretId>()
                    .ok()
                    .and_then(|sid| ns.store.record(&sid).ok().flatten())
                {
                    Some(rec) if exposed_as_raw_secret(&rec) => {
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
                    Some(_) | None => reply.error(Errno::ENOENT),
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
        if let Some(items) = &self.inner.items {
            // A directory inode contains no secret data. Once allocated it can remain visible
            // for the mount lifetime; child lookup/open still revalidates the live inventory.
            if items.owns_dir_ino(ino.0) {
                let attr = dir_attr(
                    ino.0,
                    0o555,
                    self.inner.mount_epoch,
                    self.inner.mount_uid,
                    self.inner.mount_gid,
                );
                reply.attr(&TTL, &attr);
                return;
            }
            if let Some(item) = items.item_for_file_ino(ino.0) {
                match self.inner.item_file_attr(ino.0, &item) {
                    Some(mut attr) => {
                        if let Some(len) = fh
                            .map(|file| file.0)
                            .filter(|&file| self.inner.writes.owns(file))
                            .and_then(|file| self.inner.writes.len(file))
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
        if let Some(ns) = &self.inner.surfaces {
            if let Some(id) = ns.id_for_ino(ino.0) {
                match ns
                    .registry
                    .get(&id)
                    .and_then(|registered| self.inner.surface_attr(ino.0, &registered))
                {
                    Some(mut attr) => {
                        if let Some(len) = fh
                            .map(|file| file.0)
                            .filter(|&file| self.inner.writes.owns(file))
                            .and_then(|file| self.inner.writes.len(file))
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
        if self
            .inner
            .items
            .as_ref()
            .is_some_and(|items| items.owns_dir_ino(ino.0))
        {
            reply.opened(FileHandle(0), fuser::FopenFlags::empty());
            return;
        }
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
        if let Some(items) = &self.inner.items {
            if let Some(item) = items.item_for_dir_ino(ino.0) {
                let entries = [
                    (ino.0, FileType::Directory, OsString::from(".")),
                    (items.root_ino, FileType::Directory, OsString::from("..")),
                    (
                        items.file_ino_for(&item.id),
                        FileType::RegularFile,
                        item.basename,
                    ),
                ];
                for (index, (child_ino, kind, name)) in
                    entries.iter().enumerate().skip(offset as usize)
                {
                    if reply.add(INodeNo(*child_ino), (index + 1) as u64, *kind, name) {
                        break;
                    }
                }
                reply.ok();
                return;
            }
        }
        let Some(node) = self.inner.tree.get(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !matches!(node.kind, NodeKind::Dir) {
            reply.error(Errno::ENOTDIR);
            return;
        }

        if let Some(ns) = &self.inner.surfaces {
            if ino.0 == ns.inos.dir_ino {
                let mut entries: Vec<(u64, FileType, String)> = vec![
                    (ino.0, FileType::Directory, ".".to_string()),
                    (node.parent, FileType::Directory, "..".to_string()),
                ];
                for registered in ns.registry.list() {
                    let child_ino = ns.ino_for(&registered.surface.id);
                    entries.push((child_ino, FileType::RegularFile, registered.surface.id));
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

        if let Some(items) = &self.inner.items {
            if ino.0 == items.root_ino {
                let mut entries: Vec<(u64, FileType, OsString)> = vec![
                    (ino.0, FileType::Directory, OsString::from(".")),
                    (node.parent, FileType::Directory, OsString::from("..")),
                ];
                for item in items.list() {
                    entries.push((
                        items.dir_ino_for(&item.id),
                        FileType::Directory,
                        OsString::from(item.id),
                    ));
                }
                for (index, (child_ino, kind, name)) in
                    entries.iter().enumerate().skip(offset as usize)
                {
                    if reply.add(INodeNo(*child_ino), (index + 1) as u64, *kind, name) {
                        break;
                    }
                }
                reply.ok();
                return;
            }
        }

        // The secrets directory lists the store's current contents dynamically.
        if let Some(ns) = &self.inner.secrets {
            if ino.0 == ns.inos.dir_ino {
                let mut entries: Vec<(u64, FileType, String)> = vec![
                    (ino.0, FileType::Directory, ".".to_string()),
                    (node.parent, FileType::Directory, "..".to_string()),
                ];
                for r in ns
                    .store
                    .list()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(exposed_as_raw_secret)
                {
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
        // Dispatch to the pool so a blocking authorization prompt (or slow content source) never
        // stalls the single-threaded event loop. The reply is Send and completed there.
        let (uid, gid, pid) = (req.uid(), req.gid(), req.pid() as i32);
        let shared = Arc::clone(&self.inner);
        let (ino, flags) = (ino.0, flags.0);
        self.pool
            .execute(move || shared.handle_open(ino, flags, uid, gid, pid, reply));
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let (uid, gid, pid) = (req.uid(), req.gid(), req.pid() as i32);
        let process = floria_platform::process_instance(pid);

        let existing = if self.inner.writes.owns(fh.0) {
            if self.inner.writes.is_owner(fh.0, process) {
                match self.inner.writes.read_slice(fh.0, offset, size) {
                    Some(slice) => {
                        reply.data(&slice);
                        return;
                    }
                    None => ExistingRead::BadHandle,
                }
            } else {
                self.inner
                    .reads
                    .read_existing_secondary(fh.0, process, offset, size)
            }
        } else {
            self.inner.reads.read_existing(fh.0, process, offset, size)
        };
        match existing {
            ExistingRead::Hit(slice) => {
                reply.data(&slice);
                return;
            }
            ExistingRead::BadHandle => {
                reply.error(Errno::EBADF);
                return;
            }
            ExistingRead::Missing => {}
        }

        let shared = Arc::clone(&self.inner);
        self.pool.execute(move || {
            shared.handle_uncached_read(
                PendingRead {
                    ino: ino.0,
                    fh: fh.0,
                    offset,
                    size,
                    uid,
                    gid,
                    pid,
                },
                reply,
            )
        });
    }

    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let (uid, gid, pid) = (req.uid(), req.gid(), req.pid() as i32);
        if self.inner.writes.owns(fh.0) && !self.inner.is_write_owner(fh.0, pid) {
            let shared = Arc::clone(&self.inner);
            self.pool.execute(move || {
                shared.log_cross_process_write_denied(ino.0, uid, gid, pid);
                reply.error(errno(libc::EACCES));
            });
            return;
        }
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
        req: &Request,
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
        if let Some(write_fh) = write_fh {
            let (uid, gid, pid) = (req.uid(), req.gid(), req.pid() as i32);
            if !self.inner.is_write_owner(write_fh, pid) {
                let shared = Arc::clone(&self.inner);
                self.pool.execute(move || {
                    shared.log_cross_process_write_denied(ino.0, uid, gid, pid);
                    reply.error(errno(libc::EACCES));
                });
                return;
            }
        }
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
        let attr = match self.inner.setattr_attr(ino.0, write_fh) {
            Some(a) => a,
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        reply.attr(&TTL, &attr);
    }

    fn fsync(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        // fsync is exactly our commit point: "make it durable now". Editors (vim/nvim) call it
        // right after writing and before close — commit here so their durability assumption
        // holds and an encrypt/store failure surfaces as their fsync error, not at close.
        if self.inner.writes.owns(fh.0) {
            let pid = req.pid() as i32;
            let shared = Arc::clone(&self.inner);
            self.pool.execute(move || {
                if !shared.is_write_owner(fh.0, pid) {
                    // A logical reader can share the writer's physical fh. It has no mutation
                    // to commit, so acknowledge fsync without touching the owner buffer.
                    reply.ok();
                    return;
                }
                match shared.commit_write(fh.0) {
                    Ok(_) => reply.ok(),
                    Err(e) => {
                        tracing::warn!(fh = fh.0, "write commit failed: {e}");
                        reply.error(e.errno);
                    }
                }
            });
            return;
        }
        // Read fds have nothing to sync.
        reply.ok();
    }

    fn flush(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        // flush maps to the writer's close(2) return value: commit the buffer here so a failed
        // encrypt/store write surfaces as EIO to the writer. Commit does crypto + store I/O
        // (may wait on the store lock), so it runs on the pool like open().
        if self.inner.writes.owns(fh.0) {
            let pid = req.pid() as i32;
            let shared = Arc::clone(&self.inner);
            self.pool.execute(move || {
                if !shared.is_write_owner(fh.0, pid) {
                    // macFUSE sends flush for every logical close sharing this physical fh.
                    // A non-owner has no mutation to commit and must not flush the owner buffer.
                    reply.ok();
                    return;
                }
                match shared.commit_write(fh.0) {
                    Ok(_) => reply.ok(),
                    Err(e) => {
                        tracing::warn!(fh = fh.0, "write commit failed: {e}");
                        reply.error(e.errno);
                    }
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
                let write_target = shared.write_targets.remove(&fh.0).map(|(_, target)| target);
                if let Some(closed) = shared.writes.remove(fh.0) {
                    let path = write_target
                        .as_ref()
                        .map(WriteOpenTarget::virtual_path)
                        .unwrap_or_else(|| shared.dynamic_path(closed.ino).unwrap_or_default());
                    if closed.dirty_bytes.is_some() {
                        // Commit failed even at release; the fd is gone, the content is lost.
                        tracing::error!(path = %path, fh = fh.0, "uncommitted write dropped at close");
                    }
                    tracing::debug!(path = %path, fh = fh.0, bytes = closed.size, "close (write)");
                    let _ = shared.audit.log_close(
                        &path,
                        fh.0,
                        closed.duration.as_millis(),
                        closed.size,
                        commit_err.as_ref().map(|error| error.message.as_str()),
                    );
                }
                // Purge committed snapshots created for readers that macFUSE attached to this
                // write handle while it was alive.
                let _ = shared.reads.remove(fh.0);
                reply.ok();
            });
            return;
        }
        if let Some(info) = self.inner.reads.remove(fh.0) {
            let path = self
                .inner
                .tree
                .get(info.ino)
                .map(|n| n.virtual_path())
                .filter(|p| !p.is_empty())
                .or_else(|| self.inner.dynamic_path(info.ino))
                .unwrap_or_default();
            tracing::debug!(path = %path, fh = fh.0, bytes = info.bytes_served, "close");
            let _ = self.inner.audit.log_close(
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
    mount_with_audit(
        cfg,
        authorizer,
        store,
        catalog,
        surface_registry,
        audit,
        Arc::new(ManagedMutationCoordinator::new()),
    )
}

/// Mount using an audit sink shared with other runtime capabilities such as SSH agent surfaces.
pub fn mount_with_audit(
    cfg: ResolvedConfig,
    authorizer: Arc<dyn Authorizer>,
    store: Option<Arc<dyn SecretStore>>,
    catalog: Option<Catalog>,
    surface_registry: Option<Arc<SurfaceRegistry>>,
    audit: Arc<AuditLog>,
    mutations: Arc<ManagedMutationCoordinator>,
) -> anyhow::Result<()> {
    let mount_point = cfg.mount_path.clone();
    let config = mount_config(&cfg.volname);
    let fs = Floria::new(
        &cfg,
        audit,
        authorizer,
        store,
        catalog,
        surface_registry,
        mutations,
    )?;

    tracing::info!(
        mount = %mount_point.display(),
        files = cfg.files.len(),
        "mounting floria"
    );
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .map_err(|e| anyhow::anyhow!("install signal handler: {e}"))?;

    #[cfg(all(target_os = "macos", not(feature = "macos-no-mount")))]
    let session = macos_mount::spawn(fs, &mount_point, &config)?;
    #[cfg(not(all(target_os = "macos", not(feature = "macos-no-mount"))))]
    let session = fuser::spawn_mount2(fs, &mount_point, &config)?;

    tracing::info!("mounted; press Ctrl-C to unmount");
    #[cfg(all(target_os = "macos", not(feature = "macos-no-mount")))]
    let stop_reason = wait_for_mount_stop(
        &rx,
        || session.is_finished(),
        MOUNT_SESSION_POLL_INTERVAL,
    );
    #[cfg(not(all(target_os = "macos", not(feature = "macos-no-mount"))))]
    let stop_reason = wait_for_mount_stop(
        &rx,
        || session.guard.is_finished(),
        MOUNT_SESSION_POLL_INTERVAL,
    );

    match stop_reason {
        MountStopReason::ShutdownRequested => {
            tracing::info!(mount = %mount_point.display(), "unmounting");
            #[cfg(all(target_os = "macos", not(feature = "macos-no-mount")))]
            session.unmount_and_join()?;
            #[cfg(not(all(target_os = "macos", not(feature = "macos-no-mount"))))]
            drop(session); // fuser's mounted BackgroundSession unmounts on drop.
            Ok(())
        }
        MountStopReason::SessionEnded => {
            tracing::error!(mount = %mount_point.display(), "filesystem session ended unexpectedly; exiting so launchd can restart it");
            #[cfg(all(target_os = "macos", not(feature = "macos-no-mount")))]
            session.join()?;
            #[cfg(not(all(target_os = "macos", not(feature = "macos-no-mount"))))]
            session.join()?;
            anyhow::bail!("filesystem session ended unexpectedly")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use floria_catalog::{
        Binding, BindingScope, CatalogSnapshot, EntrySelection, EntrySpec, Environment, FileBacking,
        Project, Resource, ResourceCodec, ResourceKind, ResourceSource, Surface, SurfaceFormat,
        SurfaceInput, SurfaceKind, ValueShape,
    };
    use floria_core::authz::{AllowAll, Enforcement};
    use floria_core::config::FileEntry;
    use floria_core::identity::ProcessIdentity;
    use floria_store::{
        ManagedPlacement, NewSecret, SecretOrigin, SecretRecord, StoreError, StoreResult,
        VersionRecord,
    };
    use floria_surface::{DIRENV_MAX_SIZE, DOTENV_MAX_SIZE, INI_MAX_SIZE, LINES_MAX_SIZE};
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::time::Duration;
    use zeroize::Zeroizing;

    const RAW_SECRET_ID: &str = "00000000-0000-0000-0000-000000000401";
    const MANAGED_SECRET_ID: &str = "00000000-0000-0000-0000-000000000402";
    const INI_SECRET_ID: &str = "00000000-0000-0000-0000-000000000403";
    const DIRECT_SECRET_ID: &str = "00000000-0000-0000-0000-000000000404";

    #[test]
    fn mount_wait_detects_an_ended_session() {
        let (_shutdown_tx, shutdown_rx) = mpsc::channel();

        assert_eq!(
            wait_for_mount_stop(&shutdown_rx, || true, Duration::from_millis(1)),
            MountStopReason::SessionEnded
        );
    }

    #[test]
    fn mount_wait_honors_a_shutdown_request() {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        shutdown_tx.send(()).unwrap();

        assert_eq!(
            wait_for_mount_stop(&shutdown_rx, || false, Duration::from_millis(1)),
            MountStopReason::ShutdownRequested
        );
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-no-mount")))]
    #[test]
    #[ignore = "requires the live macFUSE kernel backend"]
    fn externally_unmounted_session_returns_instead_of_leaving_a_zombie_daemon() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let root = std::env::temp_dir().join(format!(
            "floria-external-unmount-test-{}",
            std::process::id()
        ));
        let mount_path = root.join("mount");
        let config_path = root.join("floria.toml");
        let audit_path = root.join("audit.jsonl");
        std::fs::create_dir_all(&mount_path).unwrap();
        std::fs::write(
            &config_path,
            format!(
                r#"[mount]
path = "{}"
volname = "Floria Lifecycle Test"
audit_log = "{}"

[agent]
socket = "{}"

[store]
root = "{}"
ssh_key = "{}"
key_source = "ssh"
"#,
                mount_path.display(),
                audit_path.display(),
                root.join("agent.sock").display(),
                root.join("store").display(),
                root.join("unused-key").display(),
            ),
        )
        .unwrap();
        let cfg = floria_core::config::Config::load(&config_path).unwrap();
        let audit = Arc::new(AuditLog::open(&audit_path).unwrap());
        let unmount_path = CString::new(mount_path.as_os_str().as_bytes()).unwrap();
        let unmount_worker = std::thread::spawn(move || {
            for _ in 0..250 {
                // SAFETY: `unmount_path` is a live, NUL-terminated path for the duration of each
                // call. Before the mount is ready, unmount returns an error and the loop retries.
                if unsafe { libc::unmount(unmount_path.as_ptr(), 0) } == 0 {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("timed out waiting to externally unmount the test filesystem");
        });

        let result = mount_with_audit(
            cfg,
            Arc::new(AllowAll),
            None,
            None,
            None,
            audit,
            Arc::new(ManagedMutationCoordinator::new()),
        );
        unmount_worker.join().unwrap();

        let error = result.expect_err("an externally removed mount must stop the daemon");
        assert!(
            error.to_string().contains("filesystem session ended unexpectedly"),
            "unexpected mount error: {error:#}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[derive(Clone)]
    struct StoredFixture {
        origin: SecretOrigin,
        mode: u32,
        versions: Vec<Vec<u8>>,
        head: u32,
    }

    struct ReadWriteStore {
        entries: Mutex<HashMap<String, StoredFixture>>,
        fail_get: Mutex<HashSet<String>>,
    }

    impl ReadWriteStore {
        fn fixture() -> Self {
            ReadWriteStore {
                entries: Mutex::new(HashMap::from([
                    (
                        RAW_SECRET_ID.to_string(),
                        StoredFixture {
                            origin: SecretOrigin::File {
                                source_path: PathBuf::from("/fixture/protected.txt"),
                            },
                            mode: 0o640,
                            versions: vec![b"protected-value".to_vec()],
                            head: 1,
                        },
                    ),
                    (
                        MANAGED_SECRET_ID.to_string(),
                        StoredFixture {
                            origin: SecretOrigin::Managed {
                                label: "Managed fixture".to_string(),
                            },
                            mode: 0o600,
                            versions: vec![b"managed-value".to_vec()],
                            head: 1,
                        },
                    ),
                    (
                        INI_SECRET_ID.to_string(),
                        StoredFixture {
                            origin: SecretOrigin::Managed {
                                label: "INI fixture".to_string(),
                            },
                            mode: 0o600,
                            versions: vec![b"[dev]\nKEY=ini-value\n".to_vec()],
                            head: 1,
                        },
                    ),
                    (
                        DIRECT_SECRET_ID.to_string(),
                        StoredFixture {
                            origin: SecretOrigin::File {
                                source_path: PathBuf::from("/fixture/project/.env.source"),
                            },
                            mode: 0o644,
                            versions: vec![b"# preserved\nKEY='direct value'\n".to_vec()],
                            head: 1,
                        },
                    ),
                ])),
                fail_get: Mutex::new(HashSet::new()),
            }
        }

        fn current_bytes(&self, id: &str) -> Vec<u8> {
            let entries = self.entries.lock().unwrap();
            let entry = entries.get(id).unwrap();
            entry.versions[(entry.head - 1) as usize].clone()
        }

        fn current_version(&self, id: &str) -> u32 {
            self.entries.lock().unwrap().get(id).unwrap().head
        }
    }

    impl SecretStore for ReadWriteStore {
        fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            if self.fail_get.lock().unwrap().contains(id.as_str()) {
                return Err(StoreError::Crypto("fixture read failure".to_string()));
            }
            let entries = self.entries.lock().unwrap();
            let entry = entries
                .get(id.as_str())
                .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
            Ok(Zeroizing::new(
                entry.versions[(entry.head - 1) as usize].clone(),
            ))
        }

        fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            let entry = entries
                .get(id.as_str())
                .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
            let bytes = entry
                .versions
                .get((version - 1) as usize)
                .ok_or_else(|| StoreError::NotFound(format!("{id}@{version}")))?;
            Ok(Zeroizing::new(bytes.clone()))
        }

        fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
            let mut entries = self.entries.lock().unwrap();
            let entry = entries
                .get_mut(id.as_str())
                .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
            entry.versions.push(plaintext.to_vec());
            entry.head = entry.versions.len() as u32;
            Ok(entry.head)
        }

        fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            Ok(entries.get(id.as_str()).map(|entry| SecretRecord {
                id: id.clone(),
                origin: entry.origin.clone(),
                mode: entry.mode,
                size: entry.versions[(entry.head - 1) as usize].len() as u64,
                created: "fixture-time".to_string(),
                current_version: entry.head,
                enforcement: Enforcement::Prompt,
                environment_ids: None,
                placements: Vec::new(),
                metadata: Default::default(),
            }))
        }

        fn delete(&self, id: &SecretId) -> StoreResult<()> {
            self.entries
                .lock()
                .unwrap()
                .remove(id.as_str())
                .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
            Ok(())
        }

        fn put(&self, _meta: NewSecret, _plaintext: &[u8]) -> StoreResult<SecretId> {
            unimplemented!()
        }

        fn history(&self, _id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            unimplemented!()
        }

        fn set_head(&self, _id: &SecretId, _version: u32) -> StoreResult<()> {
            unimplemented!()
        }

        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            Ok(entries
                .iter()
                .map(|(id, entry)| SecretRecord {
                    id: id.parse().expect("fixture ids are UUIDs"),
                    origin: entry.origin.clone(),
                    mode: entry.mode,
                    size: entry.versions[(entry.head - 1) as usize].len() as u64,
                    created: "fixture-time".to_string(),
                    current_version: entry.head,
                    enforcement: Enforcement::Prompt,
                    environment_ids: None,
                    placements: Vec::new(),
                    metadata: Default::default(),
                })
                .collect())
        }

        fn get_by_path(&self, _source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            unimplemented!()
        }

        fn update_settings(
            &self,
            _id: &SecretId,
            _metadata: floria_core::metadata::ItemMetadata,
            _enforcement: Enforcement,
            _environment_ids: Option<Vec<String>>,
        ) -> StoreResult<()> {
            unimplemented!()
        }

        fn update_placements(
            &self,
            _id: &SecretId,
            _placements: Vec<floria_store::ManagedPlacement>,
        ) -> StoreResult<()> {
            unimplemented!()
        }
    }

    fn upsert_resource(catalog: &Catalog, resource: Resource) {
        catalog.upsert_resource(&resource).unwrap();
    }

    fn upsert_binding(catalog: &Catalog, id: &str, resource_id: &str, position: i64) {
        catalog
            .upsert_binding(&Binding {
                id: id.to_string(),
                project_id: "fixture-project".to_string(),
                scope: BindingScope::Environment {
                    environment_id: "fixture-environment".to_string(),
                },
                resource_id: resource_id.to_string(),
                selection: EntrySelection::All,
                key_override: None,
                enabled: true,
                allow_override: false,
                position,
            })
            .unwrap();
    }

    fn upsert_surface(
        catalog: &Catalog,
        id: &str,
        name: &str,
        kind: SurfaceKind,
        input: SurfaceInput,
        position: i64,
    ) {
        catalog
            .upsert_surface(&Surface {
                id: id.to_string(),
                environment_id: "fixture-environment".to_string(),
                name: name.to_string(),
                kind,
                path: Some(PathBuf::from(format!("/fixture/project/{name}"))),
                input,
                enforcement: Enforcement::Prompt,
                position,
            })
            .unwrap();
    }

    fn surface_catalog(path: &Path) -> Catalog {
        let catalog = Catalog::open(path).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture Project".to_string(),
                path: PathBuf::from("/fixture/project"),
                ..Default::default()
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

        upsert_resource(
            &catalog,
            Resource {
                id: "fixture-env".to_string(),
                name: "Fixture Environment Value".to_string(),
                kind: ResourceKind::Literal,
                shape: ValueShape::Scalar,
                codec: ResourceCodec::Opaque,
                default_env_key: Some("TOKEN".to_string()),
                entries: vec![EntrySpec {
                    address: "value".to_string(),
                    label: "TOKEN".to_string(),
                    key: Some("TOKEN".to_string()),
                    sensitive: true,
                }],
                source: ResourceSource::Literal {
                    value: "literal-value".to_string(),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        upsert_resource(
            &catalog,
            Resource {
                id: "fixture-ini".to_string(),
                name: "Fixture INI".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Ini,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "sections/dev/keys/KEY".to_string(),
                    label: "[dev] KEY".to_string(),
                    key: Some("KEY".to_string()),
                    sensitive: true,
                }],
                source: ResourceSource::SecretRef {
                    secret_id: INI_SECRET_ID.to_string(),
                    managed_source_ids: Vec::new(),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        upsert_resource(
            &catalog,
            Resource {
                id: "fixture-line".to_string(),
                name: "Fixture Line".to_string(),
                kind: ResourceKind::Literal,
                shape: ValueShape::Scalar,
                codec: ResourceCodec::Opaque,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "value".to_string(),
                    label: "Fixture Line".to_string(),
                    key: None,
                    sensitive: true,
                }],
                source: ResourceSource::Literal {
                    value: "line-value".to_string(),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        upsert_resource(
            &catalog,
            Resource {
                id: "fixture-direct".to_string(),
                name: "Fixture Direct Env".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Dotenv,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "keys/KEY".to_string(),
                    label: "KEY".to_string(),
                    key: Some("KEY".to_string()),
                    sensitive: true,
                }],
                source: ResourceSource::SecretRef {
                    secret_id: DIRECT_SECRET_ID.to_string(),
                    managed_source_ids: Vec::new(),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            },
        );
        upsert_resource(
            &catalog,
            Resource {
                id: "fixture-protected-line".to_string(),
                name: "Fixture Protected Line".to_string(),
                kind: ResourceKind::SharedSecret,
                shape: ValueShape::Scalar,
                codec: ResourceCodec::Opaque,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "value".to_string(),
                    label: "Fixture Protected Line".to_string(),
                    key: None,
                    sensitive: true,
                }],
                source: ResourceSource::SecretRef {
                    secret_id: RAW_SECRET_ID.to_string(),
                    managed_source_ids: Vec::new(),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
                origin: Default::default(),
            },
        );

        upsert_binding(&catalog, "fixture-env-binding", "fixture-env", 0);
        upsert_binding(&catalog, "fixture-ini-binding", "fixture-ini", 1);
        upsert_binding(&catalog, "fixture-line-binding", "fixture-line", 2);
        upsert_binding(
            &catalog,
            "fixture-protected-line-binding",
            "fixture-protected-line",
            3,
        );
        upsert_surface(
            &catalog,
            "fixture-dotenv",
            ".env",
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            SurfaceInput::Bindings {
                binding_ids: vec!["fixture-env-binding".to_string()],
            },
            0,
        );
        upsert_surface(
            &catalog,
            "fixture-direnv",
            ".envrc",
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv)),
            SurfaceInput::Bindings {
                binding_ids: vec!["fixture-env-binding".to_string()],
            },
            1,
        );
        upsert_surface(
            &catalog,
            "fixture-ini-surface",
            "credentials.ini",
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
            SurfaceInput::Bindings {
                binding_ids: vec!["fixture-ini-binding".to_string()],
            },
            2,
        );
        upsert_surface(
            &catalog,
            "fixture-lines",
            "credentials.lines",
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
            SurfaceInput::Bindings {
                binding_ids: vec!["fixture-line-binding".to_string()],
            },
            3,
        );
        upsert_surface(
            &catalog,
            "fixture-direct-surface",
            ".env.source",
            SurfaceKind::File(FileBacking::EnvFileDirect),
            SurfaceInput::Resource {
                resource_id: "fixture-direct".to_string(),
            },
            4,
        );
        upsert_surface(
            &catalog,
            "fixture-protected-lines",
            "protected.lines",
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
            SurfaceInput::Bindings {
                binding_ids: vec!["fixture-protected-line-binding".to_string()],
            },
            5,
        );
        catalog
    }

    fn shared_fixture(
        files: &[FileEntry],
        store: Arc<dyn SecretStore>,
        catalog: Option<Catalog>,
        registry: Option<Arc<SurfaceRegistry>>,
        tmp: &Path,
    ) -> Arc<Shared> {
        let tree = Tree::build(files);
        let next_ino = Arc::new(AtomicU64::new(tree.next_ino()));
        let mutations = Arc::new(ManagedMutationCoordinator::new());
        let items = ItemsNs::new(
            Arc::clone(&store),
            registry.clone(),
            tree.items_dir_ino(),
            Arc::clone(&next_ino),
        );
        let secrets = SecretsNs::new(
            Arc::clone(&store),
            catalog.clone(),
            Arc::clone(&mutations),
            tree.secrets_dir_ino(),
            Arc::clone(&next_ino),
        );
        let surfaces = match (catalog, registry) {
            (Some(catalog), Some(registry)) => Some(SurfaceNs::new(
                registry,
                SurfaceResolver::with_mutation_coordinator(catalog, store, mutations),
                tree.surfaces_dir_ino(),
                next_ino,
            )),
            _ => None,
        };
        Arc::new(Shared {
            tree,
            reads: ReadSessionTable::new(),
            writes: WriteBufTable::new(),
            write_targets: DashMap::new(),
            audit: Arc::new(AuditLog::open(&tmp.join("audit.jsonl")).unwrap()),
            authorizer: Arc::new(AllowAll),
            secrets: Some(secrets),
            surfaces,
            items: Some(items),
            mount_epoch: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            mount_uid: 501,
            mount_gid: 20,
        })
    }

    fn surface_registry_snapshot(surface: Surface) -> CatalogSnapshot {
        CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture Project".to_string(),
                path: PathBuf::from("/fixture/project"),
                default_environment_id: Some("fixture-development".to_string()),
            }],
            environments: vec![Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            }],
            surfaces: vec![surface],
            ..CatalogSnapshot::default()
        }
    }

    #[test]
    fn raw_secret_namespace_exposes_file_origins_and_portable_placements() {
        let record = |origin| SecretRecord {
            id: "00000000-0000-0000-0000-000000000301".parse().unwrap(),
            origin,
            mode: 0o600,
            size: 32,
            created: "fixture-time".to_string(),
            current_version: 1,
            enforcement: floria_core::authz::Enforcement::Prompt,
            environment_ids: None,
            placements: Vec::new(),
            metadata: Default::default(),
        };

        assert!(exposed_as_raw_secret(&record(SecretOrigin::File {
            source_path: PathBuf::from("/fixture/protected.env"),
        })));
        assert!(!exposed_as_raw_secret(&record(SecretOrigin::Managed {
            label: "Fixture managed value".to_string(),
        })));
        let mut portable = record(SecretOrigin::Managed {
            label: "Portable file".to_string(),
        });
        portable.placements = vec![ManagedPlacement::home(".pgpass").unwrap()];
        assert!(exposed_as_raw_secret(&portable));
        assert_eq!(ItemsNs::secret_item(portable).unwrap().basename, ".pgpass");
    }

    #[test]
    fn resolves_and_generates_static_files_without_mounting() {
        let tmp = tempfile::tempdir().unwrap();
        let files = vec![
            FileEntry {
                path: "constant.txt".to_string(),
                components: vec!["constant.txt".to_string()],
                mode: 0o440,
                ttl: Duration::ZERO,
                enforcement: Enforcement::Allow,
                declared_size: None,
                source: Arc::new(floria_core::source::LiteralSource::new(Arc::new(
                    b"constant bytes".to_vec(),
                ))),
            },
            FileEntry {
                path: "nested/script.txt".to_string(),
                components: vec!["nested".to_string(), "script.txt".to_string()],
                mode: 0o400,
                ttl: Duration::ZERO,
                enforcement: Enforcement::Allow,
                declared_size: Some(256),
                source: Arc::new(floria_core::source::CommandSource::new(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "printf '%s:%s' \"$FLORIA_PATH\" \"$FLORIA_REQUEST_PID\"".to_string(),
                ])),
            },
        ];
        let store = Arc::new(ReadWriteStore::fixture());
        let shared = shared_fixture(
            &files,
            store as Arc<dyn SecretStore>,
            None,
            None,
            tmp.path(),
        );
        let identity = ProcessIdentity::bare(4242, 501, 20);

        let constant_ino = shared.tree.lookup_child(1, "constant.txt").unwrap();
        let constant = shared.resolve_open_target(constant_ino).unwrap();
        assert_eq!(constant.virtual_path, "constant.txt");
        assert_eq!(constant.display, None);
        assert!(!constant.direct_io);
        let generated = shared.generate_read(&constant, &identity).unwrap();
        assert_eq!(generated.bytes, b"constant bytes");
        assert!(generated.dependencies.is_none());

        let nested_ino = shared.tree.lookup_child(1, "nested").unwrap();
        let script_ino = shared.tree.lookup_child(nested_ino, "script.txt").unwrap();
        let script = shared.resolve_open_target(script_ino).unwrap();
        assert_eq!(script.virtual_path, "nested/script.txt");
        assert!(script.direct_io);
        let generated = shared.generate_read(&script, &identity).unwrap();
        assert_eq!(generated.bytes, b"nested/script.txt:4242");
        assert!(generated.dependencies.is_none());

        assert_eq!(
            shared.resolve_open_target(nested_ino).err().unwrap().code(),
            libc::EISDIR
        );
        assert_eq!(
            shared.resolve_open_target(u64::MAX).err().unwrap().code(),
            libc::ENOENT
        );
    }

    #[test]
    fn raw_secret_resolution_enforces_origin_existence_and_read_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(ReadWriteStore::fixture());
        let shared = shared_fixture(
            &[],
            Arc::clone(&store) as Arc<dyn SecretStore>,
            None,
            None,
            tmp.path(),
        );
        let identity = ProcessIdentity::bare(4242, 501, 20);
        let secrets = shared.secrets.as_ref().unwrap();

        let raw_ino = secrets.ino_for(RAW_SECRET_ID);
        let target = shared.resolve_open_target(raw_ino).unwrap();
        assert_eq!(target.virtual_path, format!("secrets/{RAW_SECRET_ID}"));
        assert_eq!(
            target.display.as_deref(),
            Some("/fixture/protected.txt")
        );
        assert!(target.direct_io);
        let generated = shared.generate_read(&target, &identity).unwrap();
        assert_eq!(generated.bytes, b"protected-value");
        assert!(generated.dependencies.is_none());

        store
            .fail_get
            .lock()
            .unwrap()
            .insert(RAW_SECRET_ID.to_string());
        assert_eq!(
            shared.generate_read(&target, &identity).err().unwrap().code(),
            libc::EIO
        );

        let managed_ino = secrets.ino_for(MANAGED_SECRET_ID);
        assert_eq!(
            shared.resolve_open_target(managed_ino).err().unwrap().code(),
            libc::ENOENT
        );

        store
            .delete(&RAW_SECRET_ID.parse::<SecretId>().unwrap())
            .unwrap();
        assert_eq!(
            shared.resolve_open_target(raw_ino).err().unwrap().code(),
            libc::ENOENT
        );
    }

    #[test]
    fn public_items_alias_existing_backings_without_replacing_legacy_namespaces() {
        let tmp = tempfile::tempdir().unwrap();
        let catalog = surface_catalog(&tmp.path().join("catalog.sqlite"));
        let registry = Arc::new(SurfaceRegistry::from_snapshot(&catalog.snapshot().unwrap()));
        let store = Arc::new(ReadWriteStore::fixture());
        let shared = shared_fixture(
            &[],
            store as Arc<dyn SecretStore>,
            Some(catalog),
            Some(registry),
            tmp.path(),
        );
        let items = shared.items.as_ref().unwrap();

        let raw = items.get(RAW_SECRET_ID).expect("raw protected file item");
        assert_eq!(raw.basename, "protected.txt");
        let raw_target = shared
            .resolve_open_target(items.file_ino_for(RAW_SECRET_ID))
            .unwrap();
        assert_eq!(
            raw_target.virtual_path,
            format!("items/{RAW_SECRET_ID}/protected.txt")
        );
        assert!(matches!(raw_target.kind, OpenKind::Secret(_)));

        let direct = items
            .get("fixture-direct-surface")
            .expect("direct file surface item");
        assert_eq!(direct.basename, ".env.source");
        let direct_target = shared
            .resolve_open_target(items.file_ino_for("fixture-direct-surface"))
            .unwrap();
        assert_eq!(
            direct_target.virtual_path,
            "items/fixture-direct-surface/.env.source"
        );
        assert!(matches!(direct_target.kind, OpenKind::DirectEnvFileSurface(_)));

        // The old adapters remain independently addressable for rollback.
        let legacy = shared
            .resolve_open_target(shared.secrets.as_ref().unwrap().ino_for(RAW_SECRET_ID))
            .unwrap();
        assert_eq!(legacy.virtual_path, format!("secrets/{RAW_SECRET_ID}"));
    }

    #[test]
    fn file_surfaces_resolve_to_stable_paths_and_generate_auditable_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        let catalog = surface_catalog(&tmp.path().join("catalog.sqlite"));
        let registry = Arc::new(SurfaceRegistry::from_snapshot(&catalog.snapshot().unwrap()));
        let store = Arc::new(ReadWriteStore::fixture());
        let shared = shared_fixture(
            &[],
            store as Arc<dyn SecretStore>,
            Some(catalog.clone()),
            Some(registry),
            tmp.path(),
        );
        let identity = ProcessIdentity::bare(4242, 501, 20);
        let surfaces = shared.surfaces.as_ref().unwrap();
        let cases: &[(&str, &str, &[u8])] = &[
            ("fixture-dotenv", ".env", b"TOKEN=literal-value\n"),
            (
                "fixture-direnv",
                ".envrc",
                b"export TOKEN='literal-value'\n",
            ),
            (
                "fixture-ini-surface",
                "credentials.ini",
                b"[dev]\nKEY = ini-value\n",
            ),
            ("fixture-lines", "credentials.lines", b"line-value\n"),
            (
                "fixture-direct-surface",
                ".env.source",
                b"# preserved\nKEY='direct value'\n",
            ),
        ];

        for (surface_id, name, expected) in cases {
            let ino = surfaces.ino_for(surface_id);
            let target = shared.resolve_open_target(ino).unwrap();
            assert_eq!(target.virtual_path, format!("surfaces/{surface_id}"));
            assert_eq!(
                target.display.as_deref(),
                Some(format!("/fixture/project/{name}").as_str())
            );
            assert!(target.direct_io);

            let generated = shared.generate_read(&target, &identity).unwrap();
            assert_eq!(&generated.bytes, expected);
            assert!(
                generated
                    .dependencies
                    .as_ref()
                    .is_some_and(|dependencies| !dependencies.is_empty())
            );
        }

        let stale_target = shared
            .resolve_open_target(surfaces.ino_for("fixture-dotenv"))
            .unwrap();
        catalog.remove_surface("fixture-dotenv").unwrap();
        let generated = shared.generate_read(&stale_target, &identity).unwrap();
        assert_eq!(generated.bytes, b"TOKEN=literal-value\n");
    }

    #[test]
    fn surface_attributes_freeze_composed_limits_and_preserve_direct_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let catalog = surface_catalog(&tmp.path().join("catalog.sqlite"));
        let registry = Arc::new(SurfaceRegistry::from_snapshot(&catalog.snapshot().unwrap()));
        let store = Arc::new(ReadWriteStore::fixture());
        let shared = shared_fixture(
            &[],
            store as Arc<dyn SecretStore>,
            Some(catalog),
            Some(Arc::clone(&registry)),
            tmp.path(),
        );
        let surfaces = shared.surfaces.as_ref().unwrap();

        for (surface_id, expected_size) in [
            ("fixture-dotenv", DOTENV_MAX_SIZE as u64),
            ("fixture-direnv", DIRENV_MAX_SIZE as u64),
            ("fixture-ini-surface", INI_MAX_SIZE as u64),
            ("fixture-lines", LINES_MAX_SIZE as u64),
        ] {
            let registered = registry.get(surface_id).unwrap();
            let attr = shared
                .surface_attr(surfaces.ino_for(surface_id), &registered)
                .unwrap();
            assert_eq!(attr.size, expected_size, "{surface_id}");
            assert_eq!(attr.perm, 0o400, "{surface_id}");
        }

        let registered = registry.get("fixture-direct-surface").unwrap();
        let attr = shared
            .surface_attr(
                surfaces.ino_for("fixture-direct-surface"),
                &registered,
            )
            .unwrap();
        assert_eq!(attr.size, b"# preserved\nKEY='direct value'\n".len() as u64);
        assert_eq!(attr.perm, 0o644);
    }

    #[test]
    fn commits_validate_catalog_secrets_and_direct_env_file_schema() {
        let tmp = tempfile::tempdir().unwrap();
        let catalog = surface_catalog(&tmp.path().join("catalog.sqlite"));
        let registry = Arc::new(SurfaceRegistry::from_snapshot(&catalog.snapshot().unwrap()));
        let store = Arc::new(ReadWriteStore::fixture());
        let shared = shared_fixture(
            &[],
            Arc::clone(&store) as Arc<dyn SecretStore>,
            Some(catalog.clone()),
            Some(Arc::clone(&registry)),
            tmp.path(),
        );
        let identity = Arc::new(ProcessIdentity::bare(4242, 501, 20));

        let raw_ino = shared.secrets.as_ref().unwrap().ino_for(RAW_SECRET_ID);
        let raw_fh = shared
            .writes
            .insert(raw_ino, Arc::clone(&identity), Vec::new());
        shared
            .write_targets
            .insert(
                raw_fh,
                WriteOpenTarget::Secret {
                    id: RAW_SECRET_ID.to_string(),
                    virtual_path: format!("secrets/{RAW_SECRET_ID}"),
                },
            );
        shared
            .writes
            .write_at(raw_fh, 0, b"first line\nsecond line")
            .unwrap();
        let error = shared.commit_write(raw_fh).unwrap_err();
        assert!(
            error.to_string().contains("one line"),
            "unexpected validation error: {error}"
        );
        assert_eq!(store.current_version(RAW_SECRET_ID), 1);
        assert_eq!(store.current_bytes(RAW_SECRET_ID), b"protected-value");

        let direct_ino = shared
            .surfaces
            .as_ref()
            .unwrap()
            .ino_for("fixture-direct-surface");
        let direct_fh = shared
            .writes
            .insert(direct_ino, Arc::clone(&identity), Vec::new());
        let direct_plan = shared
            .surfaces
            .as_ref()
            .unwrap()
            .surface_for_ino(direct_ino)
            .unwrap();
        shared.write_targets.insert(
            direct_fh,
            WriteOpenTarget::DirectEnvFile {
                plan: Box::new(direct_plan.clone()),
                virtual_path: "surfaces/fixture-direct-surface".to_string(),
            },
        );
        let mut rebound_resource = catalog
            .snapshot()
            .unwrap()
            .resources
            .into_iter()
            .find(|resource| resource.id == "fixture-direct")
            .unwrap();
        rebound_resource.source = ResourceSource::SecretRef {
            secret_id: RAW_SECRET_ID.to_string(),
            managed_source_ids: Vec::new(),
        };
        catalog.upsert_resource(&rebound_resource).unwrap();
        registry.replace(&catalog.snapshot().unwrap());
        shared
            .writes
            .write_at(direct_fh, 0, b"# changed\nKEY=new-value\n")
            .unwrap();
        assert!(shared.commit_write(direct_fh).unwrap());
        assert_eq!(store.current_version(DIRECT_SECRET_ID), 2);
        assert_eq!(
            store.current_bytes(DIRECT_SECRET_ID),
            b"# changed\nKEY=new-value\n"
        );
        assert_eq!(store.current_bytes(RAW_SECRET_ID), b"protected-value");

        let invalid_fh = shared.writes.insert(direct_ino, identity, Vec::new());
        shared.write_targets.insert(
            invalid_fh,
            WriteOpenTarget::DirectEnvFile {
                plan: Box::new(direct_plan),
                virtual_path: "surfaces/fixture-direct-surface".to_string(),
            },
        );
        shared
            .writes
            .write_at(invalid_fh, 0, b"OTHER=new-value\n")
            .unwrap();
        let error = shared.commit_write(invalid_fh).unwrap_err();
        assert_eq!(error.errno.code(), libc::EINVAL);
        assert!(error.to_string().contains("entries changed"));
        assert_eq!(store.current_version(DIRECT_SECRET_ID), 2);
    }

    #[test]
    fn managed_item_setattr_returns_attributes_after_editor_truncation() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(ReadWriteStore::fixture());
        let shared = shared_fixture(&[], store.clone(), None, None, tmp.path());
        let items = shared.items.as_ref().unwrap();
        let item = items.get(RAW_SECRET_ID).unwrap();
        let ino = items.file_ino_for(&item.id);
        let identity = Arc::new(ProcessIdentity::bare(4242, 501, 20));
        let fh = shared.writes.insert(ino, identity, b"protected-value".to_vec());
        shared.write_targets.insert(fh, WriteOpenTarget::Secret {
            id: RAW_SECRET_ID.into(),
            virtual_path: format!("items/{RAW_SECRET_ID}/protected.txt"),
        });
        shared.writes.truncate(fh, 0).unwrap();
        let attr = shared.setattr_attr(ino, Some(fh))
            .expect("ftruncate must not return ENOENT for a managed item inode");
        assert_eq!(attr.ino, INodeNo(ino));
        assert_eq!(attr.size, 0);
        assert_eq!(attr.perm, 0o640);
        shared.writes.write_at(fh, 0, b"edited-value").unwrap();
        assert_eq!(shared.setattr_attr(ino, Some(fh)).unwrap().size, 12);
        shared.commit_write(fh).unwrap();
        assert_eq!(store.current_bytes(RAW_SECRET_ID), b"edited-value");
    }

    #[test]
    fn configured_item_setattr_uses_its_surface_backing_and_write_buffer() {
        let tmp = tempfile::tempdir().unwrap();
        let catalog = surface_catalog(&tmp.path().join("catalog.sqlite"));
        let registry = Arc::new(SurfaceRegistry::from_snapshot(&catalog.snapshot().unwrap()));
        let shared = shared_fixture(&[], Arc::new(ReadWriteStore::fixture()),
            Some(catalog), Some(registry), tmp.path());
        let items = shared.items.as_ref().unwrap();
        let item = items.list().into_iter().find(|item| matches!(
            &item.backing, ManagedItemBacking::Surface(id) if id == "fixture-direct-surface"
        )).unwrap();
        let ino = items.file_ino_for(&item.id);
        let identity = Arc::new(ProcessIdentity::bare(4242, 501, 20));
        let fh = shared.writes.insert(ino, identity, Vec::new());
        let attr = shared.setattr_attr(ino, Some(fh)).unwrap();
        assert_eq!(attr.ino, INodeNo(ino));
        assert_eq!(attr.size, 0);
        assert_eq!(attr.perm, 0o644);
        assert!(shared.setattr_attr(u64::MAX, None).is_none());
    }

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
            None,
            Arc::new(ManagedMutationCoordinator::new()),
            tree.secrets_dir_ino(),
            Arc::clone(&next_ino),
        );
        let surface = Surface {
            id: "fixture-dotenv-a".to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: Some(tmp.path().join("project/.env")),
            input: SurfaceInput::Bindings { binding_ids: Vec::new() },
            enforcement: floria_core::authz::Enforcement::Prompt,
            position: 0,
        };
        let registry = Arc::new(SurfaceRegistry::from_snapshot(&surface_registry_snapshot(
            surface.clone(),
        )));
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
        assert_eq!(
            surface_ns.surface_for_ino(first_surface_ino).map(|registered| registered.surface),
            Some(surface)
        );

        let replacement = Surface {
            id: "fixture-dotenv-b".to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env.local".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: Some(tmp.path().join("project/.env.local")),
            input: SurfaceInput::Bindings { binding_ids: Vec::new() },
            enforcement: floria_core::authz::Enforcement::Prompt,
            position: 0,
        };
        registry.replace(&surface_registry_snapshot(replacement.clone()));
        assert!(surface_ns.surface_for_ino(first_surface_ino).is_none());
        let replacement_ino = surface_ns.ino_for(&replacement.id);
        assert_ne!(replacement_ino, first_surface_ino);
        assert_eq!(
            surface_ns.surface_for_ino(replacement_ino).map(|registered| registered.surface),
            Some(replacement)
        );
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
        fn update_settings(
            &self,
            _id: &SecretId,
            _metadata: floria_core::metadata::ItemMetadata,
            _enforcement: floria_core::authz::Enforcement,
            _environment_ids: Option<Vec<String>>,
        ) -> StoreResult<()> {
            unimplemented!()
        }
        fn update_placements(
            &self,
            _id: &SecretId,
            _placements: Vec<floria_store::ManagedPlacement>,
        ) -> StoreResult<()> {
            unimplemented!()
        }
        fn delete(&self, _id: &SecretId) -> StoreResult<()> {
            unimplemented!()
        }
    }

    fn shared_with_store(store: Arc<dyn SecretStore>, tmp: &Path) -> Arc<Shared> {
        let tree = Tree::build(&[]);
        let next_ino = Arc::new(AtomicU64::new(tree.next_ino()));
        let items = ItemsNs::new(
            Arc::clone(&store),
            None,
            tree.items_dir_ino(),
            Arc::clone(&next_ino),
        );
        let secrets = SecretsNs::new(
            store,
            None,
            Arc::new(ManagedMutationCoordinator::new()),
            tree.secrets_dir_ino(),
            next_ino,
        );
        Arc::new(Shared {
            tree,
            reads: ReadSessionTable::new(),
            writes: WriteBufTable::new(),
            write_targets: DashMap::new(),
            audit: Arc::new(AuditLog::open(&tmp.join("audit.jsonl")).unwrap()),
            authorizer: Arc::new(AllowAll),
            secrets: Some(secrets),
            surfaces: None,
            items: Some(items),
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
        shared
            .write_targets
            .insert(
                fh,
                WriteOpenTarget::Secret {
                    id: id.to_string(),
                    virtual_path: format!("secrets/{id}"),
                },
            );
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
