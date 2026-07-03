//! accessfs-fs: macFUSE backend. Exposes the virtual file tree from
//! [`ResolvedConfig`] as a read-only FUSE volume.
//!
//! Key semantics (see the product brief):
//! - `stat/readdir/getattr` never generate content, and attributes stay constant
//!   for the mount's lifetime → dev tools don't trigger accidentally.
//! - `open()` identifies the reading process, generates a single per-open snapshot,
//!   and writes an audit record.
//! - Repeated `read`s on the same fd return the same bytes; different fds get
//!   independent snapshots.

mod reply;
mod tree;

use std::sync::Arc;
use std::time::SystemTime;

use accessfs_core::audit::AuditLog;
use accessfs_core::authz::{AllowAll, AuthRequest, Authorizer, Operation};
use accessfs_core::config::ResolvedConfig;
use accessfs_core::handler::HandlerCtx;
use accessfs_core::snapshot::SnapshotTable;
use fuser::{
    AccessFlags, Errno, FileHandle, FileType, INodeNo, KernelConfig, OpenFlags, ReplyAttr,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyXattr, Request,
};

use reply::{dir_attr, file_attr, mount_config, TTL};
use tree::{NodeKind, Tree};

/// FUSE filesystem instance. The tree is immutable for the mount's lifetime; only
/// the snapshot table and audit log need interior mutability.
pub struct AccessFs {
    tree: Tree,
    snapshots: SnapshotTable,
    audit: Arc<AuditLog>,
    /// Authorization decision boundary. Initially AllowAll (monitor mode); a real
    /// implementation will be supplied by the agent later.
    authorizer: Arc<dyn Authorizer>,
    /// Stable timestamp used for all attributes (captured at mount time, never
    /// changes), so watchers don't trigger accidentally.
    mount_epoch: SystemTime,
    mount_uid: u32,
    mount_gid: u32,
}

impl AccessFs {
    pub fn new(cfg: &ResolvedConfig, audit: Arc<AuditLog>, authorizer: Arc<dyn Authorizer>) -> Self {
        // SAFETY: geteuid/getegid take no arguments, have no side effects, and always succeed.
        let (mount_uid, mount_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        AccessFs {
            tree: Tree::build(cfg),
            snapshots: SnapshotTable::new(),
            audit,
            authorizer,
            mount_epoch: SystemTime::now(),
            mount_uid,
            mount_gid,
        }
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
}

/// Build error codes that fuser doesn't provide constants for (EROFS/ENOATTR, etc.) from libc.
fn errno(code: i32) -> Errno {
    Errno::from_i32(code)
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
        match self
            .tree
            .lookup_child(parent.0, name)
            .and_then(|ino| self.attr_for(ino))
        {
            Some(attr) => reply.entry(&TTL, &attr, fuser::Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.attr_for(ino.0) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.tree.get(ino.0).map(|n| &n.kind) {
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
        let Some(node) = self.tree.get(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !matches!(node.kind, NodeKind::Dir) {
            reply.error(Errno::ENOTDIR);
            return;
        }

        // . and .. always come first, then child nodes. offset is the "next" cursor.
        let mut entries: Vec<(u64, FileType, &str)> = vec![
            (ino.0, FileType::Directory, "."),
            (node.parent, FileType::Directory, ".."),
        ];
        for &child_ino in self.tree.children(ino.0) {
            if let Some(child) = self.tree.get(child_ino) {
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
        let Some(node) = self.tree.get(ino.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let NodeKind::File(file) = &node.kind else {
            reply.error(Errno::EISDIR);
            return;
        };
        // Read-only: reject any write open.
        if flags.0 & libc::O_ACCMODE != libc::O_RDONLY {
            reply.error(errno(libc::EROFS));
            return;
        }

        let (uid, gid, pid) = (req.uid(), req.gid(), req.pid() as i32);
        let identity = Arc::new(accessfs_platform::enrich(pid, uid, gid));

        // Authorization boundary: decide after resolving the identity, before generating content.
        // Blocking, which matches the blocking semantics of FUSE open.
        let decision = self.authorizer.authorize(&AuthRequest {
            path: &file.virtual_path,
            operation: Operation::Read,
            identity: &identity,
        });
        if !decision.is_allowed() {
            tracing::info!(
                path = %file.virtual_path,
                chain = %identity.chain_display(),
                reason = %decision.reason,
                "deny"
            );
            self.audit.log_denied(
                &file.virtual_path,
                &identity,
                decision.rule_id.as_deref(),
                &decision.reason,
            );
            reply.error(errno(libc::EACCES));
            return;
        }

        // open boundary: generate a snapshot once.
        let ctx = HandlerCtx {
            virtual_path: file.virtual_path.clone(),
            request_uid: uid,
            request_pid: pid,
        };
        let bytes = match file.handler.generate(&ctx) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(path = %file.virtual_path, reader = %identity.chain_display(), "handler failed: {e}");
                reply.error(errno(libc::EIO));
                return;
            }
        };

        let opened = self.snapshots.insert(ino.0, Arc::clone(&identity), bytes);
        tracing::info!(
            path = %file.virtual_path,
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
            &file.virtual_path,
            &identity,
            decision.decision_str(),
            decision.rule_id.as_deref(),
            &opened.content_version,
            opened.fh,
            opened.size,
        );

        // Dynamic (script) files use direct-io: the kernel won't truncate to attr size
        // or cache across opens, so the fd returns the snapshot's real bytes and EOF.
        // Constant files take the default cached path (mmap-able).
        let fopen = if file.direct_io {
            fuser::FopenFlags::FOPEN_DIRECT_IO
        } else {
            fuser::FopenFlags::empty()
        };
        reply.opened(FileHandle(opened.fh), fopen);
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
        match self.snapshots.read_slice(fh.0, offset, size) {
            Some(slice) => reply.data(&slice),
            None => reply.error(Errno::EBADF),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        // A read-only filesystem has nothing to flush; just return ok to avoid the default ENOSYS warning noise.
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
        if let Some(info) = self.snapshots.remove(fh.0) {
            let path = self
                .tree
                .get(info.ino)
                .map(|n| n.virtual_path())
                .unwrap_or_default();
            tracing::debug!(path = %path, fh = fh.0, bytes = info.bytes_served, "close");
            self.audit.log_close(
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
pub fn mount(cfg: ResolvedConfig) -> anyhow::Result<()> {
    let audit = Arc::new(AuditLog::open(&cfg.audit_log)?);
    let mount_point = cfg.mount_path.clone();
    let config = mount_config(&cfg.volname);
    // Initial step: monitor mode (allow everything, audit only). Later swapped for the agent's policy engine.
    let authorizer: Arc<dyn Authorizer> = Arc::new(AllowAll);
    let fs = AccessFs::new(&cfg, audit, authorizer);

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
