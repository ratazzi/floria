//! Process-scoped read snapshots layered over macFUSE's vnode-scoped file handles.
//!
//! macFUSE may reuse one FUSE `fh` for POSIX opens from several processes while any process
//! still holds the vnode open. `open()` therefore cannot be the complete authorization boundary.
//! This table keeps the snapshot created by the observable FUSE open as the base session and
//! lazily creates one isolated snapshot for every other process lifetime observed at `read()`.

use std::sync::{Arc, OnceLock};

use accessfs_core::identity::{ProcessIdentity, ProcessInstance};
use accessfs_core::snapshot::{ClosedInfo, OpenedInfo, SnapshotTable};
use dashmap::DashMap;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadSessionError {
    BadHandle,
    Generate(i32),
}

pub enum ExistingRead {
    Hit(Vec<u8>),
    Missing,
    BadHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ReaderKey {
    fh: u64,
    process: ProcessInstance,
}

struct ReaderSnapshot {
    bytes: Zeroizing<Vec<u8>>,
}

impl ReaderSnapshot {
    fn read_slice(&self, offset: u64, size: u32) -> Vec<u8> {
        let start = (offset as usize).min(self.bytes.len());
        let end = start.saturating_add(size as usize).min(self.bytes.len());
        self.bytes[start..end].to_vec()
    }
}

type ReaderSlot = OnceLock<Result<ReaderSnapshot, i32>>;

/// One coherent interface for reads, hiding macFUSE handle reuse and concurrent first reads.
pub struct ReadSessionTable {
    base: SnapshotTable,
    readers: DashMap<ReaderKey, Arc<ReaderSlot>>,
}

impl ReadSessionTable {
    pub fn new() -> Self {
        Self {
            base: SnapshotTable::new(),
            readers: DashMap::new(),
        }
    }

    pub fn insert(
        &self,
        ino: u64,
        identity: Arc<ProcessIdentity>,
        bytes: Vec<u8>,
    ) -> OpenedInfo {
        self.base.insert(ino, identity, bytes)
    }

    /// Fast path used directly from the FUSE event loop. It never authorizes, generates, or
    /// waits for another thread: a missing process session is returned to the caller for pool
    /// dispatch.
    pub fn read_existing(
        &self,
        fh: u64,
        process: ProcessInstance,
        offset: u64,
        size: u32,
    ) -> ExistingRead {
        let Some(base_identity) = self.base.get_identity(fh) else {
            return ExistingRead::BadHandle;
        };
        if base_identity.instance() == process {
            return self
                .base
                .read_slice(fh, offset, size)
                .map_or(ExistingRead::BadHandle, ExistingRead::Hit);
        }
        self.read_existing_secondary(fh, process, offset, size)
    }

    pub fn read_existing_secondary(
        &self,
        fh: u64,
        process: ProcessInstance,
        offset: u64,
        size: u32,
    ) -> ExistingRead {
        let key = ReaderKey { fh, process };
        let Some(slot) = self.readers.get(&key) else {
            return ExistingRead::Missing;
        };
        match slot.get() {
            Some(Ok(snapshot)) => ExistingRead::Hit(snapshot.read_slice(offset, size)),
            // An in-flight creator is allowed to continue on the pool. The caller dispatches
            // and joins it through `read_secondary` rather than blocking the event loop here.
            Some(Err(_)) | None => ExistingRead::Missing,
        }
    }

    /// Read the snapshot belonging to `identity`, creating it exactly once for a process that
    /// did not receive the original FUSE open callback. Failed creation is not cached, so a
    /// later access can prompt again after a one-time denial or transient generation failure.
    pub fn read_or_create<F>(
        &self,
        fh: u64,
        identity: &ProcessIdentity,
        offset: u64,
        size: u32,
        create: F,
    ) -> Result<Vec<u8>, ReadSessionError>
    where
        F: FnOnce() -> Result<Vec<u8>, i32>,
    {
        let base_identity = self
            .base
            .get_identity(fh)
            .ok_or(ReadSessionError::BadHandle)?;
        if base_identity.instance() == identity.instance() {
            return self
                .base
                .read_slice(fh, offset, size)
                .ok_or(ReadSessionError::BadHandle);
        }

        self.read_secondary(fh, identity, offset, size, create)
    }

    /// Create a process-scoped committed snapshot when the kernel attached a reader to a FUSE
    /// handle originally opened for writing. The writer's in-memory buffer is never exposed.
    pub fn read_secondary<F>(
        &self,
        fh: u64,
        identity: &ProcessIdentity,
        offset: u64,
        size: u32,
        create: F,
    ) -> Result<Vec<u8>, ReadSessionError>
    where
        F: FnOnce() -> Result<Vec<u8>, i32>,
    {
        let key = ReaderKey {
            fh,
            process: identity.instance(),
        };
        let slot = Arc::clone(
            self.readers
                .entry(key)
                .or_insert_with(|| Arc::new(OnceLock::new()))
                .value(),
        );
        let initialized = slot.get_or_init(|| {
            create().map(|bytes| ReaderSnapshot {
                bytes: Zeroizing::new(bytes),
            })
        });
        match initialized {
            Ok(snapshot) => Ok(snapshot.read_slice(offset, size)),
            Err(code) => {
                self.readers
                    .remove_if(&key, |_, current| Arc::ptr_eq(current, &slot));
                Err(ReadSessionError::Generate(*code))
            }
        }
    }

    pub fn remove(&self, fh: u64) -> Option<ClosedInfo> {
        self.readers.retain(|key, _| key.fh != fh);
        self.base.remove(fh)
    }
}

impl Default for ReadSessionTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn identity(pid: i32, started_at_micros: u64) -> Arc<ProcessIdentity> {
        let mut identity = ProcessIdentity::bare(pid, 501, 20);
        identity.started_at_micros = Some(started_at_micros);
        Arc::new(identity)
    }

    #[test]
    fn base_process_reads_open_snapshot_without_regeneration() {
        let table = ReadSessionTable::new();
        let opener = identity(10, 100);
        let fh = table.insert(2, Arc::clone(&opener), b"base".to_vec()).fh;
        assert_ne!(
            fh, 0,
            "FUSE fh zero is reserved as the no-handle sentinel"
        );

        let bytes = table
            .read_or_create(fh, &opener, 0, 20, || panic!("base snapshot regenerated"))
            .unwrap();

        assert_eq!(bytes, b"base");
    }

    #[test]
    fn reused_fh_gets_one_snapshot_per_process_lifetime() {
        let table = ReadSessionTable::new();
        let opener = identity(10, 100);
        let other = identity(11, 200);
        let fh = table.insert(2, opener, b"base".to_vec()).fh;
        let calls = AtomicUsize::new(0);

        let first = table
            .read_or_create(fh, &other, 0, 20, || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(b"other".to_vec())
            })
            .unwrap();
        let second = table
            .read_or_create(fh, &other, 1, 3, || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(b"wrong".to_vec())
            })
            .unwrap();

        assert_eq!(first, b"other");
        assert_eq!(second, b"the");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pid_reuse_does_not_inherit_an_authorized_snapshot() {
        let table = ReadSessionTable::new();
        let opener = identity(10, 100);
        let reused_pid = identity(10, 101);
        let fh = table.insert(2, opener, b"old process".to_vec()).fh;

        let bytes = table
            .read_or_create(fh, &reused_pid, 0, 20, || Ok(b"new process".to_vec()))
            .unwrap();

        assert_eq!(bytes, b"new process");
    }

    #[test]
    fn failed_creation_can_be_retried() {
        let table = ReadSessionTable::new();
        let opener = identity(10, 100);
        let other = identity(11, 200);
        let fh = table.insert(2, opener, b"base".to_vec()).fh;

        assert_eq!(
            table.read_or_create(fh, &other, 0, 20, || Err(libc::EACCES)),
            Err(ReadSessionError::Generate(libc::EACCES))
        );
        assert_eq!(
            table
                .read_or_create(fh, &other, 0, 20, || Ok(b"allowed later".to_vec()))
                .unwrap(),
            b"allowed later"
        );
    }

    #[test]
    fn fast_path_distinguishes_hit_missing_and_bad_handle() {
        let table = ReadSessionTable::new();
        let opener = identity(10, 100);
        let other = identity(11, 200);
        let fh = table.insert(2, Arc::clone(&opener), b"base".to_vec()).fh;

        assert!(matches!(
            table.read_existing(fh, opener.instance(), 0, 20),
            ExistingRead::Hit(bytes) if bytes == b"base"
        ));
        assert!(matches!(
            table.read_existing(fh, other.instance(), 0, 20),
            ExistingRead::Missing
        ));
        assert!(matches!(
            table.read_existing(999, opener.instance(), 0, 20),
            ExistingRead::BadHandle
        ));
    }
}
