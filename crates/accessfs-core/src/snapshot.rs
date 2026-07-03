use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::identity::ProcessIdentity;

/// Frozen state for a single open fd. Created on `open()`, destroyed on `release()`.
pub struct OpenState {
    pub ino: u64,
    pub identity: Arc<ProcessIdentity>,
    /// Snapshot bytes for this open, zeroed on drop.
    pub bytes: Arc<Zeroizing<Vec<u8>>>,
    pub opened_at: Instant,
    /// sha256 of the content, for audit only (never logs plaintext).
    pub content_hash: [u8; 32],
}

impl OpenState {
    pub fn content_version(&self) -> String {
        let mut s = String::from("sha256:");
        for b in &self.content_hash {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

/// `fh -> OpenState` table. Because fuser 0.17 callbacks take `&self`, an interior-mutable concurrent container is required.
#[derive(Default)]
pub struct SnapshotTable {
    next_fh: AtomicU64,
    open: DashMap<u64, OpenState>,
}

impl SnapshotTable {
    pub fn new() -> Self {
        SnapshotTable {
            // fh starts at 1; 0 is reserved as the "no fh" sentinel (e.g. opendir).
            next_fh: AtomicU64::new(1),
            open: DashMap::new(),
        }
    }

    /// Freeze a snapshot, returning the allocated fh and the metadata needed for auditing. Each open gets its own fh and its own bytes.
    pub fn insert(
        &self,
        ino: u64,
        identity: Arc<ProcessIdentity>,
        bytes: Vec<u8>,
    ) -> OpenedInfo {
        let content_hash: [u8; 32] = Sha256::digest(&bytes).into();
        let size = bytes.len() as u64;
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        let state = OpenState {
            ino,
            identity,
            bytes: Arc::new(Zeroizing::new(bytes)),
            opened_at: Instant::now(),
            content_hash,
        };
        let content_version = state.content_version();
        self.open.insert(fh, state);
        OpenedInfo {
            fh,
            content_version,
            size,
        }
    }

    /// Read the `[offset, offset+size)` slice of an fh's snapshot (clamped to bounds, empty past EOF).
    pub fn read_slice(&self, fh: u64, offset: u64, size: u32) -> Option<Vec<u8>> {
        let state = self.open.get(&fh)?;
        let bytes: &[u8] = state.bytes.as_ref();
        let start = (offset as usize).min(bytes.len());
        let end = start.saturating_add(size as usize).min(bytes.len());
        Some(bytes[start..end].to_vec())
    }

    /// Take and remove an fh (called on release). Returns `(ino, content version, byte count, open duration)` for auditing.
    pub fn remove(&self, fh: u64) -> Option<ClosedInfo> {
        let (_, state) = self.open.remove(&fh)?;
        Some(ClosedInfo {
            ino: state.ino,
            content_version: state.content_version(),
            bytes_served: state.bytes.len() as u64,
            duration: state.opened_at.elapsed(),
        })
    }

    pub fn get_identity(&self, fh: u64) -> Option<Arc<ProcessIdentity>> {
        self.open.get(&fh).map(|s| Arc::clone(&s.identity))
    }
}

/// Metadata returned to the caller for auditing after a successful `open()`.
pub struct OpenedInfo {
    pub fh: u64,
    pub content_version: String,
    pub size: u64,
}

pub struct ClosedInfo {
    pub ino: u64,
    pub content_version: String,
    pub bytes_served: u64,
    pub duration: std::time::Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> Arc<ProcessIdentity> {
        Arc::new(ProcessIdentity::bare(123, 501, 20))
    }

    #[test]
    fn each_open_gets_distinct_fh() {
        let table = SnapshotTable::new();
        let a = table.insert(2, ident(), b"hello".to_vec());
        let b = table.insert(2, ident(), b"hello".to_vec());
        assert_ne!(a.fh, b.fh);
    }

    #[test]
    fn read_slice_is_consistent_and_bounded() {
        let table = SnapshotTable::new();
        let fh = table.insert(2, ident(), b"hello world".to_vec()).fh;
        assert_eq!(table.read_slice(fh, 0, 5).unwrap(), b"hello");
        assert_eq!(table.read_slice(fh, 0, 5).unwrap(), b"hello");
        assert_eq!(table.read_slice(fh, 6, 100).unwrap(), b"world");
        assert_eq!(table.read_slice(fh, 100, 10).unwrap(), b"");
    }

    #[test]
    fn remove_reports_and_frees() {
        let table = SnapshotTable::new();
        let opened = table.insert(2, ident(), b"abc".to_vec());
        assert!(opened.content_version.starts_with("sha256:"));
        let info = table.remove(opened.fh).unwrap();
        assert_eq!(info.bytes_served, 3);
        assert!(table.read_slice(opened.fh, 0, 3).is_none());
    }
}
