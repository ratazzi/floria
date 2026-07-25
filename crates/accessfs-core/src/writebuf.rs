//! Per-open write buffers for store-backed secrets.
//!
//! A write-open gets a whole-file in-memory buffer ([`Zeroizing`], secrets are small): `write`
//! and truncate mutate the buffer only; the commit (encrypt + append an immutable version)
//! happens at `flush`/`release`. Every committed close is a new version, so concurrent writers
//! never destroy each other — each commit appends, the last one becomes the head.
//!
//! Write fhs live in their own numeric range ([`WRITE_FH_BASE`]) so they can share the
//! `read`/`flush`/`release` callbacks with read snapshots without colliding.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;
use zeroize::Zeroizing;

use crate::identity::{ProcessIdentity, ProcessInstance};

/// First fh handed out for write-opens. Read snapshots allocate from 1 upward and will never
/// reach this, so `fh >= WRITE_FH_BASE` unambiguously identifies a write fd.
pub const WRITE_FH_BASE: u64 = 1 << 32;

/// Hard cap on a single write buffer. Secrets are small files; anything larger is a runaway
/// writer, refused with EFBIG rather than ballooning daemon memory.
pub const MAX_WRITE_BYTES: u64 = 16 * 1024 * 1024;

/// State of one write-open fd. Created on `open()` for write, consumed on `release()`.
struct WriteState {
    ino: u64,
    identity: Arc<ProcessIdentity>,
    buf: Zeroizing<Vec<u8>>,
    /// Set by any mutation; cleared when a commit snapshot is taken.
    dirty: bool,
    /// Serializes commits for this fh: fsync/flush/release can overlap on pool threads, and
    /// unserialized commits could append an older snapshot *after* a newer one, moving the
    /// store head backwards. Held across take-snapshot → store-append → (mark-dirty on error).
    /// `Arc` so the guard outlives the map reference (never lock while holding a shard).
    commit_lock: Arc<Mutex<()>>,
    opened_at: Instant,
}

/// `fh -> WriteState` table (interior-mutable: fuser callbacks take `&self`).
#[derive(Default)]
pub struct WriteBufTable {
    next_fh: AtomicU64,
    open: DashMap<u64, WriteState>,
}

/// Why a buffer mutation was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum WriteErr {
    /// fh unknown (not a write fd).
    BadHandle,
    /// Would exceed [`MAX_WRITE_BYTES`].
    TooBig,
}

impl WriteBufTable {
    pub fn new() -> Self {
        WriteBufTable {
            next_fh: AtomicU64::new(WRITE_FH_BASE),
            open: DashMap::new(),
        }
    }

    /// Whether this fh belongs to the write table (cheap range check, no lookup).
    pub fn owns(&self, fh: u64) -> bool {
        fh >= WRITE_FH_BASE
    }

    /// Start a write session seeded with `initial` (the decrypted head, or empty on O_TRUNC).
    /// The session starts clean: closing without writing commits nothing.
    pub fn insert(&self, ino: u64, identity: Arc<ProcessIdentity>, initial: Vec<u8>) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.open.insert(
            fh,
            WriteState {
                ino,
                identity,
                buf: Zeroizing::new(initial),
                dirty: false,
                commit_lock: Arc::new(Mutex::new(())),
                opened_at: Instant::now(),
            },
        );
        fh
    }

    /// Write `data` at `offset`, zero-filling any gap (sparse writes land as zeros).
    /// Returns the number of bytes written.
    pub fn write_at(&self, fh: u64, offset: u64, data: &[u8]) -> Result<u32, WriteErr> {
        let mut state = self.open.get_mut(&fh).ok_or(WriteErr::BadHandle)?;
        let end = offset.saturating_add(data.len() as u64);
        if end > MAX_WRITE_BYTES {
            return Err(WriteErr::TooBig);
        }
        let (offset, end) = (offset as usize, end as usize);
        if state.buf.len() < end {
            state.buf.resize(end, 0);
        }
        state.buf[offset..end].copy_from_slice(data);
        state.dirty = true;
        Ok(data.len() as u32)
    }

    /// Truncate (or zero-extend) the buffer to `size`.
    pub fn truncate(&self, fh: u64, size: u64) -> Result<(), WriteErr> {
        if size > MAX_WRITE_BYTES {
            return Err(WriteErr::TooBig);
        }
        let mut state = self.open.get_mut(&fh).ok_or(WriteErr::BadHandle)?;
        state.buf.resize(size as usize, 0);
        state.dirty = true;
        Ok(())
    }

    /// Read back a slice of the buffer (O_RDWR readers see their own uncommitted writes).
    pub fn read_slice(&self, fh: u64, offset: u64, size: u32) -> Option<Vec<u8>> {
        let state = self.open.get(&fh)?;
        let bytes: &[u8] = &state.buf;
        let start = (offset as usize).min(bytes.len());
        let end = start.saturating_add(size as usize).min(bytes.len());
        Some(bytes[start..end].to_vec())
    }

    /// Current buffer length (for fstat on a write fd).
    pub fn len(&self, fh: u64) -> Option<u64> {
        self.open.get(&fh).map(|s| s.buf.len() as u64)
    }

    /// The commit-serialization lock for this fh. The caller MUST hold it across the whole
    /// commit (take_dirty → store append → mark_dirty on failure): it orders concurrent
    /// fsync/flush/release commits so an older snapshot can never land after a newer one,
    /// and it makes release wait out any in-flight commit before tearing the state down.
    pub fn commit_guard(&self, fh: u64) -> Option<Arc<Mutex<()>>> {
        self.open.get(&fh).map(|s| Arc::clone(&s.commit_lock))
    }

    /// Take a commit snapshot if the buffer is dirty, clearing the flag. `None` means nothing
    /// to commit. If the commit fails, call [`mark_dirty`](Self::mark_dirty) so release retries.
    /// Call with the [`commit_guard`](Self::commit_guard) held.
    pub fn take_dirty(&self, fh: u64) -> Option<Zeroizing<Vec<u8>>> {
        let mut state = self.open.get_mut(&fh)?;
        if !state.dirty {
            return None;
        }
        state.dirty = false;
        Some(Zeroizing::new(state.buf.to_vec()))
    }

    /// Re-arm the dirty flag after a failed commit attempt.
    pub fn mark_dirty(&self, fh: u64) {
        if let Some(mut state) = self.open.get_mut(&fh) {
            state.dirty = true;
        }
    }

    pub fn get_identity(&self, fh: u64) -> Option<Arc<ProcessIdentity>> {
        self.open.get(&fh).map(|s| Arc::clone(&s.identity))
    }

    /// Whether this request comes from the process lifetime that opened the write session.
    /// macFUSE may attach another process to the same vnode-level fh without another `open()`.
    pub fn is_owner(&self, fh: u64, process: ProcessInstance) -> bool {
        self.open
            .get(&fh)
            .is_some_and(|state| state.identity.instance() == process)
    }

    pub fn ino_of(&self, fh: u64) -> Option<u64> {
        self.open.get(&fh).map(|s| s.ino)
    }

    /// End the session (called on release). Returns final state for the last-chance commit
    /// and the close audit record; the buffer zeroes on drop.
    pub fn remove(&self, fh: u64) -> Option<ClosedWrite> {
        let (_, state) = self.open.remove(&fh)?;
        Some(ClosedWrite {
            ino: state.ino,
            identity: state.identity,
            dirty_bytes: state.dirty.then(|| Zeroizing::new(state.buf.to_vec())),
            size: state.buf.len() as u64,
            duration: state.opened_at.elapsed(),
        })
    }
}

/// Final state of a write session, for release-time commit + auditing.
pub struct ClosedWrite {
    pub ino: u64,
    pub identity: Arc<ProcessIdentity>,
    /// Uncommitted content, present only if the buffer is still dirty (flush already committed
    /// the common case; this is the fallback).
    pub dirty_bytes: Option<Zeroizing<Vec<u8>>>,
    pub size: u64,
    pub duration: std::time::Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> Arc<ProcessIdentity> {
        Arc::new(ProcessIdentity::bare(123, 501, 20))
    }

    #[test]
    fn write_read_roundtrip_with_gap_zero_fill() {
        let t = WriteBufTable::new();
        let fh = t.insert(2, ident(), Vec::new());
        assert!(t.owns(fh));
        assert_eq!(t.write_at(fh, 0, b"hello").unwrap(), 5);
        assert_eq!(t.write_at(fh, 7, b"world").unwrap(), 5);
        assert_eq!(t.read_slice(fh, 0, 100).unwrap(), b"hello\0\0world");
        assert_eq!(t.len(fh), Some(12));
    }

    #[test]
    fn starts_clean_dirty_after_write_clean_after_take() {
        let t = WriteBufTable::new();
        let fh = t.insert(2, ident(), b"seed".to_vec());
        assert!(t.take_dirty(fh).is_none()); // open + close without writing commits nothing
        t.write_at(fh, 4, b"!").unwrap();
        assert_eq!(t.take_dirty(fh).unwrap().as_slice(), b"seed!");
        assert!(t.take_dirty(fh).is_none()); // double flush doesn't double-commit
        t.mark_dirty(fh); // failed commit re-arms
        assert!(t.take_dirty(fh).is_some());
    }

    #[test]
    fn truncate_marks_dirty_even_to_same_content() {
        let t = WriteBufTable::new();
        let fh = t.insert(2, ident(), b"secret".to_vec());
        t.truncate(fh, 0).unwrap(); // `> file` with no write commits an empty version
        let taken = t.take_dirty(fh).unwrap();
        assert!(taken.is_empty());
    }

    #[test]
    fn remove_carries_uncommitted_bytes_only_when_dirty() {
        let t = WriteBufTable::new();
        let fh = t.insert(2, ident(), Vec::new());
        t.write_at(fh, 0, b"data").unwrap();
        let closed = t.remove(fh).unwrap();
        assert_eq!(closed.dirty_bytes.unwrap().as_slice(), b"data");

        let fh = t.insert(2, ident(), b"x".to_vec());
        let _ = t.take_dirty(fh); // clean
        let closed = t.remove(fh).unwrap();
        assert!(closed.dirty_bytes.is_none());
        assert!(t.read_slice(fh, 0, 1).is_none());
    }

    #[test]
    fn size_cap_is_enforced() {
        let t = WriteBufTable::new();
        let fh = t.insert(2, ident(), Vec::new());
        assert_eq!(t.write_at(fh, MAX_WRITE_BYTES, b"x"), Err(WriteErr::TooBig));
        assert_eq!(t.truncate(fh, MAX_WRITE_BYTES + 1), Err(WriteErr::TooBig));
        assert_eq!(t.write_at(999, 0, b"x"), Err(WriteErr::BadHandle));
    }

    #[test]
    fn writer_ownership_includes_process_start_to_reject_pid_reuse() {
        let t = WriteBufTable::new();
        let mut owner = ProcessIdentity::bare(123, 501, 20);
        owner.started_at_micros = Some(100);
        let fh = t.insert(2, Arc::new(owner), Vec::new());

        assert!(t.is_owner(
            fh,
            ProcessInstance { pid: 123, started_at_micros: Some(100) }
        ));
        assert!(!t.is_owner(
            fh,
            ProcessInstance { pid: 123, started_at_micros: Some(101) }
        ));
        assert!(!t.is_owner(
            fh,
            ProcessInstance { pid: 124, started_at_micros: Some(100) }
        ));
    }
}
