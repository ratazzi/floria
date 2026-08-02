//! Platform-specific process identity forensics. macOS uses libproc + sysctl.
//!
//! The only public entry point is [`enrich`]: given the pid/uid/gid from a FUSE
//! request, it best-effort fills in exe/cmdline/cwd/parent chain and returns a
//! [`ProcessIdentity`]. Any individual failure just leaves that field `None`;
//! it never panics and never blocks the caller's `open()`.

use floria_core::identity::{ProcessIdentity, ProcessInstance};

#[cfg(target_os = "macos")]
mod codesign;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod peer;

#[cfg(target_os = "macos")]
pub use peer::{
    CodeSignedPeerVerifier, PeerAccess, PeerPolicyError, PeerVerificationError,
    SameUserPeerVerifier, SocketPeerVerifier, VerifiedPeer,
};

/// Enrich the process identity. `uid/gid/pid` come from the FUSE request; the rest relies on platform forensics.
#[cfg(target_os = "macos")]
pub fn enrich(pid: i32, uid: u32, gid: u32) -> ProcessIdentity {
    macos::enrich(pid, uid, gid)
}

/// Return the lightweight process-lifetime key used by FUSE callback ownership checks.
#[cfg(target_os = "macos")]
pub fn process_instance(pid: i32) -> ProcessInstance {
    macos::process_instance(pid)
}

/// Fallback for non-macOS platforms: return only the pid/uid/gid known to FUSE.
#[cfg(not(target_os = "macos"))]
pub fn enrich(pid: i32, uid: u32, gid: u32) -> ProcessIdentity {
    ProcessIdentity::bare(pid, uid, gid)
}

#[cfg(not(target_os = "macos"))]
pub fn process_instance(pid: i32) -> ProcessInstance {
    ProcessInstance {
        pid,
        started_at_micros: None,
    }
}
