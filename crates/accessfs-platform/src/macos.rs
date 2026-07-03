use std::path::PathBuf;

use accessfs_core::identity::{ProcSummary, ProcessIdentity};
use libproc::bsd_info::BSDInfo;
use libproc::proc_pid::{self, pidinfo};

/// Maximum depth when walking up the parent chain; guards against cycles and anomalies.
const MAX_CHAIN_DEPTH: usize = 32;

pub fn enrich(pid: i32, uid: u32, gid: u32) -> ProcessIdentity {
    let exe_path = proc_pid::pidpath(pid).ok().map(PathBuf::from);
    if exe_path.is_none() {
        // Common in the macfuse#378 pid-vs-tid case: pidpath returns ESRCH for a tid.
        // Keep FUSE's uid/gid/pid and degrade the rest to empty.
        tracing::warn!(pid, "pidpath failed; process enrichment degraded");
    }

    ProcessIdentity {
        pid,
        uid,
        gid,
        exe_path,
        cmdline: cmdline(pid),
        cwd: cwd(pid),
        parent_chain: parent_chain(pid),
        bundle_id: None, // TODO(P1): SecCode / SecStaticCode enrichment
        team_id: None,   // TODO(P1)
    }
}

/// Walk ppid from `pid` all the way to launchd, returning a leaf-first process chain.
fn parent_chain(start: i32) -> Vec<ProcSummary> {
    let mut chain = Vec::new();
    let mut pid = start;
    for _ in 0..MAX_CHAIN_DEPTH {
        let Some(info) = bsd_info(pid) else { break };
        let ppid = info.pbi_ppid as i32;
        chain.push(ProcSummary {
            pid,
            ppid,
            name: proc_name(&info).unwrap_or_else(|| format!("pid:{pid}")),
            exe_path: proc_pid::pidpath(pid).ok().map(PathBuf::from),
        });
        if ppid == 0 || pid == 1 {
            break;
        }
        pid = ppid;
    }
    chain
}

fn bsd_info(pid: i32) -> Option<BSDInfo> {
    pidinfo::<BSDInfo>(pid, 0).ok()
}

/// Prefer the longer `pbi_name`; fall back to `pbi_comm` when it is empty.
fn proc_name(info: &BSDInfo) -> Option<String> {
    cstr_from_array(&info.pbi_name).or_else(|| cstr_from_array(&info.pbi_comm))
}

/// Get the current working directory via `proc_pidinfo(PROC_PIDVNODEPATHINFO)`. Across users it EPERMs, so return None.
fn cwd(pid: i32) -> Option<PathBuf> {
    // SAFETY: pass a correctly sized stack buffer and check the returned byte count.
    unsafe {
        let mut vpi: libc::proc_vnodepathinfo = std::mem::zeroed();
        let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
        let n = libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut vpi as *mut _ as *mut libc::c_void,
            size,
        );
        if n < size {
            return None;
        }
        // In some libc versions vip_path is a 2D array [[c_char; 32]; 32]; read it as flat bytes.
        let path = &vpi.pvi_cdir.vip_path;
        cstr_from_raw(
            path.as_ptr() as *const libc::c_char,
            std::mem::size_of_val(path),
        )
        .map(PathBuf::from)
    }
}

/// Get the command line via `sysctl(KERN_PROCARGS2)`. For display only.
fn cmdline(pid: i32) -> Option<Vec<String>> {
    let raw = proc_args2(pid)?;
    if raw.len() < std::mem::size_of::<libc::c_int>() {
        return None;
    }

    // Layout: [argc: c_int][exec_path\0][alignment \0...][argv0\0 argv1\0 ...][env...]
    let argc = i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if argc <= 0 {
        return None;
    }
    let mut cursor = std::mem::size_of::<libc::c_int>();

    // Skip the saved exec_path and the alignment NULs that follow it.
    while cursor < raw.len() && raw[cursor] != 0 {
        cursor += 1;
    }
    while cursor < raw.len() && raw[cursor] == 0 {
        cursor += 1;
    }

    let mut args = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        if cursor >= raw.len() {
            break;
        }
        let start = cursor;
        while cursor < raw.len() && raw[cursor] != 0 {
            cursor += 1;
        }
        args.push(String::from_utf8_lossy(&raw[start..cursor]).into_owned());
        cursor += 1; // skip the separating NUL
    }

    (!args.is_empty()).then_some(args)
}

/// Raw `sysctl [CTL_KERN, KERN_PROCARGS2, pid]`, returning the byte buffer the kernel fills in.
fn proc_args2(pid: i32) -> Option<Vec<u8>> {
    // SAFETY: standard two-step sysctl call: ask for the size first, then fetch the data.
    unsafe {
        let mut mib: [libc::c_int; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut size: libc::size_t = 0;
        let rc = libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if rc != 0 || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size];
        let rc = libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if rc != 0 {
            return None;
        }
        buf.truncate(size);
        Some(buf)
    }
}

/// Truncate a fixed-length `[c_char; N]` array at the first NUL into a String; None if empty.
fn cstr_from_array(buf: &[libc::c_char]) -> Option<String> {
    // SAFETY: pass a valid fixed-length array pointer and length.
    unsafe { cstr_from_raw(buf.as_ptr(), buf.len()) }
}

/// Truncate a raw C char buffer (possibly a flat view of a multidimensional array) at the first NUL into a String.
///
/// # Safety
/// `ptr` must point to at least `len` bytes of valid memory.
unsafe fn cstr_from_raw(ptr: *const libc::c_char, len: usize) -> Option<String> {
    let bytes: &[u8] = std::slice::from_raw_parts(ptr as *const u8, len);
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify forensics works against our own process (no macFUSE needed).
    #[test]
    fn enriches_self() {
        let pid = std::process::id() as i32;
        let id = enrich(pid, 0, 0);
        assert_eq!(id.pid, pid);
        // The current process must always resolve exe and cwd.
        assert!(id.exe_path.is_some(), "exe_path should resolve for self");
        assert!(id.cwd.is_some(), "cwd should resolve for self");
        // The chain contains at least ourselves, and adjacent entries must connect (prev.ppid == next.pid).
        assert!(!id.parent_chain.is_empty());
        assert_eq!(id.parent_chain[0].pid, pid);
        for pair in id.parent_chain.windows(2) {
            assert_eq!(pair[0].ppid, pair[1].pid, "chain links must connect");
        }
    }

    #[test]
    fn cmdline_of_self_has_test_binary() {
        let pid = std::process::id() as i32;
        let args = cmdline(pid).expect("cmdline for self");
        assert!(!args.is_empty());
    }
}
