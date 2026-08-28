use std::path::PathBuf;

use floria_core::identity::{ProcSummary, ProcessIdentity, ProcessInstance};
use libproc::bsd_info::BSDInfo;
use libproc::proc_pid::{self, pidinfo};

/// Maximum depth when walking up the parent chain; guards against cycles and anomalies.
const MAX_CHAIN_DEPTH: usize = 32;

// `libproc` exposes PROC_PIDTBSDINFO but not the less privileged short BSD flavor. Keep this
// definition in sync with <sys/proc_info.h>; the layout is stable across supported macOS releases.
const PROC_PIDT_SHORTBSDINFO: libc::c_int = 13;
const MAXCOMLEN: usize = 16;

#[repr(C)]
struct ProcBsdShortInfo {
    pid: u32,
    ppid: u32,
    pgid: u32,
    status: u32,
    comm: [libc::c_char; MAXCOMLEN],
    flags: u32,
    uid: libc::uid_t,
    gid: libc::gid_t,
    ruid: libc::uid_t,
    rgid: libc::gid_t,
    svuid: libc::uid_t,
    svgid: libc::gid_t,
    reserved: u32,
}

pub fn enrich(pid: i32, uid: u32, gid: u32) -> ProcessIdentity {
    let started_at_micros = process_start_micros(pid);
    let exe_path = proc_pid::pidpath(pid).ok().map(PathBuf::from);
    if exe_path.is_none() {
        // Common in the macfuse#378 pid-vs-tid case: pidpath returns ESRCH for a tid.
        // Keep FUSE's uid/gid/pid and degrade the rest to empty.
        tracing::warn!(pid, "pidpath failed; process enrichment degraded");
    }

    let sig = crate::codesign::code_signature(pid);
    ProcessIdentity {
        pid,
        started_at_micros,
        uid,
        gid,
        exe_path,
        cmdline: cmdline(pid),
        cwd: cwd(pid),
        parent_chain: parent_chain(pid),
        bundle_id: sig.bundle_id,
        team_id: sig.team_id,
    }
}

pub fn process_instance(pid: i32) -> ProcessInstance {
    ProcessInstance {
        pid,
        started_at_micros: process_start_micros(pid),
    }
}

fn process_start_micros(pid: i32) -> Option<u64> {
    let info = bsd_info(pid)?;
    Some(
        info.pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
    )
}

/// Walk ppid from `pid` all the way to launchd, returning a leaf-first process chain.
fn parent_chain(start: i32) -> Vec<ProcSummary> {
    let mut chain = Vec::new();
    let mut pid = start;
    for _ in 0..MAX_CHAIN_DEPTH {
        let Some(process) = process_summary(pid) else {
            break;
        };
        let ppid = process.ppid;
        chain.push(process);
        if ppid == 0 || pid == 1 {
            break;
        }
        pid = ppid;
    }
    chain
}

fn process_summary(pid: i32) -> Option<ProcSummary> {
    let exe_path = proc_pid::pidpath(pid).ok().map(PathBuf::from);
    let (ppid, name) = match bsd_info(pid) {
        Some(info) => (info.pbi_ppid as i32, proc_name(&info)),
        // A terminal's root-owned `login` process rejects PROC_PIDTBSDINFO with EPERM. The
        // deliberately smaller PROC_PIDT_SHORTBSDINFO flavor remains readable and carries the
        // parent relationship needed to reach the user-owned terminal application above it.
        None => short_bsd_info(pid)?,
    };
    let name = name
        .or_else(|| {
            exe_path
                .as_deref()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| format!("pid:{pid}"));
    Some(ProcSummary {
        pid,
        ppid,
        name,
        exe_path,
    })
}

fn bsd_info(pid: i32) -> Option<BSDInfo> {
    pidinfo::<BSDInfo>(pid, 0).ok()
}

/// Read display-only ancestry through libproc's short BSD flavor when richer metadata is denied.
fn short_bsd_info(pid: i32) -> Option<(i32, Option<String>)> {
    // SAFETY: ProcBsdShortInfo mirrors the public proc_bsdshortinfo layout, and the result is
    // accepted only when proc_pidinfo fills the complete structure.
    unsafe {
        let mut info: ProcBsdShortInfo = std::mem::zeroed();
        let size = std::mem::size_of::<ProcBsdShortInfo>() as libc::c_int;
        let written = libc::proc_pidinfo(
            pid,
            PROC_PIDT_SHORTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        );
        if written < size {
            return None;
        }
        Some((info.ppid as i32, cstr_from_array(&info.comm)))
    }
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
        assert!(id.started_at_micros.is_some(), "process start should resolve for self");
        assert_eq!(id.instance(), process_instance(pid));
        // The current process must always resolve exe and cwd.
        assert!(id.exe_path.is_some(), "exe_path should resolve for self");
        assert!(id.cwd.is_some(), "cwd should resolve for self");
        // The chain contains at least ourselves, and adjacent entries must connect (prev.ppid == next.pid).
        assert!(!id.parent_chain.is_empty());
        assert_eq!(id.parent_chain[0].pid, pid);
        for pair in id.parent_chain.windows(2) {
            assert_eq!(pair[0].ppid, pair[1].pid, "chain links must connect");
        }
        assert_eq!(
            id.parent_chain.last().map(|process| process.pid),
            Some(1),
            "the fallback should carry ancestry through protected processes to launchd"
        );
    }

    #[test]
    fn short_bsd_info_reports_protected_launchd() {
        assert_eq!(short_bsd_info(1).map(|info| info.0), Some(0));
        let launchd = process_summary(1).expect("launchd should remain displayable");
        assert_eq!(launchd.ppid, 0);
        assert_eq!(launchd.name, "launchd");
    }

    #[test]
    fn cmdline_of_self_has_test_binary() {
        let pid = std::process::id() as i32;
        let args = cmdline(pid).expect("cmdline for self");
        assert!(!args.is_empty());
    }
}
