use std::path::PathBuf;

use serde::Serialize;

/// Identity profile of the reading process. Populated by `accessfs-platform::enrich` during `open()`.
///
/// `uid/gid/pid` come from the FUSE request; the rest come from libproc, best-effort, `None` on
/// failure. `open()` must never fail just because forensics collection failed.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub exe_path: Option<PathBuf>,
    /// For display only, not used in authorization decisions.
    pub cmdline: Option<Vec<String>>,
    pub cwd: Option<PathBuf>,
    /// Parent process chain from the reading process up to launchd (leaf-first).
    pub parent_chain: Vec<ProcSummary>,
    /// Only populated in P1 (SecCode/SecStaticCode).
    pub bundle_id: Option<String>,
    /// Only populated in P1.
    pub team_id: Option<String>,
}

impl ProcessIdentity {
    /// Minimal identity with only FUSE request info and no enrichment. Used as the fallback when enrich fails.
    pub fn bare(pid: i32, uid: u32, gid: u32) -> Self {
        ProcessIdentity {
            pid,
            uid,
            gid,
            exe_path: None,
            cmdline: None,
            cwd: None,
            parent_chain: Vec::new(),
            bundle_id: None,
            team_id: None,
        }
    }

    /// Concise process chain for log display, e.g. `login -> zsh -> node` (root-first).
    pub fn chain_display(&self) -> String {
        if self.parent_chain.is_empty() {
            return format!("pid={}", self.pid);
        }
        self.parent_chain
            .iter()
            .rev()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcSummary {
    pub pid: i32,
    pub ppid: i32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
}
