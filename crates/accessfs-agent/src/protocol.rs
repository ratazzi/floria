//! Wire protocol between the daemon (server) and the menubar app (client).
//!
//! Framing: a 4-byte big-endian length prefix followed by that many bytes of JSON.
//! The Swift side mirrors these message shapes.

use std::io::{self, Read, Write};

use accessfs_core::identity::ProcessIdentity;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Reject frames larger than this to bound memory on a hostile/broken peer.
const MAX_MSG: usize = 1 << 20;

/// Messages the app (client) sends to the daemon.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Handshake sent by the app right after connecting.
    Hello { version: u32 },
    /// The user's answer to a prompt.
    Decision {
        req_id: u64,
        /// "allow" | "deny"
        outcome: String,
        /// "once" | "ttl" | "app_file" | "app_project"
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
}

/// Messages the daemon (server) sends to the app.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMsg<'a> {
    /// A blocking authorization request: the app must reply with a `decision`.
    Prompt {
        req_id: u64,
        path: &'a str,
        /// Human-facing name (a secret's original source path); `path` stays the rule key.
        display: Option<&'a str>,
        operation: &'a str,
        enforcement: &'a str,
        identity: IdentityView,
    },
    /// A fire-and-forget record of an access, for the app's "recent access" UI.
    AccessEvent {
        ts: String,
        path: &'a str,
        /// Human-facing name (a secret's original source path); `path` stays the rule key.
        display: Option<&'a str>,
        /// `read` or `write` — with a writable mount, "allowed" alone is ambiguous.
        operation: &'a str,
        decision: &'a str,
        rule_id: Option<&'a str>,
        identity: IdentityView,
    },
}

/// The reader identity as shown to the app (display-only projection of [`ProcessIdentity`]).
#[derive(Debug, Serialize)]
pub struct IdentityView {
    pub pid: i32,
    pub uid: u32,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub cmdline: Option<Vec<String>>,
    pub bundle_id: Option<String>,
    pub team_id: Option<String>,
    /// Parent processes ordered from the root toward the direct reader.
    pub parent_chain: Vec<ProcessView>,
    /// Parent-process chain, root-first, e.g. `login -> zsh -> node`.
    pub chain: String,
}

#[derive(Debug, Serialize)]
pub struct ProcessView {
    pub pid: i32,
    pub name: String,
    pub exe: Option<String>,
}

impl IdentityView {
    pub fn from_identity(id: &ProcessIdentity) -> Self {
        IdentityView {
            pid: id.pid,
            uid: id.uid,
            exe: id.exe_path.as_ref().map(|p| p.display().to_string()),
            cwd: id.cwd.as_ref().map(|p| p.display().to_string()),
            cmdline: id.cmdline.clone(),
            bundle_id: id.bundle_id.clone(),
            team_id: id.team_id.clone(),
            parent_chain: id
                .parent_chain
                .iter()
                .rev()
                .map(|process| ProcessView {
                    pid: process.pid,
                    name: process.name.clone(),
                    exe: process.exe_path.as_ref().map(|path| path.display().to_string()),
                })
                .collect(),
            chain: id.chain_display(),
        }
    }
}

/// The user's decision, decoded from [`ClientMsg::Decision`].
#[derive(Debug, Clone)]
pub struct ClientDecision {
    pub allow: bool,
    pub scope: Option<String>,
    pub ttl_secs: Option<u64>,
}

/// Write one length-prefixed JSON message.
pub fn write_msg<W: Write>(w: &mut W, msg: &impl Serialize) -> io::Result<()> {
    let body = serde_json::to_vec(msg)?;
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one length-prefixed JSON message. Blocks until a full frame arrives.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Swift side decodes these by hand; assert the wire shape (tag + fields) so schema
    /// drift between the two ends fails a test instead of silently dropping data.
    #[test]
    fn access_event_wire_shape_includes_operation() {
        let id = ProcessIdentity::bare(42, 501, 20);
        let msg = DaemonMsg::AccessEvent {
            ts: "2026-07-11T00:00:00.000Z".to_string(),
            path: "secrets/abc",
            display: Some("/Users/me/.env"),
            operation: "write",
            decision: "allowed",
            rule_id: Some("grant"),
            identity: IdentityView::from_identity(&id),
        };
        let v: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&msg).unwrap()).unwrap();
        assert_eq!(v["type"], "access_event");
        assert_eq!(v["display"], "/Users/me/.env");
        assert_eq!(v["operation"], "write");
        assert_eq!(v["decision"], "allowed");
        assert_eq!(v["path"], "secrets/abc");
        assert_eq!(v["rule_id"], "grant");
        assert_eq!(v["identity"]["pid"], 42);
        assert_eq!(v["identity"]["parent_chain"], serde_json::json!([]));
    }

    #[test]
    fn prompt_wire_shape_includes_operation() {
        let mut id = ProcessIdentity::bare(7, 501, 20);
        id.exe_path = Some("/bin/cat".into());
        id.cmdline = Some(vec!["cat".to_string(), "/fixture/file".to_string()]);
        id.parent_chain = vec![
            accessfs_core::identity::ProcSummary {
                pid: 7,
                ppid: 6,
                name: "cat".to_string(),
                exe_path: Some("/bin/cat".into()),
            },
            accessfs_core::identity::ProcSummary {
                pid: 6,
                ppid: 1,
                name: "zsh".to_string(),
                exe_path: Some("/bin/zsh".into()),
            },
            accessfs_core::identity::ProcSummary {
                pid: 1,
                ppid: 0,
                name: "launchd".to_string(),
                exe_path: Some("/sbin/launchd".into()),
            },
        ];
        let msg = DaemonMsg::Prompt {
            req_id: 9,
            path: "secrets/abc",
            display: None,
            operation: "read",
            enforcement: "prompt",
            identity: IdentityView::from_identity(&id),
        };
        let v: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&msg).unwrap()).unwrap();
        assert_eq!(v["type"], "prompt");
        assert_eq!(v["display"], serde_json::Value::Null);
        assert_eq!(v["req_id"], 9);
        assert_eq!(v["operation"], "read");
        assert_eq!(v["enforcement"], "prompt");
        assert_eq!(v["identity"]["cmdline"][0], "cat");
        assert_eq!(v["identity"]["parent_chain"][0]["name"], "launchd");
        assert_eq!(v["identity"]["parent_chain"][2]["name"], "cat");
    }
}
