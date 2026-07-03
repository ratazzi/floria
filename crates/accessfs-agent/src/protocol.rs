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
        operation: &'a str,
        enforcement: &'a str,
        identity: IdentityView,
    },
    /// A fire-and-forget record of an access, for the app's "recent access" UI.
    AccessEvent {
        ts: String,
        path: &'a str,
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
    /// Parent-process chain, root-first, e.g. `login -> zsh -> node`.
    pub chain: String,
}

impl IdentityView {
    pub fn from_identity(id: &ProcessIdentity) -> Self {
        IdentityView {
            pid: id.pid,
            uid: id.uid,
            exe: id.exe_path.as_ref().map(|p| p.display().to_string()),
            cwd: id.cwd.as_ref().map(|p| p.display().to_string()),
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
