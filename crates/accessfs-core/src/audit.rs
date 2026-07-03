use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

use crate::error::Result;
use crate::identity::ProcessIdentity;

/// Append-only JSONL audit log. Flushed line by line so no already-written event is lost even if the process is killed.
pub struct AuditLog {
    writer: Mutex<BufWriter<std::fs::File>>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditLog {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    fn write(&self, value: &impl Serialize) {
        let line = match serde_json::to_string(value) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("audit serialize failed: {e}");
                return;
            }
        };
        // An audit write failure must not affect file semantics; just log an error.
        if let Ok(mut w) = self.writer.lock() {
            if let Err(e) = writeln!(w, "{line}").and_then(|_| w.flush()) {
                tracing::error!("audit write failed: {e}");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_open(
        &self,
        path: &str,
        identity: &ProcessIdentity,
        decision: &str,
        rule_id: Option<&str>,
        content_version: &str,
        fh: u64,
        size: u64,
    ) {
        self.write(&OpenEvent {
            ts: now_rfc3339(),
            event: "open",
            path,
            operation: "read",
            decision,
            rule_id,
            request: RequestInfo {
                uid: identity.uid,
                gid: identity.gid,
                pid: identity.pid,
            },
            identity,
            content_version,
            fh,
            size,
        });
    }

    /// Authorization denied: no snapshot/fh, only records the identity and the rationale for the decision.
    pub fn log_denied(
        &self,
        path: &str,
        identity: &ProcessIdentity,
        rule_id: Option<&str>,
        reason: &str,
    ) {
        self.write(&DeniedEvent {
            ts: now_rfc3339(),
            event: "open",
            path,
            operation: "read",
            decision: "denied",
            rule_id,
            reason,
            request: RequestInfo {
                uid: identity.uid,
                gid: identity.gid,
                pid: identity.pid,
            },
            identity,
        });
    }

    pub fn log_close(
        &self,
        path: &str,
        fh: u64,
        duration_ms: u128,
        bytes_served: u64,
        error: Option<&str>,
    ) {
        self.write(&CloseEvent {
            ts: now_rfc3339(),
            event: "close",
            path,
            fh,
            duration_ms,
            bytes_served,
            error,
        });
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[derive(Serialize)]
struct RequestInfo {
    uid: u32,
    gid: u32,
    pid: i32,
}

#[derive(Serialize)]
struct OpenEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    operation: &'static str,
    decision: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'a str>,
    request: RequestInfo,
    identity: &'a ProcessIdentity,
    content_version: &'a str,
    fh: u64,
    size: u64,
}

#[derive(Serialize)]
struct DeniedEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    operation: &'static str,
    decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'a str>,
    reason: &'a str,
    request: RequestInfo,
    identity: &'a ProcessIdentity,
}

#[derive(Serialize)]
struct CloseEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    fh: u64,
    duration_ms: u128,
    bytes_served: u64,
    error: Option<&'a str>,
}
