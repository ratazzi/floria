use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

use crate::authz::PolicyEvaluation;
use crate::error::Result;
use crate::identity::ProcessIdentity;

/// Append-only JSONL audit log. Flushed line by line so no already-written event is lost even if the process is killed.
pub struct AuditLog {
    writer: Mutex<BufWriter<std::fs::File>>,
}

/// Metadata-only provenance for one rendered surface export. Secret ids and immutable version
/// numbers are safe to audit; plaintext values never enter this structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditDependency {
    pub key: String,
    pub binding_id: String,
    pub resource_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

/// Public destination context for one SSH signing event. The requested name is display-only;
/// the host-key fingerprint and forwarding count come from a verified OpenSSH session binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SshSessionAudit<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_destination: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_host_key_fingerprint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_user: Option<&'a str>,
    pub forwarding_hops: usize,
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
        operation: &'static str,
        identity: &ProcessIdentity,
        decision: &str,
        rule_id: Option<&str>,
        policy: Option<&PolicyEvaluation>,
        content_version: &str,
        fh: u64,
        size: u64,
        dependencies: Option<&[AuditDependency]>,
    ) {
        self.write(&OpenEvent {
            ts: now_rfc3339(),
            event: "open",
            path,
            operation,
            decision,
            rule_id,
            policy,
            request: RequestInfo {
                uid: identity.uid,
                gid: identity.gid,
                pid: identity.pid,
            },
            identity,
            content_version,
            fh,
            size,
            dependencies,
        });
    }

    /// Authorization denied: no snapshot/fh, only records the identity and the rationale for the decision.
    pub fn log_denied(
        &self,
        path: &str,
        operation: &'static str,
        identity: &ProcessIdentity,
        rule_id: Option<&str>,
        reason: &str,
        policy: Option<&PolicyEvaluation>,
    ) {
        self.write(&DeniedEvent {
            ts: now_rfc3339(),
            event: "open",
            path,
            operation,
            decision: "denied",
            rule_id,
            reason,
            policy,
            request: RequestInfo {
                uid: identity.uid,
                gid: identity.gid,
                pid: identity.pid,
            },
            identity,
        });
    }

    /// A committed write: a new immutable version appended to the store. Records only the
    /// content hash and version number, never plaintext.
    pub fn log_write_commit(
        &self,
        path: &str,
        fh: u64,
        version: u32,
        content_version: &str,
        size: u64,
    ) {
        self.write(&WriteCommitEvent {
            ts: now_rfc3339(),
            event: "write_commit",
            path,
            fh,
            version,
            content_version,
            size,
        });
    }

    /// One SSH agent signature attempt. Only public identity metadata and the authorization/
    /// provider outcome are recorded; the public key blob, bytes-to-sign, and signature are not.
    #[allow(clippy::too_many_arguments)]
    pub fn log_ssh_sign(
        &self,
        path: &str,
        identity: &ProcessIdentity,
        decision: &str,
        rule_id: Option<&str>,
        reason: &str,
        policy: Option<&PolicyEvaluation>,
        surface_id: &str,
        resource_id: &str,
        key_fingerprint: &str,
        result: &str,
        ssh_session: Option<SshSessionAudit<'_>>,
    ) {
        self.write(&SshSignEvent {
            ts: now_rfc3339(),
            event: "ssh_sign",
            path,
            operation: "sign",
            decision,
            rule_id,
            reason,
            policy,
            request: RequestInfo {
                uid: identity.uid,
                gid: identity.gid,
                pid: identity.pid,
            },
            identity,
            surface_id,
            resource_id,
            key_fingerprint,
            result,
            ssh_session,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a PolicyEvaluation>,
    request: RequestInfo,
    identity: &'a ProcessIdentity,
    content_version: &'a str,
    fh: u64,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<&'a [AuditDependency]>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a PolicyEvaluation>,
    request: RequestInfo,
    identity: &'a ProcessIdentity,
}

#[derive(Serialize)]
struct WriteCommitEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    fh: u64,
    version: u32,
    content_version: &'a str,
    size: u64,
}

#[derive(Serialize)]
struct SshSignEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    operation: &'static str,
    decision: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'a str>,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a PolicyEvaluation>,
    request: RequestInfo,
    identity: &'a ProcessIdentity,
    surface_id: &'a str,
    resource_id: &'a str,
    key_fingerprint: &'a str,
    result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_session: Option<SshSessionAudit<'a>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Enforcement, PolicyMode};

    #[test]
    fn surface_audit_records_version_provenance_without_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).unwrap();
        let policy = PolicyEvaluation {
            configured_enforcement: Enforcement::TouchId,
            effective_enforcement: Enforcement::Allow,
            mode: PolicyMode::AuditOnly,
        };
        audit.log_open(
            "surfaces/fixture-dotenv",
            "read",
            &ProcessIdentity::bare(42, 501, 20),
            "allowed",
            Some("surfaces-default"),
            Some(&policy),
            "sha256:fixture-content-hash",
            7,
            32,
            Some(&[AuditDependency {
                key: "SERVICE_TOKEN".to_string(),
                binding_id: "fixture-binding".to_string(),
                resource_id: "fixture-resource".to_string(),
                secret_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
                version: Some(3),
            }]),
        );

        let line = std::fs::read_to_string(path).unwrap();
        assert!(line.contains("fixture-resource"));
        assert!(line.contains("\"version\":3"));
        assert!(line.contains("\"configured_enforcement\":\"touchid\""));
        assert!(line.contains("\"effective_enforcement\":\"allow\""));
        assert!(line.contains("\"mode\":\"audit_only\""));
        assert!(!line.contains("fixture-secret-value"));
    }

    #[test]
    fn ssh_sign_audit_records_public_identity_but_not_signing_material() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).unwrap();
        audit.log_ssh_sign(
            "surfaces/fixture-agent",
            &ProcessIdentity::bare(42, 501, 20),
            "allowed",
            Some("prompt"),
            "prompt: allowed",
            None,
            "fixture-agent",
            "fixture-provider",
            "SHA256:fixtureFingerprint",
            "signed",
            Some(SshSessionAudit {
                requested_destination: Some("fixture.example"),
                verified_host_key_fingerprint: Some("SHA256:fixtureHostKey"),
                ssh_user: Some("fixture-user"),
                forwarding_hops: 1,
            }),
        );

        let line = std::fs::read_to_string(path).unwrap();
        assert!(line.contains("\"event\":\"ssh_sign\""));
        assert!(line.contains("SHA256:fixtureFingerprint"));
        assert!(line.contains("\"result\":\"signed\""));
        assert!(line.contains("SHA256:fixtureHostKey"));
        assert!(line.contains("\"forwarding_hops\":1"));
        assert!(!line.contains("fixture-bytes-to-sign"));
        assert!(!line.contains("fixture-signature"));
    }
}
