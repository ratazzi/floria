//! Authorization boundary: the sole decision interface between the FS backend and the agent.
//!
//! At the first observable FUSE access boundary for each process lifetime, the FS backend calls
//! [`Authorizer::authorize`] and allows/denies per the [`Decision`], holding no policy of its own.
//! This is usually `open()`, but can be `read()` when macFUSE reuses a vnode-level handle and hides
//! a later process's POSIX open. The interface is **synchronous and blocking**: an implementation
//! may do IPC or wait on a user prompt, as long as it returns within `daemon_timeout`.

use crate::identity::ProcessIdentity;
use serde::{Deserialize, Serialize};

/// A single authorization request at a process's first observable access boundary.
pub struct AuthRequest<'a> {
    /// Virtual file path, e.g. `env/demo/dev.env`.
    pub path: &'a str,
    /// Human-facing name for prompts and the recent-access UI — a store-backed secret's
    /// original source path instead of its opaque `secrets/<uuid>`. Display only: rules,
    /// grants, and audit all keep keying on the stable `path`.
    pub display: Option<&'a str>,
    /// Stable digest of the resolved object graph. Grant caches include it so a path cannot be
    /// rebound to different backing state while retaining an earlier approval.
    pub object_revision: Option<&'a str>,
    pub operation: Operation,
    /// Operation-specific public metadata for prompts, grant scoping, and audit. Rules continue
    /// to key on stable path + operation; callers must never place payloads or bytes-to-sign here.
    pub context: Option<AccessContext<'a>>,
    /// Enriched identity of the reader.
    pub identity: &'a ProcessIdentity,
}

/// Metadata for capabilities that cross the same authorization seam as file access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessContext<'a> {
    SshSign(SshSignContext<'a>),
}

/// Public, non-secret identity information for one SSH signature request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshSignContext<'a> {
    pub surface_id: &'a str,
    pub surface_name: &'a str,
    pub resource_id: &'a str,
    pub key_fingerprint: &'a str,
    pub key_label: &'a str,
    /// Destination token claimed by the local ssh process. Display-only: the SSH agent protocol
    /// does not authenticate hostnames, so policy must not treat this as a destination constraint.
    pub requested_destination: Option<&'a str>,
    /// SHA-256 fingerprint of the host key whose KEX signature was verified by OpenSSH
    /// `session-bind`. This identifies a cryptographic key, not a hostname.
    pub verified_host_key_fingerprint: Option<&'a str>,
    /// Server account parsed from the user-auth request tied to the verified session.
    pub ssh_user: Option<&'a str>,
    /// Number of verified forwarding bindings preceding the final authentication session.
    pub forwarding_hops: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Read,
    /// Opening for write (store-backed secrets only). Each committed close appends a new
    /// immutable version to the store, so a write is never destructive.
    Write,
    /// Use a non-exportable private capability to sign data, currently for SSH agent requests.
    Sign,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Sign => "sign",
        }
    }
}

/// The enforcement level configured for a path: how strictly its access is gated.
/// Attached per-file in config; consumed by the policy engine (agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    /// Allow silently, audit only (monitor mode). The default.
    #[default]
    Allow,
    /// Deny outright.
    Deny,
    /// Block and ask the user (via the menubar app), subject to the grant cache.
    Prompt,
    /// Like `Prompt`, but the user must also pass biometric (Touch ID) to allow.
    TouchId,
}

impl Enforcement {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Enforcement::Allow),
            "deny" => Some(Enforcement::Deny),
            "prompt" => Some(Enforcement::Prompt),
            "touchid" => Some(Enforcement::TouchId),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Enforcement::Allow => "allow",
            Enforcement::Deny => "deny",
            Enforcement::Prompt => "prompt",
            Enforcement::TouchId => "touchid",
        }
    }
}

/// Daemon-wide runtime policy. It changes how configured enforcement is applied without
/// rewriting any per-item security level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Apply every item's configured enforcement unchanged.
    #[default]
    Normal,
    /// Allow configured prompt/Touch ID items without interaction while retaining auditing.
    /// Explicit deny rules remain deny.
    AuditOnly,
}

/// Persisted and control-plane-visible status for the daemon-wide runtime policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyModeStatus {
    pub mode: PolicyMode,
    /// Unix timestamp in seconds. `None` means the mode remains until explicitly changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl Default for PolicyModeStatus {
    fn default() -> Self {
        PolicyModeStatus { mode: PolicyMode::Normal, expires_at: None }
    }
}

/// Structured policy rationale carried through the Authorizer seam into both audit sinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub configured_enforcement: Enforcement,
    pub effective_enforcement: Enforcement,
    pub mode: PolicyMode,
}

/// Authorization decision. The FS only cares about allow/deny; side effects like `notify` are
/// handled by the authorizer itself and don't belong in this type. `reason`/`rule_id` are for auditing.
#[derive(Debug, Clone)]
pub struct Decision {
    pub outcome: Outcome,
    /// Human-readable rationale for the decision, recorded in the audit log.
    pub reason: String,
    /// The matched rule/grant id, recorded in the audit log; None in monitor mode.
    pub rule_id: Option<String>,
    /// Present when a policy engine evaluated configured enforcement for this decision.
    pub policy: Option<PolicyEvaluation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allowed,
    Denied,
}

impl Decision {
    pub fn allow(reason: impl Into<String>) -> Self {
        Decision {
            outcome: Outcome::Allowed,
            reason: reason.into(),
            rule_id: None,
            policy: None,
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Decision {
            outcome: Outcome::Denied,
            reason: reason.into(),
            rule_id: None,
            policy: None,
        }
    }

    pub fn with_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    pub fn with_policy(mut self, policy: PolicyEvaluation) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn is_allowed(&self) -> bool {
        self.outcome == Outcome::Allowed
    }

    /// Decision string for auditing: allowed / denied.
    pub fn decision_str(&self) -> &'static str {
        match self.outcome {
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
        }
    }
}

/// The only authorization interface the FS backend depends on. `Send + Sync`: fuser callbacks take `&self` and may run on multiple threads.
pub trait Authorizer: Send + Sync {
    fn authorize(&self, req: &AuthRequest) -> Decision;
}

/// Monitor mode: allow everything and rely solely on the audit log. The default implementation for
/// the first step, and the starting point for collecting real traffic to infer rules from.
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(&self, _req: &AuthRequest) -> Decision {
        Decision::allow("monitor mode (allow-all)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_allows() {
        let id = ProcessIdentity::bare(1, 501, 20);
        let d = AllowAll.authorize(&AuthRequest {
            path: "env/demo/dev.env",
            display: None,
            object_revision: None,
            operation: Operation::Read,
            context: None,
            identity: &id,
        });
        assert!(d.is_allowed());
        assert_eq!(d.decision_str(), "allowed");
    }

    #[test]
    fn deny_with_rule() {
        let d = Decision::deny("prod requires prompt").with_rule("rule-42");
        assert!(!d.is_allowed());
        assert_eq!(d.decision_str(), "denied");
        assert_eq!(d.rule_id.as_deref(), Some("rule-42"));
    }
}
