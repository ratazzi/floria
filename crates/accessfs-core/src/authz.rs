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
    pub operation: Operation,
    /// Enriched identity of the reader.
    pub identity: &'a ProcessIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Read,
    /// Opening for write (store-backed secrets only). Each committed close appends a new
    /// immutable version to the store, so a write is never destructive.
    Write,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Read => "read",
            Operation::Write => "write",
        }
    }
}

/// The enforcement level configured for a path: how strictly its access is gated.
/// Attached per-file in config; consumed by the policy engine (agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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

/// Authorization decision. The FS only cares about allow/deny; side effects like `notify` are
/// handled by the authorizer itself and don't belong in this type. `reason`/`rule_id` are for auditing.
#[derive(Debug, Clone)]
pub struct Decision {
    pub outcome: Outcome,
    /// Human-readable rationale for the decision, recorded in the audit log.
    pub reason: String,
    /// The matched rule/grant id, recorded in the audit log; None in monitor mode.
    pub rule_id: Option<String>,
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
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Decision {
            outcome: Outcome::Denied,
            reason: reason.into(),
            rule_id: None,
        }
    }

    pub fn with_rule(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
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
            operation: Operation::Read,
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
