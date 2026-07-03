//! `SocketAgent`: the policy engine wired to the socket. Implements [`Authorizer`].
//!
//! Per-path enforcement comes from config. `prompt` paths consult an in-memory grant
//! cache and, on a miss, block on a prompt round-trip to the menubar app. Missing app or
//! timeout fails closed. Every final decision is streamed to the app as an access event.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use accessfs_core::authz::{AuthRequest, Authorizer, Decision, Enforcement};
use accessfs_core::config::ResolvedConfig;
use dashmap::DashMap;

use crate::protocol::{DaemonMsg, IdentityView};
use crate::socket::{PromptResult, SocketServer};

/// How long to block a reader's `open()` waiting for the user to answer a prompt.
/// Must stay below the mount's `daemon_timeout` (60s).
const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default TTL for an "allow for a while" grant when the app doesn't specify one.
const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// TTL used for "this app / this project" grants in M1 (real persistence is a later milestone).
const PERSISTENT_TTL: Duration = Duration::from_secs(24 * 3600);

pub struct SocketAgent {
    server: Arc<SocketServer>,
    /// virtual path -> enforcement level.
    enforcement: HashMap<String, Enforcement>,
    /// (subject, path) -> grant expiry.
    grants: DashMap<(String, String), Instant>,
}

impl SocketAgent {
    /// Start the socket server and build the agent from resolved config.
    pub fn start(cfg: &ResolvedConfig) -> std::io::Result<Arc<SocketAgent>> {
        let server = SocketServer::start(&cfg.agent_socket)?;
        let enforcement = cfg
            .files
            .iter()
            .map(|f| (f.path.clone(), f.enforcement))
            .collect();
        tracing::info!(socket = %cfg.agent_socket.display(), "agent socket listening");
        Ok(Arc::new(SocketAgent {
            server,
            enforcement,
            grants: DashMap::new(),
        }))
    }

    fn enforcement_for(&self, path: &str) -> Enforcement {
        self.enforcement.get(path).copied().unwrap_or_default()
    }

    fn handle_prompt(&self, req: &AuthRequest, enforcement: Enforcement) -> Decision {
        let subject = subject_key(req);
        let key = (subject, req.path.to_string());

        if self.grant_valid(&key) {
            return Decision::allow("cached grant").with_rule("grant");
        }

        let result = self.server.prompt_and_wait(
            |req_id| DaemonMsg::Prompt {
                req_id,
                path: req.path,
                operation: req.operation.as_str(),
                enforcement: enforcement.as_str(),
                identity: IdentityView::from_identity(req.identity),
            },
            PROMPT_TIMEOUT,
        );

        match result {
            PromptResult::Decision(d) if d.allow => {
                if let Some(ttl) = grant_ttl(&d) {
                    self.grants.insert(key, Instant::now() + ttl);
                }
                Decision::allow("prompt: allowed").with_rule("prompt")
            }
            PromptResult::Decision(_) => Decision::deny("prompt: denied").with_rule("prompt"),
            PromptResult::NoApp => {
                Decision::deny("no agent app connected").with_rule("fail-closed")
            }
            PromptResult::Timeout => {
                Decision::deny("prompt timed out").with_rule("fail-closed")
            }
        }
    }

    /// True if a non-expired grant exists for `key`; expired grants are evicted.
    fn grant_valid(&self, key: &(String, String)) -> bool {
        match self.grants.get(key) {
            Some(exp) if *exp > Instant::now() => true,
            Some(_) => {
                drop(self.grants.remove(key));
                false
            }
            None => false,
        }
    }
}

impl Authorizer for SocketAgent {
    fn authorize(&self, req: &AuthRequest) -> Decision {
        let decision = match self.enforcement_for(req.path) {
            Enforcement::Allow => Decision::allow("monitor mode (allow)"),
            Enforcement::Deny => Decision::deny("policy: deny").with_rule("deny"),
            enf @ (Enforcement::Prompt | Enforcement::TouchId) => self.handle_prompt(req, enf),
        };

        // Stream every final decision to the app for its "recent access" view.
        self.server.send_event(&DaemonMsg::AccessEvent {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            path: req.path,
            decision: decision.decision_str(),
            rule_id: decision.rule_id.as_deref(),
            identity: IdentityView::from_identity(req.identity),
        });

        decision
    }
}

/// Cache key for the reading app. M1 keys on exe path; proper code-signature identity
/// (TeamID/bundle id) is a later milestone.
fn subject_key(req: &AuthRequest) -> String {
    req.identity
        .exe_path
        .as_deref()
        .map(Path::to_string_lossy)
        .map(|s| s.into_owned())
        .unwrap_or_else(|| format!("pid:{}", req.identity.pid))
}

/// Map a decision's scope to a grant TTL. `once` caches nothing.
fn grant_ttl(d: &crate::protocol::ClientDecision) -> Option<Duration> {
    match d.scope.as_deref() {
        Some("ttl") => Some(d.ttl_secs.map(Duration::from_secs).unwrap_or(DEFAULT_TTL)),
        Some("app_file") | Some("app_project") => Some(PERSISTENT_TTL),
        _ => None, // "once" or unspecified
    }
}
