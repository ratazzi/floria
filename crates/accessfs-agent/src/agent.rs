//! `SocketAgent`: the policy engine wired to the socket. Implements [`Authorizer`].
//!
//! Enforcement is decided by the config's [`RuleSet`] (first-match by priority). `prompt`/`touchid`
//! matches consult an in-memory grant cache and, on a miss, block on a prompt round-trip to the
//! menubar app. Missing app or timeout fails closed. Every final decision is streamed to the app
//! as an access event.

use std::sync::Arc;
use std::time::{Duration, Instant};

use accessfs_core::authz::{AuthRequest, Authorizer, Decision, Enforcement};
use accessfs_core::config::ResolvedConfig;
use accessfs_core::identity::ProcessIdentity;
use accessfs_core::rules::{repo_root, RuleSet};
use dashmap::DashMap;

use crate::protocol::{DaemonMsg, IdentityView};
use crate::socket::{PromptResult, SocketServer};

/// Executable basenames treated as interpreters: their code identity is the distributor's, not the
/// script's, so grants for them are keyed by repo rather than team id.
const INTERPRETERS: &[&str] = &[
    "node", "python", "python2", "python3", "ruby", "bun", "deno", "perl", "php", "java", "bash",
    "sh", "zsh",
];

/// How long to block a reader's `open()` waiting for the user to answer a prompt.
/// Must stay below the mount's `daemon_timeout` (60s).
const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default TTL for an "allow for a while" grant when the app doesn't specify one.
const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// TTL used for "this app / this project" grants in M1 (real persistence is a later milestone).
const PERSISTENT_TTL: Duration = Duration::from_secs(24 * 3600);

pub struct SocketAgent {
    server: Arc<SocketServer>,
    /// Policy rules, evaluated first-match by priority.
    rules: RuleSet,
    /// (grant_key, path) -> grant expiry.
    grants: DashMap<(String, String), Instant>,
}

impl SocketAgent {
    /// Start the socket server and build the agent from resolved config.
    pub fn start(cfg: &ResolvedConfig) -> std::io::Result<Arc<SocketAgent>> {
        let server = SocketServer::start(&cfg.agent_socket)?;
        tracing::info!(
            socket = %cfg.agent_socket.display(),
            rules = cfg.rules.len(),
            "agent socket listening"
        );
        Ok(Arc::new(SocketAgent {
            server,
            rules: cfg.rules.clone(),
            grants: DashMap::new(),
        }))
    }

    fn handle_prompt(
        &self,
        req: &AuthRequest,
        enforcement: Enforcement,
        grant_key: String,
    ) -> Decision {
        let key = (grant_key, req.path.to_string());

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
        // Derive the reader's git checkout once; both rule matching and grant keying use it.
        let repo = req.identity.cwd.as_deref().and_then(repo_root);
        let (enforcement, rule_id) = self.rules.decide(req.identity, req.path, repo.as_deref());

        let decision = match enforcement {
            Enforcement::Allow => attach(Decision::allow("allowed by rule"), rule_id),
            Enforcement::Deny => attach(Decision::deny("denied by rule"), rule_id),
            enf @ (Enforcement::Prompt | Enforcement::TouchId) => {
                let key = grant_key(req.identity, repo.as_deref());
                self.handle_prompt(req, enf, key)
            }
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

/// Attach an optional rule id to a decision.
fn attach(d: Decision, rule_id: Option<String>) -> Decision {
    match rule_id {
        Some(r) => d.with_rule(r),
        None => d,
    }
}

/// Normalize identity into a grant cache key, so one approval covers an app's helper processes and
/// its later runs (see `docs/design/policy-engine.md`):
/// - interpreters (node/python/...) key on the repo they run from (their code identity is the
///   distributor's, shared across every script);
/// - compiled/GUI apps key on their team id (stable across helper processes);
/// - everything else falls back to the exe path, then pid.
fn grant_key(id: &ProcessIdentity, repo: Option<&str>) -> String {
    if let Some(exe) = id.exe_path.as_deref() {
        let is_interpreter = exe
            .file_name()
            .map(|n| INTERPRETERS.contains(&n.to_string_lossy().as_ref()))
            .unwrap_or(false);
        if is_interpreter {
            // Interpreter: key on the repo it runs from; its team id is the distributor's.
            return match repo {
                Some(r) => format!("repo:{r}"),
                None => format!("exe:{}", exe.to_string_lossy()),
            };
        }
    }

    if let Some(team) = &id.team_id {
        return format!("team:{team}");
    }
    if let Some(exe) = id.exe_path.as_deref() {
        return format!("exe:{}", exe.to_string_lossy());
    }
    format!("pid:{}", id.pid)
}

/// Map a decision's scope to a grant TTL. `once` caches nothing.
fn grant_ttl(d: &crate::protocol::ClientDecision) -> Option<Duration> {
    match d.scope.as_deref() {
        Some("ttl") => Some(d.ttl_secs.map(Duration::from_secs).unwrap_or(DEFAULT_TTL)),
        Some("app_file") | Some("app_project") => Some(PERSISTENT_TTL),
        _ => None, // "once" or unspecified
    }
}
