//! `SocketAgent`: the policy engine wired to the socket. Implements [`Authorizer`].
//!
//! Enforcement is decided by the config's [`RuleSet`] (first-match by priority). `prompt`/`touchid`
//! matches consult an in-memory grant cache and, on a miss, block on a prompt round-trip to the
//! menubar app. Missing app or timeout fails closed. Every final decision is streamed to the app
//! as an access event.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use accessfs_core::authz::{
    AuthRequest, Authorizer, Decision, Enforcement, Operation, PolicyMode, PolicyModeStatus,
};
use accessfs_core::config::ResolvedConfig;
use accessfs_core::identity::ProcessIdentity;
use accessfs_core::rules::{repo_root, RuleSet};
use dashmap::DashMap;

use crate::protocol::{DaemonMsg, IdentityView, SshSignView};
use crate::policy_mode::PolicyModeState;
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
    /// Per-managed-path defaults supplied by the live catalog/store snapshot. Explicit process
    /// rules still win; these values replace only the built-in secrets/surfaces defaults.
    managed_enforcement: RwLock<HashMap<String, Enforcement>>,
    /// Daemon-wide runtime override, persisted independently from per-item catalog settings.
    policy_mode: PolicyModeState,
    /// (grant_key, object, operation) -> grant expiry. The object is the path for file access and
    /// path + public-key fingerprint for SSH signatures. Operation is part of the key so a read
    /// grant never authorizes a write (and vice versa) — approving "read .env" must not let
    /// the same subject silently rewrite it within the TTL.
    grants: DashMap<(String, String, Operation), Instant>,
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
            managed_enforcement: RwLock::new(HashMap::new()),
            policy_mode: PolicyModeState::open(
                cfg.agent_socket.with_file_name("policy-mode.json"),
            ),
            grants: DashMap::new(),
        }))
    }

    pub fn policy_mode(&self) -> PolicyModeStatus {
        self.policy_mode.status()
    }

    pub fn set_policy_mode(
        &self,
        mode: PolicyMode,
        duration_secs: Option<u64>,
    ) -> std::io::Result<PolicyModeStatus> {
        let status = self.policy_mode.set(mode, duration_secs)?;
        // Grants are scoped to the policy regime under which the user approved them. A mode
        // transition must not let an old grant silently survive a return to stricter policy.
        self.grants.clear();
        tracing::info!(mode = ?status.mode, expires_at = ?status.expires_at, "policy mode changed");
        Ok(status)
    }

    /// Atomically replace the default enforcement for managed secret and surface paths.
    pub fn replace_managed_enforcement(&self, values: HashMap<String, Enforcement>) {
        match self.managed_enforcement.write() {
            Ok(mut current) => *current = values,
            Err(poisoned) => *poisoned.into_inner() = values,
        }
        self.grants.clear();
    }

    fn managed_enforcement(&self, path: &str) -> Option<Enforcement> {
        match self.managed_enforcement.read() {
            Ok(values) => values.get(path).copied(),
            Err(poisoned) => poisoned.into_inner().get(path).copied(),
        }
    }

    fn handle_prompt(
        &self,
        req: &AuthRequest,
        enforcement: Enforcement,
        grant_key: String,
    ) -> Decision {
        let key = (grant_key, grant_object(req), req.operation);

        if self.grant_valid(&key) {
            return Decision::allow("cached grant").with_rule("grant");
        }

        let result = self.server.prompt_and_wait(
            |req_id| DaemonMsg::Prompt {
                req_id,
                path: req.path,
                display: req.display,
                operation: req.operation.as_str(),
                enforcement: enforcement.as_str(),
                ssh: SshSignView::from_context(req.context),
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
    fn grant_valid(&self, key: &(String, String, Operation)) -> bool {
        // Copy the expiry out so the shard Ref from `get` is dropped before `remove`:
        // dashmap self-deadlocks on a same-shard remove while a Ref is still alive
        // (a match on `get` keeps the Ref for the whole match).
        let exp = self.grants.get(key).map(|r| *r);
        match exp {
            Some(exp) if exp > Instant::now() => true,
            Some(_) => {
                self.grants.remove(key);
                false
            }
            None => false,
        }
    }
}

fn grant_object(req: &AuthRequest<'_>) -> String {
    match req.context {
        Some(accessfs_core::authz::AccessContext::SshSign(context)) => {
            format!("{}#{}", req.path, context.key_fingerprint)
        }
        None => req.path.to_string(),
    }
}

impl Authorizer for SocketAgent {
    fn authorize(&self, req: &AuthRequest) -> Decision {
        // Derive the reader's git checkout once; both rule matching and grant keying use it.
        let repo = req.identity.cwd.as_deref().and_then(repo_root);
        let (mut enforcement, mut rule_id) =
            self.rules
                .decide(req.identity, req.path, repo.as_deref(), req.operation);
        if matches!(rule_id.as_deref(), Some("secrets-default" | "surfaces-default")) {
            if let Some(level) = self.managed_enforcement(req.path) {
                enforcement = level;
                rule_id = Some(format!("security-level:{}", level.as_str()));
            }
        }

        let policy = self.policy_mode.evaluate(enforcement);
        let decision = match policy.effective_enforcement {
            Enforcement::Allow if policy.effective_enforcement != policy.configured_enforcement => {
                Decision::allow("allowed by global audit-only mode")
                    .with_rule("policy-mode:audit-only")
            }
            Enforcement::Allow => attach(Decision::allow("allowed by rule"), rule_id),
            Enforcement::Deny => attach(Decision::deny("denied by rule"), rule_id),
            enf @ (Enforcement::Prompt | Enforcement::TouchId) => {
                let key = grant_key(req.identity, repo.as_deref());
                self.handle_prompt(req, enf, key)
            }
        }
        .with_policy(policy);

        // Stream every final decision to the app for its "recent access" view.
        self.server.send_event(&DaemonMsg::AccessEvent {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            path: req.path,
            display: req.display,
            operation: req.operation.as_str(),
            decision: decision.decision_str(),
            rule_id: decision.rule_id.as_deref(),
            policy: decision.policy,
            ssh: SshSignView::from_context(req.context),
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

#[cfg(test)]
mod tests {
    use super::*;
    use accessfs_core::authz::{AccessContext, SshSignContext};
    use accessfs_core::rules::{any_path_glob, Rule, RuleOps, SubjectMatch};

    fn agent_with_rules(dir: &std::path::Path, rules: Vec<Rule>) -> SocketAgent {
        let server = SocketServer::start(&dir.join("agent.sock")).unwrap();
        SocketAgent {
            server,
            rules: RuleSet::new(rules),
            managed_enforcement: RwLock::new(HashMap::new()),
            policy_mode: PolicyModeState::open(dir.join("policy-mode.json")),
            grants: DashMap::new(),
        }
    }

    /// Agent whose rules prompt for everything (both operations), with a live socket but no
    /// app connected — any prompt fails closed, so only the grant cache can produce an allow.
    fn prompt_only_agent(dir: &std::path::Path) -> SocketAgent {
        agent_with_rules(
            dir,
            vec![Rule {
                id: "prompt-all".into(),
                priority: 0,
                subject: SubjectMatch::default(),
                path_glob: any_path_glob(),
                ops: RuleOps::READ_WRITE,
                enforcement: Enforcement::Prompt,
                enabled: true,
            }],
        )
    }

    fn req<'a>(id: &'a ProcessIdentity, op: Operation) -> AuthRequest<'a> {
        AuthRequest {
            path: "secrets/test-id",
            display: None,
            operation: op,
            context: None,
            identity: id,
        }
    }

    #[test]
    fn read_grant_does_not_cover_write() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = prompt_only_agent(tmp.path());
        let id = ProcessIdentity::bare(1234, 501, 20);

        // Seed a read grant, as if the user had answered "allow reads for 10 min".
        agent.grants.insert(
            (
                grant_key(&id, None),
                "secrets/test-id".to_string(),
                Operation::Read,
            ),
            Instant::now() + Duration::from_secs(600),
        );

        // Read hits the cache.
        let d = agent.authorize(&req(&id, Operation::Read));
        assert!(d.is_allowed());
        assert_eq!(d.rule_id.as_deref(), Some("grant"));

        // Write must NOT: it re-prompts, and with no app connected it fails closed.
        let d = agent.authorize(&req(&id, Operation::Write));
        assert!(!d.is_allowed());
        assert_eq!(d.rule_id.as_deref(), Some("fail-closed"));
    }

    #[test]
    fn ssh_grant_is_scoped_to_one_public_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = agent_with_rules(
            tmp.path(),
            vec![Rule {
                id: "prompt-sign".into(),
                priority: 0,
                subject: SubjectMatch::default(),
                path_glob: any_path_glob(),
                ops: RuleOps::SIGN,
                enforcement: Enforcement::Prompt,
                enabled: true,
            }],
        );
        let id = ProcessIdentity::bare(1234, 501, 20);
        let first = SshSignContext {
            surface_id: "fixture-agent",
            surface_name: "Fixture Agent",
            resource_id: "fixture-provider",
            key_fingerprint: "SHA256:fixture-first",
            key_label: "First key",
        };
        let second = SshSignContext {
            key_fingerprint: "SHA256:fixture-second",
            key_label: "Second key",
            ..first
        };
        let first_request = AuthRequest {
            path: "surfaces/fixture-agent",
            display: Some("Fixture Agent"),
            operation: Operation::Sign,
            context: Some(AccessContext::SshSign(first)),
            identity: &id,
        };
        agent.grants.insert(
            (
                grant_key(&id, None),
                grant_object(&first_request),
                Operation::Sign,
            ),
            Instant::now() + Duration::from_secs(600),
        );

        assert!(agent.authorize(&first_request).is_allowed());
        let second_request = AuthRequest {
            context: Some(AccessContext::SshSign(second)),
            ..first_request
        };
        let decision = agent.authorize(&second_request);
        assert!(!decision.is_allowed());
        assert_eq!(decision.rule_id.as_deref(), Some("fail-closed"));
    }

    #[test]
    fn read_only_allow_rule_does_not_cover_write() {
        // A pre-write-era static config: broad allow with no operation declared.
        let tmp = tempfile::tempdir().unwrap();
        let agent = agent_with_rules(
            tmp.path(),
            vec![Rule {
                id: "legacy-allow".into(),
                priority: 10,
                subject: SubjectMatch::default(),
                path_glob: any_path_glob(),
                ops: RuleOps::READ, // what `operation = None` in config resolves to
                enforcement: Enforcement::Allow,
                enabled: true,
            }],
        );
        let id = ProcessIdentity::bare(1234, 501, 20);

        let d = agent.authorize(&req(&id, Operation::Read));
        assert!(d.is_allowed());
        assert_eq!(d.rule_id.as_deref(), Some("legacy-allow"));

        // The same subject writing must not ride the read rule: nothing matches → fail closed.
        let d = agent.authorize(&req(&id, Operation::Write));
        assert!(!d.is_allowed());
        assert_eq!(d.rule_id.as_deref(), Some("default-deny"));
    }

    #[test]
    fn managed_security_level_replaces_only_the_builtin_secret_default() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = agent_with_rules(
            tmp.path(),
            vec![Rule {
                id: "secrets-default".into(),
                priority: 0,
                subject: SubjectMatch::default(),
                path_glob: any_path_glob(),
                ops: RuleOps::READ_WRITE,
                enforcement: Enforcement::Prompt,
                enabled: true,
            }],
        );
        agent.replace_managed_enforcement(HashMap::from([(
            "secrets/test-id".to_string(),
            Enforcement::Allow,
        )]));

        let id = ProcessIdentity::bare(1234, 501, 20);
        let decision = agent.authorize(&req(&id, Operation::Read));
        assert!(decision.is_allowed());
        assert_eq!(decision.rule_id.as_deref(), Some("security-level:allow"));
    }

    #[test]
    fn explicit_process_rule_wins_over_managed_security_level() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = agent_with_rules(
            tmp.path(),
            vec![
                Rule {
                    id: "explicit-deny".into(),
                    priority: 100,
                    subject: SubjectMatch::default(),
                    path_glob: any_path_glob(),
                    ops: RuleOps::READ,
                    enforcement: Enforcement::Deny,
                    enabled: true,
                },
                Rule {
                    id: "secrets-default".into(),
                    priority: 0,
                    subject: SubjectMatch::default(),
                    path_glob: any_path_glob(),
                    ops: RuleOps::READ_WRITE,
                    enforcement: Enforcement::Prompt,
                    enabled: true,
                },
            ],
        );
        agent.replace_managed_enforcement(HashMap::from([(
            "secrets/test-id".to_string(),
            Enforcement::Allow,
        )]));

        let id = ProcessIdentity::bare(1234, 501, 20);
        let decision = agent.authorize(&req(&id, Operation::Read));
        assert!(!decision.is_allowed());
        assert_eq!(decision.rule_id.as_deref(), Some("explicit-deny"));
    }

    /// Regression: an EXPIRED grant used to deadlock `grant_valid` (dashmap remove while
    /// the Ref from `get` was still alive), hanging the reader forever with no prompt.
    /// Run authorize on a helper thread with a deadline so a regression fails the test
    /// instead of hanging the suite.
    #[test]
    fn expired_grant_reprompts_instead_of_deadlocking() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = Arc::new(prompt_only_agent(tmp.path()));
        let id = ProcessIdentity::bare(1234, 501, 20);
        agent.grants.insert(
            (
                grant_key(&id, None),
                "secrets/test-id".to_string(),
                Operation::Read,
            ),
            Instant::now() - Duration::from_secs(1), // already expired
        );

        let handle = {
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || {
                let id = ProcessIdentity::bare(1234, 501, 20);
                agent.authorize(&req(&id, Operation::Read)).is_allowed()
            })
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !handle.is_finished() {
            assert!(
                Instant::now() < deadline,
                "authorize deadlocked on an expired grant"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // No app is connected, so the re-prompt fails closed — but it must RETURN.
        assert!(!handle.join().unwrap());
        assert!(agent.grants.is_empty(), "expired grant must be evicted");
    }

    #[test]
    fn write_grant_does_not_cover_read() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = prompt_only_agent(tmp.path());
        let id = ProcessIdentity::bare(1234, 501, 20);

        agent.grants.insert(
            (
                grant_key(&id, None),
                "secrets/test-id".to_string(),
                Operation::Write,
            ),
            Instant::now() + Duration::from_secs(600),
        );

        let d = agent.authorize(&req(&id, Operation::Write));
        assert!(d.is_allowed());

        let d = agent.authorize(&req(&id, Operation::Read));
        assert!(!d.is_allowed());
    }

    #[test]
    fn audit_only_allows_prompt_without_app_and_records_policy_context() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = prompt_only_agent(tmp.path());
        agent.set_policy_mode(PolicyMode::AuditOnly, None).unwrap();
        let id = ProcessIdentity::bare(1234, 501, 20);

        let decision = agent.authorize(&req(&id, Operation::Read));

        assert!(decision.is_allowed());
        assert_eq!(decision.rule_id.as_deref(), Some("policy-mode:audit-only"));
        let policy = decision.policy.expect("policy evaluation");
        assert_eq!(policy.configured_enforcement, Enforcement::Prompt);
        assert_eq!(policy.effective_enforcement, Enforcement::Allow);
        assert_eq!(policy.mode, PolicyMode::AuditOnly);
    }

    #[test]
    fn changing_policy_mode_clears_existing_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = prompt_only_agent(tmp.path());
        let id = ProcessIdentity::bare(1234, 501, 20);
        agent.grants.insert(
            (
                grant_key(&id, None),
                "secrets/test-id".to_string(),
                Operation::Read,
            ),
            Instant::now() + Duration::from_secs(600),
        );

        agent.set_policy_mode(PolicyMode::AuditOnly, Some(3600)).unwrap();

        assert!(agent.grants.is_empty());
    }
}
