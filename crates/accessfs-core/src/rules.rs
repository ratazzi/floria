//! Policy rule engine:
//! `who (subject) × what (path + object) × how-accessed (operation) -> how (enforcement)`.
//!
//! Evaluation is **first-match by priority** (like pf/iptables): rules are ordered by
//! descending priority and the first enabled rule whose subject *and* path both match wins.
//! No "most specific wins" heuristic -- ordering is explicit and predictable.
//!
//! The hard part is the subject. A [`SubjectMatch`] is a set of optional facets combined with
//! AND: every facet that is set must match. Compiled apps are keyed by `team_id` (stable across
//! their helper processes); interpreters (`node`, `python`, ...) share their distributor's
//! `team_id`, so they must be identified by `repo` (the git checkout they run from) instead.

use std::cmp::Reverse;
use std::path::Path;

use globset::{Glob, GlobMatcher};

use crate::authz::{Enforcement, Operation};
use crate::identity::ProcessIdentity;

pub const MANAGED_RESOURCE_PRIORITY: i32 = i32::MIN + 3;
pub const MANAGED_ITEM_PRIORITY: i32 = i32::MIN + 2;
pub const BUILTIN_DEFAULT_PRIORITY: i32 = i32::MIN + 1;
pub const CATCH_ALL_PRIORITY: i32 = i32::MIN;

/// Which operations a rule matches. Rules predate the writable mount and mean
/// "who may *read* what"; keeping unstated rules read-only preserves exactly that — a
/// read-era `allow` must never silently start covering writes or signatures. Write and sign
/// access are opt-in via an explicit rule operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleOps {
    pub read: bool,
    pub write: bool,
    pub sign: bool,
}

impl RuleOps {
    pub const READ: RuleOps = RuleOps { read: true, write: false, sign: false };
    pub const WRITE: RuleOps = RuleOps { read: false, write: true, sign: false };
    pub const SIGN: RuleOps = RuleOps { read: false, write: false, sign: true };
    pub const READ_WRITE: RuleOps = RuleOps { read: true, write: true, sign: false };
    pub const READ_WRITE_SIGN: RuleOps = RuleOps { read: true, write: true, sign: true };

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(RuleOps::READ),
            "write" => Some(RuleOps::WRITE),
            "readwrite" => Some(RuleOps::READ_WRITE),
            "sign" => Some(RuleOps::SIGN),
            _ => None,
        }
    }

    pub fn matches(&self, op: Operation) -> bool {
        match op {
            Operation::Read => self.read,
            Operation::Write => self.write,
            Operation::Sign => self.sign,
        }
    }
}

/// A compiled subject matcher. Every facet that is `Some` must match (AND). All `None` matches any reader.
#[derive(Debug, Clone, Default)]
pub struct SubjectMatch {
    /// Code-signing team (compiled/GUI apps; stable across helpers).
    pub team_id: Option<String>,
    /// Code-signing bundle id (finer than team).
    pub bundle_id: Option<String>,
    /// Glob over the reader's executable path. `*` does not cross `/`; use `**/foo` to match a basename.
    pub exe_glob: Option<GlobMatcher>,
    /// Git repo root the reader runs from (for interpreters). Compared for equality.
    pub repo: Option<String>,
    /// The reader's cwd must start with this prefix.
    pub cwd_prefix: Option<String>,
}

impl SubjectMatch {
    /// True if every set facet matches this identity. `repo` is the reader's derived git root, if any.
    pub fn matches(&self, id: &ProcessIdentity, repo: Option<&str>) -> bool {
        if let Some(t) = &self.team_id {
            if id.team_id.as_deref() != Some(t.as_str()) {
                return false;
            }
        }
        if let Some(b) = &self.bundle_id {
            if id.bundle_id.as_deref() != Some(b.as_str()) {
                return false;
            }
        }
        if let Some(g) = &self.exe_glob {
            match &id.exe_path {
                Some(p) if g.is_match(p) => {}
                _ => return false,
            }
        }
        if let Some(r) = &self.repo {
            if repo != Some(r.as_str()) {
                return false;
            }
        }
        if let Some(prefix) = &self.cwd_prefix {
            match &id.cwd {
                Some(cwd) if cwd.starts_with(prefix) => {}
                _ => return false,
            }
        }
        true
    }
}

/// Trusted object metadata selected by the runtime for one authorization request.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleObject<'a> {
    pub resource_id: Option<&'a str>,
}

/// Object facets matched by one rule. Every `Some` facet is combined with the subject and path
/// using AND; `None` remains a wildcard.
#[derive(Debug, Clone, Default)]
pub struct ObjectMatch {
    pub resource_id: Option<String>,
}

impl ObjectMatch {
    fn matches(&self, object: RuleObject<'_>) -> bool {
        self.resource_id
            .as_deref()
            .is_none_or(|resource_id| object.resource_id == Some(resource_id))
    }
}

/// Complete input to one rule-engine decision.
#[derive(Debug, Clone, Copy)]
pub struct RuleRequest<'a> {
    pub identity: &'a ProcessIdentity,
    pub path: &'a str,
    pub repo: Option<&'a str>,
    pub operation: Operation,
    pub object: RuleObject<'a>,
}

/// One policy rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    /// Higher priority is evaluated first.
    pub priority: i32,
    pub subject: SubjectMatch,
    pub object: ObjectMatch,
    /// Glob over the virtual path, e.g. `env/*/prod.env`.
    pub path_glob: GlobMatcher,
    /// Which operations this rule applies to (config defaults to read-only).
    pub ops: RuleOps,
    pub enforcement: Enforcement,
    pub enabled: bool,
}

/// An ordered set of rules, evaluated first-match by descending priority.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Build a rule set. Rules are stably sorted by descending priority; equal priority keeps
    /// insertion order, so callers can insert more-authoritative rules first to win ties.
    pub fn new(mut rules: Vec<Rule>) -> Self {
        rules.sort_by_key(|rule| Reverse(rule.priority));
        RuleSet { rules }
    }

    /// Decide enforcement for one typed request. Returns the matched rule's
    /// enforcement and id. If nothing matches, **fail closed**: config appends a read
    /// catch-all, so this is reachable only for operations no rule opted into — the visible
    /// catch-all expresses monitor-mode allow, a hidden default must not.
    pub fn decide(&self, request: &RuleRequest<'_>) -> (Enforcement, Option<String>) {
        for r in &self.rules {
            if r.enabled
                && r.ops.matches(request.operation)
                && r.path_glob.is_match(request.path)
                && r.subject.matches(request.identity, request.repo)
                && r.object.matches(request.object)
            {
                return (r.enforcement, Some(r.id.clone()));
            }
        }
        (Enforcement::Deny, Some("default-deny".to_string()))
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Build a fresh ordered set from these base rules plus runtime-synthesized rules.
    pub fn with_additional(&self, additional: Vec<Rule>) -> Self {
        let mut rules = self.rules.clone();
        rules.extend(additional);
        RuleSet::new(rules)
    }
}

/// Compile a glob pattern into a matcher.
pub fn compile_glob(pattern: &str) -> std::result::Result<GlobMatcher, globset::Error> {
    Ok(Glob::new(pattern)?.compile_matcher())
}

/// Matcher for one exact literal path (glob metacharacters escaped).
pub fn exact_path_glob(path: &str) -> GlobMatcher {
    compile_glob(&globset::escape(path)).expect("an escaped literal is always a valid glob")
}

/// Matcher for any path.
pub fn any_path_glob() -> GlobMatcher {
    compile_glob("**").expect("`**` is a valid glob")
}

/// Walk up from `cwd` to the nearest git checkout, returning its root path as a stable repo id.
/// `.git` may be a directory (normal clone) or a file (worktree/submodule), so test for existence.
pub fn repo_root(cwd: &Path) -> Option<String> {
    let mut dir = cwd;
    loop {
        if dir.join(".git").exists() {
            return Some(dir.to_string_lossy().into_owned());
        }
        dir = dir.parent()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ident(exe: &str, team: Option<&str>) -> ProcessIdentity {
        let mut id = ProcessIdentity::bare(42, 501, 20);
        id.exe_path = Some(PathBuf::from(exe));
        id.team_id = team.map(String::from);
        id
    }

    fn rule(id: &str, priority: i32, subject: SubjectMatch, path: &str, enf: Enforcement) -> Rule {
        Rule {
            id: id.to_string(),
            priority,
            subject,
            object: ObjectMatch::default(),
            path_glob: compile_glob(path).unwrap(),
            ops: RuleOps::READ,
            enforcement: enf,
            enabled: true,
        }
    }

    fn decide(
        set: &RuleSet,
        identity: &ProcessIdentity,
        path: &str,
        repo: Option<&str>,
        operation: Operation,
    ) -> (Enforcement, Option<String>) {
        set.decide(&RuleRequest {
            identity,
            path,
            repo,
            operation,
            object: RuleObject::default(),
        })
    }

    #[test]
    fn first_match_by_priority_wins() {
        let set = RuleSet::new(vec![
            rule("low", 0, SubjectMatch::default(), "**", Enforcement::Allow),
            rule("high", 100, SubjectMatch::default(), "env/**", Enforcement::Deny),
        ]);
        let id = ident("/usr/bin/cat", None);
        let (enf, matched) = decide(&set, &id, "env/demo/dev.env", None, Operation::Read);
        assert_eq!(enf, Enforcement::Deny);
        assert_eq!(matched.as_deref(), Some("high"));
        // A path outside the high rule falls through to the catch-all.
        let (enf, matched) = decide(&set, &id, "demo/hello.txt", None, Operation::Read);
        assert_eq!(enf, Enforcement::Allow);
        assert_eq!(matched.as_deref(), Some("low"));
    }

    #[test]
    fn subject_facets_are_anded() {
        let subject = SubjectMatch {
            team_id: Some("EQHXZ8M8AV".into()),
            exe_glob: Some(compile_glob("**/Google Chrome*").unwrap()),
            ..Default::default()
        };
        let set = RuleSet::new(vec![rule(
            "chrome",
            10,
            subject,
            "**",
            Enforcement::Prompt,
        )]);

        let chrome = ident("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", Some("EQHXZ8M8AV"));
        assert_eq!(decide(&set, &chrome, "env/x", None, Operation::Read).0, Enforcement::Prompt);

        // Right team, wrong exe -> no match, falls to the fail-closed default.
        let other = ident("/usr/bin/curl", Some("EQHXZ8M8AV"));
        assert_eq!(decide(&set, &other, "env/x", None, Operation::Read).0, Enforcement::Deny);

        // Right exe, wrong team -> no match.
        let unsigned = ident("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", None);
        assert_eq!(decide(&set, &unsigned, "env/x", None, Operation::Read).0, Enforcement::Deny);
    }

    #[test]
    fn repo_facet_matches_derived_root() {
        let subject = SubjectMatch {
            repo: Some("/Users/me/proj".into()),
            ..Default::default()
        };
        let set = RuleSet::new(vec![rule("proj", 10, subject, "**", Enforcement::TouchId)]);
        let node = ident("/usr/local/bin/node", Some("HX7739G8FX"));
        assert_eq!(decide(&set, &node, "env/x", Some("/Users/me/proj"), Operation::Read).0, Enforcement::TouchId);
        assert_eq!(decide(&set, &node, "env/x", Some("/Users/me/other"), Operation::Read).0, Enforcement::Deny);
        assert_eq!(decide(&set, &node, "env/x", None, Operation::Read).0, Enforcement::Deny);
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let mut r = rule("off", 100, SubjectMatch::default(), "**", Enforcement::Deny);
        r.enabled = false;
        let set = RuleSet::new(vec![r]);
        let (enf, matched) = decide(
            &set,
            &ident("/usr/bin/cat", None),
            "x",
            None,
            Operation::Read,
        );
        assert_eq!(enf, Enforcement::Deny);
        assert_eq!(matched.as_deref(), Some("default-deny"), "must not match the disabled rule");
    }

    #[test]
    fn read_era_rules_do_not_cover_writes() {
        // A pre-write-era config: a broad allow with no operation declared (defaults to read).
        let set = RuleSet::new(vec![rule("legacy-allow", 10, SubjectMatch::default(), "**", Enforcement::Allow)]);
        let id = ident("/usr/bin/cat", None);
        assert_eq!(decide(&set, &id, "secrets/x", None, Operation::Read).0, Enforcement::Allow);
        // The same subject writing must NOT ride the read rule: no match -> fail closed.
        let (enf, matched) = decide(&set, &id, "secrets/x", None, Operation::Write);
        assert_eq!(enf, Enforcement::Deny);
        assert_eq!(matched.as_deref(), Some("default-deny"));

        // An explicit readwrite rule covers both.
        let mut rw = rule("rw", 10, SubjectMatch::default(), "**", Enforcement::Prompt);
        rw.ops = RuleOps::READ_WRITE;
        let set = RuleSet::new(vec![rw]);
        assert_eq!(decide(&set, &id, "secrets/x", None, Operation::Write).0, Enforcement::Prompt);
        assert_eq!(decide(&set, &id, "secrets/x", None, Operation::Read).0, Enforcement::Prompt);
    }

    #[test]
    fn object_resource_facet_is_anded_and_none_is_a_wildcard() {
        let id = ident("/usr/bin/ssh", None);
        let mut resource = rule(
            "managed-resource",
            20,
            SubjectMatch::default(),
            "surfaces/**",
            Enforcement::TouchId,
        );
        resource.ops = RuleOps::SIGN;
        resource.object.resource_id = Some("fixture-key".to_string());
        let mut surface = rule(
            "managed-surface",
            10,
            SubjectMatch::default(),
            "surfaces/**",
            Enforcement::Prompt,
        );
        surface.ops = RuleOps::SIGN;
        let set = RuleSet::new(vec![surface, resource]);

        let request = |resource_id| RuleRequest {
            identity: &id,
            path: "surfaces/fixture-agent",
            repo: None,
            operation: Operation::Sign,
            object: RuleObject { resource_id },
        };
        assert_eq!(
            set.decide(&request(Some("fixture-key"))).0,
            Enforcement::TouchId
        );
        assert_eq!(
            set.decide(&request(Some("other-key"))).0,
            Enforcement::Prompt
        );
        assert_eq!(set.decide(&request(None)).0, Enforcement::Prompt);
    }

    #[test]
    fn sign_requires_an_explicit_sign_rule() {
        let id = ident("/usr/bin/ssh", None);
        let read = RuleSet::new(vec![rule(
            "legacy-read",
            10,
            SubjectMatch::default(),
            "surfaces/**",
            Enforcement::Allow,
        )]);
        assert_eq!(
            decide(&read, &id, "surfaces/agent", None, Operation::Sign),
            (Enforcement::Deny, Some("default-deny".to_string()))
        );

        let mut sign = rule(
            "sign",
            10,
            SubjectMatch::default(),
            "surfaces/**",
            Enforcement::Prompt,
        );
        sign.ops = RuleOps::SIGN;
        assert_eq!(
            decide(
                &RuleSet::new(vec![sign]),
                &id,
                "surfaces/agent",
                None,
                Operation::Sign,
            )
            .0,
            Enforcement::Prompt
        );
    }
}
