//! Policy rule engine: `who (subject) × what (path) -> how (enforcement)`.
//!
//! Evaluation is **first-match by priority** (like pf/iptables): rules are ordered by
//! descending priority and the first enabled rule whose subject *and* path both match wins.
//! No "most specific wins" heuristic -- ordering is explicit and predictable.
//!
//! The hard part is the subject. A [`SubjectMatch`] is a set of optional facets combined with
//! AND: every facet that is set must match. Compiled apps are keyed by `team_id` (stable across
//! their helper processes); interpreters (`node`, `python`, ...) share their distributor's
//! `team_id`, so they must be identified by `repo` (the git checkout they run from) instead.

use std::path::Path;

use globset::{Glob, GlobMatcher};

use crate::authz::Enforcement;
use crate::identity::ProcessIdentity;

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

/// One policy rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    /// Higher priority is evaluated first.
    pub priority: i32,
    pub subject: SubjectMatch,
    /// Glob over the virtual path, e.g. `env/*/prod.env`.
    pub path_glob: GlobMatcher,
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
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        RuleSet { rules }
    }

    /// Decide enforcement for `id` reading `path`. Returns the matched rule's enforcement and id.
    /// Falls back to `Allow` with no rule id if nothing matches (config always appends a catch-all).
    pub fn decide(
        &self,
        id: &ProcessIdentity,
        path: &str,
        repo: Option<&str>,
    ) -> (Enforcement, Option<String>) {
        for r in &self.rules {
            if r.enabled && r.path_glob.is_match(path) && r.subject.matches(id, repo) {
                return (r.enforcement, Some(r.id.clone()));
            }
        }
        (Enforcement::Allow, None)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
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
            path_glob: compile_glob(path).unwrap(),
            enforcement: enf,
            enabled: true,
        }
    }

    #[test]
    fn first_match_by_priority_wins() {
        let set = RuleSet::new(vec![
            rule("low", 0, SubjectMatch::default(), "**", Enforcement::Allow),
            rule("high", 100, SubjectMatch::default(), "env/**", Enforcement::Deny),
        ]);
        let id = ident("/usr/bin/cat", None);
        let (enf, matched) = set.decide(&id, "env/demo/dev.env", None);
        assert_eq!(enf, Enforcement::Deny);
        assert_eq!(matched.as_deref(), Some("high"));
        // A path outside the high rule falls through to the catch-all.
        let (enf, matched) = set.decide(&id, "demo/hello.txt", None);
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
        assert_eq!(set.decide(&chrome, "env/x", None).0, Enforcement::Prompt);

        // Right team, wrong exe -> no match, falls back to default allow.
        let other = ident("/usr/bin/curl", Some("EQHXZ8M8AV"));
        assert_eq!(set.decide(&other, "env/x", None).0, Enforcement::Allow);

        // Right exe, wrong team -> no match.
        let unsigned = ident("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", None);
        assert_eq!(set.decide(&unsigned, "env/x", None).0, Enforcement::Allow);
    }

    #[test]
    fn repo_facet_matches_derived_root() {
        let subject = SubjectMatch {
            repo: Some("/Users/me/proj".into()),
            ..Default::default()
        };
        let set = RuleSet::new(vec![rule("proj", 10, subject, "**", Enforcement::TouchId)]);
        let node = ident("/usr/local/bin/node", Some("HX7739G8FX"));
        assert_eq!(set.decide(&node, "env/x", Some("/Users/me/proj")).0, Enforcement::TouchId);
        assert_eq!(set.decide(&node, "env/x", Some("/Users/me/other")).0, Enforcement::Allow);
        assert_eq!(set.decide(&node, "env/x", None).0, Enforcement::Allow);
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let mut r = rule("off", 100, SubjectMatch::default(), "**", Enforcement::Deny);
        r.enabled = false;
        let set = RuleSet::new(vec![r]);
        assert_eq!(set.decide(&ident("/usr/bin/cat", None), "x", None).0, Enforcement::Allow);
    }
}
