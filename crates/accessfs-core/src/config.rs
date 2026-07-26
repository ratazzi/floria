use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::authz::Enforcement;
use crate::error::{CoreError, Result};
use crate::handler::ContentHandler;
use crate::rules::{
    any_path_glob, compile_glob, exact_path_glob, ObjectMatch, Rule, RuleOps, RuleSet,
    SubjectMatch, BUILTIN_DEFAULT_PRIORITY, CATCH_ALL_PRIORITY, MANAGED_RESOURCE_PRIORITY,
};

/// Virtual directory under the mount where store-backed secrets are surfaced (`secrets/<id>`).
pub const SECRETS_DIR: &str = "secrets";
/// Virtual directory containing catalog-backed rendered surfaces (`surfaces/<id>`).
pub const SURFACES_DIR: &str = "surfaces";

/// Raw TOML structure, deserialized directly. Validation/resolution happens in [`Config::resolve`].
#[derive(Debug, Deserialize)]
pub struct Config {
    pub mount: MountCfg,
    pub agent: Option<AgentCfg>,
    pub store: Option<StoreCfg>,
    #[serde(default, rename = "file")]
    pub files: Vec<FileCfg>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleCfg>,
}

/// Raw `[[rule]]` block. Subject facets are all optional and combined with AND.
#[derive(Debug, Deserialize)]
pub struct RuleCfg {
    /// Stable id for auditing/UI. Defaults to `rule-<index>`.
    pub id: Option<String>,
    /// Higher priority is evaluated first. Defaults to 0 (same as per-file enforcement).
    pub priority: Option<i32>,
    /// Path glob this rule applies to, e.g. `env/*/prod.env`. Defaults to `**` (any path).
    pub path: Option<String>,
    /// Enforcement to apply on match: `"allow"`, `"deny"`, `"prompt"`, or `"touchid"`.
    pub enforcement: String,
    /// Which operations the rule matches: `"read"` (default), `"write"`, `"readwrite"`, or
    /// `"sign"`.
    /// Defaults to read so pre-write-era rules keep meaning "who may read what";
    /// write access is always an explicit opt-in.
    pub operation: Option<String>,
    /// Defaults to true.
    pub enabled: Option<bool>,
    pub team_id: Option<String>,
    pub bundle_id: Option<String>,
    /// Glob over the reader's executable path.
    pub exe: Option<String>,
    /// Git repo root the reader runs from.
    pub repo: Option<String>,
    /// Prefix the reader's cwd must start with.
    pub cwd_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MountCfg {
    pub path: PathBuf,
    pub volname: Option<String>,
    pub audit_log: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct AgentCfg {
    /// Override the default agent socket path.
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct StoreCfg {
    /// Root directory for encrypted secret blobs. Defaults to `~/.floria/store`.
    pub root: Option<PathBuf>,
    /// SSH private key used as the age identity. Defaults to `~/.ssh/id_ed25519`.
    pub ssh_key: Option<PathBuf>,
    /// Where the decryption key comes from: `auto` (ssh file if present, else Keychain),
    /// `ssh`, or `keychain`. Defaults to `auto`.
    pub key_source: Option<String>,
}

/// Source of the store's decryption key. `Auto` keys off the ssh private key file's presence:
/// a dev machine keeps the file and never touches the Keychain; removing the file (after
/// `keys import`) flips the machine to Keychain without a config edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKeySource {
    Auto,
    Ssh,
    Keychain,
}

#[derive(Debug, Deserialize)]
pub struct FileCfg {
    /// Virtual path relative to the mount point, e.g. `env/demo/dev.env`.
    pub path: String,
    /// Permission string, e.g. `"0444"`. Defaults to 0444. Read-only is always enforced.
    pub mode: Option<String>,
    /// Cache TTL, e.g. `"5m"`. Defaults to 0 (regenerated on every open).
    pub ttl: Option<String>,
    /// Declared size (upper bound) for script handlers. Required for scripts, ignored for constant files.
    pub size: Option<u64>,
    /// Enforcement level: `"allow"` (default, monitor), `"deny"`, or `"prompt"`.
    pub enforcement: Option<String>,
    /// Built-in constant content.
    pub content: Option<String>,
    /// argv for a local script handler.
    pub read: Option<Vec<String>>,
}

/// Validated and resolved mount config, consumed directly by the FS layer.
#[derive(Debug)]
pub struct ResolvedConfig {
    pub mount_path: PathBuf,
    pub volname: String,
    pub audit_log: PathBuf,
    /// Path to the agent's Unix socket (default or config override).
    pub agent_socket: PathBuf,
    /// Root directory for the encrypted secret store.
    pub store_root: PathBuf,
    /// SSH private key used as the store's age identity.
    pub store_ssh_key: PathBuf,
    /// Where the store's decryption key comes from.
    pub store_key_source: StoreKeySource,
    pub files: Vec<FileEntry>,
    /// Policy rules, evaluated first-match by priority. Synthesized from `[[rule]]` blocks,
    /// per-file `enforcement`, and a trailing catch-all default.
    pub rules: RuleSet,
}

/// A resolved virtual file.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Normalized relative virtual path, e.g. `env/demo/dev.env`.
    pub path: String,
    /// Path components, e.g. `["env", "demo", "dev.env"]`.
    pub components: Vec<String>,
    pub mode: u16,
    pub ttl: Duration,
    /// Enforcement level for this file.
    pub enforcement: Enforcement,
    /// `Some(n)`: declared size upper bound for a script file (reported via direct-io).
    /// `None`: constant file, size determined exactly by its content.
    pub declared_size: Option<u64>,
    pub handler: ContentHandler,
}

impl Config {
    /// Load from a TOML file and run security checks (the file must be user-owned and not group/world-writable).
    pub fn load(path: &Path) -> Result<ResolvedConfig> {
        check_secure_perms(path)?;
        let text = std::fs::read_to_string(path)?;
        let raw: Config = toml::from_str(&text)?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        raw.resolve(base_dir)
    }

    /// Validate and resolve. `base_dir` is used to resolve relative script paths (relative to the config file's directory).
    pub fn resolve(self, base_dir: &Path) -> Result<ResolvedConfig> {
        let mount_path = expand_tilde(&self.mount.path);
        if !mount_path.is_absolute() {
            return Err(CoreError::config(format!(
                "mount.path must be absolute after ~ expansion: {}",
                mount_path.display()
            )));
        }

        let audit_log = self
            .mount
            .audit_log
            .map(|p| expand_tilde(&p))
            .unwrap_or_else(|| default_audit_path(&mount_path));

        let volname = self.mount.volname.unwrap_or_else(|| "AccessFS".to_string());

        let agent_socket = self
            .agent
            .and_then(|a| a.socket)
            .map(|p| expand_tilde(&p))
            .unwrap_or_else(default_agent_socket);

        let store =
            self.store.unwrap_or(StoreCfg { root: None, ssh_key: None, key_source: None });
        let store_root = store
            .root
            .map(|p| expand_tilde(&p))
            .unwrap_or_else(default_store_root);
        let store_ssh_key = store
            .ssh_key
            .map(|p| expand_tilde(&p))
            .unwrap_or_else(default_ssh_key);
        let store_key_source = match store.key_source.as_deref() {
            None | Some("auto") => StoreKeySource::Auto,
            Some("ssh") => StoreKeySource::Ssh,
            Some("keychain") => StoreKeySource::Keychain,
            Some(other) => {
                return Err(CoreError::config(format!(
                    "store.key_source must be \"auto\", \"ssh\", or \"keychain\", got {other:?}"
                )))
            }
        };

        let mut files = Vec::with_capacity(self.files.len());
        let mut seen = std::collections::HashSet::new();
        for fc in self.files {
            let entry = resolve_file(fc, base_dir)?;
            if !seen.insert(entry.path.clone()) {
                return Err(CoreError::config(format!(
                    "duplicate virtual path: {}",
                    entry.path
                )));
            }
            files.push(entry);
        }

        let rules = build_ruleset(self.rules, &files)?;

        Ok(ResolvedConfig {
            mount_path,
            volname,
            audit_log,
            agent_socket,
            store_root,
            store_ssh_key,
            store_key_source,
            files,
            rules,
        })
    }
}

/// Assemble the rule set from three layers, most-authoritative first (ties broken by insertion order):
/// explicit `[[rule]]` blocks, then per-file `enforcement` as exact-path rules at priority 0,
/// then a single catch-all `allow` default at the lowest priority so the default is visible, not hidden.
fn build_ruleset(rule_cfgs: Vec<RuleCfg>, files: &[FileEntry]) -> Result<RuleSet> {
    let mut rules = Vec::with_capacity(rule_cfgs.len() + files.len() + 2);

    for (idx, rc) in rule_cfgs.into_iter().enumerate() {
        rules.push(resolve_rule(rc, idx)?);
    }

    for f in files {
        // Config-defined files are read-only at the FS layer, so their rules only ever see reads.
        rules.push(Rule {
            id: format!("file:{}", f.path),
            priority: 0,
            subject: SubjectMatch::default(),
            object: ObjectMatch::default(),
            path_glob: exact_path_glob(&f.path),
            ops: RuleOps::READ,
            enforcement: f.enforcement,
            enabled: true,
        });
    }

    // Store-backed secrets are prompted by default (above the catch-all, below anything explicit),
    // so protecting a file gates it even without a per-id rule. Read AND write: secrets are the
    // one writable namespace, and both directions must be gated. Tighten with an explicit `[[rule]]`.
    rules.push(Rule {
        id: "secrets-default".to_string(),
        priority: BUILTIN_DEFAULT_PRIORITY,
        subject: SubjectMatch::default(),
        object: ObjectMatch::default(),
        path_glob: compile_glob(&format!("{SECRETS_DIR}/**"))
            .expect("`secrets/**` is a valid glob"),
        ops: RuleOps::READ_WRITE,
        enforcement: Enforcement::Prompt,
        enabled: true,
    });

    // File surfaces may contain several secrets. Prompt for both operations here; the filesystem
    // capability gate still rejects writes to composed surfaces before authorization.
    rules.push(Rule {
        id: "surfaces-default".to_string(),
        priority: BUILTIN_DEFAULT_PRIORITY,
        subject: SubjectMatch::default(),
        object: ObjectMatch::default(),
        path_glob: compile_glob(&format!("{SURFACES_DIR}/**"))
            .expect("`surfaces/**` is a valid glob"),
        ops: RuleOps::READ_WRITE_SIGN,
        enforcement: Enforcement::Prompt,
        enabled: true,
    });

    // Read-only catch-all: monitor-mode allow for reads. Writes and signatures deliberately never
    // match it — either capability falling past every rule hits the fail-closed default instead.
    rules.push(Rule {
        id: "default".to_string(),
        priority: CATCH_ALL_PRIORITY,
        subject: SubjectMatch::default(),
        object: ObjectMatch::default(),
        path_glob: any_path_glob(),
        ops: RuleOps::READ,
        enforcement: Enforcement::Allow,
        enabled: true,
    });

    Ok(RuleSet::new(rules))
}

fn resolve_rule(rc: RuleCfg, idx: usize) -> Result<Rule> {
    let id = rc.id.unwrap_or_else(|| format!("rule-{idx}"));
    let priority = rc.priority.unwrap_or(0);
    if priority <= MANAGED_RESOURCE_PRIORITY {
        return Err(CoreError::config(format!(
            "rule {id}: priority must be greater than {MANAGED_RESOURCE_PRIORITY}"
        )));
    }
    let enforcement = Enforcement::parse(&rc.enforcement)
        .ok_or_else(|| CoreError::config(format!("rule {id}: invalid enforcement {:?}", rc.enforcement)))?;
    let path_glob = compile_glob(rc.path.as_deref().unwrap_or("**"))
        .map_err(|e| CoreError::config(format!("rule {id}: invalid path glob: {e}")))?;
    let exe_glob = match rc.exe {
        Some(g) => Some(
            compile_glob(&g)
                .map_err(|e| CoreError::config(format!("rule {id}: invalid exe glob: {e}")))?,
        ),
        None => None,
    };
    let subject = SubjectMatch {
        team_id: rc.team_id,
        bundle_id: rc.bundle_id,
        exe_glob,
        repo: rc.repo.map(|p| tilde_str(&p)),
        cwd_prefix: rc.cwd_prefix.map(|p| tilde_str(&p)),
    };
    let ops = match rc.operation.as_deref() {
        None => RuleOps::READ, // pre-write-era rules stay read-only; write is opt-in
        Some(s) => RuleOps::parse(s)
            .ok_or_else(|| CoreError::config(format!("rule {id}: invalid operation {s:?}")))?,
    };
    Ok(Rule {
        id,
        priority,
        subject,
        object: ObjectMatch::default(),
        path_glob,
        ops,
        enforcement,
        enabled: rc.enabled.unwrap_or(true),
    })
}

/// Expand a leading `~` and return the path as a string (for repo/cwd_prefix facets).
fn tilde_str(s: &str) -> String {
    expand_tilde(Path::new(s)).to_string_lossy().into_owned()
}

fn resolve_file(fc: FileCfg, base_dir: &Path) -> Result<FileEntry> {
    let components = normalize_virtual_path(&fc.path)?;
    let path = components.join("/");

    let mode = match fc.mode.as_deref() {
        Some(s) => parse_mode(s)?,
        None => 0o444,
    };

    let ttl = match fc.ttl.as_deref() {
        Some(s) => humantime::parse_duration(s)
            .map_err(|e| CoreError::config(format!("invalid ttl {s:?}: {e}")))?,
        None => Duration::ZERO,
    };

    let enforcement = match fc.enforcement.as_deref() {
        Some(s) => Enforcement::parse(s)
            .ok_or_else(|| CoreError::config(format!("{path}: invalid enforcement {s:?}")))?,
        None => Enforcement::default(),
    };

    let (handler, declared_size) = match (fc.content, fc.read) {
        (Some(_), Some(_)) => {
            return Err(CoreError::config(format!(
                "{path}: set exactly one of `content` or `read`, not both"
            )))
        }
        (None, None) => {
            return Err(CoreError::config(format!(
                "{path}: must set one of `content` or `read`"
            )))
        }
        (Some(content), None) => {
            let bytes = Arc::new(content.into_bytes());
            (ContentHandler::Constant(bytes), None)
        }
        (None, Some(argv)) => {
            if argv.is_empty() {
                return Err(CoreError::config(format!("{path}: `read` argv is empty")));
            }
            let size = fc.size.ok_or_else(|| {
                CoreError::config(format!("{path}: script files require `size`"))
            })?;
            // Check ownership/permissions of the script executable (relative paths resolved against the config dir).
            let exe = resolve_script_exe(&argv[0], base_dir);
            check_secure_perms(&exe)?;
            let mut resolved_argv = argv;
            resolved_argv[0] = exe.to_string_lossy().into_owned();
            (
                ContentHandler::Script {
                    argv: resolved_argv,
                },
                Some(size),
            )
        }
    };

    Ok(FileEntry {
        path,
        components,
        mode,
        ttl,
        enforcement,
        declared_size,
        handler,
    })
}

/// Normalize a virtual path: relative, no `..`, no empty components, no leading `/`.
fn normalize_virtual_path(raw: &str) -> Result<Vec<String>> {
    if raw.starts_with('/') {
        return Err(CoreError::config(format!(
            "virtual path must be relative: {raw:?}"
        )));
    }
    let mut out = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {
                return Err(CoreError::config(format!(
                    "virtual path has empty component: {raw:?}"
                )))
            }
            ".." => {
                return Err(CoreError::config(format!(
                    "virtual path must not contain `..`: {raw:?}"
                )))
            }
            other => out.push(other.to_string()),
        }
    }
    if out.is_empty() {
        return Err(CoreError::config("virtual path is empty".to_string()));
    }
    Ok(out)
}

fn parse_mode(s: &str) -> Result<u16> {
    let trimmed = s.trim_start_matches("0o");
    u16::from_str_radix(trimmed, 8)
        .map_err(|e| CoreError::config(format!("invalid mode {s:?}: {e}")))
}

fn resolve_script_exe(arg0: &str, base_dir: &Path) -> PathBuf {
    let p = expand_tilde(Path::new(arg0));
    if p.is_absolute() {
        p
    } else {
        base_dir.join(p)
    }
}

/// Expand a leading `~` in the path to `$HOME`.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if s == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    path.to_path_buf()
}

/// Default agent socket: `~/Library/Application Support/floria/agent.sock`.
fn default_agent_socket() -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("Library/Application Support/floria/agent.sock")
}

/// Default secret store root: `~/.floria/store`.
fn default_store_root() -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(".floria/store")
}

/// Default age identity: the user's SSH ed25519 key.
fn default_ssh_key() -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(".ssh/id_ed25519")
}

fn default_audit_path(mount_path: &Path) -> PathBuf {
    // Place the audit log next to the mount point, so it isn't written into the virtual volume itself.
    let name = mount_path
        .file_name()
        .map(|n| format!("{}.audit.jsonl", n.to_string_lossy()))
        .unwrap_or_else(|| "accessfs.audit.jsonl".to_string());
    mount_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

/// Security check: the file must be owned by the current user and must not be group/world-writable.
pub fn check_secure_perms(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path).map_err(|e| CoreError::InsecurePerms {
        path: path.to_path_buf(),
        reason: format!("stat failed: {e}"),
    })?;

    // SAFETY: geteuid takes no args, has no side effects, and POSIX guarantees it always succeeds.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(CoreError::InsecurePerms {
            path: path.to_path_buf(),
            reason: format!("owned by uid {}, not current euid {}", meta.uid(), euid),
        });
    }

    if meta.mode() & 0o022 != 0 {
        return Err(CoreError::InsecurePerms {
            path: path.to_path_buf(),
            reason: format!("group/world writable (mode {:04o})", meta.mode() & 0o7777),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleObject, RuleRequest};
    use crate::authz::Operation;
    use crate::identity::ProcessIdentity;

    #[test]
    fn rejects_parent_traversal() {
        assert!(normalize_virtual_path("env/../etc/passwd").is_err());
        assert!(normalize_virtual_path("/abs/path").is_err());
        assert!(normalize_virtual_path("a//b").is_err());
    }

    #[test]
    fn splits_components() {
        assert_eq!(
            normalize_virtual_path("env/demo/dev.env").unwrap(),
            vec!["env", "demo", "dev.env"]
        );
    }

    #[test]
    fn parses_store_key_source() {
        let resolve = |body: &str| {
            toml::from_str::<Config>(&format!(
                "[mount]\npath = \"/tmp/fixture-mount\"\n{body}"
            ))
            .unwrap()
            .resolve(Path::new("/tmp"))
        };
        assert_eq!(resolve("").unwrap().store_key_source, StoreKeySource::Auto);
        assert_eq!(
            resolve("[store]\nkey_source = \"auto\"").unwrap().store_key_source,
            StoreKeySource::Auto
        );
        assert_eq!(
            resolve("[store]\nkey_source = \"ssh\"").unwrap().store_key_source,
            StoreKeySource::Ssh
        );
        assert_eq!(
            resolve("[store]\nkey_source = \"keychain\"").unwrap().store_key_source,
            StoreKeySource::Keychain
        );
        assert!(resolve("[store]\nkey_source = \"vault\"").is_err());
    }

    #[test]
    fn parses_octal_mode() {
        assert_eq!(parse_mode("0444").unwrap(), 0o444);
        assert_eq!(parse_mode("600").unwrap(), 0o600);
        assert_eq!(parse_mode("0o640").unwrap(), 0o640);
        assert!(parse_mode("999").is_err());
    }

    #[test]
    fn constant_file_resolves_without_size() {
        let fc = FileCfg {
            path: "demo/hello.txt".to_string(),
            mode: None,
            ttl: None,
            size: None,
            enforcement: None,
            content: Some("hi\n".to_string()),
            read: None,
        };
        let entry = resolve_file(fc, Path::new(".")).unwrap();
        assert_eq!(entry.declared_size, None);
        assert_eq!(entry.mode, 0o444);
        assert_eq!(entry.ttl, Duration::ZERO);
    }

    #[test]
    fn script_file_requires_size() {
        let fc = FileCfg {
            path: "env/x.env".to_string(),
            mode: None,
            ttl: None,
            size: None,
            enforcement: None,
            content: None,
            read: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        };
        assert!(resolve_file(fc, Path::new(".")).is_err());
    }

    fn rule_cfg(id: &str, path: &str, enforcement: &str) -> RuleCfg {
        RuleCfg {
            id: Some(id.to_string()),
            priority: None,
            path: Some(path.to_string()),
            enforcement: enforcement.to_string(),
            operation: None,
            enabled: None,
            team_id: None,
            bundle_id: None,
            exe: None,
            repo: None,
            cwd_prefix: None,
        }
    }

    fn decide(
        rules: &RuleSet,
        identity: &ProcessIdentity,
        path: &str,
        operation: Operation,
    ) -> (Enforcement, Option<String>) {
        rules.decide(&RuleRequest {
            identity,
            path,
            repo: None,
            operation,
            object: RuleObject::default(),
        })
    }

    #[test]
    fn builds_ruleset_with_explicit_file_and_default_layers() {
        let file = resolve_file(
            FileCfg {
                path: "env/demo/dev.env".to_string(),
                mode: None,
                ttl: None,
                size: None,
                enforcement: Some("prompt".to_string()),
                content: Some("x".to_string()),
                read: None,
            },
            Path::new("."),
        )
        .unwrap();

        let rules = build_ruleset(
            vec![rule_cfg("prod", "env/*/prod.env", "deny")],
            std::slice::from_ref(&file),
        )
        .unwrap();

        // explicit rule + one per-file rule + two protected namespaces + catch-all
        assert_eq!(rules.len(), 5);

        // any secrets/<id> path is prompted by the built-in rule — for reads AND writes
        let id = ProcessIdentity::bare(1, 501, 20);
        assert_eq!(
            decide(&rules, &id, "secrets/abc-123", Operation::Read),
            (Enforcement::Prompt, Some("secrets-default".to_string()))
        );
        assert_eq!(
            decide(&rules, &id, "secrets/abc-123", Operation::Write),
            (Enforcement::Prompt, Some("secrets-default".to_string()))
        );

        // surfaces are gated for both operations; the filesystem decides which kinds are writable
        assert_eq!(
            decide(&rules, &id, "surfaces/fixture-dotenv", Operation::Read),
            (Enforcement::Prompt, Some("surfaces-default".to_string()))
        );
        assert_eq!(
            decide(&rules, &id, "surfaces/fixture-dotenv", Operation::Write),
            (Enforcement::Prompt, Some("surfaces-default".to_string()))
        );

        // explicit deny rule wins for prod
        assert_eq!(
            decide(&rules, &id, "env/svc/prod.env", Operation::Read),
            (Enforcement::Deny, Some("prod".to_string()))
        );
        // per-file prompt applies to dev.env
        assert_eq!(
            decide(&rules, &id, "env/demo/dev.env", Operation::Read),
            (Enforcement::Prompt, Some("file:env/demo/dev.env".to_string()))
        );
        // reads on anything else fall through to the visible catch-all allow...
        assert_eq!(
            decide(&rules, &id, "demo/hello.txt", Operation::Read),
            (Enforcement::Allow, Some("default".to_string()))
        );
        // ...but writes never ride the read catch-all: unmatched writes fail closed.
        assert_eq!(
            decide(&rules, &id, "demo/hello.txt", Operation::Write),
            (Enforcement::Deny, Some("default-deny".to_string()))
        );
    }

    #[test]
    fn rule_operation_parses_and_rejects_garbage() {
        let mut rc = rule_cfg("w", "secrets/**", "allow");
        rc.operation = Some("write".to_string());
        let rules = build_ruleset(vec![rc], &[]).unwrap();
        let id = ProcessIdentity::bare(1, 501, 20);
        // write-only allow matches writes, not reads (reads fall to secrets-default prompt)
        assert_eq!(
            decide(&rules, &id, "secrets/abc", Operation::Write),
            (Enforcement::Allow, Some("w".to_string()))
        );
        assert_eq!(
            decide(&rules, &id, "secrets/abc", Operation::Read),
            (Enforcement::Prompt, Some("secrets-default".to_string()))
        );

        let mut bad = rule_cfg("bad", "**", "allow");
        bad.operation = Some("readwrite-ish".to_string());
        assert!(build_ruleset(vec![bad], &[]).is_err());
    }

    #[test]
    fn explicit_rule_priority_must_stay_above_managed_policy() {
        let mut reserved = rule_cfg("reserved", "**", "allow");
        reserved.priority = Some(MANAGED_RESOURCE_PRIORITY);
        assert!(build_ruleset(vec![reserved], &[]).is_err());

        let mut explicit = rule_cfg("explicit", "**", "allow");
        explicit.priority = Some(MANAGED_RESOURCE_PRIORITY + 1);
        assert!(build_ruleset(vec![explicit], &[]).is_ok());
    }

    #[test]
    fn rejects_invalid_rule() {
        assert!(build_ruleset(vec![rule_cfg("bad", "**", "yolo")], &[]).is_err());
        assert!(build_ruleset(vec![rule_cfg("bad", "env/[", "deny")], &[]).is_err());
    }

    #[test]
    fn rejects_both_content_and_read() {
        let fc = FileCfg {
            path: "x".to_string(),
            mode: None,
            ttl: None,
            size: Some(10),
            enforcement: None,
            content: Some("a".to_string()),
            read: Some(vec!["/bin/echo".to_string()]),
        };
        assert!(resolve_file(fc, Path::new(".")).is_err());
    }
}
