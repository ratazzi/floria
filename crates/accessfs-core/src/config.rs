use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::authz::Enforcement;
use crate::error::{CoreError, Result};
use crate::handler::ContentHandler;

/// Raw TOML structure, deserialized directly. Validation/resolution happens in [`Config::resolve`].
#[derive(Debug, Deserialize)]
pub struct Config {
    pub mount: MountCfg,
    pub agent: Option<AgentCfg>,
    #[serde(default, rename = "file")]
    pub files: Vec<FileCfg>,
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
    pub files: Vec<FileEntry>,
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

        Ok(ResolvedConfig {
            mount_path,
            volname,
            audit_log,
            agent_socket,
            files,
        })
    }
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
