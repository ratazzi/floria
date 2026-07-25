use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitCheckoutError {
    #[error("Git checkout path must be absolute: {0}")]
    RelativePath(PathBuf),
    #[error("Git metadata is missing below {0}")]
    NotGitCheckout(PathBuf),
    #[error("cannot inspect Git metadata at {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("invalid Git metadata at {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCheckoutDiscovery {
    pub common_dir: PathBuf,
    pub checkouts: Vec<DiscoveredGitCheckout>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredGitCheckout {
    pub path: PathBuf,
    pub git_primary: bool,
}

/// Discover the primary checkout and live linked worktrees using Git's metadata files only.
/// Project-controlled hooks and commands are never executed.
pub fn discover_git_checkouts(root: &Path) -> Result<GitCheckoutDiscovery, GitCheckoutError> {
    if !root.is_absolute() {
        return Err(GitCheckoutError::RelativePath(root.to_path_buf()));
    }
    let requested = canonicalize(root)?;
    let git_dir = resolve_git_dir(&requested)?;
    let common_dir = resolve_common_dir(&git_dir)?;
    let primary = primary_checkout(&common_dir)?;
    let mut paths = HashSet::from([requested, primary.clone()]);

    let worktrees = common_dir.join("worktrees");
    match fs::read_dir(&worktrees) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| GitCheckoutError::Io {
                    path: worktrees.clone(),
                    source,
                })?;
                let gitdir_file = entry.path().join("gitdir");
                let Ok(value) = fs::read_to_string(&gitdir_file) else {
                    continue;
                };
                let git_marker = resolve_metadata_path(entry.path().as_path(), value.trim());
                let Some(checkout) = git_marker.parent() else { continue };
                if checkout.is_dir() {
                    if let Ok(checkout) = fs::canonicalize(checkout) {
                        paths.insert(checkout);
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(GitCheckoutError::Io { path: worktrees, source });
        }
    }

    let mut checkouts = paths
        .into_iter()
        .map(|path| DiscoveredGitCheckout {
            git_primary: path == primary,
            path,
        })
        .collect::<Vec<_>>();
    checkouts.sort_by(|left, right| {
        right
            .git_primary
            .cmp(&left.git_primary)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(GitCheckoutDiscovery { common_dir, checkouts })
}

fn resolve_git_dir(root: &Path) -> Result<PathBuf, GitCheckoutError> {
    let marker = root.join(".git");
    let metadata = fs::symlink_metadata(&marker).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GitCheckoutError::NotGitCheckout(root.to_path_buf())
        } else {
            GitCheckoutError::Io { path: marker.clone(), source: error }
        }
    })?;
    if metadata.is_dir() {
        return canonicalize(&marker);
    }
    if !metadata.is_file() {
        return Err(GitCheckoutError::Invalid {
            path: marker,
            reason: "expected a .git directory or gitdir file".to_string(),
        });
    }
    let value = fs::read_to_string(&marker)
        .map_err(|source| GitCheckoutError::Io { path: marker.clone(), source })?;
    let git_dir = value
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("gitdir: "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GitCheckoutError::Invalid {
            path: marker.clone(),
            reason: "missing gitdir directive".to_string(),
        })?;
    canonicalize(&resolve_metadata_path(root, git_dir))
}

fn resolve_common_dir(git_dir: &Path) -> Result<PathBuf, GitCheckoutError> {
    let marker = git_dir.join("commondir");
    let value = match fs::read_to_string(&marker) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(git_dir.to_path_buf());
        }
        Err(source) => return Err(GitCheckoutError::Io { path: marker, source }),
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(GitCheckoutError::Invalid {
            path: marker,
            reason: "commondir cannot be empty".to_string(),
        });
    }
    canonicalize(&resolve_metadata_path(git_dir, value))
}

fn primary_checkout(common_dir: &Path) -> Result<PathBuf, GitCheckoutError> {
    if common_dir.file_name().is_some_and(|name| name == ".git") {
        return common_dir
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| GitCheckoutError::Invalid {
                path: common_dir.to_path_buf(),
                reason: "primary .git directory has no checkout parent".to_string(),
            });
    }
    Err(GitCheckoutError::Invalid {
        path: common_dir.to_path_buf(),
        reason: "bare repositories are not Project Checkouts".to_string(),
    })
}

fn resolve_metadata_path(base: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() { path.to_path_buf() } else { base.join(path) }
}

fn canonicalize(path: &Path) -> Result<PathBuf, GitCheckoutError> {
    fs::canonicalize(path)
        .map_err(|source| GitCheckoutError::Io { path: path.to_path_buf(), source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn discovers_primary_and_linked_worktrees_from_either_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("main");
        let feature = dir.path().join("feature");
        let common = primary.join(".git");
        let worktree_git = common.join("worktrees/feature");
        fs::create_dir_all(&worktree_git).unwrap();
        fs::create_dir(&feature).unwrap();
        fs::write(
            feature.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .unwrap();
        fs::write(worktree_git.join("commondir"), "../..\n").unwrap();
        fs::write(
            worktree_git.join("gitdir"),
            format!("{}\n", feature.join(".git").display()),
        )
        .unwrap();

        let from_primary = discover_git_checkouts(&primary).unwrap();
        let from_feature = discover_git_checkouts(&feature).unwrap();
        assert_eq!(from_primary, from_feature);
        assert_eq!(from_primary.common_dir, fs::canonicalize(common).unwrap());
        assert_eq!(
            from_primary.checkouts,
            vec![
                DiscoveredGitCheckout {
                    path: fs::canonicalize(primary).unwrap(),
                    git_primary: true,
                },
                DiscoveredGitCheckout {
                    path: fs::canonicalize(feature).unwrap(),
                    git_primary: false,
                },
            ]
        );
    }

    #[test]
    fn ignores_stale_and_malformed_worktree_entries() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("main");
        let common = primary.join(".git");
        fs::create_dir_all(common.join("worktrees/stale")).unwrap();
        fs::create_dir_all(common.join("worktrees/malformed")).unwrap();
        fs::write(
            common.join("worktrees/stale/gitdir"),
            dir.path().join("missing/.git").display().to_string(),
        )
        .unwrap();

        let discovered = discover_git_checkouts(&primary).unwrap();
        assert_eq!(discovered.checkouts.len(), 1);
        assert!(discovered.checkouts[0].git_primary);
    }

    #[test]
    fn canonicalizes_symlinked_checkout_roots() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("main");
        fs::create_dir_all(primary.join(".git")).unwrap();
        let alias = dir.path().join("alias");
        symlink(&primary, &alias).unwrap();

        let discovered = discover_git_checkouts(&alias).unwrap();
        assert_eq!(discovered.checkouts[0].path, fs::canonicalize(primary).unwrap());
    }
}
