use std::io;
use std::os::unix::fs::symlink;
use std::path::{Component, Path};

use accessfs_catalog::{Surface, SurfaceKind};
use accessfs_core::config::SURFACES_DIR;

use crate::error::{SurfaceError, SurfaceResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceLinkState {
    Created,
    Ready,
}

/// Ensure that a project-facing file path is a symlink to its mounted surface inode.
/// Existing files and links with a different target are never replaced.
pub fn ensure_file_surface_link(
    surface: &Surface,
    mount_path: &Path,
) -> SurfaceResult<SurfaceLinkState> {
    if !matches!(surface.kind, SurfaceKind::DotenvFile | SurfaceKind::EnvFileDirect) {
        return Err(SurfaceError::UnsupportedSurface {
            surface_id: surface.id.clone(),
            kind: format!("{:?}", surface.kind),
        });
    }
    validate_surface_id(&surface.id)?;
    let expected = mount_path.join(SURFACES_DIR).join(&surface.id);

    match std::fs::symlink_metadata(&surface.path) {
        Ok(metadata) => validate_existing_link(&surface.path, &expected, metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_link(&surface.path, &expected)
        }
        Err(source) => Err(SurfaceError::LinkIo {
            operation: "inspecting",
            path: surface.path.clone(),
            source,
        }),
    }
}

fn validate_surface_id(id: &str) -> SurfaceResult<()> {
    let mut components = Path::new(id).components();
    let valid_component = matches!(components.next(), Some(Component::Normal(component)) if component == id);
    let valid_chars = id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
    if !id.is_empty() && valid_component && components.next().is_none() && valid_chars {
        Ok(())
    } else {
        Err(SurfaceError::InvalidSurfaceId(id.to_string()))
    }
}

fn create_link(path: &Path, expected: &Path) -> SurfaceResult<SurfaceLinkState> {
    match symlink(expected, path) {
        Ok(()) => Ok(SurfaceLinkState::Created),
        // Another process may have created the path after the lstat. Re-inspect it and only
        // accept the exact link we wanted.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path).map_err(|source| {
                SurfaceError::LinkIo {
                    operation: "inspecting concurrently-created",
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            validate_existing_link(path, expected, metadata)
        }
        Err(source) => Err(SurfaceError::LinkIo {
            operation: "creating",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_existing_link(
    path: &Path,
    expected: &Path,
    metadata: std::fs::Metadata,
) -> SurfaceResult<SurfaceLinkState> {
    if !metadata.file_type().is_symlink() {
        return Err(link_conflict(path, expected, "an existing non-symlink occupies the path"));
    }
    let actual = std::fs::read_link(path).map_err(|source| SurfaceError::LinkIo {
        operation: "reading",
        path: path.to_path_buf(),
        source,
    })?;
    if actual == expected {
        Ok(SurfaceLinkState::Ready)
    } else {
        Err(link_conflict(
            path,
            expected,
            format!("existing symlink points to {}", actual.display()),
        ))
    }
}

fn link_conflict(path: &Path, expected: &Path, reason: impl Into<String>) -> SurfaceError {
    SurfaceError::LinkConflict {
        path: path.to_path_buf(),
        expected: expected.to_path_buf(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_surface(path: PathBuf) -> Surface {
        Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::DotenvFile,
            path,
            resource_id: None,
            position: 0,
        }
    }

    #[test]
    fn creates_project_link_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let surface = fixture_surface(project.join(".env"));
        let mount = dir.path().join("mount");
        let expected = mount.join(SURFACES_DIR).join("fixture-dotenv");

        assert_eq!(
            ensure_file_surface_link(&surface, &mount).unwrap(),
            SurfaceLinkState::Created
        );
        assert_eq!(std::fs::read_link(&surface.path).unwrap(), expected);
        assert_eq!(
            ensure_file_surface_link(&surface, &mount).unwrap(),
            SurfaceLinkState::Ready
        );
    }

    #[test]
    fn refuses_to_replace_existing_file_or_different_link() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let surface = fixture_surface(project.join(".env"));
        let mount = dir.path().join("mount");

        std::fs::write(&surface.path, b"FIXTURE=local\n").unwrap();
        assert!(matches!(
            ensure_file_surface_link(&surface, &mount),
            Err(SurfaceError::LinkConflict { .. })
        ));
        assert_eq!(std::fs::read(&surface.path).unwrap(), b"FIXTURE=local\n");

        std::fs::remove_file(&surface.path).unwrap();
        symlink("/fixture/different-target", &surface.path).unwrap();
        assert!(matches!(
            ensure_file_surface_link(&surface, &mount),
            Err(SurfaceError::LinkConflict { .. })
        ));
        assert_eq!(
            std::fs::read_link(&surface.path).unwrap(),
            PathBuf::from("/fixture/different-target")
        );
    }

    #[test]
    fn rejects_surface_id_that_is_not_one_safe_path_component() {
        let dir = tempfile::tempdir().unwrap();
        let mut surface = fixture_surface(dir.path().join(".env"));
        surface.id = "../fixture-dotenv".to_string();
        assert!(matches!(
            ensure_file_surface_link(&surface, dir.path()),
            Err(SurfaceError::InvalidSurfaceId(_))
        ));
        assert!(!surface.path.exists());
    }
}
