use std::io;
use std::os::unix::fs::symlink;
use std::path::{Component, Path};

use accessfs_catalog::{CatalogSnapshot, ProjectCheckoutKind, Surface, SurfaceKind};
use accessfs_core::config::SURFACES_DIR;

use crate::error::{SurfaceError, SurfaceResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceLinkState {
    Created,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceLinkRemoval {
    Missing,
    Removed,
    Preserved,
}

/// Materialize each configured file Surface at the primary checkout and every provisioned
/// worktree that selected the Surface's Environment. The mounted target remains the one canonical
/// Surface id; only project-facing links multiply.
pub fn file_surface_instances(snapshot: &CatalogSnapshot) -> SurfaceResult<Vec<Surface>> {
    let mut instances = Vec::new();
    for surface in snapshot.surfaces.iter().filter(|surface| is_file_surface(surface.kind)) {
        instances.push(surface.clone());
        let environment = snapshot
            .environments
            .iter()
            .find(|environment| environment.id == surface.environment_id)
            .ok_or_else(|| SurfaceError::CheckoutMaterialization {
                surface_id: surface.id.clone(),
                reason: format!("environment {:?} is missing", surface.environment_id),
            })?;
        let project = snapshot
            .projects
            .iter()
            .find(|project| project.id == environment.project_id)
            .ok_or_else(|| SurfaceError::CheckoutMaterialization {
                surface_id: surface.id.clone(),
                reason: format!("project {:?} is missing", environment.project_id),
            })?;
        let relative = surface.path.strip_prefix(&project.path).map_err(|_| {
            SurfaceError::CheckoutMaterialization {
                surface_id: surface.id.clone(),
                reason: format!(
                    "path {} is outside primary checkout {}",
                    surface.path.display(),
                    project.path.display()
                ),
            }
        })?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(SurfaceError::CheckoutMaterialization {
                surface_id: surface.id.clone(),
                reason: format!("relative path {} is invalid", relative.display()),
            });
        }
        for checkout in snapshot.checkouts.iter().filter(|checkout| {
            checkout.project_id == project.id
                && checkout.kind == ProjectCheckoutKind::Worktree
                && checkout.environment_id.as_deref() == Some(environment.id.as_str())
        }) {
            let mut instance = surface.clone();
            instance.path = checkout.path.join(relative);
            instances.push(instance);
        }
    }
    Ok(instances)
}

/// Ensure that a project-facing file path is a symlink to its mounted surface inode.
/// Existing files and links with a different target are never replaced.
pub fn ensure_file_surface_link(
    surface: &Surface,
    mount_path: &Path,
) -> SurfaceResult<SurfaceLinkState> {
    if !is_file_surface(surface.kind) {
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

/// Remove a project-facing link only when it still points to this exact mounted surface.
/// A real file or a link owned by something else is always preserved.
pub fn remove_file_surface_link(
    surface: &Surface,
    mount_path: &Path,
) -> SurfaceResult<SurfaceLinkRemoval> {
    if !is_file_surface(surface.kind) {
        return Ok(SurfaceLinkRemoval::Preserved);
    }
    validate_surface_id(&surface.id)?;
    let expected = mount_path.join(SURFACES_DIR).join(&surface.id);
    let metadata = match std::fs::symlink_metadata(&surface.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SurfaceLinkRemoval::Missing);
        }
        Err(source) => {
            return Err(SurfaceError::LinkIo {
                operation: "inspecting before removal",
                path: surface.path.clone(),
                source,
            });
        }
    };
    if !metadata.file_type().is_symlink() {
        return Ok(SurfaceLinkRemoval::Preserved);
    }
    let actual = std::fs::read_link(&surface.path).map_err(|source| SurfaceError::LinkIo {
        operation: "reading before removal",
        path: surface.path.clone(),
        source,
    })?;
    if actual != expected {
        return Ok(SurfaceLinkRemoval::Preserved);
    }
    std::fs::remove_file(&surface.path).map_err(|source| SurfaceError::LinkIo {
        operation: "removing",
        path: surface.path.clone(),
        source,
    })?;
    Ok(SurfaceLinkRemoval::Removed)
}

fn is_file_surface(kind: SurfaceKind) -> bool {
    matches!(
        kind,
        SurfaceKind::DotenvFile
            | SurfaceKind::DirenvFile
            | SurfaceKind::IniFile
            | SurfaceKind::EnvFileDirect
            | SurfaceKind::LinesFile
    )
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
    use accessfs_catalog::{
        CatalogSnapshot, Environment, Project, ProjectCheckout, ProjectCheckoutKind, SurfaceInput,
    };
    use std::path::PathBuf;

    fn fixture_surface(path: PathBuf) -> Surface {
        Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::DotenvFile,
            path,
            input: SurfaceInput::Bindings { binding_ids: Vec::new() },
            enforcement: accessfs_core::authz::Enforcement::Prompt,
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
    fn materializes_selected_environment_surfaces_in_each_worktree() {
        let primary = PathBuf::from("/workspace/floria");
        let development = fixture_surface(primary.join(".env"));
        let mut staging = fixture_surface(primary.join(".env.staging"));
        staging.id = "fixture-staging".to_string();
        staging.environment_id = "fixture-staging".to_string();
        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary.clone(),
            }],
            checkouts: vec![
                ProjectCheckout {
                    id: "fixture-project".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: primary,
                    environment_id: None,
                    kind: ProjectCheckoutKind::Primary,
                    git_common_dir: None,
                },
                ProjectCheckout {
                    id: "fixture-feature".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: PathBuf::from("/workspace/floria-feature"),
                    environment_id: Some("fixture-development".to_string()),
                    kind: ProjectCheckoutKind::Worktree,
                    git_common_dir: Some(PathBuf::from("/workspace/floria/.git")),
                },
            ],
            environments: vec![
                Environment {
                    id: "fixture-development".to_string(),
                    project_id: "fixture-project".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                },
                Environment {
                    id: "fixture-staging".to_string(),
                    project_id: "fixture-project".to_string(),
                    name: "Staging".to_string(),
                    position: 1,
                },
            ],
            surfaces: vec![development, staging],
            ..CatalogSnapshot::default()
        };

        let instances = file_surface_instances(&snapshot).unwrap();
        assert_eq!(
            instances
                .iter()
                .map(|surface| (surface.id.as_str(), surface.path.as_path()))
                .collect::<Vec<_>>(),
            vec![
                ("fixture-dotenv", Path::new("/workspace/floria/.env")),
                ("fixture-dotenv", Path::new("/workspace/floria-feature/.env")),
                ("fixture-staging", Path::new("/workspace/floria/.env.staging")),
            ]
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

    #[test]
    fn removal_only_unlinks_the_exact_managed_target() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let surface = fixture_surface(project.join(".env"));
        let mount = dir.path().join("mount");

        assert_eq!(
            remove_file_surface_link(&surface, &mount).unwrap(),
            SurfaceLinkRemoval::Missing
        );
        ensure_file_surface_link(&surface, &mount).unwrap();
        assert_eq!(
            remove_file_surface_link(&surface, &mount).unwrap(),
            SurfaceLinkRemoval::Removed
        );
        assert!(!surface.path.exists());

        symlink("/fixture/owned-elsewhere", &surface.path).unwrap();
        assert_eq!(
            remove_file_surface_link(&surface, &mount).unwrap(),
            SurfaceLinkRemoval::Preserved
        );
        assert_eq!(
            std::fs::read_link(&surface.path).unwrap(),
            PathBuf::from("/fixture/owned-elsewhere")
        );
    }
}
