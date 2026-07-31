use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use floria_catalog::{
    CatalogSnapshot, ProjectCheckout, ProjectCheckoutKind, Surface, SurfaceKind,
};
use floria_core::config::{SECRETS_DIR, SURFACES_DIR};
use floria_store::{SecretRecord, SecretStore};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedLinkStatus {
    Ready,
    Missing,
    Replaced,
}

/// One desired project-facing symbolic link.
///
/// Callers only identify the path they care about. Target derivation, health
/// inspection, and safe repair remain behind this module's interface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ManagedSymlink {
    path: PathBuf,
    expected: PathBuf,
}

enum ManagedLinkInspection {
    Ready,
    Missing,
    ForeignSymlink(PathBuf),
    Occupied,
}

impl ManagedSymlink {
    pub fn new(path: impl Into<PathBuf>, expected: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), expected: expected.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn expected_target(&self) -> &Path {
        &self.expected
    }

    pub fn status(&self) -> SurfaceResult<ManagedLinkStatus> {
        Ok(match self.inspect()? {
            ManagedLinkInspection::Ready => ManagedLinkStatus::Ready,
            ManagedLinkInspection::Missing => ManagedLinkStatus::Missing,
            ManagedLinkInspection::ForeignSymlink(_) | ManagedLinkInspection::Occupied => {
                ManagedLinkStatus::Replaced
            }
        })
    }

    pub fn is_ready(&self) -> SurfaceResult<bool> {
        self.status().map(|status| status == ManagedLinkStatus::Ready)
    }

    fn ensure(&self) -> SurfaceResult<SurfaceLinkState> {
        match self.inspect()? {
            ManagedLinkInspection::Ready => Ok(SurfaceLinkState::Ready),
            ManagedLinkInspection::Missing => create_link(&self.path, &self.expected),
            ManagedLinkInspection::ForeignSymlink(actual) => Err(link_conflict(
                &self.path,
                &self.expected,
                format!("existing symlink points to {}", actual.display()),
            )),
            ManagedLinkInspection::Occupied => Err(link_conflict(
                &self.path,
                &self.expected,
                "an existing non-symlink occupies the path",
            )),
        }
    }

    /// Repair this explicitly selected link without ever replacing a regular file.
    pub fn repair(&self) -> SurfaceResult<SurfaceLinkState> {
        match self.inspect()? {
            ManagedLinkInspection::Ready => Ok(SurfaceLinkState::Ready),
            ManagedLinkInspection::Missing => {
                if let Some(parent) = self.path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(|source| {
                            SurfaceError::LinkIo {
                                operation: "creating containing directory",
                                path: parent.to_path_buf(),
                                source,
                            }
                        })?;
                    }
                }
                create_link(&self.path, &self.expected)
            }
            ManagedLinkInspection::ForeignSymlink(_) => {
                replace_file_with_symlink(&self.path, &self.expected).map_err(|source| {
                    SurfaceError::LinkIo {
                        operation: "repairing",
                        path: self.path.clone(),
                        source,
                    }
                })?;
                Ok(SurfaceLinkState::Created)
            }
            ManagedLinkInspection::Occupied => Err(link_conflict(
                &self.path,
                &self.expected,
                "an existing file occupies the path; move it aside before repairing",
            )),
        }
    }

    fn inspect(&self) -> SurfaceResult<ManagedLinkInspection> {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ManagedLinkInspection::Missing);
            }
            Err(source) => {
                return Err(SurfaceError::LinkIo {
                    operation: "inspecting",
                    path: self.path.clone(),
                    source,
                });
            }
        };
        if !metadata.file_type().is_symlink() {
            return Ok(ManagedLinkInspection::Occupied);
        }
        let actual = std::fs::read_link(&self.path).map_err(|source| SurfaceError::LinkIo {
            operation: "reading",
            path: self.path.clone(),
            source,
        })?;
        Ok(if actual == self.expected {
            ManagedLinkInspection::Ready
        } else {
            ManagedLinkInspection::ForeignSymlink(actual)
        })
    }
}

/// Materialize each configured file Surface at the primary checkout and every provisioned
/// worktree that selected the Surface's Environment. The mounted target remains the one canonical
/// Surface id; only project-facing links multiply.
pub fn file_surface_instances(snapshot: &CatalogSnapshot) -> SurfaceResult<Vec<Surface>> {
    let mut instances = Vec::new();
    for surface in snapshot.surfaces.iter().filter(|surface| is_file_surface(surface.kind)) {
        instances.push(surface.clone());
        let surface_path = file_surface_path(surface)?;
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
        let relative = surface_path.strip_prefix(&project.path).map_err(|_| {
            SurfaceError::CheckoutMaterialization {
                surface_id: surface.id.clone(),
                reason: format!(
                    "path {} is outside primary checkout {}",
                    surface_path.display(),
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
            instance.path = Some(checkout.path.join(relative));
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
    let path = file_surface_path(surface)?;
    let expected = mount_path.join(SURFACES_DIR).join(&surface.id);
    ManagedSymlink::new(path, expected).ensure()
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
    let path = file_surface_path(surface)?;
    let expected = mount_path.join(SURFACES_DIR).join(&surface.id);
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(SurfaceLinkRemoval::Missing);
        }
        Err(source) => {
            return Err(SurfaceError::LinkIo {
                operation: "inspecting before removal",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.file_type().is_symlink() {
        return Ok(SurfaceLinkRemoval::Preserved);
    }
    let actual = std::fs::read_link(path).map_err(|source| SurfaceError::LinkIo {
        operation: "reading before removal",
        path: path.to_path_buf(),
        source,
    })?;
    if actual != expected {
        return Ok(SurfaceLinkRemoval::Preserved);
    }
    std::fs::remove_file(path).map_err(|source| SurfaceError::LinkIo {
        operation: "removing",
        path: path.to_path_buf(),
        source,
    })?;
    Ok(SurfaceLinkRemoval::Removed)
}

fn is_file_surface(kind: SurfaceKind) -> bool {
    kind.is_file()
}

fn file_surface_path(surface: &Surface) -> SurfaceResult<&Path> {
    surface.path.as_deref().ok_or_else(|| SurfaceError::CheckoutMaterialization {
        surface_id: surface.id.clone(),
        reason: "file surface has no project path".to_string(),
    })
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
            ManagedSymlink::new(path, expected).ensure()
        }
        Err(source) => Err(SurfaceError::LinkIo {
            operation: "creating",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn link_conflict(path: &Path, expected: &Path, reason: impl Into<String>) -> SurfaceError {
    SurfaceError::LinkConflict {
        path: path.to_path_buf(),
        expected: expected.to_path_buf(),
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtectedCheckoutLink {
    secret_id: floria_store::SecretId,
    path: PathBuf,
    target: PathBuf,
    mode: u32,
    current_version: u32,
}

/// Build the desired protected-file links for managed worktrees. A file belongs
/// to exactly one project: the deepest project path that contains its original
/// source, matching discovery's nested-project assignment rule.
pub fn protected_checkout_links(
    snapshot: &CatalogSnapshot,
    records: &[SecretRecord],
    mount_path: &Path,
) -> Vec<ProtectedCheckoutLink> {
    let configured_paths = file_surface_instances(snapshot)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|surface| surface.path)
        .collect::<HashSet<_>>();
    protected_checkout_links_excluding(snapshot, records, mount_path, &configured_paths)
}

/// Resolve every file-backed Managed item's desired project-facing link.
///
/// This is the single source of truth used by health reporting, worktree
/// inspection, and explicit repair.
pub fn managed_file_links(
    snapshot: &CatalogSnapshot,
    records: &[SecretRecord],
    mount_path: &Path,
) -> SurfaceResult<Vec<ManagedSymlink>> {
    let surfaces = file_surface_instances(snapshot)?;
    let configured_secret_ids = snapshot.file_surface_secret_ids();
    let mut links = BTreeMap::<PathBuf, PathBuf>::new();

    for surface in surfaces {
        let path = file_surface_path(&surface)?.to_path_buf();
        insert_managed_link(
            &mut links,
            path,
            mount_path.join(SURFACES_DIR).join(surface.id),
        )?;
    }
    for record in records.iter().filter(|record| {
        !configured_secret_ids.contains(record.id.as_str()) && record.source_path().is_some()
    }) {
        insert_managed_link(
            &mut links,
            record.source_path().expect("filtered file origin").to_path_buf(),
            mount_path.join(SECRETS_DIR).join(record.id.to_string()),
        )?;
    }
    for link in protected_checkout_links(snapshot, records, mount_path) {
        insert_managed_link(&mut links, link.path, link.target)?;
    }

    Ok(links
        .into_iter()
        .map(|(path, expected)| ManagedSymlink::new(path, expected))
        .collect())
}

fn insert_managed_link(
    links: &mut BTreeMap<PathBuf, PathBuf>,
    path: PathBuf,
    expected: PathBuf,
) -> SurfaceResult<()> {
    if let Some(existing) = links.insert(path.clone(), expected.clone()) {
        if existing != expected {
            return Err(link_conflict(
                &path,
                &expected,
                format!("catalog also resolves this path to {}", existing.display()),
            ));
        }
    }
    Ok(())
}

/// Inspect every project-facing file that a managed worktree should expose.
/// This is read-only: foreign links, divergent files, and missing paths are
/// reported to callers instead of being replaced.
pub fn checkout_link_issues(
    snapshot: &CatalogSnapshot,
    records: &[SecretRecord],
    mount_path: &Path,
    checkout: &ProjectCheckout,
) -> SurfaceResult<Vec<PathBuf>> {
    if checkout.kind != ProjectCheckoutKind::Worktree {
        return Ok(Vec::new());
    }

    let mut issues = Vec::new();
    for link in managed_file_links(snapshot, records, mount_path)?
        .into_iter()
        .filter(|link| link.path().starts_with(&checkout.path))
    {
        if !link.is_ready()? {
            issues.push(link.path);
        }
    }
    Ok(issues)
}

fn protected_checkout_links_excluding(
    snapshot: &CatalogSnapshot,
    records: &[SecretRecord],
    mount_path: &Path,
    excluded_paths: &HashSet<PathBuf>,
) -> Vec<ProtectedCheckoutLink> {
    let mut links = Vec::new();
    for record in records {
        let Some(source) = record.source_path() else { continue };
        let Some(project) = snapshot
            .projects
            .iter()
            .filter(|project| source.starts_with(&project.path))
            .max_by_key(|project| project.path.components().count())
        else {
            continue;
        };
        let Ok(relative) = source.strip_prefix(&project.path) else { continue };
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            continue;
        }
        let target = mount_path.join(SECRETS_DIR).join(record.id.to_string());
        for checkout in snapshot.checkouts.iter().filter(|checkout| {
            checkout.kind == ProjectCheckoutKind::Worktree
                && checkout.project_id == project.id
                && record.environment_ids.as_ref().is_none_or(|environment_ids| {
                    checkout
                        .environment_id
                        .as_ref()
                        .is_some_and(|id| environment_ids.contains(id))
                })
        }) {
            let path = checkout.path.join(relative);
            if excluded_paths.contains(&path) {
                continue;
            }
            links.push(ProtectedCheckoutLink {
                secret_id: record.id.clone(),
                path,
                target: target.clone(),
                mode: record.mode,
                current_version: record.current_version,
            });
        }
    }
    links.sort_by(|left, right| {
        left.secret_id
            .as_str()
            .cmp(right.secret_id.as_str())
            .then_with(|| left.path.cmp(&right.path))
    });
    links
}

/// Release an exact protected-file worktree link when a configured file Surface now owns the
/// same path. Foreign links and divergent regular files are preserved. Call this before
/// reconciling file Surface links so the transition never restores plaintext between models.
pub fn release_protected_links_for_file_surfaces(
    snapshot: &CatalogSnapshot,
    records: &[SecretRecord],
    surfaces: &[Surface],
    mount_path: &Path,
) -> io::Result<bool> {
    let surfaced_paths = surfaces
        .iter()
        .filter_map(|surface| surface.path.clone())
        .collect::<HashSet<_>>();
    let candidates =
        protected_checkout_links_excluding(snapshot, records, mount_path, &HashSet::new());
    let mut changed = false;
    for link in candidates
        .into_iter()
        .filter(|link| surfaced_paths.contains(&link.path))
    {
        if !is_exact_symlink(&link.path, &link.target)? {
            continue;
        }
        std::fs::remove_file(&link.path)?;
        changed = true;
    }
    Ok(changed)
}

/// Apply only the delta between two desired link inventories. Unchanged plans
/// do no filesystem or decryption work; removed exact Floria links are restored
/// to regular files before new/changed links are reconciled.
pub fn refresh_protected_checkout_links(
    active: &mut Vec<ProtectedCheckoutLink>,
    next: Vec<ProtectedCheckoutLink>,
    store: &dyn SecretStore,
) -> io::Result<bool> {
    if *active == next {
        return Ok(false);
    }
    let removed = active
        .iter()
        .filter(|old| !next.iter().any(|new| old.same_location(new)))
        .cloned()
        .collect::<Vec<_>>();
    let changed = next
        .iter()
        .filter(|new| !active.contains(new))
        .cloned()
        .collect::<Vec<_>>();

    restore_removed_links(&removed, store)?;
    reconcile_protected_links(&changed, store)?;
    *active = next;
    Ok(true)
}

/// Remove exact Floria links that fall out of one Managed File's Environment Scope.
///
/// Unlike removing a Checkout or stopping protection, narrowing visibility must not leave a
/// plaintext copy behind in the excluded checkout.
pub fn remove_excluded_protected_checkout_links(
    current: &[ProtectedCheckoutLink],
    next: &[ProtectedCheckoutLink],
) -> io::Result<bool> {
    let mut changed = false;
    for link in current
        .iter()
        .filter(|old| !next.iter().any(|new| old.same_location(new)))
    {
        if is_exact_symlink(&link.path, &link.target)? {
            std::fs::remove_file(&link.path)?;
            changed = true;
        }
    }
    Ok(changed)
}

/// Restore every exact worktree link for one protected file while its plaintext
/// is still available. Foreign links, divergent regular files, and missing
/// paths remain untouched.
pub fn restore_protected_checkout_links(
    snapshot: &CatalogSnapshot,
    record: &SecretRecord,
    plaintext: &[u8],
    mount_path: &Path,
) -> io::Result<()> {
    let links = protected_checkout_links(snapshot, std::slice::from_ref(record), mount_path);
    for link in links {
        restore_exact_link(&link, plaintext)?;
    }
    Ok(())
}

impl ProtectedCheckoutLink {
    fn same_location(&self, other: &Self) -> bool {
        self.secret_id == other.secret_id
            && self.path == other.path
            && self.target == other.target
    }
}

fn reconcile_protected_links(
    links: &[ProtectedCheckoutLink],
    store: &dyn SecretStore,
) -> io::Result<()> {
    let mut groups = HashMap::<floria_store::SecretId, Vec<&ProtectedCheckoutLink>>::new();
    for link in links {
        groups.entry(link.secret_id.clone()).or_default().push(link);
    }
    for (secret_id, links) in groups {
        let plaintext =
            store.get(&secret_id).map_err(|error| io::Error::other(error.to_string()))?;
        for link in links {
            link_protected_copy(link, &plaintext)?;
        }
    }
    Ok(())
}

fn restore_removed_links(
    links: &[ProtectedCheckoutLink],
    store: &dyn SecretStore,
) -> io::Result<()> {
    let mut groups = HashMap::<floria_store::SecretId, Vec<&ProtectedCheckoutLink>>::new();
    for link in links {
        if is_exact_symlink(&link.path, &link.target)? {
            groups.entry(link.secret_id.clone()).or_default().push(link);
        }
    }
    for (secret_id, links) in groups {
        let plaintext =
            store.get(&secret_id).map_err(|error| io::Error::other(error.to_string()))?;
        for link in links {
            restore_exact_link(link, &plaintext)?;
        }
    }
    Ok(())
}

fn restore_exact_link(link: &ProtectedCheckoutLink, plaintext: &[u8]) -> io::Result<()> {
    let _ = replace_symlink_with_file_if_target(
        &link.path,
        &link.target,
        plaintext,
        link.mode,
    )?;
    Ok(())
}

fn link_protected_copy(link: &ProtectedCheckoutLink, plaintext: &[u8]) -> io::Result<()> {
    match std::fs::symlink_metadata(&link.path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Do not invent directories inside a checkout; only fill in the leaf.
            let Some(parent) = link.path.parent() else { return Ok(()) };
            if !parent.is_dir() {
                return Ok(());
            }
            symlink(&link.target, &link.path)?;
            tracing::info!(path = %link.path.display(), "linked protected file into worktree");
            Ok(())
        }
        Err(error) => Err(error),
        // Already ours, or a foreign symlink the user owns; either way leave it.
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(()),
        Ok(metadata) if metadata.is_file() => {
            if !replace_regular_file_with_symlink_if_matches(
                &link.path,
                &link.target,
                plaintext,
            )? {
                tracing::debug!(
                    path = %link.path.display(),
                    "worktree copy differs from the protected head; leaving it untouched"
                );
                return Ok(());
            }
            tracing::info!(
                path = %link.path.display(),
                "replaced worktree copy with protected link"
            );
            Ok(())
        }
        Ok(_) => Ok(()),
    }
}

/// Atomically swap a regular file for a symlink to `target`.
///
/// This unconditional primitive is reserved for explicit user actions whose
/// caller already owns the path. Automatic worktree reconciliation uses the
/// conditional swap below so a concurrent save cannot be overwritten.
pub fn replace_file_with_symlink(path: &Path, target: &Path) -> io::Result<()> {
    let temporary = create_temporary_symlink(path, target, "link")?;
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

/// Replace a regular file only while its bytes still match the caller's snapshot.
///
/// This is the rollback half of a cross-store transition: concurrent edits are preserved.
pub fn replace_regular_file_with_symlink_if_matches(
    path: &Path,
    target: &Path,
    expected: &[u8],
) -> io::Result<bool> {
    replace_regular_file_with_symlink_if_matches_with(path, target, expected, || Ok(()))
}

/// Replace a regular file only while both its identity and bytes still match a captured snapshot.
///
/// Unlike automatic worktree reconciliation, explicit protection must also preserve metadata-only
/// saves and same-content file replacements that happened while the encrypted copy was prepared.
pub fn replace_regular_file_with_symlink_if_unchanged(
    path: &Path,
    target: &Path,
    expected: &[u8],
    expected_metadata: &std::fs::Metadata,
) -> io::Result<bool> {
    replace_regular_file_with_symlink_if_matches_snapshot(
        path,
        target,
        expected,
        Some(expected_metadata),
        || Ok(()),
    )
}

fn replace_regular_file_with_symlink_if_matches_with(
    path: &Path,
    target: &Path,
    expected: &[u8],
    before_swap: impl FnOnce() -> io::Result<()>,
) -> io::Result<bool> {
    replace_regular_file_with_symlink_if_matches_snapshot(
        path,
        target,
        expected,
        None,
        before_swap,
    )
}

fn replace_regular_file_with_symlink_if_matches_snapshot(
    path: &Path,
    target: &Path,
    expected: &[u8],
    expected_metadata: Option<&std::fs::Metadata>,
    before_swap: impl FnOnce() -> io::Result<()>,
) -> io::Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || expected_metadata.is_some_and(|expected| !same_file_snapshot(&metadata, expected))
        || std::fs::read(path)?.as_slice() != expected
    {
        return Ok(false);
    }
    before_swap()?;

    let temporary = create_temporary_symlink(path, target, "conditional-link")?;
    if let Err(error) = swap_paths(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    let swapped_matches = std::fs::symlink_metadata(&temporary)
        .map(|metadata| {
            metadata.is_file()
                && expected_metadata
                    .is_none_or(|expected| same_displaced_file_snapshot(&metadata, expected))
        })
        .unwrap_or(false)
        && std::fs::read(&temporary).map(|bytes| bytes == expected).unwrap_or(false);
    if swapped_matches {
        std::fs::remove_file(&temporary)?;
        return Ok(true);
    }
    rollback_swap(path, &temporary, target)?;
    Ok(false)
}

fn same_file_snapshot(actual: &std::fs::Metadata, expected: &std::fs::Metadata) -> bool {
    same_displaced_file_snapshot(actual, expected)
        && actual.ctime() == expected.ctime()
        && actual.ctime_nsec() == expected.ctime_nsec()
}

fn same_displaced_file_snapshot(
    actual: &std::fs::Metadata,
    expected: &std::fs::Metadata,
) -> bool {
    actual.dev() == expected.dev()
        && actual.ino() == expected.ino()
        && actual.len() == expected.len()
        && actual.mode() == expected.mode()
        && actual.mtime() == expected.mtime()
        && actual.mtime_nsec() == expected.mtime_nsec()
}

/// Replace only an exact symlink with a regular file. The swap is verified
/// after it happens, so a path changed concurrently is restored rather than
/// overwritten.
pub fn replace_symlink_with_file_if_target(
    path: &Path,
    expected_target: &Path,
    bytes: &[u8],
    mode: u32,
) -> io::Result<bool> {
    if !is_exact_symlink(path, expected_target)? {
        return Ok(false);
    }
    let temporary = create_temporary_file(path, bytes, mode)?;
    let temporary_metadata = std::fs::symlink_metadata(&temporary)?;
    if let Err(error) = swap_paths(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if is_exact_symlink(&temporary, expected_target)? {
        std::fs::remove_file(&temporary)?;
        return Ok(true);
    }
    rollback_file_swap(path, &temporary, &temporary_metadata, bytes)?;
    Ok(false)
}

fn rollback_swap(path: &Path, temporary: &Path, expected_target: &Path) -> io::Result<()> {
    if !is_exact_symlink(path, expected_target)? {
        return Err(io::Error::other(format!(
            "{} changed during an atomic Floria swap; displaced content was preserved at {}",
            path.display(),
            temporary.display()
        )));
    }
    swap_paths(temporary, path)?;
    std::fs::remove_file(temporary)
}

fn rollback_file_swap(
    path: &Path,
    temporary: &Path,
    inserted_metadata: &std::fs::Metadata,
    inserted_bytes: &[u8],
) -> io::Result<()> {
    let current = std::fs::symlink_metadata(path)?;
    let still_inserted = current.is_file()
        && current.dev() == inserted_metadata.dev()
        && current.ino() == inserted_metadata.ino()
        && std::fs::read(path)?.as_slice() == inserted_bytes;
    if !still_inserted {
        return Err(io::Error::other(format!(
            "{} changed during an atomic Floria restore; displaced content was preserved at {}",
            path.display(),
            temporary.display()
        )));
    }
    swap_paths(temporary, path)?;
    std::fs::remove_file(temporary)
}

fn is_exact_symlink(path: &Path, expected_target: &Path) -> io::Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_symlink() {
        return Ok(false);
    }
    Ok(std::fs::read_link(path)? == expected_target)
}

fn create_temporary_symlink(path: &Path, target: &Path, label: &str) -> io::Result<PathBuf> {
    allocate_temporary_path(path, label, |candidate| symlink(target, candidate))
}

fn create_temporary_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<PathBuf> {
    allocate_temporary_path(path, "restore", |candidate| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(candidate)?;
        let result = file
            .write_all(bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| {
                std::fs::set_permissions(candidate, std::fs::Permissions::from_mode(mode))
            });
        if result.is_err() {
            let _ = std::fs::remove_file(candidate);
        }
        result
    })
}

fn allocate_temporary_path(
    path: &Path,
    label: &str,
    create: impl Fn(&Path) -> io::Result<()>,
) -> io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    for counter in 0..100 {
        let candidate = parent.join(format!(
            ".{name}.floria-{label}-{}-{counter}.tmp",
            std::process::id()
        ));
        match create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a temporary Floria path",
    ))
}

fn path_c_string(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains a NUL byte: {}", path.display()),
        )
    })
}

#[cfg(target_os = "macos")]
fn swap_paths(left: &Path, right: &Path) -> io::Result<()> {
    let left = path_c_string(left)?;
    let right = path_c_string(right)?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the call.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(target_os = "linux")]
fn swap_paths(left: &Path, right: &Path) -> io::Result<()> {
    let left = path_c_string(left)?;
    let right = path_c_string(right)?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn swap_paths(_left: &Path, _right: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic path exchange is unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use floria_catalog::{
        CatalogSnapshot, Environment, FileBacking, Project, ProjectCheckout, ProjectCheckoutKind,
        SurfaceFormat, SurfaceInput,
    };
    use floria_store::{AgeDirStore, KeyProvider, NewSecret, SecretId, StoreResult};
    use std::path::PathBuf;
    use std::sync::Arc;

    struct TestKeys(age::x25519::Identity);

    impl KeyProvider for TestKeys {
        #[allow(clippy::type_complexity)]
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.0.to_public())])
        }

        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    fn fixture_surface(path: PathBuf) -> Surface {
        Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "fixture-development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
            path: Some(path),
            input: SurfaceInput::Bindings { binding_ids: Vec::new() },
            enforcement: floria_core::authz::Enforcement::Prompt,
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
        assert_eq!(
            std::fs::read_link(surface.path.as_ref().unwrap()).unwrap(),
            expected
        );
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
                ..Default::default()
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
                .map(|surface| {
                    (
                        surface.id.as_str(),
                        surface.path.as_ref().unwrap().as_path(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                ("fixture-dotenv", Path::new("/workspace/floria/.env")),
                ("fixture-dotenv", Path::new("/workspace/floria-feature/.env")),
                ("fixture-staging", Path::new("/workspace/floria/.env.staging")),
            ]
        );
    }

    #[test]
    fn checkout_health_requires_the_exact_surface_target() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("project");
        let worktree = dir.path().join("worktree");
        std::fs::create_dir(&primary).unwrap();
        std::fs::create_dir(&worktree).unwrap();
        let checkout = ProjectCheckout {
            id: "fixture-feature".to_string(),
            project_id: "fixture-project".to_string(),
            path: worktree.clone(),
            environment_id: Some("fixture-development".to_string()),
            kind: ProjectCheckoutKind::Worktree,
            git_common_dir: None,
        };
        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary.clone(),
                ..Default::default()
            }],
            checkouts: vec![checkout.clone()],
            environments: vec![Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            }],
            surfaces: vec![fixture_surface(primary.join(".env"))],
            ..CatalogSnapshot::default()
        };
        let mount = dir.path().join("mount");
        let worktree_path = worktree.join(".env");
        symlink("../project/.env", &worktree_path).unwrap();

        assert_eq!(
            checkout_link_issues(&snapshot, &[], &mount, &checkout).unwrap(),
            vec![worktree_path.clone()]
        );

        std::fs::remove_file(&worktree_path).unwrap();
        symlink(
            mount.join(SURFACES_DIR).join("fixture-dotenv"),
            &worktree_path,
        )
        .unwrap();
        assert!(
            checkout_link_issues(&snapshot, &[], &mount, &checkout)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn explicit_checkout_repair_replaces_foreign_links_but_preserves_files() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("project");
        let worktree = dir.path().join("worktree");
        std::fs::create_dir(&primary).unwrap();
        std::fs::create_dir(&worktree).unwrap();
        let checkout = ProjectCheckout {
            id: "fixture-feature".to_string(),
            project_id: "fixture-project".to_string(),
            path: worktree.clone(),
            environment_id: Some("fixture-development".to_string()),
            kind: ProjectCheckoutKind::Worktree,
            git_common_dir: None,
        };
        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary.clone(),
                ..Default::default()
            }],
            checkouts: vec![checkout.clone()],
            environments: vec![Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            }],
            surfaces: vec![fixture_surface(primary.join(".env"))],
            ..CatalogSnapshot::default()
        };
        let mount = dir.path().join("mount");
        let path = worktree.join(".env");
        let expected = mount.join(SURFACES_DIR).join("fixture-dotenv");
        symlink("../project/.env", &path).unwrap();

        managed_file_links(&snapshot, &[], &mount)
            .unwrap()
            .into_iter()
            .find(|link| link.path() == path)
            .unwrap()
            .repair()
            .unwrap();
        assert_eq!(std::fs::read_link(&path).unwrap(), expected);

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"FIXTURE=local\n").unwrap();
        assert!(matches!(
            managed_file_links(&snapshot, &[], &mount)
                .unwrap()
                .into_iter()
                .find(|link| link.path() == path)
                .unwrap()
                .repair(),
            Err(SurfaceError::LinkConflict { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"FIXTURE=local\n");
    }

    #[test]
    fn explicit_repair_creates_missing_containing_directories() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("missing/nested");
        let path = parent.join(".env");
        let expected = dir.path().join("mount/surfaces/fixture-dotenv");

        assert_eq!(
            ManagedSymlink::new(&path, &expected).repair().unwrap(),
            SurfaceLinkState::Created
        );
        assert!(parent.is_dir());
        assert_eq!(std::fs::read_link(path).unwrap(), expected);
    }

    #[test]
    fn refuses_to_replace_existing_file_or_different_link() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let surface = fixture_surface(project.join(".env"));
        let mount = dir.path().join("mount");

        let surface_path = surface.path.as_ref().unwrap();
        std::fs::write(surface_path, b"FIXTURE=local\n").unwrap();
        assert!(matches!(
            ensure_file_surface_link(&surface, &mount),
            Err(SurfaceError::LinkConflict { .. })
        ));
        assert_eq!(std::fs::read(surface_path).unwrap(), b"FIXTURE=local\n");

        std::fs::remove_file(surface_path).unwrap();
        symlink("/fixture/different-target", surface_path).unwrap();
        assert!(matches!(
            ensure_file_surface_link(&surface, &mount),
            Err(SurfaceError::LinkConflict { .. })
        ));
        assert_eq!(
            std::fs::read_link(surface_path).unwrap(),
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
        assert!(!surface.path.as_ref().unwrap().exists());
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
        let surface_path = surface.path.as_ref().unwrap();
        assert!(!surface_path.exists());

        symlink("/fixture/owned-elsewhere", surface_path).unwrap();
        assert_eq!(
            remove_file_surface_link(&surface, &mount).unwrap(),
            SurfaceLinkRemoval::Preserved
        );
        assert_eq!(
            std::fs::read_link(surface_path).unwrap(),
            PathBuf::from("/fixture/owned-elsewhere")
        );
    }

    #[test]
    fn extends_protected_files_into_managed_worktrees() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("project");
        let worktree = dir.path().join("worktree");
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&worktree).unwrap();
        let mount = dir.path().join("mount");
        let store = AgeDirStore::open(
            dir.path().join("store"),
            Arc::new(TestKeys(age::x25519::Identity::generate())),
        )
        .unwrap();

        let protect = |name: &str, content: &[u8]| -> SecretId {
            let source = primary.join(name);
            let id = store
                .put(NewSecret::file(source.clone(), 0o644), content)
                .unwrap();
            symlink(mount.join(SECRETS_DIR).join(id.to_string()), &source).unwrap();
            id
        };
        let identical_id = protect("mise.local.toml", b"secret = 1\n");
        let divergent_id = protect(".envrc", b"export A=1\n");
        let missing_id = protect(".pgpass", b"host|5432|db|user|pw\n");
        let _ = divergent_id;

        // The worktree starts with an identical copy, a locally edited copy,
        // and no copy at all.
        std::fs::write(worktree.join("mise.local.toml"), b"secret = 1\n").unwrap();
        std::fs::write(worktree.join(".envrc"), b"export A=2\n").unwrap();

        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary.clone(),
                ..Default::default()
            }],
            checkouts: vec![
                ProjectCheckout {
                    id: "fixture-project".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: primary,
                    kind: ProjectCheckoutKind::Primary,
                    ..Default::default()
                },
                ProjectCheckout {
                    id: "fixture-feature".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: worktree.clone(),
                    environment_id: Some("fixture-development".to_string()),
                    ..Default::default()
                },
            ],
            ..CatalogSnapshot::default()
        };

        let mut active_links = Vec::new();
        let links = protected_checkout_links(&snapshot, &store.list().unwrap(), &mount);
        refresh_protected_checkout_links(&mut active_links, links, &store).unwrap();

        let identical = worktree.join("mise.local.toml");
        assert!(std::fs::symlink_metadata(&identical).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(&identical).unwrap(),
            mount.join(SECRETS_DIR).join(identical_id.to_string())
        );

        let divergent = worktree.join(".envrc");
        assert!(!std::fs::symlink_metadata(&divergent).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&divergent).unwrap(), b"export A=2\n");

        let missing = worktree.join(".pgpass");
        assert!(std::fs::symlink_metadata(&missing).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(&missing).unwrap(),
            mount.join(SECRETS_DIR).join(missing_id.to_string())
        );
    }

    #[test]
    fn configured_surface_takes_over_only_matching_worktree_links_without_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("project");
        let development_worktree = dir.path().join("development-worktree");
        let staging_worktree = dir.path().join("staging-worktree");
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&development_worktree).unwrap();
        std::fs::create_dir_all(&staging_worktree).unwrap();
        let mount = dir.path().join("mount");
        let store = AgeDirStore::open(
            dir.path().join("store"),
            Arc::new(TestKeys(age::x25519::Identity::generate())),
        )
        .unwrap();
        let id = store
            .put(NewSecret::file(primary.join(".env"), 0o600), b"SECRET=fixture\n")
            .unwrap();
        let secret_target = mount.join(SECRETS_DIR).join(id.to_string());
        symlink(&secret_target, development_worktree.join(".env")).unwrap();
        symlink(&secret_target, staging_worktree.join(".env")).unwrap();

        let surface = fixture_surface(primary.join(".env"));
        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary.clone(),
                ..Default::default()
            }],
            checkouts: vec![
                ProjectCheckout {
                    id: "fixture-development-worktree".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: development_worktree.clone(),
                    environment_id: Some("fixture-development".to_string()),
                    ..Default::default()
                },
                ProjectCheckout {
                    id: "fixture-staging-worktree".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: staging_worktree.clone(),
                    environment_id: Some("fixture-staging".to_string()),
                    ..Default::default()
                },
            ],
            environments: vec![Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            }],
            surfaces: vec![surface],
            ..Default::default()
        };
        let records = store.list().unwrap();
        let surface_instances = file_surface_instances(&snapshot).unwrap();

        assert!(release_protected_links_for_file_surfaces(
            &snapshot,
            &records,
            &surface_instances,
            &mount,
        )
        .unwrap());
        let development_surface = surface_instances
            .iter()
            .find(|surface| surface.path.as_ref() == Some(&development_worktree.join(".env")))
            .unwrap();
        ensure_file_surface_link(development_surface, &mount).unwrap();

        assert_eq!(
            std::fs::read_link(development_worktree.join(".env")).unwrap(),
            mount.join(SURFACES_DIR).join("fixture-dotenv")
        );
        assert_eq!(
            std::fs::read_link(staging_worktree.join(".env")).unwrap(),
            secret_target
        );
        assert!(protected_checkout_links(&snapshot, &records, &mount)
            .iter()
            .any(|link| link.path == staging_worktree.join(".env")));
    }

    #[test]
    fn protected_file_environment_scope_limits_worktree_links() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("project");
        let development_worktree = dir.path().join("development-worktree");
        let production_worktree = dir.path().join("production-worktree");
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&development_worktree).unwrap();
        std::fs::create_dir_all(&production_worktree).unwrap();
        let mount = dir.path().join("mount");
        let store = AgeDirStore::open(
            dir.path().join("store"),
            Arc::new(TestKeys(age::x25519::Identity::generate())),
        )
        .unwrap();
        let id = store
            .put(NewSecret::file(primary.join("production.key"), 0o600), b"fixture")
            .unwrap();
        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary,
                ..Default::default()
            }],
            environments: vec![
                Environment {
                    id: "fixture-development".to_string(),
                    project_id: "fixture-project".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                },
                Environment {
                    id: "fixture-production".to_string(),
                    project_id: "fixture-project".to_string(),
                    name: "Production".to_string(),
                    position: 1,
                },
            ],
            checkouts: vec![
                ProjectCheckout {
                    id: "fixture-development-checkout".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: development_worktree.clone(),
                    environment_id: Some("fixture-development".to_string()),
                    ..Default::default()
                },
                ProjectCheckout {
                    id: "fixture-production-checkout".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: production_worktree.clone(),
                    environment_id: Some("fixture-production".to_string()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let mut active = protected_checkout_links(&snapshot, &store.list().unwrap(), &mount);
        refresh_protected_checkout_links(&mut Vec::new(), active.clone(), &store).unwrap();
        assert!(development_worktree.join("production.key").is_symlink());
        assert!(production_worktree.join("production.key").is_symlink());

        store
            .update_settings(
                &id,
                Default::default(),
                floria_core::authz::Enforcement::Prompt,
                Some(vec!["fixture-production".to_string()]),
            )
            .unwrap();
        let links = protected_checkout_links(&snapshot, &store.list().unwrap(), &mount);
        remove_excluded_protected_checkout_links(&active, &links).unwrap();
        refresh_protected_checkout_links(&mut active, links.clone(), &store).unwrap();

        assert!(!links
            .iter()
            .any(|link| link.path == development_worktree.join("production.key")));
        assert!(links
            .iter()
            .any(|link| link.path == production_worktree.join("production.key")));
        assert!(!development_worktree.join("production.key").exists());
        assert!(production_worktree.join("production.key").is_symlink());
    }

    #[test]
    fn assigns_a_protected_file_only_to_the_deepest_nested_project() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("workspace");
        let nested = parent.join("service");
        let parent_worktree = dir.path().join("workspace-feature");
        let nested_worktree = dir.path().join("service-feature");
        std::fs::create_dir_all(&nested).unwrap();
        let mount = dir.path().join("mount");
        let store = AgeDirStore::open(
            dir.path().join("store"),
            Arc::new(TestKeys(age::x25519::Identity::generate())),
        )
        .unwrap();
        store
            .put(NewSecret::file(nested.join(".env"), 0o600), b"SECRET=fixture\n")
            .unwrap();
        let snapshot = CatalogSnapshot {
            projects: vec![
                Project {
                    id: "parent".to_string(),
                    name: "Parent".to_string(),
                    path: parent.clone(),
                    ..Default::default()
                },
                Project {
                    id: "nested".to_string(),
                    name: "Nested".to_string(),
                    path: nested,
                    ..Default::default()
                },
            ],
            checkouts: vec![
                ProjectCheckout {
                    id: "parent-feature".to_string(),
                    project_id: "parent".to_string(),
                    path: parent_worktree,
                    kind: ProjectCheckoutKind::Worktree,
                    environment_id: Some("parent-development".to_string()),
                    ..Default::default()
                },
                ProjectCheckout {
                    id: "nested-feature".to_string(),
                    project_id: "nested".to_string(),
                    path: nested_worktree.clone(),
                    kind: ProjectCheckoutKind::Worktree,
                    environment_id: Some("nested-development".to_string()),
                    ..Default::default()
                },
            ],
            ..CatalogSnapshot::default()
        };

        let links = protected_checkout_links(&snapshot, &store.list().unwrap(), &mount);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].path, nested_worktree.join(".env"));
    }

    #[test]
    fn removing_a_managed_checkout_restores_its_exact_protected_links() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("project");
        let worktree = dir.path().join("worktree");
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&worktree).unwrap();
        let mount = dir.path().join("mount");
        let store = AgeDirStore::open(
            dir.path().join("store"),
            Arc::new(TestKeys(age::x25519::Identity::generate())),
        )
        .unwrap();
        let id = store
            .put(NewSecret::file(primary.join(".env"), 0o640), b"SECRET=fixture\n")
            .unwrap();
        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary,
                ..Default::default()
            }],
            checkouts: vec![ProjectCheckout {
                id: "fixture-feature".to_string(),
                project_id: "fixture-project".to_string(),
                path: worktree.clone(),
                kind: ProjectCheckoutKind::Worktree,
                environment_id: Some("fixture-development".to_string()),
                ..Default::default()
            }],
            ..CatalogSnapshot::default()
        };
        let mut active_links = Vec::new();
        let links = protected_checkout_links(&snapshot, &store.list().unwrap(), &mount);
        refresh_protected_checkout_links(&mut active_links, links, &store).unwrap();
        assert_eq!(
            std::fs::read_link(worktree.join(".env")).unwrap(),
            mount.join(SECRETS_DIR).join(id.to_string())
        );

        refresh_protected_checkout_links(&mut active_links, Vec::new(), &store).unwrap();

        let restored = worktree.join(".env");
        assert!(!std::fs::symlink_metadata(&restored).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(restored).unwrap(), b"SECRET=fixture\n");
    }

    #[test]
    fn restoring_a_file_restores_worktree_links_before_the_store_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("project");
        let worktree = dir.path().join("worktree");
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&worktree).unwrap();
        let mount = dir.path().join("mount");
        let store = AgeDirStore::open(
            dir.path().join("store"),
            Arc::new(TestKeys(age::x25519::Identity::generate())),
        )
        .unwrap();
        let id = store
            .put(NewSecret::file(primary.join(".env"), 0o600), b"SECRET=fixture\n")
            .unwrap();
        let record = store.record(&id).unwrap().unwrap();
        let target = mount.join(SECRETS_DIR).join(id.to_string());
        symlink(&target, worktree.join(".env")).unwrap();
        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary,
                ..Default::default()
            }],
            checkouts: vec![ProjectCheckout {
                id: "fixture-feature".to_string(),
                project_id: "fixture-project".to_string(),
                path: worktree.clone(),
                kind: ProjectCheckoutKind::Worktree,
                environment_id: Some("fixture-development".to_string()),
                ..Default::default()
            }],
            ..CatalogSnapshot::default()
        };

        restore_protected_checkout_links(
            &snapshot,
            &record,
            &store.get(&id).unwrap(),
            &mount,
        )
        .unwrap();

        let restored = worktree.join(".env");
        assert!(!std::fs::symlink_metadata(&restored).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(restored).unwrap(), b"SECRET=fixture\n");
    }

    #[test]
    fn conditional_link_swap_preserves_a_file_changed_after_comparison() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join(".env");
        let target = dir.path().join("secret");
        std::fs::write(&candidate, b"SECRET=old\n").unwrap();

        let linked = replace_regular_file_with_symlink_if_matches_with(
            &candidate,
            &target,
            b"SECRET=old\n",
            || std::fs::write(&candidate, b"SECRET=new\n"),
        )
        .unwrap();

        assert!(!linked);
        assert!(!std::fs::symlink_metadata(&candidate).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(candidate).unwrap(), b"SECRET=new\n");
    }

    #[test]
    fn conditional_link_swap_preserves_a_same_content_file_replaced_after_comparison() {
        let dir = tempfile::tempdir().unwrap();
        let candidate = dir.path().join(".env");
        let replacement = dir.path().join(".env.replacement");
        let target = dir.path().join("secret");
        std::fs::write(&candidate, b"SECRET=fixture\n").unwrap();
        let expected_metadata = std::fs::symlink_metadata(&candidate).unwrap();

        let linked = replace_regular_file_with_symlink_if_matches_snapshot(
            &candidate,
            &target,
            b"SECRET=fixture\n",
            Some(&expected_metadata),
            || {
                std::fs::write(&replacement, b"SECRET=fixture\n")?;
                std::fs::rename(&replacement, &candidate)
            },
        )
        .unwrap();

        assert!(!linked);
        assert!(!std::fs::symlink_metadata(&candidate).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(candidate).unwrap(), b"SECRET=fixture\n");
    }

    #[test]
    fn unchanged_link_plan_skips_rechecking_divergent_files() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("project");
        let worktree = dir.path().join("worktree");
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&worktree).unwrap();
        let mount = dir.path().join("mount");
        let store = AgeDirStore::open(
            dir.path().join("store"),
            Arc::new(TestKeys(age::x25519::Identity::generate())),
        )
        .unwrap();
        let id = store
            .put(NewSecret::file(primary.join(".env"), 0o600), b"SECRET=expected\n")
            .unwrap();
        std::fs::write(worktree.join(".env"), b"SECRET=divergent\n").unwrap();
        let snapshot = CatalogSnapshot {
            projects: vec![Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary,
                ..Default::default()
            }],
            checkouts: vec![ProjectCheckout {
                id: "fixture-feature".to_string(),
                project_id: "fixture-project".to_string(),
                path: worktree.clone(),
                kind: ProjectCheckoutKind::Worktree,
                environment_id: Some("fixture-development".to_string()),
                ..Default::default()
            }],
            ..CatalogSnapshot::default()
        };
        let mut active_links = Vec::new();
        let plan = protected_checkout_links(&snapshot, &store.list().unwrap(), &mount);
        refresh_protected_checkout_links(&mut active_links, plan.clone(), &store).unwrap();
        std::fs::write(worktree.join(".env"), b"SECRET=expected\n").unwrap();

        assert!(!refresh_protected_checkout_links(&mut active_links, plan, &store).unwrap());
        assert!(!std::fs::symlink_metadata(worktree.join(".env"))
            .unwrap()
            .file_type()
            .is_symlink());

        store.append_version(&id, b"SECRET=expected\n").unwrap();
        let updated = protected_checkout_links(&snapshot, &store.list().unwrap(), &mount);
        assert!(refresh_protected_checkout_links(&mut active_links, updated, &store).unwrap());
        assert!(std::fs::symlink_metadata(worktree.join(".env"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
