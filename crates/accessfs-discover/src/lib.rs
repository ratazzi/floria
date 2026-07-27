//! Static discovery of project-local configuration and credential files.
//!
//! Discovery never executes project code. It produces a redacted plan for review while retaining
//! plaintext only in zeroizing values long enough to compare candidates with existing resources.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use accessfs_catalog::ResourceCodec;
use accessfs_surface::decode_source;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

mod git;
mod watch;

pub use git::{
    discover_git_checkouts, DiscoveredGitCheckout, GitCheckoutDiscovery, GitCheckoutError,
};
pub use watch::{
    GitCheckoutInventory, GitCheckoutMonitor, MonitoredGitCheckout, MonitoredGitProject,
};

const MAX_DEPTH: usize = 6;
const MAX_CANDIDATES: usize = 1_000;
const MAX_FILE_SIZE: u64 = 1 << 20;
const PROGRESS_DIRECTORY_INTERVAL: usize = 64;
const PROGRESS_FILE_INTERVAL: usize = 16;
const IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    ".direnv",
    ".build",
    ".cache",
    ".astro",
    ".docusaurus",
    ".eggs",
    ".gradle",
    ".history",
    ".hypothesis",
    ".ipynb_checkpoints",
    ".kotlin",
    ".mypy_cache",
    ".next",
    ".nox",
    ".npm",
    ".nuxt",
    ".nyc_output",
    ".parcel-cache",
    ".pnpm-store",
    ".pybuilder",
    ".pyre",
    ".pytest_cache",
    ".pytype",
    ".ruff_cache",
    ".ruby-lsp",
    ".svelte-kit",
    ".terraform",
    ".tox",
    ".turbo",
    ".venv",
    ".vs",
    ".vscode-test",
    ".wrangler",
    ".zig-cache",
    "__pycache__",
    "__pypackages__",
    "_deps",
    "bower_components",
    "cdk.out",
    "CMakeFiles",
    "CMakeScripts",
    "DerivedData",
    "develop-eggs",
    "dist-packages",
    "jspm_packages",
    "node_modules",
    "site-packages",
    "venv",
    "vcpkg_installed",
    "web_modules",
    "xcuserdata",
    "zig-cache",
    "zig-out",
];

#[derive(Clone, Copy, Default)]
struct EcosystemContext(u16);

impl EcosystemContext {
    const JAVASCRIPT: u16 = 1 << 0;
    const PYTHON: u16 = 1 << 1;
    const GO: u16 = 1 << 2;
    const RUST: u16 = 1 << 3;
    const RUBY: u16 = 1 << 4;
    const SWIFT: u16 = 1 << 5;
    const GRADLE: u16 = 1 << 6;
    const MAVEN: u16 = 1 << 7;
    const CMAKE: u16 = 1 << 8;
    const ZIG: u16 = 1 << 9;
    const PHP: u16 = 1 << 10;
    const SERVERLESS: u16 = 1 << 11;
    const VITE: u16 = 1 << 12;
    const NUXT: u16 = 1 << 13;

    fn contains_any(self, ecosystems: u16) -> bool {
        self.0 & ecosystems != 0
    }

    fn add(&mut self, ecosystem: u16) {
        self.0 |= ecosystem;
    }
}

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("discover path must be absolute: {0}")]
    RelativePath(PathBuf),
    #[error("discover path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("discovery was cancelled")]
    Cancelled,
    #[error("cannot inspect {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryScanPhase {
    ProjectCandidates,
    CandidateFiles,
    ParsingFiles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryProgress {
    pub phase: DiscoveryScanPhase,
    pub directories_scanned: usize,
    pub candidate_files: usize,
    pub project_candidates: usize,
    pub files_parsed: usize,
}

struct ProgressReporter<'a> {
    callback: &'a mut dyn FnMut(DiscoveryProgress) -> bool,
    progress: DiscoveryProgress,
}

impl ProgressReporter<'_> {
    fn emit(&mut self) -> Result<(), DiscoverError> {
        if (self.callback)(self.progress) {
            Ok(())
        } else {
            Err(DiscoverError::Cancelled)
        }
    }

    fn begin(&mut self, phase: DiscoveryScanPhase) -> Result<(), DiscoverError> {
        self.progress.phase = phase;
        self.emit()
    }

    fn scanned_directory(&mut self) -> Result<(), DiscoverError> {
        self.progress.directories_scanned += 1;
        if self
            .progress
            .directories_scanned
            .is_multiple_of(PROGRESS_DIRECTORY_INTERVAL)
        {
            self.emit()?;
        }
        Ok(())
    }

    fn found_candidates(&mut self, count: usize) -> Result<(), DiscoverError> {
        self.progress.candidate_files = count;
        if count.is_multiple_of(PROGRESS_FILE_INTERVAL) {
            self.emit()?;
        }
        Ok(())
    }

    fn found_projects(&mut self, count: usize) -> Result<(), DiscoverError> {
        self.progress.project_candidates = count;
        self.emit()
    }

    fn parsed_file(&mut self) -> Result<(), DiscoverError> {
        self.progress.files_parsed += 1;
        if self.progress.files_parsed.is_multiple_of(PROGRESS_FILE_INTERVAL) {
            self.emit()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryPlan {
    pub paths: Vec<PathBuf>,
    pub projects: Vec<DiscoveredProject>,
    pub files: Vec<DiscoveredFile>,
    pub summary: DiscoverySummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredProject {
    pub name: String,
    pub path: PathBuf,
    pub markers: Vec<ProjectMarker>,
    pub ecosystems: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_project_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMarker {
    pub kind: ProjectMarkerKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectMarkerKind {
    Git,
    PackageJson,
    JavaScriptLock,
    Pyproject,
    PythonRequirements,
    GoModule,
    Cargo,
    CargoLock,
    Ruby,
    Swift,
    Gradle,
    Maven,
    Cmake,
    Zig,
    Composer,
    Serverless,
    Wrangler,
    Vite,
    Nuxt,
    Compose,
    Dockerfile,
    SelectedFolder,
    SelectedFileParent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverySummary {
    pub files: usize,
    pub entries: usize,
    pub new_secrets: usize,
    pub reused_secrets: usize,
    pub missing_reference_entries: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub assignment: ProjectAssignment,
    pub kind: DiscoveredFileKind,
    pub codec: ResourceCodec,
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_surface_id: Option<String>,
    pub tags: Vec<String>,
    pub entries: Vec<DiscoveredEntry>,
    pub warnings: Vec<DiscoveryWarning>,
    pub action: DiscoveredFileAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<PlacementCaution>,
}

/// A location that is legitimate to scan but implausible for a long-lived credential.
///
/// Scanning and selection are separate decisions: skipping such a directory would silently
/// drop the very files most worth protecting, so discovery still reports them and only asks
/// the user to confirm. See `docs/design/discovery-ignore-boundaries-research.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementCaution {
    /// Below a `tmp` / `temp` directory, whose contents are conventionally disposable.
    TemporaryDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectAssignment {
    pub state: ProjectAssignmentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_path: Option<PathBuf>,
    #[serde(default)]
    pub candidate_project_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectAssignmentState {
    Assigned,
    Unassigned,
    NeedsReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveredFileKind {
    Dotenv,
    Direnv,
    Mise,
    AwsCredentials,
    Pgpass,
    SshPrivateKey,
    ProtectedFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveredFileAction {
    Compose,
    Protect,
    ImportSshIdentity,
    Reference,
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredEntry {
    pub address: String,
    pub key: String,
    pub section: Option<String>,
    pub action: DiscoveredEntryAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DiscoveredEntryAction {
    CreateSharedSecret {
        group_id: String,
    },
    ReuseSharedSecret {
        resource_id: String,
        resource_name: String,
    },
    ReuseDiscoveredSecret {
        group_id: String,
    },
    CreateEnvFileEntry,
    KeepInProtectedFile,
    ReferenceEntry {
        matched: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryWarning {
    pub line: Option<usize>,
    pub message: String,
}

/// Default treatment of a discovered key, decided from its name alone.
///
/// The heuristic only picks the default; the review step may promote or demote
/// individual entries before apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    Secret,
    Plain,
}

const SECRET_KEY_SEGMENTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "PASSPHRASE",
    "APIKEY",
    "CREDENTIAL",
    "CREDENTIALS",
    "DSN",
    "AUTH",
    "BEARER",
    "SALT",
];

const SECRET_KEY_SEGMENT_PAIRS: &[(&str, &str)] = &[
    ("API", "KEY"),
    ("ACCESS", "KEY"),
    ("PRIVATE", "KEY"),
    ("SIGNING", "KEY"),
    ("ENCRYPTION", "KEY"),
    ("LICENSE", "KEY"),
    ("MASTER", "KEY"),
];

const SECRET_EXACT_KEYS: &[&str] = &["DATABASE_URL"];

/// Classify a key name as a secret candidate or a plain configuration value.
///
/// Matching is segment-based, not substring-based: `FEISHU_OAUTH_ENABLED` does
/// not match `AUTH`, and a lone `ID` or `KEY` segment never triggers.
pub fn classify_key(key: &str) -> KeyClass {
    let upper = key.to_ascii_uppercase();
    if SECRET_EXACT_KEYS.contains(&upper.as_str()) {
        return KeyClass::Secret;
    }
    let segments: Vec<&str> = upper
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.iter().any(|segment| SECRET_KEY_SEGMENTS.contains(segment)) {
        return KeyClass::Secret;
    }
    if segments
        .windows(2)
        .any(|pair| SECRET_KEY_SEGMENT_PAIRS.contains(&(pair[0], pair[1])))
    {
        return KeyClass::Secret;
    }
    KeyClass::Plain
}

/// Existing scalar resource used only for exact, in-memory reuse matching.
pub struct ExistingSecret {
    pub resource_id: String,
    pub name: String,
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
}

/// Existing managed outputs used to compare reference declarations without decrypting values.
pub struct ExistingProject {
    pub id: String,
    pub path: PathBuf,
    pub environments: Vec<ExistingEnvironment>,
}

pub struct ExistingEnvironment {
    pub name: String,
    pub surfaces: Vec<ExistingSurface>,
}

pub struct ExistingSurface {
    pub id: String,
    pub path: PathBuf,
    pub keys: Vec<String>,
}

pub struct Discovery {
    requested_paths: Vec<PathBuf>,
    projects: Vec<DiscoveredProject>,
    files: Vec<InternalFile>,
}

/// Plaintext-bearing discovery output for a trusted, local mutation boundary.
///
/// This type deliberately implements neither `Debug` nor `Serialize`.
pub struct DiscoveredContent {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub assignment: ProjectAssignment,
    pub kind: DiscoveredFileKind,
    pub codec: ResourceCodec,
    pub environment: Option<String>,
    pub entries: Vec<DiscoveredValue>,
    pub warnings: Vec<DiscoveryWarning>,
    pub action: DiscoveredFileAction,
}

/// One discovered value retained in zeroizing memory for import.
pub struct DiscoveredValue {
    pub address: String,
    pub key: String,
    pub section: Option<String>,
    pub value: Zeroizing<String>,
}

struct InternalFile {
    path: PathBuf,
    relative_path: PathBuf,
    assignment: ProjectAssignment,
    kind: DiscoveredFileKind,
    codec: ResourceCodec,
    environment: Option<String>,
    tags: Vec<String>,
    entries: Vec<InternalEntry>,
    warnings: Vec<DiscoveryWarning>,
    action: DiscoveredFileAction,
    entry_disposition: EntryDisposition,
}

struct InternalEntry {
    address: String,
    key: String,
    section: Option<String>,
    value: Zeroizing<String>,
}

#[derive(Clone, Copy)]
enum EntryDisposition {
    SharedSecret,
    EnvFile,
    ProtectedFile,
    Reference,
}

/// Discover supported files below one path without executing project-controlled content.
///
/// This compatibility wrapper shares the multi-input implementation used by workspace discovery.
pub fn discover(path: &Path) -> Result<Discovery, DiscoverError> {
    discover_many(&[path.to_path_buf()])
}

/// Discover supported files and Project Candidates from files, projects, or Workspace Folders.
pub fn discover_many(paths: &[PathBuf]) -> Result<Discovery, DiscoverError> {
    discover_many_with_progress(paths, |_| true)
}

/// Discover supported files while reporting bounded progress and honoring cancellation.
///
/// The callback runs on the scanning thread. Returning `false` stops before any mutation; discovery
/// itself remains read-only and returns [`DiscoverError::Cancelled`].
pub fn discover_many_with_progress(
    paths: &[PathBuf],
    mut callback: impl FnMut(DiscoveryProgress) -> bool,
) -> Result<Discovery, DiscoverError> {
    let mut progress = ProgressReporter {
        callback: &mut callback,
        progress: DiscoveryProgress {
            phase: DiscoveryScanPhase::ProjectCandidates,
            directories_scanned: 0,
            candidate_files: 0,
            project_candidates: 0,
            files_parsed: 0,
        },
    };
    progress.emit()?;
    let mut requested_paths = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.is_absolute() {
            return Err(DiscoverError::RelativePath(path.clone()));
        }
        if !path.exists() {
            return Err(DiscoverError::NotFound(path.clone()));
        }
        if !requested_paths.contains(path) {
            requested_paths.push(path.clone());
        }
    }
    if requested_paths.is_empty() {
        return Err(DiscoverError::NotFound(PathBuf::from("<empty discovery>")));
    }

    let projects = discover_project_candidates(&requested_paths, &mut progress)?;
    progress.found_projects(projects.len())?;
    progress.begin(DiscoveryScanPhase::CandidateFiles)?;
    let mut candidate_paths = Vec::new();
    for path in &requested_paths {
        for candidate in collect_candidates(path, &mut progress)? {
            if !candidate_paths.contains(&candidate) {
                candidate_paths.push(candidate);
                progress.found_candidates(candidate_paths.len())?;
            }
        }
    }
    progress.emit()?;

    progress.begin(DiscoveryScanPhase::ParsingFiles)?;
    let mut files = Vec::with_capacity(candidate_paths.len());
    for candidate in candidate_paths {
        let scan_root = containing_input_root(&requested_paths, &candidate)
            .unwrap_or_else(|| candidate.parent().unwrap_or(&candidate).to_path_buf());
        let assignment = assign_project(&candidate, &projects);
        let relative_root =
            assignment.project_path.as_deref().unwrap_or(scan_root.as_path());
        match discover_file(relative_root, &candidate) {
            Ok(Some(mut file)) => {
                file.assignment = assignment_for_action(assignment, file.action);
                files.push(file);
            }
            Ok(None) => {}
            Err(error) => {
                let mut file =
                    warning_file(relative_root, &candidate, error.to_string());
                file.assignment = assignment_for_action(assignment, file.action);
                files.push(file);
            }
        }
        progress.parsed_file()?;
    }
    files.sort_by(|left, right| {
        left.assignment
            .project_path
            .cmp(&right.assignment.project_path)
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });

    progress.emit()?;
    Ok(Discovery { requested_paths, projects, files })
}

impl Discovery {
    pub fn projects(&self) -> &[DiscoveredProject] {
        &self.projects
    }

    /// Return only keys whose discovered values may reuse an existing Shared Secret.
    ///
    /// Callers can use this before loading plaintext from the secret store, avoiding
    /// unrelated decryptions during discovery.
    pub fn shared_secret_candidate_keys(&self) -> HashSet<String> {
        self.files
            .iter()
            .filter(|file| matches!(file.entry_disposition, EntryDisposition::SharedSecret))
            .flat_map(|file| file.entries.iter())
            .filter(|entry| classify_key(&entry.key) == KeyClass::Secret)
            .map(|entry| entry.key.clone())
            .collect()
    }

    /// Produce the review-safe plan. No plaintext candidate value is serialized or returned.
    pub fn plan(&self, existing: &[ExistingSecret]) -> DiscoveryPlan {
        self.plan_with_projects(existing, &[])
    }

    /// Produce a review-safe plan with the keys already exported by a managed project.
    pub fn plan_with_projects(
        &self,
        existing: &[ExistingSecret],
        managed_projects: &[ExistingProject],
    ) -> DiscoveryPlan {
        let mut reused_secrets = 0;
        let mut new_secrets = 0;
        let mut missing_reference_entries = 0;
        let mut discovered_groups = Vec::<(&str, &[u8], String)>::new();
        let mut discovered_dotenv_keys = HashMap::<String, HashSet<String>>::new();
        for file in self.files.iter().filter(|file| {
            file.kind == DiscoveredFileKind::Dotenv
                && file.action == DiscoveredFileAction::Compose
        }) {
            let keys = discovered_dotenv_keys
                .entry(normalize_environment(file.environment.as_deref()))
                .or_default();
            keys.extend(file.entries.iter().map(|entry| entry.key.clone()));
        }
        let mut files = Vec::with_capacity(self.files.len());
        for file in &self.files {
            let managed_project = file
                .assignment
                .project_path
                .as_ref()
                .and_then(|path| managed_projects.iter().find(|project| &project.path == path));
            let managed_surface = managed_project
                .and_then(|project| {
                    project.environments.iter().find(|environment| {
                        normalize_environment(Some(&environment.name))
                            == normalize_environment(file.environment.as_deref())
                    })
                })
                .and_then(|environment| {
                    reference_target_path(&file.path).and_then(|target| {
                        environment
                            .surfaces
                            .iter()
                            .find(|surface| surface.path == target)
                    })
                });
            let mut entries = Vec::with_capacity(file.entries.len());
            for entry in &file.entries {
                let action = match file.entry_disposition {
                    EntryDisposition::SharedSecret => {
                        if classify_key(&entry.key) == KeyClass::Plain {
                            DiscoveredEntryAction::CreateEnvFileEntry
                        } else if let Some(candidate) = existing.iter().find(|candidate| {
                            candidate.key == entry.key
                                && candidate.value.as_slice() == entry.value.as_bytes()
                        }) {
                            reused_secrets += 1;
                            DiscoveredEntryAction::ReuseSharedSecret {
                                resource_id: candidate.resource_id.clone(),
                                resource_name: candidate.name.clone(),
                            }
                        } else if let Some((_, _, group_id)) =
                            discovered_groups.iter().find(|(key, value, _)| {
                                *key == entry.key && *value == entry.value.as_bytes()
                            })
                        {
                            reused_secrets += 1;
                            DiscoveredEntryAction::ReuseDiscoveredSecret {
                                group_id: group_id.clone(),
                            }
                        } else {
                            new_secrets += 1;
                            let group_id = format!("discovered-{new_secrets}");
                            discovered_groups.push((
                                entry.key.as_str(),
                                entry.value.as_bytes(),
                                group_id.clone(),
                            ));
                            DiscoveredEntryAction::CreateSharedSecret { group_id }
                        }
                    }
                    EntryDisposition::EnvFile => DiscoveredEntryAction::CreateEnvFileEntry,
                    EntryDisposition::ProtectedFile => {
                        DiscoveredEntryAction::KeepInProtectedFile
                    }
                    EntryDisposition::Reference => {
                        let environment = normalize_environment(file.environment.as_deref());
                        let matched = discovered_dotenv_keys
                            .get(&environment)
                            .is_some_and(|keys| keys.contains(entry.key.as_str()))
                            || managed_surface
                                .is_some_and(|surface| surface.keys.contains(&entry.key));
                        if !matched {
                            missing_reference_entries += 1;
                        }
                        DiscoveredEntryAction::ReferenceEntry { matched }
                    }
                };
                entries.push(DiscoveredEntry {
                    address: entry.address.clone(),
                    key: entry.key.clone(),
                    section: entry.section.clone(),
                    action,
                });
            }
            files.push(DiscoveredFile {
                path: file.path.clone(),
                relative_path: file.relative_path.clone(),
                assignment: file.assignment.clone(),
                kind: file.kind,
                codec: file.codec,
                environment: file.environment.clone(),
                managed_surface_id: managed_surface.map(|surface| surface.id.clone()),
                tags: file.tags.clone(),
                entries,
                warnings: file.warnings.clone(),
                action: file.action,
                placement: placement_caution(&file.relative_path),
            });
        }
        let entries = files.iter().map(|file| file.entries.len()).sum();
        let warnings = files.iter().map(|file| file.warnings.len()).sum();

        let mut projects = self.projects.clone();
        for project in &mut projects {
            project.managed_project_id = managed_projects
                .iter()
                .find(|existing| existing.path == project.path)
                .map(|existing| existing.id.clone());
        }
        DiscoveryPlan {
            paths: self.requested_paths.clone(),
            projects,
            summary: DiscoverySummary {
                files: files.len(),
                entries,
                new_secrets,
                reused_secrets,
                missing_reference_entries,
                warnings,
            },
            files,
        }
    }

    pub fn into_contents(self) -> Vec<DiscoveredContent> {
        self.files
            .into_iter()
            .map(|file| DiscoveredContent {
                path: file.path,
                relative_path: file.relative_path,
                assignment: file.assignment,
                kind: file.kind,
                codec: file.codec,
                environment: file.environment,
                entries: file
                    .entries
                    .into_iter()
                    .map(|entry| DiscoveredValue {
                        address: entry.address,
                        key: entry.key,
                        section: entry.section,
                        value: entry.value,
                    })
                    .collect(),
                warnings: file.warnings,
                action: file.action,
            })
            .collect()
    }
}

fn discover_project_candidates(
    inputs: &[PathBuf],
    progress: &mut ProgressReporter<'_>,
) -> Result<Vec<DiscoveredProject>, DiscoverError> {
    let mut inspected_directories = HashSet::new();
    for input in inputs {
        let start = if input.is_dir() {
            input.as_path()
        } else {
            input.parent().unwrap_or(input)
        };
        collect_directories(start, &mut inspected_directories, progress)?;
        for ancestor in start.ancestors().skip(1).take(MAX_DEPTH) {
            inspected_directories.insert(ancestor.to_path_buf());
            if ancestor.join(".git").exists() {
                break;
            }
        }
    }

    let mut marker_directories = inspected_directories
        .into_iter()
        .filter_map(|directory| {
            let markers = project_markers(&directory);
            (!markers.is_empty()).then_some((directory, markers))
        })
        .collect::<Vec<_>>();
    marker_directories.sort_by(|left, right| {
        path_depth(&left.0)
            .cmp(&path_depth(&right.0))
            .then_with(|| left.0.cmp(&right.0))
    });

    let mut projects = marker_directories
        .iter()
        .filter(|(_, markers)| markers.iter().any(|marker| marker.kind == ProjectMarkerKind::Git))
        .map(|(path, markers)| discovered_project(path, markers.clone()))
        .collect::<Vec<_>>();

    for (path, markers) in marker_directories {
        if markers.iter().any(|marker| marker.kind == ProjectMarkerKind::Git) {
            continue;
        }
        if let Some(project) = projects
            .iter_mut()
            .filter(|project| path.starts_with(&project.path))
            .max_by_key(|project| path_depth(&project.path))
        {
            merge_project_markers(project, markers);
            continue;
        }
        if let Some(project) = projects
            .iter_mut()
            .filter(|project| {
                !project
                    .markers
                    .iter()
                    .any(|marker| marker.kind == ProjectMarkerKind::Git)
                    && path.starts_with(&project.path)
            })
            .max_by_key(|project| path_depth(&project.path))
        {
            merge_project_markers(project, markers);
        } else {
            projects.push(discovered_project(&path, markers));
        }
    }

    for input in inputs.iter().filter(|input| input.is_dir()) {
        let has_project = projects.iter().any(|project| {
            project.path.starts_with(input) || input.starts_with(&project.path)
        });
        if !has_project {
            projects.push(discovered_project(
                input,
                vec![ProjectMarker {
                    kind: ProjectMarkerKind::SelectedFolder,
                    path: input.clone(),
                }],
            ));
            continue;
        }
        for candidate in collect_candidates(input, progress)? {
            if !candidate_likely_needs_project(&candidate)
                || projects.iter().any(|project| candidate.starts_with(&project.path))
            {
                continue;
            }
            let Some(parent) = candidate.parent().map(Path::to_path_buf) else { continue };
            let marker = ProjectMarker {
                kind: ProjectMarkerKind::SelectedFileParent,
                path: candidate,
            };
            if let Some(project) =
                projects.iter_mut().find(|project| project.path == parent)
            {
                merge_project_markers(project, vec![marker]);
            } else {
                projects.push(discovered_project(&parent, vec![marker]));
            }
        }
    }

    for input in inputs.iter().filter(|input| input.is_file()) {
        if !is_candidate(input) {
            continue;
        }
        let Some(parent) = input.parent() else { continue };
        let has_project = projects.iter().any(|project| input.starts_with(&project.path));
        if !has_project {
            projects.push(discovered_project(
                parent,
                vec![ProjectMarker {
                    kind: ProjectMarkerKind::SelectedFileParent,
                    path: input.clone(),
                }],
            ));
        }
    }

    projects.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(projects)
}

fn collect_directories(
    root: &Path,
    directories: &mut HashSet<PathBuf>,
    progress: &mut ProgressReporter<'_>,
) -> Result<(), DiscoverError> {
    let mut stack = vec![(root.to_path_buf(), 0usize, EcosystemContext::default())];
    while let Some((directory, depth, inherited_ecosystems)) = stack.pop() {
        if !directories.insert(directory.clone()) {
            continue;
        }
        progress.scanned_directory()?;
        if depth >= MAX_DEPTH {
            continue;
        }
        let entries = directory_entries(&directory)?;
        if is_python_virtual_environment(&entries)
            || (depth > 0 && is_cmake_out_of_source_build_tree(&directory, &entries))
        {
            continue;
        }
        let ecosystems = ecosystems_for_entries(inherited_ecosystems, &entries);
        for (entry, file_type) in entries {
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            if is_ignored_directory(&entry.path(), ecosystems) {
                continue;
            }
            stack.push((entry.path(), depth + 1, ecosystems));
        }
    }
    Ok(())
}

fn directory_entries(
    directory: &Path,
) -> Result<Vec<(fs::DirEntry, fs::FileType)>, DiscoverError> {
    fs::read_dir(directory)
        .map_err(|source| DiscoverError::Io { path: directory.to_path_buf(), source })?
        .map(|entry| {
            let entry = entry.map_err(|source| DiscoverError::Io {
                path: directory.to_path_buf(),
                source,
            })?;
            let file_type = entry.file_type().map_err(|source| DiscoverError::Io {
                path: entry.path(),
                source,
            })?;
            Ok((entry, file_type))
        })
        .collect()
}

fn is_python_virtual_environment(entries: &[(fs::DirEntry, fs::FileType)]) -> bool {
    entries
        .iter()
        .any(|(entry, file_type)| file_type.is_file() && entry.file_name() == "pyvenv.cfg")
}

fn is_cmake_out_of_source_build_tree(
    directory: &Path,
    entries: &[(fs::DirEntry, fs::FileType)],
) -> bool {
    let Some(cache) = entries
        .iter()
        .find_map(|(entry, file_type)| {
            (file_type.is_file() && entry.file_name() == "CMakeCache.txt")
                .then(|| entry.path())
        })
    else {
        return false;
    };
    let Ok(metadata) = fs::metadata(&cache) else { return false };
    if metadata.len() > MAX_FILE_SIZE {
        return false;
    }
    let Ok(contents) = fs::read_to_string(cache) else { return false };
    let Some(source) = contents
        .lines()
        .find_map(|line| line.strip_prefix("CMAKE_HOME_DIRECTORY:INTERNAL="))
    else {
        return false;
    };
    let source = Path::new(source);
    let source = fs::canonicalize(source).unwrap_or_else(|_| source.to_path_buf());
    let directory =
        fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
    source != directory
}

fn ecosystems_for_entries(
    inherited_ecosystems: EcosystemContext,
    entries: &[(fs::DirEntry, fs::FileType)],
) -> EcosystemContext {
    let starts_git_project = entries
        .iter()
        .any(|(entry, _)| entry.file_name() == ".git");
    let mut ecosystems = if starts_git_project {
        EcosystemContext::default()
    } else {
        inherited_ecosystems
    };
    for (entry, file_type) in entries {
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        match name {
            "package.json" | "bun.lock" | "bun.lockb" | "package-lock.json"
            | "pnpm-lock.yaml" | "yarn.lock" => {
                ecosystems.add(EcosystemContext::JAVASCRIPT)
            }
            "pyproject.toml" | "uv.lock" | "Pipfile" | "poetry.lock" => {
                ecosystems.add(EcosystemContext::PYTHON)
            }
            "go.mod" | "go.work" => ecosystems.add(EcosystemContext::GO),
            "Cargo.toml" | "Cargo.lock" => ecosystems.add(EcosystemContext::RUST),
            "Gemfile" => ecosystems.add(EcosystemContext::RUBY),
            "Package.swift" => ecosystems.add(EcosystemContext::SWIFT),
            "build.gradle" | "build.gradle.kts" | "settings.gradle"
            | "settings.gradle.kts" => ecosystems.add(EcosystemContext::GRADLE),
            "pom.xml" => ecosystems.add(EcosystemContext::MAVEN),
            "CMakeLists.txt" => ecosystems.add(EcosystemContext::CMAKE),
            "build.zig" | "build.zig.zon" => ecosystems.add(EcosystemContext::ZIG),
            "composer.json" => ecosystems.add(EcosystemContext::PHP),
            "serverless.yml" | "serverless.yaml" => {
                ecosystems.add(EcosystemContext::SERVERLESS)
            }
            "vite.config.js" | "vite.config.mjs" | "vite.config.cjs"
            | "vite.config.ts" | "vite.config.mts" | "vite.config.cts" => {
                ecosystems.add(EcosystemContext::VITE)
            }
            "nuxt.config.js" | "nuxt.config.mjs" | "nuxt.config.cjs"
            | "nuxt.config.ts" | "nuxt.config.mts" | "nuxt.config.cts" => {
                ecosystems.add(EcosystemContext::NUXT)
            }
            _ if name == "requirements.txt"
                || (name.starts_with("requirements-") && name.ends_with(".txt")) =>
            {
                ecosystems.add(EcosystemContext::PYTHON)
            }
            _ => {}
        }
    }
    ecosystems
}

/// Flag a credential sitting below a conventionally disposable directory.
///
/// Keyed on the path relative to the scan root, so a root the user pointed at explicitly is
/// never itself suspect: scanning `~/tmp` on purpose reports its contents without caution.
fn placement_caution(relative_path: &Path) -> Option<PlacementCaution> {
    let mut directories = relative_path.components().collect::<Vec<_>>();
    directories.pop();
    directories
        .iter()
        .any(|component| match component {
            Component::Normal(name) => name
                .to_str()
                .is_some_and(|name| {
                    name.eq_ignore_ascii_case("tmp") || name.eq_ignore_ascii_case("temp")
                }),
            _ => false,
        })
        .then_some(PlacementCaution::TemporaryDirectory)
}

fn is_ignored_directory(path: &Path, ecosystems: EcosystemContext) -> bool {
    let Some(name) = path.file_name() else { return false };
    if IGNORED_DIRECTORIES.iter().any(|ignored| name == *ignored) {
        return true;
    }
    let Some(name) = name.to_str() else { return false };
    match name {
        "build" => {
            path_ends_with(path, &[".aws-sam", "build"])
                || ecosystems.contains_any(
                    EcosystemContext::PYTHON
                        | EcosystemContext::GRADLE
                        | EcosystemContext::CMAKE
                        | EcosystemContext::ZIG,
                )
        }
        "coverage" => ecosystems
            .contains_any(EcosystemContext::JAVASCRIPT | EcosystemContext::RUBY),
        "deps" => ecosystems.contains_any(EcosystemContext::ZIG),
        "dist" => ecosystems
            .contains_any(EcosystemContext::JAVASCRIPT | EcosystemContext::PYTHON),
        "target" => ecosystems.contains_any(
            EcosystemContext::RUST
                | EcosystemContext::PYTHON
                | EcosystemContext::GRADLE
                | EcosystemContext::MAVEN,
        ),
        "vendor" => {
            ecosystems.contains_any(EcosystemContext::GO | EcosystemContext::PHP)
        }
        ".output" => ecosystems.contains_any(EcosystemContext::NUXT),
        ".vite" => ecosystems.contains_any(EcosystemContext::VITE),
        ".serverless" => ecosystems.contains_any(EcosystemContext::SERVERLESS),
        "cython_debug" | "htmlcov" | "wheels" => {
            ecosystems.contains_any(EcosystemContext::PYTHON)
        }
        ".yardoc" | "_yardoc" | "rdoc" => {
            ecosystems.contains_any(EcosystemContext::RUBY)
        }
        "Build"
            if path_ends_with(path, &["Carthage", "Build"])
                && ecosystems.contains_any(EcosystemContext::SWIFT) =>
        {
            true
        }
        "Build" => ecosystems.contains_any(EcosystemContext::CMAKE),
        "cache"
            if path_ends_with(path, &[".angular", "cache"])
                || path_ends_with(path, &[".nx", "cache"]) =>
        {
            true
        }
        "workspace-data" if path_ends_with(path, &[".nx", "workspace-data"]) => true,
        "bundle"
            if path_ends_with(path, &["vendor", "bundle"])
                && ecosystems.contains_any(EcosystemContext::RUBY) =>
        {
            true
        }
        "cache" | "unplugged"
            if path_ends_with(path, &[".yarn", name])
                && ecosystems.contains_any(EcosystemContext::JAVASCRIPT) =>
        {
            true
        }
        _ if name.starts_with("cmake-build-")
            && ecosystems.contains_any(EcosystemContext::CMAKE) =>
        {
            true
        }
        _ if name.starts_with(".nuxt-")
            && ecosystems.contains_any(EcosystemContext::NUXT) =>
        {
            true
        }
        _ if name.starts_with("build-")
            && ecosystems.contains_any(EcosystemContext::CMAKE | EcosystemContext::ZIG) =>
        {
            true
        }
        _ => false,
    }
}

fn path_ends_with(path: &Path, suffix: &[&str]) -> bool {
    let mut components = path.components().rev();
    suffix.iter().rev().all(|expected| {
        components
            .next()
            .is_some_and(|component| component.as_os_str() == *expected)
    })
}

fn project_markers(directory: &Path) -> Vec<ProjectMarker> {
    let mut markers = Vec::new();
    let known = [
        (".git", ProjectMarkerKind::Git),
        ("package.json", ProjectMarkerKind::PackageJson),
        ("bun.lock", ProjectMarkerKind::JavaScriptLock),
        ("bun.lockb", ProjectMarkerKind::JavaScriptLock),
        ("package-lock.json", ProjectMarkerKind::JavaScriptLock),
        ("pnpm-lock.yaml", ProjectMarkerKind::JavaScriptLock),
        ("yarn.lock", ProjectMarkerKind::JavaScriptLock),
        ("pyproject.toml", ProjectMarkerKind::Pyproject),
        ("uv.lock", ProjectMarkerKind::PythonRequirements),
        ("Pipfile", ProjectMarkerKind::PythonRequirements),
        ("poetry.lock", ProjectMarkerKind::PythonRequirements),
        ("go.mod", ProjectMarkerKind::GoModule),
        ("go.work", ProjectMarkerKind::GoModule),
        ("Cargo.toml", ProjectMarkerKind::Cargo),
        ("Cargo.lock", ProjectMarkerKind::CargoLock),
        ("Gemfile", ProjectMarkerKind::Ruby),
        ("Package.swift", ProjectMarkerKind::Swift),
        ("build.gradle", ProjectMarkerKind::Gradle),
        ("build.gradle.kts", ProjectMarkerKind::Gradle),
        ("settings.gradle", ProjectMarkerKind::Gradle),
        ("settings.gradle.kts", ProjectMarkerKind::Gradle),
        ("pom.xml", ProjectMarkerKind::Maven),
        ("CMakeLists.txt", ProjectMarkerKind::Cmake),
        ("build.zig", ProjectMarkerKind::Zig),
        ("build.zig.zon", ProjectMarkerKind::Zig),
        ("composer.json", ProjectMarkerKind::Composer),
        ("serverless.yml", ProjectMarkerKind::Serverless),
        ("serverless.yaml", ProjectMarkerKind::Serverless),
        ("wrangler.toml", ProjectMarkerKind::Wrangler),
        ("wrangler.json", ProjectMarkerKind::Wrangler),
        ("wrangler.jsonc", ProjectMarkerKind::Wrangler),
        ("vite.config.js", ProjectMarkerKind::Vite),
        ("vite.config.mjs", ProjectMarkerKind::Vite),
        ("vite.config.cjs", ProjectMarkerKind::Vite),
        ("vite.config.ts", ProjectMarkerKind::Vite),
        ("vite.config.mts", ProjectMarkerKind::Vite),
        ("vite.config.cts", ProjectMarkerKind::Vite),
        ("nuxt.config.js", ProjectMarkerKind::Nuxt),
        ("nuxt.config.mjs", ProjectMarkerKind::Nuxt),
        ("nuxt.config.cjs", ProjectMarkerKind::Nuxt),
        ("nuxt.config.ts", ProjectMarkerKind::Nuxt),
        ("nuxt.config.mts", ProjectMarkerKind::Nuxt),
        ("nuxt.config.cts", ProjectMarkerKind::Nuxt),
        ("compose.yaml", ProjectMarkerKind::Compose),
        ("compose.yml", ProjectMarkerKind::Compose),
        ("docker-compose.yaml", ProjectMarkerKind::Compose),
        ("docker-compose.yml", ProjectMarkerKind::Compose),
    ];
    for (name, kind) in known {
        let path = directory.join(name);
        if path.exists() {
            markers.push(ProjectMarker { kind, path });
        }
    }
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_str().is_some_and(|name| name.starts_with("Dockerfile"))
                && entry.path().is_file()
            {
                markers.push(ProjectMarker {
                    kind: ProjectMarkerKind::Dockerfile,
                    path: entry.path(),
                });
            }
            if name.to_str().is_some_and(|name| {
                name == "requirements.txt"
                    || (name.starts_with("requirements-") && name.ends_with(".txt"))
            }) && entry.path().is_file()
            {
                markers.push(ProjectMarker {
                    kind: ProjectMarkerKind::PythonRequirements,
                    path: entry.path(),
                });
            }
        }
    }
    markers
}

fn discovered_project(path: &Path, markers: Vec<ProjectMarker>) -> DiscoveredProject {
    let mut project = DiscoveredProject {
        name: path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Project")
            .to_string(),
        path: path.to_path_buf(),
        markers,
        ecosystems: Vec::new(),
        managed_project_id: None,
    };
    project.ecosystems = project_ecosystems(&project.markers);
    project
}

fn merge_project_markers(project: &mut DiscoveredProject, markers: Vec<ProjectMarker>) {
    for marker in markers {
        if !project.markers.contains(&marker) {
            project.markers.push(marker);
        }
    }
    project.markers.sort_by(|left, right| left.path.cmp(&right.path));
    project.ecosystems = project_ecosystems(&project.markers);
}

fn project_ecosystems(markers: &[ProjectMarker]) -> Vec<String> {
    let mut ecosystems = Vec::new();
    for marker in markers {
        let ecosystem = match marker.kind {
            ProjectMarkerKind::PackageJson => Some("javascript"),
            ProjectMarkerKind::JavaScriptLock => Some("javascript"),
            ProjectMarkerKind::Pyproject | ProjectMarkerKind::PythonRequirements => Some("python"),
            ProjectMarkerKind::GoModule => Some("go"),
            ProjectMarkerKind::Cargo | ProjectMarkerKind::CargoLock => Some("rust"),
            ProjectMarkerKind::Ruby => Some("ruby"),
            ProjectMarkerKind::Swift => Some("swift"),
            ProjectMarkerKind::Gradle => Some("gradle"),
            ProjectMarkerKind::Maven => Some("maven"),
            ProjectMarkerKind::Cmake => Some("cmake"),
            ProjectMarkerKind::Zig => Some("zig"),
            ProjectMarkerKind::Composer => Some("php"),
            ProjectMarkerKind::Serverless => Some("serverless"),
            ProjectMarkerKind::Wrangler => Some("cloudflare"),
            ProjectMarkerKind::Vite => Some("vite"),
            ProjectMarkerKind::Nuxt => Some("nuxt"),
            ProjectMarkerKind::Compose | ProjectMarkerKind::Dockerfile => Some("docker"),
            ProjectMarkerKind::Git
            | ProjectMarkerKind::SelectedFolder
            | ProjectMarkerKind::SelectedFileParent => None,
        };
        if let Some(ecosystem) = ecosystem {
            if !ecosystems.iter().any(|candidate| candidate == ecosystem) {
                ecosystems.push(ecosystem.to_string());
            }
        }
    }
    ecosystems
}

fn assign_project(path: &Path, projects: &[DiscoveredProject]) -> ProjectAssignment {
    let containing_projects = projects
        .iter()
        .filter(|project| path.starts_with(&project.path))
        .collect::<Vec<_>>();
    if let Some(project) = containing_projects
        .iter()
        .copied()
        .max_by_key(|project| path_depth(&project.path))
    {
        let candidate_project_paths = containing_projects
            .iter()
            .map(|candidate| candidate.path.clone())
            .collect::<Vec<_>>();
        if project.markers.iter().all(|marker| {
            marker.kind == ProjectMarkerKind::SelectedFileParent
        }) {
            return ProjectAssignment {
                state: ProjectAssignmentState::Unassigned,
                project_path: None,
                candidate_project_paths,
            };
        }
        return ProjectAssignment {
            state: ProjectAssignmentState::Assigned,
            project_path: Some(project.path.clone()),
            candidate_project_paths,
        };
    }
    ProjectAssignment {
        state: ProjectAssignmentState::Unassigned,
        project_path: None,
        candidate_project_paths: projects.iter().map(|project| project.path.clone()).collect(),
    }
}

fn assignment_for_action(
    mut assignment: ProjectAssignment,
    action: DiscoveredFileAction,
) -> ProjectAssignment {
    if assignment.state == ProjectAssignmentState::Unassigned
        && matches!(
            action,
            DiscoveredFileAction::Compose | DiscoveredFileAction::Reference
        )
    {
        assignment.state = ProjectAssignmentState::NeedsReview;
    }
    assignment
}

fn unassigned_project() -> ProjectAssignment {
    ProjectAssignment {
        state: ProjectAssignmentState::Unassigned,
        project_path: None,
        candidate_project_paths: Vec::new(),
    }
}

fn containing_input_root(inputs: &[PathBuf], path: &Path) -> Option<PathBuf> {
    inputs
        .iter()
        .filter_map(|input| {
            if input.is_file() {
                (input == path).then(|| input.parent().unwrap_or(input).to_path_buf())
            } else {
                path.starts_with(input).then(|| input.clone())
            }
        })
        .max_by_key(|input| path_depth(input))
}

fn path_depth(path: &Path) -> usize {
    path.components().count()
}

fn collect_candidates(
    path: &Path,
    progress: &mut ProgressReporter<'_>,
) -> Result<Vec<PathBuf>, DiscoverError> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    let mut candidates = Vec::new();
    let mut stack = vec![(path.to_path_buf(), 0usize, EcosystemContext::default())];
    while let Some((directory, depth, inherited_ecosystems)) = stack.pop() {
        progress.scanned_directory()?;
        let entries = directory_entries(&directory)?;
        if is_python_virtual_environment(&entries)
            || (depth > 0 && is_cmake_out_of_source_build_tree(&directory, &entries))
        {
            continue;
        }
        let ecosystems = ecosystems_for_entries(inherited_ecosystems, &entries);
        for (entry, file_type) in entries {
            if file_type.is_symlink() {
                continue;
            }
            let child = entry.path();
            if file_type.is_dir() {
                if depth < MAX_DEPTH && !is_ignored_directory(&child, ecosystems) {
                    stack.push((child, depth + 1, ecosystems));
                }
            } else if file_type.is_file() {
                if is_candidate(&child)
                    && dotenv_reference_marker(&child).is_none()
                    && !candidates.contains(&child)
                {
                    candidates.push(child.clone());
                    if candidates.len() >= MAX_CANDIDATES {
                        return Ok(candidates);
                    }
                }
                if is_compose_file(&child) {
                    for referenced in static_compose_references(&child, path) {
                        if !candidates.contains(&referenced) {
                            candidates.push(referenced);
                            if candidates.len() >= MAX_CANDIDATES {
                                return Ok(candidates);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(candidates)
}

fn is_compose_file(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
        matches!(
            name,
            "compose.yaml" | "compose.yml" | "docker-compose.yaml" | "docker-compose.yml"
        )
    })
}

/// Resolve only literal, local file references from common Compose forms.
///
/// Referenced paths must already exist below the selected scan root and may not be symlinks.
/// Variables, anchors, URLs, and other YAML expressions are deliberately ignored.
fn static_compose_references(compose: &Path, scan_root: &Path) -> Vec<PathBuf> {
    let Ok(text) = fs::read_to_string(compose) else { return Vec::new() };
    let canonical_root = fs::canonicalize(scan_root).unwrap_or_else(|_| scan_root.to_path_buf());
    let mut references = Vec::new();
    let mut top_section = String::new();
    let mut env_file_indent = None;

    for line in text.lines() {
        let indent = line.chars().take_while(|character| character.is_whitespace()).count();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if indent == 0 {
            top_section = trimmed
                .split_once(':')
                .map(|(key, _)| key.trim().to_string())
                .unwrap_or_default();
        }
        if env_file_indent.is_some_and(|block_indent| indent <= block_indent)
            && !trimmed.starts_with("env_file:")
        {
            env_file_indent = None;
        }

        let mut scalar = None;
        if let Some(value) = trimmed.strip_prefix("env_file:") {
            env_file_indent = Some(indent);
            if !value.trim().is_empty() {
                scalar = Some(value.trim());
            }
        } else if env_file_indent.is_some_and(|block_indent| indent > block_indent) {
            let item = trimmed.strip_prefix("- ").unwrap_or(trimmed);
            scalar = Some(item.strip_prefix("path:").map(str::trim).unwrap_or(item));
        } else if matches!(top_section.as_str(), "secrets" | "configs") {
            scalar = trimmed.strip_prefix("file:").map(str::trim);
        }

        let Some(value) = scalar.and_then(literal_yaml_path) else { continue };
        let path = compose.parent().unwrap_or(compose).join(value);
        let Ok(metadata) = fs::symlink_metadata(&path) else { continue };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            continue;
        }
        let Ok(canonical) = fs::canonicalize(&path) else { continue };
        if canonical.starts_with(&canonical_root) && !references.contains(&path) {
            references.push(path);
        }
    }
    references
}

fn literal_yaml_path(value: &str) -> Option<&str> {
    let value = value
        .split_once(" #")
        .map(|(value, _)| value)
        .unwrap_or(value)
        .trim()
        .trim_matches(|character| matches!(character, '\'' | '"'));
    if value.is_empty()
        || value.contains("${")
        || value.contains(['{', '}', '[', ']', '*', '&', '!'])
        || value.contains("://")
    {
        None
    } else {
        Some(value)
    }
}

fn is_candidate(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let parent = path.parent().and_then(Path::file_name).and_then(|name| name.to_str());
    let credential_extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".env")
        || name == ".dev.vars"
        || name.starts_with(".dev.vars.")
        || name == ".envrc"
        || matches!(name, "mise.toml" | ".mise.toml" | "mise.local.toml")
        || name == ".pgpass"
        || (name == "credentials" && parent == Some(".aws"))
        || (parent == Some(".ssh") && name.starts_with("id_") && !name.ends_with(".pub"))
        || matches!(name, ".npmrc" | ".pypirc" | ".netrc" | "pip.conf")
        || (parent == Some(".cargo") && name == "credentials.toml")
        || (parent == Some(".docker") && name == "config.json")
        || credential_extension.as_deref().is_some_and(|extension| {
            matches!(extension, "pem" | "key" | "p12" | "pfx" | "jks" | "keystore")
        })
}

fn candidate_likely_needs_project(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".env")
        || name == ".dev.vars"
        || name.starts_with(".dev.vars.")
        || name == ".envrc"
        || matches!(name, "mise.toml" | ".mise.toml" | "mise.local.toml")
}

fn credential_file_tag(path: &Path) -> &'static str {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    let parent = path.parent().and_then(Path::file_name).and_then(|name| name.to_str());
    match (parent, name) {
        (_, ".npmrc") => "javascript",
        (_, ".pypirc" | "pip.conf") => "python",
        (Some(".cargo"), "credentials.toml") => "rust",
        (Some(".docker"), "config.json") => "docker",
        (_, ".netrc") => "credentials",
        _ => "protected",
    }
}

fn is_opaque_credential_file(path: &Path) -> bool {
    credential_file_tag(path) != "protected"
}

fn discover_file(root: &Path, path: &Path) -> Result<Option<InternalFile>, DiscoverError> {
    let metadata = fs::metadata(path)
        .map_err(|source| DiscoverError::Io { path: path.to_path_buf(), source })?;
    if metadata.len() > MAX_FILE_SIZE {
        return Ok(Some(warning_file(
            root,
            path,
            format!("file exceeds the {} byte discovery limit", MAX_FILE_SIZE),
        )));
    }
    let bytes =
        fs::read(path).map_err(|source| DiscoverError::Io { path: path.to_path_buf(), source })?;
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();

    if name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".env")
        || name == ".dev.vars"
        || name.starts_with(".dev.vars.")
    {
        return Ok(Some(discover_dotenv(root, path, &bytes)));
    }
    if name == ".envrc" {
        return Ok(Some(discover_direnv(root, path, &bytes)));
    }
    if matches!(name, "mise.toml" | ".mise.toml" | "mise.local.toml") {
        return Ok(Some(discover_mise(root, path, &bytes)));
    }
    if name == "credentials"
        && path.parent().and_then(Path::file_name).and_then(|name| name.to_str()) == Some(".aws")
    {
        return Ok(Some(discover_ini(root, path, &bytes)));
    }
    if name == ".pgpass" {
        return Ok(Some(opaque_file(
            root,
            path,
            DiscoveredFileKind::Pgpass,
            DiscoveredFileAction::Protect,
            "database",
        )));
    }
    if is_opaque_credential_file(path) {
        return Ok(Some(opaque_file(
            root,
            path,
            DiscoveredFileKind::ProtectedFile,
            DiscoveredFileAction::Protect,
            credential_file_tag(path),
        )));
    }
    if looks_like_private_key(&bytes) {
        return Ok(Some(opaque_file(
            root,
            path,
            DiscoveredFileKind::SshPrivateKey,
            DiscoveredFileAction::ImportSshIdentity,
            "ssh",
        )));
    }
    let mut dotenv_warnings = Vec::new();
    let entries = if looks_like_dotenv_assignments(&bytes) {
        decode_entries(ResourceCodec::Dotenv, path, &bytes, &mut dotenv_warnings)
    } else {
        Vec::new()
    };
    if !entries.is_empty() && dotenv_warnings.is_empty() {
        return Ok(Some(structured_file(
            root,
            path,
            DiscoveredFileKind::Dotenv,
            ResourceCodec::Dotenv,
            Some("development".to_string()),
            entries,
            Vec::new(),
        )));
    }
    Ok(Some(opaque_file(
        root,
        path,
        DiscoveredFileKind::ProtectedFile,
        DiscoveredFileAction::Protect,
        credential_file_tag(path),
    )))
}

fn discover_dotenv(root: &Path, path: &Path, bytes: &[u8]) -> InternalFile {
    let mut warnings = Vec::new();
    let entries = decode_entries(ResourceCodec::Dotenv, path, bytes, &mut warnings);
    let environment = dotenv_environment(path);
    let mut file = structured_file(
        root,
        path,
        DiscoveredFileKind::Dotenv,
        ResourceCodec::Dotenv,
        environment,
        entries,
        warnings,
    );
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.split('.').any(|part| part == "local"))
    {
        file.tags.push("local".to_string());
    }
    if dotenv_reference_marker(path).is_some() {
        file.tags.push("reference".to_string());
        file.action = DiscoveredFileAction::Reference;
        file.entry_disposition = EntryDisposition::Reference;
        return file;
    }
    finalize_structured_file(file)
}

fn discover_ini(root: &Path, path: &Path, bytes: &[u8]) -> InternalFile {
    let mut warnings = Vec::new();
    let entries = decode_entries(ResourceCodec::Ini, path, bytes, &mut warnings);
    finalize_structured_file(structured_file(
        root,
        path,
        DiscoveredFileKind::AwsCredentials,
        ResourceCodec::Ini,
        None,
        entries,
        warnings,
    ))
}

fn discover_direnv(root: &Path, path: &Path, bytes: &[u8]) -> InternalFile {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            for (index, line) in text.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if has_shell_expansion(trimmed) {
                    warnings.push(DiscoveryWarning {
                        line: Some(index + 1),
                        message: "dynamic shell expression was not evaluated".to_string(),
                    });
                    continue;
                }
                match decode_source(ResourceCodec::Dotenv, &path.display().to_string(), line.as_bytes())
                {
                    Ok(decoded) if decoded.len() == 1 => {
                        let decoded = decoded.into_iter().next().expect("checked one entry");
                        if let Some(key) = decoded.key {
                            entries.push(InternalEntry {
                                address: decoded.address,
                                key,
                                section: None,
                                value: decoded.value,
                            });
                        }
                    }
                    _ => warnings.push(DiscoveryWarning {
                        line: Some(index + 1),
                        message: "unsupported .envrc statement was not evaluated".to_string(),
                    }),
                }
            }
        }
        Err(_) => warnings.push(DiscoveryWarning {
            line: None,
            message: "file is not valid UTF-8".to_string(),
        }),
    }
    finalize_structured_file(structured_file(
        root,
        path,
        DiscoveredFileKind::Direnv,
        ResourceCodec::Dotenv,
        Some("development".to_string()),
        entries,
        warnings,
    ))
}

fn discover_mise(root: &Path, path: &Path, bytes: &[u8]) -> InternalFile {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    match std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse::<toml::Value>().ok())
        .and_then(|document| document.get("env").cloned())
    {
        Some(toml::Value::Table(environment)) => {
            for (key, value) in environment {
                if key == "_" {
                    warnings.push(DiscoveryWarning {
                        line: None,
                        message: "mise env directives were recorded but not evaluated".to_string(),
                    });
                    continue;
                }
                let literal = match value {
                    toml::Value::String(value) if !has_template_expression(&value) => Some(value),
                    toml::Value::Integer(value) => Some(value.to_string()),
                    toml::Value::Float(value) => Some(value.to_string()),
                    toml::Value::Boolean(value) => Some(value.to_string()),
                    _ => None,
                };
                if let Some(value) = literal {
                    entries.push(InternalEntry {
                        address: format!("keys/{key}"),
                        key,
                        section: None,
                        value: Zeroizing::new(value),
                    });
                } else {
                    warnings.push(DiscoveryWarning {
                        line: None,
                        message: format!("dynamic mise value for {key} was not evaluated"),
                    });
                }
            }
        }
        _ => warnings.push(DiscoveryWarning {
            line: None,
            message: "mise.toml has no statically readable [env] table".to_string(),
        }),
    }
    let mut file = structured_file(
        root,
        path,
        DiscoveredFileKind::Mise,
        ResourceCodec::Dotenv,
        Some("development".to_string()),
        entries,
        warnings,
    );
    if file.entries.is_empty() {
        file.action = DiscoveredFileAction::Review;
        file.entry_disposition = EntryDisposition::ProtectedFile;
    } else {
        protect_as_is(&mut file);
    }
    file
}

fn decode_entries(
    codec: ResourceCodec,
    path: &Path,
    bytes: &[u8],
    warnings: &mut Vec<DiscoveryWarning>,
) -> Vec<InternalEntry> {
    match decode_source(codec, &path.display().to_string(), bytes) {
        Ok(decoded) => decoded
            .into_iter()
            .filter_map(|entry| {
                entry.key.map(|key| InternalEntry {
                    address: entry.address,
                    key,
                    section: entry.section,
                    value: entry.value,
                })
            })
            .collect(),
        Err(error) => {
            warnings.push(DiscoveryWarning { line: None, message: error.to_string() });
            Vec::new()
        }
    }
}

fn structured_file(
    root: &Path,
    path: &Path,
    kind: DiscoveredFileKind,
    codec: ResourceCodec,
    environment: Option<String>,
    entries: Vec<InternalEntry>,
    warnings: Vec<DiscoveryWarning>,
) -> InternalFile {
    let mut tags = vec![file_kind_tag(kind).to_string()];
    if let Some(environment) = &environment {
        tags.push(environment.clone());
    }
    InternalFile {
        path: path.to_path_buf(),
        relative_path: relative_to(root, path),
        assignment: unassigned_project(),
        kind,
        codec,
        environment,
        tags,
        entries,
        warnings,
        action: DiscoveredFileAction::Compose,
        entry_disposition: match kind {
            DiscoveredFileKind::AwsCredentials => EntryDisposition::EnvFile,
            _ => EntryDisposition::SharedSecret,
        },
    }
}

fn finalize_structured_file(mut file: InternalFile) -> InternalFile {
    if !file.warnings.is_empty() {
        protect_as_is(&mut file);
    } else if file.entries.is_empty() {
        file.action = DiscoveredFileAction::Review;
        file.entry_disposition = EntryDisposition::ProtectedFile;
    }
    file
}

fn protect_as_is(file: &mut InternalFile) {
    file.codec = ResourceCodec::Opaque;
    file.entries.clear();
    file.action = DiscoveredFileAction::Protect;
    file.entry_disposition = EntryDisposition::ProtectedFile;
}

fn opaque_file(
    root: &Path,
    path: &Path,
    kind: DiscoveredFileKind,
    action: DiscoveredFileAction,
    tag: &str,
) -> InternalFile {
    InternalFile {
        path: path.to_path_buf(),
        relative_path: relative_to(root, path),
        assignment: unassigned_project(),
        kind,
        codec: ResourceCodec::Opaque,
        environment: None,
        tags: vec![tag.to_string()],
        entries: Vec::new(),
        warnings: Vec::new(),
        action,
        entry_disposition: EntryDisposition::ProtectedFile,
    }
}

fn warning_file(root: &Path, path: &Path, message: String) -> InternalFile {
    InternalFile {
        path: path.to_path_buf(),
        relative_path: relative_to(root, path),
        assignment: unassigned_project(),
        kind: DiscoveredFileKind::Dotenv,
        codec: ResourceCodec::Opaque,
        environment: None,
        tags: Vec::new(),
        entries: Vec::new(),
        warnings: vec![DiscoveryWarning { line: None, message }],
        action: DiscoveredFileAction::Review,
        entry_disposition: EntryDisposition::ProtectedFile,
    }
}

fn dotenv_environment(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if name == ".env" {
        return Some("development".to_string());
    }
    if name == ".dev.vars" || (name.ends_with(".env") && !name.starts_with(".env.")) {
        return Some("development".to_string());
    }
    if let Some(suffix) = name.strip_prefix(".dev.vars.") {
        return Some(
            suffix
                .split('.')
                .find(|part| !part.is_empty() && *part != "local")
                .unwrap_or("development")
                .to_string(),
        );
    }
    let suffix = name.strip_prefix(".env.")?;
    suffix
        .split('.')
        .find(|part| {
            !part.is_empty()
                && *part != "local"
                && !DOTENV_REFERENCE_MARKERS.contains(part)
        })
        .map(str::to_string)
        .or_else(|| Some("development".to_string()))
}

fn normalize_environment(environment: Option<&str>) -> String {
    let normalized = environment
        .unwrap_or("development")
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-");
    if normalized.is_empty() {
        "development".to_string()
    } else {
        normalized
    }
}

const DOTENV_REFERENCE_MARKERS: &[&str] = &["example", "sample", "template", "dist"];

fn dotenv_reference_marker(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    name.strip_prefix(".env.")?
        .split('.')
        .find_map(|part| DOTENV_REFERENCE_MARKERS.iter().copied().find(|marker| *marker == part))
}

fn reference_target_path(path: &Path) -> Option<PathBuf> {
    let marker = dotenv_reference_marker(path)?;
    let file_name = path.file_name()?.to_str()?;
    let target_name = file_name.replacen(&format!(".{marker}"), "", 1);
    Some(path.with_file_name(target_name))
}

fn relative_to(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn file_kind_tag(kind: DiscoveredFileKind) -> &'static str {
    match kind {
        DiscoveredFileKind::Dotenv => "dotenv",
        DiscoveredFileKind::Direnv => "direnv",
        DiscoveredFileKind::Mise => "mise",
        DiscoveredFileKind::AwsCredentials => "aws",
        DiscoveredFileKind::Pgpass => "database",
        DiscoveredFileKind::SshPrivateKey => "ssh",
        DiscoveredFileKind::ProtectedFile => "protected",
    }
}

fn has_shell_expansion(value: &str) -> bool {
    value.contains("$(")
        || value.contains('`')
        || value.contains("${")
        || value.split('=').nth(1).is_some_and(|rhs| rhs.contains('$'))
}

fn has_template_expression(value: &str) -> bool {
    value.contains("{{") || value.contains("${") || value.contains("$(") || value.contains('`')
}

fn looks_like_private_key(bytes: &[u8]) -> bool {
    let prefix = bytes.get(..bytes.len().min(128)).unwrap_or(bytes);
    let text = String::from_utf8_lossy(prefix);
    [
        concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----"),
        concat!("-----BEGIN ", "PRIVATE KEY-----"),
        concat!("-----BEGIN RSA ", "PRIVATE KEY-----"),
        concat!("-----BEGIN EC ", "PRIVATE KEY-----"),
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn looks_like_dotenv_assignments(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else { return false };
    let mut found = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains('=') {
            return false;
        }
        found = true;
    }
    found
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn progress_callback_can_cancel_a_workspace_scan() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        for index in 0..80 {
            fs::create_dir(root.join(format!("project-{index}"))).unwrap();
        }
        let mut observed = Vec::new();

        let result = discover_many_with_progress(&[root.to_path_buf()], |progress| {
            observed.push(progress);
            progress.directories_scanned < PROGRESS_DIRECTORY_INTERVAL
        });

        assert!(matches!(result, Err(DiscoverError::Cancelled)));
        assert!(observed.iter().any(|progress| {
            progress.phase == DiscoveryScanPhase::ProjectCandidates
                && progress.directories_scanned == PROGRESS_DIRECTORY_INTERVAL
        }));
    }

    #[test]
    fn progress_reports_each_discovery_phase() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join(".git")).unwrap();
        fs::write(root.join(".env"), "FIXTURE_VALUE=plain-value\n").unwrap();
        let mut observed = Vec::new();

        let discovery = discover_many_with_progress(&[root.to_path_buf()], |progress| {
            observed.push(progress);
            true
        })
        .unwrap();

        assert_eq!(discovery.plan(&[]).summary.files, 1);
        assert!(observed.iter().any(|progress| {
            progress.phase == DiscoveryScanPhase::ProjectCandidates
                && progress.project_candidates == 1
        }));
        assert!(observed.iter().any(|progress| {
            progress.phase == DiscoveryScanPhase::CandidateFiles
                && progress.candidate_files == 1
        }));
        assert!(observed.iter().any(|progress| {
            progress.phase == DiscoveryScanPhase::ParsingFiles
                && progress.files_parsed == 1
        }));
    }

    #[test]
    fn discovers_supported_files_and_classifies_environments() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join(".git")).unwrap();
        fs::create_dir(root.join(".aws")).unwrap();
        fs::write(root.join(".env.production"), "API_TOKEN=fixture-production-value\n").unwrap();
        fs::write(root.join(".envrc"), "export LOCAL_FLAG=fixture-local\nuse flake\n").unwrap();
        fs::write(
            root.join("mise.toml"),
            "[env]\nREGION = \"fixture-region\"\nDYNAMIC = \"{{ exec(command='ignored') }}\"\n",
        )
        .unwrap();
        fs::write(
            root.join(".aws/credentials"),
            "[default]\naws_access_key_id=fixture-access-id\n",
        )
        .unwrap();
        fs::write(root.join(".pgpass"), "db.invalid|5432|fixture|fixture|fixture\n").unwrap();

        let discovery = discover(root).unwrap();
        let plan = discovery.plan(&[]);

        assert_eq!(plan.projects.len(), 1);
        assert_eq!(plan.projects[0].path, root);
        assert_eq!(plan.summary.files, 5);
        assert_eq!(plan.summary.entries, 2);
        assert_eq!(plan.summary.new_secrets, 1);
        assert_eq!(plan.summary.warnings, 2);
        assert!(plan.files.iter().any(|file| {
            file.relative_path == Path::new(".envrc")
                && file.entries.is_empty()
                && file.action == DiscoveredFileAction::Protect
        }));
        assert_eq!(
            plan.files
                .iter()
                .find(|file| file.relative_path == Path::new(".env.production"))
                .and_then(|file| file.environment.as_deref()),
            Some("production")
        );
        assert!(plan.files.iter().any(|file| {
            file.kind == DiscoveredFileKind::Pgpass
                && file.action == DiscoveredFileAction::Protect
        }));
        assert!(plan.files.iter().any(|file| {
            file.kind == DiscoveredFileKind::AwsCredentials
                && file.entries.iter().all(|entry| {
                    entry.action == DiscoveredEntryAction::CreateEnvFileEntry
                })
        }));
        assert!(plan.files.iter().any(|file| {
            file.kind == DiscoveredFileKind::Mise
                && file.entries.is_empty()
                && file.action == DiscoveredFileAction::Protect
        }));
    }

    #[test]
    fn exact_key_and_value_reuses_an_existing_shared_secret() {
        let directory = tempdir().unwrap();
        let file = directory.path().join(".env");
        fs::write(&file, "API_TOKEN=fixture-shared-value\n").unwrap();
        let discovery = discover(&file).unwrap();
        let existing = [ExistingSecret {
            resource_id: "shared-api-token".to_string(),
            name: "Shared API token".to_string(),
            key: "API_TOKEN".to_string(),
            value: Zeroizing::new(b"fixture-shared-value".to_vec()),
        }];

        let plan = discovery.plan(&existing);

        assert_eq!(plan.paths, vec![file]);
        assert_eq!(plan.summary.reused_secrets, 1);
        assert_eq!(plan.summary.new_secrets, 0);
        assert_eq!(
            plan.files[0].entries[0].action,
            DiscoveredEntryAction::ReuseSharedSecret {
                resource_id: "shared-api-token".to_string(),
                resource_name: "Shared API token".to_string(),
            }
        );
    }

    #[test]
    fn repeated_values_in_one_discovery_share_a_redacted_candidate_group() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join(".env"), "API_TOKEN=fixture-shared-value\n").unwrap();
        fs::write(
            root.join(".env.production"),
            "API_TOKEN=fixture-shared-value\n",
        )
        .unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.new_secrets, 1);
        assert_eq!(plan.summary.reused_secrets, 1);
        let first_action = &plan.files[0].entries[0].action;
        let second_action = &plan.files[1].entries[0].action;
        let DiscoveredEntryAction::CreateSharedSecret { group_id } = first_action else {
            panic!("expected first entry to create the candidate group");
        };
        assert_eq!(
            second_action,
            &DiscoveredEntryAction::ReuseDiscoveredSecret {
                group_id: group_id.clone()
            }
        );
        let serialized = serde_json::to_string(&plan).unwrap();
        assert!(!serialized.contains("fixture-shared-value"));
    }

    #[test]
    fn does_not_execute_dynamic_direnv_or_mise_content() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join(".envrc"), "SAFE=fixture\nDYNAMIC=$(untrusted-command)\n").unwrap();
        fs::write(root.join("mise.toml"), "[env]\nSAFE=\"fixture\"\nDYNAMIC=\"{{ exec() }}\"\n")
            .unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert!(plan.files.iter().all(|file| file.entries.is_empty()));
        assert_eq!(plan.summary.warnings, 2);
        assert!(plan
            .files
            .iter()
            .all(|file| file.action == DiscoveredFileAction::Protect));
    }

    #[test]
    fn static_direnv_content_remains_available_for_structured_sharing() {
        let directory = tempdir().unwrap();
        let file = directory.path().join(".envrc");
        fs::write(
            &file,
            "export API_TOKEN=fixture-token\nexport REGION=fixture-region\n",
        )
        .unwrap();

        let plan = discover(&file).unwrap().plan(&[]);

        assert_eq!(plan.files[0].action, DiscoveredFileAction::Compose);
        assert_eq!(plan.files[0].entries.len(), 2);
        assert!(plan.files[0].warnings.is_empty());
    }

    #[test]
    fn ignores_symlinks_and_dependency_directories() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("node_modules")).unwrap();
        fs::create_dir(root.join(".venv")).unwrap();
        fs::create_dir_all(root.join("deps/openssl")).unwrap();
        fs::create_dir_all(root.join("python-runtime")).unwrap();
        fs::write(root.join("node_modules/.env"), "IGNORED=fixture\n").unwrap();
        fs::write(root.join(".venv/cacert.pem"), "IGNORED=fixture\n").unwrap();
        fs::write(
            root.join("deps/openssl/cacert.pem"),
            "IGNORED=fixture\n",
        )
        .unwrap();
        fs::write(root.join("build.zig"), "pub fn build() void {}\n").unwrap();
        fs::write(root.join("python-runtime/pyvenv.cfg"), "home = /fixture/python\n").unwrap();
        fs::write(
            root.join("python-runtime/cacert.pem"),
            "IGNORED=fixture\n",
        )
        .unwrap();
        fs::write(root.join(".env"), "VISIBLE=fixture\n").unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 1);
        assert_eq!(plan.files[0].relative_path, Path::new(".env"));
    }

    #[test]
    fn reports_credentials_below_temporary_directories_as_needing_confirmation() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::create_dir_all(root.join("tmp/secrets")).unwrap();
        fs::write(
            root.join("tmp/secrets/customs.key.pem"),
            "-----BEGIN FIXTURE MATERIAL-----\nfixture\n-----END FIXTURE MATERIAL-----\n",
        )
        .unwrap();
        fs::write(root.join(".env"), "VISIBLE=fixture\n").unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        // Scanning is unaffected: the key is still discovered, only flagged for confirmation.
        let key = plan
            .files
            .iter()
            .find(|file| file.relative_path == Path::new("tmp/secrets/customs.key.pem"))
            .expect("a credential below tmp is still discovered");
        assert_eq!(key.placement, Some(PlacementCaution::TemporaryDirectory));

        let env = plan
            .files
            .iter()
            .find(|file| file.relative_path == Path::new(".env"))
            .expect("the ordinary file is discovered");
        assert_eq!(env.placement, None);
    }

    #[test]
    fn temporary_placement_matches_whole_segments_only() {
        for cautioned in ["tmp/x.pem", "TMP/x.pem", "temp/nested/x.pem", "a/tmp/x.pem"] {
            assert_eq!(
                placement_caution(Path::new(cautioned)),
                Some(PlacementCaution::TemporaryDirectory),
                "{cautioned} should be flagged"
            );
        }
        // A file *named* tmp, a directory merely containing the substring, and the scan root
        // itself must not be flagged.
        for plain in ["tmp.env", "contemporary/x.pem", "tmpfiles/x.pem", ".env"] {
            assert_eq!(
                placement_caution(Path::new(plain)),
                None,
                "{plain} should not be flagged"
            );
        }
    }

    #[test]
    fn ignores_unambiguous_generated_ecosystem_directories() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        for generated in [
            ".gradle",
            ".pnpm-store",
            ".terraform",
            "__pypackages__",
            "CMakeFiles",
            "DerivedData",
        ] {
            let generated = root.join(generated);
            fs::create_dir_all(&generated).unwrap();
            fs::write(generated.join(".env"), "IGNORED=fixture\n").unwrap();
        }
        fs::write(root.join(".env"), "VISIBLE=fixture\n").unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 1);
        assert_eq!(plan.files[0].relative_path, Path::new(".env"));
    }

    #[test]
    fn ignores_tool_owned_state_and_structurally_identified_build_trees() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        for generated in [".wrangler", "zig-out", ".astro", ".docusaurus", "cdk.out"] {
            let generated = root.join(generated);
            fs::create_dir_all(&generated).unwrap();
            fs::write(generated.join(".env"), "IGNORED=fixture\n").unwrap();
        }
        for generated in [
            ".angular/cache",
            ".nx/cache",
            ".nx/workspace-data",
            ".aws-sam/build",
        ] {
            let generated = root.join(generated);
            fs::create_dir_all(&generated).unwrap();
            fs::write(generated.join(".env"), "IGNORED=fixture\n").unwrap();
        }
        let cmake_build = root.join("arbitrary-cmake-output");
        fs::create_dir_all(&cmake_build).unwrap();
        fs::write(
            cmake_build.join("CMakeCache.txt"),
            format!(
                "CMAKE_HOME_DIRECTORY:INTERNAL={}\n",
                root.to_string_lossy()
            ),
        )
        .unwrap();
        fs::write(cmake_build.join(".env"), "IGNORED=fixture\n").unwrap();
        fs::write(root.join(".angular/.env"), "VISIBLE_ANGULAR=fixture\n").unwrap();
        fs::write(root.join(".nx/.env"), "VISIBLE_NX=fixture\n").unwrap();
        fs::write(root.join(".aws-sam/.env"), "VISIBLE_SAM=fixture\n").unwrap();
        fs::write(root.join(".dev.vars"), "VISIBLE=fixture\n").unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 4);
        let relative_paths = plan
            .files
            .iter()
            .map(|file| file.relative_path.as_path())
            .collect::<HashSet<_>>();
        assert_eq!(
            relative_paths,
            HashSet::from([
                Path::new(".angular/.env"),
                Path::new(".nx/.env"),
                Path::new(".aws-sam/.env"),
                Path::new(".dev.vars"),
            ])
        );
    }

    #[test]
    fn keeps_a_cmake_source_tree_after_an_in_source_build() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        let project = root.join("cmake-source");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("CMakeLists.txt"), "project(fixture)\n").unwrap();
        fs::write(
            project.join("CMakeCache.txt"),
            format!(
                "CMAKE_HOME_DIRECTORY:INTERNAL={}\n",
                project.to_string_lossy()
            ),
        )
        .unwrap();
        fs::write(project.join(".env"), "VISIBLE=fixture\n").unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 1);
        assert_eq!(plan.files[0].path, project.join(".env"));
    }

    #[test]
    fn ignores_ambiguous_output_names_only_in_matching_ecosystems() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        let projects = [
            ("javascript", "package.json", vec!["dist", "coverage", ".yarn/cache"]),
            ("python", "pyproject.toml", vec!["build", "dist", "htmlcov"]),
            ("rust", "Cargo.toml", vec!["target"]),
            ("go", "go.mod", vec!["vendor"]),
            ("ruby", "Gemfile", vec!["coverage", ".yardoc"]),
            ("ruby-bundler", "Gemfile", vec!["vendor/bundle"]),
            ("swift", "Package.swift", vec!["Carthage/Build"]),
            ("cmake", "CMakeLists.txt", vec!["build", "cmake-build-debug"]),
            ("cmake-uppercase", "CMakeLists.txt", vec!["Build"]),
            ("zig", "build.zig", vec!["build-release", "deps"]),
            ("php", "composer.json", vec!["vendor"]),
            ("gradle", "build.gradle", vec!["build"]),
            ("maven", "pom.xml", vec!["target"]),
            (
                "serverless",
                "serverless.yml",
                vec![".serverless"],
            ),
            ("vite", "vite.config.ts", vec![".vite"]),
            (
                "nuxt",
                "nuxt.config.ts",
                vec![".output", ".nuxt-build"],
            ),
        ];
        for (project_name, marker, outputs) in projects {
            let project = root.join(project_name);
            fs::create_dir_all(&project).unwrap();
            fs::write(project.join(marker), "fixture\n").unwrap();
            for output in outputs {
                let output = project.join(output);
                fs::create_dir_all(&output).unwrap();
                fs::write(output.join(".env"), "IGNORED=fixture\n").unwrap();
            }
        }
        fs::write(root.join(".env"), "VISIBLE=fixture\n").unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 1);
        assert_eq!(plan.files[0].relative_path, Path::new(".env"));
    }

    #[test]
    fn keeps_ambiguous_directory_names_without_matching_ecosystem_markers() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        for ordinary in [
            "build",
            "coverage",
            "deps",
            "dist",
            "target",
            "vendor",
            "cmake-build-debug",
            ".yarn/cache",
            "Carthage/Build",
            ".serverless",
            ".vite",
            ".output",
            ".webpack",
        ] {
            let ordinary = root.join(ordinary);
            fs::create_dir_all(&ordinary).unwrap();
            fs::write(ordinary.join(".env"), "VISIBLE=fixture\n").unwrap();
        }

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 13);
    }

    #[test]
    fn generic_javascript_context_does_not_imply_framework_outputs() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join("package.json"), "{}\n").unwrap();
        for ordinary in [".vite", ".output", ".webpack"] {
            fs::create_dir_all(root.join(ordinary)).unwrap();
            fs::write(root.join(ordinary).join(".env"), "VISIBLE=fixture\n").unwrap();
        }

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 3);
    }

    #[test]
    fn ecosystem_context_stops_at_a_nested_git_project() {
        let directory = tempdir().unwrap();
        let workspace = directory.path();
        fs::write(workspace.join("CMakeLists.txt"), "project(parent)\n").unwrap();
        let nested = workspace.join("independent");
        fs::create_dir_all(nested.join(".git")).unwrap();
        fs::create_dir_all(nested.join("Build")).unwrap();
        fs::write(nested.join("Build/.env"), "VISIBLE=fixture\n").unwrap();

        let plan = discover(workspace).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 1);
        assert_eq!(plan.files[0].path, nested.join("Build/.env"));
    }

    #[test]
    fn classifies_local_dotenv_as_development_with_a_local_tag() {
        let directory = tempdir().unwrap();
        let file = directory.path().join(".env.development.local");
        fs::write(&file, "LOCAL_ONLY=fixture-local-value\n").unwrap();

        let plan = discover(&file).unwrap().plan(&[]);

        assert_eq!(plan.files[0].environment.as_deref(), Some("development"));
        assert!(plan.files[0].tags.iter().any(|tag| tag == "local"));
    }

    #[test]
    fn classifies_common_secret_names_by_segment_not_substring() {
        for key in [
            "FEISHU_OAUTH_APP_SECRET",
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_BEARER_TOKEN",
            "QUEBEC_DSN",
            "DATABASE_URL",
            "AWS_SECRET_ACCESS_KEY",
            "STRIPE_API_KEY",
            "SSH_PRIVATE_KEY",
            "BASIC_AUTH",
            "postgres_password",
        ] {
            assert_eq!(classify_key(key), KeyClass::Secret, "{key} should be a secret");
        }
        for key in [
            "DEBUG",
            "COMS_ENV",
            "WEBAUTHN_RP_ID",
            "WEBAUTHN_ORIGIN",
            "LEGACY_SYNC_KAFKA_GROUP_ID",
            "FEISHU_OAUTH_ENABLED",
            "FEISHU_OAUTH_APP_ID",
            "FEISHU_OAUTH_REDIRECT_BASE",
            "CLOUDFLARE_ZONE_ID",
            "SORT_KEY_NAME",
            "MONKEY",
        ] {
            assert_eq!(classify_key(key), KeyClass::Plain, "{key} should be plain");
        }
    }

    #[test]
    fn plain_named_keys_become_env_file_entries_and_never_match_reuse() {
        let directory = tempdir().unwrap();
        let file = directory.path().join(".env");
        fs::write(&file, "API_TOKEN=fixture-value\nDEBUG=true\n").unwrap();
        let existing = [ExistingSecret {
            resource_id: "shared-debug".to_string(),
            name: "Debug".to_string(),
            key: "DEBUG".to_string(),
            value: Zeroizing::new(b"true".to_vec()),
        }];

        let plan = discover(&file).unwrap().plan(&existing);

        assert_eq!(plan.summary.new_secrets, 1);
        assert_eq!(plan.summary.reused_secrets, 0);
        let entries = &plan.files[0].entries;
        assert!(entries.iter().any(|entry| {
            entry.key == "DEBUG" && entry.action == DiscoveredEntryAction::CreateEnvFileEntry
        }));
        assert!(entries.iter().any(|entry| {
            entry.key == "API_TOKEN"
                && matches!(entry.action, DiscoveredEntryAction::CreateSharedSecret { .. })
        }));
    }

    #[test]
    fn automatic_scan_excludes_dotenv_reference_templates() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(root.join(".env"), "API_TOKEN=fixture-real-value\n").unwrap();
        fs::write(
            root.join(".env.example"),
            "API_TOKEN=replace-me\nOPTIONAL_FLAG=false\n",
        )
        .unwrap();
        fs::write(
            root.join(".env.production.sample"),
            "API_TOKEN=replace-production\n",
        )
        .unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 1);
        assert_eq!(plan.summary.new_secrets, 1);
        assert_eq!(plan.files[0].relative_path, Path::new(".env"));
    }

    #[test]
    fn an_explicit_dotenv_template_is_available_as_a_reference() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        let example_path = root.join(".env.example");
        fs::write(
            &example_path,
            "API_TOKEN=replace-me\nOPTIONAL_FLAG=false\n",
        )
        .unwrap();
        let target_path = root.join(".env");
        fs::write(&target_path, "API_TOKEN=fixture-real-value\n").unwrap();

        let plan = discover_many(&[target_path, example_path]).unwrap().plan(&[]);

        let example = plan
            .files
            .iter()
            .find(|file| file.relative_path == Path::new(".env.example"))
            .unwrap();
        assert_eq!(example.action, DiscoveredFileAction::Reference);
        assert_eq!(example.environment.as_deref(), Some("development"));
        assert!(example.tags.iter().any(|tag| tag == "reference"));
        assert!(example
            .entries
            .iter()
            .any(|entry| {
                entry.key == "API_TOKEN"
                    && entry.action
                        == DiscoveredEntryAction::ReferenceEntry { matched: true }
            }));
        assert!(example.entries.iter().any(|entry| {
            entry.key == "OPTIONAL_FLAG"
                && entry.action
                    == DiscoveredEntryAction::ReferenceEntry { matched: false }
        }));
        assert_eq!(plan.summary.missing_reference_entries, 1);
    }

    #[test]
    fn managed_environment_outputs_cover_reference_keys_without_source_files() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::write(
            root.join(".env.qa-west.example"),
            "MANAGED_TOKEN=replace-me\nMISSING_TOKEN=replace-me\n",
        )
        .unwrap();
        let managed = ExistingProject {
            id: "fixture-project".to_string(),
            path: root.to_path_buf(),
            environments: vec![ExistingEnvironment {
                name: "QA West".to_string(),
                surfaces: vec![ExistingSurface {
                    id: "fixture-surface".to_string(),
                    path: root.join(".env.qa-west"),
                    keys: vec!["MANAGED_TOKEN".to_string()],
                }],
            }],
        };

        let plan = discover_many(&[
            root.to_path_buf(),
            root.join(".env.qa-west.example"),
        ])
            .unwrap()
            .plan_with_projects(&[], &[managed]);

        assert_eq!(
            plan.projects[0].managed_project_id.as_deref(),
            Some("fixture-project")
        );
        assert_eq!(plan.summary.missing_reference_entries, 1);
        assert_eq!(plan.files[0].managed_surface_id.as_deref(), Some("fixture-surface"));
        let entries = &plan.files[0].entries;
        assert!(entries.iter().any(|entry| {
            entry.key == "MANAGED_TOKEN"
                && entry.action
                    == DiscoveredEntryAction::ReferenceEntry { matched: true }
        }));
        assert!(entries.iter().any(|entry| {
            entry.key == "MISSING_TOKEN"
                && entry.action
                    == DiscoveredEntryAction::ReferenceEntry { matched: false }
        }));
    }

    #[test]
    fn workspace_discovery_groups_files_by_independent_git_projects() {
        let directory = tempdir().unwrap();
        let workspace = directory.path();
        let web = workspace.join("web");
        let api = workspace.join("api");
        fs::create_dir_all(web.join(".git")).unwrap();
        fs::create_dir_all(api.join(".git")).unwrap();
        fs::write(web.join("package.json"), "{}\n").unwrap();
        fs::write(web.join(".env"), "WEB_TOKEN=fixture-web\n").unwrap();
        fs::write(api.join("pyproject.toml"), "[project]\nname='fixture'\n").unwrap();
        fs::write(api.join(".env"), "API_TOKEN=fixture-api\n").unwrap();
        fs::write(workspace.join(".env"), "SHARED_TOKEN=fixture-shared\n").unwrap();

        let plan = discover(workspace).unwrap().plan(&[]);

        assert_eq!(plan.projects.len(), 3);
        assert_eq!(
            plan.projects
                .iter()
                .map(|project| project.path.clone())
                .collect::<HashSet<_>>(),
            HashSet::from([workspace.to_path_buf(), web.clone(), api.clone()])
        );
        assert!(plan.projects.iter().any(|project| {
            project.path == web && project.ecosystems == ["javascript"]
        }));
        assert!(plan.projects.iter().any(|project| {
            project.path == api && project.ecosystems == ["python"]
        }));
        assert!(plan.files.iter().any(|file| {
            file.path == web.join(".env")
                && file.assignment.state == ProjectAssignmentState::Assigned
                && file.assignment.project_path.as_ref() == Some(&web)
        }));
        let shared = plan
            .files
            .iter()
            .find(|file| file.path == workspace.join(".env"))
            .unwrap();
        assert_eq!(shared.assignment.state, ProjectAssignmentState::NeedsReview);
        assert_eq!(
            shared.assignment.candidate_project_paths,
            vec![workspace.to_path_buf()]
        );
    }

    #[test]
    fn one_git_project_can_be_polyglot() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join(".git")).unwrap();
        fs::write(root.join("package.json"), "{}\n").unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname='fixture'\nversion='0.0.0'\n")
            .unwrap();
        fs::write(root.join(".env"), "APP_TOKEN=fixture-app\n").unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.projects.len(), 1);
        assert_eq!(
            plan.projects[0]
                .ecosystems
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>(),
            HashSet::from(["javascript", "rust"])
        );
    }

    #[test]
    fn package_markers_find_mainstream_projects_without_git() {
        let directory = tempdir().unwrap();
        let workspace = directory.path();
        let projects = [
            ("javascript", "package.json", "{}\n"),
            ("python", "requirements.txt", "fixture-package==0.0.0\n"),
            ("go", "go.mod", "module example.invalid/fixture\n"),
            (
                "rust",
                "Cargo.toml",
                "[package]\nname='fixture'\nversion='0.0.0'\n",
            ),
            ("ruby", "Gemfile", "source 'https://example.invalid'\n"),
            ("swift", "Package.swift", "// swift-tools-version: 6.0\n"),
            ("gradle", "build.gradle.kts", "plugins {}\n"),
            ("maven", "pom.xml", "<project />\n"),
            ("cmake", "CMakeLists.txt", "project(fixture)\n"),
            ("zig", "build.zig", "const std = @import(\"std\");\n"),
            ("php", "composer.json", "{}\n"),
            ("serverless", "serverless.yml", "service: fixture\n"),
            ("cloudflare", "wrangler.toml", "name = \"fixture\"\n"),
            ("vite", "vite.config.ts", "export default {}\n"),
            ("nuxt", "nuxt.config.ts", "export default {}\n"),
            ("docker", "compose.yaml", "services: {}\n"),
        ];
        for (name, marker, contents) in projects {
            let path = workspace.join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join(".env"), "FIXTURE_VALUE=not-a-secret\n").unwrap();
            fs::write(path.join(marker), contents).unwrap();
        }

        let plan = discover(workspace).unwrap().plan(&[]);

        assert_eq!(plan.projects.len(), 16);
        let ecosystems = plan
            .projects
            .iter()
            .flat_map(|project| project.ecosystems.iter().map(String::as_str))
            .collect::<HashSet<_>>();
        assert_eq!(
            ecosystems,
            HashSet::from([
                "javascript",
                "python",
                "go",
                "rust",
                "ruby",
                "swift",
                "gradle",
                "maven",
                "cmake",
                "zig",
                "php",
                "serverless",
                "cloudflare",
                "vite",
                "nuxt",
                "docker",
            ])
        );
        assert!(plan
            .files
            .iter()
            .all(|file| file.assignment.state == ProjectAssignmentState::Assigned));
    }

    #[test]
    fn compose_literal_file_references_join_discovery_without_following_outside_paths() {
        let directory = tempdir().unwrap();
        let project = directory.path().join("project");
        let outside = directory.path().join("outside.env");
        fs::create_dir_all(project.join("secrets")).unwrap();
        fs::write(project.join("runtime.values"), "APP_MODE=fixture\n").unwrap();
        fs::write(project.join("secrets/database-password"), "fixture-password\n").unwrap();
        fs::write(&outside, "OUTSIDE_VALUE=ignored\n").unwrap();
        fs::write(
            project.join("compose.yaml"),
            format!(
                "services:\n  app:\n    env_file:\n      - runtime.values\nsecrets:\n  database_password:\n    file: ./secrets/database-password\nconfigs:\n  outside:\n    file: {}\n",
                outside.display()
            ),
        )
        .unwrap();

        let plan = discover(&project).unwrap().plan(&[]);

        assert!(plan.files.iter().any(|file| {
            file.relative_path == Path::new("runtime.values")
                && file.kind == DiscoveredFileKind::Dotenv
                && file.action == DiscoveredFileAction::Compose
        }));
        assert!(
            plan.files.iter().any(|file| {
                file.relative_path == Path::new("secrets/database-password")
                    && file.kind == DiscoveredFileKind::ProtectedFile
                    && file.action == DiscoveredFileAction::Protect
            }),
            "{plan:#?}"
        );
        assert!(!plan.files.iter().any(|file| file.path == outside));
    }

    #[test]
    fn an_explicit_unknown_file_is_discovered_losslessly() {
        let directory = tempdir().unwrap();
        let file = directory.path().join("credential.data");
        fs::write(&file, "fixture opaque credential\n").unwrap();

        let plan = discover(&file).unwrap().plan(&[]);

        assert_eq!(plan.projects.len(), 0);
        assert_eq!(plan.files.len(), 1);
        assert_eq!(plan.files[0].kind, DiscoveredFileKind::ProtectedFile);
        assert_eq!(plan.files[0].action, DiscoveredFileAction::Protect);
        assert_eq!(
            plan.files[0].assignment.state,
            ProjectAssignmentState::Unassigned
        );
    }

    #[test]
    fn workspace_discovery_includes_binary_pkcs12_credentials() {
        let directory = tempdir().unwrap();
        let file = directory.path().join("client-identity.p12");
        fs::write(&file, b"\x30\x82\x00\x08\xff\x00fixture-p12").unwrap();

        let explicit_plan = discover(&file).unwrap().plan(&[]);
        assert_eq!(explicit_plan.files.len(), 1);
        assert_eq!(explicit_plan.files[0].kind, DiscoveredFileKind::ProtectedFile);
        assert_eq!(explicit_plan.files[0].action, DiscoveredFileAction::Protect);

        let plan = discover(directory.path()).unwrap().plan(&[]);

        assert!(plan.files.iter().any(|candidate| {
            candidate.path == file
                && candidate.kind == DiscoveredFileKind::ProtectedFile
                && candidate.action == DiscoveredFileAction::Protect
        }));
    }

    #[test]
    fn an_explicit_dotenv_without_project_markers_requires_parent_confirmation() {
        let directory = tempdir().unwrap();
        let file = directory.path().join(".env");
        fs::write(&file, "SERVICE_TOKEN=fixture-value\n").unwrap();

        let plan = discover(&file).unwrap().plan(&[]);

        assert_eq!(plan.projects.len(), 1);
        assert_eq!(plan.projects[0].path, directory.path());
        assert_eq!(
            plan.projects[0].markers[0].kind,
            ProjectMarkerKind::SelectedFileParent
        );
        assert_eq!(plan.files.len(), 1);
        assert_eq!(
            plan.files[0].assignment.state,
            ProjectAssignmentState::NeedsReview
        );
        assert_eq!(plan.files[0].assignment.project_path, None);
        assert_eq!(
            plan.files[0].assignment.candidate_project_paths,
            vec![directory.path().to_path_buf()]
        );
    }
}
