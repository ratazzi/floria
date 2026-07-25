//! Static discovery of project-local configuration and credential files.
//!
//! Discovery never executes project code. It produces a redacted plan for review while retaining
//! plaintext only in zeroizing values long enough to compare candidates with existing resources.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use accessfs_catalog::ResourceCodec;
use accessfs_surface::decode_source;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

mod git;

pub use git::{
    discover_git_checkouts, DiscoveredGitCheckout, GitCheckoutDiscovery, GitCheckoutError,
};

const MAX_DEPTH: usize = 6;
const MAX_CANDIDATES: usize = 1_000;
const MAX_FILE_SIZE: u64 = 1 << 20;
const IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    ".direnv",
    ".build",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
];

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("discover path must be absolute: {0}")]
    RelativePath(PathBuf),
    #[error("discover path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("cannot inspect {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryPlan {
    pub path: PathBuf,
    pub project: DiscoveredProject,
    pub files: Vec<DiscoveredFile>,
    pub summary: DiscoverySummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredProject {
    pub name: String,
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_project_id: Option<String>,
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
    pub kind: DiscoveredFileKind,
    pub codec: ResourceCodec,
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_surface_id: Option<String>,
    pub tags: Vec<String>,
    pub entries: Vec<DiscoveredEntry>,
    pub warnings: Vec<DiscoveryWarning>,
    pub action: DiscoveredFileAction,
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
    requested_path: PathBuf,
    project: DiscoveredProject,
    files: Vec<InternalFile>,
}

/// Plaintext-bearing discovery output for a trusted, local mutation boundary.
///
/// This type deliberately implements neither `Debug` nor `Serialize`.
pub struct DiscoveredContent {
    pub path: PathBuf,
    pub relative_path: PathBuf,
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

/// Discover supported files below `path` without executing any project-controlled content.
pub fn discover(path: &Path) -> Result<Discovery, DiscoverError> {
    if !path.is_absolute() {
        return Err(DiscoverError::RelativePath(path.to_path_buf()));
    }
    if !path.exists() {
        return Err(DiscoverError::NotFound(path.to_path_buf()));
    }

    let root = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };
    let project_path = find_project_root(&root);
    let project = DiscoveredProject {
        name: project_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Project")
            .to_string(),
        path: project_path,
        managed_project_id: None,
    };

    let candidates = collect_candidates(path)?;
    let mut files = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        match discover_file(&root, &candidate) {
            Ok(Some(file)) => files.push(file),
            Ok(None) => {}
            Err(error) => files.push(warning_file(&root, &candidate, error.to_string())),
        }
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    Ok(Discovery {
        requested_path: path.to_path_buf(),
        project,
        files,
    })
}

impl Discovery {
    pub fn project(&self) -> &DiscoveredProject {
        &self.project
    }

    /// Produce the review-safe plan. No plaintext candidate value is serialized or returned.
    pub fn plan(&self, existing: &[ExistingSecret]) -> DiscoveryPlan {
        self.plan_with_project(existing, None)
    }

    /// Produce a review-safe plan with the keys already exported by a managed project.
    pub fn plan_with_project(
        &self,
        existing: &[ExistingSecret],
        managed_project: Option<&ExistingProject>,
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
                        if let Some(candidate) = existing.iter().find(|candidate| {
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
                kind: file.kind,
                codec: file.codec,
                environment: file.environment.clone(),
                managed_surface_id: managed_surface.map(|surface| surface.id.clone()),
                tags: file.tags.clone(),
                entries,
                warnings: file.warnings.clone(),
                action: file.action,
            });
        }
        let entries = files.iter().map(|file| file.entries.len()).sum();
        let warnings = files.iter().map(|file| file.warnings.len()).sum();

        let mut project = self.project.clone();
        project.managed_project_id = managed_project.map(|existing| existing.id.clone());
        DiscoveryPlan {
            path: self.requested_path.clone(),
            project,
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

fn collect_candidates(path: &Path) -> Result<Vec<PathBuf>, DiscoverError> {
    if path.is_file() {
        return Ok(if is_candidate(path) {
            vec![path.to_path_buf()]
        } else {
            Vec::new()
        });
    }

    let mut candidates = Vec::new();
    let mut stack = vec![(path.to_path_buf(), 0usize)];
    while let Some((directory, depth)) = stack.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|source| DiscoverError::Io { path: directory.clone(), source })?;
        for entry in entries {
            let entry = entry.map_err(|source| DiscoverError::Io {
                path: directory.clone(),
                source,
            })?;
            let file_type = entry.file_type().map_err(|source| DiscoverError::Io {
                path: entry.path(),
                source,
            })?;
            if file_type.is_symlink() {
                continue;
            }
            let child = entry.path();
            if file_type.is_dir() {
                let name = entry.file_name();
                if depth < MAX_DEPTH
                    && !IGNORED_DIRECTORIES.iter().any(|ignored| name == *ignored)
                {
                    stack.push((child, depth + 1));
                }
            } else if file_type.is_file() && is_candidate(&child) {
                candidates.push(child);
                if candidates.len() >= MAX_CANDIDATES {
                    return Ok(candidates);
                }
            }
        }
    }
    Ok(candidates)
}

fn is_candidate(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let parent = path.parent().and_then(Path::file_name).and_then(|name| name.to_str());
    name == ".env"
        || name.starts_with(".env.")
        || name == ".envrc"
        || matches!(name, "mise.toml" | ".mise.toml" | "mise.local.toml")
        || name == ".pgpass"
        || (name == "credentials" && parent == Some(".aws"))
        || (parent == Some(".ssh") && name.starts_with("id_") && !name.ends_with(".pub"))
        || name.ends_with(".pem")
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

    if name == ".env" || name.starts_with(".env.") {
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
    if looks_like_private_key(&bytes) {
        return Ok(Some(opaque_file(
            root,
            path,
            DiscoveredFileKind::SshPrivateKey,
            DiscoveredFileAction::ImportSshIdentity,
            "ssh",
        )));
    }
    Ok(None)
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
    }
    file
}

fn discover_ini(root: &Path, path: &Path, bytes: &[u8]) -> InternalFile {
    let mut warnings = Vec::new();
    let entries = decode_entries(ResourceCodec::Ini, path, bytes, &mut warnings);
    structured_file(
        root,
        path,
        DiscoveredFileKind::AwsCredentials,
        ResourceCodec::Ini,
        None,
        entries,
        warnings,
    )
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
    structured_file(
        root,
        path,
        DiscoveredFileKind::Direnv,
        ResourceCodec::Dotenv,
        Some("development".to_string()),
        entries,
        warnings,
    )
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
    file.action = DiscoveredFileAction::Review;
    file.entry_disposition = EntryDisposition::ProtectedFile;
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

fn find_project_root(start: &Path) -> PathBuf {
    let fallback = match start.file_name().and_then(|name| name.to_str()) {
        Some(".aws" | ".ssh") => start.parent().unwrap_or(start),
        _ => start,
    };
    let mut current = Some(start);
    while let Some(path) = current {
        if path.join(".git").exists() {
            return path.to_path_buf();
        }
        current = path.parent();
    }
    fallback.to_path_buf()
}

fn dotenv_environment(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if name == ".env" {
        return Some("development".to_string());
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;

    use tempfile::tempdir;

    use super::*;

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

        assert_eq!(plan.project.path, root);
        assert_eq!(plan.summary.files, 5);
        assert_eq!(plan.summary.entries, 4);
        assert_eq!(plan.summary.new_secrets, 2);
        assert_eq!(plan.summary.warnings, 2);
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

        assert_eq!(plan.path, file);
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

        let keys = plan
            .files
            .iter()
            .flat_map(|file| file.entries.iter().map(|entry| entry.key.as_str()))
            .collect::<HashSet<_>>();
        assert_eq!(keys, HashSet::from(["SAFE"]));
        assert_eq!(plan.summary.warnings, 2);
        assert_eq!(
            plan.files
                .iter()
                .find(|file| file.kind == DiscoveredFileKind::Mise)
                .map(|file| file.action),
            Some(DiscoveredFileAction::Review)
        );
    }

    #[test]
    fn ignores_symlinks_and_dependency_directories() {
        let directory = tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules/.env"), "IGNORED=fixture\n").unwrap();
        fs::write(root.join(".env"), "VISIBLE=fixture\n").unwrap();

        let plan = discover(root).unwrap().plan(&[]);

        assert_eq!(plan.summary.files, 1);
        assert_eq!(plan.files[0].relative_path, Path::new(".env"));
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
    fn classifies_dotenv_examples_as_references_without_secret_candidates() {
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

        assert_eq!(plan.summary.new_secrets, 1);
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
        assert_eq!(plan.summary.missing_reference_entries, 2);

        let production = plan
            .files
            .iter()
            .find(|file| file.relative_path == Path::new(".env.production.sample"))
            .unwrap();
        assert_eq!(production.action, DiscoveredFileAction::Reference);
        assert_eq!(production.environment.as_deref(), Some("production"));
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
            environments: vec![ExistingEnvironment {
                name: "QA West".to_string(),
                surfaces: vec![ExistingSurface {
                    id: "fixture-surface".to_string(),
                    path: root.join(".env.qa-west"),
                    keys: vec!["MANAGED_TOKEN".to_string()],
                }],
            }],
        };

        let plan = discover(root).unwrap().plan_with_project(&[], Some(&managed));

        assert_eq!(plan.project.managed_project_id.as_deref(), Some("fixture-project"));
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
}
