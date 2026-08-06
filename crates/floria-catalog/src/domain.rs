use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use floria_core::authz::Enforcement;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
pub use floria_core::metadata::{ItemLink, ItemMetadata};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    /// Materialized path of the primary checkout. The catalog persists this on the corresponding
    /// `ProjectCheckout`, keeping Project itself independent from local working directories.
    pub path: PathBuf,
    /// Environment newly discovered worktrees are provisioned with automatically.
    /// `None` keeps worktree linking manual.
    #[serde(default)]
    pub default_environment_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectCheckoutKind {
    Primary,
    /// The default: worktrees are the many, the primary is the singleton
    /// `upsert_project` creates itself.
    #[default]
    Worktree,
}

impl ProjectCheckoutKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ProjectCheckoutKind::Primary => "primary",
            ProjectCheckoutKind::Worktree => "worktree",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "primary" => Some(ProjectCheckoutKind::Primary),
            "worktree" => Some(ProjectCheckoutKind::Worktree),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCheckout {
    pub id: String,
    pub project_id: String,
    pub path: PathBuf,
    /// Primary checkouts expose the project's explicitly configured links. Provisioned worktrees
    /// select one environment so Production is never inferred from a branch name.
    #[serde(default)]
    pub environment_id: Option<String>,
    pub kind: ProjectCheckoutKind,
    #[serde(default)]
    pub git_common_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    pub id: String,
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub position: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    SharedSecret,
    Secret,
    EnvFile,
    Literal,
    Command,
    SshIdentity,
    SshAgent,
}

impl ResourceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ResourceKind::SharedSecret => "shared_secret",
            ResourceKind::Secret => "secret",
            ResourceKind::EnvFile => "env_file",
            ResourceKind::Literal => "literal",
            ResourceKind::Command => "command",
            ResourceKind::SshIdentity => "ssh_identity",
            ResourceKind::SshAgent => "ssh_agent",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "shared_secret" => Some(ResourceKind::SharedSecret),
            "secret" => Some(ResourceKind::Secret),
            "env_file" => Some(ResourceKind::EnvFile),
            "literal" => Some(ResourceKind::Literal),
            "command" => Some(ResourceKind::Command),
            "ssh_identity" => Some(ResourceKind::SshIdentity),
            "ssh_agent" => Some(ResourceKind::SshAgent),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueShape {
    Scalar,
    KeyValueSet,
    Bytes,
    SshIdentity,
    Socket,
}

impl ValueShape {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ValueShape::Scalar => "scalar",
            ValueShape::KeyValueSet => "key_value_set",
            ValueShape::Bytes => "bytes",
            ValueShape::SshIdentity => "ssh_identity",
            ValueShape::Socket => "socket",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "scalar" => Some(ValueShape::Scalar),
            "key_value_set" => Some(ValueShape::KeyValueSet),
            "bytes" => Some(ValueShape::Bytes),
            "ssh_identity" => Some(ValueShape::SshIdentity),
            "socket" => Some(ValueShape::Socket),
            _ => None,
        }
    }
}

/// Grammar used to decode a Resource's opaque source bytes into addressed entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCodec {
    Opaque,
    Dotenv,
    Ini,
}

impl ResourceCodec {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ResourceCodec::Opaque => "opaque",
            ResourceCodec::Dotenv => "dotenv",
            ResourceCodec::Ini => "ini",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "opaque" => Some(ResourceCodec::Opaque),
            "dotenv" => Some(ResourceCodec::Dotenv),
            "ini" => Some(ResourceCodec::Ini),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySpec {
    pub address: String,
    pub label: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub sensitive: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntrySelection {
    #[default]
    All,
    Entries { addresses: Vec<String> },
}

/// How a resource obtains its value. Secret values are referenced by id and never stored here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceSource {
    SecretRef { secret_id: String },
    Literal { value: String },
    Command { argv: Vec<String> },
    Socket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub name: String,
    pub kind: ResourceKind,
    pub shape: ValueShape,
    pub codec: ResourceCodec,
    #[serde(default)]
    pub default_env_key: Option<String>,
    #[serde(default)]
    pub entries: Vec<EntrySpec>,
    pub source: ResourceSource,
    /// Default authorization behavior when no explicit process rule matches this resource.
    pub enforcement: Enforcement,
    #[serde(default)]
    pub metadata: ItemMetadata,
    /// System-maintained provenance. Unlike `metadata`, it is never user-edited.
    #[serde(default)]
    pub origin: ResourceOrigin,
}

/// Where a resource came from and every file it was imported or reused from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceOrigin {
    #[serde(default)]
    pub kind: OriginKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<OriginSource>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginKind {
    /// Predates origin tracking.
    #[default]
    Unknown,
    Manual,
    Discovered,
    SshImport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginSource {
    /// Absolute path of the file the value was imported from.
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// RFC 3339 timestamp of the import that recorded this source.
    pub imported_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BindingScope {
    #[default]
    Common,
    Environment { environment_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub id: String,
    pub project_id: String,
    pub scope: BindingScope,
    pub resource_id: String,
    #[serde(default)]
    pub selection: EntrySelection,
    #[serde(default)]
    pub key_override: Option<String>,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Allows an environment binding to replace a conflicting common export explicitly.
    #[serde(default)]
    pub allow_override: bool,
    #[serde(default)]
    pub position: i64,
}

fn enabled_by_default() -> bool {
    true
}

// Hand-written so `enabled` matches the serde default (true); a derived
// Default would silently construct disabled bindings.
impl Default for Binding {
    fn default() -> Self {
        Binding {
            id: String::new(),
            project_id: String::new(),
            scope: BindingScope::default(),
            resource_id: String::new(),
            selection: EntrySelection::default(),
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceFormat {
    Dotenv,
    Direnv,
    Ini,
    Lines,
}

/// The catalog-side document shape accepted by one composed surface format.
///
/// This is domain compatibility data, not byte-layout behavior. The catalog uses it while
/// validating writes and the surface resolver uses the same value to choose its resolution
/// pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatInputModel {
    /// A resolved environment projection with override, conflict, and environment-key semantics.
    EnvironmentProjection,
    /// Ordered key/value entries, optionally carrying structural metadata such as an INI section.
    StructuredEntries {
        required_kind: ResourceKind,
        required_shape: ValueShape,
        required_codec: ResourceCodec,
        stored_only: bool,
    },
    /// Ordered scalar values whose selected entries must not expose keys.
    KeylessScalars {
        required_codec: ResourceCodec,
        allow_literal: bool,
    },
}

/// The complete catalog compatibility contract for one composed output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatSpec {
    pub input: FormatInputModel,
    pub allow_key_override: bool,
}

impl SurfaceFormat {
    pub const fn spec(self) -> FormatSpec {
        match self {
            SurfaceFormat::Dotenv | SurfaceFormat::Direnv => FormatSpec {
                input: FormatInputModel::EnvironmentProjection,
                allow_key_override: true,
            },
            SurfaceFormat::Ini => FormatSpec {
                input: FormatInputModel::StructuredEntries {
                    required_kind: ResourceKind::EnvFile,
                    required_shape: ValueShape::KeyValueSet,
                    required_codec: ResourceCodec::Ini,
                    stored_only: true,
                },
                allow_key_override: false,
            },
            SurfaceFormat::Lines => FormatSpec {
                input: FormatInputModel::KeylessScalars {
                    required_codec: ResourceCodec::Opaque,
                    allow_literal: true,
                },
                allow_key_override: false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBacking {
    /// Rendered from bindings on every open.
    Composed(SurfaceFormat),
    /// Raw passthrough of one env_file resource.
    EnvFileDirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    File(FileBacking),
    UnixSocket,
}

impl SurfaceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)) => "dotenv_file",
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv)) => "direnv_file",
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)) => "ini_file",
            SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)) => "lines_file",
            SurfaceKind::File(FileBacking::EnvFileDirect) => "env_file_direct",
            SurfaceKind::UnixSocket => "unix_socket",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "dotenv_file" => Some(SurfaceKind::File(FileBacking::Composed(
                SurfaceFormat::Dotenv,
            ))),
            "direnv_file" => Some(SurfaceKind::File(FileBacking::Composed(
                SurfaceFormat::Direnv,
            ))),
            "ini_file" => Some(SurfaceKind::File(FileBacking::Composed(
                SurfaceFormat::Ini,
            ))),
            "env_file_direct" => Some(SurfaceKind::File(FileBacking::EnvFileDirect)),
            "lines_file" => Some(SurfaceKind::File(FileBacking::Composed(
                SurfaceFormat::Lines,
            ))),
            "unix_socket" => Some(SurfaceKind::UnixSocket),
            _ => None,
        }
    }

    pub const fn is_file(self) -> bool {
        matches!(self, SurfaceKind::File(_))
    }

    pub const fn composed_format(self) -> Option<SurfaceFormat> {
        match self {
            SurfaceKind::File(FileBacking::Composed(format)) => Some(format),
            SurfaceKind::File(FileBacking::EnvFileDirect) | SurfaceKind::UnixSocket => None,
        }
    }
}

impl Serialize for SurfaceKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SurfaceKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        SurfaceKind::parse(&value)
            .ok_or_else(|| D::Error::custom(format!("unknown surface kind {value:?}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SurfaceInput {
    Bindings { binding_ids: Vec<String> },
    SshAgent {
        binding_ids: Vec<String>,
        #[serde(default)]
        route: Option<SshRouteSpec>,
    },
    Resource { resource_id: String },
}

impl SurfaceInput {
    pub fn binding_ids(&self) -> Option<&[String]> {
        match self {
            SurfaceInput::Bindings { binding_ids }
            | SurfaceInput::SshAgent { binding_ids, .. } => Some(binding_ids),
            SurfaceInput::Resource { .. } => None,
        }
    }
}

/// One OpenSSH `Host` route selecting a filtered agent surface. Multiple patterns share the same
/// socket and identity set; richer DSLs can compile to additional surfaces without changing the
/// runtime contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshRouteSpec {
    pub host_patterns: Vec<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub forward_agent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Surface {
    pub id: String,
    pub environment_id: String,
    pub name: String,
    pub kind: SurfaceKind,
    /// Project-local materialization path for file surfaces. Capability surfaces such as an SSH
    /// agent have no catalog path; their machine-local endpoint is derived at runtime.
    pub path: Option<PathBuf>,
    pub input: SurfaceInput,
    pub enforcement: Enforcement,
    #[serde(default)]
    pub position: i64,
}

/// Catalog rows removed when one discovered file stops using a configured surface.
///
/// A discovered resource can outlive the surface when another managed file still reuses it.
/// Callers use `resource_removed` to decide whether its encrypted backing can also be deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedFileConfigurationRemoval {
    pub binding_removed: bool,
    pub resource_removed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    pub projects: Vec<Project>,
    #[serde(default)]
    pub checkouts: Vec<ProjectCheckout>,
    pub environments: Vec<Environment>,
    pub resources: Vec<Resource>,
    /// Machine-local endpoints keyed by socket resource id. This table is excluded from sync.
    #[serde(default)]
    pub endpoints: HashMap<String, PathBuf>,
    pub bindings: Vec<Binding>,
    pub surfaces: Vec<Surface>,
}

/// Portable catalog state carried inside an encrypted replication Operation.
///
/// Checkout paths, resource endpoints, and import origins are deliberately absent: they are
/// device-local overlays and are preserved when this projection is applied on another Mac.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicatedCatalog {
    pub format_version: u32,
    pub projects: Vec<ReplicatedProject>,
    pub environments: Vec<Environment>,
    pub resources: Vec<Resource>,
    pub bindings: Vec<Binding>,
    pub surfaces: Vec<ReplicatedSurface>,
}

impl Default for ReplicatedCatalog {
    fn default() -> Self {
        Self {
            format_version: 1,
            projects: Vec::new(),
            environments: Vec::new(),
            resources: Vec::new(),
            bindings: Vec::new(),
            surfaces: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicatedProject {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub default_environment_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicatedSurface {
    pub id: String,
    pub environment_id: String,
    pub name: String,
    pub kind: SurfaceKind,
    /// Project-relative path. Socket surfaces carry `None`.
    #[serde(default)]
    pub relative_path: Option<PathBuf>,
    pub input: SurfaceInput,
    pub enforcement: Enforcement,
    #[serde(default)]
    pub position: i64,
}

/// One immutable local-store version referenced by a replication outbox row.
/// Export never rereads a mutable store head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationStoreVersionRef {
    pub secret_id: String,
    pub version: u32,
}

/// A committed shared mutation waiting for sequence allocation, signing, and publication.
/// `catalog_payload` contains only shared catalog state; secret bytes remain in the referenced
/// immutable store versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationOutboxEntry {
    pub intent_id: String,
    pub logical_id: String,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default)]
    pub store_versions: Vec<ReplicationStoreVersionRef>,
    pub catalog_payload: Vec<u8>,
    pub created_at: String,
}

impl CatalogSnapshot {
    /// Stable identity used by the public `items/` namespace for a file Surface.
    ///
    /// A direct Env File is a configured view of an existing protected file, so it retains the
    /// backing Secret id. Other Surfaces are independently created Managed Items and use their
    /// own stable Surface id.
    pub fn managed_item_id_for_surface<'a>(&'a self, surface: &'a Surface) -> &'a str {
        if !surface.kind.is_file() {
            return &surface.id;
        }
        let resource_id = match &surface.input {
            SurfaceInput::Resource { resource_id } => Some(resource_id.as_str()),
            SurfaceInput::Bindings { binding_ids } if binding_ids.len() == 1 => self
                .bindings
                .iter()
                .find(|binding| binding.id == binding_ids[0])
                .map(|binding| binding.resource_id.as_str()),
            _ => None,
        };
        let Some(resource_id) = resource_id else {
            return &surface.id;
        };
        self.resources
            .iter()
            .find(|resource| {
                resource.id == resource_id
                    && resource.kind == ResourceKind::EnvFile
                    && surface.path.as_ref().is_some_and(|surface_path| {
                        resource
                            .origin
                            .sources
                            .iter()
                            .any(|source| source.path == *surface_path)
                    })
            })
            .and_then(|resource| match &resource.source {
                ResourceSource::SecretRef { secret_id } => Some(secret_id.as_str()),
                _ => None,
            })
            .unwrap_or(&surface.id)
    }

    /// Stored secrets whose former file-origin path is now represented by a configured file
    /// surface. This is the semantic boundary between byte-preserving managed files and
    /// explicitly configured outputs.
    pub fn file_surface_secret_ids(&self) -> HashSet<&str> {
        self.surfaces
            .iter()
            .filter(|surface| {
                self.managed_item_id_for_surface(surface) != surface.id.as_str()
            })
            .map(|surface| self.managed_item_id_for_surface(surface))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedExport {
    pub key: String,
    /// Stable catalog address used to locate the decoded resource entry.
    pub address: String,
    pub binding_id: String,
    pub resource_id: String,
    pub resource_name: String,
    pub sensitive: bool,
    #[serde(default)]
    pub overrides_binding_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEnvironment {
    pub project_id: String,
    pub environment_id: String,
    pub exports: Vec<ResolvedExport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBindingUsage {
    pub binding_id: String,
    pub project_id: String,
    pub scope: BindingScope,
    pub environment_ids: Vec<String>,
    pub surface_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub resource_id: String,
    pub bindings: Vec<ResourceBindingUsage>,
    pub direct_surface_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_formats_declare_their_catalog_input_contract() {
        for format in [SurfaceFormat::Dotenv, SurfaceFormat::Direnv] {
            let spec = format.spec();
            assert_eq!(spec.input, FormatInputModel::EnvironmentProjection);
            assert!(spec.allow_key_override);
        }

        let ini = SurfaceFormat::Ini.spec();
        assert_eq!(
            ini.input,
            FormatInputModel::StructuredEntries {
                required_kind: ResourceKind::EnvFile,
                required_shape: ValueShape::KeyValueSet,
                required_codec: ResourceCodec::Ini,
                stored_only: true,
            }
        );
        assert!(!ini.allow_key_override);

        let lines = SurfaceFormat::Lines.spec();
        assert_eq!(
            lines.input,
            FormatInputModel::KeylessScalars {
                required_codec: ResourceCodec::Opaque,
                allow_literal: true,
            }
        );
        assert!(!lines.allow_key_override);
    }

    #[test]
    fn file_surface_secret_ids_excludes_unconfigured_resources() {
        let resource = |id: &str, secret_id: &str| Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Dotenv,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "keys/FIXTURE".to_string(),
                label: "FIXTURE".to_string(),
                key: Some("FIXTURE".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: secret_id.to_string() },
            enforcement: Enforcement::Prompt,
            metadata: ItemMetadata::default(),
            origin: ResourceOrigin {
                kind: OriginKind::Discovered,
                sources: vec![OriginSource {
                    path: PathBuf::from("/fixture/.env"),
                    project_id: Some("fixture-project".to_string()),
                    environment: Some("Development".to_string()),
                    imported_at: "2026-08-05T00:00:00Z".to_string(),
                }],
            },
        };
        let snapshot = CatalogSnapshot {
            resources: vec![
                resource("configured", "configured-secret"),
                resource("unconfigured", "unconfigured-secret"),
            ],
            bindings: vec![Binding {
                id: "configured-binding".to_string(),
                project_id: "fixture-project".to_string(),
                scope: BindingScope::Environment {
                    environment_id: "fixture-environment".to_string(),
                },
                resource_id: "configured".to_string(),
                ..Default::default()
            }],
            surfaces: vec![Surface {
                id: "fixture-surface".to_string(),
                environment_id: "fixture-environment".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: Some(PathBuf::from("/fixture/.env")),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["configured-binding".to_string()],
                },
                enforcement: Enforcement::Prompt,
                position: 0,
            }],
            ..Default::default()
        };

        assert_eq!(
            snapshot.file_surface_secret_ids(),
            HashSet::from(["configured-secret"])
        );
    }

    #[test]
    fn managed_item_identity_only_follows_a_file_to_its_origin_surface() {
        let origin_path = PathBuf::from("/fixture/.env");
        let resource = Resource {
            id: "fixture-resource".to_string(),
            name: ".env".to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Dotenv,
            default_env_key: None,
            entries: Vec::new(),
            source: ResourceSource::SecretRef {
                secret_id: "fixture-secret".to_string(),
            },
            enforcement: Enforcement::Prompt,
            metadata: ItemMetadata::default(),
            origin: ResourceOrigin {
                kind: OriginKind::Discovered,
                sources: vec![OriginSource {
                    path: origin_path.clone(),
                    project_id: Some("fixture-project".to_string()),
                    environment: Some("Development".to_string()),
                    imported_at: "2026-08-05T00:00:00Z".to_string(),
                }],
            },
        };
        let make_surface = |id: &str, path: PathBuf| Surface {
            id: id.to_string(),
            environment_id: "fixture-environment".to_string(),
            name: path
                .file_name()
                .expect("fixture path has a basename")
                .to_string_lossy()
                .into_owned(),
            kind: SurfaceKind::File(FileBacking::EnvFileDirect),
            path: Some(path),
            input: SurfaceInput::Resource {
                resource_id: resource.id.clone(),
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        let configured_file = make_surface("configured-file", origin_path);
        let additional_output = make_surface(
            "additional-output",
            PathBuf::from("/fixture/generated/.env"),
        );
        let snapshot = CatalogSnapshot {
            resources: vec![resource],
            surfaces: vec![configured_file.clone(), additional_output.clone()],
            ..Default::default()
        };

        assert_eq!(
            snapshot.managed_item_id_for_surface(&configured_file),
            "fixture-secret"
        );
        assert_eq!(
            snapshot.managed_item_id_for_surface(&additional_output),
            "additional-output"
        );
        assert_eq!(
            snapshot.file_surface_secret_ids(),
            HashSet::from(["fixture-secret"])
        );
    }

    #[test]
    fn surface_kind_round_trips_database_and_flat_json_names() {
        let cases = [
            (
                SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                "dotenv_file",
            ),
            (
                SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Direnv)),
                "direnv_file",
            ),
            (
                SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)),
                "ini_file",
            ),
            (
                SurfaceKind::File(FileBacking::EnvFileDirect),
                "env_file_direct",
            ),
            (
                SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
                "lines_file",
            ),
            (SurfaceKind::UnixSocket, "unix_socket"),
        ];

        for (kind, name) in cases {
            assert_eq!(kind.as_str(), name);
            assert_eq!(SurfaceKind::parse(name), Some(kind));

            let encoded = serde_json::to_string(&kind).unwrap();
            assert_eq!(encoded, format!("\"{name}\""));
            assert_eq!(serde_json::from_str::<SurfaceKind>(&encoded).unwrap(), kind);
        }
        assert_eq!(SurfaceKind::parse("unknown"), None);
        assert_eq!(SurfaceKind::parse("regular_file"), None);
    }

    #[test]
    fn legacy_socket_source_json_ignores_the_embedded_endpoint() {
        let source: ResourceSource = serde_json::from_str(
            r#"{"type":"socket","endpoint":"/fixture/legacy-agent.sock"}"#,
        )
        .unwrap();
        assert_eq!(source, ResourceSource::Socket);
        assert_eq!(
            serde_json::to_string(&source).unwrap(),
            r#"{"type":"socket"}"#
        );
    }
}
