use std::path::PathBuf;

use accessfs_core::authz::Enforcement;
use serde::{Deserialize, Serialize};
pub use accessfs_core::metadata::{ItemLink, ItemMetadata};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    Socket { endpoint: PathBuf },
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BindingScope {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceKind {
    DotenvFile,
    DirenvFile,
    IniFile,
    EnvFileDirect,
    LinesFile,
    RegularFile,
    UnixSocket,
}

impl SurfaceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SurfaceKind::DotenvFile => "dotenv_file",
            SurfaceKind::DirenvFile => "direnv_file",
            SurfaceKind::IniFile => "ini_file",
            SurfaceKind::EnvFileDirect => "env_file_direct",
            SurfaceKind::LinesFile => "lines_file",
            SurfaceKind::RegularFile => "regular_file",
            SurfaceKind::UnixSocket => "unix_socket",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "dotenv_file" => Some(SurfaceKind::DotenvFile),
            "direnv_file" => Some(SurfaceKind::DirenvFile),
            "ini_file" => Some(SurfaceKind::IniFile),
            "env_file_direct" => Some(SurfaceKind::EnvFileDirect),
            "lines_file" => Some(SurfaceKind::LinesFile),
            "regular_file" => Some(SurfaceKind::RegularFile),
            "unix_socket" => Some(SurfaceKind::UnixSocket),
            _ => None,
        }
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
    pub path: PathBuf,
    pub input: SurfaceInput,
    pub enforcement: Enforcement,
    #[serde(default)]
    pub position: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSnapshot {
    pub projects: Vec<Project>,
    pub environments: Vec<Environment>,
    pub resources: Vec<Resource>,
    pub bindings: Vec<Binding>,
    pub surfaces: Vec<Surface>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedExport {
    pub key: String,
    /// The key used inside the resource value before a scalar binding renames it.
    pub source_key: String,
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
