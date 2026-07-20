use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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
    Socket,
}

impl ValueShape {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ValueShape::Scalar => "scalar",
            ValueShape::KeyValueSet => "key_value_set",
            ValueShape::Bytes => "bytes",
            ValueShape::Socket => "socket",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "scalar" => Some(ValueShape::Scalar),
            "key_value_set" => Some(ValueShape::KeyValueSet),
            "bytes" => Some(ValueShape::Bytes),
            "socket" => Some(ValueShape::Socket),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSpec {
    pub key: String,
    #[serde(default)]
    pub sensitive: bool,
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
    #[serde(default)]
    pub default_env_key: Option<String>,
    #[serde(default)]
    pub exports: Vec<ExportSpec>,
    pub source: ResourceSource,
    #[serde(default)]
    pub detail: Option<String>,
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
    RegularFile,
    UnixSocket,
}

impl SurfaceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SurfaceKind::DotenvFile => "dotenv_file",
            SurfaceKind::RegularFile => "regular_file",
            SurfaceKind::UnixSocket => "unix_socket",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "dotenv_file" => Some(SurfaceKind::DotenvFile),
            "regular_file" => Some(SurfaceKind::RegularFile),
            "unix_socket" => Some(SurfaceKind::UnixSocket),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Surface {
    pub id: String,
    pub environment_id: String,
    pub name: String,
    pub kind: SurfaceKind,
    pub path: PathBuf,
    #[serde(default)]
    pub resource_id: Option<String>,
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
