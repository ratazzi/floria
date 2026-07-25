use std::io::{self, Read, Write};
use std::path::PathBuf;

use accessfs_catalog::{
    Binding, CatalogError, CatalogSnapshot, Environment, Project, ResolvedEnvironment, Resource,
    ResourceCodec, ResourceUsage, Surface,
};
use accessfs_store::StoreError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_MSG: usize = 8 << 20;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRequest {
    pub request_id: u64,
    #[serde(flatten)]
    pub command: ControlCommand,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        SecretValue(value.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum ControlCommand {
    Ping,
    Snapshot,
    ProtectedFiles,
    FileProtect { path: PathBuf },
    ResolveEnvironment { project_id: String, environment_id: String },
    ResourceUsage { resource_id: String },
    SharedSecretCreate {
        resource_id: String,
        name: String,
        default_env_key: Option<String>,
        value: SecretValue,
    },
    SharedSecretRotate { resource_id: String, value: SecretValue },
    EnvFileCreate {
        resource_id: String,
        name: String,
        codec: ResourceCodec,
        value: SecretValue,
    },
    ProjectCreate { project: Project, environment: Environment, surface: Surface },
    ProjectUpsert { project: Project },
    ProjectRemove { id: String },
    EnvironmentUpsert { environment: Environment },
    EnvironmentRemove { id: String },
    ResourceUpsert { resource: Resource },
    ResourceRemove { id: String },
    BindingUpsert { binding: Binding },
    BindingRemove { id: String },
    SurfaceUpsert { surface: Surface },
    SurfaceRemove { id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlResponse {
    pub request_id: u64,
    #[serde(flatten)]
    pub outcome: ControlOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlOutcome {
    Ok { result: ControlResult },
    Error { error: ControlErrorBody },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ControlResult {
    Pong { schema_version: i64 },
    Snapshot(CatalogSnapshot),
    ProtectedFiles(Vec<ProtectedFile>),
    FileProtected { file: ProtectedFile, created: bool },
    ResolvedEnvironment(ResolvedEnvironment),
    ResourceUsage(ResourceUsage),
    SharedSecretCreated { resource: Resource, version: u32 },
    SharedSecretRotated { resource_id: String, version: u32 },
    EnvFileCreated { resource: Resource, version: u32 },
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedFile {
    pub id: String,
    pub source_path: PathBuf,
    pub mode: u32,
    pub size: u64,
    pub current_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlErrorBody {
    pub code: String,
    pub message: String,
}

impl From<&CatalogError> for ControlErrorBody {
    fn from(error: &CatalogError) -> Self {
        let code = match error {
            CatalogError::Io { .. } => "io",
            CatalogError::Database(_) => "database",
            CatalogError::Encoding(_) => "encoding",
            CatalogError::Validation(_) => "validation",
            CatalogError::NotFound(_) => "not_found",
            CatalogError::AlreadyExists { .. } => "already_exists",
            CatalogError::Conflict { .. } => "conflict",
            CatalogError::ResourceInUse { .. } => "resource_in_use",
            CatalogError::UnsupportedSchema { .. } => "unsupported_schema",
        };
        ControlErrorBody { code: code.to_string(), message: error.to_string() }
    }
}

impl From<&StoreError> for ControlErrorBody {
    fn from(error: &StoreError) -> Self {
        let code = match error {
            StoreError::Io { .. } => "store_io",
            StoreError::NotFound(_) => "secret_not_found",
            StoreError::Key(_) => "key",
            StoreError::Crypto(_) => "crypto",
            StoreError::Invalid(_) => "validation",
            StoreError::Corrupt { .. } => "store_corrupt",
        };
        ControlErrorBody { code: code.to_string(), message: error.to_string() }
    }
}

pub(crate) fn write_msg<W: Write>(writer: &mut W, value: &impl Serialize) -> io::Result<()> {
    let body = Zeroizing::new(serde_json::to_vec(value)?);
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "control message too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

pub(crate) fn read_msg<R: Read, T: DeserializeOwned>(reader: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "control frame too large"));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_shape_is_stable_for_swift_client() {
        let request = ControlRequest {
            request_id: 7,
            command: ControlCommand::ResolveEnvironment {
                project_id: "floria".to_string(),
                environment_id: "development".to_string(),
            },
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["request_id"], 7);
        assert_eq!(value["method"], "resolve_environment");
        assert_eq!(value["params"]["project_id"], "floria");
        assert_eq!(value["params"]["environment_id"], "development");
    }

    #[test]
    fn response_error_has_machine_readable_code() {
        let error = CatalogError::Conflict {
            key: "TOKEN".to_string(),
            binding_ids: vec!["a".to_string(), "b".to_string()],
        };
        let response = ControlResponse {
            request_id: 3,
            outcome: ControlOutcome::Error { error: (&error).into() },
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], "conflict");
    }

    #[test]
    fn env_file_create_carries_the_explicit_codec() {
        let request = ControlRequest {
            request_id: 8,
            command: ControlCommand::EnvFileCreate {
                resource_id: "fixture-ini".to_string(),
                name: "Fixture INI".to_string(),
                codec: ResourceCodec::Ini,
                value: SecretValue::new("[fixture]\nREGION=fixture-region\n"),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "env_file_create");
        assert_eq!(value["params"]["codec"], "ini");
        assert_eq!(value["params"]["resource_id"], "fixture-ini");
    }

    #[test]
    fn file_protect_carries_only_the_absolute_source_path() {
        let request = ControlRequest {
            request_id: 9,
            command: ControlCommand::FileProtect {
                path: PathBuf::from("/fixture/project/.env"),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "file_protect");
        assert_eq!(value["params"]["path"], "/fixture/project/.env");
    }

    #[test]
    fn secret_value_debug_is_redacted_and_wire_shape_is_scalar() {
        let value = SecretValue::new("fixture-secret-value");
        assert_eq!(format!("{value:?}"), "SecretValue([REDACTED])");
        let wire = serde_json::to_string(&value).unwrap();
        assert_eq!(wire, "\"fixture-secret-value\"");
        assert_eq!(serde_json::from_str::<SecretValue>(&wire).unwrap(), value);
    }

}
