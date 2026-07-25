use std::io::{self, Read, Write};
use std::path::PathBuf;

use accessfs_catalog::{
    Binding, CatalogError, CatalogSnapshot, Environment, Project, ResolvedEnvironment, Resource,
    ItemMetadata, ResourceCodec, ResourceUsage, Surface,
};
use accessfs_core::authz::{Enforcement, PolicyEvaluation, PolicyMode, PolicyModeStatus};
use accessfs_discover::DiscoveryPlan;
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
    PolicyModeGet,
    PolicyModeSet { mode: PolicyMode, duration_secs: Option<u64> },
    AccessHistory { limit: usize },
    Snapshot,
    Discover { path: PathBuf },
    DiscoverApply { path: PathBuf },
    SshAgentDiscover { endpoint: PathBuf },
    SshIdentityImport {
        resource_id: String,
        name: String,
        path: PathBuf,
        passphrase: Option<SecretValue>,
        enforcement: Enforcement,
        metadata: ItemMetadata,
    },
    SshIdentityRemove { resource_id: String },
    SshConfigStatus,
    SshConfigInstall,
    SshConfigRemove,
    ProtectedFiles,
    FileProtect { path: PathBuf },
    ProtectedFileHistory { id: String },
    ProtectedFileRollback { id: String, version: u32 },
    ProtectedFileMetadataUpdate {
        id: String,
        enforcement: Enforcement,
        metadata: ItemMetadata,
    },
    FileRestore { id: String },
    ResolveEnvironment { project_id: String, environment_id: String },
    ResourceUsage { resource_id: String },
    SharedSecretCreate {
        resource_id: String,
        name: String,
        default_env_key: Option<String>,
        value: SecretValue,
        enforcement: Enforcement,
        metadata: ItemMetadata,
    },
    SharedSecretUpdate {
        resource_id: String,
        name: String,
        default_env_key: Option<String>,
        value: Option<SecretValue>,
        enforcement: Enforcement,
        metadata: ItemMetadata,
    },
    SharedSecretRemove { resource_id: String },
    SharedSecretRotate { resource_id: String, value: SecretValue },
    EnvFileCreate {
        resource_id: String,
        name: String,
        codec: ResourceCodec,
        value: SecretValue,
        enforcement: Enforcement,
        metadata: ItemMetadata,
    },
    ResourceMetadataUpdate {
        resource_id: String,
        name: String,
        enforcement: Enforcement,
        metadata: ItemMetadata,
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
    PolicyMode(PolicyModeStatus),
    AccessHistory(Vec<AccessHistoryEvent>),
    Snapshot(CatalogSnapshot),
    Discovery(DiscoveryPlan),
    DiscoveryApplied(DiscoveryApplyResult),
    SshAgentIdentities(Vec<SshIdentity>),
    SshIdentityCreated { resource: Resource },
    SshConfig(SshConfigStatus),
    ProtectedFiles(Vec<ProtectedFile>),
    FileProtected { file: ProtectedFile, created: bool },
    ProtectedFileHistory { id: String, versions: Vec<ProtectedFileVersion> },
    ProtectedFileRolledBack { file: ProtectedFile },
    FileRestored { path: PathBuf, storage_deleted: bool },
    ResolvedEnvironment(ResolvedEnvironment),
    ResourceUsage(ResourceUsage),
    SharedSecretCreated { resource: Resource, version: u32 },
    SharedSecretRotated { resource_id: String, version: u32 },
    EnvFileCreated { resource: Resource, version: u32 },
    Empty,
}

/// Metadata-only persisted access event. Its JSON shape mirrors the agent's live `access_event`
/// payload so GUI clients can merge history and live updates without a second presentation model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessHistoryEvent {
    pub ts: String,
    pub path: String,
    pub display: Option<String>,
    pub operation: String,
    pub decision: String,
    pub rule_id: Option<String>,
    pub policy: Option<PolicyEvaluation>,
    pub ssh: Option<AccessHistorySsh>,
    pub identity: AccessHistoryIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessHistoryIdentity {
    pub pid: i32,
    pub uid: u32,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub cmdline: Option<Vec<String>>,
    pub bundle_id: Option<String>,
    pub team_id: Option<String>,
    pub parent_chain: Vec<AccessHistoryProcess>,
    pub chain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessHistoryProcess {
    pub pid: i32,
    pub name: String,
    pub exe: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessHistorySsh {
    pub surface_id: String,
    pub surface_name: String,
    pub resource_id: String,
    pub key_fingerprint: String,
    pub key_label: String,
    pub requested_destination: Option<String>,
    pub verified_host_key_fingerprint: Option<String>,
    pub ssh_user: Option<String>,
    pub forwarding_hops: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryApplyResult {
    pub project_id: Option<String>,
    pub created_resources: usize,
    pub reused_resources: usize,
    pub protected_files: usize,
    pub imported_ssh_identities: usize,
    pub files: Vec<DiscoveryAppliedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryAppliedFile {
    pub path: PathBuf,
    pub outcome: DiscoveryApplyOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryApplyOutcome {
    Imported,
    Protected,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshIdentity {
    pub address: String,
    pub fingerprint: String,
    pub comment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshConfigState {
    Disabled,
    Managed,
    External,
    NeedsRepair,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConfigStatus {
    pub state: SshConfigState,
    pub writable: bool,
    pub user_config: PathBuf,
    pub generated_config: PathBuf,
    pub include_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedFile {
    pub id: String,
    pub source_path: PathBuf,
    pub mode: u32,
    pub size: u64,
    pub current_version: u32,
    pub linked: bool,
    pub enforcement: Enforcement,
    pub metadata: ItemMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedFileVersion {
    pub version: u32,
    pub size: u64,
    pub created: String,
    pub note: Option<String>,
    pub current: bool,
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
    fn policy_mode_set_wire_shape_is_stable_for_swift_client() {
        let request = ControlRequest {
            request_id: 8,
            command: ControlCommand::PolicyModeSet {
                mode: PolicyMode::AuditOnly,
                duration_secs: Some(3600),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "policy_mode_set");
        assert_eq!(value["params"]["mode"], "audit_only");
        assert_eq!(value["params"]["duration_secs"], 3600);
    }

    #[test]
    fn access_history_wire_shape_is_stable_for_swift_client() {
        let request = ControlRequest {
            request_id: 14,
            command: ControlCommand::AccessHistory { limit: 500 },
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "request_id": 14,
                "method": "access_history",
                "params": { "limit": 500 }
            })
        );
    }

    #[test]
    fn discover_carries_only_the_review_path() {
        let request = ControlRequest {
            request_id: 12,
            command: ControlCommand::Discover {
                path: PathBuf::from("/fixture/project"),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "discover");
        assert_eq!(value["params"]["path"], "/fixture/project");
        assert_eq!(value["params"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn discover_apply_is_an_explicit_separate_mutation() {
        let request = ControlRequest {
            request_id: 13,
            command: ControlCommand::DiscoverApply {
                path: PathBuf::from("/fixture/project"),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "discover_apply");
        assert_eq!(value["params"]["path"], "/fixture/project");
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
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "env_file_create");
        assert_eq!(value["params"]["codec"], "ini");
        assert_eq!(value["params"]["resource_id"], "fixture-ini");
    }

    #[test]
    fn ssh_agent_discovery_carries_only_the_public_endpoint() {
        let request = ControlRequest {
            request_id: 10,
            command: ControlCommand::SshAgentDiscover {
                endpoint: PathBuf::from("/private/tmp/fixture-agent.sock"),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "ssh_agent_discover");
        assert_eq!(value["params"]["endpoint"], "/private/tmp/fixture-agent.sock");
    }

    #[test]
    fn ssh_identity_import_carries_a_path_and_redacted_passphrase_type() {
        let request = ControlRequest {
            request_id: 11,
            command: ControlCommand::SshIdentityImport {
                resource_id: "fixture-identity".to_string(),
                name: "Fixture identity".to_string(),
                path: PathBuf::from("/private/tmp/fixture-id_ed25519"),
                passphrase: Some(SecretValue::new("fixture passphrase")),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            },
        };
        assert!(format!("{request:?}").contains("SecretValue([REDACTED])"));
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "ssh_identity_import");
        assert_eq!(value["params"]["path"], "/private/tmp/fixture-id_ed25519");
        assert_eq!(value["params"]["passphrase"], "fixture passphrase");
        assert!(value["params"].get("private_key").is_none());
    }

    #[test]
    fn ssh_config_commands_and_status_have_stable_wire_shapes() {
        for (command, method) in [
            (ControlCommand::SshConfigStatus, "ssh_config_status"),
            (ControlCommand::SshConfigInstall, "ssh_config_install"),
            (ControlCommand::SshConfigRemove, "ssh_config_remove"),
        ] {
            let value = serde_json::to_value(ControlRequest { request_id: 19, command }).unwrap();
            assert_eq!(value["method"], method);
            assert!(value.get("params").is_none());
        }

        let result = ControlResult::SshConfig(SshConfigStatus {
            state: SshConfigState::Managed,
            writable: true,
            user_config: PathBuf::from("/fixture/.ssh/config"),
            generated_config: PathBuf::from("/fixture/floria/ssh/config"),
            include_line: "Include \"/fixture/floria/ssh/config\"".to_string(),
        });
        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value["type"], "ssh_config");
        assert_eq!(value["value"]["state"], "managed");
        assert_eq!(value["value"]["writable"], true);
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
