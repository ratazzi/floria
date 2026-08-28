use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use floria_catalog::{
    Binding, CatalogError, CatalogSnapshot, Environment, Project, ResolvedEnvironment, Resource,
    ItemMetadata, ProjectCheckout, ReplicatedProject, ResourceCodec, ResourceUsage, Surface,
};
use floria_core::authz::{Enforcement, PolicyEvaluation, PolicyMode, PolicyModeStatus};
use floria_discover::DiscoveryPlan;
pub use floria_replication::sync_control::{
    SyncDeliveryDisposition, SyncDeliveryOutcome, SyncDomainStatus, SyncInboundBatch,
    SyncInboundManifest, SyncInboundObject, SyncInboundReport, SyncInboundRevision,
    SyncObjectAsset, SyncOutboundBatch, SyncOutboundCommit, SyncOutboundRevision,
    SyncProjectionDisposition, SyncSettlementReport,
};
pub use floria_replication::record_conflict::{
    SyncConflictCandidate, SyncConflictEntityKind, SyncConflictReview,
};
pub use floria_replication::sync_bootstrap::{
    SyncBootstrapDocument, SyncBootstrapEnvelope, SyncEnrollmentPreparation,
    SyncEnrollmentReview, SyncVaultActivation, SyncVaultBootstrap, SyncVaultDevice,
};
use floria_store::StoreError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_MSG: usize = 8 << 20;
pub(crate) const MAX_RECORD_SYNC_BATCH_BYTES: usize = 6 << 20;
pub const CONTROL_PROTOCOL_VERSION: u32 = 22;

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
    Health,
    PolicyModeGet,
    PolicyModeSet { mode: PolicyMode, duration_secs: Option<u64> },
    GrantList,
    GrantRevoke { id: String },
    GrantClear,
    AccessHistory { limit: usize },
    BackupCreate { destination: PathBuf },
    BackupVerify { backup: PathBuf },
    RecoveryKeyExport { destination: PathBuf, passphrase: SecretValue },
    DiagnosticsExport { destination: PathBuf, include_paths: bool },
    ReplicationStatus,
    ReplicationCreate { directory: PathBuf },
    ReplicationOpen { directory: PathBuf },
    ReplicationSync,
    ReplicationResolveWithCurrent,
    ReplicationRevokeDevice { device_id: String },
    ReplicationRequestReenrollment,
    ReplicationDisable,
    ReplicationEnrollment,
    ReplicationEnroll { enrollment: ReplicationEnrollment },
    /// Approve a pending enrollment request that arrived through the sync directory. The GUI
    /// must have shown the request's key fingerprint for out-of-band comparison first.
    ReplicationApprove { device_id: String },
    RecordSyncStatus,
    RecordSyncReviewConflicts,
    RecordSyncResolveConflict {
        entity_id: String,
        selected_revision_id: String,
        resolved_at: String,
    },
    RecordSyncVaultBootstrap,
    RecordSyncValidateVaultBootstrap {
        expected_vault_id: String,
        bootstrap: SyncVaultBootstrap,
    },
    RecordSyncPrepareVaultEnrollment {
        bootstrap: SyncVaultBootstrap,
        device_name: Option<String>,
        requested_at: String,
    },
    RecordSyncPrepareVaultReenrollment {
        bootstrap: SyncVaultBootstrap,
        expected_fingerprint: String,
        device_name: Option<String>,
        requested_at: String,
    },
    RecordSyncReviewVaultEnrollments {
        bootstrap: SyncVaultBootstrap,
    },
    RecordSyncReviewVaultDevices {
        bootstrap: SyncVaultBootstrap,
    },
    RecordSyncApproveVaultEnrollment {
        bootstrap: SyncVaultBootstrap,
        device_id: String,
        expected_fingerprint: String,
    },
    RecordSyncRevokeVaultDevice {
        bootstrap: SyncVaultBootstrap,
        device_id: String,
        expected_fingerprint: String,
    },
    RecordSyncActivateVault {
        bootstrap: SyncVaultBootstrap,
    },
    RecordSyncNextOutbound { limit: usize },
    RecordSyncSettleOutbound { outcomes: Vec<SyncDeliveryOutcome> },
    RecordSyncApplyInbound { batch: SyncInboundBatch, observed_at: String },
    Snapshot,
    Discover { paths: Vec<PathBuf> },
    DiscoverStart { paths: Vec<PathBuf> },
    DiscoverStatus { id: String },
    DiscoverCancel { id: String },
    DiscoverApply {
        paths: Vec<PathBuf>,
        imports: Option<Vec<DiscoveryImport>>,
        separate_entries: Vec<DiscoveryEntryRef>,
        /// Review overrides: import these plain-classified entries as secrets.
        #[serde(default)]
        promote_entries: Vec<DiscoveryEntryRef>,
        /// Review overrides: keep these secret-classified entries as plain env values.
        #[serde(default)]
        demote_entries: Vec<DiscoveryEntryRef>,
    },
    DiscoverReferenceResolve {
        surface_id: String,
        key: String,
        source: DiscoveryReferenceSource,
    },
    ProjectCheckoutInventory,
    ProjectCheckoutInventoryIfChanged { revision: u64 },
    ProjectCheckoutDiscover { project_id: String },
    ProjectCheckoutUpsert { checkout: ProjectCheckout },
    ProjectCheckoutRemove { id: String },
    ManagedLinkRepair { path: PathBuf },
    SshAgentDiscover { endpoint: PathBuf },
    SshIdentityImport {
        resource_id: String,
        name: String,
        path: PathBuf,
        passphrase: Option<SecretValue>,
        manage_source: bool,
        enforcement: Enforcement,
        metadata: ItemMetadata,
    },
    SshIdentityRemove { resource_id: String },
    SshConfigStatus,
    SshConfigInstall,
    SshConfigRemove,
    ProtectedFiles,
    ProtectedFileLookup { id: Option<String>, path: Option<PathBuf> },
    FileProtect { path: PathBuf },
    ProtectedFileHistory { id: String },
    ProtectedFileRollback { id: String, version: u32 },
    ProtectedFileContentsUpdate { id: String, path: PathBuf },
    ProtectedFileMetadataUpdate {
        id: String,
        enforcement: Enforcement,
        environment_ids: Vec<String>,
        metadata: ItemMetadata,
    },
    ManagedFileConfigure {
        id: String,
        project_id: String,
        environment_id: Option<String>,
    },
    ManagedFileRestore { id: String },
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
    ProjectAttach { project_id: String, path: PathBuf },
    ProjectDefaultEnvironmentSet { project_id: String, environment_id: Option<String> },
    ProjectRemove { id: String },
    EnvironmentUpsert { environment: Environment },
    EnvironmentRemove { id: String },
    ResourceUpsert {
        resource: Resource,
        #[serde(default)]
        endpoint: Option<PathBuf>,
    },
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
    Pong {
        protocol_version: u32,
        daemon_version: String,
        schema_version: i64,
        minimum_schema_version: i64,
        store_format_version: u32,
        minimum_store_format_version: u32,
    },
    Health(HealthReport),
    PolicyMode(PolicyModeStatus),
    ActiveGrants(Vec<ActiveGrant>),
    AccessHistory(Vec<AccessHistoryEvent>),
    Backup(BackupReport),
    RecoveryKey(RecoveryKeyReport),
    Diagnostics(DiagnosticsReport),
    ReplicationStatus(ReplicationStatus),
    ReplicationEnrollment(ReplicationEnrollment),
    RecordSyncStatus(SyncDomainStatus),
    RecordSyncConflicts(Vec<SyncConflictReview>),
    RecordSyncVaultBootstrap(SyncVaultBootstrap),
    RecordSyncEnrollmentPreparation(SyncEnrollmentPreparation),
    RecordSyncEnrollmentReviews(Vec<SyncEnrollmentReview>),
    RecordSyncVaultDevices(Vec<SyncVaultDevice>),
    RecordSyncVaultActivation(SyncVaultActivation),
    RecordSyncOutbound(SyncOutboundBatch),
    RecordSyncSettlement(SyncSettlementReport),
    RecordSyncInbound(SyncInboundReport),
    Snapshot(WorkspaceSnapshot),
    Discovery(DiscoveryReviewPlan),
    DiscoveryJob(DiscoveryJobStatus),
    DiscoveryApplied(DiscoveryApplyResult),
    DiscoveryReferenceResolved(DiscoveryReferenceResolution),
    ProjectCheckoutInventory(ProjectCheckoutInventory),
    ProjectCheckoutDiscovery(ProjectCheckoutDiscovery),
    SshAgentIdentities(Vec<SshIdentity>),
    SshIdentityCreated { resource: Resource },
    SshConfig(SshConfigStatus),
    ProtectedFiles(Vec<ProtectedFile>),
    ProtectedFile(ProtectedFile),
    FileProtected { file: ProtectedFile, created: bool },
    ProtectedFileHistory { id: String, versions: Vec<ProtectedFileVersion> },
    ProtectedFileRolledBack { file: ProtectedFile },
    ProtectedFileUpdated { file: ProtectedFile },
    ManagedFileConfigured { surface: Surface },
    FileRestored { path: PathBuf, storage_deleted: bool },
    ResolvedEnvironment(ResolvedEnvironment),
    ResourceUsage(ResourceUsage),
    SharedSecretCreated { resource: Resource, version: u32 },
    SharedSecretRotated { resource_id: String, version: u32 },
    EnvFileCreated { resource: Resource, version: u32 },
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationMode {
    Off,
    WaitingForEnrollment,
    Active,
    Removed,
    Fenced,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationStatus {
    pub mode: ReplicationMode,
    pub directory: Option<PathBuf>,
    pub device_id: Option<String>,
    pub vault_id: Option<String>,
    pub key_generation: Option<u32>,
    pub published: usize,
    pub imported: usize,
    pub pending: usize,
    pub conflicts: usize,
    pub damaged: usize,
    pub damaged_files: Vec<PathBuf>,
    pub devices: Vec<ReplicationDevice>,
    pub message: Option<String>,
    /// This Mac's signing-key fingerprint, displayed while waiting for approval so the user can
    /// compare it on the genesis Mac (number matching).
    #[serde(default)]
    pub device_fingerprint: Option<String>,
    /// Enrollment requests found in the sync directory that await genesis approval.
    #[serde(default)]
    pub pending_enrollments: Vec<ReplicationPendingEnrollment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationPendingEnrollment {
    pub device_id: String,
    pub device_name: Option<String>,
    /// Short signing-key fingerprint the approver must compare with the requesting Mac's screen.
    pub fingerprint: String,
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationDevice {
    pub device_id: String,
    pub device_name: Option<String>,
    pub enrolled_generation: u32,
    pub revoked_generation: Option<u32>,
    pub is_genesis: bool,
    pub is_current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationEnrollment {
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_recipient: String,
    pub device_name: Option<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Stable machine-readable identifier used to keep UI presentation independent of wording.
    pub id: String,
    pub status: HealthStatus,
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub checks: Vec<HealthCheck>,
}

impl HealthReport {
    pub fn new(checks: Vec<HealthCheck>) -> Self {
        let status = checks
            .iter()
            .map(|check| check.status)
            .max()
            .unwrap_or(HealthStatus::Healthy);
        HealthReport { status, checks }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupReport {
    pub path: PathBuf,
    pub catalog_schema: i64,
    pub projects: usize,
    pub resources: usize,
    pub secrets: usize,
    pub versions: usize,
    pub plaintext_bytes: u64,
    pub files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryKeyReport {
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub path: PathBuf,
    pub paths_included: bool,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    #[serde(flatten)]
    pub catalog: CatalogSnapshot,
    #[serde(default)]
    pub managed_links: Vec<ManagedLink>,
    /// Portable Projects downloaded from the Library that have no checkout on this Mac yet.
    #[serde(default)]
    pub unplaced_projects: Vec<ReplicatedProject>,
}

impl Deref for WorkspaceSnapshot {
    type Target = CatalogSnapshot;

    fn deref(&self) -> &Self::Target {
        &self.catalog
    }
}

impl DerefMut for WorkspaceSnapshot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.catalog
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedLink {
    pub path: PathBuf,
    pub status: ManagedLinkStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedLinkStatus {
    Linked,
    Missing,
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCheckoutInventory {
    pub revision: u64,
    pub projects: Vec<ProjectCheckoutDiscovery>,
    #[serde(default)]
    pub unchanged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCheckoutDiscovery {
    pub project_id: String,
    pub common_dir: PathBuf,
    pub checkouts: Vec<ProjectCheckoutCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCheckoutCandidate {
    pub path: PathBuf,
    pub git_primary: bool,
    pub managed_checkout_id: Option<String>,
    #[serde(default)]
    pub link_issues: Vec<PathBuf>,
}

/// Metadata-only view of one non-expired authorization grant. Matching continues to use the
/// normalized subject/object; display fields explain the grant without exposing secret content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveGrant {
    pub id: String,
    pub subject: String,
    pub object: String,
    pub operation: String,
    pub enforcement: Enforcement,
    pub scope: String,
    pub expires_at: Option<i64>,
    pub client: String,
    pub executable: Option<String>,
    pub bundle_id: Option<String>,
    pub target: String,
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
    pub identity_source: Option<String>,
    pub requested_destination: Option<String>,
    pub verified_host_key_fingerprint: Option<String>,
    pub ssh_user: Option<String>,
    pub forwarding_hops: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryApplyResult {
    pub project_id: Option<String>,
    pub project_ids: Vec<String>,
    pub created_resources: usize,
    pub reused_resources: usize,
    pub protected_files: usize,
    pub imported_ssh_identities: usize,
    pub files: Vec<DiscoveryAppliedFile>,
}

/// Control-plane discovery result enriched with the state of paths Floria already manages.
///
/// Static discovery remains catalog-agnostic. The control server reconciles its result with the
/// catalog, encrypted store, and mount layout before crossing the IPC seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReviewPlan {
    #[serde(flatten)]
    pub discovery: DiscoveryPlan,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_items: Vec<DiscoveryManagedItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryJobStatus {
    pub id: String,
    pub state: DiscoveryJobState,
    pub progress: DiscoveryJobProgress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<DiscoveryReviewPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DiscoveryJobStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            DiscoveryJobState::Completed
                | DiscoveryJobState::Cancelled
                | DiscoveryJobState::Failed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryJobState {
    Queued,
    Running,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryJobPhase {
    Starting,
    ProjectCandidates,
    CandidateFiles,
    ParsingFiles,
    Reconciling,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryJobProgress {
    pub phase: DiscoveryJobPhase,
    pub directories_scanned: usize,
    pub candidate_files: usize,
    pub project_candidates: usize,
    pub files_parsed: usize,
}

impl Deref for DiscoveryReviewPlan {
    type Target = DiscoveryPlan;

    fn deref(&self) -> &Self::Target {
        &self.discovery
    }
}

impl DerefMut for DiscoveryReviewPlan {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.discovery
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryManagedItem {
    pub id: String,
    pub path: PathBuf,
    pub relative_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub kind: DiscoveryManagedItemKind,
    pub status: ManagedLinkStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryManagedItemKind {
    Surface,
    ProtectedFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryImport {
    pub path: PathBuf,
    pub destination: DiscoveryImportDestination,
    pub source_disposition: DiscoverySourceDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DiscoveryImportDestination {
    ProjectFile {
        project_path: PathBuf,
        /// An existing portable Project explicitly chosen during review. `None` creates a new
        /// Project unless this path is already attached locally.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project_id: Option<String>,
    },
    ProjectOutput {
        project_path: PathBuf,
        output_path: PathBuf,
    },
    Library,
    ProjectOutputs {
        outputs: Vec<DiscoveryProjectOutput>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiscoveryProjectOutput {
    pub project_path: PathBuf,
    pub output_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySourceDisposition {
    ReplaceWithSurface,
    ProtectInPlace,
    LeaveUnchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiscoveryEntryRef {
    pub path: PathBuf,
    pub address: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DiscoveryReferenceSource {
    NewSharedSecret {
        name: String,
        value: SecretValue,
        enforcement: Enforcement,
        metadata: ItemMetadata,
    },
    ExistingSharedSecret {
        resource_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReferenceResolution {
    pub surface_id: String,
    pub resource_id: String,
    pub binding_id: String,
    pub key: String,
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
    Failed,
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
    pub environment_ids: Vec<String>,
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
            CatalogError::Integrity(_) => "integrity",
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
            StoreError::Integrity(_) => "store_integrity",
            StoreError::Invalid(_) => "validation",
            StoreError::Corrupt { .. } => "store_corrupt",
        };
        ControlErrorBody { code: code.to_string(), message: error.to_string() }
    }
}

pub(crate) fn write_msg<W: Write>(writer: &mut W, value: &impl Serialize) -> io::Result<()> {
    let body = Zeroizing::new(serde_json::to_vec(value)?);
    if body.len() > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "control frame too large"));
    }
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
    use floria_catalog::{
        EntrySelection, EntrySpec, ResourceKind, ResourceSource, SshAccessSpec,
        SshIdentitySelection, SshRouteSpec, ValueShape,
    };

    #[test]
    fn ping_reports_protocol_daemon_and_catalog_versions() {
        let result = ControlResult::Pong {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            daemon_version: "0.1.0".to_string(),
            schema_version: 14,
            minimum_schema_version: 14,
            store_format_version: 3,
            minimum_store_format_version: 1,
        };
        let value = serde_json::to_value(result).unwrap();

        assert_eq!(value["type"], "pong");
        assert_eq!(value["value"]["protocol_version"], CONTROL_PROTOCOL_VERSION);
        assert_eq!(value["value"]["daemon_version"], "0.1.0");
        assert_eq!(value["value"]["schema_version"], 14);
        assert_eq!(value["value"]["minimum_schema_version"], 14);
        assert_eq!(value["value"]["store_format_version"], 3);
        assert_eq!(value["value"]["minimum_store_format_version"], 1);
    }

    #[test]
    fn health_report_uses_the_most_severe_check() {
        let result = ControlResult::Health(HealthReport::new(vec![
            HealthCheck {
                id: "catalog".to_string(),
                status: HealthStatus::Healthy,
                title: "Catalog".to_string(),
                message: "Ready".to_string(),
                guidance: None,
            },
            HealthCheck {
                id: "disk".to_string(),
                status: HealthStatus::Warning,
                title: "Storage".to_string(),
                message: "Running low".to_string(),
                guidance: Some("Free disk space".to_string()),
            },
        ]));
        let value = serde_json::to_value(result).unwrap();

        assert_eq!(value["type"], "health");
        assert_eq!(value["value"]["status"], "warning");
        assert_eq!(value["value"]["checks"][1]["id"], "disk");
        assert_eq!(value["value"]["checks"][1]["guidance"], "Free disk space");
    }

    #[test]
    fn diagnostics_export_has_a_stable_redaction_contract() {
        let request = ControlRequest {
            request_id: 9,
            command: ControlCommand::DiagnosticsExport {
                destination: PathBuf::from("/tmp/Floria Diagnostics"),
                include_paths: false,
            },
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["method"], "diagnostics_export");
        assert_eq!(value["params"]["destination"], "/tmp/Floria Diagnostics");
        assert_eq!(value["params"]["include_paths"], false);

        let result = ControlResult::Diagnostics(DiagnosticsReport {
            path: PathBuf::from("/tmp/Floria Diagnostics"),
            paths_included: false,
            files: 4,
            bytes: 1024,
        });
        let value = serde_json::to_value(result).unwrap();
        assert_eq!(value["type"], "diagnostics");
        assert_eq!(value["value"]["paths_included"], false);
        assert_eq!(value["value"]["files"], 4);
    }

    #[test]
    fn recovery_key_export_redacts_the_passphrase_from_debug_output() {
        let request = ControlRequest {
            request_id: 10,
            command: ControlCommand::RecoveryKeyExport {
                destination: PathBuf::from("/tmp/Floria Recovery Key.age"),
                passphrase: SecretValue::new("fixture recovery phrase"),
            },
        };
        let value = serde_json::to_value(&request).unwrap();
        let debug = format!("{request:?}");

        assert_eq!(value["method"], "recovery_key_export");
        assert_eq!(
            value["params"]["destination"],
            "/tmp/Floria Recovery Key.age"
        );
        assert_eq!(
            value["params"]["passphrase"],
            "fixture recovery phrase"
        );
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("fixture recovery phrase"));
    }

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
    fn backup_commands_and_report_have_stable_wire_shapes() {
        let create = serde_json::to_value(ControlRequest {
            request_id: 18,
            command: ControlCommand::BackupCreate {
                destination: PathBuf::from("/tmp/floria-backup"),
            },
        })
        .unwrap();
        assert_eq!(create["method"], "backup_create");
        assert_eq!(create["params"]["destination"], "/tmp/floria-backup");

        let verify = serde_json::to_value(ControlRequest {
            request_id: 19,
            command: ControlCommand::BackupVerify {
                backup: PathBuf::from("/tmp/floria-backup"),
            },
        })
        .unwrap();
        assert_eq!(verify["method"], "backup_verify");
        assert_eq!(verify["params"]["backup"], "/tmp/floria-backup");

        let result = serde_json::to_value(ControlResult::Backup(BackupReport {
            path: PathBuf::from("/tmp/floria-backup"),
            catalog_schema: 5,
            projects: 2,
            resources: 3,
            secrets: 4,
            versions: 5,
            plaintext_bytes: 6,
            files: 7,
        }))
        .unwrap();
        assert_eq!(result["type"], "backup");
        assert_eq!(result["value"]["path"], "/tmp/floria-backup");
        assert_eq!(result["value"]["versions"], 5);
    }

    #[test]
    fn replication_commands_and_status_have_stable_wire_shapes() {
        let create = serde_json::to_value(ControlRequest {
            request_id: 24,
            command: ControlCommand::ReplicationCreate {
                directory: PathBuf::from("/tmp/Personal.floriavault"),
            },
        })
        .unwrap();
        assert_eq!(create["method"], "replication_create");
        assert_eq!(
            create["params"]["directory"],
            "/tmp/Personal.floriavault"
        );

        let enrollment = ReplicationEnrollment {
            device_id: "fixture-device".to_string(),
            signing_public_key: "fixture-signing-key".to_string(),
            wrapping_recipient: "fixture-recipient".to_string(),
            device_name: Some("Fixture Mac".to_string()),
        };
        let enroll = serde_json::to_value(ControlRequest {
            request_id: 25,
            command: ControlCommand::ReplicationEnroll {
                enrollment: enrollment.clone(),
            },
        })
        .unwrap();
        assert_eq!(enroll["method"], "replication_enroll");
        assert_eq!(
            enroll["params"]["enrollment"]["device_id"],
            "fixture-device"
        );
        let resolve = serde_json::to_value(ControlRequest {
            request_id: 26,
            command: ControlCommand::ReplicationResolveWithCurrent,
        })
        .unwrap();
        assert_eq!(resolve["method"], "replication_resolve_with_current");
        let revoke = serde_json::to_value(ControlRequest {
            request_id: 27,
            command: ControlCommand::ReplicationRevokeDevice {
                device_id: "fixture-device".to_string(),
            },
        })
        .unwrap();
        assert_eq!(revoke["method"], "replication_revoke_device");
        assert_eq!(revoke["params"]["device_id"], "fixture-device");
        let reenroll = serde_json::to_value(ControlRequest {
            request_id: 28,
            command: ControlCommand::ReplicationRequestReenrollment,
        })
        .unwrap();
        assert_eq!(reenroll["method"], "replication_request_reenrollment");
        assert!(reenroll.get("params").is_none());

        let status = serde_json::to_value(ControlResult::ReplicationStatus(
            ReplicationStatus {
                mode: ReplicationMode::WaitingForEnrollment,
                directory: Some(PathBuf::from("/tmp/Personal.floriavault")),
                device_id: Some("fixture-device".to_string()),
                vault_id: Some("fixture-vault".to_string()),
                key_generation: Some(2),
                device_fingerprint: Some("3F09-A2C4-88D1".to_string()),
                pending_enrollments: vec![ReplicationPendingEnrollment {
                    device_id: "fixture-joining".to_string(),
                    device_name: Some("Fixture Laptop".to_string()),
                    fingerprint: "AB12-CD34-EF56".to_string(),
                    requested_at: "2026-08-06T00:00:00Z".to_string(),
                }],
                published: 3,
                imported: 4,
                pending: 1,
                conflicts: 0,
                damaged: 0,
                damaged_files: vec![PathBuf::from("objects/damaged.age")],
                devices: vec![ReplicationDevice {
                    device_id: "fixture-device".to_string(),
                    device_name: Some("Fixture Mac".to_string()),
                    enrolled_generation: 1,
                    revoked_generation: None,
                    is_genesis: true,
                    is_current: true,
                }],
                message: Some("Approval required".to_string()),
            },
        ))
        .unwrap();
        assert_eq!(status["type"], "replication_status");
        assert_eq!(status["value"]["mode"], "waiting_for_enrollment");
        assert_eq!(status["value"]["key_generation"], 2);
        assert_eq!(status["value"]["pending"], 1);
        assert_eq!(status["value"]["damaged_files"][0], "objects/damaged.age");
        assert_eq!(status["value"]["devices"][0]["device_name"], "Fixture Mac");
    }

    #[test]
    fn authorization_grant_wire_shapes_are_stable_for_swift_client() {
        let list = serde_json::to_value(ControlRequest {
            request_id: 15,
            command: ControlCommand::GrantList,
        })
        .unwrap();
        assert_eq!(list["method"], "grant_list");
        assert!(list.get("params").is_none());
        let clear = serde_json::to_value(ControlRequest {
            request_id: 17,
            command: ControlCommand::GrantClear,
        })
        .unwrap();
        assert_eq!(clear["method"], "grant_clear");
        assert!(clear.get("params").is_none());

        let revoke = serde_json::to_value(ControlRequest {
            request_id: 16,
            command: ControlCommand::GrantRevoke { id: "fixture-grant".to_string() },
        })
        .unwrap();
        assert_eq!(revoke["method"], "grant_revoke");
        assert_eq!(revoke["params"]["id"], "fixture-grant");

        let result = serde_json::to_value(ControlResult::ActiveGrants(vec![ActiveGrant {
            id: "fixture-grant".to_string(),
            subject: "exe:/usr/bin/cat".to_string(),
            object: "secrets/fixture".to_string(),
            operation: "read".to_string(),
            enforcement: Enforcement::Prompt,
            scope: "today".to_string(),
            expires_at: Some(1_800_000_600),
            client: "cat".to_string(),
            executable: Some("/usr/bin/cat".to_string()),
            bundle_id: None,
            target: "~/.pgpass".to_string(),
        }]))
        .unwrap();
        assert_eq!(result["type"], "active_grants");
        assert_eq!(result["value"][0]["client"], "cat");
        assert_eq!(result["value"][0]["enforcement"], "prompt");
        assert_eq!(result["value"][0]["scope"], "today");
    }

    #[test]
    fn discover_carries_only_the_review_path() {
        let request = ControlRequest {
            request_id: 12,
            command: ControlCommand::Discover {
                paths: vec![PathBuf::from("/fixture/project")],
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "discover");
        assert_eq!(
            value["params"]["paths"],
            serde_json::json!(["/fixture/project"])
        );
        assert_eq!(value["params"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn asynchronous_discovery_commands_have_stable_wire_shapes() {
        let start = serde_json::to_value(ControlRequest {
            request_id: 13,
            command: ControlCommand::DiscoverStart {
                paths: vec![PathBuf::from("/fixture/workspace")],
            },
        })
        .unwrap();
        assert_eq!(start["method"], "discover_start");
        assert_eq!(
            start["params"]["paths"],
            serde_json::json!(["/fixture/workspace"])
        );

        let status = serde_json::to_value(ControlRequest {
            request_id: 14,
            command: ControlCommand::DiscoverStatus { id: "discover-1".to_string() },
        })
        .unwrap();
        assert_eq!(status["method"], "discover_status");
        assert_eq!(status["params"]["id"], "discover-1");

        let cancel = serde_json::to_value(ControlRequest {
            request_id: 15,
            command: ControlCommand::DiscoverCancel { id: "discover-1".to_string() },
        })
        .unwrap();
        assert_eq!(cancel["method"], "discover_cancel");
        assert_eq!(cancel["params"]["id"], "discover-1");
    }

    #[test]
    fn project_checkout_commands_have_stable_wire_shapes() {
        let inventory = serde_json::to_value(ControlRequest {
            request_id: 30,
            command: ControlCommand::ProjectCheckoutInventory,
        })
        .unwrap();
        assert_eq!(inventory["method"], "project_checkout_inventory");
        assert!(inventory.get("params").is_none());

        let unchanged = serde_json::to_value(ControlRequest {
            request_id: 35,
            command: ControlCommand::ProjectCheckoutInventoryIfChanged { revision: 4 },
        })
        .unwrap();
        assert_eq!(
            unchanged["method"],
            "project_checkout_inventory_if_changed"
        );
        assert_eq!(unchanged["params"]["revision"], 4);

        let discover = serde_json::to_value(ControlRequest {
            request_id: 31,
            command: ControlCommand::ProjectCheckoutDiscover {
                project_id: "fixture-project".to_string(),
            },
        })
        .unwrap();
        assert_eq!(discover["method"], "project_checkout_discover");
        assert_eq!(discover["params"]["project_id"], "fixture-project");

        let upsert = serde_json::to_value(ControlRequest {
            request_id: 32,
            command: ControlCommand::ProjectCheckoutUpsert {
                checkout: ProjectCheckout {
                    id: "fixture-worktree".to_string(),
                    project_id: "fixture-project".to_string(),
                    path: PathBuf::from("/workspace/fixture-worktree"),
                    environment_id: Some("fixture-development".to_string()),
                    kind: floria_catalog::ProjectCheckoutKind::Worktree,
                    git_common_dir: Some(PathBuf::from("/workspace/fixture/.git")),
                },
            },
        })
        .unwrap();
        assert_eq!(upsert["method"], "project_checkout_upsert");
        assert_eq!(
            upsert["params"]["checkout"]["environment_id"],
            "fixture-development"
        );
        assert_eq!(upsert["params"]["checkout"]["kind"], "worktree");

        let repair = serde_json::to_value(ControlRequest {
            request_id: 33,
            command: ControlCommand::ManagedLinkRepair {
                path: PathBuf::from("/workspace/fixture-worktree/.envrc"),
            },
        })
        .unwrap();
        assert_eq!(repair["method"], "managed_link_repair");
        assert_eq!(
            repair["params"]["path"],
            "/workspace/fixture-worktree/.envrc"
        );

        let remove = serde_json::to_value(ControlRequest {
            request_id: 34,
            command: ControlCommand::ProjectCheckoutRemove {
                id: "fixture-worktree".to_string(),
            },
        })
        .unwrap();
        assert_eq!(remove["method"], "project_checkout_remove");
        assert_eq!(remove["params"]["id"], "fixture-worktree");

        let attach = serde_json::to_value(ControlRequest {
            request_id: 35,
            command: ControlCommand::ProjectAttach {
                project_id: "synced-project".to_string(),
                path: PathBuf::from("/workspace/synced-project"),
            },
        })
        .unwrap();
        assert_eq!(attach["method"], "project_attach");
        assert_eq!(attach["params"]["project_id"], "synced-project");
        assert_eq!(attach["params"]["path"], "/workspace/synced-project");

        let result = serde_json::to_value(ControlResult::ProjectCheckoutDiscovery(
            ProjectCheckoutDiscovery {
                project_id: "fixture-project".to_string(),
                common_dir: PathBuf::from("/workspace/fixture/.git"),
                checkouts: vec![ProjectCheckoutCandidate {
                    path: PathBuf::from("/workspace/fixture-worktree"),
                    git_primary: false,
                    managed_checkout_id: None,
                    link_issues: Vec::new(),
                }],
            },
        ))
        .unwrap();
        assert_eq!(result["type"], "project_checkout_discovery");
        assert_eq!(
            result["value"]["checkouts"][0]["path"],
            "/workspace/fixture-worktree"
        );
        assert_eq!(
            result["value"]["checkouts"][0]["link_issues"],
            serde_json::json!([])
        );

        let inventory = serde_json::to_value(ControlResult::ProjectCheckoutInventory(
            ProjectCheckoutInventory {
                revision: 4,
                projects: vec![],
                unchanged: false,
            },
        ))
        .unwrap();
        assert_eq!(inventory["type"], "project_checkout_inventory");
        assert_eq!(inventory["value"]["revision"], 4);
        assert_eq!(inventory["value"]["unchanged"], false);
    }

    #[test]
    fn discover_apply_is_an_explicit_separate_mutation() {
        let request = ControlRequest {
            request_id: 13,
            command: ControlCommand::DiscoverApply {
                paths: vec![PathBuf::from("/fixture/project")],
                imports: Some(vec![DiscoveryImport {
                    path: PathBuf::from("/fixture/project/.env"),
                    destination: DiscoveryImportDestination::ProjectOutput {
                        project_path: PathBuf::from("/fixture/project"),
                        output_path: PathBuf::from("/fixture/project/.env"),
                    },
                    source_disposition: DiscoverySourceDisposition::ReplaceWithSurface,
                }]),
                separate_entries: vec![DiscoveryEntryRef {
                    path: PathBuf::from("/fixture/project/.env"),
                    address: "keys/API_TOKEN".to_string(),
                }],
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "discover_apply");
        assert_eq!(
            value["params"]["paths"],
            serde_json::json!(["/fixture/project"])
        );
        assert_eq!(
            value["params"]["imports"],
            serde_json::json!([{
                "path": "/fixture/project/.env",
                "destination": {
                    "type": "project_output",
                    "project_path": "/fixture/project",
                    "output_path": "/fixture/project/.env"
                },
                "source_disposition": "replace_with_surface"
            }])
        );
        assert_eq!(
            value["params"]["separate_entries"],
            serde_json::json!([{
                "path": "/fixture/project/.env",
                "address": "keys/API_TOKEN"
            }])
        );

        let existing_project = serde_json::to_value(
            DiscoveryImportDestination::ProjectFile {
                project_path: PathBuf::from("/fixture/project"),
                project_id: Some("synced-project".to_string()),
            },
        )
        .unwrap();
        assert_eq!(
            existing_project,
            serde_json::json!({
                "type": "project_file",
                "project_path": "/fixture/project",
                "project_id": "synced-project"
            })
        );
    }

    #[test]
    fn discover_reference_resolve_has_one_atomic_wire_command() {
        let request = ControlRequest {
            request_id: 10,
            command: ControlCommand::DiscoverReferenceResolve {
                surface_id: "fixture-surface".to_string(),
                key: "API_TOKEN".to_string(),
                source: DiscoveryReferenceSource::NewSharedSecret {
                    name: "API token".to_string(),
                    value: SecretValue::new("fixture-reference-value"),
                    enforcement: Enforcement::Prompt,
                    metadata: ItemMetadata::default(),
                },
            },
        };

        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["method"], "discover_reference_resolve");
        assert_eq!(value["params"]["surface_id"], "fixture-surface");
        assert_eq!(value["params"]["key"], "API_TOKEN");
        assert_eq!(value["params"]["source"]["type"], "new_shared_secret");
        assert_eq!(value["params"]["source"]["enforcement"], "prompt");
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
    fn socket_resource_upsert_keeps_endpoint_out_of_syncable_source_data() {
        let request = ControlRequest {
            request_id: 18,
            command: ControlCommand::ResourceUpsert {
                resource: Resource {
                    id: "fixture-agent".to_string(),
                    name: "Fixture Agent".to_string(),
                    kind: ResourceKind::SshAgent,
                    shape: ValueShape::Socket,
                    codec: ResourceCodec::Opaque,
                    default_env_key: None,
                    entries: vec![EntrySpec {
                        address:
                            "ssh/sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                        label: "Fixture key".to_string(),
                        key: None,
                        sensitive: false,
                    }],
                    source: ResourceSource::Socket,
                    enforcement: Enforcement::Prompt,
                    metadata: Default::default(),
                    origin: Default::default(),
                },
                endpoint: Some(PathBuf::from("/private/tmp/fixture-agent.sock")),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "resource_upsert");
        assert_eq!(
            value["params"]["endpoint"],
            "/private/tmp/fixture-agent.sock"
        );
        assert_eq!(
            value["params"]["resource"]["source"],
            serde_json::json!({ "type": "socket" })
        );
    }

    #[test]
    fn library_ssh_access_wire_shape_keeps_project_relationship_optional() {
        let source = ResourceSource::SshAccess(Box::new(SshAccessSpec {
            identities: vec![SshIdentitySelection {
                resource_id: "fixture-identity".to_string(),
                selection: EntrySelection::All,
            }],
            route: SshRouteSpec {
                host_patterns: vec!["github.com".to_string()],
                hostname: None,
                user: Some("git".to_string()),
                port: None,
                forward_agent: false,
            },
            project_ids: Vec::new(),
        }));

        let value = serde_json::to_value(&source).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "type": "ssh_access",
                "identities": [{
                    "resource_id": "fixture-identity",
                    "selection": { "type": "all" }
                }],
                "route": {
                    "host_patterns": ["github.com"],
                    "hostname": null,
                    "user": "git",
                    "port": null,
                    "forward_agent": false
                }
            })
        );
        assert_eq!(serde_json::from_value::<ResourceSource>(value).unwrap(), source);
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
                manage_source: true,
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            },
        };
        assert!(format!("{request:?}").contains("SecretValue([REDACTED])"));
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "ssh_identity_import");
        assert_eq!(value["params"]["path"], "/private/tmp/fixture-id_ed25519");
        assert_eq!(value["params"]["passphrase"], "fixture passphrase");
        assert_eq!(value["params"]["manage_source"], true);
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
    fn protected_file_lookup_has_one_explicit_selector() {
        let request = ControlRequest {
            request_id: 28,
            command: ControlCommand::ProtectedFileLookup {
                id: None,
                path: Some(PathBuf::from("/fixture/.env")),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "protected_file_lookup");
        assert_eq!(value["params"]["id"], serde_json::Value::Null);
        assert_eq!(value["params"]["path"], "/fixture/.env");
    }

    #[test]
    fn protected_file_update_carries_environment_scope() {
        let request = ControlRequest {
            request_id: 10,
            command: ControlCommand::ProtectedFileMetadataUpdate {
                id: "fixture-secret".to_string(),
                enforcement: Enforcement::Prompt,
                environment_ids: vec![
                    "fixture-development".to_string(),
                    "fixture-staging".to_string(),
                ],
                metadata: ItemMetadata::default(),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "protected_file_metadata_update");
        assert_eq!(
            value["params"]["environment_ids"],
            serde_json::json!(["fixture-development", "fixture-staging"])
        );
    }

    #[test]
    fn protected_file_contents_update_carries_only_the_local_input_path() {
        let request = ControlRequest {
            request_id: 11,
            command: ControlCommand::ProtectedFileContentsUpdate {
                id: "fixture-secret".to_string(),
                path: PathBuf::from("/fixture/replacement.p12"),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "protected_file_contents_update");
        assert_eq!(value["params"]["id"], "fixture-secret");
        assert_eq!(value["params"]["path"], "/fixture/replacement.p12");
        assert_eq!(value["params"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn managed_file_configuration_is_an_explicit_project_transition() {
        let request = ControlRequest {
            request_id: 10,
            command: ControlCommand::ManagedFileConfigure {
                id: "fixture-secret".to_string(),
                project_id: "fixture-project".to_string(),
                environment_id: Some("fixture-development".to_string()),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "managed_file_configure");
        assert_eq!(value["params"]["id"], "fixture-secret");
        assert_eq!(value["params"]["project_id"], "fixture-project");
        assert_eq!(value["params"]["environment_id"], "fixture-development");
    }

    #[test]
    fn configured_managed_file_restore_names_the_surface() {
        let request = ControlRequest {
            request_id: 11,
            command: ControlCommand::ManagedFileRestore {
                id: "fixture-surface".to_string(),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "managed_file_restore");
        assert_eq!(value["params"]["id"], "fixture-surface");
    }

    #[test]
    fn secret_value_debug_is_redacted_and_wire_shape_is_scalar() {
        let value = SecretValue::new("fixture-secret-value");
        assert_eq!(format!("{value:?}"), "SecretValue([REDACTED])");
        let wire = serde_json::to_string(&value).unwrap();
        assert_eq!(wire, "\"fixture-secret-value\"");
        assert_eq!(serde_json::from_str::<SecretValue>(&wire).unwrap(), value);
    }

    #[test]
    fn coordinated_record_sync_wire_is_opaque_and_transport_neutral() {
        let resolution_request = serde_json::to_value(ControlRequest {
            request_id: 40,
            command: ControlCommand::RecordSyncResolveConflict {
                entity_id: "11111111-1111-4111-8111-111111111111".to_string(),
                selected_revision_id: "22222222-2222-4222-8222-222222222222".to_string(),
                resolved_at: "2026-08-09T12:00:00Z".to_string(),
            },
        })
        .unwrap();
        assert_eq!(
            resolution_request["method"],
            "record_sync_resolve_conflict"
        );
        assert_eq!(
            resolution_request["params"]["selected_revision_id"],
            "22222222-2222-4222-8222-222222222222"
        );

        let bootstrap_request = serde_json::to_value(ControlRequest {
            request_id: 41,
            command: ControlCommand::RecordSyncVaultBootstrap,
        })
        .unwrap();
        assert_eq!(bootstrap_request["method"], "record_sync_vault_bootstrap");
        assert!(bootstrap_request.get("params").is_none());

        let bootstrap: SyncVaultBootstrap = serde_json::from_value(serde_json::json!({
            "vault_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "vault_document_base64": "dmF1bHQ=",
            "device_identities": [],
            "enrollment_requests": [],
            "key_generations": [],
            "generation_envelopes": []
        }))
        .unwrap();
        let validation_request = serde_json::to_value(ControlRequest {
            request_id: 45,
            command: ControlCommand::RecordSyncValidateVaultBootstrap {
                expected_vault_id: bootstrap.vault_id().to_string(),
                bootstrap: bootstrap.clone(),
            },
        })
        .unwrap();
        assert_eq!(
            validation_request["method"],
            "record_sync_validate_vault_bootstrap"
        );
        assert_eq!(
            validation_request["params"]["expected_vault_id"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(
            validation_request["params"]["bootstrap"]["vault_id"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );

        let preparation_request = serde_json::to_value(ControlRequest {
            request_id: 46,
            command: ControlCommand::RecordSyncPrepareVaultEnrollment {
                bootstrap: bootstrap.clone(),
                device_name: Some("Studio".to_string()),
                requested_at: "2026-08-08T12:00:00Z".to_string(),
            },
        })
        .unwrap();
        assert_eq!(
            preparation_request["method"],
            "record_sync_prepare_vault_enrollment"
        );
        assert_eq!(preparation_request["params"]["device_name"], "Studio");

        let reenrollment_request = serde_json::to_value(ControlRequest {
            request_id: 52,
            command: ControlCommand::RecordSyncPrepareVaultReenrollment {
                bootstrap: bootstrap.clone(),
                expected_fingerprint: "AB12-CD34-EF56".to_string(),
                device_name: Some("Studio".to_string()),
                requested_at: "2026-08-09T12:00:00Z".to_string(),
            },
        })
        .unwrap();
        assert_eq!(
            reenrollment_request["method"],
            "record_sync_prepare_vault_reenrollment"
        );
        assert_eq!(
            reenrollment_request["params"]["expected_fingerprint"],
            "AB12-CD34-EF56"
        );

        let review_request = serde_json::to_value(ControlRequest {
            request_id: 47,
            command: ControlCommand::RecordSyncReviewVaultEnrollments {
                bootstrap: bootstrap.clone(),
            },
        })
        .unwrap();
        assert_eq!(
            review_request["method"],
            "record_sync_review_vault_enrollments"
        );

        let device_review_request = serde_json::to_value(ControlRequest {
            request_id: 50,
            command: ControlCommand::RecordSyncReviewVaultDevices {
                bootstrap: bootstrap.clone(),
            },
        })
        .unwrap();
        assert_eq!(
            device_review_request["method"],
            "record_sync_review_vault_devices"
        );

        let approval_request = serde_json::to_value(ControlRequest {
            request_id: 48,
            command: ControlCommand::RecordSyncApproveVaultEnrollment {
                bootstrap: bootstrap.clone(),
                device_id: "fixture-device".to_string(),
                expected_fingerprint: "sha256:fixture".to_string(),
            },
        })
        .unwrap();
        assert_eq!(
            approval_request["method"],
            "record_sync_approve_vault_enrollment"
        );
        assert_eq!(
            approval_request["params"]["expected_fingerprint"],
            "sha256:fixture"
        );

        let revocation_request = serde_json::to_value(ControlRequest {
            request_id: 51,
            command: ControlCommand::RecordSyncRevokeVaultDevice {
                bootstrap: bootstrap.clone(),
                device_id: "fixture-device".to_string(),
                expected_fingerprint: "sha256:fixture".to_string(),
            },
        })
        .unwrap();
        assert_eq!(
            revocation_request["method"],
            "record_sync_revoke_vault_device"
        );
        assert_eq!(
            revocation_request["params"]["expected_fingerprint"],
            "sha256:fixture"
        );

        let activation_request = serde_json::to_value(ControlRequest {
            request_id: 49,
            command: ControlCommand::RecordSyncActivateVault { bootstrap },
        })
        .unwrap();
        assert_eq!(activation_request["method"], "record_sync_activate_vault");
        assert_eq!(
            activation_request["params"]["bootstrap"]["vault_id"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );

        let preparation: SyncEnrollmentPreparation =
            serde_json::from_value(serde_json::json!({
                "status": "request",
                "device_id": "fixture-device",
                "device_name": "Studio",
                "requested_at": "2026-08-08T12:00:00Z",
                "fingerprint": "sha256:fixture",
                "document_base64": "cmVxdWVzdA=="
            }))
            .unwrap();
        let preparation_result = serde_json::to_value(
            ControlResult::RecordSyncEnrollmentPreparation(preparation),
        )
        .unwrap();
        assert_eq!(
            preparation_result["value"]["status"],
            "request"
        );
        assert_eq!(
            preparation_result["value"]["fingerprint"],
            "sha256:fixture"
        );

        let request = ControlRequest {
            request_id: 42,
            command: ControlCommand::RecordSyncApplyInbound {
                batch: SyncInboundBatch::new(
                    vec![SyncInboundManifest::new("commit-1", "bWFuaWZlc3Q=")],
                    vec![SyncInboundRevision::new(
                        "entity-1",
                        "revision-1",
                        "cmV2aXNpb24=",
                    )],
                    vec![SyncInboundObject::new(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        9,
                        PathBuf::from("/tmp/floria-sync-object"),
                    )],
                ),
                observed_at: "2026-08-07T12:00:00Z".to_string(),
            },
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["method"], "record_sync_apply_inbound");
        assert_eq!(value["params"]["batch"]["manifests"][0]["commit_id"], "commit-1");
        assert_eq!(
            value["params"]["batch"]["objects"][0]["file"],
            "/tmp/floria-sync-object"
        );
        assert_eq!(value["params"]["observed_at"], "2026-08-07T12:00:00Z");
        assert!(!value.to_string().contains("plaintext"));

        let result = serde_json::to_value(ControlResult::RecordSyncOutbound(
            SyncOutboundBatch::default(),
        ))
        .unwrap();
        assert_eq!(result["type"], "record_sync_outbound");
        assert_eq!(result["value"]["commits"], serde_json::json!([]));

        let activation = serde_json::to_value(ControlResult::RecordSyncVaultActivation(
            SyncVaultActivation::Ready {
                vault_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
                key_generation: 2,
                restart_required: true,
            },
        ))
        .unwrap();
        assert_eq!(activation["type"], "record_sync_vault_activation");
        assert_eq!(activation["value"]["status"], "ready");
        assert_eq!(activation["value"]["restart_required"], true);
    }

    #[test]
    fn writer_rejects_frames_that_the_reader_would_refuse() {
        let mut wire = Vec::new();
        let error = write_msg(&mut wire, &"x".repeat(MAX_MSG)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(wire.is_empty());
    }

}
