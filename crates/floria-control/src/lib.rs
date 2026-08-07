//! Separate local control plane for catalog CRUD and metadata-only environment resolution.
//!
//! This socket is intentionally independent from the blocking authorization/event connection
//! in `floria-agent`, so GUI management calls cannot delay a FUSE authorization prompt.

mod client;
mod protocol;
mod server;
mod ssh_config;

pub use client::ControlClient;
pub use protocol::{
    AccessHistoryEvent, AccessHistoryIdentity, AccessHistoryProcess, AccessHistorySsh, ActiveGrant,
    BackupReport, ControlCommand, ControlErrorBody, ControlOutcome, ControlRequest, ControlResponse,
    ControlResult, DiagnosticsReport, DiscoveryJobPhase, DiscoveryJobProgress, DiscoveryJobState,
    DiscoveryJobStatus, HealthCheck, HealthReport, HealthStatus, ProjectCheckoutCandidate,
    ProjectCheckoutDiscovery, ProjectCheckoutInventory, ProtectedFile, ProtectedFileVersion,
    RecoveryKeyReport, ReplicationDevice, ReplicationEnrollment, ReplicationMode,
    ReplicationPendingEnrollment, ReplicationStatus, SecretValue,
    SyncBootstrapDocument, SyncBootstrapEnvelope,
    SyncDeliveryDisposition, SyncDeliveryOutcome, SyncDomainStatus, SyncInboundBatch,
    SyncInboundManifest, SyncInboundObject, SyncInboundReport, SyncInboundRevision,
    SyncObjectAsset, SyncOutboundBatch, SyncOutboundCommit, SyncOutboundRevision,
    SyncProjectionDisposition, SyncSettlementReport, SyncVaultBootstrap,
    SshConfigState, SshConfigStatus, SshIdentity,
    CONTROL_PROTOCOL_VERSION,
};
pub use server::{
    BackupService, CatalogObserver, ControlRuntimeServices, ControlServer,
    RecoveryKeyExporter, RuntimeDiagnosticsExporter, RuntimeHealthReporter,
    RuntimePolicyController, RuntimeRecordSyncService, RuntimeReplicationService, SshConfigManager,
    SshIdentityDiscovery,
};
pub use ssh_config::ManagedSshConfig;
