//! Separate local control plane for catalog CRUD and metadata-only environment resolution.
//!
//! This socket is intentionally independent from the blocking authorization/event connection
//! in `accessfs-agent`, so GUI management calls cannot delay a FUSE authorization prompt.

mod client;
mod protocol;
mod server;
mod ssh_config;

pub use client::ControlClient;
pub use protocol::{
    ControlCommand, ControlErrorBody, ControlOutcome, ControlRequest, ControlResponse,
    ControlResult, ProtectedFile, ProtectedFileVersion, SecretValue, SshConfigState,
    SshConfigStatus, SshIdentity,
};
pub use server::{
    CatalogObserver, ControlRuntimeServices, ControlServer, RuntimePolicyController,
    SshConfigManager, SshIdentityDiscovery,
};
pub use ssh_config::ManagedSshConfig;
