//! accessfs-agent: the policy engine and Unix-socket bridge to the menubar app.
//!
//! Implements [`accessfs_core::authz::Authorizer`] via [`agent::SocketAgent`], which the FS
//! daemon plugs into `mount()`. Compiles managed catalog policy into rules, holds the grant cache,
//! and talks to
//! the Swift menubar app over a Unix socket for interactive prompts.

pub mod agent;
mod grant_cache;
mod managed_rules;
mod policy_mode;
pub mod protocol;
mod ssh_agent;
pub mod socket;

pub use agent::SocketAgent;
pub use grant_cache::{ActiveGrant, GrantMetadata};
pub use managed_rules::{ManagedObject, ManagedPolicyItem};
pub use ssh_agent::{
    discover_identities, DiscoveredSshIdentity, ManagedKeyReader, SshAgentRuntime,
};
