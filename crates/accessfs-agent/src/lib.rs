//! accessfs-agent: the policy engine and Unix-socket bridge to the menubar app.
//!
//! Implements [`accessfs_core::authz::Authorizer`] via [`agent::SocketAgent`], which the FS
//! daemon plugs into `mount()`. Holds per-path enforcement and the grant cache, and talks to
//! the Swift menubar app over a Unix socket for interactive prompts.

pub mod agent;
mod policy_mode;
pub mod protocol;
mod ssh_agent;
pub mod socket;

pub use agent::SocketAgent;
pub use ssh_agent::{discover_identities, DiscoveredSshIdentity, SshAgentRuntime};
