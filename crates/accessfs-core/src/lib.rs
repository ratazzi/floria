//! accessfs-core: backend-agnostic core logic.
//!
//! Pure data and logic only: config parsing and security checks, content handlers,
//! the base FUSE-handle snapshot table, process identity structs, and audit events. No dependency
//! on fuser / macFUSE, so it can be unit-tested without an actual mount.

pub mod audit;
pub mod authz;
pub mod config;
pub mod error;
pub mod handler;
pub mod identity;
pub mod metadata;
pub mod rules;
pub mod snapshot;
pub mod writebuf;

pub use error::{CoreError, Result};
