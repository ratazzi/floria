//! accessfs-store: confidential secret storage, decoupled from encryption backend.
//!
//! Secrets live as portable age-encrypted blobs ([`AgeDirStore`]); the key that protects them
//! comes from a swappable [`KeyProvider`] (SSH ed25519 for dev; a dedicated age key or Keychain
//! later). The FS read path and the `protect` CLI both drive the same [`SecretStore`] trait.

mod error;
mod keys;
mod source;
mod store;

pub use error::{StoreError, StoreResult};
pub use keys::{
    KeyProvider, KeychainKeyProvider, SshKeyProvider, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE,
};
pub use source::StoreSource;
pub use store::{
    AgeDirStore, NewSecret, SecretId, SecretOrigin, SecretRecord, SecretStore, VersionRecord,
};
