//! floria-store: confidential secret storage, decoupled from encryption backend.
//!
//! Secrets live as portable age-encrypted blobs ([`AgeDirStore`]); the key that protects them
//! comes from a swappable [`KeyProvider`] (an SSH key for development or a dedicated ed25519 key
//! in the login Keychain for installed apps). The FS read path and the `protect` CLI both drive
//! the same [`SecretStore`] trait.

mod device;
mod error;
mod generations;
mod keys;
mod recovery;
mod source;
mod store;
pub mod vault;

pub use device::{DeviceKeyMaterial, DeviceKeyStore};
pub use error::{StoreError, StoreResult};
pub use keys::{
    KeyProvider, KeychainKeyProvider, SshKeyProvider, KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE,
};
pub use recovery::{decrypt_recovery_key, export_recovery_key};
pub use source::StoreSource;
pub use store::{
    AgeDirStore, NewSecret, SecretId, SecretOrigin, SecretRecord, SecretStore,
    StoreMaintenanceGuard, StoreVerification, StoreVersionRef, VersionRecord,
    MIN_SUPPORTED_STORE_FORMAT_VERSION, STORE_FORMAT_VERSION,
};
