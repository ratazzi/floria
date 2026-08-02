//! Authentication and anti-rollback for daemon-owned security state.
//!
//! Storage formats remain adapters: JSON and SQLite are not trust boundaries. This module owns
//! the invariant that a persisted security decision is accepted only when its HMAC and monotonic
//! Keychain checkpoint both verify.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const ENVELOPE_FORMAT: u32 = 1;
const KEY_BYTES: usize = 32;
const KEYCHAIN_SERVICE: &str = "floria.hola.ac.integrity";
const KEYCHAIN_KEY_ACCOUNT: &str = "state-authentication-key";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("integrity state I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("integrity state encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("Keychain integrity authority failed: {0}")]
    Keychain(String),
    #[error("invalid authenticated state for {domain}: {reason}")]
    Invalid { domain: String, reason: String },
    #[error("authenticated state for {domain} was rolled back from generation {expected} to {actual}")]
    Rollback { domain: String, expected: u64, actual: u64 },
}

pub type IntegrityResult<T> = Result<T, IntegrityError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Checkpoint {
    generation: u64,
    mac: String,
}

trait CheckpointStore: Send + Sync {
    fn load(&self, domain: &str) -> IntegrityResult<Option<Checkpoint>>;
    fn store(&self, domain: &str, checkpoint: &Checkpoint) -> IntegrityResult<()>;
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: u32,
    generation: u64,
    payload: String,
    mac: String,
}

/// Authenticated payload plus the generation to pass back on the next write.
pub struct LoadedState<T> {
    pub value: Option<T>,
    pub generation: u64,
}

/// One deep boundary for authenticating security state, independent of its payload schema.
#[derive(Clone)]
pub struct StateAuthenticator {
    key: Arc<Zeroizing<Vec<u8>>>,
    checkpoints: Arc<dyn CheckpointStore>,
}

impl StateAuthenticator {
    /// Open the production authority. The HMAC key and anti-rollback checkpoints live in the
    /// login Keychain and are never persisted beside the files they authenticate.
    #[cfg(target_os = "macos")]
    pub fn keychain() -> IntegrityResult<Self> {
        let key = match security_framework::passwords::get_generic_password(
            KEYCHAIN_SERVICE,
            KEYCHAIN_KEY_ACCOUNT,
        ) {
            Ok(key) => key,
            Err(error)
                if error.code() == security_framework_sys::base::errSecItemNotFound =>
            {
                let mut key = vec![0_u8; KEY_BYTES];
                security_framework::random::SecRandom::default()
                    .copy_bytes(&mut key)
                    .map_err(|error| IntegrityError::Keychain(error.to_string()))?;
                security_framework::passwords::set_generic_password(
                    KEYCHAIN_SERVICE,
                    KEYCHAIN_KEY_ACCOUNT,
                    &key,
                )
                .map_err(|error| IntegrityError::Keychain(error.to_string()))?;
                key
            }
            Err(error) => return Err(IntegrityError::Keychain(error.to_string())),
        };
        if key.len() != KEY_BYTES {
            return Err(IntegrityError::Keychain(format!(
                "{KEYCHAIN_SERVICE}/{KEYCHAIN_KEY_ACCOUNT} has invalid length {}",
                key.len()
            )));
        }
        Ok(Self {
            key: Arc::new(Zeroizing::new(key)),
            checkpoints: Arc::new(KeychainCheckpoints),
        })
    }

    /// Deterministic isolated authority for unit tests. It has the same rollback semantics as the
    /// Keychain adapter without mutating the developer's login Keychain.
    pub fn for_tests(key: [u8; KEY_BYTES]) -> Self {
        Self {
            key: Arc::new(Zeroizing::new(key.to_vec())),
            checkpoints: Arc::new(MemoryCheckpoints::default()),
        }
    }

    pub fn load<T: DeserializeOwned>(
        &self,
        path: &Path,
        domain: &str,
    ) -> IntegrityResult<LoadedState<T>> {
        let checkpoint = self.checkpoints.load(domain)?;
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(LoadedState {
                    value: None,
                    generation: checkpoint.map_or(0, |checkpoint| checkpoint.generation),
                });
            }
            Err(source) => return Err(io_error(path, source)),
        };
        validate_private_regular_file(path)?;
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        if envelope.format != ENVELOPE_FORMAT {
            return Err(invalid(domain, format!("unsupported envelope format {}", envelope.format)));
        }
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&envelope.payload)
            .map_err(|error| invalid(domain, format!("payload is not Base64: {error}")))?;
        self.verify_mac(domain, envelope.generation, &payload, &envelope.mac)?;

        if let Some(checkpoint) = checkpoint {
            if envelope.generation < checkpoint.generation {
                return Err(IntegrityError::Rollback {
                    domain: domain.to_string(),
                    expected: checkpoint.generation,
                    actual: envelope.generation,
                });
            }
            if envelope.generation > checkpoint.generation {
                return Err(invalid(
                    domain,
                    format!(
                        "state generation {} is ahead of Keychain checkpoint {}",
                        envelope.generation, checkpoint.generation
                    ),
                ));
            }
            if envelope.mac != checkpoint.mac {
                return Err(invalid(domain, "checkpoint MAC does not match the state file"));
            }
        } else {
            return Err(invalid(
                domain,
                "state file exists without its Keychain checkpoint",
            ));
        }

        let value = serde_json::from_slice(&payload)?;
        Ok(LoadedState { value: Some(value), generation: envelope.generation })
    }

    pub fn persist<T: Serialize>(
        &self,
        path: &Path,
        domain: &str,
        current_generation: u64,
        value: &T,
    ) -> IntegrityResult<u64> {
        let checkpoint = self.checkpoints.load(domain)?;
        if checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.generation > current_generation)
        {
            return Err(IntegrityError::Rollback {
                domain: domain.to_string(),
                expected: checkpoint.expect("checked above").generation,
                actual: current_generation,
            });
        }
        let generation = current_generation
            .checked_add(1)
            .ok_or_else(|| invalid(domain, "generation overflow"))?;
        let payload = serde_json::to_vec(value)?;
        let mac = self.mac(domain, generation, &payload);
        let envelope = Envelope {
            format: ENVELOPE_FORMAT,
            generation,
            payload: base64::engine::general_purpose::STANDARD.encode(payload),
            mac: mac.clone(),
        };
        write_private_atomic(path, &serde_json::to_vec(&envelope)?)?;
        self.checkpoints.store(domain, &Checkpoint { generation, mac })?;
        Ok(generation)
    }

    pub fn checkpoint_generation(&self, domain: &str) -> IntegrityResult<u64> {
        Ok(self.checkpoints.load(domain)?.map_or(0, |checkpoint| checkpoint.generation))
    }

    /// Authenticate an append-only record without advancing a rollback checkpoint.
    ///
    /// Callers still persist their latest accepted tail through [`StateAuthenticator::persist`].
    /// This detached tag prevents a process that can edit the log from forging extra records
    /// between authenticated checkpoints.
    pub fn authenticate_detached(&self, domain: &str, payload: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(b"floria-detached-v1");
        mac.update(&(domain.len() as u64).to_be_bytes());
        mac.update(domain.as_bytes());
        mac.update(&(payload.len() as u64).to_be_bytes());
        mac.update(payload);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    pub fn verify_detached(
        &self,
        domain: &str,
        payload: &[u8],
        encoded: &str,
    ) -> IntegrityResult<()> {
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| invalid(domain, format!("detached MAC is not Base64: {error}")))?;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(b"floria-detached-v1");
        mac.update(&(domain.len() as u64).to_be_bytes());
        mac.update(domain.as_bytes());
        mac.update(&(payload.len() as u64).to_be_bytes());
        mac.update(payload);
        mac.verify_slice(&expected)
            .map_err(|_| invalid(domain, "detached HMAC verification failed"))
    }

    fn mac(&self, domain: &str, generation: u64, payload: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&(domain.len() as u64).to_be_bytes());
        mac.update(domain.as_bytes());
        mac.update(&generation.to_be_bytes());
        mac.update(&(payload.len() as u64).to_be_bytes());
        mac.update(payload);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn verify_mac(
        &self,
        domain: &str,
        generation: u64,
        payload: &[u8],
        encoded: &str,
    ) -> IntegrityResult<()> {
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| invalid(domain, format!("MAC is not Base64: {error}")))?;
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&(domain.len() as u64).to_be_bytes());
        mac.update(domain.as_bytes());
        mac.update(&generation.to_be_bytes());
        mac.update(&(payload.len() as u64).to_be_bytes());
        mac.update(payload);
        mac.verify_slice(&expected)
            .map_err(|_| invalid(domain, "HMAC verification failed"))
    }
}

#[cfg(target_os = "macos")]
struct KeychainCheckpoints;

#[cfg(target_os = "macos")]
impl CheckpointStore for KeychainCheckpoints {
    fn load(&self, domain: &str) -> IntegrityResult<Option<Checkpoint>> {
        let account = checkpoint_account(domain);
        match security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, &account) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(IntegrityError::from),
            Err(error)
                if error.code() == security_framework_sys::base::errSecItemNotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(IntegrityError::Keychain(error.to_string())),
        }
    }

    fn store(&self, domain: &str, checkpoint: &Checkpoint) -> IntegrityResult<()> {
        security_framework::passwords::set_generic_password(
            KEYCHAIN_SERVICE,
            &checkpoint_account(domain),
            &serde_json::to_vec(checkpoint)?,
        )
        .map_err(|error| IntegrityError::Keychain(error.to_string()))
    }
}

#[derive(Default)]
struct MemoryCheckpoints(Mutex<HashMap<String, Checkpoint>>);

impl CheckpointStore for MemoryCheckpoints {
    fn load(&self, domain: &str) -> IntegrityResult<Option<Checkpoint>> {
        Ok(self.0.lock().expect("checkpoint store poisoned").get(domain).cloned())
    }

    fn store(&self, domain: &str, checkpoint: &Checkpoint) -> IntegrityResult<()> {
        self.0
            .lock()
            .expect("checkpoint store poisoned")
            .insert(domain.to_string(), checkpoint.clone());
        Ok(())
    }
}

fn checkpoint_account(domain: &str) -> String {
    let digest = Sha256::digest(domain.as_bytes());
    format!(
        "checkpoint-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn validate_private_regular_file(path: &Path) -> IntegrityResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(invalid("file", format!("{} must be a regular file", path.display())));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid(
            "file",
            format!("{} must not be accessible by group or other users", path.display()),
        ));
    }
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> IntegrityResult<()> {
    let parent = path.parent().ok_or_else(|| invalid("file", "state path has no parent"))?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(parent, source))?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("tmp.{}.{}", std::process::id(), sequence));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|source| io_error(&temporary, source))?;
    file.write_all(bytes).map_err(|source| io_error(&temporary, source))?;
    file.sync_all().map_err(|source| io_error(&temporary, source))?;
    fs::rename(&temporary, path).map_err(|source| io_error(path, source))?;
    let directory = OpenOptions::new().read(true).open(parent).map_err(|source| io_error(parent, source))?;
    directory.sync_all().map_err(|source| io_error(parent, source))
}

fn invalid(domain: &str, reason: impl Into<String>) -> IntegrityError {
    IntegrityError::Invalid { domain: domain.to_string(), reason: reason.into() }
}

fn io_error(path: impl Into<PathBuf>, source: io::Error) -> IntegrityError {
    IntegrityError::Io { path: path.into(), source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Fixture {
        value: String,
    }

    #[test]
    fn authenticates_and_reopens_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let auth = StateAuthenticator::for_tests([7; KEY_BYTES]);

        let generation = auth
            .persist(&path, "fixture", 0, &Fixture { value: "safe".into() })
            .unwrap();
        let loaded = auth.load::<Fixture>(&path, "fixture").unwrap();

        assert_eq!(generation, 1);
        assert_eq!(loaded.generation, 1);
        assert_eq!(loaded.value.unwrap().value, "safe");
    }

    #[test]
    fn rejects_tampering_and_signed_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let auth = StateAuthenticator::for_tests([9; KEY_BYTES]);
        let first = auth.persist(&path, "fixture", 0, &Fixture { value: "one".into() }).unwrap();
        let old = fs::read(&path).unwrap();
        auth.persist(&path, "fixture", first, &Fixture { value: "two".into() }).unwrap();

        fs::write(&path, &old).unwrap();
        assert!(matches!(
            auth.load::<Fixture>(&path, "fixture"),
            Err(IntegrityError::Rollback { .. })
        ));

        let mut tampered = old;
        *tampered.last_mut().unwrap() ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(auth.load::<Fixture>(&path, "fixture").is_err());
    }

    #[test]
    fn rejects_a_valid_state_ahead_of_its_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let auth = StateAuthenticator::for_tests([11; KEY_BYTES]);
        auth.persist(&path, "fixture", 0, &Fixture { value: "one".into() })
            .unwrap();

        let payload = serde_json::to_vec(&Fixture { value: "future".into() }).unwrap();
        let envelope = Envelope {
            format: ENVELOPE_FORMAT,
            generation: 2,
            payload: base64::engine::general_purpose::STANDARD.encode(&payload),
            mac: auth.mac("fixture", 2, &payload),
        };
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        assert!(matches!(
            auth.load::<Fixture>(&path, "fixture"),
            Err(IntegrityError::Invalid { .. })
        ));
    }
}
