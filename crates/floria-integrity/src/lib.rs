//! Authentication and anti-rollback for daemon-owned security state.
//!
//! Storage formats remain adapters: JSON and SQLite are not trust boundaries. This module owns
//! the invariant that a persisted security decision is accepted only when its HMAC and monotonic
//! Keychain checkpoint both verify.

use std::collections::{BTreeMap, HashMap};
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
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

const ENVELOPE_FORMAT: u32 = 1;
const AUTHORITY_FORMAT: u32 = 1;
const KEY_BYTES: usize = 32;
const KEYCHAIN_SERVICE: &str = "floria.hola.ac.integrity";
const KEYCHAIN_AUTHORITY_ACCOUNT: &str = "state-authentication-key";
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static KEYCHAIN_AUTHORITY_WRITE_LOCK: Mutex<()> = Mutex::new(());

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

trait CredentialStore: Send + Sync {
    fn load(&self, account: &str) -> IntegrityResult<Option<Vec<u8>>>;
    fn store(&self, account: &str, value: &[u8]) -> IntegrityResult<()>;
    fn delete(&self, account: &str) -> IntegrityResult<()>;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRecord {
    format: u32,
    key: String,
    checkpoints: BTreeMap<String, Checkpoint>,
}

impl AuthorityRecord {
    fn new(key: &[u8]) -> Self {
        Self {
            format: AUTHORITY_FORMAT,
            key: base64::engine::general_purpose::STANDARD.encode(key),
            checkpoints: BTreeMap::new(),
        }
    }

    fn key_bytes(&self) -> IntegrityResult<Vec<u8>> {
        if self.format != AUTHORITY_FORMAT {
            return Err(IntegrityError::Keychain(format!(
                "{KEYCHAIN_SERVICE}/{KEYCHAIN_AUTHORITY_ACCOUNT} has unsupported format {}",
                self.format
            )));
        }
        let key = base64::engine::general_purpose::STANDARD
            .decode(&self.key)
            .map_err(|error| {
                IntegrityError::Keychain(format!(
                    "{KEYCHAIN_SERVICE}/{KEYCHAIN_AUTHORITY_ACCOUNT} has an invalid key: {error}"
                ))
            })?;
        validate_key_length(&key)?;
        Ok(key)
    }
}

impl Drop for AuthorityRecord {
    fn drop(&mut self) {
        self.key.zeroize();
    }
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
    /// login Keychain as one versioned record and are never persisted beside the files they
    /// authenticate.
    #[cfg(target_os = "macos")]
    pub fn keychain() -> IntegrityResult<Self> {
        let credentials: Arc<dyn CredentialStore> = Arc::new(KeychainCredentials);
        let (key, checkpoints) = open_credential_authority(credentials, || {
            let mut key = vec![0_u8; KEY_BYTES];
            security_framework::random::SecRandom::default()
                .copy_bytes(&mut key)
                .map_err(|error| IntegrityError::Keychain(error.to_string()))?;
            Ok(key)
        })?;
        Ok(Self {
            key: Arc::new(Zeroizing::new(key)),
            checkpoints,
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

    /// Reconstruct only the exact state already committed to the trusted checkpoint.
    /// This read-only recovery operation neither advances Keychain nor accepts a future state.
    pub fn reconstruct_checkpointed_state<T: Serialize>(
        &self,
        domain: &str,
        candidates: impl IntoIterator<Item = T>,
    ) -> IntegrityResult<Vec<u8>> {
        let checkpoint = self.checkpoints.load(domain)?
            .ok_or_else(|| invalid(domain, "trusted checkpoint is missing"))?;
        for candidate in candidates {
            let payload = serde_json::to_vec(&candidate)?;
            if self.verify_mac(domain, checkpoint.generation, &payload, &checkpoint.mac).is_ok() {
                let envelope = Envelope {
                    format: ENVELOPE_FORMAT,
                    generation: checkpoint.generation,
                    payload: base64::engine::general_purpose::STANDARD.encode(payload),
                    mac: checkpoint.mac,
                };
                return Ok(serde_json::to_vec(&envelope)?);
            }
        }
        Err(invalid(domain, "no candidate matches the trusted checkpoint"))
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

/// Checkpoints share one credential record. Product mutations have one daemon writer; the static
/// lock additionally prevents read-modify-write loss between its worker threads and authenticator
/// instances in the same process.
struct CredentialCheckpoints {
    credentials: Arc<dyn CredentialStore>,
}

impl CheckpointStore for CredentialCheckpoints {
    fn load(&self, domain: &str) -> IntegrityResult<Option<Checkpoint>> {
        let account = legacy_checkpoint_account(domain);
        let record = load_authority_record(self.credentials.as_ref())?;
        if let Some(checkpoint) = record.checkpoints.get(&account) {
            return Ok(Some(checkpoint.clone()));
        }

        let Some(bytes) = self.credentials.load(&account)? else {
            return Ok(None);
        };
        let checkpoint = serde_json::from_slice::<Checkpoint>(&bytes)?;
        self.merge_legacy_checkpoint(&account, &checkpoint)?;
        Ok(Some(checkpoint))
    }

    fn store(&self, domain: &str, checkpoint: &Checkpoint) -> IntegrityResult<()> {
        let account = legacy_checkpoint_account(domain);
        let _guard = KEYCHAIN_AUTHORITY_WRITE_LOCK
            .lock()
            .map_err(|_| keychain_error("authority write lock is poisoned"))?;
        let mut record = load_authority_record(self.credentials.as_ref())?;
        record.checkpoints.insert(account, checkpoint.clone());
        store_and_verify_authority_record(self.credentials.as_ref(), &record)
    }
}

impl CredentialCheckpoints {
    fn merge_legacy_checkpoint(
        &self,
        legacy_account: &str,
        checkpoint: &Checkpoint,
    ) -> IntegrityResult<()> {
        let _guard = KEYCHAIN_AUTHORITY_WRITE_LOCK
            .lock()
            .map_err(|_| keychain_error("authority write lock is poisoned"))?;
        let mut record = load_authority_record(self.credentials.as_ref())?;
        match record.checkpoints.get(legacy_account) {
            Some(existing) if existing != checkpoint => {
                return Err(keychain_error(format!(
                    "legacy checkpoint {legacy_account} conflicts with the migrated authority record"
                )));
            }
            Some(_) => {}
            None => {
                record
                    .checkpoints
                    .insert(legacy_account.to_string(), checkpoint.clone());
                store_and_verify_authority_record(self.credentials.as_ref(), &record)?;
            }
        }

        // The aggregate record is authoritative after the verified write. Failure to remove the
        // legacy item must not make the authenticated state unavailable; it will remain inert.
        let _ = self.credentials.delete(legacy_account);
        Ok(())
    }
}

fn open_credential_authority(
    credentials: Arc<dyn CredentialStore>,
    create_key: impl FnOnce() -> IntegrityResult<Vec<u8>>,
) -> IntegrityResult<(Vec<u8>, Arc<dyn CheckpointStore>)> {
    let key = match credentials.load(KEYCHAIN_AUTHORITY_ACCOUNT)? {
        Some(bytes) if bytes.len() == KEY_BYTES => {
            validate_key_length(&bytes)?;
            let record = AuthorityRecord::new(&bytes);
            store_and_verify_authority_record(credentials.as_ref(), &record)?;
            bytes
        }
        Some(bytes) => decode_authority_record(&bytes)?.key_bytes()?,
        None => {
            let key = create_key()?;
            validate_key_length(&key)?;
            let record = AuthorityRecord::new(&key);
            store_and_verify_authority_record(credentials.as_ref(), &record)?;
            key
        }
    };
    let checkpoints: Arc<dyn CheckpointStore> = Arc::new(CredentialCheckpoints { credentials });
    Ok((key, checkpoints))
}

fn load_authority_record(credentials: &dyn CredentialStore) -> IntegrityResult<AuthorityRecord> {
    let bytes = credentials.load(KEYCHAIN_AUTHORITY_ACCOUNT)?.ok_or_else(|| {
        keychain_error(format!(
            "{KEYCHAIN_SERVICE}/{KEYCHAIN_AUTHORITY_ACCOUNT} disappeared while Floria was running"
        ))
    })?;
    decode_authority_record(&bytes)
}

fn decode_authority_record(bytes: &[u8]) -> IntegrityResult<AuthorityRecord> {
    let record = serde_json::from_slice::<AuthorityRecord>(bytes).map_err(|error| {
        keychain_error(format!(
            "{KEYCHAIN_SERVICE}/{KEYCHAIN_AUTHORITY_ACCOUNT} is not a valid authority record: {error}"
        ))
    })?;
    record.key_bytes()?;
    Ok(record)
}

fn store_and_verify_authority_record(
    credentials: &dyn CredentialStore,
    record: &AuthorityRecord,
) -> IntegrityResult<()> {
    credentials.store(KEYCHAIN_AUTHORITY_ACCOUNT, &serde_json::to_vec(record)?)?;
    let verified = load_authority_record(credentials)?;
    if verified.key != record.key || verified.checkpoints != record.checkpoints {
        return Err(keychain_error("authority record did not round-trip exactly"));
    }
    Ok(())
}

fn validate_key_length(key: &[u8]) -> IntegrityResult<()> {
    if key.len() == KEY_BYTES {
        Ok(())
    } else {
        Err(keychain_error(format!(
            "{KEYCHAIN_SERVICE}/{KEYCHAIN_AUTHORITY_ACCOUNT} has invalid key length {}",
            key.len()
        )))
    }
}

fn keychain_error(reason: impl Into<String>) -> IntegrityError {
    IntegrityError::Keychain(reason.into())
}

#[cfg(target_os = "macos")]
struct KeychainCredentials;

#[cfg(target_os = "macos")]
impl CredentialStore for KeychainCredentials {
    fn load(&self, account: &str) -> IntegrityResult<Option<Vec<u8>>> {
        match security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, account) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error)
                if error.code() == security_framework_sys::base::errSecItemNotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(keychain_error(error.to_string())),
        }
    }

    fn store(&self, account: &str, value: &[u8]) -> IntegrityResult<()> {
        security_framework::passwords::set_generic_password(KEYCHAIN_SERVICE, account, value)
            .map_err(|error| keychain_error(error.to_string()))
    }

    fn delete(&self, account: &str) -> IntegrityResult<()> {
        match security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, account) {
            Ok(()) => Ok(()),
            Err(error)
                if error.code() == security_framework_sys::base::errSecItemNotFound =>
            {
                Ok(())
            }
            Err(error) => Err(keychain_error(error.to_string())),
        }
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

fn legacy_checkpoint_account(domain: &str) -> String {
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

    #[derive(Default)]
    struct MemoryCredentials(Mutex<HashMap<String, Vec<u8>>>);

    impl MemoryCredentials {
        fn insert(&self, account: impl Into<String>, value: Vec<u8>) {
            self.0.lock().unwrap().insert(account.into(), value);
        }

        fn accounts(&self) -> Vec<String> {
            let mut accounts = self.0.lock().unwrap().keys().cloned().collect::<Vec<_>>();
            accounts.sort();
            accounts
        }
    }

    impl CredentialStore for MemoryCredentials {
        fn load(&self, account: &str) -> IntegrityResult<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().get(account).cloned())
        }

        fn store(&self, account: &str, value: &[u8]) -> IntegrityResult<()> {
            self.0.lock().unwrap().insert(account.to_string(), value.to_vec());
            Ok(())
        }

        fn delete(&self, account: &str) -> IntegrityResult<()> {
            self.0.lock().unwrap().remove(account);
            Ok(())
        }
    }

    fn credential_authenticator(
        credentials: Arc<MemoryCredentials>,
        key: [u8; KEY_BYTES],
    ) -> StateAuthenticator {
        let store: Arc<dyn CredentialStore> = credentials;
        let (key, checkpoints) =
            open_credential_authority(store, || Ok(key.to_vec())).unwrap();
        StateAuthenticator { key: Arc::new(Zeroizing::new(key)), checkpoints }
    }

    #[test]
    fn integrity_authority_uses_one_keychain_item_across_domains() {
        let dir = tempfile::tempdir().unwrap();
        let credentials = Arc::new(MemoryCredentials::default());
        let auth = credential_authenticator(Arc::clone(&credentials), [5; KEY_BYTES]);
        let domains = [
            "encrypted-store-security-state",
            "catalog-security-state",
            "authorization-grants",
            "global-policy-mode",
            "audit-log-checkpoint",
            "replication-runtime-settings",
        ];
        for domain in domains {
            auth.persist(
                &dir.path().join(format!("{domain}.json")),
                domain,
                0,
                &Fixture { value: domain.into() },
            )
            .unwrap();
        }

        assert_eq!(credentials.accounts(), [KEYCHAIN_AUTHORITY_ACCOUNT]);

        let reopened = credential_authenticator(Arc::clone(&credentials), [99; KEY_BYTES]);
        for domain in domains {
            let loaded = reopened
                .load::<Fixture>(&dir.path().join(format!("{domain}.json")), domain)
                .unwrap();
            assert_eq!(loaded.value.unwrap().value, domain);
        }
    }

    #[test]
    fn migrates_legacy_key_and_checkpoint_into_the_authority_item() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let domain = "catalog-security-state";
        let key = [13; KEY_BYTES];
        let legacy = StateAuthenticator::for_tests(key);
        legacy
            .persist(&path, domain, 0, &Fixture { value: "legacy".into() })
            .unwrap();
        let checkpoint = legacy.checkpoints.load(domain).unwrap().unwrap();

        let credentials = Arc::new(MemoryCredentials::default());
        credentials.insert(KEYCHAIN_AUTHORITY_ACCOUNT, key.to_vec());
        credentials.insert(
            legacy_checkpoint_account(domain),
            serde_json::to_vec(&checkpoint).unwrap(),
        );
        let auth = credential_authenticator(Arc::clone(&credentials), [99; KEY_BYTES]);

        let loaded = auth.load::<Fixture>(&path, domain).unwrap();
        assert_eq!(loaded.value.unwrap().value, "legacy");
        assert_eq!(credentials.accounts(), [KEYCHAIN_AUTHORITY_ACCOUNT]);

        let record = load_authority_record(credentials.as_ref()).unwrap();
        assert_eq!(record.key_bytes().unwrap(), key);
        assert_eq!(record.checkpoints.get(&legacy_checkpoint_account(domain)), Some(&checkpoint));
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

    #[test]
    fn reconstructs_only_the_committed_state_after_an_interrupted_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let auth = StateAuthenticator::for_tests([12; KEY_BYTES]);
        auth.persist(&path, "fixture", 0, &Fixture { value: "committed".into() }).unwrap();
        let committed = fs::read(&path).unwrap();
        let payload = serde_json::to_vec(&Fixture { value: "uncommitted".into() }).unwrap();
        let torn = Envelope {
            format: ENVELOPE_FORMAT,
            generation: 2,
            payload: base64::engine::general_purpose::STANDARD.encode(&payload),
            mac: auth.mac("fixture", 2, &payload),
        };
        fs::write(&path, serde_json::to_vec(&torn).unwrap()).unwrap();
        assert!(auth.load::<Fixture>(&path, "fixture").is_err());

        let recovered = auth.reconstruct_checkpointed_state("fixture", [
            Fixture { value: "uncommitted".into() },
            Fixture { value: "committed".into() },
        ]).unwrap();
        assert_eq!(recovered, committed);
        assert_eq!(auth.checkpoint_generation("fixture").unwrap(), 1);
        fs::write(&path, recovered).unwrap();
        assert_eq!(auth.load::<Fixture>(&path, "fixture").unwrap().value.unwrap().value, "committed");

        auth.persist(&path, "fixture", 1, &Fixture { value: "newer".into() }).unwrap();
        assert!(auth.reconstruct_checkpointed_state("fixture", [
            Fixture { value: "committed".into() },
        ]).is_err());
        assert!(auth.reconstruct_checkpointed_state("unknown", [
            Fixture { value: "newer".into() },
        ]).is_err());
    }
}
