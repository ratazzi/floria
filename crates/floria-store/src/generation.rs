//! Generation data keys: the indirection that keeps version files device-independent.
//!
//! Version blobs are encrypted to a random per-generation X25519 data key (plus the recovery
//! recipient), never to a device key. Devices hold small wrap envelopes under `<root>/keys/`:
//! `<N>.age` seals generation `N`'s identity to the device key supplied by [`KeyProvider`].
//! Adding or removing a device therefore never rewrites version files; revocation starts a new
//! generation and old files keep their bytes — the property that makes the store directly
//! syncable (see `docs/design/portable-replication.md`).
//!
//! Encryption needs only the plaintext `<N>.pub` / `recovery.pub` files, so `protect` still
//! works without unlocking the device key; only decryption unwraps an envelope (cached for the
//! store's lifetime).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use age::secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{StoreError, StoreResult};
use crate::keys::KeyProvider;
use crate::store::write_private;

pub(crate) const KEYS_DIR: &str = "keys";
const RECOVERY_PUB: &str = "recovery.pub";
const RECOVERY_ENVELOPE: &str = "recovery.age";

pub(crate) struct GenerationKeys {
    dir: PathBuf,
    unwrapped: Mutex<HashMap<u32, age::x25519::Identity>>,
}

impl GenerationKeys {
    pub(crate) fn open(root: &Path) -> Self {
        GenerationKeys {
            dir: root.join(KEYS_DIR),
            unwrapped: Mutex::new(HashMap::new()),
        }
    }

    /// Create generation 1 and the recovery recipient for a store that has none yet.
    ///
    /// Both identities are generated in memory; the generation secret and the recovery escrow
    /// are written wrapped to the device recipients only. Callers hold the store lock.
    pub(crate) fn initialize_if_missing(&self, device: &dyn KeyProvider) -> StoreResult<bool> {
        if self.current_generation()?.is_some() {
            return Ok(false);
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| StoreError::io(&self.dir, e))?;
        let recipients = device.recipients()?;
        if recipients.is_empty() {
            return Err(StoreError::Key(
                "device key provider returned no recipients".to_string(),
            ));
        }
        let generation = age::x25519::Identity::generate();
        let recovery = age::x25519::Identity::generate();

        // Publish public halves first (plaintext, needed to encrypt without unlocking anything),
        // then the wrapped secrets. A crash in between leaves a keys dir that fails closed on
        // decrypt and is repaired by deleting the partial directory of an empty store.
        write_private(
            &self.dir.join("1.pub"),
            generation.to_public().to_string().as_bytes(),
        )?;
        write_private(
            &self.dir.join(RECOVERY_PUB),
            recovery.to_public().to_string().as_bytes(),
        )?;
        let device_recipients = device.recipients()?;
        write_private(
            &self.dir.join("1.age"),
            &encrypt_to(recipients, generation.to_string().expose_secret().as_bytes())?,
        )?;
        write_private(
            &self.dir.join(RECOVERY_ENVELOPE),
            &encrypt_to(device_recipients, recovery.to_string().expose_secret().as_bytes())?,
        )?;
        Ok(true)
    }

    /// Highest generation with a published public key, or `None` for an uninitialized store.
    pub(crate) fn current_generation(&self) -> StoreResult<Option<u32>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::io(&self.dir, e)),
        };
        let mut max = None;
        for entry in entries {
            let entry = entry.map_err(|e| StoreError::io(&self.dir, e))?;
            let name = entry.file_name();
            if let Some(stem) = name.to_string_lossy().strip_suffix(".pub") {
                if let Ok(generation) = stem.parse::<u32>() {
                    max = Some(max.map_or(generation, |m: u32| m.max(generation)));
                }
            }
        }
        Ok(max)
    }

    fn require_current_generation(&self) -> StoreResult<u32> {
        self.current_generation()?.ok_or_else(|| {
            StoreError::Key(format!(
                "store has no generation keys under {}; the store was not initialized",
                self.dir.display()
            ))
        })
    }

    /// Encryption recipients for new versions: the current generation plus recovery.
    pub(crate) fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
        let generation = self.require_current_generation()?;
        Ok(vec![
            Box::new(self.read_recipient(&format!("{generation}.pub"))?),
            Box::new(self.read_recipient(RECOVERY_PUB)?),
        ])
    }

    /// The generation new versions are encrypted under right now.
    pub(crate) fn encryption_generation(&self) -> StoreResult<u32> {
        self.require_current_generation()
    }

    /// Unwrap (and cache) the identity for `generation` using the device key.
    pub(crate) fn identity(
        &self,
        generation: u32,
        device: &dyn KeyProvider,
    ) -> StoreResult<age::x25519::Identity> {
        if let Some(identity) = self
            .unwrapped
            .lock()
            .expect("generation key cache poisoned")
            .get(&generation)
        {
            return Ok(identity.clone());
        }
        let path = self.dir.join(format!("{generation}.age"));
        let ciphertext = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::Key(format!(
                    "generation {generation} envelope is missing at {}",
                    path.display()
                ))
            } else {
                StoreError::io(&path, e)
            }
        })?;
        let device_identity = device.identity()?;
        let secret = decrypt_with(&ciphertext, device_identity.as_ref())?;
        let text = std::str::from_utf8(&secret)
            .map_err(|_| StoreError::Key(format!("generation {generation} envelope is not text")))?;
        let identity = age::x25519::Identity::from_str(text.trim()).map_err(|e| {
            StoreError::Key(format!("parse generation {generation} identity: {e}"))
        })?;
        self.unwrapped
            .lock()
            .expect("generation key cache poisoned")
            .insert(generation, identity.clone());
        Ok(identity)
    }

    /// The wrapped secret string of a generation identity (for enrollment envelopes).
    pub(crate) fn identity_secret(
        &self,
        generation: u32,
        device: &dyn KeyProvider,
    ) -> StoreResult<Zeroizing<String>> {
        let identity = self.identity(generation, device)?;
        Ok(Zeroizing::new(identity.to_string().expose_secret().clone()))
    }

    /// The plaintext public key of a generation, or `None` if that generation is unknown here.
    pub(crate) fn generation_public(&self, generation: u32) -> StoreResult<Option<String>> {
        let path = self.dir.join(format!("{generation}.pub"));
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text.trim().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::io(&path, e)),
        }
    }

    /// The plaintext recovery recipient string.
    pub(crate) fn recovery_public(&self) -> StoreResult<String> {
        let path = self.dir.join(RECOVERY_PUB);
        std::fs::read_to_string(&path)
            .map(|text| text.trim().to_string())
            .map_err(|e| StoreError::io(&path, e))
    }

    /// Start generation N+1 with a fresh random identity. Existing files are untouched;
    /// only new versions encrypt to the new generation. Callers hold the store lock.
    pub(crate) fn rotate(&self, device: &dyn KeyProvider) -> StoreResult<u32> {
        let current = self.require_current_generation()?;
        let next = current
            .checked_add(1)
            .ok_or_else(|| StoreError::Key("generation overflow".to_string()))?;
        let identity = age::x25519::Identity::generate();
        self.write_generation(next, &identity, device)?;
        Ok(next)
    }

    /// Replace this store's key material with externally supplied generations (joining a
    /// vault). Only legal while the store holds no secret entries — a populated store's
    /// versions are bound to the local generations and would become undecryptable.
    /// Callers hold the store lock and have verified the store is empty.
    pub(crate) fn adopt(
        &self,
        device: &dyn KeyProvider,
        generations: &[(u32, Zeroizing<String>)],
        recovery_public: &str,
    ) -> StoreResult<()> {
        if generations.is_empty() {
            return Err(StoreError::Key("cannot adopt an empty generation set".to_string()));
        }
        if std::fs::read_dir(&self.dir).is_ok() {
            std::fs::remove_dir_all(&self.dir).map_err(|e| StoreError::io(&self.dir, e))?;
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| StoreError::io(&self.dir, e))?;
        for (generation, secret) in generations {
            let identity = age::x25519::Identity::from_str(secret.trim()).map_err(|e| {
                StoreError::Key(format!("parse adopted generation {generation}: {e}"))
            })?;
            self.write_generation(*generation, &identity, device)?;
        }
        age::x25519::Recipient::from_str(recovery_public.trim())
            .map_err(|e| StoreError::Key(format!("parse adopted recovery recipient: {e}")))?;
        write_private(&self.dir.join(RECOVERY_PUB), recovery_public.trim().as_bytes())?;
        self.unwrapped.lock().expect("generation key cache poisoned").clear();
        Ok(())
    }

    /// Install one generation this store doesn't have yet without touching existing keys
    /// (a re-enrolled member learning the vault's newer generations). Idempotent when the
    /// same key is already present; a different key for an existing generation is an error.
    pub(crate) fn install(
        &self,
        generation: u32,
        secret: &str,
        device: &dyn KeyProvider,
    ) -> StoreResult<()> {
        let identity = age::x25519::Identity::from_str(secret.trim()).map_err(|e| {
            StoreError::Key(format!("parse installed generation {generation}: {e}"))
        })?;
        if let Some(existing) = self.generation_public(generation)? {
            if existing == identity.to_public().to_string() {
                return Ok(());
            }
            return Err(StoreError::Key(format!(
                "generation {generation} already exists with a different key"
            )));
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| StoreError::io(&self.dir, e))?;
        self.write_generation(generation, &identity, device)
    }

    fn write_generation(
        &self,
        generation: u32,
        identity: &age::x25519::Identity,
        device: &dyn KeyProvider,
    ) -> StoreResult<()> {
        write_private(
            &self.dir.join(format!("{generation}.pub")),
            identity.to_public().to_string().as_bytes(),
        )?;
        write_private(
            &self.dir.join(format!("{generation}.age")),
            &encrypt_to(device.recipients()?, identity.to_string().expose_secret().as_bytes())?,
        )?;
        self.unwrapped
            .lock()
            .expect("generation key cache poisoned")
            .insert(generation, identity.clone());
        Ok(())
    }

    /// Stable content listing of the keys directory for the authenticated store snapshot.
    /// Public keys and envelopes are integrity-relevant: swapping `<N>.pub` would redirect
    /// future encryption to an attacker recipient.
    pub(crate) fn snapshot_entries(&self) -> StoreResult<Vec<(String, String)>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(StoreError::io(&self.dir, e)),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| StoreError::io(&self.dir, e))?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|e| StoreError::io(&path, e))?;
            let digest: String =
                Sha256::digest(&bytes).iter().map(|byte| format!("{byte:02x}")).collect();
            out.push((name, digest));
        }
        out.sort();
        Ok(out)
    }

    fn read_recipient(&self, name: &str) -> StoreResult<age::x25519::Recipient> {
        let path = self.dir.join(name);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::Key(format!(
                    "store key file {} is missing; the store was not initialized",
                    path.display()
                ))
            } else {
                StoreError::io(&path, e)
            }
        })?;
        age::x25519::Recipient::from_str(text.trim())
            .map_err(|e| StoreError::Key(format!("parse {name}: {e}")))
    }
}

fn encrypt_to(
    recipients: Vec<Box<dyn age::Recipient + Send>>,
    plaintext: &[u8],
) -> StoreResult<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| StoreError::Crypto("no recipients configured".to_string()))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| StoreError::Crypto(format!("wrap: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| StoreError::Crypto(format!("write: {e}")))?;
    writer
        .finish()
        .map_err(|e| StoreError::Crypto(format!("finish: {e}")))?;
    Ok(out)
}

fn decrypt_with(
    ciphertext: &[u8],
    identity: &dyn age::Identity,
) -> StoreResult<Zeroizing<Vec<u8>>> {
    let decryptor = match age::Decryptor::new(ciphertext)
        .map_err(|e| StoreError::Crypto(format!("open envelope: {e}")))?
    {
        age::Decryptor::Recipients(d) => d,
        age::Decryptor::Passphrase(_) => {
            return Err(StoreError::Crypto(
                "key envelope is passphrase-encrypted, expected recipient-encrypted".to_string(),
            ))
        }
    };
    let mut reader = decryptor
        .decrypt(std::iter::once(identity))
        .map_err(|e| StoreError::Crypto(format!("decrypt envelope: {e}")))?;
    let mut out = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut out)
        .map_err(|e| StoreError::Crypto(format!("read envelope: {e}")))?;
    Ok(out)
}
