//! Key material for the store, abstracted behind [`KeyProvider`] so the encryption backend is
//! swappable. Development can use an existing SSH ed25519 key ([`SshKeyProvider`]); installed
//! apps generate a dedicated ed25519 key in the login Keychain.
//!
//! Asymmetry worth noting: encryption needs only the public recipient (cheap, no unlock), so
//! `protect` never touches the private key or a passphrase. Only decryption ([`identity`]) does.

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::Secret;
use zeroize::Zeroizing;

use crate::error::{StoreError, StoreResult};

/// Supplies the age recipient (encrypt) and identity (decrypt). `Send + Sync` because the store is
/// shared across threads; the returned boxes are constructed per-call and used immediately.
pub trait KeyProvider: Send + Sync {
    /// Public recipients used to encrypt. Does not require the private key or a passphrase.
    /// Plural on purpose: leaves room for a recovery recipient / key rotation (encrypt to old+new)
    /// without an on-disk format change. Must be non-empty.
    fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>>;
    /// Private identity used to decrypt.
    fn identity(&self) -> StoreResult<Box<dyn age::Identity>>;
}

/// Encrypt to / decrypt with an OpenSSH ed25519 key pair. age natively supports `ssh-ed25519`.
pub struct SshKeyProvider {
    public_key_path: PathBuf,
    private_key_path: PathBuf,
    /// Passphrase for an encrypted private key. `None` assumes the key is unencrypted.
    passphrase: Option<Zeroizing<String>>,
}

impl SshKeyProvider {
    /// `private_key_path` is e.g. `~/.ssh/id_ed25519`; the public key is `<path>.pub`.
    pub fn new(private_key_path: PathBuf, passphrase: Option<Zeroizing<String>>) -> Self {
        let public_key_path = {
            let mut p = private_key_path.clone().into_os_string();
            p.push(".pub");
            PathBuf::from(p)
        };
        SshKeyProvider {
            public_key_path,
            private_key_path,
            passphrase,
        }
    }
}

impl KeyProvider for SshKeyProvider {
    fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
        let text = std::fs::read_to_string(&self.public_key_path)
            .map_err(|e| StoreError::io(&self.public_key_path, e))?;
        let recipient = age::ssh::Recipient::from_str(text.trim())
            .map_err(|e| StoreError::Key(format!("parse ssh public key: {e:?}")))?;
        Ok(vec![Box::new(recipient)])
    }

    fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
        // The private key must be user-owned and not group/world accessible.
        floria_core::config::check_secure_perms(&self.private_key_path)
            .map_err(|e| StoreError::Key(format!("insecure ssh private key: {e}")))?;
        let data = std::fs::read(&self.private_key_path)
            .map_err(|e| StoreError::io(&self.private_key_path, e))?;
        let identity = age::ssh::Identity::from_buffer(
            BufReader::new(&data[..]),
            Some(self.private_key_path.display().to_string()),
        )
        .map_err(|e| StoreError::Key(format!("parse ssh private key: {e:?}")))?;

        if let age::ssh::Identity::Unsupported(kind) = &identity {
            return Err(StoreError::Key(format!("unsupported ssh key: {kind:?}")));
        }

        match &self.passphrase {
            Some(p) => Ok(Box::new(identity.with_callbacks(PassCallbacks(p.clone())))),
            None => Ok(Box::new(identity)),
        }
    }
}

/// Keychain item coordinates for the store's decryption key. One fixed generic-password item in
/// the user's login keychain holds the *decrypted* OpenSSH ed25519 private key, generated on first
/// installed-app mount or written by `floria keys import`. Reading it needs no passphrase or KDF;
/// macOS gates access per binary signature instead.
pub const KEYCHAIN_SERVICE: &str = "floria.hola.ac.store";
pub const KEYCHAIN_ACCOUNT: &str = "store-ssh-key";

/// Decrypt with the OpenSSH key held in the macOS login Keychain.
///
/// Unlike [`SshKeyProvider`] there is no on-disk private key and no passphrase: `keys import`
/// stores the key already decrypted, and both recipients and identity are derived from that one
/// Keychain item (the `.pub` file is not consulted).
pub struct KeychainKeyProvider;

impl KeychainKeyProvider {
    fn read_key() -> StoreResult<Zeroizing<Vec<u8>>> {
        security_framework::passwords::get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
            .map(Zeroizing::new)
            .map_err(|e| {
                StoreError::Key(format!(
                    "read Keychain item {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT}: {e} \
                     (run `floria keys import` to store the key)"
                ))
            })
    }

    pub fn export_private_key() -> StoreResult<Zeroizing<Vec<u8>>> {
        Self::read_key()
    }

    /// Import a recovery key without ever replacing an unrelated key or orphaning store data.
    pub fn import_recovery_key(private_key: &[u8], store_root: &Path) -> StoreResult<bool> {
        validate_private_key(private_key, "recovery import")?;
        match security_framework::passwords::get_generic_password(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
        ) {
            Ok(existing) => {
                let existing = Zeroizing::new(existing);
                if existing.as_slice() == private_key {
                    Ok(false)
                } else {
                    Err(StoreError::Key(format!(
                        "Keychain item {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT} already contains a \
                         different key; refusing to replace it"
                    )))
                }
            }
            Err(error)
                if error.code() == security_framework_sys::base::errSecItemNotFound =>
            {
                if store_root_has_data(store_root)? {
                    return Err(StoreError::Key(format!(
                        "encrypted store data already exists at {}; import the recovery key \
                         before restoring data",
                        store_root.display()
                    )));
                }
                Self::import(private_key)?;
                Ok(true)
            }
            Err(error) => Err(StoreError::Key(format!(
                "inspect Keychain item {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT}: {error}"
            ))),
        }
    }

    /// Create a dedicated Floria ed25519 key when the Keychain item is genuinely absent.
    ///
    /// Existing encrypted data makes generation fail closed: a replacement key could never
    /// decrypt it. Keychain access errors are also propagated and never mistaken for absence.
    pub fn initialize_if_missing(store_root: &Path) -> StoreResult<bool> {
        match security_framework::passwords::get_generic_password(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
        ) {
            Ok(private_key) => {
                let private_key = Zeroizing::new(private_key);
                parse_identity(&private_key, "keychain")?;
                Ok(false)
            }
            Err(error)
                if error.code() == security_framework_sys::base::errSecItemNotFound =>
            {
                if store_root_has_data(store_root)? {
                    return Err(StoreError::Key(format!(
                        "Keychain item {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT} is missing but \
                         encrypted store data already exists at {}; refusing to generate a \
                         replacement key (restore the original key first)",
                        store_root.display()
                    )));
                }
                let key = ssh_key::PrivateKey::random(
                    &mut ssh_key::rand_core::OsRng,
                    ssh_key::Algorithm::Ed25519,
                )
                .map_err(|error| {
                    StoreError::Key(format!("generate dedicated store key: {error}"))
                })?;
                let private_key =
                    key.to_openssh(ssh_key::LineEnding::LF).map_err(|error| {
                        StoreError::Key(format!("encode dedicated store key: {error}"))
                    })?;
                Self::import(private_key.as_bytes())?;
                Ok(true)
            }
            Err(error) => Err(StoreError::Key(format!(
                "inspect Keychain item {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT}: {error}"
            ))),
        }
    }

    /// Store `private_key` (a *decrypted* OpenSSH private key) in the Keychain, replacing any
    /// previous item. Verifies the material parses as a supported age ssh identity first.
    pub fn import(private_key: &[u8]) -> StoreResult<()> {
        parse_identity(private_key, "keychain import")?;
        security_framework::passwords::set_generic_password(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
            private_key,
        )
        .map_err(|e| {
            StoreError::Key(format!(
                "write Keychain item {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT}: {e}"
            ))
        })
    }
}

fn store_root_has_data(root: &Path) -> StoreResult<bool> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(StoreError::io(root, error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| StoreError::io(root, error))?;
        if entry.file_name() != ".lock" {
            return Ok(true);
        }
    }
    Ok(false)
}

impl KeyProvider for KeychainKeyProvider {
    fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
        let data = Self::read_key()?;
        let key = ssh_key::PrivateKey::from_openssh(&data[..])
            .map_err(|e| StoreError::Key(format!("parse Keychain ssh private key: {e}")))?;
        let public = key
            .public_key()
            .to_openssh()
            .map_err(|e| StoreError::Key(format!("derive ssh public key: {e}")))?;
        let recipient = age::ssh::Recipient::from_str(public.trim())
            .map_err(|e| StoreError::Key(format!("parse derived ssh public key: {e:?}")))?;
        Ok(vec![Box::new(recipient)])
    }

    fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
        let data = Self::read_key()?;
        parse_identity(&data, "keychain")
    }
}

pub(crate) fn validate_private_key(data: &[u8], context: &str) -> StoreResult<()> {
    parse_identity(data, context).map(|_| ())
}

fn parse_identity(data: &[u8], context: &str) -> StoreResult<Box<dyn age::Identity>> {
    let identity = age::ssh::Identity::from_buffer(BufReader::new(data), Some(context.to_string()))
        .map_err(|e| StoreError::Key(format!("parse ssh private key ({context}): {e:?}")))?;
    match &identity {
        age::ssh::Identity::Unsupported(kind) => {
            Err(StoreError::Key(format!("unsupported ssh key ({context}): {kind:?}")))
        }
        age::ssh::Identity::Encrypted(_) => Err(StoreError::Key(format!(
            "ssh key is still passphrase-protected ({context}); import stores it decrypted"
        ))),
        _ => Ok(Box::new(identity)),
    }
}

/// Non-interactive callbacks that answer the private key's passphrase prompt from a preset value.
#[derive(Clone)]
struct PassCallbacks(Zeroizing<String>);

impl age::Callbacks for PassCallbacks {
    fn display_message(&self, _message: &str) {}

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, _description: &str) -> Option<Secret<String>> {
        Some(Secret::new(self.0.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_lock_only_store_is_safe_for_first_key_generation() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        assert!(!store_root_has_data(&missing).unwrap());

        let root = directory.path().join("store");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join(".lock"), b"").unwrap();
        assert!(!store_root_has_data(&root).unwrap());
    }

    #[test]
    fn any_store_payload_prevents_replacement_key_generation() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("encrypted-entry"), b"ciphertext").unwrap();

        assert!(store_root_has_data(directory.path()).unwrap());
    }
}
