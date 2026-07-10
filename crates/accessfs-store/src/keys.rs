//! Key material for the store, abstracted behind [`KeyProvider`] so the encryption backend is
//! swappable. Dev uses an existing SSH ed25519 key ([`SshKeyProvider`]); a dedicated age key or a
//! Keychain-wrapped key can slot in later without touching the store.
//!
//! Asymmetry worth noting: encryption needs only the public recipient (cheap, no unlock), so
//! `protect` never touches the private key or a passphrase. Only decryption ([`identity`]) does.

use std::io::BufReader;
use std::path::PathBuf;
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
        accessfs_core::config::check_secure_perms(&self.private_key_path)
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
