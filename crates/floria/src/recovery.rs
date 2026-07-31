use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use floria_control::{RecoveryKeyExporter, RecoveryKeyReport};
use floria_core::config::StoreKeySource;
use floria_store::{AgeDirStore, KeychainKeyProvider};
use zeroize::Zeroizing;

/// One runtime recovery boundary shared by the GUI and the existing store implementation.
///
/// The GUI supplies only an absolute destination and a passphrase. This service verifies the
/// active store before exporting the exact key source selected by the daemon, then delegates
/// private-file publication to `floria-store`.
pub(crate) struct RuntimeRecoveryKeyExporter {
    store: Arc<AgeDirStore>,
    key_source: StoreKeySource,
    ssh_key: PathBuf,
}

impl RuntimeRecoveryKeyExporter {
    pub(crate) fn new(
        store: Arc<AgeDirStore>,
        key_source: StoreKeySource,
        ssh_key: PathBuf,
    ) -> Self {
        Self { store, key_source, ssh_key }
    }

    fn private_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        match self.key_source {
            StoreKeySource::Ssh => read_ssh_private_key(&self.ssh_key),
            StoreKeySource::Auto if self.ssh_key.exists() => {
                read_ssh_private_key(&self.ssh_key)
            }
            StoreKeySource::Auto | StoreKeySource::Keychain => {
                KeychainKeyProvider::export_private_key()
                    .context("reading the store key from Keychain")
            }
        }
    }
}

impl RecoveryKeyExporter for RuntimeRecoveryKeyExporter {
    fn export(
        &self,
        destination: &Path,
        passphrase: &str,
    ) -> Result<RecoveryKeyReport, String> {
        let export = || -> Result<RecoveryKeyReport> {
            self.store
                .verify_all()
                .context("verifying every encrypted store version before recovery export")?;
            let private_key = self.private_key()?;
            let path = floria_store::export_recovery_key(
                private_key.as_slice(),
                passphrase,
                destination,
            )
            .with_context(|| {
                format!("exporting recovery key to {}", destination.display())
            })?;
            Ok(RecoveryKeyReport { path })
        };
        export().map_err(|error| format!("{error:#}"))
    }
}

pub(crate) fn read_ssh_private_key(key_path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let data = std::fs::read(key_path)
        .with_context(|| format!("reading ssh private key {}", key_path.display()))?;
    let key = ssh_key::PrivateKey::from_openssh(&data[..])
        .with_context(|| format!("parsing ssh private key {}", key_path.display()))?;
    let key = if key.is_encrypted() {
        let passphrase = std::env::var("FLORIA_KEY_PASSPHRASE").context(
            "the key is passphrase-protected; set FLORIA_KEY_PASSPHRASE for this operation",
        )?;
        let passphrase = Zeroizing::new(passphrase);
        key.decrypt(passphrase.as_bytes())
            .context("decrypting ssh private key (wrong FLORIA_KEY_PASSPHRASE?)")?
    } else {
        key
    };
    let decrypted = key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("re-encoding decrypted ssh private key")?;
    Ok(Zeroizing::new(decrypted.as_bytes().to_vec()))
}
