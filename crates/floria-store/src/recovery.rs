//! Password-encrypted export for the store's private key.
//!
//! A ciphertext backup without its decryption key is not a disaster-recovery artifact. This
//! module creates a separate age/scrypt envelope that users can store alongside (or separately
//! from) a Floria backup. Plaintext key bytes stay in zeroizing memory.

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use age::secrecy::Secret;
use zeroize::Zeroizing;

use crate::error::{StoreError, StoreResult};
use crate::keys::validate_private_key;

const RECOVERY_MAGIC: &[u8] = b"FLORIA-STORE-RECOVERY-KEY\0";
const RECOVERY_FORMAT: u8 = 1;
const MINIMUM_PASSPHRASE_CHARACTERS: usize = 12;

/// Export one OpenSSH private key through an age passphrase envelope.
///
/// The destination parent must exist and the destination is never overwritten.
pub fn export_recovery_key(
    private_key: &[u8],
    passphrase: &str,
    destination: &Path,
) -> StoreResult<PathBuf> {
    validate_passphrase(passphrase)?;
    validate_private_key(private_key, "recovery export")?;
    let destination = normalized_new_destination(destination)?;
    if destination.exists() {
        return Err(StoreError::Invalid(format!(
            "recovery key destination already exists: {}",
            destination.display()
        )));
    }

    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        RECOVERY_MAGIC.len() + 1 + private_key.len(),
    ));
    plaintext.extend_from_slice(RECOVERY_MAGIC);
    plaintext.push(RECOVERY_FORMAT);
    plaintext.extend_from_slice(private_key);

    let encryptor =
        age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_string()));
    let mut ciphertext = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|error| StoreError::Crypto(format!("create recovery envelope: {error}")))?;
        writer
            .write_all(&plaintext)
            .map_err(|error| StoreError::io(&destination, error))?;
        writer
            .finish()
            .map_err(|error| StoreError::Crypto(format!("finish recovery envelope: {error}")))?;
    }
    publish_private_file(&destination, &ciphertext)?;
    Ok(destination)
}

/// Decrypt and validate one recovery-key file.
pub fn decrypt_recovery_key(source: &Path, passphrase: &str) -> StoreResult<Zeroizing<Vec<u8>>> {
    validate_passphrase(passphrase)?;
    let ciphertext = std::fs::read(source).map_err(|error| StoreError::io(source, error))?;
    let decryptor = match age::Decryptor::new(&ciphertext[..])
        .map_err(|error| StoreError::Crypto(format!("open recovery envelope: {error}")))?
    {
        age::Decryptor::Passphrase(decryptor) => decryptor,
        age::Decryptor::Recipients(_) => {
            return Err(StoreError::Invalid(
                "recovery key is not protected by a passphrase".to_string(),
            ))
        }
    };
    let mut reader = decryptor
        .decrypt(&Secret::new(passphrase.to_string()), None)
        .map_err(|error| {
            StoreError::Crypto(format!("decrypt recovery key (wrong passphrase?): {error}"))
        })?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|error| StoreError::io(source, error))?;
    let prefix_length = RECOVERY_MAGIC.len() + 1;
    if plaintext.len() <= prefix_length
        || !plaintext.starts_with(RECOVERY_MAGIC)
        || plaintext[RECOVERY_MAGIC.len()] != RECOVERY_FORMAT
    {
        return Err(StoreError::Invalid(
            "recovery key has an unsupported or invalid Floria format".to_string(),
        ));
    }
    let private_key = Zeroizing::new(plaintext[prefix_length..].to_vec());
    validate_private_key(&private_key, "recovery import")?;
    Ok(private_key)
}

fn validate_passphrase(passphrase: &str) -> StoreResult<()> {
    if passphrase.chars().count() < MINIMUM_PASSPHRASE_CHARACTERS {
        Err(StoreError::Invalid(format!(
            "recovery passphrase must contain at least {MINIMUM_PASSPHRASE_CHARACTERS} characters"
        )))
    } else {
        Ok(())
    }
}

fn normalized_new_destination(destination: &Path) -> StoreResult<PathBuf> {
    let name = destination.file_name().ok_or_else(|| {
        StoreError::Invalid(format!(
            "recovery key destination must name a new file: {}",
            destination.display()
        ))
    })?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|error| StoreError::io(parent, error))?;
    Ok(parent.join(name))
}

fn publish_private_file(destination: &Path, bytes: &[u8]) -> StoreResult<()> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination.file_name().and_then(|name| name.to_str()).unwrap_or("recovery-key");
    for attempt in 0..100u32 {
        let temporary =
            parent.join(format!(".{name}.floria-tmp-{}-{attempt}", std::process::id()));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StoreError::io(&temporary, error)),
        };
        let result = (|| {
            file.write_all(bytes).map_err(|error| StoreError::io(&temporary, error))?;
            file.sync_all().map_err(|error| StoreError::io(&temporary, error))?;
            rename_without_overwrite(&temporary, destination)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        return result;
    }
    Err(StoreError::Invalid(
        "could not allocate a temporary recovery-key file".to_string(),
    ))
}

fn rename_without_overwrite(source: &Path, destination: &Path) -> StoreResult<()> {
    let source_c = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| StoreError::Invalid(format!("path contains NUL: {}", source.display())))?;
    let destination_c = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        StoreError::Invalid(format!("path contains NUL: {}", destination.display()))
    })?;
    // SAFETY: both C strings are valid and remain alive for the call. RENAME_EXCL atomically
    // refuses a destination created after our initial check.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source_c.as_ptr(),
            libc::AT_FDCWD,
            destination_c.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(StoreError::io(destination, std::io::Error::last_os_error()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};

    fn private_key() -> Zeroizing<String> {
        PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap()
    }

    #[test]
    fn recovery_key_round_trips_without_plaintext_on_disk() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("recovery-key.age");
        let private_key = private_key();

        let published =
            export_recovery_key(private_key.as_bytes(), "fixture passphrase", &destination)
                .unwrap();
        let recovered = decrypt_recovery_key(&destination, "fixture passphrase").unwrap();

        assert_eq!(published, std::fs::canonicalize(&destination).unwrap());
        assert_eq!(&recovered[..], private_key.as_bytes());
        let ciphertext = std::fs::read(&destination).unwrap();
        assert!(!ciphertext
            .windows(b"OPENSSH PRIVATE KEY".len())
            .any(|window| window == b"OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn wrong_passphrase_and_short_passphrases_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("recovery-key.age");
        let private_key = private_key();
        export_recovery_key(private_key.as_bytes(), "fixture passphrase", &destination).unwrap();

        assert!(decrypt_recovery_key(&destination, "different passphrase").is_err());
        assert!(export_recovery_key(
            private_key.as_bytes(),
            "too short",
            &directory.path().join("other.age")
        )
        .is_err());
    }

    #[test]
    fn recovery_export_never_overwrites_an_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("recovery-key.age");
        std::fs::write(&destination, b"keep").unwrap();
        let private_key = private_key();

        let error =
            export_recovery_key(private_key.as_bytes(), "fixture passphrase", &destination)
                .unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(std::fs::read(&destination).unwrap(), b"keep");
    }
}
