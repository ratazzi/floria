use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{ReplicationError, ReplicationResult};

/// Validate one untrusted ciphertext asset without loading it into memory.
pub(crate) fn verify_object_file(
    path: &Path,
    expected_digest: &str,
    expected_size: u64,
) -> ReplicationResult<()> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| ReplicationError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| ReplicationError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(ReplicationError::Invalid(format!(
            "replication object {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() != expected_size {
        return Err(ReplicationError::Invalid(format!(
            "replication object {expected_digest} has {} bytes, expected {expected_size}",
            metadata.len()
        )));
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| ReplicationError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual_digest = format!("{:x}", hasher.finalize());
    if actual_digest != expected_digest {
        return Err(ReplicationError::Invalid(format!(
            "replication object {} has digest {actual_digest}, expected {expected_digest}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn verifies_regular_file_size_and_digest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.age");
        let bytes = b"encrypted fixture bytes";
        std::fs::write(&path, bytes).unwrap();
        let digest = format!("{:x}", Sha256::digest(bytes));

        verify_object_file(&path, &digest, bytes.len() as u64).unwrap();
        assert!(verify_object_file(&path, &digest, bytes.len() as u64 + 1).is_err());
        assert!(verify_object_file(&path, &"0".repeat(64), bytes.len() as u64).is_err());
    }

    #[test]
    fn rejects_symlinks_even_when_the_target_matches() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.age");
        let link = directory.path().join("link.age");
        let bytes = b"encrypted fixture bytes";
        std::fs::write(&target, bytes).unwrap();
        symlink(&target, &link).unwrap();
        let digest = format!("{:x}", Sha256::digest(bytes));

        assert!(verify_object_file(&link, &digest, bytes.len() as u64).is_err());
    }
}
