use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use floria_catalog::Catalog;
use floria_control::{
    HealthCheck, HealthReport, HealthStatus, RuntimeHealthReporter,
};
use floria_store::{KeyProvider, SecretStore};

use crate::exact_mount;

const MACFUSE_PATH: &str = "/Library/Filesystems/macfuse.fs";
const DISK_WARNING_BYTES: u64 = 1024 * 1024 * 1024;
const DISK_ERROR_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) struct RuntimeHealth {
    catalog: Catalog,
    store: Arc<dyn SecretStore>,
    keys: Arc<dyn KeyProvider>,
    mount_path: PathBuf,
    data_path: PathBuf,
}

impl RuntimeHealth {
    pub(crate) fn new(
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        keys: Arc<dyn KeyProvider>,
        mount_path: PathBuf,
        data_path: PathBuf,
    ) -> Self {
        RuntimeHealth {
            catalog,
            store,
            keys,
            mount_path,
            data_path,
        }
    }

    fn checks(&self) -> Vec<HealthCheck> {
        vec![
            macfuse_check(),
            key_check(self.keys.as_ref()),
            catalog_check(&self.catalog),
            store_check(self.store.as_ref()),
            disk_check(available_bytes(&self.data_path)),
            mount_check(&self.mount_path),
        ]
    }
}

impl RuntimeHealthReporter for RuntimeHealth {
    fn report(&self) -> HealthReport {
        HealthReport::new(self.checks())
    }
}

fn macfuse_check() -> HealthCheck {
    if Path::new(MACFUSE_PATH).exists() {
        healthy("macfuse", "macFUSE", "Installed")
    } else {
        error(
            "macfuse",
            "macFUSE",
            "macFUSE is not installed.",
            "Install macFUSE, approve its system extension, then restart Floria.",
        )
    }
}

fn key_check(keys: &dyn KeyProvider) -> HealthCheck {
    if keys.recipients().is_ok() && keys.identity().is_ok() {
        healthy("key", "Encryption key", "Available")
    } else {
        error(
            "key",
            "Encryption key",
            "Floria cannot access its encryption key.",
            "Unlock the login Keychain or restore the configured SSH key, then refresh.",
        )
    }
}

fn catalog_check(catalog: &Catalog) -> HealthCheck {
    if catalog.verify_integrity().is_ok() {
        healthy("catalog", "Library", "Catalog is healthy")
    } else {
        error(
            "catalog",
            "Library",
            "The catalog failed its integrity check.",
            "Run `floria doctor`; restore a verified backup if the catalog is damaged.",
        )
    }
}

fn store_check(store: &dyn SecretStore) -> HealthCheck {
    if store.list().is_ok() {
        healthy("store", "Encrypted storage", "Metadata is healthy")
    } else {
        error(
            "store",
            "Encrypted storage",
            "Encrypted item metadata could not be read.",
            "Run `floria doctor`; restore a verified backup if storage is damaged.",
        )
    }
}

fn disk_check(available: io::Result<u64>) -> HealthCheck {
    match available {
        Ok(bytes) if bytes < DISK_ERROR_BYTES => error(
            "disk",
            "Storage space",
            &format!("Only {} available.", format_bytes(bytes)),
            "Free disk space before protecting or updating more files.",
        ),
        Ok(bytes) if bytes < DISK_WARNING_BYTES => HealthCheck {
            id: "disk".to_string(),
            status: HealthStatus::Warning,
            title: "Storage space".to_string(),
            message: format!("{} available.", format_bytes(bytes)),
            guidance: Some(
                "Free disk space soon so encrypted updates and backups can complete.".to_string(),
            ),
        },
        Ok(bytes) => healthy(
            "disk",
            "Storage space",
            &format!("{} available", format_bytes(bytes)),
        ),
        Err(_) => error(
            "disk",
            "Storage space",
            "Available disk space could not be checked.",
            "Run `floria doctor` for details.",
        ),
    }
}

fn mount_check(path: &Path) -> HealthCheck {
    match exact_mount(path) {
        Ok(Some(mount)) if mount.is_floria() => {
            healthy("mount", "Protected filesystem", "Mounted")
        }
        Ok(Some(_)) => error(
            "mount",
            "Protected filesystem",
            "The mount path is occupied by another filesystem.",
            "Quit Floria, unmount the conflicting filesystem, then reopen Floria.",
        ),
        Ok(None) => error(
            "mount",
            "Protected filesystem",
            "The protected filesystem is not mounted.",
            "Restart Floria. If it remains offline, run `floria doctor`.",
        ),
        Err(_) => error(
            "mount",
            "Protected filesystem",
            "The mount state could not be checked.",
            "Run `floria doctor` for details.",
        ),
    }
}

fn available_bytes(path: &Path) -> io::Result<u64> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    Ok(u64::from(stats.f_bavail).saturating_mul(stats.f_frsize))
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024 * 1024 * 1024) as f64)
    } else {
        format!("{} MB", bytes / (1024 * 1024))
    }
}

fn healthy(id: &str, title: &str, message: &str) -> HealthCheck {
    HealthCheck {
        id: id.to_string(),
        status: HealthStatus::Healthy,
        title: title.to_string(),
        message: message.to_string(),
        guidance: None,
    }
}

fn error(id: &str, title: &str, message: &str, guidance: &str) -> HealthCheck {
    HealthCheck {
        id: id.to_string(),
        status: HealthStatus::Error,
        title: title.to_string(),
        message: message.to_string(),
        guidance: Some(guidance.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_disk_space_has_two_actionable_severities() {
        assert_eq!(
            disk_check(Ok(DISK_ERROR_BYTES - 1)).status,
            HealthStatus::Error
        );
        assert_eq!(
            disk_check(Ok(DISK_WARNING_BYTES - 1)).status,
            HealthStatus::Warning
        );
        assert_eq!(
            disk_check(Ok(DISK_WARNING_BYTES)).status,
            HealthStatus::Healthy
        );
    }

    #[test]
    fn disk_messages_use_human_scale_without_paths() {
        let check = disk_check(Ok(1536 * 1024 * 1024));
        assert_eq!(check.message, "1.5 GB available");
        assert!(check.guidance.is_none());
    }
}
