use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use accessfs_core::authz::{
    Enforcement, PolicyEvaluation, PolicyMode, PolicyModeStatus,
};

/// Persistent daemon-wide policy state. Callers see one small interface while expiry,
/// normalization, atomic persistence, and enforcement projection remain local to this module.
pub struct PolicyModeState {
    path: PathBuf,
    status: Mutex<PolicyModeStatus>,
}

impl PolicyModeState {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let status = load(&path).unwrap_or_else(|error| {
            tracing::warn!(path = %path.display(), %error, "loading policy mode failed; using normal mode");
            PolicyModeStatus::default()
        });
        let state = PolicyModeState { path, status: Mutex::new(status) };
        // An expired persisted override must never survive a daemon restart.
        let _ = state.status();
        state
    }

    pub fn status(&self) -> PolicyModeStatus {
        let mut status = self.status.lock().expect("policy mode poisoned");
        if is_expired(*status) {
            *status = PolicyModeStatus::default();
            if let Err(error) = persist(&self.path, *status) {
                tracing::warn!(path = %self.path.display(), %error, "persisting expired policy mode failed");
            }
        }
        *status
    }

    pub fn set(
        &self,
        mode: PolicyMode,
        duration_secs: Option<u64>,
    ) -> io::Result<PolicyModeStatus> {
        let expires_at = match (mode, duration_secs) {
            (PolicyMode::Normal, None) => None,
            (PolicyMode::Normal, Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "normal mode cannot have a duration",
                ));
            }
            (PolicyMode::AuditOnly, Some(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "audit-only duration must be greater than zero",
                ));
            }
            (PolicyMode::AuditOnly, Some(seconds)) => Some(
                now_unix()
                    .checked_add(i64::try_from(seconds).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "duration is too large")
                    })?)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "expiry overflows timestamp")
                    })?,
            ),
            (PolicyMode::AuditOnly, None) => None,
        };
        let next = PolicyModeStatus { mode, expires_at };
        let mut current = self.status.lock().expect("policy mode poisoned");
        persist(&self.path, next)?;
        *current = next;
        Ok(next)
    }

    pub fn evaluate(&self, configured: Enforcement) -> PolicyEvaluation {
        let status = self.status();
        let effective = match (status.mode, configured) {
            (PolicyMode::AuditOnly, Enforcement::Prompt | Enforcement::TouchId) => {
                Enforcement::Allow
            }
            _ => configured,
        };
        PolicyEvaluation {
            configured_enforcement: configured,
            effective_enforcement: effective,
            mode: status.mode,
        }
    }
}

fn load(path: &Path) -> io::Result<PolicyModeStatus> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(PolicyModeStatus::default()),
        Err(error) => Err(error),
    }
}

fn persist(path: &Path, status: PolicyModeStatus) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("json.tmp");
    let body = serde_json::to_vec(&status)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&body)?;
    file.sync_all()?;
    fs::rename(&temporary, path)
}

fn is_expired(status: PolicyModeStatus) -> bool {
    status.expires_at.is_some_and(|expiry| expiry <= now_unix())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_only_relaxes_interaction_but_preserves_explicit_deny() {
        let dir = tempfile::tempdir().unwrap();
        let state = PolicyModeState::open(dir.path().join("policy-mode.json"));
        state.set(PolicyMode::AuditOnly, None).unwrap();

        assert_eq!(
            state.evaluate(Enforcement::TouchId).effective_enforcement,
            Enforcement::Allow
        );
        assert_eq!(
            state.evaluate(Enforcement::Prompt).effective_enforcement,
            Enforcement::Allow
        );
        assert_eq!(
            state.evaluate(Enforcement::Deny).effective_enforcement,
            Enforcement::Deny
        );
    }

    #[test]
    fn setting_a_mode_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy-mode.json");
        let state = PolicyModeState::open(&path);
        let set = state.set(PolicyMode::AuditOnly, Some(3600)).unwrap();

        assert_eq!(PolicyModeState::open(path).status(), set);
        assert_eq!(
            fs::metadata(dir.path().join("policy-mode.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn expired_persisted_override_returns_to_normal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy-mode.json");
        persist(
            &path,
            PolicyModeStatus { mode: PolicyMode::AuditOnly, expires_at: Some(1) },
        )
        .unwrap();

        assert_eq!(PolicyModeState::open(path).status(), PolicyModeStatus::default());
    }
}
