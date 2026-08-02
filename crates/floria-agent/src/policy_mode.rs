use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use floria_core::authz::{
    Enforcement, PolicyEvaluation, PolicyMode, PolicyModeStatus,
};
use floria_integrity::StateAuthenticator;

const INTEGRITY_DOMAIN: &str = "global-policy-mode";

/// Persistent daemon-wide policy state. Callers see one small interface while expiry,
/// normalization, atomic persistence, and enforcement projection remain local to this module.
pub struct PolicyModeState {
    path: PathBuf,
    authenticator: Arc<StateAuthenticator>,
    generation: Mutex<u64>,
    status: Mutex<PolicyModeStatus>,
}

impl PolicyModeState {
    pub fn open(
        path: impl Into<PathBuf>,
        authenticator: Arc<StateAuthenticator>,
    ) -> Self {
        let path = path.into();
        let loaded = authenticator.load::<PolicyModeStatus>(&path, INTEGRITY_DOMAIN);
        let (status, generation) = match loaded {
            Ok(loaded) => (loaded.value.unwrap_or_default(), loaded.generation),
            Err(error) => {
                tracing::error!(
                    path = %path.display(),
                    %error,
                    "policy mode integrity verification failed; failing closed to normal mode"
                );
                let generation = authenticator
                    .checkpoint_generation(INTEGRITY_DOMAIN)
                    .unwrap_or_default();
                (PolicyModeStatus::default(), generation)
            }
        };
        let state = PolicyModeState {
            path,
            authenticator,
            generation: Mutex::new(generation),
            status: Mutex::new(status),
        };
        // An expired persisted override must never survive a daemon restart.
        let _ = state.status();
        state
    }

    pub fn status(&self) -> PolicyModeStatus {
        let mut status = self.status.lock().expect("policy mode poisoned");
        if is_expired(*status) {
            *status = PolicyModeStatus::default();
            if let Err(error) = self.persist(*status) {
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
        self.persist(next)?;
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

    fn persist(&self, status: PolicyModeStatus) -> io::Result<()> {
        let mut generation = self.generation.lock().expect("policy mode generation poisoned");
        *generation = self
            .authenticator
            .persist(&self.path, INTEGRITY_DOMAIN, *generation, &status)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(())
    }
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
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn authenticator() -> Arc<StateAuthenticator> {
        Arc::new(StateAuthenticator::for_tests([23; 32]))
    }

    #[test]
    fn audit_only_relaxes_interaction_but_preserves_explicit_deny() {
        let dir = tempfile::tempdir().unwrap();
        let state = PolicyModeState::open(dir.path().join("policy-mode.json"), authenticator());
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
        let auth = authenticator();
        let state = PolicyModeState::open(&path, Arc::clone(&auth));
        let set = state.set(PolicyMode::AuditOnly, Some(3600)).unwrap();

        assert_eq!(PolicyModeState::open(path, auth).status(), set);
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
        let auth = authenticator();
        auth.persist(
            &path,
            INTEGRITY_DOMAIN,
            0,
            &PolicyModeStatus { mode: PolicyMode::AuditOnly, expires_at: Some(1) },
        ).unwrap();

        assert_eq!(PolicyModeState::open(path, auth).status(), PolicyModeStatus::default());
    }
}
