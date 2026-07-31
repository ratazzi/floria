use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use floria_core::identity::ProcessIdentity;
use thiserror::Error;

/// Seam used by local Unix-socket servers before they consume any bytes from a client.
pub trait SocketPeerVerifier: Send + Sync + 'static {
    fn verify(&self, stream: &UnixStream) -> Result<VerifiedPeer, PeerVerificationError>;
}

/// Process identity captured from an authenticated socket peer.
#[derive(Debug, Clone)]
pub struct VerifiedPeer {
    pub identity: ProcessIdentity,
}

#[derive(Debug, Error)]
pub enum PeerPolicyError {
    #[error("at least one trusted executable is required")]
    Empty,
    #[error("could not trust executable {path}: {reason}")]
    InvalidExecutable { path: PathBuf, reason: String },
}

#[derive(Debug, Error)]
pub enum PeerVerificationError {
    #[error("could not read Unix peer credentials: {0}")]
    Credentials(#[source] io::Error),
    #[error("peer uid {actual} does not match daemon uid {expected}")]
    DifferentUid { expected: u32, actual: u32 },
    #[error("peer pid is unavailable")]
    MissingPid,
    #[error("could not inspect code signature for peer pid {pid}: {reason}")]
    CodeInspection { pid: i32, reason: String },
    #[error(
        "peer pid {pid} ({executable}) does not satisfy trusted requirements from: {trusted}"
    )]
    UntrustedCode { pid: i32, executable: String, trusted: String },
}

#[derive(Debug)]
struct TrustedRequirement {
    executable: PathBuf,
    text: String,
}

/// Verifies same-user peers against designated requirements extracted from trusted executables.
///
/// Developer ad-hoc signatures produce an exact cdhash requirement; Developer ID signatures
/// produce the stable identifier-and-certificate requirement used across product updates.
pub struct CodeSignedPeerVerifier {
    expected_uid: u32,
    requirements: Vec<TrustedRequirement>,
}

impl CodeSignedPeerVerifier {
    pub fn from_executables(
        executables: impl IntoIterator<Item = impl AsRef<Path>>,
    ) -> Result<Self, PeerPolicyError> {
        let mut requirements = Vec::new();
        for executable in executables {
            let executable = executable.as_ref();
            let path = std::fs::canonicalize(executable).map_err(|error| {
                PeerPolicyError::InvalidExecutable {
                    path: executable.to_path_buf(),
                    reason: error.to_string(),
                }
            })?;
            let text = crate::codesign::designated_requirement(&path).map_err(|reason| {
                PeerPolicyError::InvalidExecutable { path: path.clone(), reason }
            })?;
            if !requirements
                .iter()
                .any(|requirement: &TrustedRequirement| requirement.text == text)
            {
                requirements.push(TrustedRequirement { executable: path, text });
            }
        }
        if requirements.is_empty() {
            return Err(PeerPolicyError::Empty);
        }
        // SAFETY: geteuid has no preconditions.
        let expected_uid = unsafe { libc::geteuid() };
        Ok(Self { expected_uid, requirements })
    }
}

impl SocketPeerVerifier for CodeSignedPeerVerifier {
    fn verify(&self, stream: &UnixStream) -> Result<VerifiedPeer, PeerVerificationError> {
        let credentials = peer_credentials(stream)?;
        if credentials.uid != self.expected_uid {
            return Err(PeerVerificationError::DifferentUid {
                expected: self.expected_uid,
                actual: credentials.uid,
            });
        }
        let pid = credentials.pid.ok_or(PeerVerificationError::MissingPid)?;
        let identity = crate::enrich(pid, credentials.uid, credentials.gid);

        for requirement in &self.requirements {
            match crate::codesign::satisfies_requirement(pid, &requirement.text) {
                Ok(true) => return Ok(VerifiedPeer { identity }),
                Ok(false) => {}
                Err(reason) => {
                    return Err(PeerVerificationError::CodeInspection { pid, reason });
                }
            }
        }

        let executable = identity
            .exe_path
            .as_deref()
            .map(Path::display)
            .map(|path| path.to_string())
            .unwrap_or_else(|| "unknown executable".to_string());
        let trusted = self
            .requirements
            .iter()
            .map(|requirement| requirement.executable.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        Err(PeerVerificationError::UntrustedCode { pid, executable, trusted })
    }
}

/// Explicitly insecure adapter retained for socket protocol tests.
///
/// Production servers must use [`CodeSignedPeerVerifier`].
#[derive(Debug, Default)]
pub struct SameUserPeerVerifier;

impl SocketPeerVerifier for SameUserPeerVerifier {
    fn verify(&self, stream: &UnixStream) -> Result<VerifiedPeer, PeerVerificationError> {
        let credentials = peer_credentials(stream)?;
        // SAFETY: geteuid has no preconditions.
        let expected_uid = unsafe { libc::geteuid() };
        if credentials.uid != expected_uid {
            return Err(PeerVerificationError::DifferentUid {
                expected: expected_uid,
                actual: credentials.uid,
            });
        }
        let identity = match credentials.pid {
            Some(pid) => crate::enrich(pid, credentials.uid, credentials.gid),
            None => ProcessIdentity::bare(-1, credentials.uid, credentials.gid),
        };
        Ok(VerifiedPeer { identity })
    }
}

struct PeerCredentials {
    uid: u32,
    gid: u32,
    pid: Option<i32>,
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, PeerVerificationError> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: valid socket fd and writable stack out-parameters.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(PeerVerificationError::Credentials(
            io::Error::last_os_error(),
        ));
    }

    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: valid socket fd; pid/length describe a correctly sized writable out-parameter.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    };
    let pid = (result == 0 && pid > 0).then_some(pid);
    Ok(PeerCredentials { uid, gid, pid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_current_executable_accepts_current_process() {
        let executable = std::env::current_exe().unwrap();
        let verifier = CodeSignedPeerVerifier::from_executables([executable]).unwrap();
        let (peer, accepted) = UnixStream::pair().unwrap();

        let verified = verifier.verify(&accepted).unwrap();

        assert_eq!(verified.identity.pid, std::process::id() as i32);
        drop(peer);
    }

    #[test]
    fn unrelated_designated_requirement_rejects_current_process() {
        let verifier = CodeSignedPeerVerifier::from_executables(["/bin/ls"]).unwrap();
        let (_peer, accepted) = UnixStream::pair().unwrap();

        let error = verifier.verify(&accepted).unwrap_err();

        assert!(matches!(error, PeerVerificationError::UntrustedCode { .. }));
    }
}
