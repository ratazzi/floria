use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authz::PolicyEvaluation;
use crate::error::Result;
use crate::identity::ProcessIdentity;

/// Append-only JSONL audit log. Flushed line by line so no already-written event is lost even if the process is killed.
pub struct AuditLog {
    writer: Mutex<AuditWriter>,
    authority: Option<Arc<dyn AuditAuthority>>,
    checkpoint_worker: Option<CheckpointWorker>,
    health: Arc<Mutex<Option<String>>>,
    path: PathBuf,
}

const AUDIT_FORMAT: u32 = 1;
const GENESIS_HASH: &str = "genesis";
#[cfg(not(test))]
const AUDIT_CHECKPOINT_MAX_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
const AUDIT_CHECKPOINT_MAX_DELAY: Duration = Duration::from_secs(60);

/// Authenticated tail of one append-only audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub sequence: u64,
    pub head: String,
    pub file_size: u64,
}

/// The platform-owned authority for event HMACs and the anti-rollback tail checkpoint.
///
/// Core owns chain semantics; the application adapter owns Keychain access and checkpoint
/// persistence. This keeps the authorization/filesystem spine independent of macOS storage APIs.
pub trait AuditAuthority: Send + Sync {
    fn load_checkpoint(&self) -> std::io::Result<Option<AuditCheckpoint>>;
    fn authenticate(&self, payload: &[u8]) -> std::io::Result<String>;
    fn verify(&self, payload: &[u8], tag: &str) -> std::io::Result<()>;
    fn persist_checkpoint(&self, checkpoint: &AuditCheckpoint) -> std::io::Result<()>;
}

struct AuditWriter {
    output: BufWriter<File>,
    sequence: u64,
    head: String,
    file_size: u64,
    stamp: FileStamp,
}

enum CheckpointCommand {
    Update(AuditCheckpoint),
    Flush(AuditCheckpoint, mpsc::SyncSender<std::io::Result<()>>),
    Shutdown(mpsc::SyncSender<std::io::Result<()>>),
}

struct CheckpointWorker {
    sender: mpsc::Sender<CheckpointCommand>,
    join: Option<JoinHandle<()>>,
}

impl CheckpointWorker {
    fn start(
        authority: Arc<dyn AuditAuthority>,
        durable: AuditCheckpoint,
        health: Arc<Mutex<Option<String>>>,
    ) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let join = std::thread::Builder::new()
            .name("floria-audit-checkpoint".to_string())
            .spawn(move || checkpoint_worker_loop(receiver, authority, durable, health))?;
        Ok(Self {
            sender,
            join: Some(join),
        })
    }

    fn update(&self, checkpoint: AuditCheckpoint) -> std::io::Result<()> {
        self.sender
            .send(CheckpointCommand::Update(checkpoint))
            .map_err(|_| std::io::Error::other("audit checkpoint worker stopped"))
    }

    fn flush(&self, checkpoint: AuditCheckpoint) -> std::io::Result<()> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .send(CheckpointCommand::Flush(checkpoint, reply))
            .map_err(|_| std::io::Error::other("audit checkpoint worker stopped"))?;
        response
            .recv()
            .map_err(|_| std::io::Error::other("audit checkpoint worker stopped"))?
    }

    fn shutdown(&mut self) -> std::io::Result<()> {
        let (reply, response) = mpsc::sync_channel(1);
        let result = match self.sender.send(CheckpointCommand::Shutdown(reply)) {
            Ok(()) => response
                .recv()
                .map_err(|_| std::io::Error::other("audit checkpoint worker stopped"))?,
            Err(_) => Err(std::io::Error::other("audit checkpoint worker stopped")),
        };
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        result
    }
}

fn checkpoint_worker_loop(
    receiver: mpsc::Receiver<CheckpointCommand>,
    authority: Arc<dyn AuditAuthority>,
    mut durable: AuditCheckpoint,
    health: Arc<Mutex<Option<String>>>,
) {
    let mut pending: Option<AuditCheckpoint> = None;
    let mut deadline: Option<Instant> = None;

    loop {
        let command = match deadline {
            Some(at) => match receiver.recv_timeout(at.saturating_duration_since(Instant::now())) {
                Ok(command) => Some(command),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if let Some(checkpoint) = pending.take() {
                        if let Err(error) =
                            persist_newer_checkpoint(authority.as_ref(), &mut durable, checkpoint)
                        {
                            mark_degraded(&health, &error);
                        }
                    }
                    break;
                }
            },
            None => match receiver.recv() {
                Ok(command) => Some(command),
                Err(_) => break,
            },
        };

        match command {
            Some(CheckpointCommand::Update(checkpoint)) => {
                pending = Some(checkpoint);
                if deadline.is_none() {
                    deadline = Some(Instant::now() + AUDIT_CHECKPOINT_MAX_DELAY);
                }
            }
            Some(CheckpointCommand::Flush(checkpoint, reply)) => {
                let result = persist_newer_checkpoint(authority.as_ref(), &mut durable, checkpoint);
                if let Err(error) = &result {
                    mark_degraded(&health, error);
                }
                pending = pending.filter(|candidate| candidate.sequence > durable.sequence);
                deadline = pending
                    .as_ref()
                    .map(|_| Instant::now() + AUDIT_CHECKPOINT_MAX_DELAY);
                let failed = result.is_err();
                let _ = reply.send(result);
                if failed {
                    break;
                }
            }
            Some(CheckpointCommand::Shutdown(reply)) => {
                let result = match pending.take() {
                    Some(checkpoint) => {
                        persist_newer_checkpoint(authority.as_ref(), &mut durable, checkpoint)
                    }
                    None => Ok(()),
                };
                if let Err(error) = &result {
                    mark_degraded(&health, error);
                }
                let _ = reply.send(result);
                break;
            }
            None => {
                if let Some(checkpoint) = pending.take() {
                    if let Err(error) =
                        persist_newer_checkpoint(authority.as_ref(), &mut durable, checkpoint)
                    {
                        mark_degraded(&health, &error);
                        break;
                    }
                }
                deadline = None;
            }
        }
    }
}

fn persist_newer_checkpoint(
    authority: &dyn AuditAuthority,
    durable: &mut AuditCheckpoint,
    checkpoint: AuditCheckpoint,
) -> std::io::Result<()> {
    if checkpoint.sequence < durable.sequence {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit checkpoint worker refused to move backwards",
        ));
    }
    if checkpoint == *durable {
        return Ok(());
    }
    if checkpoint.sequence == durable.sequence {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit checkpoint sequence has conflicting authenticated tails",
        ));
    }
    authority.persist_checkpoint(&checkpoint)?;
    *durable = checkpoint;
    Ok(())
}

fn mark_degraded(health: &Mutex<Option<String>>, error: &std::io::Error) {
    if let Ok(mut degraded) = health.lock() {
        if degraded.is_none() {
            *degraded = Some(error.to_string());
        }
    }
    tracing::error!(%error, "audit checkpoint failed; future allowed access will fail closed");
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    size: u64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Serialize, Deserialize)]
struct AuditEnvelope {
    format: u32,
    sequence: u64,
    previous: String,
    event: serde_json::Value,
    tag: String,
}

/// Metadata-only provenance for one rendered surface export. Secret ids and immutable version
/// numbers are safe to audit; plaintext values never enter this structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditDependency {
    pub key: String,
    pub binding_id: String,
    pub resource_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

/// Public destination context for one SSH signing event. The requested name is display-only;
/// the host-key fingerprint and forwarding count come from a verified OpenSSH session binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SshSessionAudit<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_destination: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_host_key_fingerprint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_user: Option<&'a str>,
    pub forwarding_hops: usize,
}

/// One persisted authorization event projected from the append-only JSONL log.
///
/// Close and write-commit rows intentionally do not deserialize into this shape because they
/// carry no reader identity. Callers receive only the events meaningful to access-history UI.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditAccessRecord {
    pub ts: String,
    pub event: String,
    pub path: String,
    pub operation: String,
    pub decision: String,
    pub rule_id: Option<String>,
    pub policy: Option<PolicyEvaluation>,
    pub identity: ProcessIdentity,
    pub surface_id: Option<String>,
    pub resource_id: Option<String>,
    pub key_fingerprint: Option<String>,
    pub key_label: Option<String>,
    pub identity_source: Option<String>,
    pub ssh_session: Option<OwnedSshSessionAudit>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OwnedSshSessionAudit {
    pub requested_destination: Option<String>,
    pub verified_host_key_fingerprint: Option<String>,
    pub ssh_user: Option<String>,
    #[serde(default)]
    pub forwarding_hops: usize,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_authority(path, None)
    }

    pub fn open_authenticated(path: &Path, authority: Arc<dyn AuditAuthority>) -> Result<Self> {
        Self::open_with_authority(path, Some(authority))
    }

    fn open_with_authority(
        path: &Path,
        authority: Option<Arc<dyn AuditAuthority>>,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let checkpoint = match &authority {
            Some(authority) => authority.load_checkpoint()?,
            None => None,
        };
        if authority.is_some()
            && checkpoint.is_none()
            && path.exists()
            && path.metadata()?.len() != 0
        {
            let quarantine = unverified_audit_path(path);
            std::fs::rename(path, &quarantine)?;
            tracing::warn!(
                audit = %path.display(),
                quarantine = %quarantine.display(),
                "moved legacy audit log aside before starting an authenticated chain"
            );
        }

        let tail = if path.exists() {
            verify_audit_chain(path, authority.as_deref(), checkpoint.as_ref())?
        } else {
            AuditCheckpoint {
                sequence: 0,
                head: GENESIS_HASH.to_string(),
                file_size: 0,
            }
        };
        if let Some(authority) = &authority {
            if checkpoint.as_ref() != Some(&tail) {
                authority.persist_checkpoint(&tail)?;
            }
        }

        let file = open_private_append(path)?;
        let stamp = file_stamp(&file.metadata()?);
        let health = Arc::new(Mutex::new(None));
        let checkpoint_worker = match &authority {
            Some(authority) => Some(CheckpointWorker::start(
                authority.clone(),
                tail.clone(),
                health.clone(),
            )?),
            None => None,
        };
        Ok(AuditLog {
            writer: Mutex::new(AuditWriter {
                output: BufWriter::new(file),
                sequence: tail.sequence,
                head: tail.head,
                file_size: tail.file_size,
                stamp,
            }),
            authority,
            checkpoint_worker,
            health,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn ensure_healthy(&self) -> std::io::Result<()> {
        self.check_health()?;
        let writer = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("audit writer lock poisoned"))?;
        validate_writer_file(&self.path, &writer)?;
        self.check_health()
    }

    /// Read access history only after verifying the exact bytes against the live chain and
    /// authenticated tail. Keeping this on `AuditLog` prevents control-plane readers from
    /// accidentally treating the JSONL encoding as trusted state by itself.
    pub fn read_recent_verified(&self, limit: usize) -> std::io::Result<Vec<AuditAccessRecord>> {
        self.check_health()?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("audit writer lock poisoned"))?;

        let verified = (|| {
            writer.output.flush()?;
            validate_writer_file(&self.path, &writer)?;
            let expected = AuditCheckpoint {
                sequence: writer.sequence,
                head: writer.head.clone(),
                file_size: writer.file_size,
            };
            if let Some(authority) = &self.authority {
                self.checkpoint_worker
                    .as_ref()
                    .ok_or_else(|| std::io::Error::other("audit checkpoint worker is missing"))?
                    .flush(expected.clone())?;
                if authority.load_checkpoint()?.as_ref() != Some(&expected) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "audit writer tail does not match its authenticated checkpoint",
                    ));
                }
            }

            let mut input = writer.output.get_ref().try_clone()?;
            input.seek(SeekFrom::Start(0))?;
            let (tail, records) =
                read_verified_access_chain(&mut input, self.authority.as_deref(), None, limit)?;
            if tail != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "audit history does not match the live writer tail",
                ));
            }
            validate_writer_file(&self.path, &writer)?;
            Ok(records)
        })();

        if let Err(error) = &verified {
            mark_degraded(&self.health, error);
        }
        verified
    }

    fn write(&self, value: &impl Serialize) -> std::io::Result<()> {
        self.check_health()?;
        let event = serde_json::to_value(value).map_err(std::io::Error::other)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("audit writer lock poisoned"))?;
        self.check_health()?;
        if let Err(error) = validate_writer_file(&self.path, &writer) {
            mark_degraded(&self.health, &error);
            return Err(error);
        }

        let sequence = writer.sequence.checked_add(1).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "audit sequence overflow")
        })?;
        let payload = chain_payload(sequence, &writer.head, &event)?;
        let tag = match &self.authority {
            Some(authority) => authority.authenticate(&payload)?,
            None => sha256_tag(&payload),
        };
        let envelope = AuditEnvelope {
            format: AUDIT_FORMAT,
            sequence,
            previous: writer.head.clone(),
            event,
            tag: tag.clone(),
        };
        let mut line = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
        line.push(b'\n');

        let attempted = (|| -> std::io::Result<()> {
            writer.output.write_all(&line)?;
            writer.output.flush()?;
            let checkpoint = AuditCheckpoint {
                sequence,
                head: tag,
                file_size: writer.file_size.saturating_add(line.len() as u64),
            };
            writer.sequence = checkpoint.sequence;
            writer.head = checkpoint.head.clone();
            writer.file_size = checkpoint.file_size;
            writer.stamp = file_stamp(&writer.output.get_ref().metadata()?);
            if let Some(worker) = &self.checkpoint_worker {
                worker.update(checkpoint)?;
            }
            Ok(())
        })();
        match attempted {
            Ok(()) => Ok(()),
            Err(error) => {
                mark_degraded(&self.health, &error);
                tracing::error!(%error, "audit write failed; future allowed access will fail closed");
                Err(error)
            }
        }
    }

    fn check_health(&self) -> std::io::Result<()> {
        let degraded = self
            .health
            .lock()
            .map_err(|_| std::io::Error::other("audit health lock poisoned"))?;
        match &*degraded {
            Some(reason) => Err(std::io::Error::other(format!(
                "audit log is degraded: {reason}"
            ))),
            None => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_open(
        &self,
        path: &str,
        operation: &'static str,
        identity: &ProcessIdentity,
        decision: &str,
        rule_id: Option<&str>,
        policy: Option<&PolicyEvaluation>,
        content_version: &str,
        fh: u64,
        size: u64,
        dependencies: Option<&[AuditDependency]>,
    ) -> std::io::Result<()> {
        self.write(&OpenEvent {
            ts: now_rfc3339(),
            event: "open",
            path,
            operation,
            decision,
            rule_id,
            policy,
            request: RequestInfo {
                uid: identity.uid,
                gid: identity.gid,
                pid: identity.pid,
            },
            identity,
            content_version,
            fh,
            size,
            dependencies,
        })
    }

    /// Authorization denied: no snapshot/fh, only records the identity and the rationale for the decision.
    pub fn log_denied(
        &self,
        path: &str,
        operation: &'static str,
        identity: &ProcessIdentity,
        rule_id: Option<&str>,
        reason: &str,
        policy: Option<&PolicyEvaluation>,
    ) -> std::io::Result<()> {
        self.write(&DeniedEvent {
            ts: now_rfc3339(),
            event: "open",
            path,
            operation,
            decision: "denied",
            rule_id,
            reason,
            policy,
            request: RequestInfo {
                uid: identity.uid,
                gid: identity.gid,
                pid: identity.pid,
            },
            identity,
        })
    }

    /// A committed write: a new immutable version appended to the store. Records only the
    /// content hash and version number, never plaintext.
    pub fn log_write_commit(
        &self,
        path: &str,
        fh: u64,
        version: u32,
        content_version: &str,
        size: u64,
    ) -> std::io::Result<()> {
        self.write(&WriteCommitEvent {
            ts: now_rfc3339(),
            event: "write_commit",
            path,
            fh,
            version,
            content_version,
            size,
        })
    }

    /// One SSH agent signature attempt. Only public identity metadata and the authorization/
    /// provider outcome are recorded; the public key blob, bytes-to-sign, and signature are not.
    #[allow(clippy::too_many_arguments)]
    pub fn log_ssh_sign(
        &self,
        path: &str,
        identity: &ProcessIdentity,
        decision: &str,
        rule_id: Option<&str>,
        reason: &str,
        policy: Option<&PolicyEvaluation>,
        surface_id: &str,
        resource_id: &str,
        key_fingerprint: &str,
        key_label: &str,
        identity_source: Option<&str>,
        result: &str,
        ssh_session: Option<SshSessionAudit<'_>>,
    ) -> std::io::Result<()> {
        self.write(&SshSignEvent {
            ts: now_rfc3339(),
            event: "ssh_sign",
            path,
            operation: "sign",
            decision,
            rule_id,
            reason,
            policy,
            request: RequestInfo {
                uid: identity.uid,
                gid: identity.gid,
                pid: identity.pid,
            },
            identity,
            surface_id,
            resource_id,
            key_fingerprint,
            key_label,
            identity_source,
            result,
            ssh_session,
        })
    }

    pub fn log_close(
        &self,
        path: &str,
        fh: u64,
        duration_ms: u128,
        bytes_served: u64,
        error: Option<&str>,
    ) -> std::io::Result<()> {
        self.write(&CloseEvent {
            ts: now_rfc3339(),
            event: "close",
            path,
            fh,
            duration_ms,
            bytes_served,
            error,
        })
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        if let Some(worker) = &mut self.checkpoint_worker {
            if let Err(error) = worker.shutdown() {
                mark_degraded(&self.health, &error);
            }
        }
    }
}

fn open_private_append(path: &Path) -> std::io::Result<File> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("audit log must be a regular file: {}", path.display()),
            ));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("audit log must be private, found mode {mode:04o}"),
            ));
        }
    }
    OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn file_stamp(metadata: &std::fs::Metadata) -> FileStamp {
    FileStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

fn validate_writer_file(path: &Path, writer: &AuditWriter) -> std::io::Result<()> {
    let descriptor = file_stamp(&writer.output.get_ref().metadata()?);
    let path_metadata = std::fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() || path_metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit log path was replaced with a non-regular file",
        ));
    }
    let at_path = file_stamp(&path_metadata);
    if descriptor != writer.stamp || at_path != writer.stamp || descriptor.size != writer.file_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit log changed outside the authenticated writer",
        ));
    }
    Ok(())
}

fn verify_audit_chain(
    path: &Path,
    authority: Option<&dyn AuditAuthority>,
    required_checkpoint: Option<&AuditCheckpoint>,
) -> std::io::Result<AuditCheckpoint> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("audit log must be a regular file: {}", path.display()),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("audit log must be private: {}", path.display()),
        ));
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    read_verified_access_chain(&mut file, authority, required_checkpoint, 0)
        .map(|(checkpoint, _)| checkpoint)
}

fn read_verified_access_chain(
    file: &mut File,
    authority: Option<&dyn AuditAuthority>,
    required_checkpoint: Option<&AuditCheckpoint>,
    limit: usize,
) -> std::io::Result<(AuditCheckpoint, Vec<AuditAccessRecord>)> {
    let expected_size = file.metadata()?.len();
    let mut sequence = 0_u64;
    let mut head = GENESIS_HASH.to_string();
    let mut file_size = 0_u64;
    let mut records = VecDeque::with_capacity(limit.min(500));
    let reader = BufReader::new(file);
    let mut checkpoint_matched = required_checkpoint
        .map(|checkpoint| {
            checkpoint.sequence == 0 && checkpoint.head == GENESIS_HASH && checkpoint.file_size == 0
        })
        .unwrap_or(true);

    for line in reader.split(b'\n') {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        file_size = file_size.saturating_add(line.len() as u64 + 1);
        let envelope: AuditEnvelope = serde_json::from_slice(&line).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("audit row is malformed: {error}"),
            )
        })?;
        if envelope.format != AUDIT_FORMAT
            || envelope.sequence != sequence.saturating_add(1)
            || envelope.previous != head
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("audit chain breaks at sequence {}", envelope.sequence),
            ));
        }
        let payload = chain_payload(envelope.sequence, &envelope.previous, &envelope.event)?;
        match authority {
            Some(authority) => authority.verify(&payload, &envelope.tag)?,
            None if sha256_tag(&payload) == envelope.tag => {}
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("audit tag is invalid at sequence {}", envelope.sequence),
                ))
            }
        }
        sequence = envelope.sequence;
        head = envelope.tag;
        if let Some(checkpoint) = required_checkpoint {
            if sequence == checkpoint.sequence {
                if head != checkpoint.head || file_size != checkpoint.file_size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "audit chain conflicts with its authenticated checkpoint",
                    ));
                }
                checkpoint_matched = true;
            }
        }

        if limit != 0 {
            if let Ok(record) = serde_json::from_value::<AuditAccessRecord>(envelope.event) {
                if matches!(record.event.as_str(), "open" | "ssh_sign") {
                    if records.len() == limit {
                        records.pop_front();
                    }
                    records.push_back(record);
                }
            }
        }
    }
    if file_size != expected_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit log ends with a partial row",
        ));
    }
    if !checkpoint_matched {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit log was truncated before its authenticated checkpoint",
        ));
    }

    Ok((
        AuditCheckpoint { sequence, head, file_size },
        records.into_iter().rev().collect(),
    ))
}

fn chain_payload(
    sequence: u64,
    previous: &str,
    event: &serde_json::Value,
) -> std::io::Result<Vec<u8>> {
    serde_json::to_vec(&(AUDIT_FORMAT, sequence, previous, event)).map_err(std::io::Error::other)
}

fn sha256_tag(payload: &[u8]) -> String {
    format!("{:x}", Sha256::digest(payload))
}

fn unverified_audit_path(path: &Path) -> PathBuf {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    path.with_extension(format!("unverified-{suffix}-{}", std::process::id()))
}

/// Read the newest access/sign events without loading an unbounded audit file into memory.
///
/// The reader walks backward in fixed-size chunks, tolerates malformed/partial rows, and returns
/// newest first. The active writer may append concurrently; the file length captured at open is
/// treated as a consistent snapshot boundary.
pub fn read_recent_access(path: &Path, limit: usize) -> std::io::Result<Vec<AuditAccessRecord>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut cursor = file.metadata()?.len();
    let mut suffix = Vec::new();
    let mut records = Vec::with_capacity(limit);
    const CHUNK_SIZE: u64 = 64 * 1024;

    while cursor > 0 && records.len() < limit {
        let read_len = cursor.min(CHUNK_SIZE);
        cursor -= read_len;
        file.seek(SeekFrom::Start(cursor))?;
        let mut data = vec![0; read_len as usize];
        file.read_exact(&mut data)?;
        data.extend_from_slice(&suffix);

        let complete_start = if cursor == 0 {
            suffix.clear();
            0
        } else if let Some(first_newline) = data.iter().position(|byte| *byte == b'\n') {
            suffix = data[..first_newline].to_vec();
            first_newline + 1
        } else {
            suffix = data;
            continue;
        };

        for line in data[complete_start..].rsplit(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let event = serde_json::from_slice::<AuditEnvelope>(line)
                .map(|envelope| envelope.event)
                .or_else(|_| serde_json::from_slice::<serde_json::Value>(line));
            let Ok(event) = event else {
                continue;
            };
            let Ok(record) = serde_json::from_value::<AuditAccessRecord>(event) else {
                continue;
            };
            if !matches!(record.event.as_str(), "open" | "ssh_sign") {
                continue;
            }
            records.push(record);
            if records.len() == limit {
                break;
            }
        }
    }

    Ok(records)
}

fn now_rfc3339() -> String {
    chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[derive(Serialize)]
struct RequestInfo {
    uid: u32,
    gid: u32,
    pid: i32,
}

#[derive(Serialize)]
struct OpenEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    operation: &'static str,
    decision: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a PolicyEvaluation>,
    request: RequestInfo,
    identity: &'a ProcessIdentity,
    content_version: &'a str,
    fh: u64,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dependencies: Option<&'a [AuditDependency]>,
}

#[derive(Serialize)]
struct DeniedEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    operation: &'static str,
    decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'a str>,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a PolicyEvaluation>,
    request: RequestInfo,
    identity: &'a ProcessIdentity,
}

#[derive(Serialize)]
struct WriteCommitEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    fh: u64,
    version: u32,
    content_version: &'a str,
    size: u64,
}

#[derive(Serialize)]
struct SshSignEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    operation: &'static str,
    decision: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'a str>,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a PolicyEvaluation>,
    request: RequestInfo,
    identity: &'a ProcessIdentity,
    surface_id: &'a str,
    resource_id: &'a str,
    key_fingerprint: &'a str,
    key_label: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_source: Option<&'a str>,
    result: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_session: Option<SshSessionAudit<'a>>,
}

#[derive(Serialize)]
struct CloseEvent<'a> {
    ts: String,
    event: &'static str,
    path: &'a str,
    fh: u64,
    duration_ms: u128,
    bytes_served: u64,
    error: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Enforcement, PolicyMode};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct TestAuditAuthority {
        checkpoint: Mutex<Option<AuditCheckpoint>>,
        fail_persist: AtomicBool,
        persist_count: AtomicUsize,
    }

    impl AuditAuthority for TestAuditAuthority {
        fn load_checkpoint(&self) -> std::io::Result<Option<AuditCheckpoint>> {
            Ok(self.checkpoint.lock().unwrap().clone())
        }

        fn authenticate(&self, payload: &[u8]) -> std::io::Result<String> {
            let mut tagged = b"fixture-audit-key".to_vec();
            tagged.extend_from_slice(payload);
            Ok(sha256_tag(&tagged))
        }

        fn verify(&self, payload: &[u8], tag: &str) -> std::io::Result<()> {
            if self.authenticate(payload)? == tag {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fixture audit HMAC mismatch",
                ))
            }
        }

        fn persist_checkpoint(&self, checkpoint: &AuditCheckpoint) -> std::io::Result<()> {
            if self.fail_persist.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("fixture checkpoint failure"));
            }
            self.persist_count.fetch_add(1, Ordering::SeqCst);
            *self.checkpoint.lock().unwrap() = Some(checkpoint.clone());
            Ok(())
        }
    }

    #[test]
    fn authenticated_chain_rejects_rewrite_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let authority = std::sync::Arc::new(TestAuditAuthority::default());
        let audit = AuditLog::open_authenticated(&path, authority.clone()).unwrap();
        audit
            .log_denied(
                "surfaces/fixture",
                "read",
                &ProcessIdentity::bare(42, 501, 20),
                Some("fixture-deny"),
                "fixture reason",
                None,
            )
            .unwrap();
        drop(audit);
        let live = AuditLog::open_authenticated(&path, authority.clone()).unwrap();
        assert_eq!(live.read_recent_verified(10).unwrap().len(), 1);

        let original = std::fs::read(&path).unwrap();
        let rewritten = String::from_utf8(original.clone())
            .unwrap()
            .replace("fixture reason", "forged! reason");
        assert_eq!(rewritten.len(), original.len());
        std::fs::write(&path, rewritten).unwrap();
        assert!(live.read_recent_verified(10).is_err());
        assert!(live.ensure_healthy().is_err());
        drop(live);
        assert!(AuditLog::open_authenticated(&path, authority.clone()).is_err());

        std::fs::write(&path, &original[..original.len() / 2]).unwrap();
        assert!(AuditLog::open_authenticated(&path, authority).is_err());
    }

    #[test]
    fn checkpoint_failure_degrades_and_blocks_future_audit_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let authority = std::sync::Arc::new(TestAuditAuthority::default());
        let audit = AuditLog::open_authenticated(&path, authority.clone()).unwrap();
        authority.fail_persist.store(true, Ordering::SeqCst);

        audit
            .log_denied(
                "surfaces/fixture",
                "read",
                &ProcessIdentity::bare(42, 501, 20),
                Some("fixture-deny"),
                "fixture reason",
                None,
            )
            .unwrap();
        assert!(audit.read_recent_verified(10).is_err());
        assert!(audit.ensure_healthy().is_err());
    }

    #[test]
    fn authenticated_checkpoint_updates_are_coalesced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let authority = Arc::new(TestAuditAuthority::default());
        let audit = AuditLog::open_authenticated(&path, authority.clone()).unwrap();
        assert_eq!(authority.persist_count.load(Ordering::SeqCst), 1);

        for pid in 1..=10 {
            audit
                .log_denied(
                    "surfaces/fixture",
                    "read",
                    &ProcessIdentity::bare(pid, 501, 20),
                    Some("fixture-deny"),
                    "fixture reason",
                    None,
                )
                .unwrap();
        }

        assert_eq!(authority.persist_count.load(Ordering::SeqCst), 1);
        assert_eq!(audit.read_recent_verified(20).unwrap().len(), 10);
        assert_eq!(authority.persist_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn authenticated_open_recovers_a_valid_tail_ahead_of_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let authority = Arc::new(TestAuditAuthority::default());
        drop(AuditLog::open_authenticated(&path, authority.clone()).unwrap());

        let event = serde_json::json!({"event": "fixture"});
        let payload = chain_payload(1, GENESIS_HASH, &event).unwrap();
        let tag = authority.authenticate(&payload).unwrap();
        let mut line = serde_json::to_vec(&AuditEnvelope {
            format: AUDIT_FORMAT,
            sequence: 1,
            previous: GENESIS_HASH.to_string(),
            event,
            tag: tag.clone(),
        })
        .unwrap();
        line.push(b'\n');
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&line)
            .unwrap();

        let recovered = AuditLog::open_authenticated(&path, authority.clone()).unwrap();
        assert_eq!(
            authority.load_checkpoint().unwrap(),
            Some(AuditCheckpoint {
                sequence: 1,
                head: tag,
                file_size: line.len() as u64,
            })
        );
        recovered.ensure_healthy().unwrap();
    }

    #[test]
    fn surface_audit_records_version_provenance_without_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).unwrap();
        let policy = PolicyEvaluation {
            configured_enforcement: Enforcement::TouchId,
            effective_enforcement: Enforcement::Allow,
            mode: PolicyMode::AuditOnly,
        };
        audit.log_open(
            "surfaces/fixture-dotenv",
            "read",
            &ProcessIdentity::bare(42, 501, 20),
            "allowed",
            Some("surfaces-default"),
            Some(&policy),
            "sha256:fixture-content-hash",
            7,
            32,
            Some(&[AuditDependency {
                key: "SERVICE_TOKEN".to_string(),
                binding_id: "fixture-binding".to_string(),
                resource_id: "fixture-resource".to_string(),
                secret_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
                version: Some(3),
            }]),
        )
        .unwrap();

        let line = std::fs::read_to_string(path).unwrap();
        assert!(line.contains("fixture-resource"));
        assert!(line.contains("\"version\":3"));
        assert!(line.contains("\"configured_enforcement\":\"touchid\""));
        assert!(line.contains("\"effective_enforcement\":\"allow\""));
        assert!(line.contains("\"mode\":\"audit_only\""));
        assert!(!line.contains("fixture-secret-value"));
    }

    #[test]
    fn ssh_sign_audit_records_public_identity_but_not_signing_material() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).unwrap();
        audit.log_ssh_sign(
            "surfaces/fixture-agent",
            &ProcessIdentity::bare(42, 501, 20),
            "allowed",
            Some("prompt"),
            "prompt: allowed",
            None,
            "fixture-agent",
            "fixture-provider",
            "SHA256:fixtureFingerprint",
            "Fixture identity",
            Some("/Users/fixture/.ssh/fixture-key"),
            "signed",
            Some(SshSessionAudit {
                requested_destination: Some("fixture.example"),
                verified_host_key_fingerprint: Some("SHA256:fixtureHostKey"),
                ssh_user: Some("fixture-user"),
                forwarding_hops: 1,
            }),
        )
        .unwrap();

        let line = std::fs::read_to_string(path).unwrap();
        assert!(line.contains("\"event\":\"ssh_sign\""));
        assert!(line.contains("SHA256:fixtureFingerprint"));
        assert!(line.contains("/Users/fixture/.ssh/fixture-key"));
        assert!(line.contains("\"result\":\"signed\""));
        assert!(line.contains("SHA256:fixtureHostKey"));
        assert!(line.contains("\"forwarding_hops\":1"));
        assert!(!line.contains("fixture-bytes-to-sign"));
        assert!(!line.contains("fixture-signature"));
    }

    #[test]
    fn recent_access_reads_newest_authorizations_and_skips_lifecycle_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).unwrap();
        audit.log_open(
            "surfaces/fixture-env",
            "read",
            &ProcessIdentity::bare(41, 501, 20),
            "allowed",
            Some("fixture-allow"),
            None,
            "sha256:fixture-content",
            7,
            32,
            None,
        )
        .unwrap();
        audit
            .log_close("surfaces/fixture-env", 7, 4, 32, None)
            .unwrap();
        audit.log_denied(
            "secrets/00000000-0000-0000-0000-000000000001",
            "read",
            &ProcessIdentity::bare(42, 501, 20),
            Some("fixture-deny"),
            "denied by fixture",
            None,
        )
        .unwrap();

        let newest = read_recent_access(&path, 1).unwrap();
        assert_eq!(newest.len(), 1);
        assert_eq!(newest[0].identity.pid, 42);
        assert_eq!(newest[0].decision, "denied");

        let all = read_recent_access(&path, 10).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].identity.pid, 42);
        assert_eq!(all[1].identity.pid, 41);
    }

    #[test]
    fn recent_access_handles_rows_larger_than_one_reverse_read_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).unwrap();
        let mut identity = ProcessIdentity::bare(42, 501, 20);
        identity.cmdline = Some(vec!["fixture-reader".repeat(8_000)]);
        audit.log_denied(
            "surfaces/fixture-large-row",
            "read",
            &identity,
            Some("fixture-deny"),
            "denied by fixture",
            None,
        )
        .unwrap();

        let records = read_recent_access(&path, 1).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].path, "surfaces/fixture-large-row");
        assert_eq!(records[0].identity.cmdline, identity.cmdline);
    }
}
