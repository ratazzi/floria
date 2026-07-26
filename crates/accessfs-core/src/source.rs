use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use wait_timeout::ChildExt;
use zeroize::Zeroizing;

use crate::authz::Operation;
use crate::error::{CoreError, Result};

/// Execution ceiling for command sources. Must be well below the mount's `daemon_timeout`,
/// otherwise the kernel may declare the whole mount dead before the source returns.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Where a value is persisted. This is not a sensitivity classification:
/// inline plaintext may still contain a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageDisposition {
    EncryptedReference,
    InlinePlaintext,
    Computed,
}

/// Request context captured when compiling one immutable access snapshot.
#[derive(Debug, Clone, Copy)]
pub struct SourceCtx<'a> {
    pub virtual_path: &'a str,
    pub request_uid: u32,
    pub request_pid: i32,
    pub operation: Operation,
}

/// Store version captured without reading or decrypting its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedVersion {
    pub secret_id: String,
    pub version: u32,
}

pub struct SourceSnapshot {
    pub bytes: Zeroizing<Vec<u8>>,
    pub pinned: Option<PinnedVersion>,
}

pub trait PinnedContent: Send {
    fn pinned_version(&self) -> Option<&PinnedVersion>;
    fn read(self: Box<Self>) -> Result<SourceSnapshot>;
}

/// A source of bytes for one virtual file. `pin` must not decrypt bytes or execute commands;
/// callers may therefore pin every dependency before reading any of them.
pub trait ContentSource: Send + Sync + std::fmt::Debug {
    fn storage_disposition(&self) -> StorageDisposition;
    fn exact_size(&self) -> Option<u64> {
        None
    }
    fn pin(&self, ctx: &SourceCtx<'_>) -> Result<Box<dyn PinnedContent>>;
}

#[derive(Debug, Clone)]
pub struct LiteralSource {
    bytes: Arc<Vec<u8>>,
}

impl LiteralSource {
    pub fn new(bytes: Arc<Vec<u8>>) -> Self {
        LiteralSource { bytes }
    }
}

impl ContentSource for LiteralSource {
    fn storage_disposition(&self) -> StorageDisposition {
        StorageDisposition::InlinePlaintext
    }

    fn exact_size(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }

    fn pin(&self, _ctx: &SourceCtx<'_>) -> Result<Box<dyn PinnedContent>> {
        Ok(Box::new(PinnedLiteral { bytes: Arc::clone(&self.bytes) }))
    }
}

struct PinnedLiteral {
    bytes: Arc<Vec<u8>>,
}

impl PinnedContent for PinnedLiteral {
    fn pinned_version(&self) -> Option<&PinnedVersion> {
        None
    }

    fn read(self: Box<Self>) -> Result<SourceSnapshot> {
        Ok(SourceSnapshot {
            bytes: Zeroizing::new(self.bytes.as_ref().clone()),
            pinned: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CommandSource {
    argv: Vec<String>,
}

impl CommandSource {
    pub fn new(argv: Vec<String>) -> Self {
        CommandSource { argv }
    }
}

impl ContentSource for CommandSource {
    fn storage_disposition(&self) -> StorageDisposition {
        StorageDisposition::Computed
    }

    fn pin(&self, ctx: &SourceCtx<'_>) -> Result<Box<dyn PinnedContent>> {
        Ok(Box::new(PinnedCommand {
            argv: self.argv.clone(),
            virtual_path: ctx.virtual_path.to_string(),
            request_uid: ctx.request_uid,
            request_pid: ctx.request_pid,
            operation: ctx.operation,
        }))
    }
}

struct PinnedCommand {
    argv: Vec<String>,
    virtual_path: String,
    request_uid: u32,
    request_pid: i32,
    operation: Operation,
}

impl PinnedContent for PinnedCommand {
    fn pinned_version(&self) -> Option<&PinnedVersion> {
        None
    }

    fn read(self: Box<Self>) -> Result<SourceSnapshot> {
        let bytes = run_script(
            &self.argv,
            &SourceCtx {
                virtual_path: &self.virtual_path,
                request_uid: self.request_uid,
                request_pid: self.request_pid,
                operation: self.operation,
            },
        )?;
        Ok(SourceSnapshot { bytes: Zeroizing::new(bytes), pinned: None })
    }
}

fn run_script(argv: &[String], ctx: &SourceCtx<'_>) -> Result<Vec<u8>> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| CoreError::source("empty command argv"))?;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("ACCESSFS_OPERATION", ctx.operation.as_str())
        .env("ACCESSFS_PATH", ctx.virtual_path)
        .env("ACCESSFS_REQUEST_UID", ctx.request_uid.to_string())
        .env("ACCESSFS_REQUEST_PID", ctx.request_pid.to_string())
        .spawn()
        .map_err(|e| CoreError::source(format!("spawn {program}: {e}")))?;

    // Drain stdout/stderr on separate threads so the child can't deadlock by filling the pipe buffer.
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| CoreError::source("no stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| CoreError::source("no stderr pipe"))?;

    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });

    let status = match child
        .wait_timeout(SCRIPT_TIMEOUT)
        .map_err(|e| CoreError::source(format!("wait {program}: {e}")))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CoreError::source(format!(
                "{program} timed out after {}s",
                SCRIPT_TIMEOUT.as_secs()
            )));
        }
    };

    let stdout_bytes = out_thread.join().unwrap_or_default();
    let stderr_text = err_thread.join().unwrap_or_default();
    if !stderr_text.trim().is_empty() {
        tracing::debug!(source = %program, "command source stderr: {}", stderr_text.trim());
    }

    if !status.success() {
        return Err(CoreError::source(format!(
            "{program} exited with {status}"
        )));
    }

    Ok(stdout_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(operation: Operation) -> SourceCtx<'static> {
        SourceCtx {
            virtual_path: "env/demo/dev.env",
            request_uid: 501,
            request_pid: 12345,
            operation,
        }
    }

    #[test]
    fn literal_source_pins_inline_bytes() {
        let source = LiteralSource::new(Arc::new(b"hello\n".to_vec()));
        assert_eq!(source.storage_disposition(), StorageDisposition::InlinePlaintext);
        assert_eq!(source.exact_size(), Some(6));
        let pinned = source.pin(&ctx(Operation::Read)).unwrap();
        assert_eq!(pinned.pinned_version(), None);
        assert_eq!(pinned.read().unwrap().bytes.as_slice(), b"hello\n");
    }

    #[test]
    fn command_source_captures_stdout_and_request_context() {
        // Use /bin/sh to echo the injected env vars, verifying exec + env + stdout capture.
        let source = CommandSource::new(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf 'op=%s p=%s u=%s path=%s' \"$ACCESSFS_OPERATION\" \
                 \"$ACCESSFS_REQUEST_PID\" \"$ACCESSFS_REQUEST_UID\" \"$ACCESSFS_PATH\""
                .to_string(),
        ]);
        assert_eq!(source.storage_disposition(), StorageDisposition::Computed);
        let out = source.pin(&ctx(Operation::Write)).unwrap().read().unwrap();
        assert_eq!(
            String::from_utf8(out.bytes.to_vec()).unwrap(),
            "op=write p=12345 u=501 path=env/demo/dev.env"
        );
    }

    #[test]
    fn command_source_nonzero_exit_is_error() {
        let source = CommandSource::new(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 3".to_string(),
        ]);
        assert!(source
            .pin(&ctx(Operation::Read))
            .unwrap()
            .read()
            .is_err());
    }
}
