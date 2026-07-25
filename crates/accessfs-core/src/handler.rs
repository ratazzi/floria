use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use wait_timeout::ChildExt;

use crate::error::{CoreError, Result};

/// Execution ceiling for script handlers. Must be well below the mount's `daemon_timeout`,
/// otherwise the kernel may declare the whole mount dead before the handler returns.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(5);

/// The content source of a virtual file.
#[derive(Debug, Clone)]
pub enum ContentHandler {
    /// Built-in constant content. All bytes are known at mount time, so size is reported exactly.
    Constant(Arc<Vec<u8>>),
    /// Local script. Executed once on open; its stdout is the content.
    Script { argv: Vec<String> },
}

/// Context passed to a handler (scripts receive it via environment variables).
#[derive(Debug, Clone)]
pub struct HandlerCtx {
    pub virtual_path: String,
    pub request_uid: u32,
    pub request_pid: i32,
}

impl ContentHandler {
    /// Generate content once to freeze a process access-session snapshot.
    pub fn generate(&self, ctx: &HandlerCtx) -> Result<Vec<u8>> {
        match self {
            ContentHandler::Constant(bytes) => Ok(bytes.as_ref().clone()),
            ContentHandler::Script { argv } => run_script(argv, ctx),
        }
    }
}

fn run_script(argv: &[String], ctx: &HandlerCtx) -> Result<Vec<u8>> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| CoreError::handler("empty handler argv"))?;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("ACCESSFS_OPERATION", "read")
        .env("ACCESSFS_PATH", &ctx.virtual_path)
        .env("ACCESSFS_REQUEST_UID", ctx.request_uid.to_string())
        .env("ACCESSFS_REQUEST_PID", ctx.request_pid.to_string())
        .spawn()
        .map_err(|e| CoreError::handler(format!("spawn {program}: {e}")))?;

    // Drain stdout/stderr on separate threads so the child can't deadlock by filling the pipe buffer.
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| CoreError::handler("no stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| CoreError::handler("no stderr pipe"))?;

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
        .map_err(|e| CoreError::handler(format!("wait {program}: {e}")))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CoreError::handler(format!(
                "{program} timed out after {}s",
                SCRIPT_TIMEOUT.as_secs()
            )));
        }
    };

    let stdout_bytes = out_thread.join().unwrap_or_default();
    let stderr_text = err_thread.join().unwrap_or_default();
    if !stderr_text.trim().is_empty() {
        tracing::debug!(handler = %program, "handler stderr: {}", stderr_text.trim());
    }

    if !status.success() {
        return Err(CoreError::handler(format!(
            "{program} exited with {status}"
        )));
    }

    Ok(stdout_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> HandlerCtx {
        HandlerCtx {
            virtual_path: "env/demo/dev.env".to_string(),
            request_uid: 501,
            request_pid: 12345,
        }
    }

    #[test]
    fn constant_handler_returns_bytes() {
        let h = ContentHandler::Constant(Arc::new(b"hello\n".to_vec()));
        assert_eq!(h.generate(&ctx()).unwrap(), b"hello\n");
    }

    #[test]
    fn script_handler_captures_stdout_and_env() {
        // Use /bin/sh to echo the injected env vars, verifying exec + env + stdout capture.
        let h = ContentHandler::Script {
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf 'p=%s u=%s path=%s' \"$ACCESSFS_REQUEST_PID\" \
                 \"$ACCESSFS_REQUEST_UID\" \"$ACCESSFS_PATH\""
                    .to_string(),
            ],
        };
        let out = String::from_utf8(h.generate(&ctx()).unwrap()).unwrap();
        assert_eq!(out, "p=12345 u=501 path=env/demo/dev.env");
    }

    #[test]
    fn script_handler_nonzero_exit_is_error() {
        let h = ContentHandler::Script {
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), "exit 3".to_string()],
        };
        assert!(h.generate(&ctx()).is_err());
    }
}
