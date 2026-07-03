//! Unix-socket server: accepts the menubar app, routes prompt replies, streams events.
//!
//! The daemon is the listener; the app dials in and holds one persistent connection.
//! Only one app connection is served at a time (a menubar app is a singleton). A
//! background thread owns the accept + read loop; `authorize()` on FUSE worker threads
//! sends prompts through the shared writer and blocks on a per-request channel.

use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dashmap::DashMap;
use serde::Serialize;

use crate::protocol::{read_msg, write_msg, ClientDecision, ClientMsg, DaemonMsg};

/// Outcome of asking the app to authorize an access.
pub enum PromptResult {
    Decision(ClientDecision),
    /// No app is connected.
    NoApp,
    /// The app did not answer within the timeout.
    Timeout,
}

pub struct SocketServer {
    /// Writable handle to the current app connection, if any.
    conn: Mutex<Option<UnixStream>>,
    /// Pending prompts awaiting a reply, keyed by request id.
    pending: DashMap<u64, mpsc::Sender<ClientDecision>>,
    next_req: AtomicU64,
}

impl SocketServer {
    /// Bind the socket and spawn the accept/read thread. The socket file is created
    /// with mode 0600; a stale file at the path is removed first.
    pub fn start(path: &Path) -> io::Result<Arc<SocketServer>> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Remove a stale socket from a previous run (bind fails on EADDRINUSE otherwise).
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

        let server = Arc::new(SocketServer {
            conn: Mutex::new(None),
            pending: DashMap::new(),
            next_req: AtomicU64::new(1),
        });

        let srv = Arc::clone(&server);
        let sock_path = path.to_path_buf();
        std::thread::Builder::new()
            .name("accessfs-agent-accept".into())
            .spawn(move || srv.accept_loop(listener, sock_path))?;

        Ok(server)
    }

    fn accept_loop(&self, listener: UnixListener, _path: PathBuf) {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    continue;
                }
            };
            if !same_uid(&stream) {
                tracing::warn!("rejecting agent connection from a different uid");
                continue;
            }
            match stream.try_clone() {
                Ok(writer) => *self.conn.lock().expect("conn poisoned") = Some(writer),
                Err(e) => {
                    tracing::warn!("clone stream failed: {e}");
                    continue;
                }
            }
            tracing::info!("menubar app connected");
            self.read_loop(stream);
            *self.conn.lock().expect("conn poisoned") = None;
            tracing::info!("menubar app disconnected");
        }
    }

    fn read_loop(&self, mut reader: UnixStream) {
        loop {
            match read_msg::<_, ClientMsg>(&mut reader) {
                Ok(ClientMsg::Hello { version }) => {
                    tracing::info!(version, "agent hello");
                }
                Ok(ClientMsg::Decision {
                    req_id,
                    outcome,
                    scope,
                    ttl_secs,
                }) => {
                    if let Some((_, tx)) = self.pending.remove(&req_id) {
                        let _ = tx.send(ClientDecision {
                            allow: outcome == "allow",
                            scope,
                            ttl_secs,
                        });
                    }
                }
                Err(_) => break, // EOF or protocol error -> disconnect
            }
        }
    }

    /// Send a prompt and block until the app replies or the timeout elapses.
    pub fn prompt_and_wait<'a>(
        &self,
        msg_of: impl FnOnce(u64) -> DaemonMsg<'a>,
        timeout: Duration,
    ) -> PromptResult {
        let req_id = self.next_req.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.pending.insert(req_id, tx);

        if !self.send(&msg_of(req_id)) {
            self.pending.remove(&req_id);
            return PromptResult::NoApp;
        }
        match rx.recv_timeout(timeout) {
            Ok(dec) => PromptResult::Decision(dec),
            Err(_) => {
                self.pending.remove(&req_id);
                PromptResult::Timeout
            }
        }
    }

    /// Best-effort fire-and-forget send (e.g. access events).
    pub fn send_event(&self, msg: &impl Serialize) {
        let _ = self.send(msg);
    }

    /// Write a message to the app. Returns false if no app is connected or the write failed
    /// (in which case the connection is dropped so the next attempt also reports no-app).
    fn send(&self, msg: &impl Serialize) -> bool {
        let mut guard = self.conn.lock().expect("conn poisoned");
        let Some(conn) = guard.as_mut() else {
            return false;
        };
        if write_msg(conn, msg).is_err() {
            *guard = None;
            return false;
        }
        true
    }
}

/// Verify the connecting peer runs as the same uid as this process.
fn same_uid(stream: &UnixStream) -> bool {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: valid fd from the accepted stream; out-params are stack locals.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    // SAFETY: geteuid is always-safe.
    rc == 0 && uid == unsafe { libc::geteuid() }
}
