//! Unix-socket server: accepts the menubar app, routes prompt replies, streams events.
//!
//! The daemon is the listener; the app dials in and holds one persistent connection.
//! Only one app connection is served at a time (a menubar app is a singleton). A
//! background thread owns the accept + read loop; `authorize()` on FUSE worker threads
//! sends prompts through the shared writer and blocks on a per-request channel.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use floria_platform::SocketPeerVerifier;
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

/// Cap on a blocking write to the app. `send()` holds the connection mutex across the write:
/// without a timeout, an app that stopped reading (paused, hung) would fill the socket buffer
/// and block the sender forever — and since every `authorize()` streams an access event, all
/// open-pool threads (and the accept loop) would pile up on that mutex, freezing the mount.
/// On timeout the write errors and the connection is dropped (fail-closed / app reconnects).
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

pub struct SocketServer {
    peer_verifier: Arc<dyn SocketPeerVerifier>,
    /// Writable handle to the current app connection, if any, tagged with its generation so
    /// a dying connection's cleanup never clears a newer one that already replaced it.
    conn: Mutex<Option<Conn>>,
    /// Pending prompts awaiting a reply, keyed by request id.
    pending: DashMap<u64, mpsc::Sender<ClientDecision>>,
    next_req: AtomicU64,
    conn_gen: AtomicU64,
}

struct Conn {
    gen: u64,
    stream: UnixStream,
}

impl SocketServer {
    /// Bind the socket and spawn the accept/read thread. The socket file is created
    /// with mode 0600; a stale file at the path is removed first.
    pub fn start(
        path: &Path,
        peer_verifier: Arc<dyn SocketPeerVerifier>,
    ) -> io::Result<Arc<SocketServer>> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Remove a stale socket from a previous run (bind fails on EADDRINUSE otherwise).
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

        let server = Arc::new(SocketServer {
            peer_verifier,
            conn: Mutex::new(None),
            pending: DashMap::new(),
            next_req: AtomicU64::new(1),
            conn_gen: AtomicU64::new(1),
        });

        let srv = Arc::clone(&server);
        std::thread::Builder::new()
            .name("floria-agent-accept".into())
            .spawn(move || srv.accept_loop(listener))?;

        Ok(server)
    }

    /// Accept connections forever, each served by its own reader thread. Accepting must never
    /// block on serving: the app auto-reconnects, and its connect() succeeds via the listen
    /// backlog immediately — if we sat in a read loop instead of accepting, the fresh
    /// connection would hang unserved while prompts kept going to the dead one (writes into
    /// a dead socket's buffer still succeed), silently swallowing them.
    fn accept_loop(self: Arc<Self>, listener: UnixListener) {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    continue;
                }
            };
            let peer = match self.peer_verifier.verify(&stream) {
                Ok(peer) => peer,
                Err(error) => {
                    tracing::warn!(%error, "rejecting untrusted agent connection");
                    continue;
                }
            };
            let writer = match stream.try_clone() {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!("clone stream failed: {e}");
                    continue;
                }
            };
            if let Err(e) = writer.set_write_timeout(Some(SEND_TIMEOUT)) {
                tracing::warn!("set write timeout failed: {e}");
                continue;
            }
            let gen = self.conn_gen.fetch_add(1, Ordering::Relaxed);
            *self.conn.lock().expect("conn poisoned") = Some(Conn { gen, stream: writer });
            tracing::info!(
                gen,
                pid = peer.identity.pid,
                executable = ?peer.identity.exe_path,
                bundle_id = ?peer.identity.bundle_id,
                team_id = ?peer.identity.team_id,
                "trusted menubar app connected"
            );

            let srv = Arc::clone(&self);
            let spawned = std::thread::Builder::new()
                .name("floria-agent-conn".into())
                .spawn(move || {
                    srv.read_loop(stream);
                    // Clear the writer only if it is still ours — a newer connection may
                    // have replaced it while we were serving.
                    let mut guard = srv.conn.lock().expect("conn poisoned");
                    if guard.as_ref().is_some_and(|c| c.gen == gen) {
                        *guard = None;
                    }
                    tracing::info!(gen, "menubar app disconnected");
                });
            if let Err(e) = spawned {
                tracing::warn!("spawn conn thread failed: {e}");
                *self.conn.lock().expect("conn poisoned") = None;
            }
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

    #[cfg(test)]
    pub(crate) fn has_connection(&self) -> bool {
        self.conn.lock().expect("conn poisoned").is_some()
    }

    /// Write a message to the app. Returns false if no app is connected or the write failed
    /// (in which case the connection is dropped so the next attempt also reports no-app).
    fn send(&self, msg: &impl Serialize) -> bool {
        let mut guard = self.conn.lock().expect("conn poisoned");
        let Some(conn) = guard.as_mut() else {
            return false;
        };
        if write_msg(&mut conn.stream, msg).is_err() {
            *guard = None;
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::IdentityView;
    use floria_core::identity::ProcessIdentity;
    use floria_platform::{
        PeerVerificationError, SameUserPeerVerifier, SocketPeerVerifier, VerifiedPeer,
    };
    use serde_json::{json, Value};
    use std::path::PathBuf;
    use std::time::Instant;

    fn sock_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("floria-sock-test-{}-{tag}.sock", std::process::id()))
    }

    /// Connect a fake app and send the hello, like the real client does. A read timeout
    /// bounds every blocking assertion so a regression fails instead of hanging the suite.
    fn connect(path: &std::path::Path) -> UnixStream {
        let s = UnixStream::connect(path).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_msg(&mut &s, &json!({"type": "hello", "version": 1})).expect("hello");
        s
    }

    fn current_gen(srv: &SocketServer) -> Option<u64> {
        srv.conn.lock().unwrap().as_ref().map(|c| c.gen)
    }

    fn start(path: &Path) -> Arc<SocketServer> {
        SocketServer::start(path, Arc::new(SameUserPeerVerifier)).unwrap()
    }

    struct RejectAllPeers;

    impl SocketPeerVerifier for RejectAllPeers {
        fn verify(&self, _stream: &UnixStream) -> Result<VerifiedPeer, PeerVerificationError> {
            Err(PeerVerificationError::UntrustedCode {
                pid: std::process::id() as i32,
                executable: "fixture client".to_string(),
                trusted: "fixture trusted app".to_string(),
            })
        }
    }

    fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if cond() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out waiting for {what}");
    }

    fn prompt_msg(req_id: u64) -> DaemonMsg<'static> {
        let id = ProcessIdentity::bare(1, 501, 20);
        DaemonMsg::Prompt {
            req_id,
            path: "secrets/x",
            display: None,
            operation: "read",
            enforcement: "prompt",
            ssh: None,
            identity: IdentityView::from_identity(&id),
        }
    }

    #[test]
    fn prompt_without_app_is_noapp() {
        let path = sock_path("noapp");
        let srv = start(&path);
        assert!(matches!(
            srv.prompt_and_wait(prompt_msg, Duration::from_millis(200)),
            PromptResult::NoApp
        ));
        assert!(srv.pending.is_empty(), "pending must not leak on NoApp");
    }

    #[test]
    fn rejected_peer_never_becomes_the_decision_connection() {
        let path = sock_path("rejected");
        let srv = SocketServer::start(&path, Arc::new(RejectAllPeers)).unwrap();
        let _client = UnixStream::connect(&path).expect("connect");
        std::thread::sleep(Duration::from_millis(50));

        assert!(current_gen(&srv).is_none());
        assert!(matches!(
            srv.prompt_and_wait(prompt_msg, Duration::from_millis(50)),
            PromptResult::NoApp
        ));
    }

    #[test]
    fn decision_resolves_pending_prompt() {
        let path = sock_path("roundtrip");
        let srv = start(&path);
        let client = connect(&path);
        wait_until(|| current_gen(&srv).is_some(), "app connected");

        let waiter = {
            let srv = Arc::clone(&srv);
            std::thread::spawn(move || srv.prompt_and_wait(prompt_msg, Duration::from_secs(5)))
        };

        let prompt: Value = read_msg(&mut &client).unwrap();
        assert_eq!(prompt["type"], "prompt");
        let req_id = prompt["req_id"].as_u64().unwrap();
        write_msg(
            &mut &client,
            &json!({"type": "decision", "req_id": req_id, "outcome": "allow", "scope": "ttl", "ttl_secs": 600}),
        )
        .unwrap();

        match waiter.join().unwrap() {
            PromptResult::Decision(d) => {
                assert!(d.allow);
                assert_eq!(d.scope.as_deref(), Some("ttl"));
                assert_eq!(d.ttl_secs, Some(600));
            }
            _ => panic!("expected a decision"),
        }
        assert!(srv.pending.is_empty(), "pending must be drained after reply");
    }

    #[test]
    fn silent_app_times_out_and_clears_pending() {
        let path = sock_path("timeout");
        let srv = start(&path);
        let _client = connect(&path);
        wait_until(|| current_gen(&srv).is_some(), "app connected");

        assert!(matches!(
            srv.prompt_and_wait(prompt_msg, Duration::from_millis(100)),
            PromptResult::Timeout
        ));
        assert!(srv.pending.is_empty(), "pending must not leak on timeout");
    }

    /// Regression: the app reconnecting while the old connection is still open. Before the
    /// concurrent accept loop, the fresh connection sat unserved in the listen backlog and
    /// prompts went into the dead connection — this is the intermittent "no alert" bug.
    #[test]
    fn prompts_go_to_the_newest_connection() {
        let path = sock_path("reconnect");
        let srv = start(&path);
        let old = connect(&path);
        wait_until(|| current_gen(&srv).is_some(), "first connection served");
        let first_gen = current_gen(&srv).unwrap();
        let new = connect(&path);
        wait_until(|| current_gen(&srv) != Some(first_gen), "reconnect served");

        let waiter = {
            let srv = Arc::clone(&srv);
            std::thread::spawn(move || srv.prompt_and_wait(prompt_msg, Duration::from_secs(5)))
        };

        // The prompt must arrive on the NEW connection while the old one is still open.
        let prompt: Value = read_msg(&mut &new).unwrap();
        assert_eq!(prompt["type"], "prompt");
        write_msg(
            &mut &new,
            &json!({"type": "decision", "req_id": prompt["req_id"], "outcome": "allow"}),
        )
        .unwrap();
        assert!(matches!(
            waiter.join().unwrap(),
            PromptResult::Decision(d) if d.allow
        ));
        drop(old);
    }

    /// Regression: an app that stops reading must not hang `send()` forever — `send` holds
    /// the conn mutex, so a stuck write would freeze every authorize (and the accept loop).
    /// The write timeout must fail the send and drop the connection in bounded time.
    #[test]
    fn stalled_app_cannot_block_send_forever() {
        let path = sock_path("stall");
        let srv = start(&path);
        let client = connect(&path); // sends hello, then never reads
        wait_until(|| current_gen(&srv).is_some(), "app connected");

        // Overfill the socket buffer with frames the client never drains.
        let pad = "x".repeat(256 * 1024);
        let start = Instant::now();
        for _ in 0..8 {
            srv.send_event(&json!({"type": "ping", "pad": &pad}));
            if current_gen(&srv).is_none() {
                break;
            }
        }
        assert!(
            current_gen(&srv).is_none(),
            "stalled connection was not dropped"
        );
        // 2 rounds of SEND_TIMEOUT per frame worst case, with slack.
        assert!(
            start.elapsed() < SEND_TIMEOUT * 4,
            "send blocked far beyond the write timeout"
        );
        drop(client);
    }

    /// The old connection's reader thread exits after a newer one already replaced it; its
    /// cleanup must not clear the newer connection (the generation tag guards this).
    #[test]
    fn stale_reader_exit_keeps_newer_connection() {
        let path = sock_path("gen");
        let srv = start(&path);
        let old = connect(&path);
        wait_until(|| current_gen(&srv).is_some(), "first connection served");
        let first_gen = current_gen(&srv).unwrap();
        let new = connect(&path);
        wait_until(|| current_gen(&srv) != Some(first_gen), "second connection served");
        let second_gen = current_gen(&srv).unwrap();

        drop(old);
        // Give the old reader thread time to notice EOF and run its (no-op) cleanup.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(current_gen(&srv), Some(second_gen), "newer connection was cleared");

        // And it still works end to end.
        srv.send_event(&json!({"type": "ping"}));
        let ev: Value = read_msg(&mut &new).unwrap();
        assert_eq!(ev["type"], "ping");
    }
}
