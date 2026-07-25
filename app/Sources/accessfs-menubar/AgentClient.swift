import Darwin
import Foundation
import os

/// Persistent Unix-socket client to the daemon. Runs a background read loop and
/// auto-reconnects. Callbacks fire on the read thread; the UI layer re-dispatches to main.
final class AgentClient {
    static let log = Logger(subsystem: "dev.floria.hola.ac", category: "socket")

    private let socketPath: String
    /// Guarded by `writeLock`: the reconnect thread closes/replaces it while the main thread
    /// may be sending a decision — an unguarded close would race a write onto a dead (or
    /// kernel-reused) descriptor.
    private var fd: Int32 = -1
    /// (dev, inode) of the socket path when the current connection was made; guarded by
    /// `writeLock`. Used to notice a daemon restart re-binding the path (see watchdog).
    private var connectedIdentity: (dev: dev_t, ino: ino_t)?
    /// Serializes writes and fd lifecycle: decisions come from the main thread while hello
    /// and close/reconnect come from the reconnect thread — interleaved bytes would corrupt
    /// the frame stream.
    private let writeLock = NSLock()

    var onPrompt: ((PromptMsg) -> Void)?
    var onAccessEvent: ((AccessEventMsg) -> Void)?
    var onStateChange: ((Bool) -> Void)?

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    func start() {
        Thread.detachNewThread { [weak self] in self?.runForever() }
        Thread.detachNewThread { [weak self] in self?.watchSocketIdentity() }
    }

    private func runForever() {
        while true {
            if connectOnce() {
                Self.log.info("connected to daemon")
                send(HelloMsg())
                onStateChange?(true)
                readLoop()
                Self.log.warning("read loop ended, reconnecting")
                onStateChange?(false)
                writeLock.lock()
                if fd >= 0 { close(fd); fd = -1 }
                connectedIdentity = nil
                writeLock.unlock()
            }
            Thread.sleep(forTimeInterval: 1.0) // retry backoff
        }
    }

    /// A restarted daemon re-binds the socket path to a fresh inode, while a lingering old
    /// process (e.g. blocked in its shutdown path) can keep the established connection open
    /// with no EOF — the app then sits "connected" to a daemon that will never send prompts.
    /// Compare the path's identity with the one recorded at connect time and shut the stale
    /// connection down so the normal reconnect loop takes over.
    private func watchSocketIdentity() {
        while true {
            Thread.sleep(forTimeInterval: 2.0)
            writeLock.lock()
            let f = fd
            let recorded = connectedIdentity
            writeLock.unlock()
            guard f >= 0, let recorded, let current = pathIdentity() else { continue }
            if current.dev != recorded.dev || current.ino != recorded.ino {
                Self.log.warning("agent socket was re-bound by a new daemon; dropping stale connection")
                // shutdown (not close) wakes the blocked read without freeing the fd number,
                // so a concurrent send cannot race onto a reused descriptor.
                shutdown(f, SHUT_RDWR)
            }
        }
    }

    private func pathIdentity() -> (dev: dev_t, ino: ino_t)? {
        var st = stat()
        guard stat(socketPath, &st) == 0 else { return nil }
        return (st.st_dev, st.st_ino)
    }

    private func connectOnce() -> Bool {
        // Capture the path identity before connecting: if a re-bind races in between, the
        // watchdog sees a mismatch and forces one harmless reconnect. Sampling after the
        // connect could record the new inode for an old connection and mask the staleness.
        let identity = pathIdentity()
        let f = socket(AF_UNIX, SOCK_STREAM, 0)
        if f < 0 { return false }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        let ok = socketPath.withCString { src -> Bool in
            if strlen(src) >= cap { return false }
            _ = withUnsafeMutablePointer(to: &addr.sun_path.0) { dst in
                strncpy(dst, src, cap - 1)
            }
            return true
        }
        if !ok { close(f); return false }

        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(f, $0, len) }
        }
        if rc != 0 { close(f); return false }
        writeLock.lock()
        fd = f
        connectedIdentity = identity
        writeLock.unlock()
        return true
    }

    private func readLoop() {
        while true {
            guard let header = readExact(4) else { return }
            let len = (UInt32(header[0]) << 24) | (UInt32(header[1]) << 16)
                | (UInt32(header[2]) << 8) | UInt32(header[3])
            guard len > 0, len < (1 << 20), let body = readExact(Int(len)) else { return }
            dispatch(Data(body))
        }
    }

    private func dispatch(_ body: Data) {
        struct Envelope: Decodable { let type: String }
        guard let env = try? JSONDecoder().decode(Envelope.self, from: body) else { return }
        switch env.type {
        case "prompt":
            if let m = try? JSONDecoder().decode(PromptMsg.self, from: body) {
                Self.log.info("prompt received req_id=\(m.req_id) path=\(m.path)")
                onPrompt?(m)
            } else {
                Self.log.error("prompt decode failed")
            }
        case "access_event":
            if let m = try? JSONDecoder().decode(AccessEventMsg.self, from: body) { onAccessEvent?(m) }
        default:
            break
        }
    }

    func send<T: Encodable>(_ msg: T) {
        writeLock.lock()
        defer { writeLock.unlock() }
        guard fd >= 0, let body = try? JSONEncoder().encode(msg) else { return }
        var frame = Data(count: 4)
        let n = UInt32(body.count)
        frame[0] = UInt8((n >> 24) & 0xff)
        frame[1] = UInt8((n >> 16) & 0xff)
        frame[2] = UInt8((n >> 8) & 0xff)
        frame[3] = UInt8(n & 0xff)
        frame.append(body)
        writeAll(frame)
    }

    // MARK: - low-level IO

    private func readExact(_ count: Int) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = buf.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress!.advanced(by: got), count - got)
            }
            // A signal-interrupted read is not a dead connection; tearing the connection
            // down here caused reconnect churn that could swallow in-flight prompts.
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { return nil }
            got += n
        }
        return buf
    }

    private func writeAll(_ data: Data) {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                let n = write(fd, base.advanced(by: sent), raw.count - sent)
                if n < 0 && errno == EINTR { continue }
                if n <= 0 { break }
                sent += n
            }
        }
    }
}
