import Darwin
import Foundation

/// Persistent Unix-socket client to the daemon. Runs a background read loop and
/// auto-reconnects. Callbacks fire on the read thread; the UI layer re-dispatches to main.
final class AgentClient {
    private let socketPath: String
    private var fd: Int32 = -1

    var onPrompt: ((PromptMsg) -> Void)?
    var onAccessEvent: ((AccessEventMsg) -> Void)?
    var onStateChange: ((Bool) -> Void)?

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    func start() {
        Thread.detachNewThread { [weak self] in self?.runForever() }
    }

    private func runForever() {
        while true {
            if connectOnce() {
                send(HelloMsg())
                onStateChange?(true)
                readLoop()
                onStateChange?(false)
                if fd >= 0 { close(fd); fd = -1 }
            }
            Thread.sleep(forTimeInterval: 1.0) // retry backoff
        }
    }

    private func connectOnce() -> Bool {
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
        fd = f
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
            if let m = try? JSONDecoder().decode(PromptMsg.self, from: body) { onPrompt?(m) }
        case "access_event":
            if let m = try? JSONDecoder().decode(AccessEventMsg.self, from: body) { onAccessEvent?(m) }
        default:
            break
        }
    }

    func send<T: Encodable>(_ msg: T) {
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
                if n <= 0 { break }
                sent += n
            }
        }
    }
}
