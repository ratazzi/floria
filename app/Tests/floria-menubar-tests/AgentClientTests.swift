import Darwin
import XCTest

@testable import floria_menubar

final class AgentClientTests: XCTestCase {
    func testAgentSocketSuppressesSigpipeWhenDaemonDisconnects() throws {
        var sockets = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            if sockets[0] >= 0 { close(sockets[0]) }
            if sockets[1] >= 0 { close(sockets[1]) }
        }

        XCTAssertTrue(configureAgentSocket(sockets[0]))

        var enabled: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(
            getsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE, &enabled, &length),
            0)
        XCTAssertEqual(enabled, 1)

        close(sockets[1])
        sockets[1] = -1
        var byte: UInt8 = 0
        errno = 0
        XCTAssertEqual(write(sockets[0], &byte, 1), -1)
        XCTAssertEqual(errno, EPIPE)
    }
}
