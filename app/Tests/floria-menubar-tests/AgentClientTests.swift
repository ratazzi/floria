import Darwin
import Foundation
import XCTest

@testable import floria_menubar

final class AgentClientTests: XCTestCase {
    func testSocketIdentityChangesWhenPathIsImmediatelyRebound() throws {
        let directory = URL(fileURLWithPath: "/private/tmp")
            .appendingPathComponent("floria-agent-\(getpid())-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("agent.sock").path

        let firstSocket = try bindUnixSocket(at: path)
        let firstIdentity = try XCTUnwrap(SocketPathIdentity.read(from: path))
        close(firstSocket)
        XCTAssertEqual(unlink(path), 0)

        let secondSocket = try bindUnixSocket(at: path)
        defer { close(secondSocket) }
        let secondIdentity = try XCTUnwrap(SocketPathIdentity.read(from: path))

        XCTAssertNotEqual(firstIdentity, secondIdentity)
    }

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

    private func bindUnixSocket(at path: String) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        let pathFits = path.withCString { source -> Bool in
            guard strlen(source) < capacity else { return false }
            withUnsafeMutablePointer(to: &address.sun_path.0) { destination in
                _ = strncpy(destination, source, capacity - 1)
            }
            return true
        }
        guard pathFits else {
            close(descriptor)
            throw POSIXError(.ENAMETOOLONG)
        }

        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let error = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            close(descriptor)
            throw error
        }
        return descriptor
    }
}
