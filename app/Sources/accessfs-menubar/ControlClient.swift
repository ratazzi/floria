import Darwin
import Foundation

final class ControlClient: @unchecked Sendable {
    private let socketPath: String
    private let queue = DispatchQueue(label: "dev.floria.hola.ac.control", qos: .userInitiated)
    private var nextRequestID: UInt64 = 1

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    func snapshot() async throws -> CatalogSnapshot {
        guard let snapshot: CatalogSnapshot = try await request(
            .snapshot, expecting: "snapshot", as: CatalogSnapshot.self)
        else {
            throw ControlClientError.missingResult("snapshot")
        }
        return snapshot
    }

    func createSharedSecret(
        resourceID: String, name: String, defaultEnvKey: String?, value: String
    ) async throws {
        let _: SharedSecretCreated? = try await request(
            .sharedSecretCreate(
                resourceID: resourceID, name: name, defaultEnvKey: defaultEnvKey, value: value),
            expecting: "shared_secret_created", as: SharedSecretCreated.self)
    }

    func createEnvFile(
        resourceID: String, name: String, codec: WorkspaceResourceCodec, value: String
    ) async throws {
        let _: EnvFileCreated? = try await request(
            .envFileCreate(resourceID: resourceID, name: name, codec: codec.rawValue, value: value),
            expecting: "env_file_created", as: EnvFileCreated.self)
    }

    func upsertProject(_ project: CatalogProject) async throws {
        try await requestEmpty(.projectUpsert(project))
    }

    func removeProject(_ id: String) async throws {
        try await requestEmpty(.projectRemove(id))
    }

    func createProject(
        _ project: CatalogProject, environment: CatalogEnvironment, surface: CatalogSurface
    ) async throws {
        try await requestEmpty(.projectCreate(project, environment, surface))
    }

    func upsertEnvironment(_ environment: CatalogEnvironment) async throws {
        try await requestEmpty(.environmentUpsert(environment))
    }

    func removeEnvironment(_ id: String) async throws {
        try await requestEmpty(.environmentRemove(id))
    }

    func upsertBinding(_ binding: CatalogBinding) async throws {
        try await requestEmpty(.bindingUpsert(binding))
    }

    func removeBinding(_ id: String) async throws {
        try await requestEmpty(.bindingRemove(id))
    }

    func upsertSurface(_ surface: CatalogSurface) async throws {
        try await requestEmpty(.surfaceUpsert(surface))
    }

    func removeSurface(_ id: String) async throws {
        try await requestEmpty(.surfaceRemove(id))
    }

    private func requestEmpty(_ command: ControlCommand) async throws {
        let _: EmptyControlValue? = try await request(
            command, expecting: "empty", as: EmptyControlValue.self)
    }

    private func request<Value: Decodable>(
        _ command: ControlCommand, expecting resultType: String, as: Value.Type
    ) async throws -> Value? {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                do {
                    let requestID = nextRequestID
                    nextRequestID &+= 1
                    let encoder = JSONEncoder()
                    encoder.keyEncodingStrategy = .convertToSnakeCase
                    var requestBody = try command.requestData(requestID: requestID, encoder: encoder)
                    defer { requestBody.resetBytes(in: requestBody.startIndex..<requestBody.endIndex) }

                    let responseBody = try exchange(requestBody)
                    let decoder = JSONDecoder()
                    let response = try decoder.decode(
                        ControlResponseEnvelope<Value>.self, from: responseBody)
                    guard response.requestID == requestID else {
                        throw ControlClientError.responseMismatch(
                            expected: requestID, actual: response.requestID)
                    }
                    if response.status == "error" {
                        let error = response.error
                        throw ControlClientError.daemon(
                            code: error?.code ?? "unknown",
                            message: error?.message ?? "The daemon rejected the request")
                    }
                    guard response.status == "ok", let result = response.result else {
                        throw ControlClientError.invalidResponse
                    }
                    guard result.type == resultType else {
                        throw ControlClientError.unexpectedResult(
                            expected: resultType, actual: result.type)
                    }
                    continuation.resume(returning: result.value)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func exchange(_ body: Data) throws -> Data {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ControlClientError.systemCall("socket", errno) }
        defer { close(fd) }

        var noSignal: Int32 = 1
        _ = setsockopt(
            fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
            socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        let pathFits = socketPath.withCString { source -> Bool in
            guard strlen(source) < capacity else { return false }
            withUnsafeMutablePointer(to: &address.sun_path.0) { destination in
                _ = strncpy(destination, source, capacity - 1)
            }
            return true
        }
        guard pathFits else { throw ControlClientError.socketPathTooLong }

        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { throw ControlClientError.systemCall("connect", errno) }

        guard body.count <= Int(UInt32.max) else { throw ControlClientError.requestTooLarge }
        let length = UInt32(body.count)
        let header = Data([
            UInt8((length >> 24) & 0xff), UInt8((length >> 16) & 0xff),
            UInt8((length >> 8) & 0xff), UInt8(length & 0xff),
        ])
        try writeAll(header, to: fd)
        try writeAll(body, to: fd)

        let responseHeader = try readExact(4, from: fd)
        let responseLength = responseHeader.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard responseLength > 0, responseLength <= 8 << 20 else {
            throw ControlClientError.invalidResponse
        }
        return try readExact(Int(responseLength), from: fd)
    }

    private func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < raw.count {
                let count = Darwin.write(fd, base.advanced(by: sent), raw.count - sent)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw ControlClientError.systemCall("write", errno) }
                sent += count
            }
        }
    }

    private func readExact(_ count: Int, from fd: Int32) throws -> Data {
        var data = Data(count: count)
        var received = 0
        try data.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            while received < count {
                let amount = Darwin.read(fd, base.advanced(by: received), count - received)
                if amount < 0, errno == EINTR { continue }
                guard amount > 0 else { throw ControlClientError.systemCall("read", errno) }
                received += amount
            }
        }
        return data
    }

    private struct SharedSecretCreated: Decodable {
        let version: UInt32
    }

    private struct EnvFileCreated: Decodable {
        let version: UInt32
    }

}

enum ControlClientError: LocalizedError {
    case socketPathTooLong
    case requestTooLarge
    case systemCall(String, Int32)
    case responseMismatch(expected: UInt64, actual: UInt64)
    case invalidResponse
    case missingResult(String)
    case unexpectedResult(expected: String, actual: String)
    case daemon(code: String, message: String)

    var errorDescription: String? {
        switch self {
        case .socketPathTooLong: "The daemon control socket path is too long"
        case .requestTooLarge: "The daemon control request is too large"
        case .systemCall(let operation, let code):
            "Control socket \(operation) failed: \(String(cString: strerror(code)))"
        case .responseMismatch(let expected, let actual):
            "Daemon response id \(actual) does not match request \(expected)"
        case .invalidResponse: "The daemon returned an invalid control response"
        case .missingResult(let type): "The daemon response did not include \(type)"
        case .unexpectedResult(let expected, let actual):
            "Expected daemon result \(expected), received \(actual)"
        case .daemon(_, let message): message
        }
    }
}
