import Darwin
import Foundation

final class ControlClient: @unchecked Sendable {
    private let socketPath: String
    private let queue = DispatchQueue(label: "dev.floria.hola.ac.control", qos: .userInitiated)
    private var nextRequestID: UInt64 = 1

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    func policyMode() async throws -> RuntimePolicyStatus {
        guard let status: RuntimePolicyStatus = try await request(
            .policyModeGet, expecting: "policy_mode", as: RuntimePolicyStatus.self)
        else {
            throw ControlClientError.missingResult("policy_mode")
        }
        return status
    }

    func setPolicyMode(
        _ mode: RuntimePolicyMode, durationSecs: UInt64?
    ) async throws -> RuntimePolicyStatus {
        guard let status: RuntimePolicyStatus = try await request(
            .policyModeSet(mode: mode, durationSecs: durationSecs),
            expecting: "policy_mode", as: RuntimePolicyStatus.self)
        else {
            throw ControlClientError.missingResult("policy_mode")
        }
        return status
    }

    func activeGrants() async throws -> [ActiveGrant] {
        guard let grants: [ActiveGrant] = try await request(
            .grantList, expecting: "active_grants", as: [ActiveGrant].self)
        else {
            throw ControlClientError.missingResult("active_grants")
        }
        return grants
    }

    func revokeGrant(id: String) async throws -> [ActiveGrant] {
        guard let grants: [ActiveGrant] = try await request(
            .grantRevoke(id: id), expecting: "active_grants", as: [ActiveGrant].self)
        else {
            throw ControlClientError.missingResult("active_grants")
        }
        return grants
    }

    func clearGrants() async throws -> [ActiveGrant] {
        guard let grants: [ActiveGrant] = try await request(
            .grantClear, expecting: "active_grants", as: [ActiveGrant].self)
        else {
            throw ControlClientError.missingResult("active_grants")
        }
        return grants
    }

    func accessHistory(limit: Int) async throws -> [AccessEventMsg] {
        guard let events: [AccessEventMsg] = try await request(
            .accessHistory(limit: limit), expecting: "access_history",
            as: [AccessEventMsg].self)
        else {
            throw ControlClientError.missingResult("access_history")
        }
        return events
    }

    func snapshot() async throws -> CatalogSnapshot {
        guard let snapshot: CatalogSnapshot = try await request(
            .snapshot, expecting: "snapshot", as: CatalogSnapshot.self)
        else {
            throw ControlClientError.missingResult("snapshot")
        }
        return snapshot
    }

    func discover(path: String) async throws -> DiscoveryPlan {
        try await discover(paths: [path])
    }

    func discover(paths: [String]) async throws -> DiscoveryPlan {
        guard let plan: DiscoveryPlan = try await request(
            .discover(paths: paths), expecting: "discovery", as: DiscoveryPlan.self)
        else {
            throw ControlClientError.missingResult("discovery")
        }
        return plan
    }

    func startDiscovery(paths: [String]) async throws -> DiscoveryJobStatus {
        guard let status: DiscoveryJobStatus = try await request(
            .discoverStart(paths: paths),
            expecting: "discovery_job",
            as: DiscoveryJobStatus.self)
        else {
            throw ControlClientError.missingResult("discovery_job")
        }
        return status
    }

    func discoveryStatus(id: String) async throws -> DiscoveryJobStatus {
        guard let status: DiscoveryJobStatus = try await request(
            .discoverStatus(id: id),
            expecting: "discovery_job",
            as: DiscoveryJobStatus.self)
        else {
            throw ControlClientError.missingResult("discovery_job")
        }
        return status
    }

    func cancelDiscovery(id: String) async throws -> DiscoveryJobStatus {
        guard let status: DiscoveryJobStatus = try await request(
            .discoverCancel(id: id),
            expecting: "discovery_job",
            as: DiscoveryJobStatus.self)
        else {
            throw ControlClientError.missingResult("discovery_job")
        }
        return status
    }

    func applyDiscovery(
        paths: [String], imports: [DiscoveryImport],
        separateEntries: [DiscoverySeparateEntry],
        promoteEntries: [DiscoverySeparateEntry] = [],
        demoteEntries: [DiscoverySeparateEntry] = []
    ) async throws -> DiscoveryApplyResult {
        guard let result: DiscoveryApplyResult = try await request(
            .discoverApply(
                paths: paths, imports: imports,
                separateEntries: separateEntries,
                promoteEntries: promoteEntries, demoteEntries: demoteEntries),
            expecting: "discovery_applied",
            as: DiscoveryApplyResult.self)
        else {
            throw ControlClientError.missingResult("discovery_applied")
        }
        return result
    }

    func resolveDiscoveryReference(
        surfaceID: String, key: String, source: DiscoveryReferenceSource
    ) async throws -> DiscoveryReferenceResolution {
        guard let result: DiscoveryReferenceResolution = try await request(
            .discoverReferenceResolve(surfaceID: surfaceID, key: key, source: source),
            expecting: "discovery_reference_resolved",
            as: DiscoveryReferenceResolution.self)
        else {
            throw ControlClientError.missingResult("discovery_reference_resolved")
        }
        return result
    }

    func discoverProjectCheckouts(projectID: String) async throws -> ProjectCheckoutDiscovery {
        guard let result: ProjectCheckoutDiscovery = try await request(
            .projectCheckoutDiscover(projectID: projectID),
            expecting: "project_checkout_discovery",
            as: ProjectCheckoutDiscovery.self)
        else {
            throw ControlClientError.missingResult("project_checkout_discovery")
        }
        return result
    }

    func projectCheckoutInventory() async throws -> ProjectCheckoutInventory {
        guard let result: ProjectCheckoutInventory = try await request(
            .projectCheckoutInventory,
            expecting: "project_checkout_inventory",
            as: ProjectCheckoutInventory.self)
        else {
            throw ControlClientError.missingResult("project_checkout_inventory")
        }
        return result
    }

    func upsertProjectCheckout(_ checkout: CatalogProjectCheckout) async throws {
        try await requestEmpty(.projectCheckoutUpsert(checkout))
    }

    func removeProjectCheckout(_ id: String) async throws {
        try await requestEmpty(.projectCheckoutRemove(id: id))
    }

    func discoverSshIdentities(endpoint: String) async throws -> [DiscoveredSshIdentity] {
        guard let identities: [DiscoveredSshIdentity] = try await request(
            .sshAgentDiscover(endpoint: endpoint), expecting: "ssh_agent_identities",
            as: [DiscoveredSshIdentity].self)
        else {
            throw ControlClientError.missingResult("ssh_agent_identities")
        }
        return identities
    }

    func importSshIdentity(
        resourceID: String, name: String, path: String, passphrase: String?,
        enforcement: String, metadata: ItemMetadata
    ) async throws -> CatalogResource {
        guard let result: SshIdentityCreated = try await request(
            .sshIdentityImport(
                resourceID: resourceID, name: name, path: path, passphrase: passphrase,
                enforcement: enforcement, metadata: metadata),
            expecting: "ssh_identity_created", as: SshIdentityCreated.self)
        else {
            throw ControlClientError.missingResult("ssh_identity_created")
        }
        return result.resource
    }

    func removeSshIdentity(resourceID: String) async throws {
        try await requestEmpty(.sshIdentityRemove(resourceID: resourceID))
    }

    func sshConfigStatus() async throws -> SshConfigIntegrationStatus {
        try await sshConfigRequest(.sshConfigStatus)
    }

    func installSshConfig() async throws -> SshConfigIntegrationStatus {
        try await sshConfigRequest(.sshConfigInstall)
    }

    func removeSshConfig() async throws -> SshConfigIntegrationStatus {
        try await sshConfigRequest(.sshConfigRemove)
    }

    private func sshConfigRequest(_ command: ControlCommand) async throws
        -> SshConfigIntegrationStatus
    {
        guard let status: SshConfigIntegrationStatus = try await request(
            command, expecting: "ssh_config", as: SshConfigIntegrationStatus.self)
        else {
            throw ControlClientError.missingResult("ssh_config")
        }
        return status
    }

    func protectedFiles() async throws -> [CatalogProtectedFile] {
        guard let files: [CatalogProtectedFile] = try await request(
            .protectedFiles, expecting: "protected_files", as: [CatalogProtectedFile].self)
        else {
            throw ControlClientError.missingResult("protected_files")
        }
        return files
    }

    func protectFile(at path: String) async throws -> CatalogProtectedFile {
        guard let result: FileProtected = try await request(
            .fileProtect(path), expecting: "file_protected", as: FileProtected.self)
        else {
            throw ControlClientError.missingResult("file_protected")
        }
        return result.file
    }

    func protectedFileHistory(_ id: String) async throws -> [CatalogProtectedFileVersion] {
        guard let result: ProtectedFileHistory = try await request(
            .protectedFileHistory(id), expecting: "protected_file_history",
            as: ProtectedFileHistory.self)
        else {
            throw ControlClientError.missingResult("protected_file_history")
        }
        return result.versions
    }

    func rollbackProtectedFile(_ id: String, to version: UInt32) async throws
        -> CatalogProtectedFile
    {
        guard let result: ProtectedFileResult = try await request(
            .protectedFileRollback(id: id, version: version),
            expecting: "protected_file_rolled_back", as: ProtectedFileResult.self)
        else {
            throw ControlClientError.missingResult("protected_file_rolled_back")
        }
        return result.file
    }

    func updateProtectedFileMetadata(
        _ id: String, enforcement: String, metadata: ItemMetadata
    ) async throws {
        try await requestEmpty(
            .protectedFileMetadataUpdate(
                id: id, enforcement: enforcement, metadata: metadata))
    }

    func configureManagedFile(
        _ id: String, projectID: String, environmentID: String?
    ) async throws -> CatalogSurface {
        guard let result: ManagedFileConfigured = try await request(
            .managedFileConfigure(
                id: id, projectID: projectID, environmentID: environmentID),
            expecting: "managed_file_configured", as: ManagedFileConfigured.self)
        else {
            throw ControlClientError.missingResult("managed_file_configured")
        }
        return result.surface
    }

    func restoreFile(_ id: String) async throws -> Bool {
        guard let result: FileRestored = try await request(
            .fileRestore(id), expecting: "file_restored", as: FileRestored.self)
        else {
            throw ControlClientError.missingResult("file_restored")
        }
        return result.storageDeleted
    }

    func restoreManagedFile(_ id: String) async throws {
        guard let _: FileRestored = try await request(
            .managedFileRestore(id), expecting: "file_restored", as: FileRestored.self)
        else {
            throw ControlClientError.missingResult("file_restored")
        }
    }

    func createSharedSecret(
        resourceID: String, name: String, defaultEnvKey: String?, value: String,
        enforcement: String, metadata: ItemMetadata
    ) async throws {
        let _: SharedSecretCreated? = try await request(
            .sharedSecretCreate(
                resourceID: resourceID, name: name, defaultEnvKey: defaultEnvKey, value: value,
                enforcement: enforcement, metadata: metadata),
            expecting: "shared_secret_created", as: SharedSecretCreated.self)
    }

    func updateSharedSecret(
        resourceID: String, name: String, defaultEnvKey: String?, value: String?,
        enforcement: String, metadata: ItemMetadata
    ) async throws {
        try await requestEmpty(
            .sharedSecretUpdate(
                resourceID: resourceID, name: name, defaultEnvKey: defaultEnvKey,
                value: value, enforcement: enforcement, metadata: metadata))
    }

    func deleteSharedSecret(resourceID: String) async throws {
        try await requestEmpty(.sharedSecretRemove(resourceID: resourceID))
    }

    func createEnvFile(
        resourceID: String, name: String, codec: WorkspaceResourceCodec, value: String,
        enforcement: String, metadata: ItemMetadata
    ) async throws {
        let _: EnvFileCreated? = try await request(
            .envFileCreate(
                resourceID: resourceID, name: name, codec: codec.rawValue, value: value,
                enforcement: enforcement, metadata: metadata),
            expecting: "env_file_created", as: EnvFileCreated.self)
    }

    func updateResourceMetadata(
        resourceID: String, name: String, enforcement: String, metadata: ItemMetadata
    ) async throws {
        try await requestEmpty(
            .resourceMetadataUpdate(
                resourceID: resourceID, name: name, enforcement: enforcement,
                metadata: metadata))
    }

    func upsertResource(_ resource: CatalogResource, endpoint: String? = nil) async throws {
        try await requestEmpty(.resourceUpsert(resource, endpoint: endpoint))
    }

    func removeResource(_ id: String) async throws {
        try await requestEmpty(.resourceRemove(id))
    }

    func upsertProject(_ project: CatalogProject) async throws {
        try await requestEmpty(.projectUpsert(project))
    }

    func setProjectDefaultEnvironment(projectID: String, environmentID: String?) async throws {
        try await requestEmpty(
            .projectDefaultEnvironmentSet(projectID: projectID, environmentID: environmentID))
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

    private struct SshIdentityCreated: Decodable {
        let resource: CatalogResource
    }

    private struct FileProtected: Decodable {
        let file: CatalogProtectedFile
        let created: Bool
    }

    private struct ProtectedFileResult: Decodable {
        let file: CatalogProtectedFile
    }

    private struct ProtectedFileHistory: Decodable {
        let id: String
        let versions: [CatalogProtectedFileVersion]
    }

    private struct ManagedFileConfigured: Decodable {
        let surface: CatalogSurface
    }

    private struct FileRestored: Decodable {
        let path: String
        let storageDeleted: Bool

        enum CodingKeys: String, CodingKey {
            case path
            case storageDeleted = "storage_deleted"
        }
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
