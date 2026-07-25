import Foundation

enum RuntimePolicyMode: String, Codable, Sendable {
    case normal
    case auditOnly = "audit_only"
}

struct RuntimePolicyStatus: Codable, Equatable, Sendable {
    let mode: RuntimePolicyMode
    let expiresAt: Int64?

    static let normal = RuntimePolicyStatus(mode: .normal, expiresAt: nil)

    enum CodingKeys: String, CodingKey {
        case mode
        case expiresAt = "expires_at"
    }

    var expirationDate: Date? {
        expiresAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    func isAuditOnly(at date: Date = Date()) -> Bool {
        guard mode == .auditOnly else { return false }
        return expirationDate.map { $0 > date } ?? true
    }
}

struct ItemLink: Codable, Hashable, Sendable {
    let label: String
    let url: String
}

struct ItemMetadata: Codable, Hashable, Sendable {
    let note: String?
    let links: [ItemLink]

    static let empty = ItemMetadata(note: nil, links: [])

    private enum CodingKeys: String, CodingKey { case note, links }

    init(note: String?, links: [ItemLink]) {
        self.note = note
        self.links = links
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        note = try container.decodeIfPresent(String.self, forKey: .note)
        links = try container.decodeIfPresent([ItemLink].self, forKey: .links) ?? []
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(note, forKey: .note)
        try container.encode(links, forKey: .links)
    }
}

struct CatalogProject: Codable, Sendable {
    let id: String
    let name: String
    let path: String
}

struct CatalogEnvironment: Codable, Sendable {
    let id: String
    let projectID: String
    let name: String
    let position: Int64

    enum CodingKeys: String, CodingKey {
        case id, name, position
        case projectID = "project_id"
    }
}

struct CatalogEntry: Codable, Sendable {
    let address: String
    let label: String
    let key: String?
    let sensitive: Bool
}

struct CatalogResourceSource: Codable, Sendable {
    let type: String
    let secretID: String?
    let value: String?
    let argv: [String]?
    let endpoint: String?

    enum CodingKeys: String, CodingKey {
        case type, value, argv, endpoint
        case secretID = "secret_id"
    }


    static func socket(_ endpoint: String) -> CatalogResourceSource {
        CatalogResourceSource(
            type: "socket", secretID: nil, value: nil, argv: nil, endpoint: endpoint)
    }
}

struct CatalogResource: Codable, Sendable {
    let id: String
    let name: String
    let kind: String
    let shape: String
    let codec: String
    let defaultEnvKey: String?
    let entries: [CatalogEntry]
    let source: CatalogResourceSource
    let enforcement: String
    let metadata: ItemMetadata

    enum CodingKeys: String, CodingKey {
        case id, name, kind, shape, codec, entries, source, enforcement, metadata
        case defaultEnvKey = "default_env_key"
    }
}

struct CatalogSurfaceInput: Codable, Sendable {
    let type: String
    let bindingIDs: [String]?
    let resourceID: String?
    let route: CatalogSshRoute?

    enum CodingKeys: String, CodingKey {
        case type
        case bindingIDs = "binding_ids"
        case resourceID = "resource_id"
        case route
    }

    static func bindings(_ ids: [String]) -> CatalogSurfaceInput {
        CatalogSurfaceInput(type: "bindings", bindingIDs: ids, resourceID: nil, route: nil)
    }

    static func resource(_ id: String) -> CatalogSurfaceInput {
        CatalogSurfaceInput(type: "resource", bindingIDs: nil, resourceID: id, route: nil)
    }

    static func sshAgent(_ ids: [String], route: CatalogSshRoute?) -> CatalogSurfaceInput {
        CatalogSurfaceInput(
            type: "ssh_agent", bindingIDs: ids, resourceID: nil, route: route)
    }
}

struct CatalogSshRoute: Codable, Hashable, Sendable {
    let hostPatterns: [String]
    let hostname: String?
    let user: String?
    let port: UInt16?
    let forwardAgent: Bool

    enum CodingKeys: String, CodingKey {
        case hostname, user, port
        case hostPatterns = "host_patterns"
        case forwardAgent = "forward_agent"
    }
}

struct CatalogEntrySelection: Codable, Sendable {
    let type: String
    let addresses: [String]?

    static let all = CatalogEntrySelection(type: "all", addresses: nil)

    static func entries(_ addresses: [String]) -> CatalogEntrySelection {
        CatalogEntrySelection(type: "entries", addresses: addresses)
    }
}

struct CatalogBindingScope: Codable, Sendable {
    let type: String
    let environmentID: String?

    enum CodingKeys: String, CodingKey {
        case type
        case environmentID = "environment_id"
    }

    static let common = CatalogBindingScope(type: "common", environmentID: nil)

    static func environment(_ id: String) -> CatalogBindingScope {
        CatalogBindingScope(type: "environment", environmentID: id)
    }
}

struct CatalogBinding: Codable, Sendable {
    let id: String
    let projectID: String
    let scope: CatalogBindingScope
    let resourceID: String
    let selection: CatalogEntrySelection
    let keyOverride: String?
    let enabled: Bool
    let allowOverride: Bool
    let position: Int64

    enum CodingKeys: String, CodingKey {
        case id, scope, selection, enabled, position
        case projectID = "project_id"
        case resourceID = "resource_id"
        case keyOverride = "key_override"
        case allowOverride = "allow_override"
    }
}

struct CatalogSurface: Codable, Sendable {
    let id: String
    let environmentID: String
    let name: String
    let kind: String
    let path: String
    let input: CatalogSurfaceInput
    let enforcement: String
    let position: Int64

    init(
        id: String, environmentID: String, name: String, kind: String, path: String,
        input: CatalogSurfaceInput, enforcement: String = WorkspaceSecurityLevel.confirmation.rawValue,
        position: Int64
    ) {
        self.id = id
        self.environmentID = environmentID
        self.name = name
        self.kind = kind
        self.path = path
        self.input = input
        self.enforcement = enforcement
        self.position = position
    }

    enum CodingKeys: String, CodingKey {
        case id, name, kind, path, input, enforcement, position
        case environmentID = "environment_id"
    }
}

struct CatalogSnapshot: Codable, Sendable {
    let projects: [CatalogProject]
    let environments: [CatalogEnvironment]
    let resources: [CatalogResource]
    let bindings: [CatalogBinding]
    let surfaces: [CatalogSurface]
}

struct DiscoveryPlan: Codable, Hashable, Sendable {
    let path: String
    let project: DiscoveredProject
    let files: [DiscoveredFile]
    let summary: DiscoverySummary
}

struct DiscoveredProject: Codable, Hashable, Sendable {
    let name: String
    let path: String
    let managedProjectID: String?

    enum CodingKeys: String, CodingKey {
        case name, path
        case managedProjectID = "managed_project_id"
    }
}

struct DiscoverySummary: Codable, Hashable, Sendable {
    let files: Int
    let entries: Int
    let newSecrets: Int
    let reusedSecrets: Int
    let missingReferenceEntries: Int
    let warnings: Int

    enum CodingKeys: String, CodingKey {
        case files, entries, warnings
        case newSecrets = "new_secrets"
        case reusedSecrets = "reused_secrets"
        case missingReferenceEntries = "missing_reference_entries"
    }
}

enum DiscoveredFileKind: String, Codable, Hashable, Sendable {
    case dotenv
    case direnv
    case mise
    case awsCredentials = "aws_credentials"
    case pgpass
    case sshPrivateKey = "ssh_private_key"
}

enum DiscoveredFileAction: String, Codable, Hashable, Sendable {
    case compose
    case protect
    case importSshIdentity = "import_ssh_identity"
    case reference
    case review
}

struct DiscoveredFile: Codable, Hashable, Sendable, Identifiable {
    var id: String { path }
    let path: String
    let relativePath: String
    let kind: DiscoveredFileKind
    let codec: String
    let environment: String?
    let tags: [String]
    let entries: [DiscoveredEntry]
    let warnings: [DiscoveryWarning]
    let action: DiscoveredFileAction

    enum CodingKeys: String, CodingKey {
        case path, kind, codec, environment, tags, entries, warnings, action
        case relativePath = "relative_path"
    }
}

struct DiscoveredEntry: Codable, Hashable, Sendable, Identifiable {
    var id: String { "\(address):\(key)" }
    let address: String
    let key: String
    let section: String?
    let action: DiscoveredEntryAction
}

struct DiscoveredEntryAction: Codable, Hashable, Sendable {
    let type: String
    let resourceID: String?
    let resourceName: String?
    let groupID: String?
    let matched: Bool?

    enum CodingKeys: String, CodingKey {
        case type, matched
        case resourceID = "resource_id"
        case resourceName = "resource_name"
        case groupID = "group_id"
    }
}

struct DiscoveryWarning: Codable, Hashable, Sendable, Identifiable {
    var id: String { "\(line ?? 0):\(message)" }
    let line: Int?
    let message: String
}

struct DiscoveryApplyResult: Codable, Hashable, Sendable {
    let projectID: String?
    let createdResources: Int
    let reusedResources: Int
    let protectedFiles: Int
    let importedSshIdentities: Int
    let files: [DiscoveryAppliedFile]

    enum CodingKeys: String, CodingKey {
        case files
        case projectID = "project_id"
        case createdResources = "created_resources"
        case reusedResources = "reused_resources"
        case protectedFiles = "protected_files"
        case importedSshIdentities = "imported_ssh_identities"
    }
}

struct DiscoveryAppliedFile: Codable, Hashable, Sendable, Identifiable {
    var id: String { path }
    let path: String
    let outcome: String
    let detail: String
}

struct DiscoverySeparateEntry: Codable, Hashable, Sendable {
    let path: String
    let address: String
}

struct DiscoveredSshIdentity: Codable, Hashable, Sendable {
    let address: String
    let fingerprint: String
    let comment: String
}

enum SshConfigIntegrationState: String, Codable, Sendable {
    case disabled
    case managed
    case external
    case needsRepair = "needs_repair"
}

struct SshConfigIntegrationStatus: Codable, Equatable, Sendable {
    let state: SshConfigIntegrationState
    let writable: Bool
    let userConfig: String
    let generatedConfig: String
    let includeLine: String

    enum CodingKeys: String, CodingKey {
        case state, writable
        case userConfig = "user_config"
        case generatedConfig = "generated_config"
        case includeLine = "include_line"
    }
}

struct CatalogProtectedFile: Codable, Sendable {
    let id: String
    let sourcePath: String
    let mode: UInt32
    let size: UInt64
    let currentVersion: UInt32
    let linked: Bool
    let enforcement: String
    let metadata: ItemMetadata

    enum CodingKeys: String, CodingKey {
        case id, mode, size, linked, enforcement, metadata
        case sourcePath = "source_path"
        case currentVersion = "current_version"
    }
}

struct CatalogProtectedFileVersion: Codable, Sendable {
    let version: UInt32
    let size: UInt64
    let created: String
    let note: String?
    let current: Bool
}

enum ControlCommand: Sendable {
    case policyModeGet
    case policyModeSet(mode: RuntimePolicyMode, durationSecs: UInt64?)
    case accessHistory(limit: Int)
    case snapshot
    case discover(path: String)
    case discoverApply(
        path: String, files: [String], separateEntries: [DiscoverySeparateEntry])
    case sshAgentDiscover(endpoint: String)
    case sshIdentityImport(
        resourceID: String, name: String, path: String, passphrase: String?,
        enforcement: String, metadata: ItemMetadata)
    case sshIdentityRemove(resourceID: String)
    case sshConfigStatus
    case sshConfigInstall
    case sshConfigRemove
    case protectedFiles
    case fileProtect(String)
    case protectedFileHistory(String)
    case protectedFileRollback(id: String, version: UInt32)
    case protectedFileMetadataUpdate(
        id: String, enforcement: String, metadata: ItemMetadata)
    case fileRestore(String)
    case sharedSecretCreate(
        resourceID: String, name: String, defaultEnvKey: String?, value: String,
        enforcement: String, metadata: ItemMetadata)
    case sharedSecretUpdate(
        resourceID: String, name: String, defaultEnvKey: String?, value: String?,
        enforcement: String, metadata: ItemMetadata
    )
    case sharedSecretRemove(resourceID: String)
    case envFileCreate(
        resourceID: String, name: String, codec: String, value: String,
        enforcement: String, metadata: ItemMetadata)
    case resourceMetadataUpdate(
        resourceID: String, name: String, enforcement: String, metadata: ItemMetadata)
    case resourceUpsert(CatalogResource)
    case resourceRemove(String)
    case projectCreate(CatalogProject, CatalogEnvironment, CatalogSurface)
    case projectUpsert(CatalogProject)
    case projectRemove(String)
    case environmentUpsert(CatalogEnvironment)
    case environmentRemove(String)
    case bindingUpsert(CatalogBinding)
    case bindingRemove(String)
    case surfaceUpsert(CatalogSurface)
    case surfaceRemove(String)

    var method: String {
        switch self {
        case .policyModeGet: "policy_mode_get"
        case .policyModeSet: "policy_mode_set"
        case .accessHistory: "access_history"
        case .snapshot: "snapshot"
        case .discover: "discover"
        case .discoverApply: "discover_apply"
        case .sshAgentDiscover: "ssh_agent_discover"
        case .sshIdentityImport: "ssh_identity_import"
        case .sshIdentityRemove: "ssh_identity_remove"
        case .sshConfigStatus: "ssh_config_status"
        case .sshConfigInstall: "ssh_config_install"
        case .sshConfigRemove: "ssh_config_remove"
        case .protectedFiles: "protected_files"
        case .fileProtect: "file_protect"
        case .protectedFileHistory: "protected_file_history"
        case .protectedFileRollback: "protected_file_rollback"
        case .protectedFileMetadataUpdate: "protected_file_metadata_update"
        case .fileRestore: "file_restore"
        case .sharedSecretCreate: "shared_secret_create"
        case .sharedSecretUpdate: "shared_secret_update"
        case .sharedSecretRemove: "shared_secret_remove"
        case .envFileCreate: "env_file_create"
        case .resourceMetadataUpdate: "resource_metadata_update"
        case .resourceUpsert: "resource_upsert"
        case .resourceRemove: "resource_remove"
        case .projectCreate: "project_create"
        case .projectUpsert: "project_upsert"
        case .projectRemove: "project_remove"
        case .environmentUpsert: "environment_upsert"
        case .environmentRemove: "environment_remove"
        case .bindingUpsert: "binding_upsert"
        case .bindingRemove: "binding_remove"
        case .surfaceUpsert: "surface_upsert"
        case .surfaceRemove: "surface_remove"
        }
    }

    func requestData(requestID: UInt64, encoder: JSONEncoder) throws -> Data {
        switch self {
        case .policyModeGet, .snapshot, .sshConfigStatus, .sshConfigInstall, .sshConfigRemove,
            .protectedFiles:
            return try encoder.encode(ControlRequestWithoutParams(requestID: requestID, method: method))
        case .policyModeSet(let mode, let durationSecs):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: PolicyModeSetParams(mode: mode, durationSecs: durationSecs)))
        case .accessHistory(let limit):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: AccessHistoryParams(limit: limit)))
        case .discover(let path):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: DiscoverParams(path: path)))
        case .discoverApply(let path, let files, let separateEntries):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: DiscoverApplyParams(
                        path: path, files: files, separateEntries: separateEntries)))
        case .sshAgentDiscover(let endpoint):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SshAgentDiscoverParams(endpoint: endpoint)))
        case .sshIdentityImport(
            let resourceID, let name, let path, let passphrase, let enforcement, let metadata):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SshIdentityImportParams(
                        resourceID: resourceID, name: name, path: path,
                        passphrase: passphrase, enforcement: enforcement, metadata: metadata)))
        case .sshIdentityRemove(let resourceID):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SshIdentityRemoveParams(resourceID: resourceID)))
        case .fileProtect(let path):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: FileProtectParams(path: path)))
        case .protectedFileHistory(let id), .fileRestore(let id):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProtectedFileIDParams(id: id)))
        case .protectedFileRollback(let id, let version):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProtectedFileRollbackParams(id: id, version: version)))
        case .protectedFileMetadataUpdate(let id, let enforcement, let metadata):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProtectedFileMetadataUpdateParams(
                        id: id, enforcement: enforcement, metadata: metadata)))
        case .sharedSecretCreate(
            let resourceID, let name, let defaultEnvKey, let value, let enforcement, let metadata):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SharedSecretCreateParams(
                        resourceID: resourceID, name: name, defaultEnvKey: defaultEnvKey,
                        value: value, enforcement: enforcement, metadata: metadata)))
        case .sharedSecretUpdate(
            let resourceID, let name, let defaultEnvKey, let value, let enforcement, let metadata):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SharedSecretUpdateParams(
                        resourceID: resourceID, name: name, defaultEnvKey: defaultEnvKey,
                        value: value, enforcement: enforcement, metadata: metadata)))
        case .sharedSecretRemove(let resourceID):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SharedSecretRemoveParams(resourceID: resourceID)))
        case .envFileCreate(
            let resourceID, let name, let codec, let value, let enforcement, let metadata):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: EnvFileCreateParams(
                        resourceID: resourceID, name: name, codec: codec, value: value,
                        enforcement: enforcement, metadata: metadata)))
        case .resourceMetadataUpdate(let resourceID, let name, let enforcement, let metadata):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ResourceMetadataUpdateParams(
                        resourceID: resourceID, name: name, enforcement: enforcement,
                        metadata: metadata)))
        case .resourceUpsert(let resource):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ResourceUpsertParams(resource: resource)))
        case .projectCreate(let project, let environment, let surface):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProjectCreateParams(
                        project: project, environment: environment, surface: surface)))
        case .projectUpsert(let project):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProjectUpsertParams(project: project)))
        case .projectRemove(let id), .environmentRemove(let id), .resourceRemove(let id),
            .bindingRemove(let id), .surfaceRemove(let id):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method, params: RemoveParams(id: id)))
        case .environmentUpsert(let environment):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: EnvironmentUpsertParams(environment: environment)))
        case .bindingUpsert(let binding):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: BindingUpsertParams(binding: binding)))
        case .surfaceUpsert(let surface):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SurfaceUpsertParams(surface: surface)))
        }
    }
}

private struct PolicyModeSetParams: Encodable {
    let mode: RuntimePolicyMode
    let durationSecs: UInt64?
}

private struct AccessHistoryParams: Encodable { let limit: Int }
private struct DiscoverParams: Encodable { let path: String }
private struct DiscoverApplyParams: Encodable {
    let path: String
    let files: [String]
    let separateEntries: [DiscoverySeparateEntry]
}
private struct SshAgentDiscoverParams: Encodable { let endpoint: String }

private struct SshIdentityImportParams: Encodable {
    let resourceID: String
    let name: String
    let path: String
    let passphrase: String?
    let enforcement: String
    let metadata: ItemMetadata
}

private struct SshIdentityRemoveParams: Encodable { let resourceID: String }

private struct ControlRequestWithoutParams: Encodable {
    let requestID: UInt64
    let method: String
}

private struct ControlRequest<Params: Encodable>: Encodable {
    let requestID: UInt64
    let method: String
    let params: Params
}

private struct SharedSecretCreateParams: Encodable {
    let resourceID: String
    let name: String
    let defaultEnvKey: String?
    let value: String
    let enforcement: String
    let metadata: ItemMetadata
}

private struct SharedSecretUpdateParams: Encodable {
    let resourceID: String
    let name: String
    let defaultEnvKey: String?
    let value: String?
    let enforcement: String
    let metadata: ItemMetadata
}

private struct SharedSecretRemoveParams: Encodable { let resourceID: String }

private struct FileProtectParams: Encodable { let path: String }
private struct ProtectedFileIDParams: Encodable { let id: String }
private struct ProtectedFileRollbackParams: Encodable {
    let id: String
    let version: UInt32
}
private struct ProtectedFileMetadataUpdateParams: Encodable {
    let id: String
    let enforcement: String
    let metadata: ItemMetadata
}

private struct EnvFileCreateParams: Encodable {
    let resourceID: String
    let name: String
    let codec: String
    let value: String
    let enforcement: String
    let metadata: ItemMetadata
}

private struct ResourceMetadataUpdateParams: Encodable {
    let resourceID: String
    let name: String
    let enforcement: String
    let metadata: ItemMetadata
}

private struct ResourceUpsertParams: Encodable { let resource: CatalogResource }

private struct ProjectUpsertParams: Encodable { let project: CatalogProject }
private struct RemoveParams: Encodable { let id: String }
private struct ProjectCreateParams: Encodable {
    let project: CatalogProject
    let environment: CatalogEnvironment
    let surface: CatalogSurface
}
private struct EnvironmentUpsertParams: Encodable { let environment: CatalogEnvironment }
private struct BindingUpsertParams: Encodable { let binding: CatalogBinding }
private struct SurfaceUpsertParams: Encodable { let surface: CatalogSurface }

struct ControlResponseEnvelope<Value: Decodable>: Decodable {
    struct Result: Decodable {
        let type: String
        let value: Value?
    }

    struct ErrorBody: Decodable {
        let code: String
        let message: String
    }

    let requestID: UInt64
    let status: String
    let result: Result?
    let error: ErrorBody?

    enum CodingKeys: String, CodingKey {
        case status, result, error
        case requestID = "request_id"
    }
}

struct EmptyControlValue: Decodable {}
