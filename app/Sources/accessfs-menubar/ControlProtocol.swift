import Foundation

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
    let detail: String?

    enum CodingKeys: String, CodingKey {
        case id, name, kind, shape, codec, entries, source, detail
        case defaultEnvKey = "default_env_key"
    }
}

struct CatalogSurfaceInput: Codable, Sendable {
    let type: String
    let bindingIDs: [String]?
    let resourceID: String?

    enum CodingKeys: String, CodingKey {
        case type
        case bindingIDs = "binding_ids"
        case resourceID = "resource_id"
    }

    static func bindings(_ ids: [String]) -> CatalogSurfaceInput {
        CatalogSurfaceInput(type: "bindings", bindingIDs: ids, resourceID: nil)
    }

    static func resource(_ id: String) -> CatalogSurfaceInput {
        CatalogSurfaceInput(type: "resource", bindingIDs: nil, resourceID: id)
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
    let position: Int64

    enum CodingKeys: String, CodingKey {
        case id, name, kind, path, input, position
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

struct CatalogProtectedFile: Codable, Sendable {
    let id: String
    let sourcePath: String
    let mode: UInt32
    let size: UInt64
    let currentVersion: UInt32
    let linked: Bool

    enum CodingKeys: String, CodingKey {
        case id, mode, size, linked
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
    case snapshot
    case protectedFiles
    case fileProtect(String)
    case protectedFileHistory(String)
    case protectedFileRollback(id: String, version: UInt32)
    case fileRestore(String)
    case sharedSecretCreate(resourceID: String, name: String, defaultEnvKey: String?, value: String)
    case envFileCreate(resourceID: String, name: String, codec: String, value: String)
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
        case .snapshot: "snapshot"
        case .protectedFiles: "protected_files"
        case .fileProtect: "file_protect"
        case .protectedFileHistory: "protected_file_history"
        case .protectedFileRollback: "protected_file_rollback"
        case .fileRestore: "file_restore"
        case .sharedSecretCreate: "shared_secret_create"
        case .envFileCreate: "env_file_create"
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
        case .snapshot, .protectedFiles:
            return try encoder.encode(ControlRequestWithoutParams(requestID: requestID, method: method))
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
        case .sharedSecretCreate(let resourceID, let name, let defaultEnvKey, let value):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SharedSecretCreateParams(
                        resourceID: resourceID, name: name, defaultEnvKey: defaultEnvKey,
                        value: value)))
        case .envFileCreate(let resourceID, let name, let codec, let value):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: EnvFileCreateParams(
                        resourceID: resourceID, name: name, codec: codec, value: value)))
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
        case .projectRemove(let id), .environmentRemove(let id), .bindingRemove(let id),
            .surfaceRemove(let id):
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
}

private struct FileProtectParams: Encodable { let path: String }
private struct ProtectedFileIDParams: Encodable { let id: String }
private struct ProtectedFileRollbackParams: Encodable {
    let id: String
    let version: UInt32
}

private struct EnvFileCreateParams: Encodable {
    let resourceID: String
    let name: String
    let codec: String
    let value: String
}

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
