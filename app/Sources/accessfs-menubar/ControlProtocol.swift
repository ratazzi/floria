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
    let defaultEnvKey: String?
    let entries: [CatalogEntry]
    let source: CatalogResourceSource
    let detail: String?

    enum CodingKeys: String, CodingKey {
        case id, name, kind, shape, entries, source, detail
        case defaultEnvKey = "default_env_key"
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
    let resourceID: String?
    let position: Int64

    enum CodingKeys: String, CodingKey {
        case id, name, kind, path, position
        case environmentID = "environment_id"
        case resourceID = "resource_id"
    }
}

struct CatalogSnapshot: Codable, Sendable {
    let projects: [CatalogProject]
    let environments: [CatalogEnvironment]
    let resources: [CatalogResource]
    let bindings: [CatalogBinding]
    let surfaces: [CatalogSurface]
}

enum ControlCommand: Sendable {
    case snapshot
    case sharedSecretCreate(resourceID: String, name: String, defaultEnvKey: String?, value: String)
    case envFileCreate(resourceID: String, name: String, value: String)
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
        case .snapshot:
            return try encoder.encode(ControlRequestWithoutParams(requestID: requestID, method: method))
        case .sharedSecretCreate(let resourceID, let name, let defaultEnvKey, let value):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: SharedSecretCreateParams(
                        resourceID: resourceID, name: name, defaultEnvKey: defaultEnvKey,
                        value: value)))
        case .envFileCreate(let resourceID, let name, let value):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: EnvFileCreateParams(
                        resourceID: resourceID, name: name, value: value)))
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

private struct EnvFileCreateParams: Encodable {
    let resourceID: String
    let name: String
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
