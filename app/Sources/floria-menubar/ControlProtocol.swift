import Foundation

let supportedControlProtocolVersion: UInt32 = 11

struct ControlServerInfo: Decodable, Equatable, Sendable {
    let protocolVersion: UInt32?
    let daemonVersion: String?
    let schemaVersion: Int64
    let minimumSchemaVersion: Int64
    let storeFormatVersion: UInt32
    let minimumStoreFormatVersion: UInt32

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case daemonVersion = "daemon_version"
        case schemaVersion = "schema_version"
        case minimumSchemaVersion = "minimum_schema_version"
        case storeFormatVersion = "store_format_version"
        case minimumStoreFormatVersion = "minimum_store_format_version"
    }
}

enum SystemHealthStatus: String, Codable, Comparable, Sendable {
    case healthy
    case warning
    case error

    static func < (lhs: SystemHealthStatus, rhs: SystemHealthStatus) -> Bool {
        let rank: [SystemHealthStatus: Int] = [.healthy: 0, .warning: 1, .error: 2]
        return rank[lhs, default: 0] < rank[rhs, default: 0]
    }
}

struct SystemHealthCheck: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let status: SystemHealthStatus
    let title: String
    let message: String
    let guidance: String?
}

struct SystemHealthReport: Codable, Equatable, Sendable {
    let status: SystemHealthStatus
    let checks: [SystemHealthCheck]

    var issues: [SystemHealthCheck] {
        checks.filter { $0.status != .healthy }
    }

    var hasIssues: Bool {
        !issues.isEmpty
    }
}

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

struct ActiveGrant: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let subject: String
    let object: String
    let operation: String
    let enforcement: String
    let expiresAt: Int64
    let client: String
    let executable: String?
    let bundleID: String?
    let target: String

    enum CodingKeys: String, CodingKey {
        case id, subject, object, operation, enforcement, client, executable, target
        case expiresAt = "expires_at"
        case bundleID = "bundle_id"
    }

    var expirationDate: Date {
        Date(timeIntervalSince1970: TimeInterval(expiresAt))
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
    var defaultEnvironmentID: String? = nil

    enum CodingKeys: String, CodingKey {
        case id, name, path
        case defaultEnvironmentID = "default_environment_id"
    }
}

enum CatalogProjectCheckoutKind: String, Codable, Sendable {
    case primary
    case worktree
}

struct CatalogProjectCheckout: Codable, Hashable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let path: String
    let environmentID: String?
    let kind: CatalogProjectCheckoutKind
    let gitCommonDir: String?

    enum CodingKeys: String, CodingKey {
        case id, path, kind
        case projectID = "project_id"
        case environmentID = "environment_id"
        case gitCommonDir = "git_common_dir"
    }
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

    enum CodingKeys: String, CodingKey {
        case type, value, argv
        case secretID = "secret_id"
    }

    static var socket: CatalogResourceSource {
        CatalogResourceSource(
            type: "socket", secretID: nil, value: nil, argv: nil)
    }
}

struct CatalogOriginSource: Codable, Hashable, Sendable {
    let path: String
    let projectID: String?
    let environment: String?
    let importedAt: String

    enum CodingKeys: String, CodingKey {
        case path, environment
        case projectID = "project_id"
        case importedAt = "imported_at"
    }
}

struct CatalogResourceOrigin: Codable, Hashable, Sendable {
    let kind: String
    let sources: [CatalogOriginSource]

    private enum CodingKeys: String, CodingKey { case kind, sources }

    init(kind: String, sources: [CatalogOriginSource]) {
        self.kind = kind
        self.sources = sources
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        kind = try container.decodeIfPresent(String.self, forKey: .kind) ?? "unknown"
        sources = try container.decodeIfPresent([CatalogOriginSource].self, forKey: .sources) ?? []
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
    let origin: CatalogResourceOrigin?

    enum CodingKeys: String, CodingKey {
        case id, name, kind, shape, codec, entries, source, enforcement, metadata, origin
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
    let path: String?
    let input: CatalogSurfaceInput
    let enforcement: String
    let position: Int64

    init(
        id: String, environmentID: String, name: String, kind: String, path: String?,
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
    let checkouts: [CatalogProjectCheckout]
    let environments: [CatalogEnvironment]
    let resources: [CatalogResource]
    let endpoints: [String: String]
    let bindings: [CatalogBinding]
    let surfaces: [CatalogSurface]
    let managedLinks: [CatalogManagedLink]

    private enum CodingKeys: String, CodingKey {
        case projects, checkouts, environments, resources, endpoints, bindings, surfaces
        case managedLinks = "managed_links"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        projects = try container.decode([CatalogProject].self, forKey: .projects)
        checkouts =
            try container.decodeIfPresent([CatalogProjectCheckout].self, forKey: .checkouts) ?? []
        environments = try container.decode([CatalogEnvironment].self, forKey: .environments)
        resources = try container.decode([CatalogResource].self, forKey: .resources)
        endpoints =
            try container.decodeIfPresent([String: String].self, forKey: .endpoints) ?? [:]
        bindings = try container.decode([CatalogBinding].self, forKey: .bindings)
        surfaces = try container.decode([CatalogSurface].self, forKey: .surfaces)
        managedLinks =
            try container.decodeIfPresent([CatalogManagedLink].self, forKey: .managedLinks) ?? []
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(projects, forKey: .projects)
        try container.encode(checkouts, forKey: .checkouts)
        try container.encode(environments, forKey: .environments)
        try container.encode(resources, forKey: .resources)
        try container.encode(endpoints, forKey: .endpoints)
        try container.encode(bindings, forKey: .bindings)
        try container.encode(surfaces, forKey: .surfaces)
        try container.encode(managedLinks, forKey: .managedLinks)
    }
}

struct CatalogManagedLink: Codable, Hashable, Sendable {
    let path: String
    let status: ManagedLinkStatus
}

struct ProjectCheckoutDiscovery: Codable, Hashable, Sendable {
    let projectID: String
    let commonDir: String
    let checkouts: [ProjectCheckoutCandidate]

    enum CodingKeys: String, CodingKey {
        case checkouts
        case projectID = "project_id"
        case commonDir = "common_dir"
    }
}

struct ProjectCheckoutInventory: Codable, Hashable, Sendable {
    let revision: UInt64
    let projects: [ProjectCheckoutDiscovery]
}

struct ProjectCheckoutCandidate: Codable, Hashable, Identifiable, Sendable {
    let path: String
    let gitPrimary: Bool
    let managedCheckoutID: String?
    let linkIssues: [String]

    var id: String { path }
    var needsAttention: Bool { !linkIssues.isEmpty }

    enum CodingKeys: String, CodingKey {
        case path
        case gitPrimary = "git_primary"
        case managedCheckoutID = "managed_checkout_id"
        case linkIssues = "link_issues"
    }

    init(
        path: String,
        gitPrimary: Bool,
        managedCheckoutID: String?,
        linkIssues: [String] = []
    ) {
        self.path = path
        self.gitPrimary = gitPrimary
        self.managedCheckoutID = managedCheckoutID
        self.linkIssues = linkIssues
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        path = try container.decode(String.self, forKey: .path)
        gitPrimary = try container.decode(Bool.self, forKey: .gitPrimary)
        managedCheckoutID = try container.decodeIfPresent(
            String.self, forKey: .managedCheckoutID)
        linkIssues = try container.decodeIfPresent(
            [String].self, forKey: .linkIssues) ?? []
    }
}

struct DiscoveryPlan: Codable, Hashable, Sendable {
    let paths: [String]
    let projects: [DiscoveredProject]
    let files: [DiscoveredFile]
    let summary: DiscoverySummary
    let managedItems: [DiscoveryManagedItem]

    enum CodingKeys: String, CodingKey {
        case paths, projects, files, summary
        case managedItems = "managed_items"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        paths = try container.decode([String].self, forKey: .paths)
        projects = try container.decode([DiscoveredProject].self, forKey: .projects)
        files = try container.decode([DiscoveredFile].self, forKey: .files)
        summary = try container.decode(DiscoverySummary.self, forKey: .summary)
        managedItems =
            try container.decodeIfPresent([DiscoveryManagedItem].self, forKey: .managedItems) ?? []
    }
}

struct DiscoveryJobStatus: Codable, Hashable, Identifiable, Sendable {
    let id: String
    let state: DiscoveryJobState
    let progress: DiscoveryJobProgress
    let plan: DiscoveryPlan?
    let error: String?
}

enum DiscoveryJobState: String, Codable, Hashable, Sendable {
    case queued
    case running
    case cancelling
    case completed
    case cancelled
    case failed

    var isTerminal: Bool {
        self == .completed || self == .cancelled || self == .failed
    }
}

enum DiscoveryJobPhase: String, Codable, Hashable, Sendable {
    case starting
    case projectCandidates = "project_candidates"
    case candidateFiles = "candidate_files"
    case parsingFiles = "parsing_files"
    case reconciling
    case complete
}

struct DiscoveryJobProgress: Codable, Hashable, Sendable {
    let phase: DiscoveryJobPhase
    let directoriesScanned: Int
    let candidateFiles: Int
    let projectCandidates: Int
    let filesParsed: Int

    enum CodingKeys: String, CodingKey {
        case phase
        case directoriesScanned = "directories_scanned"
        case candidateFiles = "candidate_files"
        case projectCandidates = "project_candidates"
        case filesParsed = "files_parsed"
    }
}

struct DiscoveryManagedItem: Codable, Hashable, Identifiable, Sendable {
    let id: String
    let path: String
    let relativePath: String
    let projectPath: String?
    let environment: String?
    let kind: DiscoveryManagedItemKind
    let status: ManagedLinkStatus

    enum CodingKeys: String, CodingKey {
        case id, path, environment, kind, status
        case relativePath = "relative_path"
        case projectPath = "project_path"
    }
}

enum DiscoveryManagedItemKind: String, Codable, Hashable, Sendable {
    case surface
    case protectedFile = "protected_file"
}

enum ManagedLinkStatus: String, Codable, Hashable, Sendable {
    case linked
    case missing
    case replaced
}

struct DiscoveredProject: Codable, Hashable, Sendable {
    let name: String
    let path: String
    let markers: [ProjectMarker]
    let ecosystems: [String]
    let managedProjectID: String?

    enum CodingKeys: String, CodingKey {
        case name, path, markers, ecosystems
        case managedProjectID = "managed_project_id"
    }
}

struct ProjectMarker: Codable, Hashable, Identifiable, Sendable {
    var id: String { "\(kind):\(path)" }
    let kind: String
    let path: String
}

enum ProjectAssignmentState: String, Codable, Hashable, Sendable {
    case assigned
    case unassigned
    case needsReview = "needs_review"
}

struct ProjectAssignment: Codable, Hashable, Sendable {
    let state: ProjectAssignmentState
    let projectPath: String?
    let candidateProjectPaths: [String]

    enum CodingKeys: String, CodingKey {
        case state
        case projectPath = "project_path"
        case candidateProjectPaths = "candidate_project_paths"
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
    case privateKey = "private_key"
    case certificate
    case publicKey = "public_key"
    case protectedFile = "protected_file"
    /// Forward compatibility: a kind this app version does not know yet. Decoding must not
    /// fail when the daemon learns a new file type before the app does.
    case unknown

    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = DiscoveredFileKind(rawValue: raw) ?? .unknown
    }
}

enum DiscoveredFileAction: String, Codable, Hashable, Sendable {
    case compose
    case protect
    case importSshIdentity = "import_ssh_identity"
    case reference
    case review
}

/// A location that is legitimate to scan but implausible for a long-lived credential. The file
/// is still discovered; it just starts unselected so the user confirms it on purpose.
enum PlacementCaution: String, Codable, Hashable, Sendable {
    case temporaryDirectory = "temporary_directory"

    var advice: String {
        switch self {
        case .temporaryDirectory:
            return "In a temporary directory — confirm this is a long-lived credential"
        }
    }
}

struct DiscoveredFile: Codable, Hashable, Sendable, Identifiable {
    var id: String { path }
    let path: String
    let relativePath: String
    let assignment: ProjectAssignment
    let kind: DiscoveredFileKind
    let codec: String
    let environment: String?
    let managedSurfaceID: String?
    let tags: [String]
    let entries: [DiscoveredEntry]
    let warnings: [DiscoveryWarning]
    let action: DiscoveredFileAction
    let placement: PlacementCaution?

    enum CodingKeys: String, CodingKey {
        case path, assignment, kind, codec, environment, tags, entries, warnings, action
        case placement
        case relativePath = "relative_path"
        case managedSurfaceID = "managed_surface_id"
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
    let projectIDs: [String]
    let createdResources: Int
    let reusedResources: Int
    let protectedFiles: Int
    let importedSshIdentities: Int
    let files: [DiscoveryAppliedFile]

    enum CodingKeys: String, CodingKey {
        case files
        case projectID = "project_id"
        case projectIDs = "project_ids"
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

enum DiscoveryReferenceSource: Encodable, Sendable {
    case newSharedSecret(
        name: String, value: String, enforcement: String, metadata: ItemMetadata)
    case existingSharedSecret(resourceID: String)

    private enum CodingKeys: String, CodingKey {
        case type, name, value, enforcement, metadata
        case resourceID = "resource_id"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .newSharedSecret(let name, let value, let enforcement, let metadata):
            try container.encode("new_shared_secret", forKey: .type)
            try container.encode(name, forKey: .name)
            try container.encode(value, forKey: .value)
            try container.encode(enforcement, forKey: .enforcement)
            try container.encode(metadata, forKey: .metadata)
        case .existingSharedSecret(let resourceID):
            try container.encode("existing_shared_secret", forKey: .type)
            try container.encode(resourceID, forKey: .resourceID)
        }
    }
}

struct DiscoveryReferenceResolution: Codable, Hashable, Sendable {
    let surfaceID: String
    let resourceID: String
    let bindingID: String
    let key: String

    enum CodingKeys: String, CodingKey {
        case key
        case surfaceID = "surface_id"
        case resourceID = "resource_id"
        case bindingID = "binding_id"
    }
}

struct DiscoverySeparateEntry: Codable, Hashable, Sendable {
    let path: String
    let address: String
}

struct DiscoveryImport: Codable, Hashable, Sendable {
    let path: String
    let destination: DiscoveryImportDestination
    let sourceDisposition: DiscoverySourceDisposition

    enum CodingKeys: String, CodingKey {
        case path, destination
        case sourceDisposition = "source_disposition"
    }
}

struct DiscoveryProjectOutput: Codable, Hashable, Sendable {
    let projectPath: String
    let outputPath: String

    enum CodingKeys: String, CodingKey {
        case projectPath = "project_path"
        case outputPath = "output_path"
    }
}

enum DiscoveryImportDestination: Codable, Hashable, Sendable {
    case projectFile(projectPath: String)
    case projectOutput(projectPath: String, outputPath: String)
    case library
    case projectOutputs(outputs: [DiscoveryProjectOutput])

    private enum CodingKeys: String, CodingKey {
        case type
        case projectPath = "project_path"
        case outputPath = "output_path"
        case outputs
    }

    private enum Kind: String, Codable {
        case projectFile = "project_file"
        case projectOutput = "project_output"
        case library
        case projectOutputs = "project_outputs"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .type) {
        case .projectFile:
            self = .projectFile(
                projectPath: try container.decode(String.self, forKey: .projectPath))
        case .projectOutput:
            self = .projectOutput(
                projectPath: try container.decode(String.self, forKey: .projectPath),
                outputPath: try container.decode(String.self, forKey: .outputPath))
        case .library:
            self = .library
        case .projectOutputs:
            self = .projectOutputs(
                outputs: try container.decode([DiscoveryProjectOutput].self, forKey: .outputs))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .projectFile(let projectPath):
            try container.encode(Kind.projectFile, forKey: .type)
            try container.encode(projectPath, forKey: .projectPath)
        case .projectOutput(let projectPath, let outputPath):
            try container.encode(Kind.projectOutput, forKey: .type)
            try container.encode(projectPath, forKey: .projectPath)
            try container.encode(outputPath, forKey: .outputPath)
        case .library:
            try container.encode(Kind.library, forKey: .type)
        case .projectOutputs(let outputs):
            try container.encode(Kind.projectOutputs, forKey: .type)
            try container.encode(outputs, forKey: .outputs)
        }
    }
}

enum DiscoverySourceDisposition: String, Codable, Hashable, Sendable {
    case replaceWithSurface = "replace_with_surface"
    case protectInPlace = "protect_in_place"
    case leaveUnchanged = "leave_unchanged"
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
    let environmentIDs: [String]
    let metadata: ItemMetadata

    enum CodingKeys: String, CodingKey {
        case id, mode, size, linked, enforcement, metadata
        case sourcePath = "source_path"
        case currentVersion = "current_version"
        case environmentIDs = "environment_ids"
    }
}

struct CatalogProtectedFileVersion: Codable, Sendable {
    let version: UInt32
    let size: UInt64
    let created: String
    let note: String?
    let current: Bool
}

struct BackupReport: Codable, Equatable, Sendable {
    let path: String
    let catalogSchema: Int64
    let projects: Int
    let resources: Int
    let secrets: Int
    let versions: Int
    let plaintextBytes: UInt64
    let files: Int

    enum CodingKeys: String, CodingKey {
        case path, projects, resources, secrets, versions, files
        case catalogSchema = "catalog_schema"
        case plaintextBytes = "plaintext_bytes"
    }
}

struct RecoveryKeyReport: Codable, Equatable, Sendable {
    let path: String
}

struct DiagnosticsReport: Codable, Equatable, Sendable {
    let path: String
    let pathsIncluded: Bool
    let files: Int
    let bytes: UInt64

    enum CodingKeys: String, CodingKey {
        case path, files, bytes
        case pathsIncluded = "paths_included"
    }
}

enum ReplicationMode: String, Codable, Sendable {
    case off
    case waitingForEnrollment = "waiting_for_enrollment"
    case active
    case removed
    case fenced
    case error
}

struct ReplicationStatus: Codable, Equatable, Sendable {
    let mode: ReplicationMode
    let directory: String?
    let deviceID: String?
    let vaultID: String?
    let keyGeneration: UInt32?
    let published: Int
    let imported: Int
    let pending: Int
    let conflicts: Int
    let damaged: Int
    let damagedFiles: [String]
    let devices: [ReplicationDevice]
    let message: String?
    /// This Mac's signing-key fingerprint, shown while waiting for approval so the user can
    /// compare it on the genesis Mac.
    let deviceFingerprint: String?
    /// Enrollment requests found in the sync directory that await approval on this Mac.
    let pendingEnrollments: [ReplicationPendingEnrollment]

    enum CodingKeys: String, CodingKey {
        case mode, directory, published, imported, pending, conflicts, damaged, devices, message
        case deviceID = "device_id"
        case vaultID = "vault_id"
        case keyGeneration = "key_generation"
        case damagedFiles = "damaged_files"
        case deviceFingerprint = "device_fingerprint"
        case pendingEnrollments = "pending_enrollments"
    }
}

struct ReplicationPendingEnrollment: Codable, Equatable, Identifiable, Sendable {
    let deviceID: String
    let deviceName: String?
    /// Compare this fingerprint with the one shown on the requesting Mac before approving.
    let fingerprint: String
    let requestedAt: String

    var id: String { deviceID }

    enum CodingKeys: String, CodingKey {
        case fingerprint
        case deviceID = "device_id"
        case deviceName = "device_name"
        case requestedAt = "requested_at"
    }
}

struct ReplicationDevice: Codable, Equatable, Identifiable, Sendable {
    let deviceID: String
    let deviceName: String?
    let enrolledGeneration: UInt32
    let revokedGeneration: UInt32?
    let isGenesis: Bool
    let isCurrent: Bool

    var id: String { deviceID }

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case deviceName = "device_name"
        case enrolledGeneration = "enrolled_generation"
        case revokedGeneration = "revoked_generation"
        case isGenesis = "is_genesis"
        case isCurrent = "is_current"
    }
}

struct ReplicationEnrollment: Codable, Equatable, Sendable {
    let deviceID: String
    let signingPublicKey: String
    let wrappingRecipient: String
    let deviceName: String?

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case signingPublicKey = "signing_public_key"
        case wrappingRecipient = "wrapping_recipient"
        case deviceName = "device_name"
    }
}

// MARK: - Coordinated encrypted-record sync

struct SyncObjectAsset: Codable, Equatable, Sendable {
    let digest: String
    let ciphertextSize: UInt64
    let file: String

    enum CodingKeys: String, CodingKey {
        case digest, file
        case ciphertextSize = "ciphertext_size"
    }
}

struct SyncOutboundRevision: Codable, Equatable, Sendable {
    let entityID: String
    let revisionID: String
    let expectedHeadRevisionID: String?
    let envelopeBase64: String

    enum CodingKeys: String, CodingKey {
        case entityID = "entity_id"
        case revisionID = "revision_id"
        case expectedHeadRevisionID = "expected_head_revision_id"
        case envelopeBase64 = "envelope_base64"
    }
}

struct SyncOutboundCommit: Codable, Equatable, Sendable {
    let commitID: String
    let manifestBase64: String
    let revisions: [SyncOutboundRevision]
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case revisions
        case commitID = "commit_id"
        case manifestBase64 = "manifest_base64"
        case createdAt = "created_at"
    }
}

struct SyncOutboundBatch: Codable, Equatable, Sendable {
    let commits: [SyncOutboundCommit]
    let objects: [SyncObjectAsset]
}

struct SyncInboundManifest: Codable, Equatable, Sendable {
    let commitID: String
    let manifestBase64: String

    enum CodingKeys: String, CodingKey {
        case commitID = "commit_id"
        case manifestBase64 = "manifest_base64"
    }
}

struct SyncInboundRevision: Codable, Equatable, Sendable {
    let entityID: String
    let revisionID: String
    let envelopeBase64: String

    enum CodingKeys: String, CodingKey {
        case entityID = "entity_id"
        case revisionID = "revision_id"
        case envelopeBase64 = "envelope_base64"
    }
}

struct SyncInboundObject: Codable, Equatable, Sendable {
    let digest: String
    let ciphertextSize: UInt64
    let file: String

    enum CodingKeys: String, CodingKey {
        case digest, file
        case ciphertextSize = "ciphertext_size"
    }
}

struct SyncInboundBatch: Codable, Equatable, Sendable {
    let manifests: [SyncInboundManifest]
    let revisions: [SyncInboundRevision]
    let objects: [SyncInboundObject]
}

enum SyncProjectionDisposition: String, Codable, Sendable {
    case unchanged
    case pending
    case conflict
    case applied
    case alreadyApplied = "already_applied"
}

struct SyncInboundReport: Codable, Equatable, Sendable {
    let manifestsReceived: Int
    let revisionsReceived: Int
    let objectsInstalled: Int
    let objectsAlreadyPresent: Int
    let inboundSettled: Int
    let pendingTransactions: Int
    let conflictingEntities: Int
    let projection: SyncProjectionDisposition

    enum CodingKeys: String, CodingKey {
        case projection
        case manifestsReceived = "manifests_received"
        case revisionsReceived = "revisions_received"
        case objectsInstalled = "objects_installed"
        case objectsAlreadyPresent = "objects_already_present"
        case inboundSettled = "inbound_settled"
        case pendingTransactions = "pending_transactions"
        case conflictingEntities = "conflicting_entities"
    }
}

enum SyncDeliveryDisposition: String, Codable, Sendable {
    case accepted
    case retry
    case conflict
}

struct SyncDeliveryOutcome: Codable, Equatable, Sendable {
    let commitID: String
    let disposition: SyncDeliveryDisposition

    enum CodingKeys: String, CodingKey {
        case disposition
        case commitID = "commit_id"
    }
}

struct SyncSettlementReport: Codable, Equatable, Sendable {
    let accepted: Int
    let conflicts: Int
    let retrying: Int
    let settled: Int
}

struct SyncDomainStatus: Codable, Equatable, Sendable {
    let outboundTransactions: Int
    let inboundTransactions: Int
    let pendingTransactions: Int
    let conflictingEntities: Int
    let projectionPending: Bool

    enum CodingKeys: String, CodingKey {
        case outboundTransactions = "outbound_transactions"
        case inboundTransactions = "inbound_transactions"
        case pendingTransactions = "pending_transactions"
        case conflictingEntities = "conflicting_entities"
        case projectionPending = "projection_pending"
    }
}

enum ControlCommand: Sendable {
    case ping
    case health
    case policyModeGet
    case policyModeSet(mode: RuntimePolicyMode, durationSecs: UInt64?)
    case grantList
    case grantRevoke(id: String)
    case grantClear
    case accessHistory(limit: Int)
    case backupCreate(destination: String)
    case backupVerify(backup: String)
    case recoveryKeyExport(destination: String, passphrase: String)
    case diagnosticsExport(destination: String, includePaths: Bool)
    case replicationStatus
    case replicationCreate(directory: String)
    case replicationOpen(directory: String)
    case replicationSync
    case replicationResolveWithCurrent
    case replicationRevokeDevice(deviceID: String)
    case replicationRequestReenrollment
    case replicationDisable
    case replicationEnrollment
    case replicationEnroll(ReplicationEnrollment)
    case replicationApprove(deviceID: String)
    case recordSyncStatus
    case recordSyncNextOutbound(limit: Int)
    case recordSyncSettleOutbound(outcomes: [SyncDeliveryOutcome])
    case recordSyncApplyInbound(batch: SyncInboundBatch, observedAt: String)
    case snapshot
    case discover(paths: [String])
    case discoverStart(paths: [String])
    case discoverStatus(id: String)
    case discoverCancel(id: String)
    case discoverApply(
        paths: [String], imports: [DiscoveryImport],
        separateEntries: [DiscoverySeparateEntry],
        promoteEntries: [DiscoverySeparateEntry], demoteEntries: [DiscoverySeparateEntry])
    case discoverReferenceResolve(
        surfaceID: String, key: String, source: DiscoveryReferenceSource)
    case projectCheckoutInventory
    case projectCheckoutDiscover(projectID: String)
    case projectCheckoutUpsert(CatalogProjectCheckout)
    case projectCheckoutRemove(id: String)
    case managedLinkRepair(path: String)
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
    case protectedFileContentsUpdate(id: String, path: String)
    case protectedFileMetadataUpdate(
        id: String, enforcement: String, environmentIDs: [String], metadata: ItemMetadata)
    case managedFileConfigure(id: String, projectID: String, environmentID: String?)
    case managedFileRestore(String)
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
    case resourceUpsert(CatalogResource, endpoint: String?)
    case resourceRemove(String)
    case projectCreate(CatalogProject, CatalogEnvironment, CatalogSurface)
    case projectUpsert(CatalogProject)
    case projectDefaultEnvironmentSet(projectID: String, environmentID: String?)
    case projectRemove(String)
    case environmentUpsert(CatalogEnvironment)
    case environmentRemove(String)
    case bindingUpsert(CatalogBinding)
    case bindingRemove(String)
    case surfaceUpsert(CatalogSurface)
    case surfaceRemove(String)

    var method: String {
        switch self {
        case .ping: "ping"
        case .health: "health"
        case .policyModeGet: "policy_mode_get"
        case .policyModeSet: "policy_mode_set"
        case .grantList: "grant_list"
        case .grantRevoke: "grant_revoke"
        case .grantClear: "grant_clear"
        case .accessHistory: "access_history"
        case .backupCreate: "backup_create"
        case .backupVerify: "backup_verify"
        case .recoveryKeyExport: "recovery_key_export"
        case .diagnosticsExport: "diagnostics_export"
        case .replicationStatus: "replication_status"
        case .replicationCreate: "replication_create"
        case .replicationOpen: "replication_open"
        case .replicationSync: "replication_sync"
        case .replicationResolveWithCurrent: "replication_resolve_with_current"
        case .replicationRevokeDevice: "replication_revoke_device"
        case .replicationRequestReenrollment: "replication_request_reenrollment"
        case .replicationDisable: "replication_disable"
        case .replicationEnrollment: "replication_enrollment"
        case .replicationEnroll: "replication_enroll"
        case .replicationApprove: "replication_approve"
        case .recordSyncStatus: "record_sync_status"
        case .recordSyncNextOutbound: "record_sync_next_outbound"
        case .recordSyncSettleOutbound: "record_sync_settle_outbound"
        case .recordSyncApplyInbound: "record_sync_apply_inbound"
        case .snapshot: "snapshot"
        case .discover: "discover"
        case .discoverStart: "discover_start"
        case .discoverStatus: "discover_status"
        case .discoverCancel: "discover_cancel"
        case .discoverApply: "discover_apply"
        case .discoverReferenceResolve: "discover_reference_resolve"
        case .projectCheckoutInventory: "project_checkout_inventory"
        case .projectCheckoutDiscover: "project_checkout_discover"
        case .projectCheckoutUpsert: "project_checkout_upsert"
        case .projectCheckoutRemove: "project_checkout_remove"
        case .managedLinkRepair: "managed_link_repair"
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
        case .protectedFileContentsUpdate: "protected_file_contents_update"
        case .protectedFileMetadataUpdate: "protected_file_metadata_update"
        case .managedFileConfigure: "managed_file_configure"
        case .managedFileRestore: "managed_file_restore"
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
        case .projectDefaultEnvironmentSet: "project_default_environment_set"
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
        case .ping, .health, .policyModeGet, .grantList, .grantClear, .replicationStatus,
            .replicationSync, .replicationResolveWithCurrent, .replicationDisable,
            .replicationRequestReenrollment, .replicationEnrollment, .recordSyncStatus, .snapshot,
            .projectCheckoutInventory, .sshConfigStatus, .sshConfigInstall, .sshConfigRemove,
            .protectedFiles:
            return try encoder.encode(ControlRequestWithoutParams(requestID: requestID, method: method))
        case .policyModeSet(let mode, let durationSecs):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: PolicyModeSetParams(mode: mode, durationSecs: durationSecs)))
        case .grantRevoke(let id):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: GrantIDParams(id: id)))
        case .accessHistory(let limit):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: AccessHistoryParams(limit: limit)))
        case .backupCreate(let destination):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: BackupCreateParams(destination: destination)))
        case .backupVerify(let backup):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: BackupVerifyParams(backup: backup)))
        case .recoveryKeyExport(let destination, let passphrase):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: RecoveryKeyExportParams(
                        destination: destination, passphrase: passphrase)))
        case .diagnosticsExport(let destination, let includePaths):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: DiagnosticsExportParams(
                        destination: destination, includePaths: includePaths)))
        case .replicationCreate(let directory), .replicationOpen(let directory):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ReplicationDirectoryParams(directory: directory)))
        case .replicationEnroll(let enrollment):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ReplicationEnrollParams(enrollment: enrollment)))
        case .replicationRevokeDevice(let deviceID):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ReplicationRevokeDeviceParams(deviceID: deviceID)))
        case .replicationApprove(let deviceID):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ReplicationRevokeDeviceParams(deviceID: deviceID)))
        case .recordSyncNextOutbound(let limit):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: RecordSyncNextOutboundParams(limit: limit)))
        case .recordSyncSettleOutbound(let outcomes):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: RecordSyncSettleOutboundParams(outcomes: outcomes)))
        case .recordSyncApplyInbound(let batch, let observedAt):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: RecordSyncApplyInboundParams(
                        batch: batch, observedAt: observedAt)))
        case .discover(let paths):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: DiscoverParams(paths: paths)))
        case .discoverStart(let paths):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: DiscoverParams(paths: paths)))
        case .discoverStatus(let id), .discoverCancel(let id):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: DiscoveryJobIDParams(id: id)))
        case .discoverApply(
            let paths, let imports, let separateEntries,
            let promoteEntries, let demoteEntries):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: DiscoverApplyParams(
                        paths: paths, imports: imports,
                        separateEntries: separateEntries,
                        promoteEntries: promoteEntries, demoteEntries: demoteEntries)))
        case .discoverReferenceResolve(let surfaceID, let key, let source):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: DiscoverReferenceResolveParams(
                        surfaceID: surfaceID, key: key, source: source)))
        case .projectCheckoutDiscover(let projectID):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProjectCheckoutDiscoverParams(projectID: projectID)))
        case .projectCheckoutUpsert(let checkout):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProjectCheckoutUpsertParams(checkout: checkout)))
        case .managedLinkRepair(let path):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ManagedLinkRepairParams(path: path)))
        case .projectCheckoutRemove(let id):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: RemoveParams(id: id)))
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
        case .protectedFileHistory(let id), .managedFileRestore(let id), .fileRestore(let id):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProtectedFileIDParams(id: id)))
        case .protectedFileRollback(let id, let version):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProtectedFileRollbackParams(id: id, version: version)))
        case .protectedFileContentsUpdate(let id, let path):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProtectedFileContentsUpdateParams(id: id, path: path)))
        case .protectedFileMetadataUpdate(
            let id, let enforcement, let environmentIDs, let metadata):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProtectedFileMetadataUpdateParams(
                        id: id, enforcement: enforcement,
                        environmentIDs: environmentIDs, metadata: metadata)))
        case .managedFileConfigure(let id, let projectID, let environmentID):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ManagedFileConfigureParams(
                        id: id, projectID: projectID, environmentID: environmentID)))
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
        case .resourceUpsert(let resource, let endpoint):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ResourceUpsertParams(resource: resource, endpoint: endpoint)))
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
        case .projectDefaultEnvironmentSet(let projectID, let environmentID):
            return try encoder.encode(
                ControlRequest(
                    requestID: requestID, method: method,
                    params: ProjectDefaultEnvironmentSetParams(
                        projectID: projectID, environmentID: environmentID)))
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

private struct GrantIDParams: Encodable { let id: String }
private struct AccessHistoryParams: Encodable { let limit: Int }
private struct BackupCreateParams: Encodable { let destination: String }
private struct BackupVerifyParams: Encodable { let backup: String }
private struct RecoveryKeyExportParams: Encodable {
    let destination: String
    let passphrase: String
}
private struct DiagnosticsExportParams: Encodable {
    let destination: String
    let includePaths: Bool
}
private struct ReplicationDirectoryParams: Encodable { let directory: String }
private struct ReplicationEnrollParams: Encodable { let enrollment: ReplicationEnrollment }
private struct ReplicationRevokeDeviceParams: Encodable {
    let deviceID: String

    enum CodingKeys: String, CodingKey { case deviceID = "device_id" }
}
private struct RecordSyncNextOutboundParams: Encodable { let limit: Int }
private struct RecordSyncSettleOutboundParams: Encodable {
    let outcomes: [SyncDeliveryOutcome]
}
private struct RecordSyncApplyInboundParams: Encodable {
    let batch: SyncInboundBatch
    let observedAt: String
}
private struct DiscoverParams: Encodable { let paths: [String] }
private struct DiscoveryJobIDParams: Encodable { let id: String }
private struct DiscoverApplyParams: Encodable {
    let paths: [String]
    let imports: [DiscoveryImport]
    let separateEntries: [DiscoverySeparateEntry]
    let promoteEntries: [DiscoverySeparateEntry]
    let demoteEntries: [DiscoverySeparateEntry]
    enum CodingKeys: String, CodingKey {
        case paths, imports
        case separateEntries = "separate_entries"
        case promoteEntries = "promote_entries"
        case demoteEntries = "demote_entries"
    }
}
private struct DiscoverReferenceResolveParams: Encodable {
    let surfaceID: String
    let key: String
    let source: DiscoveryReferenceSource
}
private struct ProjectCheckoutDiscoverParams: Encodable { let projectID: String }
private struct ProjectCheckoutUpsertParams: Encodable { let checkout: CatalogProjectCheckout }
private struct ManagedLinkRepairParams: Encodable { let path: String }
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
private struct ProtectedFileContentsUpdateParams: Encodable {
    let id: String
    let path: String
}
private struct ProtectedFileMetadataUpdateParams: Encodable {
    let id: String
    let enforcement: String
    let environmentIDs: [String]
    let metadata: ItemMetadata

    enum CodingKeys: String, CodingKey {
        case id, enforcement, metadata
        case environmentIDs = "environment_ids"
    }
}
private struct ManagedFileConfigureParams: Encodable {
    let id: String
    let projectID: String
    let environmentID: String?
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

private struct ResourceUpsertParams: Encodable {
    let resource: CatalogResource
    let endpoint: String?
}

private struct ProjectUpsertParams: Encodable { let project: CatalogProject }
private struct ProjectDefaultEnvironmentSetParams: Encodable {
    let projectID: String
    let environmentID: String?
}
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
