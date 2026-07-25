import Darwin
import Foundation
import Observation

enum WorkspaceSecurityLevel: String, CaseIterable, Hashable, Sendable {
    case auditOnly = "allow"
    case confirmation = "prompt"
    case touchID = "touchid"

    var title: String {
        switch self {
        case .auditOnly: "Audit Only"
        case .confirmation: "Ask to Allow"
        case .touchID: "Require Touch ID"
        }
    }

    var compactTitle: String {
        switch self {
        case .auditOnly: "Audit"
        case .confirmation: "Ask"
        case .touchID: "Touch ID"
        }
    }

    var detail: String {
        switch self {
        case .auditOnly: "Allow reads immediately and record every access."
        case .confirmation: "Ask in the menu bar before allowing access."
        case .touchID: "Ask in the menu bar and authenticate before allowing access."
        }
    }

    var systemImage: String {
        switch self {
        case .auditOnly: "eye"
        case .confirmation: "hand.raised"
        case .touchID: "touchid"
        }
    }

    init(catalogValue: String) {
        self = WorkspaceSecurityLevel(rawValue: catalogValue) ?? .confirmation
    }
}

enum WorkspaceResourceKind: String, CaseIterable, Sendable {
    case sharedSecret
    case secret
    case envFile
    case literal
    case command
    case sshAgent

    var title: String {
        switch self {
        case .sharedSecret: "Shared Secret"
        case .secret: "Secret"
        case .envFile: "Env File"
        case .literal: "Literal"
        case .command: "Command"
        case .sshAgent: "SSH Agent"
        }
    }

    var systemImage: String {
        switch self {
        case .sharedSecret, .secret: "key.fill"
        case .envFile: "doc.badge.gearshape"
        case .literal: "chevron.left.forwardslash.chevron.right"
        case .command: "terminal.fill"
        case .sshAgent: "network"
        }
    }
}

enum WorkspaceValueShape: String, Sendable {
    case scalar
    case keyValueSet
    case bytes
    case socket
}

enum WorkspaceResourceCodec: String, Sendable {
    case opaque
    case dotenv
    case ini
}

enum WorkspaceIniPreset: String, CaseIterable, Sendable {
    case generic
    case awsCredentials
    case awsConfig

    var title: String {
        switch self {
        case .generic: "Generic INI"
        case .awsCredentials: "AWS credentials"
        case .awsConfig: "AWS config"
        }
    }

    var suggestedResourceName: String {
        switch self {
        case .generic: "Team settings"
        case .awsCredentials: "AWS credentials"
        case .awsConfig: "AWS config"
        }
    }

    var suggestedOutputName: String {
        switch self {
        case .generic: "credentials.ini"
        case .awsCredentials: ".aws-credentials"
        case .awsConfig: ".aws-config"
        }
    }

    var contentPlaceholder: String {
        switch self {
        case .generic:
            "[development]\nREGION=fixture-region\nOUTPUT=json"
        case .awsCredentials:
            "[default]\naws_access_key_id=...\naws_secret_access_key=...\naws_session_token=..."
        case .awsConfig:
            "[profile staging]\nregion=us-east-1\noutput=json"
        }
    }

    var pathEnvironmentKey: String? {
        switch self {
        case .generic: nil
        case .awsCredentials: "AWS_SHARED_CREDENTIALS_FILE"
        case .awsConfig: "AWS_CONFIG_FILE"
        }
    }

    var sectionGuidance: String {
        switch self {
        case .generic:
            "Sections and entries remain generic and selectable."
        case .awsCredentials:
            "Named credential profiles use [name], without a profile prefix."
        case .awsConfig:
            "Named config profiles use [profile name]; [default] remains unprefixed."
        }
    }
}

struct WorkspaceExport: Identifiable, Hashable, Sendable {
    var id: String { key }
    let key: String
    let previewValue: String
    let sensitive: Bool
}

struct WorkspaceEntry: Identifiable, Hashable, Sendable {
    var id: String { address }
    let address: String
    let label: String
    let key: String?
    let previewValue: String
    let sensitive: Bool

    init(
        address: String, label: String, key: String?, previewValue: String = "••••••••••••",
        sensitive: Bool
    ) {
        self.address = address
        self.label = label
        self.key = key
        self.previewValue = previewValue
        self.sensitive = sensitive
    }
}

struct WorkspaceResource: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let kind: WorkspaceResourceKind
    let shape: WorkspaceValueShape
    let codec: WorkspaceResourceCodec
    let defaultEnvKey: String?
    let entries: [WorkspaceEntry]
    let securityLevel: WorkspaceSecurityLevel
    let metadata: ItemMetadata
    let usageCount: Int

    init(
        id: String, name: String, kind: WorkspaceResourceKind, shape: WorkspaceValueShape,
        codec: WorkspaceResourceCodec? = nil,
        defaultEnvKey: String? = nil,
        exports: [WorkspaceExport], entries: [WorkspaceEntry] = [],
        securityLevel: WorkspaceSecurityLevel = .confirmation,
        metadata: ItemMetadata = .empty,
        usageCount: Int
    ) {
        self.id = id
        self.name = name
        self.kind = kind
        self.shape = shape
        self.codec = codec ?? (kind == .envFile ? .dotenv : .opaque)
        self.defaultEnvKey = defaultEnvKey
        self.entries = entries.isEmpty
            ? exports.map {
                WorkspaceEntry(
                    address: "keys/\($0.key)", label: $0.key, key: $0.key,
                    previewValue: $0.previewValue,
                    sensitive: $0.sensitive)
            }
            : entries
        self.securityLevel = securityLevel
        self.metadata = metadata
        self.usageCount = usageCount
    }

    var exports: [WorkspaceExport] {
        entries.compactMap { entry in
            entry.key.map {
                WorkspaceExport(
                    key: $0, previewValue: entry.previewValue, sensitive: entry.sensitive)
            }
        }
    }

    var exportSummary: String {
        if kind == .sshAgent { return "\(entries.count) identit\(entries.count == 1 ? "y" : "ies")" }
        if exports.isEmpty, entries.count == 1 { return "Keyless value" }
        if exports.count == 1, let key = exports.first?.key { return key }
        return "\(entries.count) entries"
    }
}

enum WorkspaceEntrySelection: Hashable, Sendable {
    case all
    case entries([String])

    func addresses(in resource: WorkspaceResource) -> [String] {
        switch self {
        case .all: return resource.entries.map(\.address)
        case .entries(let addresses):
            let selected = Set(addresses)
            return resource.entries.map(\.address).filter(selected.contains)
        }
    }
}

struct WorkspaceBinding: Identifiable, Hashable, Sendable {
    let id: String
    let resourceID: WorkspaceResource.ID
    let selection: WorkspaceEntrySelection
    var keyOverride: String?
    var isEnabled: Bool
    let scope: WorkspaceBindingScope
    let allowOverride: Bool
    let position: Int64

    init(
        id: String, resourceID: WorkspaceResource.ID,
        selection: WorkspaceEntrySelection = .all, keyOverride: String?, isEnabled: Bool,
        scope: WorkspaceBindingScope = .environment(""), allowOverride: Bool = false,
        position: Int64 = 0
    ) {
        self.id = id
        self.resourceID = resourceID
        self.selection = selection
        self.keyOverride = keyOverride
        self.isEnabled = isEnabled
        self.scope = scope
        self.allowOverride = allowOverride
        self.position = position
    }
}

enum WorkspaceBindingScope: Hashable, Sendable {
    case common
    case environment(WorkspaceEnvironment.ID)
}

enum WorkspaceBindingTarget: String, CaseIterable, Sendable {
    case environment
    case common

    var title: String {
        switch self {
        case .environment: "This environment"
        case .common: "All environments"
        }
    }
}

enum WorkspaceSurfaceKind: String, CaseIterable, Sendable {
    case dotenvFile
    case direnvFile
    case iniFile
    case envFileDirect
    case linesFile
    case regularFile
    case unixSocket

    var title: String {
        switch self {
        case .dotenvFile: "Dotenv File"
        case .direnvFile: "direnv File"
        case .iniFile: "INI File"
        case .envFileDirect: "Direct Env File"
        case .linesFile: "Lines File"
        case .regularFile: "File"
        case .unixSocket: "Unix Socket"
        }
    }

    var systemImage: String {
        switch self {
        case .dotenvFile: "doc.text"
        case .direnvFile: "terminal"
        case .iniFile: "list.bullet.rectangle"
        case .envFileDirect: "doc.text.fill"
        case .linesFile: "text.line.first.and.arrowtriangle.forward"
        case .regularFile: "doc"
        case .unixSocket: "point.3.connected.trianglepath.dotted"
        }
    }

    var isComposed: Bool {
        self == .dotenvFile || self == .direnvFile || self == .iniFile || self == .linesFile
    }

    var defaultFileName: String {
        switch self {
        case .dotenvFile: ".env"
        case .direnvFile: ".envrc"
        case .iniFile: "credentials.ini"
        case .linesFile: ".secrets"
        case .envFileDirect: ".env.local"
        case .regularFile: "output"
        case .unixSocket: "agent.sock"
        }
    }

    static var composedCases: [WorkspaceSurfaceKind] {
        allCases.filter(\.isComposed)
    }
}

enum WorkspaceSurfaceStatus: String, Sendable {
    case linked = "Linked"
    case listening = "Listening"
    case ready = "Ready"
    case stopped = "Stopped"

    var isHealthy: Bool { self != .stopped }
}

struct WorkspaceSurface: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let kind: WorkspaceSurfaceKind
    let path: String
    let status: WorkspaceSurfaceStatus
    let input: WorkspaceSurfaceInput
    let securityLevel: WorkspaceSecurityLevel

    init(
        id: String, name: String, kind: WorkspaceSurfaceKind, path: String,
        status: WorkspaceSurfaceStatus, input: WorkspaceSurfaceInput,
        securityLevel: WorkspaceSecurityLevel = .confirmation
    ) {
        self.id = id
        self.name = name
        self.kind = kind
        self.path = path
        self.status = status
        self.input = input
        self.securityLevel = securityLevel
    }

    var bindingIDs: [WorkspaceBinding.ID] {
        guard case .bindings(let ids) = input else { return [] }
        return ids
    }

    var resourceID: WorkspaceResource.ID? {
        guard case .resource(let id) = input else { return nil }
        return id
    }
}

enum WorkspaceSurfaceInput: Hashable, Sendable {
    case bindings([WorkspaceBinding.ID])
    case resource(WorkspaceResource.ID)
}

struct WorkspaceEnvironment: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    var bindings: [WorkspaceBinding]
    var surfaces: [WorkspaceSurface]
}

struct WorkspaceProject: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let path: String
    var commonBindings: [WorkspaceBinding]
    var environments: [WorkspaceEnvironment]
}

struct ResolvedWorkspaceExport: Identifiable, Hashable, Sendable {
    var id: String { "\(bindingID):\(key)" }
    let bindingID: WorkspaceBinding.ID
    let key: String
    let previewValue: String
    let sensitive: Bool
    let resourceName: String
    let resourceKind: WorkspaceResourceKind
}

struct ResolvedWorkspaceEntry: Identifiable, Hashable, Sendable {
    var id: String { "\(bindingID):\(address)" }
    let bindingID: WorkspaceBinding.ID
    let address: String
    let label: String
    let resourceName: String
}

enum WorkspaceProtectedFileKind: String, Sendable {
    case dotenv
    case direnv
    case pgpass
    case awsCredentials
    case file

    static func infer(from path: String) -> WorkspaceProtectedFileKind {
        let url = URL(fileURLWithPath: path)
        let name = url.lastPathComponent
        if name == ".envrc" { return .direnv }
        if name == ".pgpass" { return .pgpass }
        if name == "credentials", url.deletingLastPathComponent().lastPathComponent == ".aws" {
            return .awsCredentials
        }
        if name == ".env" || name.hasPrefix(".env.") { return .dotenv }
        return .file
    }

    var title: String {
        switch self {
        case .dotenv: "Dotenv"
        case .direnv: "direnv"
        case .pgpass: "PostgreSQL password file"
        case .awsCredentials: "AWS credentials"
        case .file: "Protected file"
        }
    }

    var systemImage: String {
        switch self {
        case .dotenv: "doc.text"
        case .direnv: "terminal"
        case .pgpass: "cylinder"
        case .awsCredentials: "cloud"
        case .file: "lock.fill"
        }
    }
}

struct WorkspaceProtectedFile: Identifiable, Hashable, Sendable {
    let id: String
    let path: String
    let mode: UInt32
    let size: UInt64
    let currentVersion: UInt32
    let linked: Bool
    let securityLevel: WorkspaceSecurityLevel
    let metadata: ItemMetadata

    var kind: WorkspaceProtectedFileKind {
        WorkspaceProtectedFileKind.infer(from: path)
    }
}

struct WorkspaceProtectedFileVersion: Identifiable, Hashable, Sendable {
    var id: UInt32 { version }
    let version: UInt32
    let size: UInt64
    let created: String
    let note: String?
    let current: Bool
}

@Observable @MainActor
final class WorkspaceStore {
    var projects: [WorkspaceProject]
    var resources: [WorkspaceResource]
    var protectedFiles: [WorkspaceProtectedFile]
    var selectedProjectID: WorkspaceProject.ID
    var selectedEnvironmentID: WorkspaceEnvironment.ID
    var selectedSurfaceID: WorkspaceSurface.ID
    var isLoading = false
    var lastError: String?

    @ObservationIgnored private let controlClient: ControlClient?

    init(
        projects: [WorkspaceProject], resources: [WorkspaceResource],
        selectedProjectID: WorkspaceProject.ID = "", controlClient: ControlClient? = nil
    ) {
        self.projects = projects
        self.resources = resources
        protectedFiles = []
        self.controlClient = controlClient
        let project = projects.first(where: { $0.id == selectedProjectID }) ?? projects.first
        self.selectedProjectID = project?.id ?? ""
        selectedEnvironmentID = project?.environments.first?.id ?? ""
        selectedSurfaceID = project?.environments.first?.surfaces.first?.id ?? ""
    }

    convenience init(controlClient: ControlClient) {
        self.init(projects: [], resources: [], controlClient: controlClient)
    }

    var selectedProject: WorkspaceProject? {
        projects.first(where: { $0.id == selectedProjectID })
    }

    var selectedEnvironment: WorkspaceEnvironment? {
        selectedProject?.environments.first(where: { $0.id == selectedEnvironmentID })
    }

    var selectedSurface: WorkspaceSurface? {
        selectedEnvironment?.surfaces.first(where: { $0.id == selectedSurfaceID })
    }

    var commonBindings: [WorkspaceBinding] { selectedProject?.commonBindings ?? [] }
    var environmentBindings: [WorkspaceBinding] { selectedEnvironment?.bindings ?? [] }

    var activeBindings: [WorkspaceBinding] {
        (commonBindings + environmentBindings).filter(\.isEnabled)
    }

    var selectedSurfaceBindings: [WorkspaceBinding] {
        bindings(for: selectedSurfaceID)
    }

    func bindings(for surfaceID: WorkspaceSurface.ID) -> [WorkspaceBinding] {
        guard let surface = selectedEnvironment?.surfaces.first(where: { $0.id == surfaceID })
        else { return [] }
        let members = Set(surface.bindingIDs)
        return activeBindings.filter { members.contains($0.id) }
    }

    var resolvedExports: [ResolvedWorkspaceExport] {
        resolvedExports(for: selectedSurfaceID)
    }

    func resolvedExports(for surfaceID: WorkspaceSurface.ID) -> [ResolvedWorkspaceExport] {
        bindings(for: surfaceID).flatMap { binding -> [ResolvedWorkspaceExport] in
            guard let resource = resource(binding.resourceID) else { return [] }
            let selected = Set(binding.selection.addresses(in: resource))
            return resource.entries.compactMap { entry in
                guard selected.contains(entry.address) else { return nil }
                let key = resource.shape == .scalar ? (binding.keyOverride ?? entry.key) : entry.key
                guard let key else { return nil }
                return ResolvedWorkspaceExport(
                    bindingID: binding.id,
                    key: key,
                    previewValue: entry.previewValue,
                    sensitive: entry.sensitive,
                    resourceName: resource.name,
                    resourceKind: resource.kind)
            }
        }
    }

    var resolvedLineEntries: [ResolvedWorkspaceEntry] {
        selectedSurfaceBindings.flatMap { binding -> [ResolvedWorkspaceEntry] in
            guard let resource = resource(binding.resourceID),
                resource.shape == .scalar, binding.keyOverride == nil
            else { return [] }
            let selected = Set(binding.selection.addresses(in: resource))
            return resource.entries.filter {
                selected.contains($0.address) && $0.key == nil
            }.map { entry in
                ResolvedWorkspaceEntry(
                    bindingID: binding.id, address: entry.address, label: entry.label,
                    resourceName: resource.name)
            }
        }
    }

    var resolvedIniEntries: [ResolvedWorkspaceEntry] {
        selectedSurfaceBindings.flatMap { binding -> [ResolvedWorkspaceEntry] in
            guard let resource = resource(binding.resourceID), resource.codec == .ini else {
                return []
            }
            let selected = Set(binding.selection.addresses(in: resource))
            return resource.entries.filter { selected.contains($0.address) }.map { entry in
                ResolvedWorkspaceEntry(
                    bindingID: binding.id, address: entry.address, label: entry.label,
                    resourceName: resource.name)
            }
        }
    }

    var conflictingKeys: Set<String> {
        let counts = Dictionary(grouping: resolvedExports, by: \.key).mapValues(\.count)
        return Set(counts.filter { $0.value > 1 }.keys)
    }

    var availableResources: [WorkspaceResource] {
        let bound = Set((commonBindings + environmentBindings).map(\.resourceID))
        return resources.filter { !bound.contains($0.id) }
    }

    var envFileResources: [WorkspaceResource] {
        resources.filter { $0.kind == .envFile && $0.codec == .dotenv }
    }

    var sshAgentResources: [WorkspaceResource] {
        resources.filter { $0.kind == .sshAgent && $0.shape == .socket }
    }

    func compatibleBindings(for kind: WorkspaceSurfaceKind) -> [WorkspaceBinding] {
        (commonBindings + environmentBindings).filter { bindingIsCompatible($0, with: kind) }
    }

    func bindingIsCompatible(
        _ binding: WorkspaceBinding, with kind: WorkspaceSurfaceKind
    ) -> Bool {
        guard let resource = resource(binding.resourceID) else { return false }
        let selected = Set(binding.selection.addresses(in: resource))
        let entries = resource.entries.filter { selected.contains($0.address) }
        switch kind {
        case .dotenvFile, .direnvFile:
            if resource.shape == .scalar {
                guard resource.codec == .opaque else { return false }
                guard resource.kind == .sharedSecret || resource.kind == .secret
                    || resource.kind == .literal
                else { return false }
                return entries.allSatisfy { entry in
                    guard let key = binding.keyOverride ?? entry.key else { return false }
                    return Self.isValidEnvKey(key)
                }
            }
            guard resource.codec == .dotenv || resource.codec == .ini else { return false }
            return resource.kind == .envFile && resource.shape == .keyValueSet
                && entries.allSatisfy { entry in
                    guard let key = entry.key else { return false }
                    return Self.isValidEnvKey(key)
                }
        case .iniFile:
            return resource.kind == .envFile && resource.shape == .keyValueSet
                && resource.codec == .ini && binding.keyOverride == nil
                && entries.allSatisfy { $0.key != nil }
        case .linesFile:
            return resource.shape == .scalar && resource.codec == .opaque
                && (resource.kind == .sharedSecret || resource.kind == .secret
                    || resource.kind == .literal)
                && binding.keyOverride == nil && entries.count == 1 && entries[0].key == nil
        case .unixSocket:
            return resource.kind == .sshAgent && resource.shape == .socket
                && resource.codec == .opaque && binding.keyOverride == nil
                && !entries.isEmpty && entries.allSatisfy { $0.key == nil && !$0.sensitive }
        case .envFileDirect, .regularFile:
            return false
        }
    }

    func resource(_ id: WorkspaceResource.ID) -> WorkspaceResource? {
        resources.first { $0.id == id }
    }

    func selectProject(_ id: WorkspaceProject.ID) {
        guard let project = projects.first(where: { $0.id == id }) else { return }
        selectedProjectID = id
        selectedEnvironmentID = project.environments.first?.id ?? ""
        selectedSurfaceID = project.environments.first?.surfaces.first?.id ?? ""
    }

    func selectEnvironment(_ id: WorkspaceEnvironment.ID) {
        guard let environment = selectedProject?.environments.first(where: { $0.id == id }) else {
            return
        }
        selectedEnvironmentID = id
        selectedSurfaceID = environment.surfaces.first?.id ?? ""
    }

    func reload(reportErrors: Bool = false) async {
        guard let controlClient else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            async let catalog = controlClient.snapshot()
            async let files = controlClient.protectedFiles()
            apply(try await catalog)
            protectedFiles = try await files.map(WorkspaceProtectedFile.init)
            lastError = nil
        } catch {
            if reportErrors { lastError = error.localizedDescription }
        }
    }

    func protectFile(at path: String) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let file = try await controlClient.protectFile(at: path)
        let protected = WorkspaceProtectedFile(file)
        if let index = protectedFiles.firstIndex(where: { $0.id == protected.id }) {
            protectedFiles[index] = protected
        } else {
            protectedFiles.append(protected)
            protectedFiles.sort { $0.path.localizedStandardCompare($1.path) == .orderedAscending }
        }
        lastError = nil
    }

    func protectedFileHistory(_ id: String) async throws -> [WorkspaceProtectedFileVersion] {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.protectedFileHistory(id).map {
            WorkspaceProtectedFileVersion(
                version: $0.version, size: $0.size, created: $0.created,
                note: $0.note, current: $0.current)
        }
    }

    func rollbackProtectedFile(_ id: String, to version: UInt32) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let file = WorkspaceProtectedFile(
            try await controlClient.rollbackProtectedFile(id, to: version))
        if let index = protectedFiles.firstIndex(where: { $0.id == id }) {
            protectedFiles[index] = file
        }
        lastError = nil
    }

    func updateProtectedFileMetadata(
        _ id: String, securityLevel: WorkspaceSecurityLevel, metadata: ItemMetadata
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard protectedFiles.contains(where: { $0.id == id }) else {
            throw WorkspaceStoreError.invalid("Choose a protected file first")
        }
        let metadata = try Self.validatedMetadata(metadata)
        try await controlClient.updateProtectedFileMetadata(
            id, enforcement: securityLevel.rawValue, metadata: metadata)
        if let files = try? await controlClient.protectedFiles() {
            protectedFiles = files.map(WorkspaceProtectedFile.init)
        }
        lastError = nil
    }

    func restoreFile(_ id: String) async throws -> Bool {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let storageDeleted = try await controlClient.restoreFile(id)
        if storageDeleted {
            protectedFiles.removeAll { $0.id == id }
        } else if let files = try? await controlClient.protectedFiles() {
            protectedFiles = files.map(WorkspaceProtectedFile.init)
        }
        lastError = nil
        return storageDeleted
    }

    @discardableResult
    func createProject(
        name: String, path: String, initialFileName: String = ".env",
        initialSurfaceKind: WorkspaceSurfaceKind = .dotenvFile
    ) async throws -> WorkspaceProject.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let path = (path as NSString).standardizingPath
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Project name is required") }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
            isDirectory.boolValue
        else {
            throw WorkspaceStoreError.invalid("Choose an existing project directory")
        }
        guard initialSurfaceKind.isComposed else {
            throw WorkspaceStoreError.invalid("Choose a composed output format")
        }
        let draft = WorkspaceProject(
            id: "", name: name, path: path, commonBindings: [], environments: [])
        let output = try newSurfaceOutput(fileName: initialFileName, in: draft)

        let projectID = Self.newID("project")
        let environmentID = Self.newID("environment")
        let surfaceID = Self.newID("surface")
        do {
            try await controlClient.createProject(
                CatalogProject(id: projectID, name: name, path: path),
                environment: CatalogEnvironment(
                    id: environmentID, projectID: projectID, name: "Development", position: 0),
                surface: CatalogSurface(
                    id: surfaceID, environmentID: environmentID, name: output.name,
                    kind: initialSurfaceKind.catalogValue, path: output.path,
                    input: .bindings([]), position: 0))
            apply(try await controlClient.snapshot(), selectingProject: projectID)
            lastError = nil
            return projectID
        } catch {
            await reload()
            throw error
        }
    }

    @discardableResult
    func createSharedSecret(
        name: String, defaultEnvKey: String, value: String,
        securityLevel: WorkspaceSecurityLevel, metadata: ItemMetadata
    ) async throws
        -> WorkspaceResource.ID
    {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let enteredKey = defaultEnvKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = enteredKey.isEmpty ? nil : enteredKey
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Secret name is required") }
        if let key, !Self.isValidEnvKey(key) {
            throw WorkspaceStoreError.invalid(
                "The default key must start with A-Z or _, followed by A-Z, 0-9, or _")
        }
        guard !value.isEmpty else { throw WorkspaceStoreError.invalid("Secret value is required") }
        let metadata = try Self.validatedMetadata(metadata)

        let resourceID = Self.newID("shared-secret")
        try await controlClient.createSharedSecret(
            resourceID: resourceID, name: name, defaultEnvKey: key, value: value,
            enforcement: securityLevel.rawValue, metadata: metadata)
        apply(try await controlClient.snapshot())
        lastError = nil
        return resourceID
    }

    func updateSharedSecret(
        _ id: WorkspaceResource.ID, name: String, defaultEnvKey: String,
        newValue: String = "", securityLevel: WorkspaceSecurityLevel,
        metadata: ItemMetadata
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard resources.contains(where: { $0.id == id && $0.kind == .sharedSecret }) else {
            throw WorkspaceStoreError.invalid("Choose a Shared Secret first")
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let enteredKey = defaultEnvKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = enteredKey.isEmpty ? nil : enteredKey
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Secret name is required") }
        if let key, !Self.isValidEnvKey(key) {
            throw WorkspaceStoreError.invalid(
                "The default key must start with A-Z or _, followed by A-Z, 0-9, or _")
        }
        let metadata = try Self.validatedMetadata(metadata)

        try await controlClient.updateSharedSecret(
            resourceID: id, name: name, defaultEnvKey: key,
            value: newValue.isEmpty ? nil : newValue,
            enforcement: securityLevel.rawValue, metadata: metadata)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    func deleteSharedSecret(_ id: WorkspaceResource.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let resource = resources.first(where: { $0.id == id && $0.kind == .sharedSecret })
        else {
            throw WorkspaceStoreError.invalid("Choose a Shared Secret first")
        }
        guard resource.usageCount == 0 else {
            let projectWord = resource.usageCount == 1 ? "project" : "projects"
            throw WorkspaceStoreError.invalid(
                "Remove this secret from \(resource.usageCount) \(projectWord) before deleting it")
        }

        try await controlClient.deleteSharedSecret(resourceID: id)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    @discardableResult
    func createEnvFile(
        name: String, codec: WorkspaceResourceCodec, value: String,
        securityLevel: WorkspaceSecurityLevel, metadata: ItemMetadata
    ) async throws -> WorkspaceResource.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Env file name is required") }
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw WorkspaceStoreError.invalid("Enter at least one file entry")
        }
        guard codec == .dotenv || codec == .ini else {
            throw WorkspaceStoreError.invalid("Choose dotenv or INI format")
        }
        let metadata = try Self.validatedMetadata(metadata)

        let resourceID = Self.newID("env-file")
        try await controlClient.createEnvFile(
            resourceID: resourceID, name: name, codec: codec, value: value,
            enforcement: securityLevel.rawValue, metadata: metadata)
        apply(try await controlClient.snapshot())
        lastError = nil
        return resourceID
    }

    func updateResourceMetadata(
        _ id: WorkspaceResource.ID, name: String,
        securityLevel: WorkspaceSecurityLevel, metadata: ItemMetadata
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard resources.contains(where: { $0.id == id }) else {
            throw WorkspaceStoreError.invalid("Choose a resource first")
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Resource name is required") }
        let metadata = try Self.validatedMetadata(metadata)
        try await controlClient.updateResourceMetadata(
            resourceID: id, name: name, enforcement: securityLevel.rawValue,
            metadata: metadata)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    func discoverSshIdentities(endpoint: String) async throws -> [DiscoveredSshIdentity] {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let endpoint = (endpoint as NSString).expandingTildeInPath
        guard (endpoint as NSString).isAbsolutePath else {
            throw WorkspaceStoreError.invalid("SSH agent socket path must be absolute")
        }
        return try await controlClient.discoverSshIdentities(endpoint: endpoint)
    }

    @discardableResult
    func createSshAgentResource(
        name: String, endpoint: String, identities: [DiscoveredSshIdentity],
        metadata: ItemMetadata = .empty
    ) async throws -> WorkspaceResource.ID {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let endpoint = (endpoint as NSString).expandingTildeInPath
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Agent name is required") }
        guard (endpoint as NSString).isAbsolutePath else {
            throw WorkspaceStoreError.invalid("SSH agent socket path must be absolute")
        }
        guard !identities.isEmpty else {
            throw WorkspaceStoreError.invalid("The SSH agent did not advertise any identities")
        }
        let metadata = try Self.validatedMetadata(metadata)
        let resourceID = Self.newID("ssh-agent")
        try await controlClient.upsertResource(
            CatalogResource(
                id: resourceID, name: name, kind: "ssh_agent", shape: "socket",
                codec: "opaque", defaultEnvKey: nil,
                entries: identities.map { identity in
                    let comment = identity.comment.trimmingCharacters(in: .whitespacesAndNewlines)
                    return CatalogEntry(
                        address: identity.address,
                        label: comment.isEmpty ? identity.fingerprint : comment,
                        key: nil, sensitive: false)
                },
                source: .socket(endpoint), enforcement: WorkspaceSecurityLevel.confirmation.rawValue,
                metadata: metadata))
        apply(try await controlClient.snapshot())
        lastError = nil
        return resourceID
    }

    func removeSshAgentResource(_ id: WorkspaceResource.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard resources.contains(where: { $0.id == id && $0.kind == .sshAgent }) else {
            throw WorkspaceStoreError.invalid("Choose an SSH agent first")
        }
        try await controlClient.removeResource(id)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    @discardableResult
    func createEnvironment(name: String, fileName: String) async throws -> WorkspaceEnvironment.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        guard let project = selectedProject else {
            throw WorkspaceStoreError.invalid("Select a project first")
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else {
            throw WorkspaceStoreError.invalid("Environment name is required")
        }
        guard !project.environments.contains(where: {
            $0.name.compare(name, options: [.caseInsensitive, .diacriticInsensitive]) == .orderedSame
        }) else {
            throw WorkspaceStoreError.invalid("An environment named \(name) already exists")
        }
        let output = try newSurfaceOutput(fileName: fileName, in: project)
        let environmentID = Self.newID("environment")
        let surfaceID = Self.newID("dotenv")
        let commonBindingIDs = project.commonBindings
            .filter { bindingIsCompatible($0, with: .dotenvFile) }
            .map(\.id)
        try await controlClient.upsertEnvironment(
            CatalogEnvironment(
                id: environmentID, projectID: project.id, name: name,
                position: Int64(project.environments.count)))
        do {
            try await controlClient.upsertSurface(
                CatalogSurface(
                    id: surfaceID, environmentID: environmentID, name: output.name,
                    kind: "dotenv_file", path: output.path,
                    input: .bindings(commonBindingIDs), position: 0))
        } catch {
            try? await controlClient.removeEnvironment(environmentID)
            await reload()
            throw error
        }
        apply(try await controlClient.snapshot())
        selectedEnvironmentID = environmentID
        selectedSurfaceID = surfaceID
        lastError = nil
        return environmentID
    }

    @discardableResult
    func createDotenvSurface(
        fileName: String, bindingIDs: [WorkspaceBinding.ID]
    ) async throws -> WorkspaceSurface.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }
        let output = try newSurfaceOutput(fileName: fileName, in: project)
        let surfaceID = Self.newID("dotenv")
        try await controlClient.upsertSurface(
            CatalogSurface(
                id: surfaceID, environmentID: environment.id, name: output.name,
                kind: "dotenv_file", path: output.path, input: .bindings(bindingIDs),
                position: Int64(environment.surfaces.count)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = surfaceID
        lastError = nil
        return surfaceID
    }

    @discardableResult
    func createDirenvSurface(
        fileName: String, bindingIDs: [WorkspaceBinding.ID]
    ) async throws -> WorkspaceSurface.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }
        let output = try newSurfaceOutput(fileName: fileName, in: project)
        let surfaceID = Self.newID("direnv")
        try await controlClient.upsertSurface(
            CatalogSurface(
                id: surfaceID, environmentID: environment.id, name: output.name,
                kind: "direnv_file", path: output.path, input: .bindings(bindingIDs),
                position: Int64(environment.surfaces.count)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = surfaceID
        lastError = nil
        return surfaceID
    }

    @discardableResult
    func createIniSurface(
        fileName: String, bindingIDs: [WorkspaceBinding.ID]
    ) async throws -> WorkspaceSurface.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }
        let output = try newSurfaceOutput(fileName: fileName, in: project)
        let surfaceID = Self.newID("ini")
        try await controlClient.upsertSurface(
            CatalogSurface(
                id: surfaceID, environmentID: environment.id, name: output.name,
                kind: "ini_file", path: output.path, input: .bindings(bindingIDs),
                position: Int64(environment.surfaces.count)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = surfaceID
        lastError = nil
        return surfaceID
    }

    @discardableResult
    func createLinesSurface(
        fileName: String, bindingIDs: [WorkspaceBinding.ID]
    ) async throws -> WorkspaceSurface.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }
        let output = try newSurfaceOutput(fileName: fileName, in: project)
        let surfaceID = Self.newID("lines")
        try await controlClient.upsertSurface(
            CatalogSurface(
                id: surfaceID, environmentID: environment.id, name: output.name,
                kind: "lines_file", path: output.path, input: .bindings(bindingIDs),
                position: Int64(environment.surfaces.count)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = surfaceID
        lastError = nil
        return surfaceID
    }

    @discardableResult
    func createDirectEnvFileSurface(
        resourceID: WorkspaceResource.ID, fileName: String
    ) async throws -> WorkspaceSurface.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }
        guard envFileResources.contains(where: { $0.id == resourceID }) else {
            throw WorkspaceStoreError.invalid("Choose an Env File resource")
        }
        let output = try newSurfaceOutput(fileName: fileName, in: project)

        let surfaceID = Self.newID("direct-env-file")
        try await controlClient.upsertSurface(
            CatalogSurface(
                id: surfaceID, environmentID: environment.id, name: output.name,
                kind: "env_file_direct", path: output.path, input: .resource(resourceID),
                position: Int64(environment.surfaces.count)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = surfaceID
        lastError = nil
        return surfaceID
    }

    @discardableResult
    func createSshAgentSurface(
        resourceID: WorkspaceResource.ID, selectedEntries: Set<String>, socketName: String,
        securityLevel: WorkspaceSecurityLevel
    ) async throws -> WorkspaceSurface.ID {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }
        guard let resource = sshAgentResources.first(where: { $0.id == resourceID }) else {
            throw WorkspaceStoreError.invalid("Choose an SSH agent")
        }
        let addresses = resource.entries.map(\.address).filter(selectedEntries.contains)
        guard !addresses.isEmpty else {
            throw WorkspaceStoreError.invalid("Select at least one SSH identity")
        }
        let output = try newSurfaceOutput(fileName: socketName, in: project)
        let bindingID = Self.newID("binding")
        let surfaceID = Self.newID("ssh-agent")
        let selection: CatalogEntrySelection = addresses.count == resource.entries.count
            ? .all : .entries(addresses)
        try await controlClient.upsertBinding(
            CatalogBinding(
                id: bindingID, projectID: project.id, scope: .environment(environment.id),
                resourceID: resource.id, selection: selection, keyOverride: nil, enabled: true,
                allowOverride: false, position: Int64(environment.bindings.count)))
        do {
            try await controlClient.upsertSurface(
                CatalogSurface(
                    id: surfaceID, environmentID: environment.id, name: output.name,
                    kind: "unix_socket", path: output.path, input: .bindings([bindingID]),
                    enforcement: securityLevel.rawValue,
                    position: Int64(environment.surfaces.count)))
        } catch {
            try? await controlClient.removeBinding(bindingID)
            throw error
        }
        apply(try await controlClient.snapshot())
        selectedSurfaceID = surfaceID
        lastError = nil
        return surfaceID
    }

    func toggleBinding(_ id: WorkspaceBinding.ID) async {
        guard let binding = (commonBindings + environmentBindings).first(where: { $0.id == id })
        else { return }
        guard let controlClient, let project = selectedProject else {
            toggleBindingLocally(id)
            return
        }

        do {
            try await controlClient.upsertBinding(
                CatalogBinding(
                    id: binding.id, projectID: project.id,
                    scope: binding.scope.catalogScope,
                    resourceID: binding.resourceID, selection: binding.selection.catalogSelection,
                    keyOverride: binding.keyOverride,
                    enabled: !binding.isEnabled, allowOverride: binding.allowOverride,
                    position: binding.position))
            apply(try await controlClient.snapshot())
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func addResource(
        _ resourceID: WorkspaceResource.ID, target: WorkspaceBindingTarget = .environment,
        selectedEntries: Set<String>? = nil, surfaceID requestedSurfaceID: WorkspaceSurface.ID? = nil
    ) async throws {
        guard let resource = availableResources.first(where: { $0.id == resourceID }) else {
            return
        }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }
        let surfaceID = requestedSurfaceID ?? selectedSurfaceID
        guard let surface = environment.surfaces.first(where: { $0.id == surfaceID }),
            surface.kind == .dotenvFile || surface.kind == .direnvFile || surface.kind == .iniFile
                || surface.kind == .linesFile || surface.kind == .unixSocket
        else {
            throw WorkspaceStoreError.invalid("Choose a composed output for this binding")
        }

        let scope: WorkspaceBindingScope =
            target == .common ? .common : .environment(environment.id)
        let position = Int64(
            target == .common ? project.commonBindings.count : environment.bindings.count)
        let selection: CatalogEntrySelection
        if resource.entries.isEmpty || selectedEntries == nil
            || selectedEntries?.count == resource.entries.count
        {
            selection = .all
        } else {
            let addresses = resource.entries.map(\.address).filter { selectedEntries?.contains($0) == true }
            guard !addresses.isEmpty else {
                throw WorkspaceStoreError.invalid("Select at least one entry")
            }
            selection = .entries(addresses)
        }
        let bindingID = Self.newID("binding")
        let workspaceBinding = WorkspaceBinding(
            id: bindingID, resourceID: resourceID,
            selection: WorkspaceEntrySelection(selection), keyOverride: nil, isEnabled: true,
            scope: scope, allowOverride: false, position: position)
        guard bindingIsCompatible(workspaceBinding, with: surface.kind) else {
            throw WorkspaceStoreError.invalid(
                "This resource cannot feed the selected \(surface.kind.title) output")
        }
        guard let controlClient else {
            addResourceLocally(resourceID, binding: workspaceBinding, surfaceID: surfaceID)
            return
        }
        try await controlClient.upsertBinding(
            CatalogBinding(
                id: bindingID, projectID: project.id, scope: scope.catalogScope,
                resourceID: resourceID, selection: selection, keyOverride: nil, enabled: true,
                allowOverride: false, position: position))
        do {
            try await controlClient.upsertSurface(
                CatalogSurface(
                    id: surface.id, environmentID: environment.id, name: surface.name,
                    kind: surface.kind.catalogValue, path: surface.path,
                    input: .bindings(surface.bindingIDs + [bindingID]),
                    enforcement: surface.securityLevel.rawValue,
                    position: Int64(
                        environment.surfaces.firstIndex(where: { $0.id == surface.id }) ?? 0)))
        } catch {
            try? await controlClient.removeBinding(bindingID)
            throw error
        }
        apply(try await controlClient.snapshot())
        selectedSurfaceID = surfaceID
        lastError = nil
    }

    func removeProject(_ id: WorkspaceProject.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        try await controlClient.removeProject(id)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    func removeEnvironment(_ id: WorkspaceEnvironment.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let project = selectedProject, project.environments.count > 1 else {
            throw WorkspaceStoreError.invalid("A project must keep at least one environment")
        }
        try await controlClient.removeEnvironment(id)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    func removeBinding(_ id: WorkspaceBinding.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        try await controlClient.removeBinding(id)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    func deleteSurface(_ id: WorkspaceSurface.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        try await controlClient.removeSurface(id)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    func removeSurface(_ id: WorkspaceSurface.ID) async throws {
        try await deleteSurface(id)
    }

    func updateSurfaceSecurityLevel(
        _ id: WorkspaceSurface.ID, securityLevel: WorkspaceSecurityLevel
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let environment = selectedEnvironment,
            let position = environment.surfaces.firstIndex(where: { $0.id == id }),
            let surface = environment.surfaces.first(where: { $0.id == id })
        else {
            throw WorkspaceStoreError.invalid("Select an output first")
        }
        try await controlClient.upsertSurface(
            CatalogSurface(
                id: surface.id, environmentID: environment.id, name: surface.name,
                kind: surface.kind.catalogValue, path: surface.path,
                input: surface.input.catalogInput, enforcement: securityLevel.rawValue,
                position: Int64(position)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = id
        lastError = nil
    }

    func updateSurface(
        _ id: WorkspaceSurface.ID, fileName: String, kind: WorkspaceSurfaceKind,
        bindingIDs: [WorkspaceBinding.ID]
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let project = selectedProject, let environment = selectedEnvironment,
            let position = environment.surfaces.firstIndex(where: { $0.id == id }),
            let surface = environment.surfaces.first(where: { $0.id == id })
        else {
            throw WorkspaceStoreError.invalid("Select an output first")
        }
        let output = try newSurfaceOutput(
            fileName: fileName, in: project, excludingSurfaceID: id)

        let input: CatalogSurfaceInput
        switch surface.input {
        case .bindings:
            guard kind.isComposed || (surface.kind == .unixSocket && kind == .unixSocket) else {
                throw WorkspaceStoreError.invalid("Choose a composed output format")
            }
            let allowed = Set(compatibleBindings(for: kind).map(\.id))
            guard bindingIDs.allSatisfy(allowed.contains) else {
                throw WorkspaceStoreError.invalid(
                    "One or more bindings cannot feed the selected format")
            }
            input = .bindings(bindingIDs)
        case .resource(let resourceID):
            guard kind == surface.kind else {
                throw WorkspaceStoreError.invalid("Direct outputs keep their source format")
            }
            input = .resource(resourceID)
        }

        try await controlClient.upsertSurface(
            CatalogSurface(
                id: id, environmentID: environment.id, name: output.name,
                kind: kind.catalogValue, path: output.path, input: input,
                enforcement: surface.securityLevel.rawValue,
                position: Int64(position)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = id
        lastError = nil
    }

    func updateSurfaceBindings(
        _ id: WorkspaceSurface.ID, bindingIDs: [WorkspaceBinding.ID]
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let environment = selectedEnvironment,
            let position = environment.surfaces.firstIndex(where: { $0.id == id }),
            let surface = environment.surfaces.first(where: { $0.id == id }),
            surface.kind == .dotenvFile || surface.kind == .direnvFile || surface.kind == .iniFile
                || surface.kind == .linesFile || surface.kind == .unixSocket
        else {
            throw WorkspaceStoreError.invalid("Choose a composed output first")
        }
        let allowed = Set(compatibleBindings(for: surface.kind).map(\.id))
        guard bindingIDs.allSatisfy(allowed.contains) else {
            throw WorkspaceStoreError.invalid("One or more bindings cannot feed this output")
        }
        try await controlClient.upsertSurface(
            CatalogSurface(
                id: surface.id, environmentID: environment.id, name: surface.name,
                kind: surface.kind.catalogValue, path: surface.path,
                input: .bindings(bindingIDs), enforcement: surface.securityLevel.rawValue,
                position: Int64(position)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = id
        lastError = nil
    }

    func repairSurfaceLink(_ id: WorkspaceSurface.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let environment = selectedEnvironment,
            let position = environment.surfaces.firstIndex(where: { $0.id == id }),
            let surface = environment.surfaces.first(where: { $0.id == id })
        else {
            throw WorkspaceStoreError.invalid("Select an output surface first")
        }
        try await controlClient.upsertSurface(
            CatalogSurface(
                id: surface.id, environmentID: environment.id, name: surface.name,
                kind: surface.kind.catalogValue, path: surface.path,
                input: surface.input.catalogInput,
                enforcement: surface.securityLevel.rawValue, position: Int64(position)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = id
        guard managedLinkTarget(for: surface) == expectedLinkTarget(for: surface) else {
            throw WorkspaceStoreError.invalid(
                "The path is occupied by another file or link. Floria did not replace it.")
        }
        lastError = nil
    }

    func expectedLinkTarget(for surface: WorkspaceSurface) -> String {
        if surface.kind == .unixSocket {
            return (NSHomeDirectory() as NSString).appendingPathComponent(
                "Library/Application Support/floria/runtime/sockets/\(surface.id).sock")
        }
        return (NSHomeDirectory() as NSString).appendingPathComponent(
            ".accessfs/surfaces/\(surface.id)")
    }

    func managedLinkTarget(for surface: WorkspaceSurface) -> String? {
        try? FileManager.default.destinationOfSymbolicLink(atPath: surface.path)
    }

    private func newSurfaceOutput(
        fileName: String, in project: WorkspaceProject,
        excludingSurfaceID: WorkspaceSurface.ID? = nil
    ) throws -> (name: String, path: String) {
        let name = fileName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name != ".", name != "..",
            (name as NSString).lastPathComponent == name
        else {
            throw WorkspaceStoreError.invalid("Output name must be one file name")
        }
        let path = (project.path as NSString).appendingPathComponent(name)
        guard !project.environments.flatMap(\.surfaces).contains(where: {
            $0.id != excludingSurfaceID && $0.path == path
        }) else {
            throw WorkspaceStoreError.invalid("\(path) is already used by another output")
        }
        if let existing = project.environments.flatMap(\.surfaces).first(where: {
            $0.id == excludingSurfaceID
        }), existing.path == path {
            return (name, path)
        }
        var fileInfo = stat()
        let status = path.withCString { lstat($0, &fileInfo) }
        guard status != 0 else {
            throw WorkspaceStoreError.invalid(
                "\(path) already exists. Floria will never replace it automatically.")
        }
        guard errno == ENOENT else {
            throw WorkspaceStoreError.invalid("Floria could not inspect \(path)")
        }
        return (name, path)
    }

    private func toggleBindingLocally(_ id: WorkspaceBinding.ID) {
        guard let projectIndex = projects.firstIndex(where: { $0.id == selectedProjectID }) else {
            return
        }
        if let bindingIndex = projects[projectIndex].commonBindings.firstIndex(where: { $0.id == id }) {
            projects[projectIndex].commonBindings[bindingIndex].isEnabled.toggle()
            return
        }
        guard
            let environmentIndex = projects[projectIndex].environments.firstIndex(where: {
                $0.id == selectedEnvironmentID
            }),
            let bindingIndex = projects[projectIndex].environments[environmentIndex].bindings
                .firstIndex(where: { $0.id == id })
        else { return }
        projects[projectIndex].environments[environmentIndex].bindings[bindingIndex].isEnabled.toggle()
    }

    private func addResourceLocally(
        _ resourceID: WorkspaceResource.ID, binding: WorkspaceBinding,
        surfaceID: WorkspaceSurface.ID
    ) {
        guard
            availableResources.contains(where: { $0.id == resourceID }),
            let projectIndex = projects.firstIndex(where: { $0.id == selectedProjectID }),
            let environmentIndex = projects[projectIndex].environments.firstIndex(where: {
                $0.id == selectedEnvironmentID
            })
        else { return }

        switch binding.scope {
        case .common:
            projects[projectIndex].commonBindings.append(binding)
        case .environment:
            projects[projectIndex].environments[environmentIndex].bindings.append(binding)
        }
        guard let surfaceIndex = projects[projectIndex].environments[environmentIndex].surfaces
            .firstIndex(where: { $0.id == surfaceID })
        else { return }
        let surface = projects[projectIndex].environments[environmentIndex].surfaces[surfaceIndex]
        projects[projectIndex].environments[environmentIndex].surfaces[surfaceIndex] =
            WorkspaceSurface(
                id: surface.id, name: surface.name, kind: surface.kind, path: surface.path,
                status: surface.status, input: .bindings(surface.bindingIDs + [binding.id]))
    }

    private func apply(_ snapshot: CatalogSnapshot, selectingProject: String? = nil) {
        let previousProjectID = selectingProject ?? selectedProjectID
        let previousEnvironmentID = selectedEnvironmentID
        let previousSurfaceID = selectedSurfaceID
        let projectUsage = Dictionary(grouping: snapshot.bindings, by: \.resourceID)
            .mapValues { Set($0.map(\.projectID)).count }

        resources = snapshot.resources.compactMap { resource in
            guard
                let kind = WorkspaceResourceKind(catalogValue: resource.kind),
                let shape = WorkspaceValueShape(catalogValue: resource.shape),
                let codec = WorkspaceResourceCodec(rawValue: resource.codec)
            else { return nil }
            let preview: String
            switch resource.source.type {
            case "literal": preview = resource.source.value ?? ""
            case "socket": preview = resource.source.endpoint ?? ""
            default: preview = "••••••••••••"
            }
            let entries = resource.entries.map {
                WorkspaceEntry(
                    address: $0.address, label: $0.label, key: $0.key,
                    previewValue: preview,
                    sensitive: $0.sensitive)
            }
            return WorkspaceResource(
                id: resource.id, name: resource.name, kind: kind, shape: shape, codec: codec,
                defaultEnvKey: resource.defaultEnvKey,
                exports: [],
                entries: entries,
                securityLevel: WorkspaceSecurityLevel(catalogValue: resource.enforcement),
                metadata: resource.metadata,
                usageCount: projectUsage[resource.id] ?? 0)
        }

        let bindings = Dictionary(grouping: snapshot.bindings, by: \.projectID)
        let environments = Dictionary(grouping: snapshot.environments, by: \.projectID)
        let surfaces = Dictionary(grouping: snapshot.surfaces, by: \.environmentID)
        projects = snapshot.projects.map { project in
            let projectBindings = bindings[project.id] ?? []
            let common = projectBindings
                .filter { $0.scope.type == "common" }
                .sorted { $0.position < $1.position }
                .map(WorkspaceBinding.init)
            let projectEnvironments = (environments[project.id] ?? [])
                .sorted { $0.position < $1.position }
                .map { environment in
                    let environmentBindings = projectBindings
                        .filter { $0.scope.environmentID == environment.id }
                        .sorted { $0.position < $1.position }
                        .map(WorkspaceBinding.init)
                    let environmentSurfaces = (surfaces[environment.id] ?? [])
                        .sorted { $0.position < $1.position }
                        .compactMap(WorkspaceSurface.init)
                    return WorkspaceEnvironment(
                        id: environment.id, name: environment.name,
                        bindings: environmentBindings, surfaces: environmentSurfaces)
                }
            return WorkspaceProject(
                id: project.id, name: project.name, path: project.path,
                commonBindings: common, environments: projectEnvironments)
        }

        let selectedProject = projects.first(where: { $0.id == previousProjectID }) ?? projects.first
        selectedProjectID = selectedProject?.id ?? ""
        let selectedEnvironment = selectedProject?.environments.first(where: {
            $0.id == previousEnvironmentID
        }) ?? selectedProject?.environments.first
        selectedEnvironmentID = selectedEnvironment?.id ?? ""
        let selectedSurface = selectedEnvironment?.surfaces.first(where: {
            $0.id == previousSurfaceID
        }) ?? selectedEnvironment?.surfaces.first
        selectedSurfaceID = selectedSurface?.id ?? ""
    }

    private static func newID(_ prefix: String) -> String {
        "\(prefix)-\(UUID().uuidString.lowercased())"
    }

    static func isValidEnvKey(_ key: String) -> Bool {
        key.range(of: "^[A-Z_][A-Z0-9_]*$", options: .regularExpression) != nil
    }

    static func validatedMetadata(_ metadata: ItemMetadata) throws -> ItemMetadata {
        let trimmedNote = metadata.note?.trimmingCharacters(in: .whitespacesAndNewlines)
        let note = trimmedNote.flatMap { $0.isEmpty ? nil : $0 }
        guard note?.utf8.count ?? 0 <= 4096 else {
            throw WorkspaceStoreError.invalid("Note cannot exceed 4096 bytes")
        }
        guard metadata.links.count <= 16 else {
            throw WorkspaceStoreError.invalid("Add no more than 16 links")
        }
        let links = try metadata.links.map { link in
            let label = link.label.trimmingCharacters(in: .whitespacesAndNewlines)
            let url = link.url.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !label.isEmpty, !url.isEmpty else {
                throw WorkspaceStoreError.invalid("Every link needs a label and URL")
            }
            guard label.utf8.count <= 100, url.utf8.count <= 2048 else {
                throw WorkspaceStoreError.invalid("A link label or URL is too long")
            }
            guard let components = URLComponents(string: url),
                components.scheme == "https" || components.scheme == "http",
                components.host?.isEmpty == false,
                components.user == nil, components.password == nil
            else {
                throw WorkspaceStoreError.invalid(
                    "Links must use a valid http:// or https:// URL without credentials")
            }
            return ItemLink(label: label, url: url)
        }
        return ItemMetadata(note: note, links: links)
    }
}

private extension WorkspaceBinding {
    init(_ binding: CatalogBinding) {
        let scope: WorkspaceBindingScope = binding.scope.type == "common"
            ? .common : .environment(binding.scope.environmentID ?? "")
        self.init(
            id: binding.id, resourceID: binding.resourceID,
            selection: WorkspaceEntrySelection(binding.selection), keyOverride: binding.keyOverride,
            isEnabled: binding.enabled, scope: scope, allowOverride: binding.allowOverride,
            position: binding.position)
    }
}

private extension WorkspaceEntrySelection {
    init(_ selection: CatalogEntrySelection) {
        self = selection.type == "entries"
            ? .entries(selection.addresses ?? []) : .all
    }

    var catalogSelection: CatalogEntrySelection {
        switch self {
        case .all: .all
        case .entries(let addresses): .entries(addresses)
        }
    }
}

private extension WorkspaceBindingScope {
    var catalogScope: CatalogBindingScope {
        switch self {
        case .common: .common
        case .environment(let id): .environment(id)
        }
    }
}

private extension WorkspaceProtectedFile {
    init(_ file: CatalogProtectedFile) {
        self.init(
            id: file.id, path: file.sourcePath, mode: file.mode, size: file.size,
            currentVersion: file.currentVersion, linked: file.linked,
            securityLevel: WorkspaceSecurityLevel(catalogValue: file.enforcement),
            metadata: file.metadata)
    }
}

private extension WorkspaceSurface {
    init?(_ surface: CatalogSurface) {
        guard let kind = WorkspaceSurfaceKind(catalogValue: surface.kind) else { return nil }
        let input: WorkspaceSurfaceInput
        switch surface.input.type {
        case "bindings": input = .bindings(surface.input.bindingIDs ?? [])
        case "resource":
            guard let resourceID = surface.input.resourceID else { return nil }
            input = .resource(resourceID)
        default: return nil
        }
        let expectedTarget = (NSHomeDirectory() as NSString).appendingPathComponent(
            kind == .unixSocket
                ? "Library/Application Support/floria/runtime/sockets/\(surface.id).sock"
                : ".accessfs/surfaces/\(surface.id)")
        let linkTarget = try? FileManager.default.destinationOfSymbolicLink(atPath: surface.path)
        let status: WorkspaceSurfaceStatus = linkTarget == expectedTarget
            ? (kind == .unixSocket ? .listening : .linked) : .stopped
        self.init(
            id: surface.id, name: surface.name, kind: kind, path: surface.path,
            status: status, input: input,
            securityLevel: WorkspaceSecurityLevel(catalogValue: surface.enforcement))
    }
}

private extension WorkspaceSurfaceInput {
    var catalogInput: CatalogSurfaceInput {
        switch self {
        case .bindings(let ids): .bindings(ids)
        case .resource(let id): .resource(id)
        }
    }
}

private extension WorkspaceResourceKind {
    init?(catalogValue: String) {
        switch catalogValue {
        case "shared_secret": self = .sharedSecret
        case "secret": self = .secret
        case "env_file": self = .envFile
        case "literal": self = .literal
        case "command": self = .command
        case "ssh_agent": self = .sshAgent
        default: return nil
        }
    }
}

private extension WorkspaceValueShape {
    init?(catalogValue: String) {
        switch catalogValue {
        case "scalar": self = .scalar
        case "key_value_set": self = .keyValueSet
        case "bytes": self = .bytes
        case "socket": self = .socket
        default: return nil
        }
    }
}

private extension WorkspaceSurfaceKind {
    var catalogValue: String {
        switch self {
        case .dotenvFile: "dotenv_file"
        case .direnvFile: "direnv_file"
        case .iniFile: "ini_file"
        case .envFileDirect: "env_file_direct"
        case .linesFile: "lines_file"
        case .regularFile: "regular_file"
        case .unixSocket: "unix_socket"
        }
    }

    init?(catalogValue: String) {
        switch catalogValue {
        case "dotenv_file": self = .dotenvFile
        case "direnv_file": self = .direnvFile
        case "ini_file": self = .iniFile
        case "env_file_direct": self = .envFileDirect
        case "lines_file": self = .linesFile
        case "regular_file": self = .regularFile
        case "unix_socket": self = .unixSocket
        default: return nil
        }
    }
}

enum WorkspaceStoreError: LocalizedError {
    case controlUnavailable
    case invalid(String)

    var errorDescription: String? {
        switch self {
        case .controlUnavailable: "The daemon control service is unavailable"
        case .invalid(let message): message
        }
    }
}

extension WorkspaceStore {
    static func preview() -> WorkspaceStore {
        let home = NSHomeDirectory()
        let socketPath = "\(home)/Library/Application Support/floria/runtime/sockets/floria-web-dev.sock"
        let resources = [
            WorkspaceResource(
                id: "cloudflare-token", name: "Cloudflare API Token", kind: .sharedSecret,
                shape: .scalar,
                exports: [
                    WorkspaceExport(
                        key: "CLOUDFLARE_API_TOKEN", previewValue: "••••••••••••", sensitive: true)
                ],
                metadata: ItemMetadata(
                    note: "Account-wide token for DNS automation",
                    links: [ItemLink(label: "Cloudflare dashboard", url: "https://dash.cloudflare.com")]),
                usageCount: 12),
            WorkspaceResource(
                id: "team-defaults", name: "Team defaults", kind: .envFile,
                shape: .keyValueSet,
                exports: [
                    WorkspaceExport(
                        key: "API_BASE_URL", previewValue: "http://localhost:8787", sensitive: false),
                    WorkspaceExport(key: "LOG_LEVEL", previewValue: "debug", sensitive: false),
                    WorkspaceExport(key: "FEATURE_FLAGS", previewValue: "local-dev", sensitive: false),
                    WorkspaceExport(key: "WORKER_ENV", previewValue: "development", sensitive: false),
                    WorkspaceExport(key: "REGION", previewValue: "local", sensitive: false),
                    WorkspaceExport(key: "TRACE_SAMPLE_RATE", previewValue: "1.0", sensitive: false),
                ],
                usageCount: 8),
            WorkspaceResource(
                id: "local-database", name: "Local database", kind: .envFile,
                shape: .keyValueSet,
                exports: [
                    WorkspaceExport(key: "DATABASE_URL", previewValue: "••••••••••••", sensitive: true),
                    WorkspaceExport(key: "REDIS_URL", previewValue: "••••••••••••", sensitive: true),
                    WorkspaceExport(key: "DATABASE_POOL", previewValue: "5", sensitive: false),
                ],
                metadata: ItemMetadata(note: "Local PostgreSQL and Redis services", links: []),
                usageCount: 1),
            WorkspaceResource(
                id: "app-env", name: "APP_ENV", kind: .literal, shape: .scalar,
                exports: [
                    WorkspaceExport(key: "APP_ENV", previewValue: "development", sensitive: false)
                ],
                usageCount: 1),
            WorkspaceResource(
                id: "developer-ssh-agent", name: "Developer SSH Agent", kind: .sshAgent,
                shape: .socket,
                exports: [
                    WorkspaceExport(key: "SSH_AUTH_SOCK", previewValue: socketPath, sensitive: false)
                ],
                metadata: ItemMetadata(note: "SSH signing proxy", links: []), usageCount: 3),
            WorkspaceResource(
                id: "sentry-dsn", name: "Sentry DSN", kind: .sharedSecret, shape: .scalar,
                exports: [
                    WorkspaceExport(key: "SENTRY_DSN", previewValue: "••••••••••••", sensitive: true)
                ],
                usageCount: 5),
            WorkspaceResource(
                id: "github-token", name: "GitHub Automation Token", kind: .sharedSecret,
                shape: .scalar,
                exports: [
                    WorkspaceExport(key: "GITHUB_TOKEN", previewValue: "••••••••••••", sensitive: true)
                ],
                usageCount: 4),
        ]

        func binding(_ id: String, _ resourceID: String) -> WorkspaceBinding {
            WorkspaceBinding(id: id, resourceID: resourceID, keyOverride: nil, isEnabled: true)
        }

        func dotenv(
            _ prefix: String, _ project: String, bindingIDs: [WorkspaceBinding.ID]
        ) -> WorkspaceSurface {
            WorkspaceSurface(
                id: "\(prefix)-dotenv", name: ".env", kind: .dotenvFile,
                path: "~/workspace/\(project)/.env", status: .linked,
                input: .bindings(bindingIDs))
        }

        let floria = WorkspaceProject(
            id: "floria-web", name: "floria-web", path: "~/workspace/floria-web",
            commonBindings: [
                binding("floria-common-cloudflare", "cloudflare-token"),
                binding("floria-common-team", "team-defaults"),
            ],
            environments: [
                WorkspaceEnvironment(
                    id: "floria-development", name: "Development",
                    bindings: [
                        binding("floria-dev-db", "local-database"),
                        binding("floria-dev-app-env", "app-env"),
                        binding("floria-dev-ssh", "developer-ssh-agent"),
                    ],
                    surfaces: [
                        dotenv(
                            "floria-dev", "floria-web",
                            bindingIDs: [
                                "floria-common-cloudflare", "floria-common-team",
                                "floria-dev-db", "floria-dev-app-env",
                            ]),
                        WorkspaceSurface(
                            id: "floria-dev-ssh-socket", name: "SSH Agent", kind: .unixSocket,
                            path: socketPath, status: .listening,
                            input: .resource("developer-ssh-agent")),
                    ]),
                WorkspaceEnvironment(
                    id: "floria-staging", name: "Staging",
                    bindings: [binding("floria-staging-app-env", "app-env")],
                    surfaces: [
                        dotenv(
                            "floria-staging", "floria-web",
                            bindingIDs: [
                                "floria-common-cloudflare", "floria-common-team",
                                "floria-staging-app-env",
                            ])
                    ]),
                WorkspaceEnvironment(
                    id: "floria-production", name: "Production",
                    bindings: [binding("floria-prod-sentry", "sentry-dsn")],
                    surfaces: [
                        dotenv(
                            "floria-production", "floria-web",
                            bindingIDs: [
                                "floria-common-cloudflare", "floria-common-team",
                                "floria-prod-sentry",
                            ])
                    ]),
            ])

        let billing = WorkspaceProject(
            id: "billing-api", name: "billing-api", path: "~/workspace/billing-api",
            commonBindings: [binding("billing-cloudflare", "cloudflare-token")],
            environments: [
                WorkspaceEnvironment(
                    id: "billing-development", name: "Development",
                    bindings: [binding("billing-dev-db", "local-database")],
                    surfaces: [
                        dotenv(
                            "billing-dev", "billing-api",
                            bindingIDs: ["billing-cloudflare", "billing-dev-db"])
                    ]),
                WorkspaceEnvironment(
                    id: "billing-production", name: "Production", bindings: [],
                    surfaces: [
                        dotenv(
                            "billing-prod", "billing-api",
                            bindingIDs: ["billing-cloudflare"])
                    ]),
            ])

        let workers = WorkspaceProject(
            id: "worker-jobs", name: "worker-jobs", path: "~/workspace/worker-jobs",
            commonBindings: [binding("workers-github", "github-token")],
            environments: [
                WorkspaceEnvironment(
                    id: "workers-development", name: "Development", bindings: [],
                    surfaces: [
                        dotenv(
                            "workers-dev", "worker-jobs",
                            bindingIDs: ["workers-github"])
                    ])
            ])

        return WorkspaceStore(
            projects: [floria, billing, workers], resources: resources,
            selectedProjectID: floria.id)
    }
}
