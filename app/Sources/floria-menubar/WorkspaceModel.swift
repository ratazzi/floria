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
        case .auditOnly: "list.bullet.clipboard"
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
    case sshIdentity
    case sshAgent

    var title: String {
        switch self {
        case .sharedSecret: "Shared Secret"
        case .secret: "Secret"
        case .envFile: "Env File"
        case .literal: "Literal"
        case .command: "Command"
        case .sshIdentity: "SSH Identity"
        case .sshAgent: "External Agent"
        }
    }

    var systemImage: String {
        switch self {
        case .sharedSecret, .secret: "key.fill"
        case .envFile: "doc.badge.gearshape"
        case .literal: "chevron.left.forwardslash.chevron.right"
        case .command: "terminal.fill"
        case .sshIdentity: "key.horizontal.fill"
        case .sshAgent: "network"
        }
    }
}

enum WorkspaceValueShape: String, Sendable {
    case scalar
    case keyValueSet
    case bytes
    case sshIdentity
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
    let origin: CatalogResourceOrigin?
    let usageCount: Int

    init(
        id: String, name: String, kind: WorkspaceResourceKind, shape: WorkspaceValueShape,
        codec: WorkspaceResourceCodec? = nil,
        defaultEnvKey: String? = nil,
        exports: [WorkspaceExport], entries: [WorkspaceEntry] = [],
        securityLevel: WorkspaceSecurityLevel = .confirmation,
        metadata: ItemMetadata = .empty,
        origin: CatalogResourceOrigin? = nil,
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
        self.origin = origin
        self.usageCount = usageCount
    }

    /// Discovery/import provenance, tilde-abbreviated for one-line display.
    var originSummary: String? {
        let sources = origin?.sources ?? []
        guard let first = sources.first else { return nil }
        let path = (first.path as NSString).abbreviatingWithTildeInPath
        return sources.count > 1 ? "\(path) +\(sources.count - 1)" : path
    }

    var originSources: [CatalogOriginSource] {
        origin?.sources ?? []
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
        if kind == .sshIdentity || kind == .sshAgent {
            return "\(entries.count) identit\(entries.count == 1 ? "y" : "ies")"
        }
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
    case unixSocket

    var title: String {
        switch self {
        case .dotenvFile: "Dotenv File"
        case .direnvFile: "direnv File"
        case .iniFile: "INI File"
        case .envFileDirect: "Direct Env File"
        case .linesFile: "Lines File"
        case .unixSocket: "Unix Socket"
        }
    }

    var managedTitle: String {
        switch self {
        case .dotenvFile, .direnvFile, .envFileDirect: "Env file"
        case .iniFile: "Credentials file"
        case .linesFile: "Text file"
        case .unixSocket: "Socket"
        }
    }

    var systemImage: String {
        switch self {
        case .dotenvFile: "doc.text"
        case .direnvFile: "terminal"
        case .iniFile: "list.bullet.rectangle"
        case .envFileDirect: "doc.text.fill"
        case .linesFile: "text.line.first.and.arrowtriangle.forward"
        case .unixSocket: "point.3.connected.trianglepath.dotted"
        }
    }

    var isFile: Bool {
        self != .unixSocket
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
        case .unixSocket: "SSH Agent"
        }
    }

    static var composedCases: [WorkspaceSurfaceKind] {
        allCases.filter(\.isComposed)
    }
}

struct WorkspaceManagedLink: Hashable, Sendable {
    let path: String
    let status: ManagedLinkStatus

    var isReady: Bool { status == .linked }
    var needsAttention: Bool { !isReady }

    var statusTitle: String {
        isReady ? "Ready" : "Needs attention"
    }

    var issueDescription: String? {
        switch status {
        case .linked:
            nil
        case .missing:
            "This path is not linked. Repair it to restore access."
        case .replaced:
            "Another file or symbolic link occupies this path. Floria will not replace a regular file."
        }
    }
}

struct WorkspaceSurface: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let kind: WorkspaceSurfaceKind
    let path: String?
    let managedLink: WorkspaceManagedLink?
    let input: WorkspaceSurfaceInput
    let securityLevel: WorkspaceSecurityLevel

    init(
        id: String, name: String, kind: WorkspaceSurfaceKind, path: String?,
        linkStatus: ManagedLinkStatus?, input: WorkspaceSurfaceInput,
        securityLevel: WorkspaceSecurityLevel = .confirmation
    ) {
        self.id = id
        self.name = name
        self.kind = kind
        self.path = path
        managedLink = path.map {
            WorkspaceManagedLink(path: $0, status: linkStatus ?? .missing)
        }
        self.input = input
        self.securityLevel = securityLevel
    }

    var bindingIDs: [WorkspaceBinding.ID] {
        switch input {
        case .bindings(let ids), .sshAgent(let ids, _): ids
        case .resource: []
        }
    }

    var resourceID: WorkspaceResource.ID? {
        guard case .resource(let id) = input else { return nil }
        return id
    }

    var sshRoute: WorkspaceSshRoute? {
        guard case .sshAgent(_, let route) = input else { return nil }
        return route
    }
}

enum WorkspaceSurfaceInput: Hashable, Sendable {
    case bindings([WorkspaceBinding.ID])
    case sshAgent([WorkspaceBinding.ID], WorkspaceSshRoute?)
    case resource(WorkspaceResource.ID)
}

struct WorkspaceSshRoute: Hashable, Sendable {
    let hostPatterns: [String]
    let hostname: String?
    let user: String?
    let port: UInt16?
    let forwardAgent: Bool

    var catalogValue: CatalogSshRoute {
        CatalogSshRoute(
            hostPatterns: hostPatterns, hostname: hostname, user: user, port: port,
            forwardAgent: forwardAgent)
    }
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
    /// Newly discovered worktrees auto-link to this environment; nil keeps linking manual.
    var defaultEnvironmentID: WorkspaceEnvironment.ID? = nil
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
        if name == ".env" || name.hasPrefix(".env.")
            || name == ".dev.vars" || name.hasPrefix(".dev.vars.")
        {
            return .dotenv
        }
        return .file
    }

    var title: String {
        switch self {
        case .dotenv: "Env file"
        case .direnv: "Shell environment"
        case .pgpass: "PostgreSQL password file"
        case .awsCredentials: "AWS credentials"
        case .file: "File"
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

    var isConfigurable: Bool {
        switch self {
        case .dotenv, .direnv, .awsCredentials: true
        case .pgpass, .file: false
        }
    }
}

struct WorkspaceProtectedFile: Identifiable, Hashable, Sendable {
    let id: String
    let path: String
    let mode: UInt32
    let size: UInt64
    let currentVersion: UInt32
    let managedLink: WorkspaceManagedLink
    let securityLevel: WorkspaceSecurityLevel
    let environmentIDs: [WorkspaceEnvironment.ID]
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
    var checkouts: [CatalogProjectCheckout]
    var checkoutDiscoveries: [WorkspaceProject.ID: ProjectCheckoutDiscovery]
    var resources: [WorkspaceResource]
    var protectedFiles: [WorkspaceProtectedFile]
    var selectedProjectID: WorkspaceProject.ID
    var selectedEnvironmentID: WorkspaceEnvironment.ID
    var selectedSurfaceID: WorkspaceSurface.ID
    var isLoading = false
    var lastError: String?

    @ObservationIgnored private let controlClient: ControlClient?
    @ObservationIgnored private var autoProvisionAttempted: Set<String> = []
    @ObservationIgnored private var managedLinkStatuses: [String: ManagedLinkStatus] = [:]

    init(
        projects: [WorkspaceProject], resources: [WorkspaceResource],
        selectedProjectID: WorkspaceProject.ID = "", controlClient: ControlClient? = nil
    ) {
        self.projects = projects
        checkouts = []
        checkoutDiscoveries = [:]
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

    func project(containingManagedPath path: String) -> WorkspaceProject? {
        let source = URL(fileURLWithPath: path).standardizedFileURL.path
        return projects
            .filter { project in
                let root = URL(fileURLWithPath: project.path).standardizedFileURL.path
                return source == root || source.hasPrefix(root + "/")
            }
            .max { left, right in left.path.count < right.path.count }
    }

    var selectedProjectCheckouts: [CatalogProjectCheckout] {
        checkouts.filter { $0.projectID == selectedProjectID }
    }

    func unmanagedCheckoutCount(projectID: WorkspaceProject.ID) -> Int {
        checkoutDiscoveries[projectID]?.checkouts.count {
            !$0.gitPrimary && $0.managedCheckoutID == nil
        } ?? 0
    }

    var selectedEnvironment: WorkspaceEnvironment? {
        selectedProject?.environments.first(where: { $0.id == selectedEnvironmentID })
    }

    var selectedSurface: WorkspaceSurface? {
        selectedEnvironment?.surfaces.first(where: { $0.id == selectedSurfaceID })
    }

    var commonBindings: [WorkspaceBinding] { selectedProject?.commonBindings ?? [] }
    var environmentBindings: [WorkspaceBinding] { selectedEnvironment?.bindings ?? [] }

    var allBindings: [WorkspaceBinding] {
        projects.flatMap { project in
            project.commonBindings + project.environments.flatMap(\.bindings)
        }
    }

    var allSurfaces: [WorkspaceSurface] {
        projects.flatMap { $0.environments.flatMap(\.surfaces) }
    }

    func backingResource(for surface: WorkspaceSurface) -> WorkspaceResource? {
        if let resourceID = surface.resourceID {
            return resource(resourceID)
        }
        let resourceIDs = Set(
            allBindings
                .filter { surface.bindingIDs.contains($0.id) }
                .map(\.resourceID))
        let matches = resources.filter { resource in
            resourceIDs.contains(resource.id)
                && resource.kind == .envFile
                && resource.originSources.contains { $0.path == surface.path }
        }
        return matches.count == 1 ? matches[0] : nil
    }

    var representedFileResourceIDs: Set<WorkspaceResource.ID> {
        Set(allSurfaces.compactMap { backingResource(for: $0)?.id })
    }

    var managedItemCount: Int {
        protectedFiles.count
            + resources.count { !representedFileResourceIDs.contains($0.id) }
            + allSurfaces.count
    }

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

    var sshIdentityProviders: [WorkspaceResource] {
        resources.filter {
            ($0.kind == .sshIdentity && $0.shape == .sshIdentity)
                || ($0.kind == .sshAgent && $0.shape == .socket)
        }
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
            let isIdentityProvider =
                (resource.kind == .sshIdentity && resource.shape == .sshIdentity)
                || (resource.kind == .sshAgent && resource.shape == .socket)
            return isIdentityProvider
                && resource.codec == .opaque && binding.keyOverride == nil
                && !entries.isEmpty && entries.allSatisfy { $0.key == nil && !$0.sensitive }
        case .envFileDirect:
            return false
        }
    }

    func resource(_ id: WorkspaceResource.ID) -> WorkspaceResource? {
        resources.first { $0.id == id }
    }

    func surface(_ id: WorkspaceSurface.ID) -> WorkspaceSurface? {
        for project in projects {
            for environment in project.environments {
                if let surface = environment.surfaces.first(where: { $0.id == id }) {
                    return surface
                }
            }
        }
        return nil
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
            _ = try await controlClient.checkCompatibility()
            async let catalog = controlClient.snapshot()
            async let files = controlClient.protectedFiles()
            apply(try await catalog)
            protectedFiles = protectedFileModels(try await files)
            lastError = nil
        } catch {
            let compatibilityFailure =
                (error as? ControlClientError)?.isCompatibilityFailure == true
            if reportErrors || compatibilityFailure {
                lastError = error.localizedDescription
            }
        }
    }

    func discover(at path: String) async throws -> DiscoveryPlan {
        try await discover(at: [path])
    }

    func discover(at paths: [String]) async throws -> DiscoveryPlan {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let standardized = paths.map { ($0 as NSString).standardizingPath }
        let plan = try await controlClient.discover(paths: standardized)
        lastError = nil
        return plan
    }

    func startDiscovery(at paths: [String]) async throws -> DiscoveryJobStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let standardized = paths.map { ($0 as NSString).standardizingPath }
        let status = try await controlClient.startDiscovery(paths: standardized)
        lastError = nil
        return status
    }

    func discoveryStatus(id: String) async throws -> DiscoveryJobStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.discoveryStatus(id: id)
    }

    func cancelDiscovery(id: String) async throws -> DiscoveryJobStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.cancelDiscovery(id: id)
    }

    func createBackup(at path: String) async throws -> BackupReport {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.createBackup(
            destination: (path as NSString).standardizingPath)
    }

    func verifyBackup(at path: String) async throws -> BackupReport {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.verifyBackup(
            at: (path as NSString).standardizingPath)
    }

    func exportRecoveryKey(
        at path: String,
        passphrase: String
    ) async throws -> RecoveryKeyReport {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.exportRecoveryKey(
            destination: (path as NSString).standardizingPath,
            passphrase: passphrase)
    }

    func exportDiagnostics(
        at path: String,
        includePaths: Bool
    ) async throws -> DiagnosticsReport {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.exportDiagnostics(
            destination: (path as NSString).standardizingPath,
            includePaths: includePaths)
    }

    func replicationStatus() async throws -> ReplicationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.replicationStatus()
    }

    func createReplicationPackage(at path: String) async throws -> ReplicationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.createReplicationPackage(
            at: (path as NSString).standardizingPath)
    }

    func openReplicationPackage(at path: String) async throws -> ReplicationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let status = try await controlClient.openReplicationPackage(
            at: (path as NSString).standardizingPath)
        if status.imported > 0 {
            await reload(reportErrors: true)
        }
        return status
    }

    func syncReplicationPackage() async throws -> ReplicationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let status = try await controlClient.syncReplicationPackage()
        if status.imported > 0 {
            await reload(reportErrors: true)
        }
        return status
    }

    func resolveReplicationConflictWithCurrent() async throws -> ReplicationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.resolveReplicationConflictWithCurrent()
    }

    func disableReplication() async throws -> ReplicationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.disableReplication()
    }

    func replicationEnrollment() async throws -> ReplicationEnrollment {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.replicationEnrollment()
    }

    func approveReplicationDevice(_ enrollment: ReplicationEnrollment) async throws
        -> ReplicationStatus
    {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.enrollReplicationDevice(enrollment)
    }

    func applyDiscovery(
        at paths: [String], imports: [DiscoveryImport],
        separateEntries: [DiscoverySeparateEntry],
        promoteEntries: [DiscoverySeparateEntry] = [],
        demoteEntries: [DiscoverySeparateEntry] = []
    ) async throws -> DiscoveryApplyResult {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let standardized = { (entries: [DiscoverySeparateEntry]) in
            entries.map {
                DiscoverySeparateEntry(
                    path: ($0.path as NSString).standardizingPath,
                    address: $0.address)
            }
        }
        let standardizedImports = imports.map { item in
            let destination: DiscoveryImportDestination
            switch item.destination {
            case .projectFile(let projectPath):
                destination = .projectFile(
                    projectPath: (projectPath as NSString).standardizingPath)
            case .projectOutput(let projectPath, let outputPath):
                destination = .projectOutput(
                    projectPath: (projectPath as NSString).standardizingPath,
                    outputPath: (outputPath as NSString).standardizingPath)
            case .library:
                destination = .library
            case .projectOutputs(let outputs):
                destination = .projectOutputs(
                    outputs: outputs.map {
                        DiscoveryProjectOutput(
                            projectPath: ($0.projectPath as NSString).standardizingPath,
                            outputPath: ($0.outputPath as NSString).standardizingPath)
                    })
            }
            return DiscoveryImport(
                path: (item.path as NSString).standardizingPath,
                destination: destination,
                sourceDisposition: item.sourceDisposition)
        }
        let result = try await controlClient.applyDiscovery(
            paths: paths.map { ($0 as NSString).standardizingPath },
            imports: standardizedImports,
            separateEntries: standardized(separateEntries),
            promoteEntries: standardized(promoteEntries),
            demoteEntries: standardized(demoteEntries))
        apply(try await controlClient.snapshot(), selectingProject: result.projectID)
        protectedFiles = protectedFileModels(try await controlClient.protectedFiles())
        lastError = nil
        return result
    }

    func resolveDiscoveryReference(
        surfaceID: String, key: String, source: DiscoveryReferenceSource
    ) async throws -> DiscoveryReferenceResolution {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let result = try await controlClient.resolveDiscoveryReference(
            surfaceID: surfaceID, key: key, source: source)
        apply(try await controlClient.snapshot())
        lastError = nil
        return result
    }

    func discoverProjectCheckouts(
        projectID: WorkspaceProject.ID
    ) async throws -> ProjectCheckoutDiscovery {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard projects.contains(where: { $0.id == projectID }) else {
            throw WorkspaceStoreError.invalid("Choose a project first")
        }
        let result = try await controlClient.discoverProjectCheckouts(projectID: projectID)
        checkoutDiscoveries[projectID] = result
        lastError = nil
        return result
    }

    func refreshProjectCheckoutDiscoveries() async {
        guard let controlClient else { return }
        guard let inventory = try? await controlClient.projectCheckoutInventory() else { return }
        let projectIDs = Set(projects.map(\.id))
        let next = Dictionary(
            uniqueKeysWithValues: inventory.projects.compactMap { discovery in
                projectIDs.contains(discovery.projectID)
                    ? (discovery.projectID, discovery)
                    : nil
            })
        if checkoutDiscoveries != next {
            checkoutDiscoveries = next
            await autoProvisionDiscoveredWorktrees()
        }
    }

    func setProjectDefaultEnvironment(
        projectID: WorkspaceProject.ID, environmentID: WorkspaceEnvironment.ID?
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let project = projects.first(where: { $0.id == projectID }) else {
            throw WorkspaceStoreError.invalid("Choose a project first")
        }
        if let environmentID {
            guard project.environments.contains(where: { $0.id == environmentID }) else {
                throw WorkspaceStoreError.invalid("Choose an environment of this project")
            }
        }
        try await controlClient.setProjectDefaultEnvironment(
            projectID: projectID, environmentID: environmentID)
        apply(try await controlClient.snapshot())
        lastError = nil
        await autoProvisionDiscoveredWorktrees()
    }

    /// Link every discovered-but-unmanaged worktree of projects that opted into
    /// a default environment. Failed paths are remembered so a broken checkout
    /// doesn't get retried every poll.
    private func autoProvisionDiscoveredWorktrees() async {
        for (projectID, discovery) in checkoutDiscoveries {
            guard let project = projects.first(where: { $0.id == projectID }),
                let environmentID = project.defaultEnvironmentID,
                project.environments.contains(where: { $0.id == environmentID })
            else { continue }
            for candidate in discovery.checkouts
            where !candidate.gitPrimary && candidate.managedCheckoutID == nil {
                guard !autoProvisionAttempted.contains(candidate.path) else { continue }
                autoProvisionAttempted.insert(candidate.path)
                do {
                    try await provisionProjectCheckout(
                        projectID: projectID, path: candidate.path,
                        environmentID: environmentID, commonDir: discovery.commonDir)
                } catch {
                    // Leave the path marked as attempted; surfaces in the sheet
                    // as still-unlinked where it can be linked manually.
                }
            }
        }
    }

    func provisionProjectCheckout(
        projectID: WorkspaceProject.ID, path: String,
        environmentID: WorkspaceEnvironment.ID, commonDir: String,
        checkoutID: String? = nil
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let project = projects.first(where: { $0.id == projectID }) else {
            throw WorkspaceStoreError.invalid("Choose a project first")
        }
        guard project.environments.contains(where: { $0.id == environmentID }) else {
            throw WorkspaceStoreError.invalid("Choose an environment for this worktree")
        }
        let path = (path as NSString).standardizingPath
        guard path != (project.path as NSString).standardizingPath else {
            throw WorkspaceStoreError.invalid("The primary checkout is already managed")
        }
        try await controlClient.upsertProjectCheckout(
            CatalogProjectCheckout(
                id: checkoutID ?? Self.newID("checkout"),
                projectID: projectID,
                path: path,
                environmentID: environmentID,
                kind: .worktree,
                gitCommonDir: (commonDir as NSString).standardizingPath))
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    func removeProjectCheckout(_ id: CatalogProjectCheckout.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard checkouts.contains(where: { $0.id == id && $0.kind == .worktree }) else {
            throw WorkspaceStoreError.invalid("Choose a managed worktree first")
        }
        try await controlClient.removeProjectCheckout(id)
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    func repairManagedLink(at path: String) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        try await controlClient.repairManagedLink(at: path)
        apply(try await controlClient.snapshot())
        protectedFiles = protectedFileModels(try await controlClient.protectedFiles())
        lastError = nil
    }

    func protectFile(at path: String) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let file = try await controlClient.protectFile(at: path)
        let protected = protectedFileModels([file])[0]
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
        let file = protectedFileModels([
            try await controlClient.rollbackProtectedFile(id, to: version)
        ])[0]
        if let index = protectedFiles.firstIndex(where: { $0.id == id }) {
            protectedFiles[index] = file
        }
        lastError = nil
    }

    func updateProtectedFileContents(_ id: String, from path: String) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let file = protectedFileModels([
            try await controlClient.updateProtectedFileContents(id, from: path)
        ])[0]
        if let index = protectedFiles.firstIndex(where: { $0.id == id }) {
            protectedFiles[index] = file
        }
        lastError = nil
    }

    func updateProtectedFileMetadata(
        _ id: String, securityLevel: WorkspaceSecurityLevel,
        environmentIDs: [WorkspaceEnvironment.ID]? = nil, metadata: ItemMetadata
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let file = protectedFiles.first(where: { $0.id == id }) else {
            throw WorkspaceStoreError.invalid("Choose a protected file first")
        }
        let metadata = try Self.validatedMetadata(metadata)
        try await controlClient.updateProtectedFileMetadata(
            id, enforcement: securityLevel.rawValue,
            environmentIDs: environmentIDs ?? file.environmentIDs, metadata: metadata)
        if let files = try? await controlClient.protectedFiles() {
            protectedFiles = protectedFileModels(files)
        }
        lastError = nil
    }

    func configureManagedFile(
        _ id: String, projectID: WorkspaceProject.ID,
        environmentID: WorkspaceEnvironment.ID?
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard projects.contains(where: { $0.id == projectID }) else {
            throw WorkspaceStoreError.invalid("Choose a project first")
        }
        _ = try await controlClient.configureManagedFile(
            id, projectID: projectID, environmentID: environmentID)
        apply(try await controlClient.snapshot(), selectingProject: projectID)
        protectedFiles = protectedFileModels(try await controlClient.protectedFiles())
        lastError = nil
    }

    func restoreFile(_ id: String) async throws -> Bool {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let storageDeleted = try await controlClient.restoreFile(id)
        if storageDeleted {
            protectedFiles.removeAll { $0.id == id }
        } else if let files = try? await controlClient.protectedFiles() {
            protectedFiles = protectedFileModels(files)
        }
        lastError = nil
        return storageDeleted
    }

    func restoreManagedFile(_ id: WorkspaceSurface.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        try await controlClient.restoreManagedFile(id)
        apply(try await controlClient.snapshot())
        protectedFiles = protectedFileModels(try await controlClient.protectedFiles())
        lastError = nil
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
    func importSshIdentity(
        name: String, path: String, passphrase: String?,
        securityLevel: WorkspaceSecurityLevel, metadata: ItemMetadata = .empty
    ) async throws -> WorkspaceResource.ID {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let path = (path as NSString).expandingTildeInPath
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Identity name is required") }
        guard (path as NSString).isAbsolutePath else {
            throw WorkspaceStoreError.invalid("SSH private key path must be absolute")
        }
        let metadata = try Self.validatedMetadata(metadata)
        let resourceID = Self.newID("ssh-identity")
        _ = try await controlClient.importSshIdentity(
            resourceID: resourceID, name: name, path: path,
            passphrase: passphrase?.isEmpty == false ? passphrase : nil,
            enforcement: securityLevel.rawValue, metadata: metadata)
        apply(try await controlClient.snapshot())
        lastError = nil
        return resourceID
    }

    func sshConfigStatus() async throws -> SshConfigIntegrationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.sshConfigStatus()
    }

    func installSshConfig() async throws -> SshConfigIntegrationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.installSshConfig()
    }

    func removeSshConfig() async throws -> SshConfigIntegrationStatus {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        return try await controlClient.removeSshConfig()
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
                source: .socket, enforcement: WorkspaceSecurityLevel.confirmation.rawValue,
                metadata: metadata,
                origin: CatalogResourceOrigin(kind: "manual", sources: [])),
            endpoint: endpoint)
        apply(try await controlClient.snapshot())
        lastError = nil
        return resourceID
    }

    func removeSshAgentResource(_ id: WorkspaceResource.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let resource = resources.first(where: { $0.id == id }),
            resource.kind == .sshIdentity || resource.kind == .sshAgent
        else {
            throw WorkspaceStoreError.invalid("Choose an SSH identity provider first")
        }
        if resource.kind == .sshIdentity {
            try await controlClient.removeSshIdentity(resourceID: id)
        } else {
            try await controlClient.removeResource(id)
        }
        apply(try await controlClient.snapshot())
        lastError = nil
    }

    @discardableResult
    func createEnvironment(
        name: String, in projectID: WorkspaceProject.ID
    ) async throws -> WorkspaceEnvironment.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        guard let project = projects.first(where: { $0.id == projectID }) else {
            throw WorkspaceStoreError.invalid("Choose a project first")
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
        let environmentID = Self.newID("environment")
        try await controlClient.upsertEnvironment(
            CatalogEnvironment(
                id: environmentID, projectID: project.id, name: name,
                position: Int64(project.environments.count)))
        apply(try await controlClient.snapshot())
        lastError = nil
        return environmentID
    }

    @discardableResult
    func createEnvironment(
        name: String, in projectID: WorkspaceProject.ID,
        includingManagedFile fileID: WorkspaceProtectedFile.ID
    ) async throws -> WorkspaceEnvironment.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        let environmentID = try await createEnvironment(name: name, in: projectID)
        do {
            guard let file = protectedFiles.first(where: { $0.id == fileID }) else {
                throw WorkspaceStoreError.invalid("Choose a managed file first")
            }
            try await updateProtectedFileMetadata(
                file.id, securityLevel: file.securityLevel,
                environmentIDs: file.environmentIDs + [environmentID],
                metadata: file.metadata)
        } catch {
            try? await controlClient.removeEnvironment(environmentID)
            apply(try await controlClient.snapshot())
            throw error
        }
        return environmentID
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
        let output = try newSurfaceOutput(fileName: fileName, in: project)
        let surfaceID = Self.newID("dotenv")
        let commonBindingIDs = project.commonBindings
            .filter { bindingIsCompatible($0, with: .dotenvFile) }
            .map(\.id)
        let environmentID = try await createEnvironment(name: name, in: project.id)
        do {
            try await controlClient.upsertSurface(
                CatalogSurface(
                    id: surfaceID, environmentID: environmentID, name: output.name,
                    kind: WorkspaceSurfaceKind.dotenvFile.catalogValue, path: output.path,
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
                kind: WorkspaceSurfaceKind.dotenvFile.catalogValue,
                path: output.path, input: .bindings(bindingIDs),
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
                kind: WorkspaceSurfaceKind.direnvFile.catalogValue,
                path: output.path, input: .bindings(bindingIDs),
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
                kind: WorkspaceSurfaceKind.iniFile.catalogValue,
                path: output.path, input: .bindings(bindingIDs),
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
                kind: WorkspaceSurfaceKind.linesFile.catalogValue,
                path: output.path, input: .bindings(bindingIDs),
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
                kind: WorkspaceSurfaceKind.envFileDirect.catalogValue,
                path: output.path, input: .resource(resourceID),
                position: Int64(environment.surfaces.count)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = surfaceID
        lastError = nil
        return surfaceID
    }

    @discardableResult
    func createSshAgentSurface(
        resourceID: WorkspaceResource.ID, selectedEntries: Set<String>,
        securityLevel: WorkspaceSecurityLevel, route: WorkspaceSshRoute?
    ) async throws -> WorkspaceSurface.ID {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }
        guard let resource = sshIdentityProviders.first(where: { $0.id == resourceID }) else {
            throw WorkspaceStoreError.invalid("Choose an SSH identity provider")
        }
        let addresses = resource.entries.map(\.address).filter(selectedEntries.contains)
        guard !addresses.isEmpty else {
            throw WorkspaceStoreError.invalid("Select at least one SSH identity")
        }
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
                    id: surfaceID, environmentID: environment.id, name: resource.name,
                    kind: WorkspaceSurfaceKind.unixSocket.catalogValue, path: nil,
                    input: .sshAgent([bindingID], route: route?.catalogValue),
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
                    input: surface.input.catalogInput(
                        replacingBindingIDs: surface.bindingIDs + [bindingID]),
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
        bindingIDs: [WorkspaceBinding.ID], sshRoute: WorkspaceSshRoute? = nil
    ) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        guard let project = selectedProject, let environment = selectedEnvironment,
            let position = environment.surfaces.firstIndex(where: { $0.id == id }),
            let surface = environment.surfaces.first(where: { $0.id == id })
        else {
            throw WorkspaceStoreError.invalid("Select an output first")
        }
        let outputName: String
        let outputPath: String?
        if kind == .unixSocket {
            outputName = surface.name
            outputPath = nil
        } else {
            let output = try newSurfaceOutput(
                fileName: fileName, in: project, excludingSurfaceID: id)
            outputName = output.name
            outputPath = output.path
        }

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
            input = kind == .unixSocket
                ? .sshAgent(bindingIDs, route: sshRoute?.catalogValue)
                : .bindings(bindingIDs)
        case .sshAgent:
            guard surface.kind == .unixSocket, kind == .unixSocket else {
                throw WorkspaceStoreError.invalid("SSH routes require a Unix Socket output")
            }
            let allowed = Set(compatibleBindings(for: .unixSocket).map(\.id))
            guard bindingIDs.allSatisfy(allowed.contains) else {
                throw WorkspaceStoreError.invalid(
                    "One or more bindings cannot feed the selected SSH agent")
            }
            input = .sshAgent(bindingIDs, route: sshRoute?.catalogValue)
        case .resource(let resourceID):
            guard kind == surface.kind else {
                throw WorkspaceStoreError.invalid("Direct outputs keep their source format")
            }
            input = .resource(resourceID)
        }

        try await controlClient.upsertSurface(
            CatalogSurface(
                id: id, environmentID: environment.id, name: outputName,
                kind: kind.catalogValue, path: outputPath, input: input,
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
                input: surface.input.catalogInput(replacingBindingIDs: bindingIDs),
                enforcement: surface.securityLevel.rawValue,
                position: Int64(position)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = id
        lastError = nil
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
                linkStatus: surface.managedLink?.status,
                input: .bindings(surface.bindingIDs + [binding.id]))
    }

    private func apply(_ snapshot: CatalogSnapshot, selectingProject: String? = nil) {
        let previousProjectID = selectingProject ?? selectedProjectID
        let previousEnvironmentID = selectedEnvironmentID
        let previousSurfaceID = selectedSurfaceID
        let projectUsage = Dictionary(grouping: snapshot.bindings, by: \.resourceID)
            .mapValues { Set($0.map(\.projectID)).count }
        managedLinkStatuses = Dictionary(
            uniqueKeysWithValues: snapshot.managedLinks.map { ($0.path, $0.status) })

        checkouts = snapshot.checkouts
        resources = snapshot.resources.compactMap { resource in
            guard
                let kind = WorkspaceResourceKind(catalogValue: resource.kind),
                let shape = WorkspaceValueShape(catalogValue: resource.shape),
                let codec = WorkspaceResourceCodec(rawValue: resource.codec)
            else { return nil }
            let preview: String
            switch resource.source.type {
            case "literal": preview = resource.source.value ?? ""
            case "socket": preview = snapshot.endpoints[resource.id] ?? ""
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
                origin: resource.origin,
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
                        .compactMap {
                            WorkspaceSurface(
                                $0,
                                linkStatus: $0.path.flatMap { managedLinkStatuses[$0] })
                        }
                    return WorkspaceEnvironment(
                        id: environment.id, name: environment.name,
                        bindings: environmentBindings, surfaces: environmentSurfaces)
                }
            return WorkspaceProject(
                id: project.id, name: project.name, path: project.path,
                commonBindings: common, environments: projectEnvironments,
                defaultEnvironmentID: project.defaultEnvironmentID)
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

    private func protectedFileModels(
        _ files: [CatalogProtectedFile]
    ) -> [WorkspaceProtectedFile] {
        files.map { file in
            WorkspaceProtectedFile(
                file,
                linkStatus: managedLinkStatuses[file.sourcePath]
                    ?? (file.linked ? .linked : .missing))
        }
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
    init(_ file: CatalogProtectedFile, linkStatus: ManagedLinkStatus) {
        self.init(
            id: file.id, path: file.sourcePath, mode: file.mode, size: file.size,
            currentVersion: file.currentVersion,
            managedLink: WorkspaceManagedLink(path: file.sourcePath, status: linkStatus),
            securityLevel: WorkspaceSecurityLevel(catalogValue: file.enforcement),
            environmentIDs: file.environmentIDs,
            metadata: file.metadata)
    }
}

private extension WorkspaceSurface {
    init?(_ surface: CatalogSurface, linkStatus: ManagedLinkStatus?) {
        guard let kind = WorkspaceSurfaceKind(catalogValue: surface.kind) else { return nil }
        let input: WorkspaceSurfaceInput
        switch surface.input.type {
        case "bindings": input = .bindings(surface.input.bindingIDs ?? [])
        case "ssh_agent":
            input = .sshAgent(
                surface.input.bindingIDs ?? [],
                surface.input.route.map(WorkspaceSshRoute.init))
        case "resource":
            guard let resourceID = surface.input.resourceID else { return nil }
            input = .resource(resourceID)
        default: return nil
        }
        self.init(
            id: surface.id, name: surface.name, kind: kind, path: surface.path,
            linkStatus: linkStatus, input: input,
            securityLevel: WorkspaceSecurityLevel(catalogValue: surface.enforcement))
    }
}

private extension WorkspaceSurfaceInput {
    var catalogInput: CatalogSurfaceInput {
        switch self {
        case .bindings(let ids): .bindings(ids)
        case .sshAgent(let ids, let route): .sshAgent(ids, route: route?.catalogValue)
        case .resource(let id): .resource(id)
        }
    }

    func catalogInput(replacingBindingIDs ids: [WorkspaceBinding.ID]) -> CatalogSurfaceInput {
        switch self {
        case .bindings: .bindings(ids)
        case .sshAgent(_, let route): .sshAgent(ids, route: route?.catalogValue)
        case .resource(let id): .resource(id)
        }
    }
}

private extension WorkspaceSshRoute {
    init(_ route: CatalogSshRoute) {
        self.init(
            hostPatterns: route.hostPatterns, hostname: route.hostname, user: route.user,
            port: route.port, forwardAgent: route.forwardAgent)
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
        case "ssh_identity": self = .sshIdentity
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
        case "ssh_identity": self = .sshIdentity
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
                path: "~/workspace/\(project)/.env", linkStatus: .linked,
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
                            path: socketPath, linkStatus: .linked,
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
