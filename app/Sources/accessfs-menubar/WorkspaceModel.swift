import Darwin
import Foundation
import Observation

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

struct WorkspaceExport: Identifiable, Hashable, Sendable {
    var id: String { key }
    let key: String
    let previewValue: String
    let sensitive: Bool
}

struct WorkspaceResource: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let kind: WorkspaceResourceKind
    let shape: WorkspaceValueShape
    let exports: [WorkspaceExport]
    let detail: String
    let usageCount: Int

    var exportSummary: String {
        if exports.count == 1, let key = exports.first?.key { return key }
        return "\(exports.count) variables"
    }
}

struct WorkspaceBinding: Identifiable, Hashable, Sendable {
    let id: String
    let resourceID: WorkspaceResource.ID
    var keyOverride: String?
    var isEnabled: Bool
    let scope: WorkspaceBindingScope
    let allowOverride: Bool
    let position: Int64

    init(
        id: String, resourceID: WorkspaceResource.ID, keyOverride: String?, isEnabled: Bool,
        scope: WorkspaceBindingScope = .environment(""), allowOverride: Bool = false,
        position: Int64 = 0
    ) {
        self.id = id
        self.resourceID = resourceID
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

enum WorkspaceSurfaceKind: String, Sendable {
    case dotenvFile
    case envFileDirect
    case regularFile
    case unixSocket

    var title: String {
        switch self {
        case .dotenvFile: "Dotenv File"
        case .envFileDirect: "Direct Env File"
        case .regularFile: "File"
        case .unixSocket: "Unix Socket"
        }
    }

    var systemImage: String {
        switch self {
        case .dotenvFile: "doc.text"
        case .envFileDirect: "doc.text.fill"
        case .regularFile: "doc"
        case .unixSocket: "point.3.connected.trianglepath.dotted"
        }
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
    let resourceID: WorkspaceResource.ID?
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

@Observable @MainActor
final class WorkspaceStore {
    var projects: [WorkspaceProject]
    var resources: [WorkspaceResource]
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

    var resolvedExports: [ResolvedWorkspaceExport] {
        activeBindings.flatMap { binding -> [ResolvedWorkspaceExport] in
            guard let resource = resource(binding.resourceID) else { return [] }
            return resource.exports.map { export in
                ResolvedWorkspaceExport(
                    bindingID: binding.id,
                    key: resource.exports.count == 1 ? (binding.keyOverride ?? export.key) : export.key,
                    previewValue: export.previewValue,
                    sensitive: export.sensitive,
                    resourceName: resource.name,
                    resourceKind: resource.kind)
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
        resources.filter { $0.kind == .envFile }
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
            apply(try await controlClient.snapshot())
            lastError = nil
        } catch {
            if reportErrors { lastError = error.localizedDescription }
        }
    }

    @discardableResult
    func createProject(name: String, path: String) async throws -> WorkspaceProject.ID {
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
        let dotenvPath = (path as NSString).appendingPathComponent(".env")
        var fileInfo = stat()
        let dotenvStatus = dotenvPath.withCString { lstat($0, &fileInfo) }
        guard dotenvStatus != 0 else {
            throw WorkspaceStoreError.invalid(
                "\(dotenvPath) already exists. Floria will never replace it automatically.")
        }
        guard errno == ENOENT else {
            throw WorkspaceStoreError.invalid("Floria could not inspect \(dotenvPath)")
        }

        let projectID = Self.newID("project")
        let environmentID = Self.newID("environment")
        let surfaceID = Self.newID("dotenv")
        do {
            try await controlClient.createProject(
                CatalogProject(id: projectID, name: name, path: path),
                environment: CatalogEnvironment(
                    id: environmentID, projectID: projectID, name: "Development", position: 0),
                surface: CatalogSurface(
                    id: surfaceID, environmentID: environmentID, name: ".env",
                    kind: "dotenv_file", path: dotenvPath, resourceID: nil, position: 0))
            apply(try await controlClient.snapshot(), selectingProject: projectID)
            lastError = nil
            return projectID
        } catch {
            await reload()
            throw error
        }
    }

    @discardableResult
    func createSharedSecret(name: String, defaultEnvKey: String, value: String) async throws
        -> WorkspaceResource.ID
    {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = defaultEnvKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Secret name is required") }
        guard Self.isValidEnvKey(key) else {
            throw WorkspaceStoreError.invalid(
                "The default key must start with A-Z or _, followed by A-Z, 0-9, or _")
        }
        guard !value.isEmpty else { throw WorkspaceStoreError.invalid("Secret value is required") }

        let resourceID = Self.newID("shared-secret")
        try await controlClient.createSharedSecret(
            resourceID: resourceID, name: name, defaultEnvKey: key, value: value)
        apply(try await controlClient.snapshot())
        lastError = nil
        return resourceID
    }

    @discardableResult
    func createEnvFile(name: String, value: String) async throws -> WorkspaceResource.ID {
        guard let controlClient else {
            throw WorkspaceStoreError.controlUnavailable
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { throw WorkspaceStoreError.invalid("Env file name is required") }
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw WorkspaceStoreError.invalid("Enter at least one KEY=VALUE line")
        }

        let resourceID = Self.newID("env-file")
        try await controlClient.createEnvFile(resourceID: resourceID, name: name, value: value)
        apply(try await controlClient.snapshot())
        lastError = nil
        return resourceID
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
        try await controlClient.upsertEnvironment(
            CatalogEnvironment(
                id: environmentID, projectID: project.id, name: name,
                position: Int64(project.environments.count)))
        do {
            try await controlClient.upsertSurface(
                CatalogSurface(
                    id: surfaceID, environmentID: environmentID, name: output.name,
                    kind: "dotenv_file", path: output.path, resourceID: nil, position: 0))
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
    func createDotenvSurface(fileName: String) async throws -> WorkspaceSurface.ID {
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
                kind: "dotenv_file", path: output.path, resourceID: nil,
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
                kind: "env_file_direct", path: output.path, resourceID: resourceID,
                position: Int64(environment.surfaces.count)))
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
                    resourceID: binding.resourceID, keyOverride: binding.keyOverride,
                    enabled: !binding.isEnabled, allowOverride: binding.allowOverride,
                    position: binding.position))
            apply(try await controlClient.snapshot())
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    func addResource(
        _ resourceID: WorkspaceResource.ID, target: WorkspaceBindingTarget = .environment
    ) async throws {
        guard availableResources.contains(where: { $0.id == resourceID }) else { return }
        guard let controlClient else {
            addResourceLocally(resourceID)
            return
        }
        guard let project = selectedProject, let environment = selectedEnvironment else {
            throw WorkspaceStoreError.invalid("Select a project environment first")
        }

        let scope: WorkspaceBindingScope =
            target == .common ? .common : .environment(environment.id)
        let position = Int64(
            target == .common ? project.commonBindings.count : environment.bindings.count)
        try await controlClient.upsertBinding(
            CatalogBinding(
                id: Self.newID("binding"), projectID: project.id, scope: scope.catalogScope,
                resourceID: resourceID, keyOverride: nil, enabled: true,
                allowOverride: false, position: position))
        apply(try await controlClient.snapshot())
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

    func removeSurface(_ id: WorkspaceSurface.ID) async throws {
        guard let controlClient else { throw WorkspaceStoreError.controlUnavailable }
        try await controlClient.removeSurface(id)
        apply(try await controlClient.snapshot())
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
                resourceID: surface.resourceID, position: Int64(position)))
        apply(try await controlClient.snapshot())
        selectedSurfaceID = id
        guard managedLinkTarget(for: surface) == expectedLinkTarget(for: surface) else {
            throw WorkspaceStoreError.invalid(
                "The path is occupied by another file or link. Floria did not replace it.")
        }
        lastError = nil
    }

    func expectedLinkTarget(for surface: WorkspaceSurface) -> String {
        (NSHomeDirectory() as NSString).appendingPathComponent(
            ".accessfs/surfaces/\(surface.id)")
    }

    func managedLinkTarget(for surface: WorkspaceSurface) -> String? {
        try? FileManager.default.destinationOfSymbolicLink(atPath: surface.path)
    }

    private func newSurfaceOutput(
        fileName: String, in project: WorkspaceProject
    ) throws -> (name: String, path: String) {
        let name = fileName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name != ".", name != "..",
            (name as NSString).lastPathComponent == name
        else {
            throw WorkspaceStoreError.invalid("Output name must be one file name")
        }
        let path = (project.path as NSString).appendingPathComponent(name)
        guard !project.environments.flatMap(\.surfaces).contains(where: { $0.path == path }) else {
            throw WorkspaceStoreError.invalid("\(path) is already used by another output")
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

    private func addResourceLocally(_ resourceID: WorkspaceResource.ID) {
        guard
            availableResources.contains(where: { $0.id == resourceID }),
            let projectIndex = projects.firstIndex(where: { $0.id == selectedProjectID }),
            let environmentIndex = projects[projectIndex].environments.firstIndex(where: {
                $0.id == selectedEnvironmentID
            })
        else { return }

        projects[projectIndex].environments[environmentIndex].bindings.append(
            WorkspaceBinding(
                id: "\(selectedProjectID)-\(selectedEnvironmentID)-\(resourceID)",
                resourceID: resourceID,
                keyOverride: nil,
                isEnabled: true))
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
                let shape = WorkspaceValueShape(catalogValue: resource.shape)
            else { return nil }
            let preview: String
            switch resource.source.type {
            case "literal": preview = resource.source.value ?? ""
            case "socket": preview = resource.source.endpoint ?? ""
            default: preview = "••••••••••••"
            }
            return WorkspaceResource(
                id: resource.id, name: resource.name, kind: kind, shape: shape,
                exports: resource.exports.map {
                    WorkspaceExport(key: $0.key, previewValue: preview, sensitive: $0.sensitive)
                },
                detail: resource.detail ?? resource.defaultEnvKey ?? kind.title,
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

    private static func isValidEnvKey(_ key: String) -> Bool {
        key.range(of: "^[A-Z_][A-Z0-9_]*$", options: .regularExpression) != nil
    }
}

private extension WorkspaceBinding {
    init(_ binding: CatalogBinding) {
        let scope: WorkspaceBindingScope = binding.scope.type == "common"
            ? .common : .environment(binding.scope.environmentID ?? "")
        self.init(
            id: binding.id, resourceID: binding.resourceID, keyOverride: binding.keyOverride,
            isEnabled: binding.enabled, scope: scope, allowOverride: binding.allowOverride,
            position: binding.position)
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

private extension WorkspaceSurface {
    init?(_ surface: CatalogSurface) {
        guard let kind = WorkspaceSurfaceKind(catalogValue: surface.kind) else { return nil }
        let expectedTarget = (NSHomeDirectory() as NSString).appendingPathComponent(
            ".accessfs/surfaces/\(surface.id)")
        let linkTarget = try? FileManager.default.destinationOfSymbolicLink(atPath: surface.path)
        let status: WorkspaceSurfaceStatus = kind == .unixSocket
            ? .listening : (linkTarget == expectedTarget ? .linked : .stopped)
        self.init(
            id: surface.id, name: surface.name, kind: kind, path: surface.path,
            status: status,
            resourceID: surface.resourceID)
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
        case .envFileDirect: "env_file_direct"
        case .regularFile: "regular_file"
        case .unixSocket: "unix_socket"
        }
    }

    init?(catalogValue: String) {
        switch catalogValue {
        case "dotenv_file": self = .dotenvFile
        case "env_file_direct": self = .envFileDirect
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
                detail: "Rotated 12 days ago", usageCount: 12),
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
                detail: "6 variables", usageCount: 8),
            WorkspaceResource(
                id: "local-database", name: "Local database", kind: .envFile,
                shape: .keyValueSet,
                exports: [
                    WorkspaceExport(key: "DATABASE_URL", previewValue: "••••••••••••", sensitive: true),
                    WorkspaceExport(key: "REDIS_URL", previewValue: "••••••••••••", sensitive: true),
                    WorkspaceExport(key: "DATABASE_POOL", previewValue: "5", sensitive: false),
                ],
                detail: "3 variables", usageCount: 1),
            WorkspaceResource(
                id: "app-env", name: "APP_ENV", kind: .literal, shape: .scalar,
                exports: [
                    WorkspaceExport(key: "APP_ENV", previewValue: "development", sensitive: false)
                ],
                detail: "development", usageCount: 1),
            WorkspaceResource(
                id: "developer-ssh-agent", name: "Developer SSH Agent", kind: .sshAgent,
                shape: .socket,
                exports: [
                    WorkspaceExport(key: "SSH_AUTH_SOCK", previewValue: socketPath, sensitive: false)
                ],
                detail: "2 keys available", usageCount: 3),
            WorkspaceResource(
                id: "sentry-dsn", name: "Sentry DSN", kind: .sharedSecret, shape: .scalar,
                exports: [
                    WorkspaceExport(key: "SENTRY_DSN", previewValue: "••••••••••••", sensitive: true)
                ],
                detail: "Rotated 2 months ago", usageCount: 5),
            WorkspaceResource(
                id: "github-token", name: "GitHub Automation Token", kind: .sharedSecret,
                shape: .scalar,
                exports: [
                    WorkspaceExport(key: "GITHUB_TOKEN", previewValue: "••••••••••••", sensitive: true)
                ],
                detail: "Expires in 24 days", usageCount: 4),
        ]

        func binding(_ id: String, _ resourceID: String) -> WorkspaceBinding {
            WorkspaceBinding(id: id, resourceID: resourceID, keyOverride: nil, isEnabled: true)
        }

        func dotenv(_ prefix: String, _ project: String) -> WorkspaceSurface {
            WorkspaceSurface(
                id: "\(prefix)-dotenv", name: ".env", kind: .dotenvFile,
                path: "~/workspace/\(project)/.env", status: .linked, resourceID: nil)
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
                        dotenv("floria-dev", "floria-web"),
                        WorkspaceSurface(
                            id: "floria-dev-ssh-socket", name: "SSH Agent", kind: .unixSocket,
                            path: socketPath, status: .listening,
                            resourceID: "developer-ssh-agent"),
                    ]),
                WorkspaceEnvironment(
                    id: "floria-staging", name: "Staging",
                    bindings: [binding("floria-staging-app-env", "app-env")],
                    surfaces: [dotenv("floria-staging", "floria-web")]),
                WorkspaceEnvironment(
                    id: "floria-production", name: "Production",
                    bindings: [binding("floria-prod-sentry", "sentry-dsn")],
                    surfaces: [dotenv("floria-production", "floria-web")]),
            ])

        let billing = WorkspaceProject(
            id: "billing-api", name: "billing-api", path: "~/workspace/billing-api",
            commonBindings: [binding("billing-cloudflare", "cloudflare-token")],
            environments: [
                WorkspaceEnvironment(
                    id: "billing-development", name: "Development",
                    bindings: [binding("billing-dev-db", "local-database")],
                    surfaces: [dotenv("billing-dev", "billing-api")]),
                WorkspaceEnvironment(
                    id: "billing-production", name: "Production", bindings: [],
                    surfaces: [dotenv("billing-prod", "billing-api")]),
            ])

        let workers = WorkspaceProject(
            id: "worker-jobs", name: "worker-jobs", path: "~/workspace/worker-jobs",
            commonBindings: [binding("workers-github", "github-token")],
            environments: [
                WorkspaceEnvironment(
                    id: "workers-development", name: "Development", bindings: [],
                    surfaces: [dotenv("workers-dev", "worker-jobs")])
            ])

        return WorkspaceStore(
            projects: [floria, billing, workers], resources: resources,
            selectedProjectID: floria.id)
    }
}
