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
}

enum WorkspaceSurfaceKind: String, Sendable {
    case dotenvFile
    case regularFile
    case unixSocket

    var title: String {
        switch self {
        case .dotenvFile: "Dotenv File"
        case .regularFile: "File"
        case .unixSocket: "Unix Socket"
        }
    }

    var systemImage: String {
        switch self {
        case .dotenvFile: "doc.text"
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

    init(
        projects: [WorkspaceProject], resources: [WorkspaceResource],
        selectedProjectID: WorkspaceProject.ID
    ) {
        self.projects = projects
        self.resources = resources
        self.selectedProjectID = selectedProjectID
        let project = projects.first(where: { $0.id == selectedProjectID }) ?? projects[0]
        selectedEnvironmentID = project.environments[0].id
        selectedSurfaceID = project.environments[0].surfaces[0].id
    }

    var selectedProject: WorkspaceProject {
        projects.first(where: { $0.id == selectedProjectID }) ?? projects[0]
    }

    var selectedEnvironment: WorkspaceEnvironment {
        selectedProject.environments.first(where: { $0.id == selectedEnvironmentID })
            ?? selectedProject.environments[0]
    }

    var selectedSurface: WorkspaceSurface {
        selectedEnvironment.surfaces.first(where: { $0.id == selectedSurfaceID })
            ?? selectedEnvironment.surfaces[0]
    }

    var commonBindings: [WorkspaceBinding] { selectedProject.commonBindings }
    var environmentBindings: [WorkspaceBinding] { selectedEnvironment.bindings }

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

    func resource(_ id: WorkspaceResource.ID) -> WorkspaceResource? {
        resources.first { $0.id == id }
    }

    func selectProject(_ id: WorkspaceProject.ID) {
        guard let project = projects.first(where: { $0.id == id }),
            let environment = project.environments.first,
            let surface = environment.surfaces.first
        else { return }
        selectedProjectID = id
        selectedEnvironmentID = environment.id
        selectedSurfaceID = surface.id
    }

    func selectEnvironment(_ id: WorkspaceEnvironment.ID) {
        guard let environment = selectedProject.environments.first(where: { $0.id == id }),
            let surface = environment.surfaces.first
        else { return }
        selectedEnvironmentID = id
        selectedSurfaceID = surface.id
    }

    func toggleBinding(_ id: WorkspaceBinding.ID) {
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

    func addResource(_ resourceID: WorkspaceResource.ID) {
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
