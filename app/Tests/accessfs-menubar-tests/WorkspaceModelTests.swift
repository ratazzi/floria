import XCTest

@testable import accessfs_menubar

@MainActor
final class WorkspaceModelTests: XCTestCase {
    func testPreviewEnvironmentResolvesBindingsAndSurfaces() {
        let store = WorkspaceStore.preview()

        XCTAssertEqual(store.selectedProject?.name, "floria-web")
        XCTAssertEqual(store.selectedEnvironment?.name, "Development")
        XCTAssertEqual(store.resolvedExports.count, 11)
        XCTAssertTrue(store.conflictingKeys.isEmpty)
        XCTAssertEqual(store.selectedEnvironment?.surfaces.map(\.kind), [.dotenvFile, .unixSocket])
        XCTAssertTrue(store.resolvedExports.contains { $0.key == "CLOUDFLARE_API_TOKEN" })
        XCTAssertFalse(store.resolvedExports.contains { $0.key == "SSH_AUTH_SOCK" })
    }

    func testDisablingBindingRemovesItsExports() async throws {
        let store = WorkspaceStore.preview()
        let binding = try XCTUnwrap(
            store.environmentBindings.first { $0.resourceID == "local-database" })

        await store.toggleBinding(binding.id)

        XCTAssertFalse(store.resolvedExports.contains { $0.key == "DATABASE_URL" })
        XCTAssertEqual(store.resolvedExports.count, 8)
    }

    func testSelectingEnvironmentResetsSurfaceSelection() throws {
        let store = WorkspaceStore.preview()
        store.selectedSurfaceID = "floria-dev-ssh-socket"
        let staging = try XCTUnwrap(
            store.selectedProject?.environments.first { $0.name == "Staging" })

        store.selectEnvironment(staging.id)

        XCTAssertEqual(store.selectedEnvironment?.name, "Staging")
        XCTAssertEqual(store.selectedSurface?.kind, .dotenvFile)
    }

    func testAddingAvailableResourceCreatesEnvironmentBinding() async throws {
        let store = WorkspaceStore.preview()

        try await store.addResource("sentry-dsn")

        XCTAssertTrue(store.environmentBindings.contains { $0.resourceID == "sentry-dsn" })
        XCTAssertTrue(store.resolvedExports.contains { $0.key == "SENTRY_DSN" })
    }

    func testEmptyStoreHasSafeSelections() {
        let store = WorkspaceStore(projects: [], resources: [])

        XCTAssertNil(store.selectedProject)
        XCTAssertNil(store.selectedEnvironment)
        XCTAssertNil(store.selectedSurface)
        XCTAssertTrue(store.resolvedExports.isEmpty)
    }

    func testEntrySelectionUsesResourceOrderInsteadOfCheckboxOrder() {
        let resource = WorkspaceResource(
            id: "fixture-env", name: "Fixture Env File",
            kind: .envFile, shape: .keyValueSet,
            exports: [
                WorkspaceExport(key: "PRIMARY_URL", previewValue: "fixture-primary", sensitive: true),
                WorkspaceExport(key: "FALLBACK_URL", previewValue: "fixture-fallback", sensitive: true),
            ],
            entries: [
                WorkspaceEntry(
                    address: "keys/PRIMARY_URL", label: "PRIMARY_URL", key: "PRIMARY_URL",
                    sensitive: true),
                WorkspaceEntry(
                    address: "keys/FALLBACK_URL", label: "FALLBACK_URL", key: "FALLBACK_URL",
                    sensitive: true),
            ],
            usageCount: 0)
        let selection = WorkspaceEntrySelection.entries([
            "keys/FALLBACK_URL", "keys/PRIMARY_URL",
        ])

        XCTAssertEqual(
            selection.addresses(in: resource),
            ["keys/PRIMARY_URL", "keys/FALLBACK_URL"])
    }

    func testBindingSelectionIncludesOnlyChosenEnvFileEntries() {
        let resource = WorkspaceResource(
            id: "fixture-env", name: "Fixture Env File", kind: .envFile,
            shape: .keyValueSet, exports: [],
            entries: [
                WorkspaceEntry(
                    address: "keys/API_HOST", label: "API_HOST", key: "API_HOST",
                    previewValue: "fixture-host", sensitive: false),
                WorkspaceEntry(
                    address: "keys/LOG_LEVEL", label: "LOG_LEVEL", key: "LOG_LEVEL",
                    previewValue: "debug", sensitive: false),
            ], usageCount: 0)
        let environment = WorkspaceEnvironment(
            id: "development", name: "Development",
            bindings: [
                WorkspaceBinding(
                    id: "fixture-binding", resourceID: resource.id,
                    selection: .entries(["keys/LOG_LEVEL"]), keyOverride: nil,
                    isEnabled: true)
            ], surfaces: [
                WorkspaceSurface(
                    id: "fixture-dotenv", name: ".env", kind: .dotenvFile,
                    path: "/tmp/fixture/.env", status: .linked,
                    input: .bindings(["fixture-binding"]))
            ])
        let project = WorkspaceProject(
            id: "fixture-project", name: "Fixture", path: "/tmp/fixture",
            commonBindings: [], environments: [environment])
        let store = WorkspaceStore(projects: [project], resources: [resource])

        XCTAssertEqual(store.resolvedExports.map(\.key), ["LOG_LEVEL"])
    }

    func testIniBindingSupportsNativeAndSelectedDotenvProjections() {
        let resource = WorkspaceResource(
            id: "fixture-ini", name: "Fixture INI", kind: .envFile,
            shape: .keyValueSet, codec: .ini, exports: [],
            entries: [
                WorkspaceEntry(
                    address: "sections/development/keys/REGION",
                    label: "[development] REGION", key: "REGION", sensitive: true),
                WorkspaceEntry(
                    address: "sections/staging/keys/REGION",
                    label: "[staging] REGION", key: "REGION", sensitive: true),
                WorkspaceEntry(
                    address: "sections/staging/keys/credential-process",
                    label: "[staging] credential-process", key: "credential-process",
                    sensitive: true),
            ], usageCount: 0)
        let store = WorkspaceStore(projects: [], resources: [resource])
        let selected = WorkspaceBinding(
            id: "fixture-binding", resourceID: resource.id,
            selection: .entries(["sections/staging/keys/REGION"]), keyOverride: nil,
            isEnabled: true)
        let all = WorkspaceBinding(
            id: "fixture-all", resourceID: resource.id, selection: .all,
            keyOverride: nil, isEnabled: true)

        XCTAssertTrue(store.bindingIsCompatible(selected, with: .dotenvFile))
        XCTAssertFalse(store.bindingIsCompatible(all, with: .dotenvFile))
        XCTAssertTrue(store.bindingIsCompatible(selected, with: .direnvFile))
        XCTAssertFalse(store.bindingIsCompatible(all, with: .direnvFile))
        XCTAssertTrue(store.bindingIsCompatible(selected, with: .iniFile))
        XCTAssertTrue(store.bindingIsCompatible(all, with: .iniFile))

        let environment = WorkspaceEnvironment(
            id: "development", name: "Development", bindings: [selected],
            surfaces: [
                WorkspaceSurface(
                    id: "fixture-ini-output", name: "credentials.ini", kind: .iniFile,
                    path: "/tmp/fixture/credentials.ini", status: .linked,
                    input: .bindings([selected.id]))
            ])
        let projected = WorkspaceStore(
            projects: [
                WorkspaceProject(
                    id: "fixture-project", name: "Fixture", path: "/tmp/fixture",
                    commonBindings: [], environments: [environment])
            ], resources: [resource])

        XCTAssertEqual(projected.resolvedIniEntries.map(\.label), ["[staging] REGION"])
    }

    func testAwsIniPresetsStayProjectScopedAndDescribeTheirDialects() {
        XCTAssertEqual(
            WorkspaceIniPreset.awsCredentials.pathEnvironmentKey,
            "AWS_SHARED_CREDENTIALS_FILE")
        XCTAssertEqual(WorkspaceIniPreset.awsCredentials.suggestedOutputName, ".aws-credentials")
        XCTAssertTrue(
            WorkspaceIniPreset.awsCredentials.contentPlaceholder.hasPrefix("[default]\n"))
        XCTAssertTrue(
            WorkspaceIniPreset.awsCredentials.sectionGuidance.contains("without a profile prefix"))

        XCTAssertEqual(WorkspaceIniPreset.awsConfig.pathEnvironmentKey, "AWS_CONFIG_FILE")
        XCTAssertEqual(WorkspaceIniPreset.awsConfig.suggestedOutputName, ".aws-config")
        XCTAssertTrue(
            WorkspaceIniPreset.awsConfig.contentPlaceholder.hasPrefix("[profile staging]\n"))
        XCTAssertTrue(WorkspaceIniPreset.awsConfig.sectionGuidance.contains("[profile name]"))

        XCTAssertNil(WorkspaceIniPreset.generic.pathEnvironmentKey)
    }

    func testSshAgentBindingsOnlyFeedSocketSurfaces() {
        let resource = WorkspaceResource(
            id: "fixture-agent", name: "Fixture Agent", kind: .sshAgent, shape: .socket,
            exports: [],
            entries: [
                WorkspaceEntry(
                    address: "ssh/sha256/fixture-address", label: "Fleet key", key: nil,
                    sensitive: false)
            ], usageCount: 0)
        let binding = WorkspaceBinding(
            id: "fixture-binding", resourceID: resource.id, keyOverride: nil, isEnabled: true)
        let store = WorkspaceStore(projects: [], resources: [resource])

        XCTAssertTrue(store.bindingIsCompatible(binding, with: .unixSocket))
        XCTAssertFalse(store.bindingIsCompatible(binding, with: .dotenvFile))
        XCTAssertEqual(resource.exportSummary, "1 identity")

        let preview = WorkspaceStore.preview()
        preview.selectedSurfaceID = "floria-dev-ssh-socket"
        let socket = preview.selectedSurface!
        XCTAssertTrue(preview.expectedLinkTarget(for: socket).hasSuffix(".sock"))

        let route = WorkspaceSshRoute(
            hostPatterns: ["ec2-*", "bastion"], hostname: nil, user: "ubuntu",
            port: nil, forwardAgent: true)
        let routed = WorkspaceSurface(
            id: "routed", name: "agent.sock", kind: .unixSocket,
            path: "/tmp/fixture/agent.sock", status: .listening,
            input: .sshAgent([binding.id], route))
        XCTAssertEqual(routed.bindingIDs, [binding.id])
        XCTAssertEqual(routed.sshRoute?.hostPatterns, ["ec2-*", "bastion"])

        let managed = WorkspaceResource(
            id: "fixture-managed", name: "Fixture managed identity", kind: .sshIdentity,
            shape: .sshIdentity, exports: [],
            entries: [
                WorkspaceEntry(
                    address: "ssh/sha256/fixture-managed-address", label: "Managed fleet key",
                    key: nil, sensitive: false)
            ], usageCount: 0)
        let managedBinding = WorkspaceBinding(
            id: "fixture-managed-binding", resourceID: managed.id, keyOverride: nil,
            isEnabled: true)
        let managedStore = WorkspaceStore(projects: [], resources: [managed])
        XCTAssertTrue(managedStore.bindingIsCompatible(managedBinding, with: .unixSocket))
        XCTAssertEqual(managedStore.sshIdentityProviders.map(\.id), [managed.id])
        XCTAssertEqual(managed.exportSummary, "1 identity")
    }

    func testSshAgentRuntimeSocketPathMatchesDaemonAndFitsMacOSAddress() {
        let surfaceID = "ssh-agent-d56d57b2-3503-40e9-86d0-48a6ca9168fd"

        XCTAssertEqual(
            SshAgentRuntimeSocket.fileName(for: surfaceID),
            "3YUjhPR-lx4my6EW.sock")
        XCTAssertLessThan(
            SshAgentRuntimeSocket.path(
                for: surfaceID, homeDirectory: "/Users/fixture-account"
            ).utf8.count,
            104)
    }

    func testProtectedFileKindsAreInferredWithoutParsingContent() {
        XCTAssertEqual(WorkspaceProtectedFileKind.infer(from: "/fixture/project/.env"), .dotenv)
        XCTAssertEqual(
            WorkspaceProtectedFileKind.infer(from: "/fixture/project/.env.production"), .dotenv)
        XCTAssertEqual(WorkspaceProtectedFileKind.infer(from: "/fixture/project/.envrc"), .direnv)
        XCTAssertEqual(WorkspaceProtectedFileKind.infer(from: "/fixture/home/.pgpass"), .pgpass)
        XCTAssertEqual(
            WorkspaceProtectedFileKind.infer(from: "/fixture/home/.aws/credentials"),
            .awsCredentials)
        XCTAssertEqual(WorkspaceProtectedFileKind.infer(from: "/fixture/opaque.bin"), .file)
    }

    func testEachSurfaceResolvesOnlyItsExplicitMembers() {
        let resources = [
            WorkspaceResource(
                id: "first", name: "First", kind: .sharedSecret, shape: .scalar,
                exports: [WorkspaceExport(key: "FIRST", previewValue: "one", sensitive: true)],
                usageCount: 1),
            WorkspaceResource(
                id: "second", name: "Second", kind: .sharedSecret, shape: .scalar,
                exports: [WorkspaceExport(key: "SECOND", previewValue: "two", sensitive: true)],
                usageCount: 1),
        ]
        let environment = WorkspaceEnvironment(
            id: "development", name: "Development",
            bindings: [
                WorkspaceBinding(
                    id: "first-binding", resourceID: "first", keyOverride: nil, isEnabled: true),
                WorkspaceBinding(
                    id: "second-binding", resourceID: "second", keyOverride: nil,
                    isEnabled: true),
            ],
            surfaces: [
                WorkspaceSurface(
                    id: "first-surface", name: ".env.first", kind: .dotenvFile,
                    path: "/tmp/fixture/.env.first", status: .linked,
                    input: .bindings(["first-binding"])),
                WorkspaceSurface(
                    id: "second-surface", name: ".env.second", kind: .dotenvFile,
                    path: "/tmp/fixture/.env.second", status: .linked,
                    input: .bindings(["second-binding"])),
            ])
        let store = WorkspaceStore(
            projects: [
                WorkspaceProject(
                    id: "fixture", name: "Fixture", path: "/tmp/fixture",
                    commonBindings: [], environments: [environment])
            ], resources: resources)

        XCTAssertEqual(store.resolvedExports.map(\.key), ["FIRST"])
        store.selectedSurfaceID = "second-surface"
        XCTAssertEqual(store.resolvedExports.map(\.key), ["SECOND"])
    }

    func testItemMetadataIsNormalizedAndRejectsCredentialURLs() throws {
        let metadata = try WorkspaceStore.validatedMetadata(
            ItemMetadata(
                note: "  Used by staging  ",
                links: [
                    ItemLink(
                        label: "  Dashboard  ",
                        url: "  https://example.invalid/tokens  ")
                ]))
        XCTAssertEqual(metadata.note, "Used by staging")
        XCTAssertEqual(metadata.links[0].label, "Dashboard")
        XCTAssertEqual(metadata.links[0].url, "https://example.invalid/tokens")

        XCTAssertThrowsError(
            try WorkspaceStore.validatedMetadata(
                ItemMetadata(
                    note: nil,
                    links: [
                        ItemLink(
                            label: "Dashboard",
                            url: "https://fixture-user:fixture-password@example.invalid")
                    ])))
    }
}
