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
            detail: "2 entries", usageCount: 0)
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
            ], detail: "2 entries", usageCount: 0)
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

    func testIniBindingCanSelectOneSectionForDotenvProjection() {
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
            ], detail: "3 entries", usageCount: 0)
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
    }

    func testEachSurfaceResolvesOnlyItsExplicitMembers() {
        let resources = [
            WorkspaceResource(
                id: "first", name: "First", kind: .sharedSecret, shape: .scalar,
                exports: [WorkspaceExport(key: "FIRST", previewValue: "one", sensitive: true)],
                detail: "First", usageCount: 1),
            WorkspaceResource(
                id: "second", name: "Second", kind: .sharedSecret, shape: .scalar,
                exports: [WorkspaceExport(key: "SECOND", previewValue: "two", sensitive: true)],
                detail: "Second", usageCount: 1),
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
}
