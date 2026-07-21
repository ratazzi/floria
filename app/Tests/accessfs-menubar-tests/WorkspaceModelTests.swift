import XCTest

@testable import accessfs_menubar

@MainActor
final class WorkspaceModelTests: XCTestCase {
    func testPreviewEnvironmentResolvesBindingsAndSurfaces() {
        let store = WorkspaceStore.preview()

        XCTAssertEqual(store.selectedProject?.name, "floria-web")
        XCTAssertEqual(store.selectedEnvironment?.name, "Development")
        XCTAssertEqual(store.resolvedExports.count, 12)
        XCTAssertTrue(store.conflictingKeys.isEmpty)
        XCTAssertEqual(store.selectedEnvironment?.surfaces.map(\.kind), [.dotenvFile, .unixSocket])
        XCTAssertTrue(store.resolvedExports.contains { $0.key == "CLOUDFLARE_API_TOKEN" })
        XCTAssertTrue(store.resolvedExports.contains { $0.key == "SSH_AUTH_SOCK" })
    }

    func testDisablingBindingRemovesItsExports() async throws {
        let store = WorkspaceStore.preview()
        let binding = try XCTUnwrap(
            store.environmentBindings.first { $0.resourceID == "local-database" })

        await store.toggleBinding(binding.id)

        XCTAssertFalse(store.resolvedExports.contains { $0.key == "DATABASE_URL" })
        XCTAssertEqual(store.resolvedExports.count, 9)
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
            ], surfaces: [])
        let project = WorkspaceProject(
            id: "fixture-project", name: "Fixture", path: "/tmp/fixture",
            commonBindings: [], environments: [environment])
        let store = WorkspaceStore(projects: [project], resources: [resource])

        XCTAssertEqual(store.resolvedExports.map(\.key), ["LOG_LEVEL"])
    }
}
