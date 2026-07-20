import XCTest

@testable import accessfs_menubar

@MainActor
final class WorkspaceModelTests: XCTestCase {
    func testPreviewEnvironmentResolvesBindingsAndSurfaces() {
        let store = WorkspaceStore.preview()

        XCTAssertEqual(store.selectedProject.name, "floria-web")
        XCTAssertEqual(store.selectedEnvironment.name, "Development")
        XCTAssertEqual(store.resolvedExports.count, 12)
        XCTAssertTrue(store.conflictingKeys.isEmpty)
        XCTAssertEqual(store.selectedEnvironment.surfaces.map(\.kind), [.dotenvFile, .unixSocket])
        XCTAssertTrue(store.resolvedExports.contains { $0.key == "CLOUDFLARE_API_TOKEN" })
        XCTAssertTrue(store.resolvedExports.contains { $0.key == "SSH_AUTH_SOCK" })
    }

    func testDisablingBindingRemovesItsExports() throws {
        let store = WorkspaceStore.preview()
        let binding = try XCTUnwrap(
            store.environmentBindings.first { $0.resourceID == "local-database" })

        store.toggleBinding(binding.id)

        XCTAssertFalse(store.resolvedExports.contains { $0.key == "DATABASE_URL" })
        XCTAssertEqual(store.resolvedExports.count, 9)
    }

    func testSelectingEnvironmentResetsSurfaceSelection() throws {
        let store = WorkspaceStore.preview()
        store.selectedSurfaceID = "floria-dev-ssh-socket"
        let staging = try XCTUnwrap(
            store.selectedProject.environments.first { $0.name == "Staging" })

        store.selectEnvironment(staging.id)

        XCTAssertEqual(store.selectedEnvironment.name, "Staging")
        XCTAssertEqual(store.selectedSurface.kind, .dotenvFile)
    }

    func testAddingAvailableResourceCreatesEnvironmentBinding() {
        let store = WorkspaceStore.preview()

        store.addResource("sentry-dsn")

        XCTAssertTrue(store.environmentBindings.contains { $0.resourceID == "sentry-dsn" })
        XCTAssertTrue(store.resolvedExports.contains { $0.key == "SENTRY_DSN" })
    }
}
