import Foundation
import XCTest

final class ProductLanguageTests: XCTestCase {
    func testResourceManagementIsCalledLibraryAcrossNavigationSurfaces() throws {
        let sources = try [
            source("MenuBarView.swift"),
            source("CompactDashboardView.swift"),
            source("WorkspaceView.swift"),
        ].joined(separator: "\n")

        XCTAssertFalse(sources.contains(#""Open Workspace""#))
        XCTAssertFalse(sources.contains(#""Refresh Workspace""#))
        XCTAssertFalse(sources.contains(#"sidebarSectionTitle("Workspace")"#))
        XCTAssertTrue(sources.contains(#""Open Library""#))
        XCTAssertTrue(sources.contains(#""Refresh Library""#))
        XCTAssertTrue(sources.contains(#"sidebarSectionTitle("Library")"#))
    }

    func testDiscoveryUsesProtectionStateInsteadOfImplementationActions() throws {
        let source = try source("CompactDashboardView.swift")

        for phrase in [
            "Env value",
            "New Secret",
            "New secret",
            "New shared secret",
            "Share in import",
            "Covered",
            "Protect in place",
            "Protected in place",
            "Import identity",
            "Review Discovery",
            "Review Changes",
            "Needs value",
            "Choose Destination",
            "Import",
            "Review",
        ] {
            XCTAssertFalse(source.contains(#""\#(phrase)""#), phrase)
        }
        XCTAssertTrue(source.contains(#""Protected""#))
        XCTAssertTrue(source.contains(#""Will be protected""#))
        XCTAssertTrue(source.contains(#""Not selected""#))
    }

    private func source(_ name: String) throws -> String {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot
            .appendingPathComponent("Sources/accessfs-menubar")
            .appendingPathComponent(name)
        return try String(contentsOf: sourceURL, encoding: .utf8)
    }
}
