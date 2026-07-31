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
        XCTAssertTrue(source.contains(#""Managed""#))
        XCTAssertTrue(source.contains(#""Will be managed""#))
        XCTAssertTrue(source.contains(#""Not selected""#))
        XCTAssertTrue(source.contains(#""Managed file""#))
        XCTAssertTrue(source.contains(#"return selected ? .green : .secondary"#))
        XCTAssertFalse(source.contains(#""doc.badge.lock""#))
        XCTAssertFalse(source.contains(#""shared automatically""#))
    }

    func testCompactProjectUsesOneManagedInventory() throws {
        let source = try source("CompactDashboardView.swift")

        XCTAssertTrue(source.contains(#"DashboardSection(title: "Managed")"#))
        XCTAssertFalse(source.contains(#"DashboardSection(title: "Outputs")"#))
        XCTAssertFalse(source.contains(#"DashboardSection(title: "Protected Files")"#))
        XCTAssertFalse(source.contains(#"DashboardSection(title: "Unattached Bindings")"#))
        XCTAssertFalse(source.contains(#""Manage Output…""#))
        XCTAssertFalse(source.contains(#""Manage Project""#))
        XCTAssertFalse(source.contains("sourceSummary"))
        XCTAssertTrue(source.contains(#""Project Settings""#))
        XCTAssertTrue(source.contains(#""No managed items yet""#))
        XCTAssertTrue(source.contains(#""\(count) managed item"#))
        XCTAssertTrue(source.contains("state.workspace.managedItemCount"))
    }

    func testLibraryDefaultsToOneInventoryAndUsesTypesAsFilters() throws {
        let workspace = try source("WorkspaceView.swift")
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertTrue(workspace.contains(#"sidebarRow("All Items""#))
        XCTAssertTrue(workspace.contains("LibraryCatalogView("))
        XCTAssertTrue(workspace.contains("LibraryCatalogFilter.allCases"))
        XCTAssertTrue(workspace.contains("store.allSurfaces"))
        XCTAssertTrue(workspace.contains("store.backingResource(for:"))
        XCTAssertFalse(workspace.contains(#"sidebarRow("Shared Secrets""#))
        XCTAssertFalse(workspace.contains(#"sidebarRow("Env Files""#))
        XCTAssertFalse(workspace.contains(#""Protected Files", systemImage:"#))
        XCTAssertTrue(dashboard.contains("openWorkspace(.library)"))
        XCTAssertTrue(workspace.contains("LibraryItemDetailSheet("))
        XCTAssertFalse(workspace.contains(#""More Details…""#))
    }

    func testProjectManagedItemsShareTheLibraryDetailSheet() throws {
        let workspace = try source("WorkspaceView.swift")
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertTrue(workspace.contains("case surface(WorkspaceSurface)"))
        XCTAssertTrue(workspace.contains("ManageSurfaceSheet(store: store, surface: surface)"))
        XCTAssertTrue(dashboard.contains("@State private var selectedManagedItem"))
        XCTAssertTrue(dashboard.contains("selectedManagedItem = .file(file)"))
        XCTAssertTrue(dashboard.contains("selectedManagedItem = .surface(surface)"))
        XCTAssertTrue(dashboard.contains(#"Button("Details…", systemImage: "info.circle")"#))
        XCTAssertFalse(workspace.contains(#""Edit Output""#))
        XCTAssertFalse(workspace.contains(#""Remove Output""#))
        XCTAssertFalse(workspace.contains(#""Remove Configuration""#))
        XCTAssertTrue(workspace.contains(#""Stop Protecting…""#))
        XCTAssertTrue(workspace.contains("store.restoreManagedFile(surface.id)"))
    }

    func testManagedItemRowsExposeDetailsWithoutOpeningTheMoreMenu() throws {
        let workspace = try source("WorkspaceView.swift")
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertEqual(dashboard.components(separatedBy: "Button(action: showDetails)").count - 1, 2)
        XCTAssertTrue(workspace.contains(#".accessibilityHint("Open details")"#))
        XCTAssertTrue(dashboard.contains(#".accessibilityHint("Open details")"#))
    }

    func testFileConfigurationHidesMountImplementationDetails() throws {
        let workspace = try source("WorkspaceView.swift")
        let dashboard = try source("CompactDashboardView.swift")
        let preview = try source("DiscoveryImportPreview.swift")

        for phrase in [
            #"InspectorSection(title: "Managed path")"#,
            #"InspectorSection(title: "Project path")"#,
            #"InspectorSection(title: "Included content")"#,
            #""Managed link is healthy""#,
            #""All configured outputs""#,
            #"configured-file conflict"#,
            #""Configured file""#,
            #"output conflict"#,
            #"existing output"#,
            #"outputs and protected files"#,
            #""Output already exists:"#,
        ] {
            XCTAssertFalse(
                workspace.contains(phrase) || dashboard.contains(phrase)
                    || preview.contains(phrase),
                phrase)
        }
        XCTAssertTrue(workspace.contains(#"InspectorSection(title: "Location")"#))
        XCTAssertTrue(workspace.contains(#"InspectorSection(title: "Contents")"#))
        XCTAssertTrue(workspace.contains(#""Values from this file""#))
        XCTAssertTrue(dashboard.contains(#""Uses project settings""#))
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
