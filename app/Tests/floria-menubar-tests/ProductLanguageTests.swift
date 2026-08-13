import Foundation
import XCTest

final class ProductLanguageTests: XCTestCase {
    func testMacFuseSetupLeadsWithRecoveryAndDoesNotSendUsersToAnEmptyPane() throws {
        let source = try source("MacFuseSetup.swift")

        XCTAssertTrue(source.contains(#""1. Enable third-party kernel extensions""#))
        XCTAssertTrue(source.contains(#""2. Approve macFUSE after restarting""#))
        XCTAssertTrue(source.contains(#""If System Settings has no Allow button yet, that is expected before this step.""#))
        XCTAssertTrue(source.contains("Do not enable the macFUSE switches under File System Extensions."))
        XCTAssertTrue(source.contains("No alert or Allow button after Recheck?"))
        XCTAssertTrue(source.contains(#""Copy manual load command""#))
        XCTAssertTrue(
            source.contains(
                "/usr/bin/sudo /usr/bin/kmutil load -p /Library/Filesystems/macfuse.fs/Contents/Extensions/26/macfuse.kext"))
        XCTAssertTrue(source.contains(#""Copy doctor command""#))
        XCTAssertTrue(source.contains(#""/Applications/Floria.app/Contents/Resources/floria" doctor"#))
        XCTAssertFalse(source.contains("doctor --config"))
        XCTAssertFalse(source.contains(#"Button("Open Privacy & Security")"#))
    }

    func testOfflineDaemonRetryActuallyReconcilesTheDaemon() throws {
        let source = try source("CompactDashboardView.swift")

        XCTAssertTrue(source.contains("case reconnectDaemon"))
        XCTAssertTrue(source.contains(#"actionTitle: "Retry", action: .reconnectDaemon"#))
        XCTAssertTrue(source.contains("state.recheckMacFuseSetup()"))
    }

    func testMissingKernelDeviceIsPresentedDuringTheProbeInsteadOfAfterTheFullTimeout() throws {
        let source = try source("AppState.swift")

        XCTAssertTrue(source.contains("elapsedSeconds == 0 && !kernelBackendReady"))
        XCTAssertTrue(source.contains("self.macFuseSetupStage = .approveKext"))
    }

    func testSetupDismissalRequiresTheActualFloriaMount() throws {
        let state = try source("AppState.swift")
        let setup = try source("MacFuseSetup.swift")

        XCTAssertTrue(state.contains("floriaMounted: floriaMounted"))
        XCTAssertTrue(state.contains("observed the live Floria mount"))
        XCTAssertFalse(state.contains("A live agent connection is definitive proof the mount is up"))
        XCTAssertTrue(setup.contains("connected && kernelBackendReady && floriaMounted"))
        XCTAssertTrue(setup.contains("No recoveryOS or System Settings action is needed"))
    }

    func testMountReadinessRefreshesOneAtomicWorkspaceSnapshot() throws {
        let state = try source("AppState.swift")
        let workspace = try source("WorkspaceModel.swift")

        XCTAssertTrue(state.contains("observed the live Floria mount"))
        XCTAssertTrue(state.contains("await self.refreshDaemonState()"))
        XCTAssertTrue(workspace.contains("let (nextCatalog, nextFiles) = try await (catalog, files)"))
        XCTAssertTrue(workspace.contains("apply(nextCatalog)"))
        XCTAssertTrue(workspace.contains("protectedFiles = protectedFileModels(nextFiles)"))
        XCTAssertFalse(workspace.contains("apply(try await catalog)"))
    }

    func testDashboardOffersSafeBackupActionsWithoutDataReplacement() throws {
        let source = try source("CompactDashboardView.swift")

        XCTAssertTrue(source.contains(#""Create Backup…""#))
        XCTAssertTrue(source.contains(#""Verify Backup…""#))
        XCTAssertTrue(source.contains(#""Export Recovery Key…""#))
        XCTAssertFalse(source.contains(#""Restore Backup…""#))
        XCTAssertFalse(source.contains(#""Activate Backup…""#))
    }

    func testRecoveryKeyExportConfirmsThePassphraseWithoutPersistingIt() throws {
        let source = try source("RecoveryKeyExportSheet.swift")

        XCTAssertEqual(source.components(separatedBy: "SecureField(").count - 1, 2)
        XCTAssertTrue(source.contains(#""Use at least 12 characters.""#))
        XCTAssertTrue(source.contains(#""Passphrases do not match.""#))
        XCTAssertTrue(source.contains("clearPassphrases()"))
        XCTAssertFalse(source.contains("UserDefaults"))
        XCTAssertFalse(source.contains("AppStorage"))
    }

    func testSyncProblemsLeadToTheSpecificFilesWithoutDeletingEvidence() throws {
        let source = try source("SyncView.swift")

        XCTAssertTrue(source.contains("status.damagedFiles"))
        XCTAssertTrue(source.contains(#"Button("Show")"#))
        XCTAssertTrue(source.contains(#""Some synced files couldn’t be verified""#))
        XCTAssertTrue(source.contains(#""Waiting for your sync tool""#))
        XCTAssertFalse(source.contains("deleteReplicationDamage"))
        XCTAssertFalse(source.contains(#"Button("Repair Sync")"#))
    }

    func testFirstProjectEmptyStateOffersDiscoveryDirectly() throws {
        let source = try source("CompactDashboardView.swift")

        XCTAssertTrue(source.contains(#""Discover a project directory to get started.""#))
        XCTAssertTrue(source.contains(#"actionTitle: state.workspace.projects.isEmpty"#))
        XCTAssertTrue(source.contains(#"action: state.workspace.projects.isEmpty ? chooseDiscoverySource : nil"#))
    }

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
        XCTAssertTrue(
            workspace.contains(
                #"Button("#)
                && workspace.contains(#""Update Contents…","#))
        XCTAssertFalse(workspace.contains(#""More Details…""#))
    }

    func testProjectManagedItemsShareTheLibraryDetailSheet() throws {
        let workspace = try source("WorkspaceView.swift")
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertTrue(workspace.contains("case surface(WorkspaceSurface)"))
        XCTAssertTrue(workspace.contains("ManageSurfaceSheet(store: store, surface: surface)"))
        XCTAssertTrue(dashboard.contains("@State private var selectedManagedItem"))
        XCTAssertTrue(dashboard.contains("selectedManagedItem = item.libraryItem"))
        XCTAssertTrue(dashboard.contains("private struct CompactManagedItemRow: View"))
        XCTAssertFalse(dashboard.contains("private struct CompactSurfaceRow: View"))
        XCTAssertFalse(dashboard.contains("private struct CompactProtectedFileRow: View"))
        XCTAssertTrue(dashboard.contains(#"Button("Details…", systemImage: "info.circle")"#))
        XCTAssertFalse(workspace.contains(#""Edit Output""#))
        XCTAssertFalse(workspace.contains(#""Remove Output""#))
        XCTAssertFalse(workspace.contains(#""Remove Configuration""#))
        XCTAssertTrue(workspace.contains(#""Stop Protecting…""#))
        XCTAssertTrue(workspace.contains("store.restoreManagedFile(surface.id)"))
    }

    func testManagedFileEnvironmentScopeIsEditableFromItsDetails() throws {
        let workspace = try source("WorkspaceView.swift")

        XCTAssertTrue(workspace.contains("ManagedFileEnvironmentMenu("))
        XCTAssertFalse(
            workspace.contains(#"LabeledContent("Environments", value: environments)"#))
    }

    func testRecentAccessCountAndTimeUseStableColumns() throws {
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertTrue(
            dashboard.contains(
                #".frame(width: AccessSummaryRowLayout.countWidth, alignment: .trailing)"#))
        XCTAssertTrue(
            dashboard.contains(
                #".frame(width: AccessSummaryRowLayout.timeWidth, alignment: .trailing)"#))
    }

    func testClosingSyncRefreshesTheVisibleLibrary() throws {
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertTrue(dashboard.contains(#".sheet(isPresented: $showingSync, onDismiss:"#))
        XCTAssertTrue(dashboard.contains("await state.workspace.reload()"))
        XCTAssertTrue(dashboard.contains("await state.workspace.refreshProjectCheckoutDiscoveries()"))
    }

    func testManagedItemRowsExposeDetailsWithoutOpeningTheMoreMenu() throws {
        let workspace = try source("WorkspaceView.swift")
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertEqual(dashboard.components(separatedBy: "Button(action: showDetails)").count - 1, 1)
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
        XCTAssertFalse(dashboard.contains(#""Uses project settings""#))
    }

    func testWorktreesUseEnvironmentSelectionAsTheOnlyStateControl() throws {
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertTrue(dashboard.contains(#"title: "Managed""#))
        XCTAssertTrue(dashboard.contains(#"title: "Other Worktrees""#))
        XCTAssertTrue(dashboard.contains(#"Text("No Default").tag("")"#))
        XCTAssertTrue(dashboard.contains(#"Text("No Environment").tag("")"#))
        XCTAssertTrue(dashboard.contains("Text(primaryEnvironmentTitle)"))
        XCTAssertTrue(dashboard.contains("await setEnvironment("))
        XCTAssertTrue(dashboard.contains(".truncationMode(.middle)"))

        XCTAssertFalse(dashboard.contains(#"checkoutBadge("Managed""#))
        XCTAssertFalse(dashboard.contains(#"Button(managed == nil ? "Link" : "Update")"#))
        XCTAssertFalse(dashboard.contains(#".help("Stop managing this worktree")"#))
        XCTAssertFalse(dashboard.contains(#""Ask every time""#))
    }

    func testWorktreeAttentionNavigatesAndRevealsSpecificFiles() throws {
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertTrue(dashboard.contains("reviewWorktreeIssuesButton"))
        XCTAssertTrue(dashboard.contains("expandedIssuePaths"))
        XCTAssertTrue(dashboard.contains("worktreeIssueDetails("))
        XCTAssertTrue(dashboard.contains("repairManagedLink("))
        XCTAssertTrue(dashboard.contains("\"Repair Link\""))
        XCTAssertTrue(dashboard.contains("revealWorktreeIssue("))
    }

    func testWorktreeOperationErrorsRenderOnlyOnce() throws {
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertEqual(
            dashboard.components(
                separatedBy:
                    #"Label(errorMessage, systemImage: "exclamationmark.triangle.fill")"#
            ).count - 1,
            1
        )
    }

    func testEveryManagedPathUsesTheSharedRepairAction() throws {
        let dashboard = try source("CompactDashboardView.swift")
        let workspace = try source("WorkspaceView.swift")
        let model = try source("WorkspaceModel.swift")
        let protocolSource = try source("ControlProtocol.swift")

        XCTAssertTrue(dashboard.contains("repairManagedLink("))
        XCTAssertTrue(workspace.contains("repairManagedLink("))
        XCTAssertTrue(model.contains("func repairManagedLink(at path: String)"))
        XCTAssertTrue(protocolSource.contains("case managedLinkRepair(path: String)"))
        XCTAssertFalse(protocolSource.contains("projectCheckoutLinkRepair"))
    }

    func testManagedRowsKeepTypeWithTheFileDescription() throws {
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertEqual(
            dashboard.components(separatedBy: "CompactManagedItemSubtitle(").count - 1,
            1)
        XCTAssertTrue(dashboard.contains("Text(kind)"))
        XCTAssertTrue(dashboard.contains("Text(path)"))
        XCTAssertFalse(dashboard.contains(".frame(width: 126, alignment: .leading)"))
    }

    func testManagedRowsUseAStableSecurityColumn() throws {
        let dashboard = try source("CompactDashboardView.swift")
        let menuParts = dashboard.components(
            separatedBy: "private struct CompactSecurityLevelMenu: View {")
        XCTAssertEqual(menuParts.count, 2)
        let menu = try XCTUnwrap(
            menuParts.last?.components(
                separatedBy: "private func compactManagedPath").first)

        XCTAssertTrue(menu.contains(".frame(width: 108, alignment: .leading)"))
        XCTAssertFalse(menu.contains(".frame(width: 78, alignment: .leading)"))
    }

    func testManagedLinkKnowledgeComesFromOneWorkspaceModel() throws {
        let model = try source("WorkspaceModel.swift")
        let dashboard = try source("CompactDashboardView.swift")
        let workspace = try source("WorkspaceView.swift")

        XCTAssertTrue(model.contains("struct WorkspaceManagedLink"))
        XCTAssertTrue(model.contains("let managedLink: WorkspaceManagedLink?"))
        XCTAssertFalse(model.contains("enum SshAgentRuntimeSocket"))
        XCTAssertFalse(model.contains("enum WorkspaceSurfaceStatus"))
        XCTAssertFalse(workspace.contains("expectedLinkTarget"))
        XCTAssertFalse(workspace.contains("destinationOfSymbolicLink"))
        XCTAssertTrue(dashboard.contains("item.managedLink?.needsAttention"))
    }

    func testLibraryWindowDoesNotAddATitleBarAboveItsOwnNavigation() throws {
        let app = try source("App.swift")
        let scenes = app.components(
            separatedBy: #"Window("Floria Library", id: "workspace")"#)
        XCTAssertEqual(scenes.count, 2)
        let libraryScene = try XCTUnwrap(scenes.last)

        XCTAssertTrue(libraryScene.contains(".defaultSize(width: 1180, height: 760)"))
        XCTAssertTrue(libraryScene.contains(".windowStyle(.hiddenTitleBar)"))
    }

    func testLibraryRowsUseStableTypeAndSecurityColumns() throws {
        let workspace = try source("WorkspaceView.swift")

        XCTAssertTrue(workspace.contains("LibraryItemTypeColumn(title: item.typeTitle)"))
        XCTAssertTrue(workspace.contains("LibrarySecurityLevelColumn("))
        XCTAssertTrue(workspace.contains(".frame(width: 180, alignment: .leading)"))
        XCTAssertTrue(workspace.contains(".frame(width: 108, alignment: .leading)"))
    }

    func testFullAndCompactProtectionMenusShareGlobalActions() throws {
        let workspace = try source("WorkspaceView.swift")
        let dashboard = try source("CompactDashboardView.swift")

        XCTAssertTrue(workspace.contains("struct ProtectionMenuContent"))
        XCTAssertTrue(workspace.contains("ProtectionMenuContent("))
        XCTAssertTrue(dashboard.contains("ProtectionMenuContent("))

        for title in [
            "Daemon connected",
            "Enable Audit Only",
            "Refresh Library",
            "Open Access Log",
        ] {
            XCTAssertTrue(workspace.contains(#""\#(title)"#), title)
        }
    }

    func testFullProtectionMenuShowsItsCurrentMode() throws {
        let workspace = try source("WorkspaceView.swift")

        XCTAssertTrue(workspace.contains("WorkspaceProtectionMenuLabel("))
        XCTAssertTrue(workspace.contains(#""Protected""#))
        XCTAssertTrue(workspace.contains(#""Audit Only""#))
        XCTAssertTrue(workspace.contains(#""Offline""#))
    }

    func testRecentProjectsSummarizeManagedItemCounts() throws {
        let dashboard = try source("CompactDashboardView.swift")
        let detailParts = dashboard.components(
            separatedBy: "private func projectDetail(_ project: WorkspaceProject) -> String {")
        XCTAssertEqual(detailParts.count, 2)
        let detail = try XCTUnwrap(
            detailParts.last?.components(
                separatedBy: "private func projectIsHealthy").first)

        XCTAssertTrue(detail.contains("projectManagedItemCount(project)"))
        XCTAssertTrue(detail.contains(#"item\(count == 1 ? "" : "s")"#))
        XCTAssertFalse(detail.contains("surfaces.prefix"))
        XCTAssertFalse(detail.contains(#""SSH agent""#))
    }

    private func source(_ name: String) throws -> String {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot
            .appendingPathComponent("Sources/floria-menubar")
            .appendingPathComponent(name)
        return try String(contentsOf: sourceURL, encoding: .utf8)
    }
}
