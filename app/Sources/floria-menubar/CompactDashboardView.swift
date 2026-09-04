import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct AppSearchFocusKey: FocusedValueKey {
    typealias Value = () -> Void
}

extension FocusedValues {
    var focusAppSearch: AppSearchFocusKey.Value? {
        get { self[AppSearchFocusKey.self] }
        set { self[AppSearchFocusKey.self] = newValue }
    }
}

private struct DiscoveryPresentation: Identifiable {
    let id = UUID()
    let paths: [String]
}

private struct BackupNotice: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

/// Matches access events to a project with pre-lowercased, pre-expanded
/// strings so hot loops stay on plain Swift string operations (macOS paths
/// are case-insensitive, so lowercased comparison is safe).
struct ProjectEventMatcher {
    private let path: String
    private let pathPrefix: String
    private let namePattern: String
    private let surfaceIDs: Set<WorkspaceSurface.ID>

    init(_ project: WorkspaceProject, resources: [WorkspaceResource] = []) {
        path = (project.path as NSString).expandingTildeInPath.lowercased()
        pathPrefix = path + "/"
        namePattern = project.name.lowercased() + "/"
        surfaceIDs = Set(project.environments.flatMap(\.surfaces).map(\.id)).union(
            resources.compactMap { resource in
                (resource.kind == .sshAccess
                    && resource.sshAccess?.projectIDs.contains(project.id) == true)
                    ? resource.id : nil
            })
    }

    static func loweredCandidates(for event: RecentAccess) -> [String] {
        [event.path, event.display, event.shownPath].compactMap { candidate in
            guard let candidate else { return nil }
            return (candidate as NSString).expandingTildeInPath.lowercased()
        }
    }

    func matchesLowered(_ candidates: [String], surfaceID: WorkspaceSurface.ID? = nil) -> Bool {
        if let surfaceID, surfaceIDs.contains(surfaceID) { return true }
        return candidates.contains { candidate in
            candidate == path || candidate.hasPrefix(pathPrefix)
                || candidate.contains(namePattern)
        }
    }

    func matches(_ event: RecentAccess) -> Bool {
        matchesLowered(
            Self.loweredCandidates(for: event), surfaceID: event.ssh?.surface_id)
    }
}

private enum DashboardIssueAction {
    case reconnectDaemon
    case reload
    case openWorkspace
}

private struct DashboardIssue: Identifiable {
    let id: String
    let title: String
    let detail: String?
    let actionTitle: String
    let action: DashboardIssueAction
}

/// Compact home dashboard. Detailed inventory management remains in AdvancedWorkspaceView.
struct DashboardView: View {
    @Bindable var state: AppState
    @State private var search = ""
    @State private var selectedProjectID: WorkspaceProject.ID?
    @State private var isDropTargeted = false
    @State private var isDiscovering = false
    @State private var discovery: DiscoveryPresentation?
    @State private var showingAccessLog = false
    @State private var showingSystemHealth = false
    @State private var pendingAuditWindow: AuditOnlyWindow?
    @State private var showingAuditConfirmation = false
    @State private var showingUninstallConfirmation = false
    @State private var uninstallInProgress = false
    @State private var backupNotice: BackupNotice?
    @State private var backupOperationInProgress = false
    @State private var showingRecoveryKeyExport = false
    @State private var showingSync = false
    @State private var showingProtectFile = false
    @State private var showingNewSecret = false
    @State private var showingImportSshIdentity = false
    @State private var showingNewSshAccess = false
    @State private var checkoutPresentationID = UUID()
    @FocusState private var searchIsFocused: Bool
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        ZStack {
            Color(nsColor: .controlBackgroundColor)
                .ignoresSafeArea()

            VStack(spacing: 0) {
                header
                Divider()
                if let selectedProject {
                    CompactProjectDetailView(
                        state: state,
                        project: selectedProject,
                        search: search,
                        recentAccess: visibleAccess,
                        selectProject: { projectID in
                            if let projectID {
                                state.workspace.selectProject(projectID)
                            }
                            selectedProjectID = projectID
                            search = ""
                        },
                        openAdvanced: {
                            openWorkspace(.project(selectedProject.id))
                        })
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 20) {
                            projectsSection
                            if !issues.isEmpty {
                                attentionSection
                            }
                            accessSection
                            librarySection
                        }
                        .padding(.horizontal, 28)
                        .padding(.top, 22)
                        .padding(.bottom, 28)
                    }
                }
            }

            if isDropTargeted {
                discoveryDropOverlay
                    .padding(18)
                    .allowsHitTesting(false)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .ignoresSafeArea(.container, edges: .top)
        .sheet(item: $state.macFuseSetupStage) { stage in
            MacFuseSetupView(state: state, stage: stage)
        }
        .focusedSceneValue(\.focusAppSearch) {
            searchIsFocused = true
        }
        .dropDestination(for: URL.self) { urls, _ in
            let paths = urls.filter(\.isFileURL).map(\.path)
            guard !paths.isEmpty else { return false }
            beginDiscovery(at: paths)
            return true
        } isTargeted: { isDropTargeted = $0 }
        .sheet(item: $discovery, onDismiss: {
            isDiscovering = false
        }) { presentation in
            DiscoveryWorkflowSheet(
                paths: presentation.paths,
                store: state.workspace,
                openProject: { projectID in
                    selectedProjectID = projectID
                    search = ""
                })
        }
        .sheet(isPresented: $showingAccessLog) {
            AccessLogView(state: state)
                .frame(minWidth: 920, minHeight: 620)
        }
        .sheet(isPresented: $showingSystemHealth) {
            SystemHealthView(state: state)
        }
        .sheet(isPresented: $showingRecoveryKeyExport) {
            RecoveryKeyExportSheet(
                export: { destination, passphrase in
                    try await state.workspace.exportRecoveryKey(
                        at: destination, passphrase: passphrase)
                },
                completed: { report in
                    backupNotice = BackupNotice(
                        title: "Recovery Key Exported",
                        message:
                            "Store this file and its passphrase separately from this Mac.\n\(report.path)"
                    )
                })
        }
        .sheet(isPresented: $showingSync, onDismiss: {
            Task {
                await state.workspace.reload()
                await state.workspace.refreshProjectCheckoutDiscoveries()
            }
        }) {
            SyncView(
                service: state.cloudSyncService,
                restartDaemon: { await state.restartDaemonForCloudSync() })
        }
        .sheet(isPresented: $showingProtectFile) {
            ProtectExistingFileSheet(store: state.workspace)
        }
        .sheet(isPresented: $showingNewSecret) {
            NewSharedSecretSheet(store: state.workspace)
        }
        .sheet(isPresented: $showingImportSshIdentity) {
            ImportSshIdentitySheet(store: state.workspace)
        }
        .sheet(isPresented: $showingNewSshAccess) {
            AddSshAccessSheet(
                store: state.workspace,
                preselectedProjectIDs: Set(selectedProject.map { [$0.id] } ?? []))
        }
        .onAppear {
            state.setWorkspacePresentation(checkoutPresentationID, visible: true)
            presentRequestedSystemHealth()
        }
        .onDisappear {
            state.setWorkspacePresentation(checkoutPresentationID, visible: false)
        }
        .onChange(of: state.systemHealthPresentationRequested) {
            presentRequestedSystemHealth()
        }
        .confirmationDialog(
            "Enable Audit Only?", isPresented: $showingAuditConfirmation,
            presenting: pendingAuditWindow
        ) { window in
            Button("Enable for \(window.title)", role: .destructive) {
                Task {
                    await state.setPolicyMode(.auditOnly, durationSecs: window.durationSecs)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text(
                "Ask and Touch ID items will be allowed without interaction. Every access will still be audited, and explicit deny rules remain blocked."
            )
        }
        .confirmationDialog(
            "Uninstall Floria?", isPresented: $showingUninstallConfirmation
        ) {
            Button("Uninstall Floria", role: .destructive) {
                uninstallApplication()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This moves Floria.app to the Trash and stops its daemon and protected filesystem. Your encrypted Library, catalog, backups, configuration, and Keychain key stay on this Mac for a future reinstall."
            )
        }
        .alert(item: $backupNotice) { notice in
            Alert(
                title: Text(notice.title),
                message: Text(notice.message),
                dismissButton: .default(Text("OK")))
        }
    }

    // Occupies the hidden-titlebar strip: traffic lights on the left, then
    // app-level chrome. Project identity lives in the content header below.
    private var header: some View {
        HStack(spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.tertiary)
                TextField("Search", text: $search)
                    .textFieldStyle(.plain)
                    .focused($searchIsFocused)
                    .onExitCommand {
                        if search.isEmpty {
                            searchIsFocused = false
                        } else {
                            search = ""
                        }
                    }
                if !search.isEmpty {
                    Button {
                        search = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.tertiary)
                    }
                    .buttonStyle(.plain)
                } else {
                    Text("⌘F")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 4))
                }
            }
            .padding(.horizontal, 11)
            .frame(minWidth: 180, maxWidth: .infinity)
            .frame(height: 34)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.secondary.opacity(0.18), lineWidth: 1)
            }
            .layoutPriority(1)

            Menu {
                Button("Protect File", systemImage: "lock.fill") {
                    showingProtectFile = true
                }
                Button("New Secret", systemImage: "key.fill") {
                    showingNewSecret = true
                }
                Button("Import SSH Identity", systemImage: "key.horizontal.fill") {
                    showingImportSshIdentity = true
                }
                Button("New SSH Access", systemImage: "point.3.connected.trianglepath.dotted") {
                    showingNewSshAccess = true
                }
            } label: {
                Image(systemName: "plus")
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .accessibilityLabel("Add Library item")
            .fixedSize()

            Divider().frame(height: 28)

            Button {
                chooseDiscoverySource()
            } label: {
                HStack(spacing: 7) {
                    if isDiscovering {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "safari")
                    }
                    Text(isDiscovering ? "Discovering…" : "Discover")
                }
                .font(.callout.weight(.medium))
            }
            .buttonStyle(.plain)
            .foregroundStyle(isDiscovering ? Color.secondary : Color.primary)
            .disabled(isDiscovering)
            .fixedSize()

            policyMenu

            Menu {
                Button("Discover Project…", systemImage: "sparkle.magnifyingglass") {
                    chooseDiscoverySource()
                }
                Button("Open Library", systemImage: "rectangle.3.group") {
                    openWorkspace()
                }
                Divider()
                Button("Sync…", systemImage: "arrow.triangle.2.circlepath") {
                    showingSync = true
                }
                Divider()
                Button("Create Backup…", systemImage: "externaldrive.badge.plus") {
                    chooseBackupDestination()
                }
                .disabled(backupOperationInProgress || !state.connected)
                Button("Verify Backup…", systemImage: "checkmark.circle") {
                    chooseBackupToVerify()
                }
                .disabled(backupOperationInProgress || !state.connected)
                Button("Export Recovery Key…", systemImage: "key.horizontal") {
                    showingRecoveryKeyExport = true
                }
                .disabled(backupOperationInProgress || !state.connected)
                Divider()
                Button("Export Diagnostics…", systemImage: "stethoscope") {
                    chooseDiagnosticsDestination()
                }
                .disabled(backupOperationInProgress || !state.connected)
                if ApplicationUninstaller.isAvailable {
                    Divider()
                    Button("Uninstall Floria…", systemImage: "trash", role: .destructive) {
                        showingUninstallConfirmation = true
                    }
                    .disabled(uninstallInProgress)
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .accessibilityLabel("More actions")
            .fixedSize()
        }
        .padding(.leading, 82)
        .padding(.trailing, 16)
        .frame(maxWidth: .infinity)
        .frame(height: 52)
        .gesture(WindowDragGesture())
    }

    private func chooseBackupDestination() {
        let panel = NSSavePanel()
        panel.title = "Create Floria Backup"
        panel.prompt = "Create Backup"
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "Floria Backup"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        runBackupOperation {
            let report = try await state.workspace.createBackup(at: url.path)
            return BackupNotice(
                title: "Backup Created",
                message:
                    "\(report.secrets) secrets and \(report.versions) versions were verified.\n\(report.path)"
            )
        }
    }

    private func chooseBackupToVerify() {
        let panel = NSOpenPanel()
        panel.title = "Verify Floria Backup"
        panel.prompt = "Verify Backup"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        runBackupOperation {
            let report = try await state.workspace.verifyBackup(at: url.path)
            return BackupNotice(
                title: "Backup Verified",
                message:
                    "\(report.secrets) secrets and \(report.versions) versions are recoverable.\n\(report.path)"
            )
        }
    }

    private func chooseDiagnosticsDestination() {
        guard let selection = chooseDiagnosticsExportDestination() else { return }
        runBackupOperation {
            let report = try await state.workspace.exportDiagnostics(
                at: selection.path,
                includePaths: selection.includePaths)
            revealDiagnostics(report)
            return BackupNotice(
                title: "Diagnostics Exported",
                message:
                    "\(report.files) support files were saved without secret data.\n\(report.path)"
            )
        }
    }

    private func runBackupOperation(
        _ operation: @escaping @MainActor () async throws -> BackupNotice
    ) {
        guard !backupOperationInProgress else { return }
        backupOperationInProgress = true
        Task {
            defer { backupOperationInProgress = false }
            do {
                backupNotice = try await operation()
            } catch {
                backupNotice = BackupNotice(
                    title: "Backup Failed",
                    message: error.localizedDescription)
            }
        }
    }

    private func uninstallApplication() {
        guard !uninstallInProgress else { return }
        uninstallInProgress = true
        ApplicationUninstaller.uninstall { result in
            switch result {
            case .success:
                break
            case .failure(let error):
                uninstallInProgress = false
                backupNotice = BackupNotice(
                    title: "Uninstall Failed",
                    message:
                        "\(error.localizedDescription)\nFloria restarted its daemon and your data was not removed."
                )
            }
        }
    }

    private var policyMenu: some View {
        let auditOnly = state.policyMode.isAuditOnly()
        return Menu {
            ProtectionMenuContent(
                state: state,
                requestAuditOnly: { window in
                    pendingAuditWindow = window
                    showingAuditConfirmation = true
                },
                refresh: reload,
                openSystemHealth: {
                    showingSystemHealth = true
                },
                openAccessLog: {
                    showingAccessLog = true
                })
        } label: {
            let needsAttention =
                state.systemHealth?.hasIssues == true || state.systemHealthError != nil
            let statusColor = needsAttention || auditOnly ? Color.orange : Color.green
            HStack(spacing: 7) {
                Image(
                    systemName: needsAttention
                        ? "exclamationmark.shield.fill"
                        : auditOnly
                        ? "eye.circle.fill"
                        : (state.connected ? "checkmark.shield.fill" : "shield.slash"))
                Text(
                    needsAttention
                        ? "Needs Attention"
                        : (auditOnly ? "Audit Only" : (state.connected ? "Protected" : "Offline")))
                    .lineLimit(1)
            }
            .font(.callout.weight(.medium))
            .foregroundStyle(
                needsAttention
                    ? Color.orange
                    : (auditOnly ? Color.orange : (state.connected ? Color.green : Color.secondary))
            )
            .padding(.horizontal, 11)
            .frame(height: 34)
            .background(
                statusColor.opacity(state.connected ? 0.09 : 0.04),
                in: RoundedRectangle(cornerRadius: 9))
            .overlay {
                RoundedRectangle(cornerRadius: 9)
                    .stroke(
                        statusColor.opacity(state.connected ? 0.22 : 0.08),
                        lineWidth: 1)
            }
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel("Security mode")
        .accessibilityValue(
            state.systemHealth?.hasIssues == true || state.systemHealthError != nil
                ? "System health needs attention"
                : (auditOnly
                    ? "Audit Only"
                    : (state.connected
                        ? "Protected; using each item's security level"
                        : "Daemon offline")))
    }

    private var projectsSection: some View {
        // Scanning recents is expensive; do it once per render and share the
        // result between the sort and the per-row relative times.
        let activity = projectActivity
        let projects = visibleProjects(activity: activity)
        let now = Date()
        return DashboardSection(title: "Recent Projects") {
            Button("View All") {
                openWorkspace()
            }
            .buttonStyle(.plain)
            .foregroundStyle(.blue)
            .font(.callout)
        } content: {
            if projects.isEmpty {
                CompactEmptyRow(
                    icon: state.workspace.projects.isEmpty ? "folder.badge.plus" : "magnifyingglass",
                    title: state.workspace.projects.isEmpty ? "No projects yet" : "No matching projects",
                    detail: state.workspace.projects.isEmpty
                        ? "Discover a project directory to get started."
                        : "Try a different search or project scope.",
                    actionTitle: state.workspace.projects.isEmpty
                        ? (isDiscovering ? "Discovering…" : "Discover…")
                        : nil,
                    actionDisabled: isDiscovering,
                    action: state.workspace.projects.isEmpty ? chooseDiscoverySource : nil)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(projects.enumerated()), id: \.element.id) { index, project in
                        Button {
                            open(project)
                        } label: {
                            ProjectRow(
                                project: project,
                                detail: projectDetail(project),
                                relativeTime: activity[project.id]?.event
                                    .relativeTime(relativeTo: now),
                                healthy: projectIsHealthy(project))
                        }
                        .buttonStyle(.plain)
                        if index != projects.count - 1 {
                            Divider().padding(.leading, 56)
                        }
                    }
                }
            }
        }
    }

    private var attentionSection: some View {
        DashboardSection(title: "Needs Attention") {
            EmptyView()
        } content: {
            VStack(spacing: 0) {
                ForEach(Array(issues.prefix(2).enumerated()), id: \.element.id) { index, issue in
                    HStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.title3)
                            .foregroundStyle(.orange)
                            .frame(width: 34)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(issue.title)
                                .font(.callout.weight(.medium))
                            if let detail = issue.detail {
                                Text(detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                        Spacer()
                        Button(issue.actionTitle) {
                            handle(issue.action)
                        }
                        .buttonStyle(.bordered)
                    }
                    .padding(.horizontal, 14)
                    .frame(minHeight: 54)
                    if index != min(issues.count, 2) - 1 {
                        Divider().padding(.leading, 60)
                    }
                }
            }
        }
    }

    private var accessSection: some View {
        DashboardSection(title: "Recent Access") {
            if !state.recents.isEmpty {
                Button("View All") {
                    showingAccessLog = true
                }
                .buttonStyle(.plain)
                .foregroundStyle(.blue)
                .font(.callout)
            }
        } content: {
            if visibleAccess.isEmpty {
                if state.accessHistoryLoading {
                    CompactLoadingRow(title: "Loading access history…")
                } else {
                    CompactEmptyRow(
                        icon: state.connected ? "checkmark.shield" : "shield.slash",
                        title: state.connected ? "No recent access" : "Daemon is offline",
                        detail: state.connected
                            ? "Reads and SSH signatures will appear here."
                            : "Reconnect the daemon to receive access events.")
                }
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(visibleAccess.enumerated()), id: \.element.id) { index, group in
                        Button {
                            showingAccessLog = true
                        } label: {
                            AccessSummaryRow(group: group)
                        }
                        .buttonStyle(.plain)
                        if index != visibleAccess.count - 1 {
                            Divider().padding(.leading, 50)
                        }
                    }
                }
            }
        }
    }

    private var librarySection: some View {
        DashboardSection(title: "Library") {
            EmptyView()
        } content: {
            HStack(spacing: 12) {
                Image(systemName: "books.vertical.fill")
                    .font(.title3)
                    .foregroundStyle(.blue)
                    .frame(width: 34, height: 34)
                    .background(Color.blue.opacity(0.09), in: RoundedRectangle(cornerRadius: 8))
                Text(librarySummary)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                Spacer()
                Button {
                    openWorkspace(.library)
                } label: {
                    Text("Open Library")
                }
                .buttonStyle(.bordered)
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 56)
        }
    }

    private var discoveryDropOverlay: some View {
        VStack(spacing: 12) {
            Image(systemName: "sparkle.magnifyingglass")
                .font(.system(size: 34, weight: .medium))
                .foregroundStyle(.blue)
            Text("Drop to Discover")
                .font(.title2.bold())
            Text("Floria will inspect supported configuration files without running project code.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(34)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
        .overlay {
            RoundedRectangle(cornerRadius: 18)
                .stroke(Color.blue, style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
        }
    }

    private var selectedProject: WorkspaceProject? {
        guard let selectedProjectID else { return nil }
        return state.workspace.projects.first { $0.id == selectedProjectID }
    }

    // One pass over recents: the first (most recent) matching event per project.
    // Everything is pre-lowercased so the inner loop is plain string compares —
    // no ICU, no repeated tilde expansion.
    private var projectActivity: [WorkspaceProject.ID: (index: Int, event: RecentAccess)] {
        let projects = state.workspace.projects
        guard !projects.isEmpty else { return [:] }
        let matchers = projects.map {
            ($0.id, ProjectEventMatcher($0, resources: state.workspace.resources))
        }
        var result: [WorkspaceProject.ID: (index: Int, event: RecentAccess)] = [:]
        for (index, event) in state.recents.enumerated() {
            let candidates = ProjectEventMatcher.loweredCandidates(for: event)
            for (id, matcher) in matchers where result[id] == nil {
                if matcher.matchesLowered(candidates, surfaceID: event.ssh?.surface_id) {
                    result[id] = (index, event)
                }
            }
            if result.count == projects.count { break }
        }
        return result
    }

    private func visibleProjects(
        activity: [WorkspaceProject.ID: (index: Int, event: RecentAccess)]
    ) -> [WorkspaceProject] {
        var projects = state.workspace.projects
        if !search.isEmpty {
            projects = projects.filter(projectMatchesSearch)
        }
        projects.sort {
            let lhs = activity[$0.id]?.index ?? Int.max
            let rhs = activity[$1.id]?.index ?? Int.max
            return lhs == rhs
                ? $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
                : lhs < rhs
        }
        return Array(projects.prefix(4))
    }

    private var visibleAccess: [RecentAccessGroup] {
        let matcher = selectedProject.map {
            ProjectEventMatcher($0, resources: state.workspace.resources)
        }
        let recents = state.recents.filter { event in
            (matcher?.matches(event) ?? true)
                && (search.isEmpty || accessMatchesSearch(event))
        }
        return RecentAccessProjection.grouped(recents, maximumGroups: 3)
    }

    private var issues: [DashboardIssue] {
        var result: [DashboardIssue] = []
        if !state.connected {
            result.append(
                DashboardIssue(
                    id: "daemon", title: "Floria daemon is offline",
                    detail: "Some Managed items may be unavailable.",
                    actionTitle: "Retry", action: .reconnectDaemon))
        }
        if let error = state.workspace.lastError {
            result.append(
                DashboardIssue(
                    id: "workspace-error", title: "Library could not refresh",
                    detail: error, actionTitle: "Retry", action: .reload))
        }

        let projects = selectedProject.map { [$0] } ?? state.workspace.projects
        for project in projects {
            let stopped = project.environments.flatMap(\.surfaces).filter {
                $0.managedLink?.needsAttention == true
            }
            if let surface = stopped.first {
                result.append(
                    DashboardIssue(
                        id: "surface:\(surface.id)",
                        title: "\(project.name): \(surface.name) is unavailable",
                        detail: surface.path.map {
                            ($0 as NSString).abbreviatingWithTildeInPath
                        } ?? "Project SSH agent",
                        actionTitle: "Manage", action: .openWorkspace))
            }
        }

        let unlinked = state.workspace.protectedFiles.filter {
            $0.managedLink.needsAttention
        }
        if let file = unlinked.first {
            result.append(
                DashboardIssue(
                    id: "protected:\(file.id)",
                    title: "\(URL(fileURLWithPath: file.path).lastPathComponent) link is missing",
                    detail: (file.path as NSString).abbreviatingWithTildeInPath,
                    actionTitle: "Manage", action: .openWorkspace))
        }
        return result
    }

    private var librarySummary: String {
        let count = state.workspace.managedItemCount
        return count == 0
            ? "No managed items yet"
            : "\(count) managed item\(count == 1 ? "" : "s")"
    }

    private func projectMatchesSearch(_ project: WorkspaceProject) -> Bool {
        let values = [
            project.name, project.path,
            project.environments.map(\.name).joined(separator: " "),
            project.environments.flatMap(\.surfaces).map(\.name).joined(separator: " "),
        ]
        return values.joined(separator: " ").localizedCaseInsensitiveContains(search)
    }

    private func accessMatchesSearch(_ event: RecentAccess) -> Bool {
        [event.exe, event.shownPath, event.path, event.operation]
            .joined(separator: " ")
            .localizedCaseInsensitiveContains(search)
    }


    private func projectDetail(_ project: WorkspaceProject) -> String {
        let environments = project.environments
        let environmentSummary =
            environments.count == 1
                ? environments[0].name
                : environments.isEmpty
                    ? "No environments"
                : "\(environments.count) environments"
        let count = projectManagedItemCount(project)
        return "\(environmentSummary)  ·  \(count) item\(count == 1 ? "" : "s")"
    }

    private func projectManagedItemCount(_ project: WorkspaceProject) -> Int {
        let surfaces = project.environments.flatMap(\.surfaces)
        let surfacePaths = Set(surfaces.compactMap { surface in
            surface.path.map {
                ($0 as NSString).standardizingPath
            }
        })
        let prefix = project.path.hasSuffix("/") ? project.path : project.path + "/"
        let protectedCount = state.workspace.protectedFiles.count { file in
            file.path.hasPrefix(prefix)
                && !surfacePaths.contains((file.path as NSString).standardizingPath)
        }
        let sshAccessCount = state.workspace.resources.count {
            $0.kind == .sshAccess && $0.sshAccess?.projectIDs.contains(project.id) == true
        }
        return surfaces.count + protectedCount + sshAccessCount
    }

    private func projectIsHealthy(_ project: WorkspaceProject) -> Bool {
        let prefix = project.path.hasSuffix("/") ? project.path : project.path + "/"
        return project.environments.flatMap(\.surfaces).allSatisfy {
            $0.managedLink?.isReady ?? true
        }
            && state.workspace.protectedFiles
                .filter { $0.path.hasPrefix(prefix) }
                .allSatisfy { $0.managedLink.isReady }
            && !(state.workspace.checkoutDiscoveries[project.id]?.checkouts.contains {
                $0.needsAttention
            } ?? false)
    }

    private func open(_ project: WorkspaceProject) {
        state.workspace.selectProject(project.id)
        selectedProjectID = project.id
        search = ""
    }

    private func openWorkspace(_ selection: WorkspaceSidebarSelection = .projects) {
        state.workspaceWindowSelection = selection
        state.workspaceWindowToken = UUID()
        openWindow(id: "workspace")
    }

    private func handle(_ action: DashboardIssueAction) {
        switch action {
        case .reconnectDaemon:
            state.recheckMacFuseSetup()
        case .reload:
            reload()
        case .openWorkspace:
            openWorkspace()
        }
    }

    private func reload() {
        Task {
            await state.workspace.reload(reportErrors: true)
            await state.reloadSystemHealth()
            await state.reloadPolicyMode()
        }
    }

    private func presentRequestedSystemHealth() {
        guard state.systemHealthPresentationRequested else { return }
        state.systemHealthPresentationRequested = false
        showingSystemHealth = true
    }

    private func chooseDiscoverySource() {
        let panel = NSOpenPanel()
        panel.title = "Discover with Floria"
        panel.message = "Choose a project directory or a supported configuration file."
        panel.prompt = "Discover"
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = true
        panel.resolvesAliases = true
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        beginDiscovery(at: panel.urls.map(\.path))
    }

    private func beginDiscovery(at paths: [String]) {
        guard !isDiscovering else { return }
        isDiscovering = true
        discovery = DiscoveryPresentation(paths: paths)
    }

}

struct FloriaMark: View {
    var body: some View {
        ZStack {
            ForEach(0..<8, id: \.self) { index in
                Capsule()
                    .fill(
                        LinearGradient(
                            colors: [.blue, Color(red: 0.13, green: 0.69, blue: 1)],
                            startPoint: .bottom,
                            endPoint: .top))
                    .frame(width: 6.5, height: 12)
                    .offset(y: -6)
                    .rotationEffect(.degrees(Double(index) * 45))
            }
            Circle()
                .fill(Color(nsColor: .windowBackgroundColor))
                .frame(width: 4, height: 4)
        }
        .accessibilityHidden(true)
    }
}

private struct DashboardSection<Trailing: View, Content: View>: View {
    let title: String
    @ViewBuilder let trailing: Trailing
    @ViewBuilder let content: Content

    init(
        title: String,
        @ViewBuilder trailing: () -> Trailing,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.trailing = trailing()
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title.uppercased())
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                    .tracking(0.35)
                Spacer()
                trailing
            }
            .padding(.horizontal, 8)

            content
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    Color(nsColor: .controlBackgroundColor),
                    in: RoundedRectangle(cornerRadius: 11))
                .overlay {
                    RoundedRectangle(cornerRadius: 11)
                        .stroke(Color.secondary.opacity(0.14), lineWidth: 1)
                }
                .shadow(color: .black.opacity(0.035), radius: 5, y: 2)
        }
    }
}

private struct ProjectRow: View {
    let project: WorkspaceProject
    let detail: String
    let relativeTime: String?
    let healthy: Bool

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: "folder")
                .font(.system(size: 16, weight: .regular))
                .foregroundStyle(Color.blue.opacity(0.78))
                .frame(width: 30, height: 30)
            Text(project.name)
                .font(.body.weight(.semibold))
                .lineLimit(1)
                .frame(width: 142, alignment: .leading)
            Text(detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer(minLength: 12)
            Text(relativeTime ?? "Not used yet")
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .frame(width: 78, alignment: .leading)
            // Healthy is the default state and stays silent; only problems earn a badge.
            if healthy {
                Color.clear.frame(width: 92, height: 1)
            } else {
                Label("Attention", systemImage: "exclamationmark.circle")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(Color.orange)
                    .frame(width: 92, alignment: .leading)
            }
            Image(systemName: "chevron.right")
                .font(.callout.weight(.medium))
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 52)
        .contentShape(Rectangle())
    }
}

private enum AccessSummaryRowLayout {
    static let countWidth: CGFloat = 58
    static let timeWidth: CGFloat = 72
}

private struct AccessSummaryRow: View {
    let group: RecentAccessGroup
    private var event: RecentAccess { group.latest }

    var body: some View {
        HStack(spacing: 11) {
            Group {
                if let path = event.exePath {
                    Image(nsImage: ExeIcon.lookup(path))
                        .resizable()
                    } else {
                    Image(systemName: "terminal.fill")
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .padding(7)
                    }
            }
            .frame(width: 28, height: 28)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))

            Text(event.exe)
                .font(.callout.weight(.medium))
            Text(event.operation)
                .font(.callout)
                .foregroundStyle(.secondary)
            Text(event.shownPath)
                .font(.callout)
                .foregroundStyle(.blue)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            ZStack(alignment: .trailing) {
                if group.count > 1 {
                    Text("×\(group.count)")
                        .font(.caption.monospacedDigit().weight(.medium))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.tertiary.opacity(0.16), in: Capsule())
                }
            }
            .frame(width: AccessSummaryRowLayout.countWidth, alignment: .trailing)
            RecentAccessTimeText(event: event)
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(width: AccessSummaryRowLayout.timeWidth, alignment: .trailing)
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 44)
        .contentShape(Rectangle())
    }
}

private struct CompactEmptyRow: View {
    let icon: String
    let title: String
    let detail: String
    var actionTitle: String? = nil
    var actionDisabled = false
    var action: (() -> Void)? = nil

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(width: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.callout.weight(.medium))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .controlSize(.small)
                    .disabled(actionDisabled)
            }
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 56)
    }
}

private struct CompactLoadingRow: View {
    let title: String

    var body: some View {
        HStack(spacing: 12) {
            ProgressView()
                .controlSize(.small)
                .frame(width: 34)
            Text(title)
                .font(.callout.weight(.medium))
                .foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 56)
    }
}

private struct CompactProjectDetailView: View {
    @Bindable var state: AppState
    let project: WorkspaceProject
    let search: String
    let recentAccess: [RecentAccessGroup]
    let selectProject: (WorkspaceProject.ID?) -> Void
    let openAdvanced: () -> Void
    @State private var showingWorktrees = false
    @State private var selectedManagedItem: LibraryCatalogItem?

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 20) {
                projectHeader
                managedSection
                projectAccessSection
            }
            .padding(.horizontal, 28)
            .padding(.top, 22)
            .padding(.bottom, 28)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .sheet(isPresented: $showingWorktrees) {
            ProjectCheckoutsSheet(store: state.workspace, projectID: project.id)
        }
        .sheet(item: $selectedManagedItem) { item in
            switch item {
            case .file(let file):
                LibraryItemDetailSheet(
                    store: state.workspace,
                    item: item,
                    configureProtectedFile: file.kind.isConfigurable
                        ? {
                            try await state.workspace.configureManagedFile(
                                file.id, projectID: project.id,
                                environmentID: selectedEnvironment?.id)
                        }
                        : nil)
            case .resource, .surface:
                LibraryItemDetailSheet(store: state.workspace, item: item)
            }
        }
    }

    private var projectHeader: some View {
        HStack(spacing: 12) {
            Image(systemName: "folder")
                .font(.system(size: 20))
                .foregroundStyle(Color.blue.opacity(0.78))
                .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 10) {
                    projectSwitcher
                    environmentMenu
                    if let item = firstManagedLinkIssue {
                        reviewManagedItemButton(item)
                    } else if projectHasWorktreeIssues {
                        reviewWorktreeIssuesButton
                    }
                }
                Text((project.path as NSString).abbreviatingWithTildeInPath)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            HStack(spacing: 8) {
                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([
                        URL(fileURLWithPath: project.path)
                    ])
                } label: {
                    Label {
                        Text("Finder")
                    } icon: {
                        Image(nsImage: ExeIcon.lookup("/System/Library/CoreServices/Finder.app"))
                            .resizable()
                            .frame(width: 16, height: 16)
                    }
                }
                .buttonStyle(.bordered)

                Button {
                    showingWorktrees = true
                } label: {
                    HStack(spacing: 5) {
                        Label("Worktrees", systemImage: "arrow.triangle.branch")
                        if unmanagedWorktreeCount > 0 {
                            Text("\(unmanagedWorktreeCount)")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(Color.white)
                                .padding(.horizontal, 5)
                                .frame(minHeight: 16)
                                .background(Color.orange, in: Capsule())
                        }
                    }
                }
                .buttonStyle(.bordered)
                .accessibilityLabel(
                    unmanagedWorktreeCount == 0
                        ? "Worktrees"
                        : "Worktrees, \(unmanagedWorktreeCount) newly discovered")

                Button(action: openAdvanced) {
                    Label("Project Settings", systemImage: "slider.horizontal.3")
                }
                .buttonStyle(.bordered)
            }
        }
    }

    // macOS flattens a borderless Menu's custom label (icons forced leading,
    // backgrounds dropped), so only the text lives inside the Menu; the
    // switcher chevron is drawn next to it.
    private var projectSwitcher: some View {
        HStack(spacing: 5) {
            Menu {
                Button("All Projects") { selectProject(nil) }
                if !state.workspace.projects.isEmpty {
                    Divider()
                    ForEach(state.workspace.projects) { candidate in
                        Button {
                            selectProject(candidate.id)
                        } label: {
                            if candidate.id == project.id {
                                Label(candidate.name, systemImage: "checkmark")
                            } else {
                                Text(candidate.name)
                            }
                        }
                    }
                }
            } label: {
                Text(project.name)
                    .font(.title2.bold())
                    .foregroundStyle(.primary)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()

            Image(systemName: "chevron.up.chevron.down")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.tertiary)
                .padding(.top, 3)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Project")
        .accessibilityValue(project.name)
    }

    private var environmentMenu: some View {
        HStack(spacing: 5) {
            Menu {
                ForEach(project.environments) { environment in
                    Button {
                        state.workspace.selectEnvironment(environment.id)
                    } label: {
                        if environment.id == selectedEnvironment?.id {
                            Label(environment.name, systemImage: "checkmark")
                        } else {
                            Text(environment.name)
                        }
                    }
                }
            } label: {
                Text(selectedEnvironment?.name ?? "No environment")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .disabled(project.environments.isEmpty)

            Image(systemName: "chevron.down")
                .font(.system(size: 8, weight: .semibold))
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 9)
        .frame(height: 22)
        .background(Color.secondary.opacity(0.09), in: Capsule())
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Environment")
        .accessibilityValue(selectedEnvironment?.name ?? "No environment")
    }

    private var managedSection: some View {
        DashboardSection(title: "Managed") {
            Text("\(managedItems.count)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        } content: {
            if filteredManagedItems.isEmpty {
                CompactEmptyRow(
                    icon: search.isEmpty ? "folder.badge.plus" : "magnifyingglass",
                    title: search.isEmpty
                        ? "Nothing managed in this project"
                        : "No matching managed items",
                    detail: search.isEmpty
                        ? "Use Discover to protect an existing file, or Project Settings to add one."
                        : "Try a different search.")
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(filteredManagedItems.enumerated()), id: \.element.id) {
                        index, item in
                        CompactManagedItemRow(
                            state: state,
                            item: item,
                            bindings: item.surface.map { bindings(for: $0) } ?? [],
                            projectPath: project.path,
                            showDetails: {
                                selectedManagedItem = item.libraryItem
                            })
                        if index != filteredManagedItems.count - 1 {
                            Divider().padding(.leading, 58)
                        }
                    }
                }
            }
        }
    }

    private var projectAccessSection: some View {
        DashboardSection(title: "Recent Access") {
            EmptyView()
        } content: {
            if recentAccess.isEmpty {
                if state.accessHistoryLoading {
                    CompactLoadingRow(title: "Loading project access…")
                } else {
                    CompactEmptyRow(
                        icon: "clock",
                        title: "No recent access for this project",
                        detail: "Reads and SSH signatures will appear here.")
                }
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(recentAccess.enumerated()), id: \.element.id) { index, group in
                        AccessSummaryRow(group: group)
                        if index != recentAccess.count - 1 {
                            Divider().padding(.leading, 50)
                        }
                    }
                }
            }
        }
    }

    private var selectedEnvironment: WorkspaceEnvironment? {
        project.environments.first { $0.id == state.workspace.selectedEnvironmentID }
            ?? project.environments.first
    }

    private var surfaces: [WorkspaceSurface] {
        selectedEnvironment?.surfaces ?? []
    }

    private func bindings(for surface: WorkspaceSurface) -> [WorkspaceBinding] {
        let activeBindings = project.commonBindings + (selectedEnvironment?.bindings ?? [])
        return surface.bindingIDs.compactMap { id in
            activeBindings.first { $0.id == id }
        }
    }

    private var projectProtectedFiles: [WorkspaceProtectedFile] {
        let prefix = project.path.hasSuffix("/") ? project.path : project.path + "/"
        return state.workspace.protectedFiles.filter { $0.path.hasPrefix(prefix) }
    }

    private var managedItems: [CompactManagedItem] {
        let surfacePaths = Set(surfaces.compactMap { surface in
            surface.path.map { ($0 as NSString).standardizingPath }
        })
        let items =
            surfaces.map(CompactManagedItem.surface)
            + state.workspace.resources
                .filter { $0.kind == .sshAccess && $0.sshAccess?.projectIDs.contains(project.id) == true }
                .map(CompactManagedItem.resource)
            + projectProtectedFiles
                .filter {
                    !surfacePaths.contains(($0.path as NSString).standardizingPath)
                }
                .map(CompactManagedItem.file)
        return items.sorted {
            $0.sortName.localizedStandardCompare($1.sortName) == .orderedAscending
        }
    }

    private var allProjectManagedItems: [CompactManagedItem] {
        let allSurfaces = project.environments.flatMap(\.surfaces)
        let surfacePaths = Set(allSurfaces.compactMap { surface in
            surface.path.map { ($0 as NSString).standardizingPath }
        })
        return (
            allSurfaces.map(CompactManagedItem.surface)
                + state.workspace.resources
                    .filter { $0.kind == .sshAccess && $0.sshAccess?.projectIDs.contains(project.id) == true }
                    .map(CompactManagedItem.resource)
                + projectProtectedFiles
                    .filter {
                        !surfacePaths.contains(($0.path as NSString).standardizingPath)
                    }
                    .map(CompactManagedItem.file)
        ).sorted {
            $0.sortName.localizedStandardCompare($1.sortName) == .orderedAscending
        }
    }

    private var filteredManagedItems: [CompactManagedItem] {
        guard !search.isEmpty else { return managedItems }
        return managedItems.filter { item in
            item.searchText(state: state, bindings: bindings)
                .localizedCaseInsensitiveContains(search)
        }
    }

    private var firstManagedLinkIssue: CompactManagedItem? {
        allProjectManagedItems.first { $0.managedLink?.needsAttention == true }
    }

    private func reviewManagedItemButton(_ item: CompactManagedItem) -> some View {
        Button {
            selectedManagedItem = item.libraryItem
        } label: {
            Label("Needs attention", systemImage: "exclamationmark.circle.fill")
                .font(.callout.weight(.medium))
                .foregroundStyle(Color.orange)
        }
        .buttonStyle(.borderless)
        .help("Review \(item.title)")
        .accessibilityHint("Open managed item details")
    }

    private var projectHasWorktreeIssues: Bool {
        state.workspace.checkoutDiscoveries[project.id]?.checkouts.contains {
            $0.needsAttention
        } ?? false
    }

    private var reviewWorktreeIssuesButton: some View {
        Button {
            showingWorktrees = true
        } label: {
            Label("Needs attention", systemImage: "exclamationmark.circle.fill")
                .font(.callout.weight(.medium))
                .foregroundStyle(Color.orange)
        }
        .buttonStyle(.borderless)
        .help("Review worktree files that Floria could not link")
        .accessibilityHint("Open Project Worktrees")
    }

    private var unmanagedWorktreeCount: Int {
        state.workspace.unmanagedCheckoutCount(projectID: project.id)
    }

}

private enum CompactManagedItem: Identifiable {
    case surface(WorkspaceSurface)
    case file(WorkspaceProtectedFile)
    case resource(WorkspaceResource)

    var id: String {
        switch self {
        case .surface(let surface): "surface:\(surface.id)"
        case .file(let file): "file:\(file.id)"
        case .resource(let resource): "resource:\(resource.id)"
        }
    }

    var path: String? {
        switch self {
        case .surface(let surface): surface.path
        case .file(let file): file.path
        case .resource: nil
        }
    }

    var managedLink: WorkspaceManagedLink? {
        switch self {
        case .surface(let surface): surface.managedLink
        case .file(let file): file.managedLink
        case .resource: nil
        }
    }

    var title: String {
        switch self {
        case .surface(let surface):
            surface.path.map { URL(fileURLWithPath: $0).lastPathComponent }
                ?? surface.displayName
        case .file(let file): URL(fileURLWithPath: file.path).lastPathComponent
        case .resource(let resource): resource.name
        }
    }

    var sortName: String { path ?? title }

    var surface: WorkspaceSurface? {
        guard case .surface(let surface) = self else { return nil }
        return surface
    }

    var kindTitle: String {
        switch self {
        case .surface(let surface): CompactManagedKindPresentation(surface: surface).title
        case .file(let file): file.kind.title
        case .resource(let resource): resource.kind.title
        }
    }

    var systemImage: String {
        switch self {
        case .surface(let surface): CompactManagedKindPresentation(surface: surface).systemImage
        case .file(let file): file.kind.systemImage
        case .resource(let resource): resource.kind.systemImage
        }
    }

    var securityLevel: WorkspaceSecurityLevel {
        switch self {
        case .surface(let surface): surface.securityLevel
        case .file(let file): file.securityLevel
        case .resource(let resource): resource.securityLevel
        }
    }

    var libraryItem: LibraryCatalogItem {
        switch self {
        case .surface(let surface): .surface(surface)
        case .file(let file): .file(file)
        case .resource(let resource): .resource(resource)
        }
    }

    var detail: String? {
        guard case .resource(let resource) = self else { return nil }
        return resource.sshAccess?.route.hostPatterns.joined(separator: " · ")
    }

    @MainActor
    func searchText(
        state: AppState,
        bindings: (WorkspaceSurface) -> [WorkspaceBinding]
    ) -> String {
        switch self {
        case .surface(let surface):
            let resources = bindings(surface).compactMap {
                state.workspace.resource($0.resourceID)
            }
            return (
                [
                    surface.displayName, surface.name, surface.path,
                    surface.kind.managedTitle, surface.securityLevel.title,
                ]
                    .compactMap { $0 }
                + resources.flatMap { [$0.name, $0.kind.title, $0.exportSummary] }
            ).joined(separator: " ")
        case .file(let file):
            return [file.path, file.kind.title, file.securityLevel.title]
                .joined(separator: " ")
        case .resource(let resource):
            return [resource.name, resource.kind.title, resource.exportSummary]
                .joined(separator: " ")
        }
    }
}

private struct ProjectCheckoutsSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: WorkspaceStore
    let projectID: WorkspaceProject.ID

    @State private var discovery: ProjectCheckoutDiscovery?
    @State private var environmentSelections: [String: WorkspaceEnvironment.ID] = [:]
    @State private var isDiscovering = false
    @State private var busyPath: String?
    @State private var errorMessage: String?
    @State private var expandedIssuePaths: Set<String> = []

    private var project: WorkspaceProject? {
        store.projects.first { $0.id == projectID }
    }

    private var sheetHeight: CGFloat {
        let rowCount = discovery?.checkouts.count ?? 1
        return min(580, max(300, CGFloat(rowCount * 62 + 240)))
    }

    // "" tags the manual mode; Picker tags must be non-optional.
    private var defaultEnvironmentSelection: Binding<String> {
        Binding(
            get: { project?.defaultEnvironmentID ?? "" },
            set: { newValue in
                let environmentID = newValue.isEmpty ? nil : newValue
                guard environmentID != project?.defaultEnvironmentID else { return }
                Task {
                    do {
                        try await store.setProjectDefaultEnvironment(
                            projectID: projectID, environmentID: environmentID)
                    } catch {
                        errorMessage = error.localizedDescription
                    }
                }
            })
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
            Divider()
            footer
        }
        .frame(width: 680, height: sheetHeight)
        .task {
            await discover()
        }
        .onChange(of: store.checkoutDiscoveries[projectID]) { _, discovery in
            guard let discovery else { return }
            apply(discovery)
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: "arrow.triangle.branch")
                .font(.system(size: 22, weight: .medium))
                .foregroundStyle(Color.accentColor)
                .frame(width: 42, height: 42)
                .background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
            VStack(alignment: .leading, spacing: 3) {
                Text("Project Worktrees")
                    .font(.title2.bold())
                Text("Expose one project environment in each Git checkout.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    Text("New worktrees")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Picker("New worktrees", selection: defaultEnvironmentSelection) {
                        Text("No Default").tag("")
                        ForEach(project?.environments ?? []) { environment in
                            Text(environment.name).tag(environment.id)
                        }
                    }
                    .labelsHidden()
                    .controlSize(.small)
                    .fixedSize()
                }
                .padding(.top, 5)
            }
            Spacer()
            Button {
                Task { await discover() }
            } label: {
                Label("Discover", systemImage: "arrow.clockwise")
            }
            .disabled(isDiscovering || busyPath != nil)
        }
        .padding(22)
    }

    @ViewBuilder
    private var content: some View {
        if isDiscovering && discovery == nil {
            VStack(spacing: 10) {
                ProgressView()
                Text("Discovering Git worktrees…")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let discovery, !discovery.checkouts.isEmpty {
            ScrollView {
                LazyVStack(spacing: 18) {
                    if let errorMessage {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(Color.orange)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                            .background(
                                Color.orange.opacity(0.08),
                                in: RoundedRectangle(cornerRadius: 8))
                    }
                    checkoutGroup(
                        title: "Managed",
                        candidates: enabledCheckouts(in: discovery),
                        commonDir: discovery.commonDir)
                    if !notManagedCheckouts(in: discovery).isEmpty {
                        checkoutGroup(
                            title: "Other Worktrees",
                            candidates: notManagedCheckouts(in: discovery),
                            commonDir: discovery.commonDir)
                    }
                }
                .padding(22)
            }
        } else {
            VStack(spacing: 12) {
                Image(systemName: "folder.badge.questionmark")
                    .font(.system(size: 30))
                    .foregroundStyle(.secondary)
                Text("No Git worktrees found")
                    .font(.headline)
                Text(errorMessage ?? "This project does not appear to be a Git checkout.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 440)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func enabledCheckouts(
        in discovery: ProjectCheckoutDiscovery
    ) -> [ProjectCheckoutCandidate] {
        sortedCheckouts(
            discovery.checkouts.filter {
                $0.gitPrimary || $0.managedCheckoutID != nil
            })
    }

    private func notManagedCheckouts(
        in discovery: ProjectCheckoutDiscovery
    ) -> [ProjectCheckoutCandidate] {
        sortedCheckouts(
            discovery.checkouts.filter {
                !$0.gitPrimary && $0.managedCheckoutID == nil
            })
    }

    private func sortedCheckouts(
        _ candidates: [ProjectCheckoutCandidate]
    ) -> [ProjectCheckoutCandidate] {
        candidates.sorted { left, right in
            if left.gitPrimary != right.gitPrimary {
                return left.gitPrimary
            }
            return left.path.localizedStandardCompare(right.path) == .orderedAscending
        }
    }

    private func checkoutGroup(
        title: String, candidates: [ProjectCheckoutCandidate], commonDir: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title.uppercased())
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(candidates.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 4)

            VStack(spacing: 0) {
                ForEach(Array(candidates.enumerated()), id: \.element.id) { index, candidate in
                    checkoutRow(candidate, commonDir: commonDir)
                    if index != candidates.count - 1 {
                        Divider().padding(.leading, 58)
                    }
                }
            }
            .background(Color(nsColor: .controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .overlay {
                RoundedRectangle(cornerRadius: 12)
                    .stroke(Color.secondary.opacity(0.16), lineWidth: 1)
            }
        }
    }

    private func checkoutRow(
        _ candidate: ProjectCheckoutCandidate, commonDir: String
    ) -> some View {
        let managed = candidate.managedCheckoutID.flatMap { id in
            store.checkouts.first { $0.id == id }
        }
        let selection = Binding<WorkspaceEnvironment.ID>(
            get: {
                environmentSelections[candidate.path] ?? managed?.environmentID ?? ""
            },
            set: { environmentID in
                let currentEnvironmentID = managed?.environmentID ?? ""
                guard environmentID != currentEnvironmentID else { return }
                environmentSelections[candidate.path] = environmentID
                Task {
                    await setEnvironment(
                        environmentID, for: candidate, commonDir: commonDir,
                        managedCheckout: managed)
                }
            })

        return VStack(spacing: 0) {
            HStack(spacing: 14) {
                Image(systemName: candidate.gitPrimary ? "folder" : "arrow.triangle.branch")
                    .font(.system(size: 19))
                    .foregroundStyle(
                        candidate.gitPrimary ? Color.accentColor : Color.blue.opacity(0.78))
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 7) {
                        Text(displayName(for: candidate.path))
                            .font(.callout.weight(.semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        if candidate.gitPrimary {
                            checkoutBadge("Primary", color: .secondary)
                        }
                    }
                    Text((candidate.path as NSString).abbreviatingWithTildeInPath)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if candidate.needsAttention {
                        Button {
                            toggleWorktreeIssueDetails(for: candidate.path)
                        } label: {
                            HStack(spacing: 5) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                Text(
                                    "\(candidate.linkIssues.count) file\(candidate.linkIssues.count == 1 ? "" : "s") need\(candidate.linkIssues.count == 1 ? "s" : "") attention"
                                )
                                Image(
                                    systemName: expandedIssuePaths.contains(candidate.path)
                                        ? "chevron.down" : "chevron.right"
                                )
                                .font(.caption2.weight(.semibold))
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .font(.caption)
                        .foregroundStyle(Color.orange)
                        .accessibilityHint("Show affected files")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .layoutPriority(1)

                if candidate.gitPrimary {
                    Text(primaryEnvironmentTitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .frame(width: 160, alignment: .leading)
                } else {
                    Picker("Environment", selection: selection) {
                        Text("No Environment").tag("")
                        ForEach(project?.environments ?? []) { environment in
                            Text(environment.name).tag(environment.id)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 160)
                    .disabled(busyPath != nil)
                }

                Button {
                    NSWorkspace.shared.open(URL(fileURLWithPath: candidate.path))
                } label: {
                    Image(systemName: "folder")
                }
                .buttonStyle(.borderless)
                .help("Open in Finder")
                .frame(width: 24)

                Group {
                    if busyPath == candidate.path {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Color.clear
                    }
                }
                .frame(width: 16, height: 16)
            }
            .padding(.horizontal, 16)
            .frame(minHeight: 62)

            if candidate.needsAttention && expandedIssuePaths.contains(candidate.path) {
                worktreeIssueDetails(candidate)
            }
        }
    }

    private func worktreeIssueDetails(
        _ candidate: ProjectCheckoutCandidate
    ) -> some View {
        VStack(spacing: 0) {
            ForEach(Array(candidate.linkIssues.enumerated()), id: \.element) { index, path in
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.circle")
                        .foregroundStyle(Color.orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(worktreeIssuePath(path, relativeTo: candidate.path))
                            .font(.caption.monospaced())
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text("Doesn’t point to Floria")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if busyPath == candidate.path {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Button("Repair Link", systemImage: "wrench.and.screwdriver") {
                            Task { await repairManagedLink(path, candidate: candidate) }
                        }
                        .controlSize(.small)
                        Button("Show in Finder", systemImage: "folder") {
                            revealWorktreeIssue(path)
                        }
                        .buttonStyle(.borderless)
                        .controlSize(.small)
                        .foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 44)
                if index != candidate.linkIssues.count - 1 {
                    Divider()
                }
            }
        }
        .background(Color.orange.opacity(0.055))
        .padding(.leading, 64)
        .padding(.trailing, 16)
        .padding(.bottom, 10)
    }

    @MainActor
    private func repairManagedLink(
        _ path: String, candidate: ProjectCheckoutCandidate
    ) async {
        busyPath = candidate.path
        errorMessage = nil
        defer { busyPath = nil }
        do {
            try await store.repairManagedLink(at: path)
            await discover()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func toggleWorktreeIssueDetails(for path: String) {
        if expandedIssuePaths.contains(path) {
            expandedIssuePaths.remove(path)
        } else {
            expandedIssuePaths.insert(path)
        }
    }

    private func worktreeIssuePath(_ path: String, relativeTo checkoutPath: String) -> String {
        let prefix = checkoutPath.hasSuffix("/") ? checkoutPath : checkoutPath + "/"
        if path.hasPrefix(prefix) {
            return String(path.dropFirst(prefix.count))
        }
        return (path as NSString).abbreviatingWithTildeInPath
    }

    private func revealWorktreeIssue(_ path: String) {
        let url = URL(fileURLWithPath: path)
        if FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.activateFileViewerSelecting([url])
            return
        }

        var parent = url.deletingLastPathComponent()
        while parent.path != "/"
            && !FileManager.default.fileExists(atPath: parent.path)
        {
            parent.deleteLastPathComponent()
        }
        NSWorkspace.shared.open(parent)
    }

    private var footer: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "checkmark.shield")
                .foregroundStyle(.green)
            Text("Managed worktrees receive this project's files. Existing local changes are never replaced.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 16)
    }

    private func checkoutBadge(_ title: String, color: Color) -> some View {
        Text(title)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.1), in: Capsule())
    }

    private func displayName(for path: String) -> String {
        let name = (path as NSString).lastPathComponent
        return name.isEmpty ? path : name
    }

    private var primaryEnvironmentTitle: String {
        let environments = project?.environments ?? []
        if environments.count == 1 {
            return environments[0].name
        }
        return environments.isEmpty ? "No Environment" : "All Environments"
    }

    @MainActor
    private func discover() async {
        isDiscovering = true
        errorMessage = nil
        defer { isDiscovering = false }
        do {
            let result = try await store.discoverProjectCheckouts(projectID: projectID)
            apply(result)
        } catch {
            discovery = nil
            errorMessage = error.localizedDescription
        }
    }

    private func apply(_ result: ProjectCheckoutDiscovery) {
        discovery = result
        var selections: [String: WorkspaceEnvironment.ID] = [:]
        for candidate in result.checkouts {
            guard let id = candidate.managedCheckoutID,
                let environmentID = store.checkouts.first(where: { $0.id == id })?.environmentID
            else { continue }
            selections[candidate.path] = environmentID
        }
        environmentSelections = selections
    }

    @MainActor
    private func setEnvironment(
        _ environmentID: WorkspaceEnvironment.ID,
        for candidate: ProjectCheckoutCandidate,
        commonDir: String,
        managedCheckout: CatalogProjectCheckout?
    ) async {
        if environmentID.isEmpty {
            guard let managedCheckout else { return }
            await remove(managedCheckout)
        } else {
            await provision(
                candidate, commonDir: commonDir,
                environmentID: environmentID, checkoutID: managedCheckout?.id)
        }
    }

    @MainActor
    private func provision(
        _ candidate: ProjectCheckoutCandidate, commonDir: String,
        environmentID: WorkspaceEnvironment.ID, checkoutID: String?
    ) async {
        busyPath = candidate.path
        errorMessage = nil
        defer { busyPath = nil }
        do {
            try await store.provisionProjectCheckout(
                projectID: projectID, path: candidate.path,
                environmentID: environmentID, commonDir: commonDir,
                checkoutID: checkoutID)
            await discover()
        } catch {
            errorMessage = error.localizedDescription
            if let discovery {
                apply(discovery)
            }
        }
    }

    @MainActor
    private func remove(_ checkout: CatalogProjectCheckout) async {
        busyPath = checkout.path
        errorMessage = nil
        defer { busyPath = nil }
        do {
            try await store.removeProjectCheckout(checkout.id)
            environmentSelections.removeValue(forKey: checkout.path)
            await discover()
        } catch {
            errorMessage = error.localizedDescription
            if let discovery {
                apply(discovery)
            }
        }
    }
}

private struct CompactManagedItemRow: View {
    @Bindable var state: AppState
    let item: CompactManagedItem
    let bindings: [WorkspaceBinding]
    let projectPath: String
    let showDetails: () -> Void
    @State private var repairError: String?
    @State private var isRepairing = false

    private var needsAttention: Bool {
        item.managedLink?.needsAttention == true
            || (!bindings.isEmpty && bindings.allSatisfy { !$0.isEnabled })
    }

    var body: some View {
        HStack(spacing: 12) {
            Button(action: showDetails) {
                HStack(spacing: 12) {
                    Image(systemName: item.systemImage)
                        .font(.system(size: 15, weight: .medium))
                        .foregroundStyle(Color.blue.opacity(0.76))
                        .frame(width: 32, height: 32)
                        .background(
                            Color.blue.opacity(0.07),
                            in: RoundedRectangle(cornerRadius: 7))

                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.title)
                            .font(.callout.weight(.semibold))
                            .lineLimit(1)
                        CompactManagedItemSubtitle(
                            kind: item.kindTitle,
                            path: item.path.map {
                                compactManagedPath($0, projectPath: projectPath)
                            } ?? item.detail,
                            needsAttention: needsAttention)
                    }

                    Spacer(minLength: 12)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .frame(maxWidth: .infinity)
            .accessibilityHint("Open details")

            CompactSecurityLevelMenu(state: state, level: item.securityLevel) { level in
                try await updateSecurity(level)
            }

            Menu {
                Button("Details…", systemImage: "info.circle") {
                    showDetails()
                }
                if item.managedLink?.needsAttention == true {
                    Button("Repair Link", systemImage: "wrench.and.screwdriver") {
                        repairManagedLink()
                    }
                    .disabled(isRepairing)
                }
                if let path = item.path {
                    Divider()
                    Button("Reveal in Finder", systemImage: "folder") {
                        NSWorkspace.shared.activateFileViewerSelecting([
                            URL(fileURLWithPath: path)
                        ])
                    }
                    Button("Copy Path", systemImage: "doc.on.doc") {
                        copyManagedPath(path)
                    }
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 26, height: 26)
                    .contentShape(Rectangle())
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .accessibilityLabel("\(item.title) actions")
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 54)
        .alert(
            "Could not repair link",
            isPresented: Binding(
                get: { repairError != nil },
                set: { if !$0 { repairError = nil } })
        ) {
            Button("OK") { repairError = nil }
        } message: {
            Text(repairError ?? "Unknown error")
        }
    }

    private func updateSecurity(_ level: WorkspaceSecurityLevel) async throws {
        switch item {
        case .surface(let surface):
            try await state.workspace.updateSurfaceSecurityLevel(
                surface.id, securityLevel: level)
        case .file(let file):
            try await state.workspace.updateProtectedFileMetadata(
                file.id, securityLevel: level, metadata: file.metadata)
        case .resource(let resource):
            try await state.workspace.updateResourceMetadata(
                resource.id, name: resource.name,
                securityLevel: level, metadata: resource.metadata)
        }
    }

    private func repairManagedLink() {
        guard let path = item.path else { return }
        Task {
            isRepairing = true
            defer { isRepairing = false }
            do {
                try await state.workspace.repairManagedLink(at: path)
            } catch {
                repairError = error.localizedDescription
            }
        }
    }
}

private struct CompactManagedItemSubtitle: View {
    let kind: String
    let path: String?
    let needsAttention: Bool

    var body: some View {
        HStack(spacing: 5) {
            if needsAttention {
                Image(systemName: "exclamationmark.triangle.fill")
                Text("Needs attention")
                    .fontWeight(.medium)
                Text("·")
            }
            Text(kind)
                .fixedSize()
            if let path {
                Text("·")
                Text(path)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .font(.caption)
        .foregroundStyle(needsAttention ? Color.orange : Color.secondary)
    }
}

private struct CompactManagedKindPresentation {
    let title: String
    let systemImage: String

    init(surface: WorkspaceSurface) {
        guard let path = surface.path else {
            title = surface.kind.managedTitle
            systemImage = surface.kind.systemImage
            return
        }
        let recognized = WorkspaceProtectedFileKind.infer(from: path)
        switch recognized {
        case .dotenv, .direnv, .pgpass, .awsCredentials:
            title = recognized.title
            systemImage = recognized.systemImage
        case .file:
            title = surface.kind.managedTitle
            systemImage = surface.kind.systemImage
        }
    }
}

private struct CompactSecurityLevelMenu: View {
    @Bindable var state: AppState
    let level: WorkspaceSecurityLevel
    let update: (WorkspaceSecurityLevel) async throws -> Void

    var body: some View {
        Menu {
            ForEach(WorkspaceSecurityLevel.allCases, id: \.self) { candidate in
                Button {
                    Task {
                        do {
                            try await update(candidate)
                        } catch {
                            state.workspace.lastError = error.localizedDescription
                        }
                    }
                } label: {
                    if candidate == level {
                        Label(candidate.title, systemImage: "checkmark")
                    } else {
                        Label(candidate.title, systemImage: candidate.systemImage)
                    }
                }
            }
        } label: {
            Label(level.compactTitle, systemImage: level.systemImage)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .frame(width: 108, alignment: .leading)
    }
}

private func compactManagedPath(_ path: String, projectPath: String) -> String {
    let standardizedPath = (path as NSString).standardizingPath
    let standardizedProject = (projectPath as NSString).standardizingPath
    let prefix = standardizedProject.hasSuffix("/") ? standardizedProject : standardizedProject + "/"
    if standardizedPath.hasPrefix(prefix) {
        return String(standardizedPath.dropFirst(prefix.count))
    }
    return (standardizedPath as NSString).abbreviatingWithTildeInPath
}

private func copyManagedPath(_ path: String) {
    let pasteboard = NSPasteboard.general
    pasteboard.clearContents()
    pasteboard.setString(path, forType: .string)
}

private struct DiscoveryProjectGroup: Identifiable {
    let id: String
    let project: DiscoveredProject?
    let files: [DiscoveredFile]
    let managedItems: [DiscoveryManagedItem]
    let needsReview: Bool
}

private struct DiscoveryProjectHeader: View {
    let group: DiscoveryProjectGroup
    @Binding var identity: DiscoveryProjectIdentityChoice?

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: group.needsReview ? "questionmark.folder" : "folder")
                .foregroundStyle(group.needsReview ? Color.orange : Color.blue)
            VStack(alignment: .leading, spacing: 1) {
                Text(group.project?.name ?? (group.needsReview ? "Choose Project" : "Other Files"))
                    .font(.callout.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            let itemCount = group.files.count + group.managedItems.count
            Text("\(itemCount) item\(itemCount == 1 ? "" : "s")")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let project = group.project,
               project.managedProjectID == nil,
               !project.projectMatches.isEmpty
            {
                Menu {
                    Section("Projects from iCloud") {
                        ForEach(project.projectMatches) { match in
                            Button {
                                identity = .existing(match.projectID)
                            } label: {
                                if identity == .existing(match.projectID) {
                                    Label(match.projectName, systemImage: "checkmark")
                                } else {
                                    Text(match.projectName)
                                }
                            }
                        }
                    }
                    Divider()
                    Button("Create New Project") {
                        identity = .createNew
                    }
                } label: {
                    Label(identityTitle(for: project), systemImage: identityIcon)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(identity == nil ? Color.orange : Color.secondary)
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Choose whether this folder belongs to an existing synced Project.")
            }
        }
        .padding(.horizontal, 2)
    }

    private var identityIcon: String {
        switch identity {
        case .existing: "checkmark.icloud"
        case .createNew: "plus"
        case nil: "questionmark.folder"
        }
    }

    private func identityTitle(for project: DiscoveredProject) -> String {
        switch identity {
        case .existing(let projectID):
            project.projectMatches
                .first(where: { $0.projectID == projectID })?
                .projectName ?? "Existing Project"
        case .createNew:
            "New Project"
        case nil:
            "Choose Project"
        }
    }

    private var detail: String {
        guard let project = group.project else {
            return group.needsReview
                ? "Choose a project for each selected file."
                : "Files not assigned to a project."
        }
        let ecosystems = project.ecosystems.joined(separator: " · ")
        return ecosystems.isEmpty ? project.path : "\(project.path) · \(ecosystems)"
    }
}

private struct DiscoveryImportPreviewBanner: View {
    let preview: DiscoveryImportPreview
    let unresolvedAssignments: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Label {
                Text(
                    preview.hasConflicts
                        ? "\(preview.conflicts.count) file conflict\(preview.conflicts.count == 1 ? "" : "s")"
                        : (unresolvedAssignments > 0
                            ? "Choose \(unresolvedAssignments) destination\(unresolvedAssignments == 1 ? "" : "s")"
                            : "Ready to protect"))
                    .font(.callout.weight(.semibold))
            } icon: {
                Image(
                    systemName: preview.hasConflicts
                        ? "exclamationmark.triangle.fill"
                        : (unresolvedAssignments > 0
                            ? "questionmark.folder.fill"
                            : "checkmark.circle.fill"))
            }
            .foregroundStyle(needsAttention ? Color.orange : Color.green)

            if preview.hasConflicts {
                ForEach(preview.conflicts.prefix(3)) { conflict in
                    Text(conflict.message)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                if preview.conflicts.count > 3 {
                    Text("And \(preview.conflicts.count - 3) more…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text(
                    "Choose Library, remove the conflicting project, or move the existing file before continuing."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            } else if unresolvedAssignments > 0 {
                Text("Choose a project for every selected file.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            (needsAttention ? Color.orange : Color.green).opacity(0.07),
            in: RoundedRectangle(cornerRadius: 10))
    }

    private var needsAttention: Bool {
        preview.hasConflicts || unresolvedAssignments > 0
    }
}

private struct DiscoveryWorkflowSheet: View {
    @Environment(\.dismiss) private var dismiss
    let paths: [String]
    @Bindable var store: WorkspaceStore
    let openProject: (String) -> Void
    @State private var job: DiscoveryJobStatus?
    @State private var errorMessage: String?
    @State private var isCancelling = false

    var body: some View {
        Group {
            if let plan = job?.plan {
                DiscoveryReviewSheet(
                    plan: plan,
                    apply: {
                        imports, separateEntries, promoteEntries, demoteEntries in
                        try await store.applyDiscovery(
                            at: plan.paths,
                            imports: imports,
                            separateEntries: separateEntries,
                            promoteEntries: promoteEntries,
                            demoteEntries: demoteEntries)
                    },
                    openProject: openProject)
            } else {
                progressView
            }
        }
        .task {
            await runDiscovery()
        }
        .interactiveDismissDisabled(isActive)
        .onDisappear {
            guard let job, !job.state.isTerminal else { return }
            Task {
                _ = try? await store.cancelDiscovery(id: job.id)
            }
        }
    }

    private var progressView: some View {
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                Image(systemName: "sparkle.magnifyingglass")
                    .font(.title2)
                    .foregroundStyle(.blue)
                    .frame(width: 42, height: 42)
                    .background(Color.blue.opacity(0.10), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 2) {
                    Text("Discovering Workspace")
                        .font(.title2.bold())
                    Text(scopeTitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
            }
            .padding(22)
            Divider()

            VStack(alignment: .leading, spacing: 20) {
                if let errorMessage {
                    Label {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Discovery could not finish")
                                .font(.headline)
                            Text(errorMessage)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                } else if job?.state == .cancelled {
                    Label("Discovery cancelled", systemImage: "xmark.circle")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                } else {
                    HStack(spacing: 12) {
                        ProgressView()
                            .controlSize(.small)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(phaseTitle)
                                .font(.headline)
                            Text(phaseDetail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                }

                HStack(spacing: 10) {
                    SummaryMetric(
                        value: progress.directoriesScanned,
                        label: "Directory visits")
                    SummaryMetric(
                        value: progress.projectCandidates,
                        label: "Projects")
                    SummaryMetric(
                        value: progress.candidateFiles,
                        label: "Candidates")
                    SummaryMetric(
                        value: progress.filesParsed,
                        label: "Read")
                }

                Text("Floria reads candidate files as data. It never executes project code.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(22)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            Divider()
            HStack {
                Text(statusNote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if isActive {
                    Button(isCancelling ? "Cancelling…" : "Cancel") {
                        cancelDiscovery()
                    }
                    .disabled(job == nil || isCancelling)
                } else {
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(.horizontal, 22)
            .frame(height: 58)
        }
        .frame(width: 640, height: 390)
    }

    private var progress: DiscoveryJobProgress {
        job?.progress
            ?? DiscoveryJobProgress(
                phase: .starting,
                directoriesScanned: 0,
                candidateFiles: 0,
                projectCandidates: 0,
                filesParsed: 0)
    }

    private var isActive: Bool {
        guard errorMessage == nil else { return false }
        guard let job else { return true }
        return !job.state.isTerminal
    }

    private var scopeTitle: String {
        if paths.count == 1 {
            return (paths[0] as NSString).abbreviatingWithTildeInPath
        }
        return "\(paths.count) selected locations"
    }

    private var phaseTitle: String {
        if isCancelling || job?.state == .cancelling {
            return "Stopping discovery…"
        }
        switch progress.phase {
        case .starting:
            return "Preparing discovery…"
        case .projectCandidates:
            return "Finding projects…"
        case .candidateFiles:
            return "Finding configuration files…"
        case .parsingFiles:
            return "Reading candidates…"
        case .reconciling:
            return "Comparing with Library…"
        case .complete:
            return "Preparing review…"
        }
    }

    private var phaseDetail: String {
        switch progress.phase {
        case .starting:
            return "Starting the background scanner."
        case .projectCandidates:
            return "\(progress.directoriesScanned) directory visits completed."
        case .candidateFiles:
            return "\(progress.candidateFiles) candidate files found."
        case .parsingFiles:
            return "\(progress.filesParsed) of \(progress.candidateFiles) candidates read."
        case .reconciling:
            return "Checking existing projects and Managed items."
        case .complete:
            return "The review is almost ready."
        }
    }

    private var statusNote: String {
        if errorMessage != nil {
            return "No changes were made."
        }
        if job?.state == .cancelled {
            return "No changes were made."
        }
        return "You can cancel safely before importing."
    }

    private func runDiscovery() async {
        do {
            var current = try await store.startDiscovery(at: paths)
            job = current
            while !Task.isCancelled && !current.state.isTerminal {
                try await Task.sleep(nanoseconds: 500_000_000)
                current = try await store.discoveryStatus(id: current.id)
                job = current
            }
            if current.state == .failed {
                errorMessage = current.error ?? "The background discovery job failed."
            } else if current.state == .completed && current.plan == nil {
                errorMessage = "Discovery completed without a review plan."
            }
        } catch is CancellationError {
            return
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func cancelDiscovery() {
        guard let job, !job.state.isTerminal, !isCancelling else { return }
        isCancelling = true
        Task {
            do {
                self.job = try await store.cancelDiscovery(id: job.id)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
                isCancelling = false
            }
        }
    }
}

private enum DiscoveryDestinationChoice: Equatable {
    case project(String)
    case library(protectOriginal: Bool)
}

private enum DiscoveryProjectIdentityChoice: Equatable {
    case existing(String)
    case createNew
}

private struct DiscoveryReviewSheet: View {
    @Environment(\.dismiss) private var dismiss
    let plan: DiscoveryPlan
    let apply:
        (
            [DiscoveryImport], [DiscoverySeparateEntry], [DiscoverySeparateEntry],
            [DiscoverySeparateEntry]
        ) async throws -> DiscoveryApplyResult
    let openProject: (String) -> Void
    @State private var isApplying = false
    @State private var appliedResult: DiscoveryApplyResult?
    @State private var applyError: String?
    @State private var selectedFilePaths: Set<String>
    @State private var destinations: [String: DiscoveryDestinationChoice]
    @State private var projectIdentities: [String: DiscoveryProjectIdentityChoice]
    @State private var protectedExpansion: [String: Bool] = [:]

    init(
        plan: DiscoveryPlan,
        apply: @escaping (
            [DiscoveryImport], [DiscoverySeparateEntry], [DiscoverySeparateEntry],
            [DiscoverySeparateEntry]
        ) async throws -> DiscoveryApplyResult,
        openProject: @escaping (String) -> Void
    ) {
        self.plan = plan
        self.apply = apply
        self.openProject = openProject
        let managedPaths = Set(plan.managedItems.map(\.path))
        // Files in an implausible location are discovered but left unselected: the user
        // confirms them deliberately instead of protecting a disposable copy by accident.
        _selectedFilePaths = State(
            initialValue: Set(
                plan.files
                    .filter {
                        $0.canApplyDiscovery && !managedPaths.contains($0.path)
                            && $0.placement == nil
                    }
                    .map(\.path)))
        _destinations = State(
            initialValue: Dictionary(
                uniqueKeysWithValues: plan.files.compactMap { file in
                    guard file.canApplyDiscovery, !managedPaths.contains(file.path) else {
                        return nil
                    }
                    let destination: DiscoveryDestinationChoice?
                    switch file.action {
                    case .compose:
                        destination = file.assignment.projectPath.map {
                            .project($0)
                        }
                    case .protect:
                        destination = file.assignment.projectPath.map {
                            .project($0)
                        } ?? .library(protectOriginal: true)
                    case .importSshIdentity:
                        destination = file.assignment.projectPath.map {
                            .project($0)
                        } ?? .library(protectOriginal: true)
                    case .reference, .review:
                        destination = nil
                    }
                    return destination.map { (file.path, $0) }
                }))
        _projectIdentities = State(
            initialValue: Dictionary(
                uniqueKeysWithValues: plan.projects.compactMap { project in
                    if let managedProjectID = project.managedProjectID {
                        return (project.path, .existing(managedProjectID))
                    }
                    if project.projectMatches.isEmpty {
                        return (project.path, .createNew)
                    }
                    return nil
                }))
    }

    private var managedItemPaths: Set<String> {
        Set(plan.managedItems.map(\.path))
    }

    private var discoveredFiles: [DiscoveredFile] {
        plan.files.filter {
            !managedItemPaths.contains($0.path) && $0.canApplyDiscovery
        }
    }

    private var discoveryScopeTitle: String {
        if plan.paths.count == 1, let path = plan.paths.first {
            return path
        }
        return "\(plan.paths.count) inputs · \(plan.projects.count) projects"
    }

    private var discoveryGroups: [DiscoveryProjectGroup] {
        var groups = plan.projects.compactMap { project -> DiscoveryProjectGroup? in
            let files = discoveredFiles.filter {
                $0.assignment.projectPath == project.path
            }
            let managedItems = plan.managedItems.filter {
                $0.projectPath == project.path
            }
            guard !files.isEmpty || !managedItems.isEmpty else { return nil }
            return DiscoveryProjectGroup(
                id: project.path,
                project: project,
                files: files,
                managedItems: managedItems,
                needsReview: false)
        }
        let unassignedFiles = discoveredFiles.filter { $0.assignment.projectPath == nil }
        let unassignedManagedItems = plan.managedItems.filter { $0.projectPath == nil }
        if !unassignedFiles.isEmpty || !unassignedManagedItems.isEmpty {
            groups.insert(
                DiscoveryProjectGroup(
                    id: "needs-review",
                    project: nil,
                    files: unassignedFiles,
                    managedItems: unassignedManagedItems,
                    needsReview: unassignedFiles.contains {
                        selectedFilePaths.contains($0.path)
                            && $0.action == .compose
                            && !destinationIsResolved(for: $0)
                    }),
                at: 0)
        }
        return groups
    }

    private var needsReviewCount: Int {
        discoveredFiles.filter {
            selectedFilePaths.contains($0.path)
                && $0.action == .compose
                && !destinationIsResolved(for: $0)
        }.count
    }

    private var managedAttentionCount: Int {
        plan.managedItems.filter { $0.status != .linked }.count
    }

    private var protectedCount: Int {
        plan.managedItems.filter { $0.status == .linked }.count
    }

    private var hasUnresolvedAssignments: Bool {
        needsReviewCount > 0
    }

    var body: some View {
        let preview = importPreview
        let cachedAppliedResults = Dictionary(
            uniqueKeysWithValues: (appliedResult?.files ?? []).map { ($0.path, $0) })
        let cachedConflicts = preview.conflicts.reduce(
            into: [String: [DiscoveryImportPreview.Conflict]]()
        ) { conflictsByPath, conflict in
            for path in conflict.sourcePaths {
                conflictsByPath[path, default: []].append(conflict)
            }
        }
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                Image(systemName: "sparkle.magnifyingglass")
                    .font(.title2)
                    .foregroundStyle(.blue)
                    .frame(width: 42, height: 42)
                    .background(Color.blue.opacity(0.10), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 2) {
                    Text(
                        plan.projects.allSatisfy { $0.managedProjectID == nil }
                            ? "Discovery Results"
                            : "Managed Status")
                        .font(.title2.bold())
                    Text(discoveryScopeTitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
            }
            .padding(22)
            Divider()

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 18) {
                    HStack(spacing: 10) {
                        SummaryMetric(value: protectedCount, label: "Managed")
                        SummaryMetric(value: selectedFilePaths.count, label: "Will Be Managed")
                        SummaryMetric(
                            value: needsReviewCount + managedAttentionCount,
                            label: "Attention")
                    }
                    if preview.hasConflicts || needsReviewCount > 0 {
                        DiscoveryImportPreviewBanner(
                            preview: preview,
                            unresolvedAssignments: needsReviewCount)
                    }
                    if let appliedResult {
                        Label(
                            appliedSummary(appliedResult),
                            systemImage: "checkmark.circle.fill")
                            .font(.callout.weight(.medium))
                            .foregroundStyle(.green)
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                    }
                    ForEach(discoveryGroups) { group in
                        let attentionItems = group.managedItems.filter { $0.status != .linked }
                        let protectedItems = group.managedItems.filter { $0.status == .linked }
                        // Collapse already-managed rows so actionable items lead; a group
                        // with nothing actionable (pure status check) stays expanded.
                        let protectedExpanded =
                            protectedExpansion[group.id]
                            ?? (group.files.isEmpty && attentionItems.isEmpty)
                        LazyVStack(alignment: .leading, spacing: 9) {
                            DiscoveryProjectHeader(
                                group: group,
                                identity: Binding(
                                    get: { projectIdentities[group.id] },
                                    set: { projectIdentities[group.id] = $0 }))
                            ForEach(attentionItems) { item in
                                DiscoveryManagedItemCard(item: item)
                            }
                            ForEach(group.files) { file in
                                DiscoveryFileCard(
                                    file: file,
                                    projects: plan.projects,
                                    destination: Binding(
                                        get: { destinations[file.path] },
                                        set: { destinations[file.path] = $0 }),
                                    selected: Binding(
                                        get: { selectedFilePaths.contains(file.path) },
                                        set: { selected in
                                            if selected {
                                                selectedFilePaths.insert(file.path)
                                            } else {
                                                selectedFilePaths.remove(file.path)
                                            }
                                        }),
                                    result: cachedAppliedResults[file.path],
                                    locked: appliedResult != nil,
                                    conflicts: cachedConflicts[file.path] ?? [])
                            }
                            if !protectedItems.isEmpty {
                                Button {
                                    withAnimation(.easeInOut(duration: 0.15)) {
                                        protectedExpansion[group.id] = !protectedExpanded
                                    }
                                } label: {
                                    HStack(spacing: 8) {
                                        Image(systemName: "checkmark.shield.fill")
                                            .foregroundStyle(.blue)
                                        Text(
                                            "\(protectedItems.count) already managed"
                                        )
                                        .font(.callout.weight(.medium))
                                        .foregroundStyle(.secondary)
                                        Spacer()
                                        Image(systemName: "chevron.right")
                                            .font(.caption.weight(.semibold))
                                            .foregroundStyle(.tertiary)
                                            .rotationEffect(
                                                .degrees(protectedExpanded ? 90 : 0))
                                    }
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 10)
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                                .background(
                                    Color(nsColor: .controlBackgroundColor),
                                    in: RoundedRectangle(cornerRadius: 12))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 12)
                                        .stroke(
                                            Color.secondary.opacity(0.14), lineWidth: 1)
                                }
                                if protectedExpanded {
                                    ForEach(protectedItems) { item in
                                        DiscoveryManagedItemCard(item: item)
                                    }
                                }
                            }
                        }
                    }
                    if discoveredFiles.isEmpty && plan.managedItems.isEmpty {
                        ContentUnavailableView(
                            "Nothing discovered",
                            systemImage: "doc.text.magnifyingglass",
                            description: Text("No supported files were found in this location."))
                            .frame(maxWidth: .infinity, minHeight: 220)
                    }
                }
                .padding(22)
            }
            Divider()
            HStack {
                Text(
                    appliedResult == nil
                        ? discoveryNote
                        : "Protection status has been refreshed.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if appliedResult == nil {
                    Button(hasImportableItems ? "Cancel" : "Done") { dismiss() }
                        .disabled(isApplying)
                }
                if appliedResult != nil || hasImportableItems {
                    Button {
                        if let appliedResult {
                            if let projectID = appliedResult.projectID {
                                openProject(projectID)
                            }
                            dismiss()
                        } else {
                            applyDiscovery()
                        }
                    } label: {
                        if isApplying {
                            HStack(spacing: 7) {
                                ProgressView().controlSize(.small)
                                Text("Protecting…")
                            }
                        } else {
                            Text(
                                appliedResult == nil
                                    ? importButtonTitle
                                    : completionButtonTitle)
                        }
                    }
                    .disabled(
                        isApplying
                            || (appliedResult == nil
                                && (selectedFilePaths.isEmpty || hasUnresolvedAssignments
                                    || preview.hasConflicts)))
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(.horizontal, 22)
            .frame(height: 58)
        }
        .frame(width: 720, height: 650)
        .alert(
            "Protection could not finish",
            isPresented: Binding(
                get: { applyError != nil },
                set: { if !$0 { applyError = nil } })
        ) {
            Button("OK") { applyError = nil }
        } message: {
            Text(applyError ?? "Unknown error")
        }
    }

    private var importButtonTitle: String {
        let files = discoveredFiles.filter { selectedFilePaths.contains($0.path) }
        let count = files.count
        guard count > 0 else { return "Select Items" }
        let suffix = count == 1 ? "" : "s"
        return "Manage \(count) File\(suffix)"
    }

    private var hasImportableItems: Bool {
        discoveredFiles.contains(where: \.canApplyDiscovery)
    }

    private var selectedFiles: [DiscoveredFile] {
        discoveredFiles.filter { selectedFilePaths.contains($0.path) }
    }

    private var selectedImports: [DiscoveryImport] {
        selectedFiles.compactMap(discoveryImport)
    }

    private var importPreview: DiscoveryImportPreview {
        DiscoveryImportPreview(
            imports: selectedImports,
            pathExists: { path in
                if FileManager.default.fileExists(atPath: path) {
                    return true
                }
                return (try? FileManager.default.destinationOfSymbolicLink(atPath: path)) != nil
            })
    }

    private var completionButtonTitle: String {
        guard let result = appliedResult else { return "Done" }
        if result.projectIDs.count > 1 {
            return "View Projects"
        }
        return result.projectID == nil ? "Done" : "Open Project"
    }

    private var discoveryNote: String {
        var notes = ["Static scan only; project code was not executed."]
        if !plan.managedItems.isEmpty {
            if managedAttentionCount == 0 {
                notes.append(
                    "\(protectedCount) path\(protectedCount == 1 ? " is" : "s are") managed."
                )
            } else {
                notes.append(
                    "\(managedAttentionCount) managed path\(managedAttentionCount == 1 ? " needs" : "s need") attention."
                )
            }
        }
        if hasUnresolvedAssignments {
            notes.append(
                "\(needsReviewCount) selected file\(needsReviewCount == 1 ? "" : "s") need a project."
            )
        }
        let conflictCount = importPreview.conflicts.count
        if conflictCount > 0 {
            notes.append(
                "\(conflictCount) selected file\(conflictCount == 1 ? "" : "s") conflict with existing Managed items."
            )
        }
        let base = notes.joined(separator: " ")
        if selectedFilePaths.isEmpty {
            return hasImportableItems
                ? "\(base) Select at least one file."
                : "\(base) No files need management."
        }
        let dynamicFiles = selectedFiles.filter {
            !$0.warnings.isEmpty
        }.count
        guard dynamicFiles > 0 else { return base }
        let suffix = dynamicFiles == 1 ? "" : "s"
        return "\(selectedFilePaths.count) selected. \(dynamicFiles) dynamic file\(suffix) will be managed unchanged."
    }

    private func destinationIsResolved(for file: DiscoveredFile) -> Bool {
        guard let destination = destinations[file.path] else { return false }
        guard case .project(let projectPath) = destination else { return true }
        return projectIdentities[projectPath] != nil
    }

    private func selectedProjectID(for projectPath: String) -> String? {
        guard case .existing(let projectID) = projectIdentities[projectPath] else {
            return nil
        }
        return projectID
    }

    private func discoveryImport(for file: DiscoveredFile) -> DiscoveryImport? {
        switch file.action {
        case .protect:
            switch destinations[file.path] {
            case .project(let projectPath):
                return DiscoveryImport(
                    path: file.path,
                    destination: .projectFile(
                        projectPath: projectPath,
                        projectID: selectedProjectID(for: projectPath)),
                    sourceDisposition: .protectInPlace)
            case .library, nil:
                return DiscoveryImport(
                    path: file.path,
                    destination: .library,
                    sourceDisposition: .protectInPlace)
            }
        case .importSshIdentity:
            switch destinations[file.path] {
            case .project(let projectPath):
                return DiscoveryImport(
                    path: file.path,
                    destination: .projectFile(
                        projectPath: projectPath,
                        projectID: selectedProjectID(for: projectPath)),
                    sourceDisposition: .protectInPlace)
            case .library(let protectOriginal):
                return DiscoveryImport(
                    path: file.path,
                    destination: .library,
                    sourceDisposition: protectOriginal ? .protectInPlace : .leaveUnchanged)
            case nil:
                return nil
            }
        case .compose:
            guard let destination = destinations[file.path] else { return nil }
            switch destination {
            case .project(let projectPath):
                return DiscoveryImport(
                    path: file.path,
                    destination: .projectFile(
                        projectPath: projectPath,
                        projectID: selectedProjectID(for: projectPath)),
                    sourceDisposition: .protectInPlace)
            case .library(let protectOriginal):
                return DiscoveryImport(
                    path: file.path,
                    destination: .library,
                    sourceDisposition: protectOriginal ? .protectInPlace : .leaveUnchanged)
            }
        case .reference, .review:
            return nil
        }
    }

    private func applyDiscovery() {
        guard !isApplying else { return }
        isApplying = true
        Task {
            defer { isApplying = false }
            do {
                appliedResult = try await apply(
                    selectedImports,
                    [],
                    [],
                    [])
            } catch {
                applyError = error.localizedDescription
            }
        }
    }

    private func appliedSummary(_ result: DiscoveryApplyResult) -> String {
        let completed = result.files.filter {
            $0.outcome == "imported" || $0.outcome == "protected"
        }.count
        let failed = result.files.filter { $0.outcome == "failed" }.count
        let skipped = result.files.filter { $0.outcome == "skipped" }.count
        var parts = ["\(completed) completed"]
        if skipped > 0 { parts.append("\(skipped) skipped") }
        if failed > 0 { parts.append("\(failed) failed") }
        return parts.joined(separator: ", ") + "."
    }

}

private struct SummaryMetric: View {
    let value: Int
    let label: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(value)").font(.title3.bold().monospacedDigit())
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct DiscoveryManagedItemCard: View {
    let item: DiscoveryManagedItem

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .frame(width: 28, height: 28)
                .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 7))
            VStack(alignment: .leading, spacing: 2) {
                Text(item.relativePath)
                    .font(.body.weight(.medium))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Label(statusTitle, systemImage: statusIcon)
                .font(.caption.weight(.medium))
                .foregroundStyle(statusColor)
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .stroke(statusColor.opacity(item.status == .linked ? 0.15 : 0.35), lineWidth: 1)
        }
        .help(statusHelp)
    }

    private var detail: String {
        var parts = ["Managed file"]
        if let environment = item.environment {
            parts.append(environment)
        }
        return parts.joined(separator: " · ")
    }

    private var icon: String {
        item.kind == .surface ? "doc.text.fill" : "doc.fill"
    }

    private var color: Color {
        statusColor
    }

    private var statusTitle: String {
        switch item.status {
        case .linked: "Managed"
        case .missing, .replaced: "Needs attention"
        }
    }

    private var statusIcon: String {
        switch item.status {
        case .linked: "checkmark.shield.fill"
        case .missing: "exclamationmark.triangle.fill"
        case .replaced: "xmark.circle.fill"
        }
    }

    private var statusColor: Color {
        switch item.status {
        case .linked: .blue
        case .missing: .orange
        case .replaced: .red
        }
    }

    private var statusHelp: String {
        switch item.status {
        case .linked:
            "This path still points to its Floria-managed content."
        case .missing:
            "The managed path no longer exists. Its catalog and encrypted content are unchanged."
        case .replaced:
            "Another file or symbolic link now occupies this managed path. Floria did not replace it."
        }
    }
}

private struct DiscoveryFileCard: View {
    let file: DiscoveredFile
    let projects: [DiscoveredProject]
    @Binding var destination: DiscoveryDestinationChoice?
    @Binding var selected: Bool
    let result: DiscoveryAppliedFile?
    let locked: Bool
    let conflicts: [DiscoveryImportPreview.Conflict]
    @State private var showsValues = false

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 10) {
                Toggle("", isOn: $selected)
                    .labelsHidden()
                    .toggleStyle(.checkbox)
                    .tint(.green)
                    .disabled(locked || !file.canApplyDiscovery)
                    .help(selectionHelp)
                Image(systemName: icon)
                    .foregroundStyle(color)
                    .frame(width: 28, height: 28)
                    .background(color.opacity(0.10), in: RoundedRectangle(cornerRadius: 7))
                VStack(alignment: .leading, spacing: 2) {
                    Text(file.relativePath)
                        .font(.body.weight(.medium))
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let placement = file.placement, result == nil {
                        Label(placement.advice, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                Spacer()
                if file.action == .compose {
                    Menu {
                        Section("Manage in Project") {
                            ForEach(projectChoices, id: \.path) { project in
                                Button {
                                    destination = .project(project.path)
                                } label: {
                                    if assignedProject?.path == project.path {
                                        Label(project.name, systemImage: "checkmark")
                                    } else {
                                        Text(project.name)
                                    }
                                }
                            }
                        }
                        Divider()
                        Button {
                            destination = .library(protectOriginal: true)
                        } label: {
                            if case .library = destination {
                                Label("Library", systemImage: "checkmark")
                            } else {
                                Text("Library")
                            }
                        }
                    } label: {
                        if destination == nil {
                            Label("Choose Project", systemImage: "folder")
                        } else {
                            Image(systemName: "ellipsis")
                        }
                    }
                    .font(.caption.weight(.medium))
                    .foregroundStyle(destination == nil ? Color.orange : Color.secondary)
                    .menuStyle(.borderlessButton)
                    .fixedSize()
                    .disabled(locked)
                }
                Label(statusTitle, systemImage: statusIcon)
                            .font(.caption.weight(.medium))
                    .foregroundStyle(statusColor)
            }
            if !file.entries.isEmpty {
                Button {
                    showsValues.toggle()
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: showsValues ? "chevron.down" : "chevron.right")
                            .font(.caption2.weight(.semibold))
                        Text(valueSummary)
                            .font(.caption)
                        Spacer()
                    }
                    .foregroundStyle(.secondary)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.leading, 38)

                if showsValues {
                    VStack(spacing: 6) {
                        ForEach(file.entries) { entry in
                            HStack {
                                Text(entry.section.map { "[\($0)] \(entry.key)" } ?? entry.key)
                                    .font(.caption.monospaced())
                                Spacer()
                                Text("Detected")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .padding(.leading, 38)
                }
            }
            if !file.warnings.isEmpty {
                Label(dynamicContentNote, systemImage: "shield.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.leading, 60)
            }
            ForEach(conflicts) { conflict in
                Label(conflict.message, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .padding(.leading, 60)
            }
            if let result, result.outcome == "failed" {
                Label(result.detail, systemImage: "xmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.leading, 60)
            }
        }
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.secondary.opacity(0.15), lineWidth: 1)
        }
    }

    private var assignedProject: DiscoveredProject? {
        guard case .project(let projectPath) = destination else { return nil }
        return projects.first { $0.path == projectPath }
    }

    private var detail: String {
        var parts = [file.kind.displayTitle]
        if let environment = file.environment { parts.append(environment) }
        for tag in file.tags
        where tag.localizedCaseInsensitiveCompare("protected") != .orderedSame
            && !parts.contains(where: { $0.localizedCaseInsensitiveCompare(tag) == .orderedSame }) {
            parts.append(tag)
        }
        return parts.joined(separator: " · ")
    }

    private var statusTitle: String {
        guard let result else {
            if selected { return "Will be managed" }
            return file.placement == nil ? "Not selected" : "Needs confirmation"
        }
        return switch result.outcome {
        case "imported", "protected": "Managed"
        case "failed": "Failed"
        default: "Skipped"
        }
    }

    private var statusIcon: String {
        guard let result else {
            return selected ? "plus.circle.fill" : "circle"
        }
        return switch result.outcome {
        case "imported", "protected": "checkmark.shield.fill"
        case "failed": "xmark.circle.fill"
        default: "minus.circle"
        }
    }

    private var statusColor: Color {
        guard let result else {
            return selected ? .green : .secondary
        }
        return switch result.outcome {
        case "imported", "protected": .blue
        case "failed": .red
        default: .secondary
        }
    }

    private var selectionHelp: String {
        if file.action == .compose && destination == nil {
            return "Choose a project before protecting this file."
        }
        return selected ? "Floria will manage this file unchanged." : "This file will remain unchanged."
    }

    private var valueSummary: String {
        let count = file.entries.count
        return "\(count) value\(count == 1 ? "" : "s") detected"
    }

    private var dynamicContentNote: String {
        selected
            ? "Dynamic content will be managed unchanged."
            : "Contains dynamic content."
    }

    private var icon: String {
        switch file.kind {
        case .dotenv: "doc.text.fill"
        case .direnv, .mise: "terminal"
        case .awsCredentials: "cloud.fill"
        case .pgpass: "cylinder.fill"
        case .sshPrivateKey, .privateKey: "key.fill"
        case .certificate: "checkmark.seal.fill"
        case .publicKey: "key"
        case .protectedFile, .unknown: "doc.fill"
        }
    }

    private var color: Color {
        statusColor
    }

    private var projectChoices: [DiscoveredProject] {
        var allowedPaths = Set(file.assignment.candidateProjectPaths)
        if let assignedPath = file.assignment.projectPath {
            allowedPaths.insert(assignedPath)
        }
        return projects.filter { allowedPaths.contains($0.path) }
    }
}

private extension DiscoveredFile {
    var canApplyDiscovery: Bool {
        switch action {
        case .reference, .review:
            false
        case .compose:
            !entries.isEmpty
        case .protect, .importSshIdentity:
            true
        }
    }
}

private extension DiscoveredFileKind {
    var displayTitle: String {
        switch self {
        case .dotenv: "dotenv"
        case .direnv: "direnv"
        case .mise: "mise"
        case .awsCredentials: "AWS credentials"
        case .pgpass: "PostgreSQL password file"
        case .sshPrivateKey: "SSH private key"
        case .privateKey: "Private key"
        case .certificate: "X.509 certificate"
        case .publicKey: "Public key"
        case .protectedFile, .unknown: "Opaque file · unchanged"
        }
    }
}
