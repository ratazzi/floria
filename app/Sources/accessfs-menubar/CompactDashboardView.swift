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

private struct WorkspacePresentation: Identifiable {
    let id = UUID()
    let selection: WorkspaceSidebarSelection
}

private enum DashboardIssueAction {
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
    @State private var workspacePresentation: WorkspacePresentation?
    @State private var showingAccessLog = false
    @State private var pendingAuditWindow: AuditOnlyWindow?
    @State private var showingAuditConfirmation = false
    @FocusState private var searchIsFocused: Bool

    var body: some View {
        ZStack {
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
                            workspacePresentation = WorkspacePresentation(
                                selection: .project(selectedProject.id))
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
        .background(Color(nsColor: .windowBackgroundColor))
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
        .sheet(item: $workspacePresentation) { presentation in
            AdvancedWorkspaceView(state: state, initialSelection: presentation.selection)
                .frame(minWidth: 1080, minHeight: 680)
        }
        .sheet(isPresented: $showingAccessLog) {
            AccessLogView(state: state)
                .frame(minWidth: 920, minHeight: 620)
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

            policyMenu

            Menu {
                Button("Discover Project…", systemImage: "sparkle.magnifyingglass") {
                    chooseDiscoverySource()
                }
                Button("Open Library", systemImage: "rectangle.3.group") {
                    openWorkspace()
                }
                Button("Open Access Log", systemImage: "clock") {
                    showingAccessLog = true
                }
                Divider()
                Button("Refresh", systemImage: "arrow.clockwise") {
                    reload()
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .accessibilityLabel("More actions")
        }
        .padding(.leading, 82)
        .padding(.trailing, 16)
        .frame(height: 52)
        .gesture(WindowDragGesture())
    }

    private var policyMenu: some View {
        let auditOnly = state.policyMode.isAuditOnly()
        return Menu {
            if !state.connected {
                Button("Daemon Offline") {}
                    .disabled(true)
            }
            if auditOnly {
                Button("Return to Normal", systemImage: "checkmark.shield") {
                    Task { await state.setPolicyMode(.normal, durationSecs: nil) }
                }
            } else {
                Menu("Enable Audit Only", systemImage: "eye") {
                    ForEach(
                        [AuditOnlyWindow.oneHour, .eightHours, .untilChanged]
                    ) { window in
                        Button(window.title) {
                            pendingAuditWindow = window
                            showingAuditConfirmation = true
                        }
                    }
                }
            }
        } label: {
            HStack(spacing: 7) {
                Image(
                    systemName: auditOnly
                        ? "eye.circle.fill"
                        : (state.connected ? "checkmark.shield.fill" : "shield.slash"))
                Text(auditOnly ? "Audit Only" : (state.connected ? "Protected" : "Offline"))
                    .lineLimit(1)
            }
            .font(.callout.weight(.medium))
            .foregroundStyle(
                auditOnly ? Color.orange : (state.connected ? Color.green : Color.secondary)
            )
            .padding(.horizontal, 11)
            .frame(height: 34)
            .background(
                (auditOnly ? Color.orange : Color.green).opacity(state.connected ? 0.09 : 0.04),
                in: RoundedRectangle(cornerRadius: 9))
            .overlay {
                RoundedRectangle(cornerRadius: 9)
                    .stroke(
                        (auditOnly ? Color.orange : Color.green).opacity(
                            state.connected ? 0.22 : 0.08),
                        lineWidth: 1)
            }
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel("Security mode")
        .accessibilityValue(
            auditOnly
                ? "Audit Only"
                : (state.connected
                    ? "Protected; using each item's security level"
                    : "Daemon offline"))
    }

    private var projectsSection: some View {
        DashboardSection(title: "Recent Projects") {
            Button("View All") {
                openWorkspace()
            }
            .buttonStyle(.plain)
            .foregroundStyle(.blue)
            .font(.callout)
        } content: {
            if visibleProjects.isEmpty {
                CompactEmptyRow(
                    icon: state.workspace.projects.isEmpty ? "folder.badge.plus" : "magnifyingglass",
                    title: state.workspace.projects.isEmpty ? "No projects yet" : "No matching projects",
                    detail: state.workspace.projects.isEmpty
                        ? "Use Discover to import a project directory."
                        : "Try a different search or project scope.")
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(visibleProjects.enumerated()), id: \.element.id) { index, project in
                        Button {
                            open(project)
                        } label: {
                            ProjectRow(
                                project: project,
                                detail: projectDetail(project),
                                relativeTime: projectRelativeTime(project),
                                healthy: projectIsHealthy(project))
                        }
                        .buttonStyle(.plain)
                        if index != visibleProjects.count - 1 {
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
                Menu {
                    Button("Protected Files", systemImage: "lock.fill") {
                        openWorkspace(.protectedFiles)
                    }
                    Button("Shared Secrets", systemImage: "key") {
                        openWorkspace(.sharedSecrets)
                    }
                    Button("Env Files", systemImage: "doc.badge.gearshape") {
                        openWorkspace(.envFiles)
                    }
                    Button("SSH Identities", systemImage: "key.horizontal") {
                        openWorkspace(.sshAgents)
                    }
                } label: {
                    HStack(spacing: 6) {
                        Text("Open Library")
                        Image(systemName: "chevron.down")
                            .font(.caption2)
                    }
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

    private var visibleProjects: [WorkspaceProject] {
        var projects = state.workspace.projects
        if !search.isEmpty {
            projects = projects.filter(projectMatchesSearch)
        }
        projects.sort {
            let lhs = projectActivityIndex($0) ?? Int.max
            let rhs = projectActivityIndex($1) ?? Int.max
            return lhs == rhs
                ? $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
                : lhs < rhs
        }
        return Array(projects.prefix(4))
    }

    private var visibleAccess: [RecentAccessGroup] {
        let recents = state.recents.filter { event in
            (selectedProject.map { eventBelongs(event, to: $0) } ?? true)
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
                    detail: "Protected files and SSH agents may be unavailable.",
                    actionTitle: "Retry", action: .reload))
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
                !$0.status.isHealthy
            }
            if let surface = stopped.first {
                result.append(
                    DashboardIssue(
                        id: "surface:\(surface.id)",
                        title: "\(project.name): \(surface.name) is unavailable",
                        detail: (surface.path as NSString).abbreviatingWithTildeInPath,
                        actionTitle: "Manage", action: .openWorkspace))
            }
        }

        let unlinked = state.workspace.protectedFiles.filter { !$0.linked }
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
        let secrets = state.workspace.resources.filter {
            $0.kind == .sharedSecret || $0.kind == .secret
        }.count
        let envFiles = state.workspace.resources.filter { $0.kind == .envFile }.count
        let sshIdentities = state.workspace.resources.filter { $0.kind == .sshIdentity }.count
        let protected = state.workspace.protectedFiles.count
        var parts = [
            "\(secrets) Secret\(secrets == 1 ? "" : "s")",
            "\(envFiles) Env File\(envFiles == 1 ? "" : "s")",
            "\(sshIdentities) SSH Identit\(sshIdentities == 1 ? "y" : "ies")",
        ]
        if protected > 0 {
            parts.append("\(protected) Protected File\(protected == 1 ? "" : "s")")
        }
        return parts.joined(separator: "  ·  ")
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

    private func projectActivityIndex(_ project: WorkspaceProject) -> Int? {
        state.recents.firstIndex { eventBelongs($0, to: project) }
    }

    private func eventBelongs(_ event: RecentAccess, to project: WorkspaceProject) -> Bool {
        let projectPath = (project.path as NSString).expandingTildeInPath
        let candidates = [event.path, event.display, event.shownPath].compactMap { $0 }
        return candidates.contains { candidate in
            let expanded = (candidate as NSString).expandingTildeInPath
            return expanded == projectPath || expanded.hasPrefix(projectPath + "/")
                || expanded.localizedCaseInsensitiveContains("/\(project.name)/")
                || expanded.localizedCaseInsensitiveContains("\(project.name)/")
        }
    }

    private func projectDetail(_ project: WorkspaceProject) -> String {
        let environments = project.environments
        guard let first = environments.first else { return "No environments" }
        var parts = [
            environments.count == 1
                ? first.name
                : "\(environments.count) environments"
        ]
        let surfaces = environments.flatMap(\.surfaces)
        parts.append(contentsOf: surfaces.prefix(2).map { surface in
            if surface.kind == .unixSocket { return "SSH agent" }
            let filename = URL(fileURLWithPath: surface.path).lastPathComponent
            return filename.isEmpty ? surface.name : filename
        })
        if surfaces.count > 2 {
            parts.append("\(surfaces.count - 2) more")
        }
        return parts.joined(separator: "  ·  ")
    }

    private func projectRelativeTime(_ project: WorkspaceProject) -> String? {
        guard let event = state.recents.first(where: { eventBelongs($0, to: project) }) else {
            return nil
        }
        return event.relativeTime(relativeTo: Date())
    }

    private func projectIsHealthy(_ project: WorkspaceProject) -> Bool {
        project.environments.flatMap(\.surfaces).allSatisfy(\.status.isHealthy)
    }

    private func open(_ project: WorkspaceProject) {
        state.workspace.selectProject(project.id)
        selectedProjectID = project.id
        search = ""
    }

    private func openWorkspace(_ selection: WorkspaceSidebarSelection = .projects) {
        workspacePresentation = WorkspacePresentation(selection: selection)
    }

    private func handle(_ action: DashboardIssueAction) {
        switch action {
        case .reload:
            reload()
        case .openWorkspace:
            openWorkspace()
        }
    }

    private func reload() {
        Task {
            await state.workspace.reload(reportErrors: true)
            await state.reloadPolicyMode()
        }
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
            Text(event.operation == "sign" ? "used" : event.operation)
                .font(.callout)
                .foregroundStyle(.secondary)
            Text(event.shownPath)
                .font(.callout)
                .foregroundStyle(.blue)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            if group.count > 1 {
                Text("×\(group.count)")
                    .font(.caption.monospacedDigit().weight(.medium))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.tertiary.opacity(0.16), in: Capsule())
            }
            RecentAccessTimeText(event: event)
                .font(.callout)
                .foregroundStyle(.secondary)
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

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 20) {
                projectHeader
                outputsSection
                bindingsSection
                protectedFilesSection
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
                    if !projectIsHealthy {
                        Label("Needs attention", systemImage: "exclamationmark.circle.fill")
                            .font(.callout.weight(.medium))
                            .foregroundStyle(Color.orange)
                    }
                }
                Text((project.path as NSString).abbreviatingWithTildeInPath)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 8) {
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
                        Label("Manage Project", systemImage: "slider.horizontal.3")
                    }
                        .buttonStyle(.bordered)
                }
                Text(headerCounts)
                    .font(.callout)
                    .foregroundStyle(.secondary)
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

    private var outputsSection: some View {
        DashboardSection(title: "Outputs") {
            Text("\(surfaces.count)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        } content: {
            if filteredSurfaces.isEmpty {
                CompactEmptyRow(
                    icon: search.isEmpty ? "doc.badge.plus" : "magnifyingglass",
                    title: search.isEmpty ? "No outputs in this environment" : "No matching outputs",
                    detail: search.isEmpty
                        ? "Choose Manage Project to add an environment file or socket."
                        : "Try a different search.")
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(filteredSurfaces.enumerated()), id: \.element.id) {
                        index, surface in
                        CompactSurfaceRow(
                            state: state,
                            surface: surface,
                            bindings: bindings(for: surface),
                            openAdvanced: openAdvanced)
                        if index != filteredSurfaces.count - 1 {
                            Divider().padding(.leading, 58)
                        }
                    }
                }
            }
        }
    }

    private var headerCounts: String {
        var parts = [
            "\(activeBindings.count) binding\(activeBindings.count == 1 ? "" : "s")",
            "\(surfaces.count) output\(surfaces.count == 1 ? "" : "s")",
        ]
        if !projectProtectedFiles.isEmpty {
            parts.append("\(projectProtectedFiles.count) protected")
        }
        return parts.joined(separator: "  ·  ")
    }

    @ViewBuilder
    private var protectedFilesSection: some View {
        if !projectProtectedFiles.isEmpty {
            DashboardSection(title: "Protected Files") {
                Text("\(projectProtectedFiles.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            } content: {
                if filteredProtectedFiles.isEmpty {
                    CompactEmptyRow(
                        icon: "magnifyingglass",
                        title: "No matching protected files",
                        detail: "Try a different search.")
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(filteredProtectedFiles.enumerated()), id: \.element.id) {
                            index, file in
                            CompactProtectedFileRow(file: file)
                            if index != filteredProtectedFiles.count - 1 {
                                Divider().padding(.leading, 58)
                            }
                        }
                    }
                }
            }
        }
    }

    // Bindings feeding an output render nested under it; this section only
    // lists bindings no output references yet.
    @ViewBuilder
    private var bindingsSection: some View {
        if !orphanBindings.isEmpty {
            DashboardSection(title: "Unattached Bindings") {
                Text("\(orphanBindings.filter(\.isEnabled).count) enabled")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } content: {
                if filteredOrphanBindings.isEmpty {
                    CompactEmptyRow(
                        icon: "magnifyingglass",
                        title: "No matching bindings",
                        detail: "Try a different search.")
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(filteredOrphanBindings.enumerated()), id: \.element.id) {
                            index, binding in
                            CompactBindingRow(
                                state: state,
                                binding: binding,
                                resource: state.workspace.resource(binding.resourceID),
                                scope: bindingScope(binding),
                                openAdvanced: openAdvanced)
                            if index != filteredOrphanBindings.count - 1 {
                                Divider().padding(.leading, 58)
                            }
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

    private var activeBindings: [WorkspaceBinding] {
        project.commonBindings + (selectedEnvironment?.bindings ?? [])
    }

    private func bindings(for surface: WorkspaceSurface) -> [WorkspaceBinding] {
        surface.bindingIDs.compactMap { id in
            activeBindings.first { $0.id == id }
        }
    }

    private var orphanBindings: [WorkspaceBinding] {
        let attached = Set(surfaces.flatMap(\.bindingIDs))
        return activeBindings.filter { !attached.contains($0.id) }
    }

    private func bindingMatchesSearch(_ binding: WorkspaceBinding) -> Bool {
        guard let resource = state.workspace.resource(binding.resourceID) else { return false }
        return [
            resource.name, resource.kind.title, resource.exportSummary,
            bindingScope(binding),
        ]
        .joined(separator: " ")
        .localizedCaseInsensitiveContains(search)
    }

    private var filteredSurfaces: [WorkspaceSurface] {
        guard !search.isEmpty else { return surfaces }
        return surfaces.filter { surface in
            [surface.name, surface.path, surface.kind.title, surface.securityLevel.title]
                .joined(separator: " ")
                .localizedCaseInsensitiveContains(search)
                || bindings(for: surface).contains(where: bindingMatchesSearch)
        }
    }

    private var projectProtectedFiles: [WorkspaceProtectedFile] {
        // Opaque protected files live on the workspace, keyed only by path; a
        // project owns the ones under its directory.
        let prefix = project.path.hasSuffix("/") ? project.path : project.path + "/"
        return state.workspace.protectedFiles.filter { $0.path.hasPrefix(prefix) }
    }

    private var filteredProtectedFiles: [WorkspaceProtectedFile] {
        guard !search.isEmpty else { return projectProtectedFiles }
        return projectProtectedFiles.filter {
            [$0.path, $0.kind.title]
                .joined(separator: " ")
                .localizedCaseInsensitiveContains(search)
        }
    }

    private var filteredOrphanBindings: [WorkspaceBinding] {
        guard !search.isEmpty else { return orphanBindings }
        return orphanBindings.filter(bindingMatchesSearch)
    }

    private var projectIsHealthy: Bool {
        project.environments.flatMap(\.surfaces).allSatisfy(\.status.isHealthy)
    }

    private var unmanagedWorktreeCount: Int {
        state.workspace.unmanagedCheckoutCount(projectID: project.id)
    }

    private func bindingScope(_ binding: WorkspaceBinding) -> String {
        switch binding.scope {
        case .common:
            return "All environments"
        case .environment:
            return selectedEnvironment?.name ?? "Environment"
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

    private var project: WorkspaceProject? {
        store.projects.first { $0.id == projectID }
    }

    private var sheetHeight: CGFloat {
        let rowCount = discovery?.checkouts.count ?? 1
        return min(560, max(270, CGFloat(rowCount * 66 + 190)))
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
        } else if let discovery {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(Array(discovery.checkouts.enumerated()), id: \.element.id) {
                        index, candidate in
                        checkoutRow(candidate, commonDir: discovery.commonDir)
                        if index != discovery.checkouts.count - 1 {
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
            set: { environmentSelections[candidate.path] = $0 })
        let selectedEnvironmentID = selection.wrappedValue
        let selectionChanged =
            managed?.environmentID != selectedEnvironmentID && !selectedEnvironmentID.isEmpty

        return HStack(spacing: 14) {
            Image(systemName: candidate.gitPrimary ? "folder" : "arrow.triangle.branch")
                .font(.system(size: 19))
                .foregroundStyle(candidate.gitPrimary ? Color.accentColor : Color.blue.opacity(0.78))
                .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 7) {
                    Text(displayName(for: candidate.path))
                        .font(.callout.weight(.semibold))
                    if candidate.gitPrimary {
                        checkoutBadge("Primary", color: .secondary)
                    } else if managed != nil {
                        checkoutBadge("Managed", color: .green)
                    }
                }
                Text((candidate.path as NSString).abbreviatingWithTildeInPath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 16)

            Button {
                NSWorkspace.shared.open(URL(fileURLWithPath: candidate.path))
            } label: {
                Image(systemName: "folder")
            }
            .buttonStyle(.borderless)
            .help("Open in Finder")

            if candidate.gitPrimary {
                Text("All configured outputs")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(width: 160, alignment: .trailing)
            } else {
                Picker("Environment", selection: selection) {
                    Text("Choose Environment").tag("")
                    ForEach(project?.environments ?? []) { environment in
                        Text(environment.name).tag(environment.id)
                    }
                }
                .labelsHidden()
                .frame(width: 160)
                .disabled(busyPath != nil)

                Button(managed == nil ? "Link" : "Update") {
                    Task {
                        await provision(
                            candidate, commonDir: commonDir,
                            environmentID: selectedEnvironmentID,
                            checkoutID: managed?.id)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .disabled(
                    selectedEnvironmentID.isEmpty || busyPath != nil
                        || (managed != nil && !selectionChanged))

                if let managed {
                    Button {
                        Task { await remove(managed) }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .disabled(busyPath != nil)
                    .help("Stop managing this worktree")
                } else {
                    Color.clear.frame(width: 16, height: 16)
                }
            }

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
        .frame(minHeight: 66)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let errorMessage, discovery != nil {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(2)
            }
            HStack(alignment: .center, spacing: 12) {
                Image(systemName: "checkmark.shield")
                    .foregroundStyle(.green)
                Text("Floria only creates and removes its own output links. Git worktrees and project files are never changed.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
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
        for candidate in result.checkouts {
            guard let id = candidate.managedCheckoutID,
                let environmentID = store.checkouts.first(where: { $0.id == id })?.environmentID
            else { continue }
            environmentSelections[candidate.path] = environmentID
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
        }
    }
}

private struct CompactSurfaceRow: View {
    @Bindable var state: AppState
    let surface: WorkspaceSurface
    let bindings: [WorkspaceBinding]
    let openAdvanced: () -> Void

    private var enabledBindings: [WorkspaceBinding] {
        bindings.filter(\.isEnabled)
    }

    // A linked output whose bindings are all disabled composes to an empty
    // file; surface that as "Paused" instead of a healthy status.
    private var isPaused: Bool {
        !bindings.isEmpty && enabledBindings.isEmpty
    }

    private var sourceSummary: String? {
        if bindings.count == 1,
            let resource = state.workspace.resource(bindings[0].resourceID)
        {
            return [resource.kind.title, resource.exportSummary]
                .compactMap { $0 }
                .joined(separator: " · ")
        }
        if bindings.count > 1 {
            return "\(bindings.count) sources · \(enabledBindings.count) enabled"
        }
        return nil
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: surface.kind.systemImage)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(Color.blue.opacity(0.76))
                .frame(width: 32, height: 32)
                .background(Color.blue.opacity(0.07), in: RoundedRectangle(cornerRadius: 7))

            VStack(alignment: .leading, spacing: 2) {
                Text(surface.name)
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                Text((surface.path as NSString).abbreviatingWithTildeInPath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            if let sourceSummary {
                Text(sourceSummary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            if isPaused {
                Label("Paused", systemImage: "pause.circle")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(Color.orange)
                    .frame(width: 82, alignment: .leading)
            } else {
                Label(
                    surface.status.rawValue,
                    systemImage: surface.status.isHealthy
                        ? "checkmark.circle" : "exclamationmark.circle")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(surface.status.isHealthy ? Color.green : Color.orange)
                    .frame(width: 82, alignment: .leading)
            }

            Label(surface.securityLevel.compactTitle, systemImage: surface.securityLevel.systemImage)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 78, alignment: .leading)

            if !bindings.isEmpty {
                Toggle(
                    "",
                    isOn: Binding(
                        get: { !enabledBindings.isEmpty },
                        set: { enabled in
                            let toFlip = bindings.filter { $0.isEnabled != enabled }
                            guard !toFlip.isEmpty else { return }
                            Task {
                                for binding in toFlip {
                                    await state.workspace.toggleBinding(binding.id)
                                }
                            }
                        })
                )
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
                .accessibilityLabel("Enable \(surface.name)")
                .accessibilityValue(enabledBindings.isEmpty ? "Paused" : "Enabled")
            }

            Menu {
                Button("Open in Finder", systemImage: "folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([
                        URL(fileURLWithPath: surface.path)
                    ])
                }
                Button("Manage Output…", systemImage: "slider.horizontal.3") {
                    openAdvanced()
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 26, height: 26)
                    .contentShape(Rectangle())
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .accessibilityLabel("\(surface.name) actions")
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 54)
    }
}

private struct CompactProtectedFileRow: View {
    let file: WorkspaceProtectedFile

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: file.kind.systemImage)
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(Color.blue.opacity(0.76))
                .frame(width: 32, height: 32)
                .background(Color.blue.opacity(0.07), in: RoundedRectangle(cornerRadius: 7))

            VStack(alignment: .leading, spacing: 2) {
                Text(URL(fileURLWithPath: file.path).lastPathComponent)
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                Text((file.path as NSString).abbreviatingWithTildeInPath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()

            Label(
                file.linked ? "Protected" : "Stored only",
                systemImage: file.linked ? "checkmark.shield" : "shield.slash")
                .font(.caption.weight(.medium))
                .foregroundStyle(file.linked ? Color.blue : Color.orange)
                .frame(width: 92, alignment: .leading)

            Text("v\(file.currentVersion)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 34, alignment: .leading)

            Menu {
                Button("Open in Finder", systemImage: "folder") {
                    NSWorkspace.shared.activateFileViewerSelecting([
                        URL(fileURLWithPath: file.path)
                    ])
                }
                Button("Copy Path", systemImage: "doc.on.doc") {
                    let pasteboard = NSPasteboard.general
                    pasteboard.clearContents()
                    pasteboard.setString(file.path, forType: .string)
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 26, height: 26)
                    .contentShape(Rectangle())
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .accessibilityLabel("\(URL(fileURLWithPath: file.path).lastPathComponent) actions")
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 54)
    }
}

private struct CompactBindingRow: View {
    @Bindable var state: AppState
    let binding: WorkspaceBinding
    let resource: WorkspaceResource?
    let scope: String
    let openAdvanced: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: resource?.kind.systemImage ?? "questionmark")
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)
                .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 7))

            VStack(alignment: .leading, spacing: 2) {
                Text(resource?.name ?? "Missing resource")
                    .font(.callout.weight(.semibold))
                    .lineLimit(1)
                Text(
                    [
                        resource?.kind.title,
                        resource?.exportSummary,
                    ].compactMap { $0 }.joined(separator: "  ·  ")
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }

            Spacer()

            Text(scope)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .frame(width: 112, alignment: .trailing)

            Toggle(
                "",
                isOn: Binding(
                    get: { binding.isEnabled },
                    set: { enabled in
                        guard enabled != binding.isEnabled else { return }
                        Task { await state.workspace.toggleBinding(binding.id) }
                    })
            )
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
            .accessibilityLabel("Enable \(resource?.name ?? "binding")")
            .accessibilityValue(binding.isEnabled ? "Enabled" : "Disabled")

            Button(action: openAdvanced) {
                Image(systemName: "slider.horizontal.3")
                    .frame(width: 26, height: 26)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .help("Manage binding")
            .accessibilityLabel("Manage \(resource?.name ?? "binding") binding")
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 54)
    }
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
        }
        .padding(.horizontal, 2)
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
                        ? "\(preview.conflicts.count) output conflict\(preview.conflicts.count == 1 ? "" : "s")"
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
                    "Choose Library, remove the conflicting project, or move the existing output before protecting."
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
            return "Checking existing projects, outputs, and protected files."
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
    case projects(Set<String>, protectOriginal: Bool)
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
    @State private var separateEntryIDs: Set<String> = []
    @State private var promotedEntryIDs: Set<String> = []
    @State private var demotedEntryIDs: Set<String> = []
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
                        destination = .library(protectOriginal: true)
                    case .importSshIdentity:
                        destination = .library(protectOriginal: false)
                    case .reference, .review:
                        destination = nil
                    }
                    return destination.map { (file.path, $0) }
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
        let cachedSharedGroupCounts = sharedGroupCounts
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
                            : "Protection Status")
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
                        SummaryMetric(value: protectedCount, label: "Protected")
                        SummaryMetric(value: selectedFilePaths.count, label: "Will Be Protected")
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
                        // Collapse already-protected rows so actionable items lead; a group
                        // with nothing actionable (pure status check) stays expanded.
                        let protectedExpanded =
                            protectedExpansion[group.id]
                            ?? (group.files.isEmpty && attentionItems.isEmpty)
                        LazyVStack(alignment: .leading, spacing: 9) {
                            DiscoveryProjectHeader(group: group)
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
                                    separateEntryIDs: $separateEntryIDs,
                                    promotedEntryIDs: $promotedEntryIDs,
                                    demotedEntryIDs: $demotedEntryIDs,
                                    sharedGroupCounts: cachedSharedGroupCounts,
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
                                            "\(protectedItems.count) already protected"
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
        return "Protect \(count) File\(suffix)"
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
                    "\(protectedCount) path\(protectedCount == 1 ? " is" : "s are") protected."
                )
            } else {
                notes.append(
                    "\(managedAttentionCount) previously protected path\(managedAttentionCount == 1 ? " is" : "s are") no longer protected."
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
                "\(conflictCount) output conflict\(conflictCount == 1 ? "" : "s") must be resolved before protection."
            )
        }
        let base = notes.joined(separator: " ")
        if selectedFilePaths.isEmpty {
            return hasImportableItems
                ? "\(base) Select at least one file."
                : "\(base) No files need protection."
        }
        let dynamicFiles = selectedFiles.filter {
            $0.action == .protect && !$0.warnings.isEmpty
        }.count
        guard dynamicFiles > 0 else { return base }
        let suffix = dynamicFiles == 1 ? "" : "s"
        return "\(selectedFilePaths.count) selected. \(dynamicFiles) dynamic file\(suffix) will be protected unchanged."
    }

    private func destinationIsResolved(for file: DiscoveredFile) -> Bool {
        guard let destination = destinations[file.path] else { return false }
        if case .projects(let projectPaths, _) = destination {
            return !projectPaths.isEmpty
        }
        return true
    }

    private func discoveryImport(for file: DiscoveredFile) -> DiscoveryImport? {
        switch file.action {
        case .protect:
            return DiscoveryImport(
                path: file.path,
                destination: .library,
                sourceDisposition: .protectInPlace)
        case .importSshIdentity:
            let protectOriginal =
                if case .library(let protectOriginal) = destinations[file.path] {
                    protectOriginal
                } else {
                    false
                }
            return DiscoveryImport(
                path: file.path,
                destination: .library,
                sourceDisposition: protectOriginal ? .protectInPlace : .leaveUnchanged)
        case .compose:
            guard let destination = destinations[file.path] else { return nil }
            switch destination {
            case .project(let projectPath):
                return DiscoveryImport(
                    path: file.path,
                    destination: .projectOutput(
                        projectPath: projectPath, outputPath: file.path),
                    sourceDisposition: .replaceWithSurface)
            case .library(let protectOriginal):
                return DiscoveryImport(
                    path: file.path,
                    destination: .library,
                    sourceDisposition: protectOriginal ? .protectInPlace : .leaveUnchanged)
            case .projects(let projectPaths, let protectOriginal):
                let outputs = projectPaths.sorted().map { projectPath in
                    DiscoveryProjectOutput(
                        projectPath: projectPath,
                        outputPath: projectOutputPath(for: file, projectPath: projectPath))
                }
                guard !outputs.isEmpty else { return nil }
                let replacesSource = outputs.contains {
                    ($0.outputPath as NSString).standardizingPath
                        == (file.path as NSString).standardizingPath
                }
                return DiscoveryImport(
                    path: file.path,
                    destination: .projectOutputs(outputs: outputs),
                    sourceDisposition: replacesSource
                        ? .replaceWithSurface
                        : (protectOriginal ? .protectInPlace : .leaveUnchanged))
            }
        case .reference, .review:
            return nil
        }
    }

    private func projectOutputPath(
        for file: DiscoveredFile, projectPath: String
    ) -> String {
        let relativePath =
            file.kind == .awsCredentials
                ? ".aws/credentials"
                : (file.path as NSString).lastPathComponent
        return (projectPath as NSString).appendingPathComponent(relativePath)
    }

    private func applyDiscovery() {
        guard !isApplying else { return }
        isApplying = true
        Task {
            defer { isApplying = false }
            do {
                let entriesMatching = { (ids: Set<String>) in
                    selectedFiles.flatMap { file in
                        file.entries.compactMap { entry in
                            ids.contains(entrySelectionID(file: file, entry: entry))
                                ? DiscoverySeparateEntry(path: file.path, address: entry.address)
                                : nil
                        }
                    }
                }
                appliedResult = try await apply(
                    selectedImports,
                    entriesMatching(separateEntryIDs),
                    entriesMatching(promotedEntryIDs),
                    entriesMatching(demotedEntryIDs))
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

    private var sharedGroupCounts: [String: Int] {
        plan.files
            .flatMap(\.entries)
            .compactMap(\.action.groupID)
            .reduce(into: [:]) { counts, groupID in counts[groupID, default: 0] += 1 }
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
        var parts = [
            item.kind == .surface ? "Managed output" : "Opaque file · unchanged"
        ]
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
        case .linked: "Protected"
        case .missing, .replaced: "Not protected"
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
    @Binding var separateEntryIDs: Set<String>
    @Binding var promotedEntryIDs: Set<String>
    @Binding var demotedEntryIDs: Set<String>
    let sharedGroupCounts: [String: Int]
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
                        Section("Project Output") {
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
                        Menu("Share with Projects") {
                            ForEach(projects, id: \.path) { project in
                                Button {
                                    toggleSharedProject(project.path)
                                } label: {
                                    if sharedProjectPaths.contains(project.path) {
                                        Label(project.name, systemImage: "checkmark")
                                    } else {
                                        Text(project.name)
                                    }
                                }
                            }
                        }
                        if canChooseOriginalDisposition {
                            Divider()
                            Button {
                                setProtectOriginal(true)
                            } label: {
                                if protectsOriginal {
                                    Label("Protect Original", systemImage: "checkmark")
                                } else {
                                    Text("Protect Original")
                                }
                            }
                            Button {
                                setProtectOriginal(false)
                            } label: {
                                if !protectsOriginal {
                                    Label("Leave Original Unchanged", systemImage: "checkmark")
                                } else {
                                    Text("Leave Original Unchanged")
                                }
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
                                entryAction(entry)
                            }
                        }
                    }
                    .padding(.leading, 38)
                }
            }
            if file.action == .protect && !file.warnings.isEmpty {
                Label(dynamicContentNote, systemImage: "shield.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.leading, 60)
            } else {
                ForEach(file.warnings) { warning in
                    Label(
                        warning.line.map { "Line \($0): \(warning.message)" } ?? warning.message,
                        systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .padding(.leading, 60)
                }
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

    private var sharedProjectPaths: Set<String> {
        guard case .projects(let paths, _) = destination else { return [] }
        return paths
    }

    private var protectsOriginal: Bool {
        switch destination {
        case .library(let protectOriginal), .projects(_, let protectOriginal):
            protectOriginal
        case .project, nil:
            false
        }
    }

    private var canChooseOriginalDisposition: Bool {
        switch destination {
        case .library:
            true
        case .projects(let paths, _):
            !paths.contains { projectOutputPath(for: $0) == standardizedSourcePath }
        case .project, nil:
            false
        }
    }

    private var standardizedSourcePath: String {
        (file.path as NSString).standardizingPath
    }

    private func projectOutputPath(for projectPath: String) -> String {
        let relativePath =
            file.kind == .awsCredentials
                ? ".aws/credentials"
                : (file.path as NSString).lastPathComponent
        return ((projectPath as NSString).appendingPathComponent(relativePath) as NSString)
            .standardizingPath
    }

    private func toggleSharedProject(_ projectPath: String) {
        var paths = sharedProjectPaths
        if paths.contains(projectPath) {
            paths.remove(projectPath)
        } else {
            paths.insert(projectPath)
        }
        destination = .projects(paths, protectOriginal: protectsOriginal || paths.count == 1)
    }

    private func setProtectOriginal(_ protectOriginal: Bool) {
        switch destination {
        case .library:
            destination = .library(protectOriginal: protectOriginal)
        case .projects(let paths, _):
            destination = .projects(paths, protectOriginal: protectOriginal)
        case .project, nil:
            break
        }
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
            if selected { return "Will be protected" }
            return file.placement == nil ? "Not selected" : "Needs confirmation"
        }
        return switch result.outcome {
        case "imported", "protected": "Protected"
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
        return selected ? "This file will be protected." : "This file will remain unchanged."
    }

    private var valueSummary: String {
        let count = file.entries.count
        let shared = file.entries.filter(isSharedAfterOverrides).count
        let values = "\(count) value\(count == 1 ? "" : "s")"
        guard selected, shared > 0 else { return values }
        return "\(values) · \(shared) shared automatically"
    }

    private var dynamicContentNote: String {
        selected
            ? "Dynamic content will be protected unchanged."
            : "Contains dynamic content."
    }

    private func isSharedAfterOverrides(_ entry: DiscoveredEntry) -> Bool {
        let selectionID = entrySelectionID(file: file, entry: entry)
        if demotedEntryIDs.contains(selectionID) {
            return false
        }
        if promotedEntryIDs.contains(selectionID) {
            return true
        }
        return isSecretActionEntry(entry)
    }

    private func entryActionTitle(_ type: String) -> String {
        return switch type {
        case "reuse_shared_secret": "Reuse"
        case "create_shared_secret", "reuse_discovered_secret": "Shared"
        case "create_env_file_entry": "This file"
        case "keep_in_protected_file": "Protect"
        default: "Unavailable"
        }
    }

    @ViewBuilder
    private func entryAction(_ entry: DiscoveredEntry) -> some View {
        let selectionID = entrySelectionID(file: file, entry: entry)
        let isSeparate = separateEntryIDs.contains(selectionID)
        if isPlainEnvEntry(entry) {
            let isPromoted = promotedEntryIDs.contains(selectionID)
            Menu {
                Button {
                    promotedEntryIDs.remove(selectionID)
                } label: {
                    if isPromoted {
                        Text("Keep in this file")
                    } else {
                        Label("Keep in this file", systemImage: "checkmark")
                    }
                }
                Button {
                    promotedEntryIDs.insert(selectionID)
                } label: {
                    if isPromoted {
                        Label("Share this value", systemImage: "checkmark")
                    } else {
                        Text("Share this value")
                    }
                }
            } label: {
                Text(isPromoted ? "Shared" : "This file")
                    .font(.caption)
                    .foregroundStyle(isPromoted ? Color.green : Color.secondary)
            }
            .menuStyle(.borderlessButton)
            .disabled(locked || !selected || !file.canApplyDiscovery)
        } else if supportsReclassification && isSecretActionEntry(entry) {
            let isDemoted = demotedEntryIDs.contains(selectionID)
            Menu {
                Button {
                    separateEntryIDs.remove(selectionID)
                    demotedEntryIDs.remove(selectionID)
                } label: {
                    if isSeparate || isDemoted {
                        Text(automaticEntryActionTitle(entry))
                    } else {
                        Label(
                            automaticEntryActionTitle(entry),
                            systemImage: "checkmark")
                    }
                }
                if supportsIsolationChoice(entry) {
                    Button {
                        separateEntryIDs.insert(selectionID)
                        demotedEntryIDs.remove(selectionID)
                    } label: {
                        if isSeparate && !isDemoted {
                            Label("Keep separate", systemImage: "checkmark")
                        } else {
                            Text("Keep separate")
                        }
                    }
                }
                Button {
                    demotedEntryIDs.insert(selectionID)
                    separateEntryIDs.remove(selectionID)
                } label: {
                    if isDemoted {
                        Label("Keep in this file", systemImage: "checkmark")
                    } else {
                        Text("Keep in this file")
                    }
                }
            } label: {
                Text(
                    isDemoted
                        ? "This file"
                        : (isSeparate
                            ? "Separate"
                            : automaticEntryActionTitle(entry)))
                .font(.caption)
                .foregroundStyle(
                    isDemoted ? Color.secondary : (isSeparate ? Color.orange : Color.green))
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(maxWidth: 220, alignment: .trailing)
            }
            .menuStyle(.borderlessButton)
            .disabled(locked || !selected || !file.canApplyDiscovery)
        } else {
            Text(automaticEntryActionTitle(entry))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var supportsReclassification: Bool {
        file.action == .compose && (file.kind == .dotenv || file.kind == .direnv)
    }

    private func isPlainEnvEntry(_ entry: DiscoveredEntry) -> Bool {
        supportsReclassification && entry.action.type == "create_env_file_entry"
    }

    private func isSecretActionEntry(_ entry: DiscoveredEntry) -> Bool {
        switch entry.action.type {
        case "create_shared_secret", "reuse_shared_secret", "reuse_discovered_secret":
            true
        default:
            false
        }
    }

    private func supportsIsolationChoice(_ entry: DiscoveredEntry) -> Bool {
        switch entry.action.type {
        case "reuse_shared_secret", "reuse_discovered_secret":
            true
        case "create_shared_secret":
            entry.action.groupID.map { sharedGroupCounts[$0, default: 0] > 1 } ?? false
        default:
            false
        }
    }

    private func automaticEntryActionTitle(_ entry: DiscoveredEntry) -> String {
        switch entry.action.type {
        case "reuse_shared_secret":
            return entry.action.resourceName.map { "Reuse \($0)" } ?? "Reuse existing"
        case "create_shared_secret", "reuse_discovered_secret":
            return "Shared"
        default:
            return entryActionTitle(entry.action.type)
        }
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

private func entrySelectionID(file: DiscoveredFile, entry: DiscoveredEntry) -> String {
    "\(file.path)\u{1f}\(entry.address)"
}

private extension DiscoveredFile {
    var canApplyDiscovery: Bool {
        switch action {
        case .reference, .review:
            false
        case .compose:
            !entries.isEmpty && warnings.isEmpty
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
