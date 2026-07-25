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
    let plan: DiscoveryPlan
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
    @State private var discoveryError: String?
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
        .focusedSceneValue(\.focusAppSearch) {
            searchIsFocused = true
        }
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first else { return false }
            beginDiscovery(at: url.path)
            return true
        } isTargeted: { isDropTargeted = $0 }
        .sheet(item: $discovery) { presentation in
            DiscoveryReviewSheet(
                plan: presentation.plan,
                sharedSecrets: state.workspace.resources.filter {
                    $0.kind == .sharedSecret && $0.shape == .scalar
                },
                apply: { files, separateEntries in
                    try await state.workspace.applyDiscovery(
                        at: presentation.plan.path, files: files,
                        separateEntries: separateEntries)
                },
                resolveReference: { surfaceID, key, source in
                    try await state.workspace.resolveDiscoveryReference(
                        surfaceID: surfaceID, key: key, source: source)
                },
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
        .alert(
            "Discovery could not finish",
            isPresented: Binding(
                get: { discoveryError != nil },
                set: { if !$0 { discoveryError = nil } })
        ) {
            Button("OK") { discoveryError = nil }
        } message: {
            Text(discoveryError ?? "Unknown error")
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

    private var header: some View {
        HStack(spacing: 12) {
            HStack(spacing: 8) {
                FloriaMark()
                    .frame(width: 26, height: 26)
                Text("Floria")
                    .font(.title3.weight(.semibold))
            }
            .fixedSize()

            projectMenu

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
        .frame(height: 58)
    }

    private var projectMenu: some View {
        Menu {
            Button {
                selectedProjectID = nil
                search = ""
            } label: {
                if selectedProjectID == nil {
                    Label("All Projects", systemImage: "checkmark")
                } else {
                    Text("All Projects")
                }
            }
            if !state.workspace.projects.isEmpty {
                Divider()
                ForEach(state.workspace.projects) { project in
                    Button {
                        state.workspace.selectProject(project.id)
                        selectedProjectID = project.id
                        search = ""
                    } label: {
                        if selectedProjectID == project.id {
                            Label(project.name, systemImage: "checkmark")
                        } else {
                            Text(project.name)
                        }
                    }
                }
            }
        } label: {
            HStack(spacing: 8) {
                Text(selectedProject?.name ?? "All Projects")
                    .lineLimit(1)
                Spacer(minLength: 4)
                Image(systemName: "chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .font(.callout.weight(.medium))
            .padding(.horizontal, 11)
            .frame(width: 142, height: 34)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.secondary.opacity(0.18), lineWidth: 1)
            }
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .focusable(false)
        .accessibilityLabel("Project filter")
        .accessibilityValue(selectedProject?.name ?? "All Projects")
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
                    ForEach(Array(visibleAccess.enumerated()), id: \.element.id) { index, event in
                        Button {
                            showingAccessLog = true
                        } label: {
                            AccessSummaryRow(event: event, relativeTime: relativeTime(event.date))
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

    private var visibleAccess: [RecentAccess] {
        state.recents.filter { event in
            (selectedProject.map { eventBelongs(event, to: $0) } ?? true)
                && (search.isEmpty || accessMatchesSearch(event))
        }
        .prefix(3)
        .map { $0 }
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
        return relativeTime(event.date)
    }

    private func projectIsHealthy(_ project: WorkspaceProject) -> Bool {
        project.environments.flatMap(\.surfaces).allSatisfy(\.status.isHealthy)
    }

    private func relativeTime(_ date: Date?) -> String? {
        guard let date else { return nil }
        return Self.relativeDate.localizedString(for: date, relativeTo: Date())
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
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        beginDiscovery(at: url.path)
    }

    private func beginDiscovery(at path: String) {
        guard !isDiscovering else { return }
        isDiscovering = true
        Task {
            defer { isDiscovering = false }
            do {
                let plan = try await state.workspace.discover(at: path)
                discovery = DiscoveryPresentation(plan: plan)
            } catch {
                discoveryError = error.localizedDescription
            }
        }
    }

    private static let relativeDate: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()
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
            Label(
                healthy ? "Healthy" : "Attention",
                systemImage: healthy ? "checkmark.circle" : "exclamationmark.circle")
                .font(.callout.weight(.medium))
                .foregroundStyle(healthy ? Color.green : Color.orange)
                .frame(width: 92, alignment: .leading)
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
    let event: RecentAccess
    let relativeTime: String?

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
            Text(relativeTime ?? event.time)
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
    let recentAccess: [RecentAccess]
    let openAdvanced: () -> Void

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 20) {
                projectHeader
                outputsSection
                bindingsSection
                projectAccessSection
            }
            .padding(.horizontal, 28)
            .padding(.top, 22)
            .padding(.bottom, 28)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var projectHeader: some View {
        HStack(spacing: 12) {
            Image(systemName: "folder")
                .font(.system(size: 20))
                .foregroundStyle(Color.blue.opacity(0.78))
                .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 10) {
                    Text(project.name)
                        .font(.title2.bold())
                    environmentMenu
                    Label(
                        projectIsHealthy ? "Healthy" : "Needs attention",
                        systemImage: projectIsHealthy
                            ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(projectIsHealthy ? Color.green : Color.orange)
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
                        Label("Finder", systemImage: "folder")
                    }
                    .buttonStyle(.bordered)

                    Button(action: openAdvanced) {
                        Label("Manage Project", systemImage: "slider.horizontal.3")
                    }
                        .buttonStyle(.bordered)
                }
                Text(
                    "\(activeBindings.count) binding\(activeBindings.count == 1 ? "" : "s")"
                        + "  ·  "
                        + "\(surfaces.count) output\(surfaces.count == 1 ? "" : "s")")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var environmentMenu: some View {
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
            HStack(spacing: 7) {
                Text(selectedEnvironment?.name ?? "No environment")
                    .lineLimit(1)
                Image(systemName: "chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .font(.caption.weight(.medium))
            .padding(.horizontal, 8)
            .frame(height: 24)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
            .overlay {
                RoundedRectangle(cornerRadius: 7)
                    .stroke(Color.secondary.opacity(0.16), lineWidth: 1)
            }
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .disabled(project.environments.isEmpty)
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
                        CompactSurfaceRow(surface: surface, openAdvanced: openAdvanced)
                        if index != filteredSurfaces.count - 1 {
                            Divider().padding(.leading, 58)
                        }
                    }
                }
            }
        }
    }

    private var bindingsSection: some View {
        DashboardSection(title: "Bindings") {
            Text("\(activeBindings.filter(\.isEnabled).count) enabled")
                .font(.caption)
                .foregroundStyle(.secondary)
        } content: {
            if filteredBindings.isEmpty {
                CompactEmptyRow(
                    icon: search.isEmpty ? "link.badge.plus" : "magnifyingglass",
                    title: search.isEmpty ? "No bindings in this environment" : "No matching bindings",
                    detail: search.isEmpty
                        ? "Choose Manage Project to compose resources into this project."
                        : "Try a different search.")
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(filteredBindings.enumerated()), id: \.element.id) {
                        index, binding in
                        CompactBindingRow(
                            state: state,
                            binding: binding,
                            resource: state.workspace.resource(binding.resourceID),
                            scope: bindingScope(binding),
                            openAdvanced: openAdvanced)
                        if index != filteredBindings.count - 1 {
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
                    ForEach(Array(recentAccess.enumerated()), id: \.element.id) { index, event in
                        AccessSummaryRow(event: event, relativeTime: relativeTime(event.date))
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

    private var filteredSurfaces: [WorkspaceSurface] {
        guard !search.isEmpty else { return surfaces }
        return surfaces.filter {
            [$0.name, $0.path, $0.kind.title, $0.securityLevel.title]
                .joined(separator: " ")
                .localizedCaseInsensitiveContains(search)
        }
    }

    private var filteredBindings: [WorkspaceBinding] {
        guard !search.isEmpty else { return activeBindings }
        return activeBindings.filter { binding in
            guard let resource = state.workspace.resource(binding.resourceID) else { return false }
            return [
                resource.name, resource.kind.title, resource.exportSummary,
                bindingScope(binding),
            ]
            .joined(separator: " ")
            .localizedCaseInsensitiveContains(search)
        }
    }

    private var projectIsHealthy: Bool {
        project.environments.flatMap(\.surfaces).allSatisfy(\.status.isHealthy)
    }

    private func bindingScope(_ binding: WorkspaceBinding) -> String {
        switch binding.scope {
        case .common:
            return "All environments"
        case .environment:
            return selectedEnvironment?.name ?? "Environment"
        }
    }

    private func relativeTime(_ date: Date?) -> String? {
        guard let date else { return nil }
        return Self.relativeDate.localizedString(for: date, relativeTo: Date())
    }

    private static let relativeDate: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()
}

private struct CompactSurfaceRow: View {
    let surface: WorkspaceSurface
    let openAdvanced: () -> Void

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

            Label(
                surface.status.rawValue,
                systemImage: surface.status.isHealthy
                    ? "checkmark.circle" : "exclamationmark.circle")
                .font(.caption.weight(.medium))
                .foregroundStyle(surface.status.isHealthy ? Color.green : Color.orange)
                .frame(width: 82, alignment: .leading)

            Label(surface.securityLevel.compactTitle, systemImage: surface.securityLevel.systemImage)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 78, alignment: .leading)

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

private struct DiscoveryReviewSheet: View {
    @Environment(\.dismiss) private var dismiss
    let plan: DiscoveryPlan
    let sharedSecrets: [WorkspaceResource]
    let apply: ([String], [DiscoverySeparateEntry]) async throws -> DiscoveryApplyResult
    let resolveReference:
        (String, String, DiscoveryReferenceSource) async throws
            -> DiscoveryReferenceResolution
    let openProject: (String) -> Void
    @State private var isApplying = false
    @State private var appliedResult: DiscoveryApplyResult?
    @State private var applyError: String?
    @State private var selectedFilePaths: Set<String>
    @State private var separateEntryIDs: Set<String> = []
    @State private var resolvedReferenceEntryIDs: Set<String> = []
    @State private var referenceTarget: ReferenceResolutionTarget?

    init(
        plan: DiscoveryPlan,
        sharedSecrets: [WorkspaceResource],
        apply: @escaping ([String], [DiscoverySeparateEntry]) async throws
            -> DiscoveryApplyResult,
        resolveReference: @escaping
            (String, String, DiscoveryReferenceSource) async throws
                -> DiscoveryReferenceResolution,
        openProject: @escaping (String) -> Void
    ) {
        self.plan = plan
        self.sharedSecrets = sharedSecrets
        self.apply = apply
        self.resolveReference = resolveReference
        self.openProject = openProject
        _selectedFilePaths = State(
            initialValue: Set(plan.files.filter(\.canApplyDiscovery).map(\.path)))
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 13) {
                Image(systemName: "sparkle.magnifyingglass")
                    .font(.title2)
                    .foregroundStyle(.blue)
                    .frame(width: 42, height: 42)
                    .background(Color.blue.opacity(0.10), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 2) {
                    Text(
                        plan.project.managedProjectID == nil
                            ? "Review Discovery"
                            : "Review Changes")
                        .font(.title2.bold())
                    Text(plan.project.path)
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
                VStack(alignment: .leading, spacing: 18) {
                    HStack(spacing: 10) {
                        SummaryMetric(value: plan.summary.files, label: "Files")
                        SummaryMetric(value: selectedSecretSummary.new, label: "New")
                        SummaryMetric(value: selectedSecretSummary.reused, label: "Reused")
                        SummaryMetric(value: plan.summary.warnings, label: "Warnings")
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
                    ForEach(plan.files) { file in
                        DiscoveryFileCard(
                            file: file,
                            selected: Binding(
                                get: { selectedFilePaths.contains(file.path) },
                                set: { selected in
                                    if selected {
                                        selectedFilePaths.insert(file.path)
                                    } else {
                                        selectedFilePaths.remove(file.path)
                                    }
                                }),
                            result: appliedResult?.files.first { $0.path == file.path },
                            locked: appliedResult != nil,
                            separateEntryIDs: $separateEntryIDs,
                            sharedGroupCounts: sharedGroupCounts,
                            automaticGroupCounts: automaticGroupCounts,
                            automaticGroupPrimaryEntryIDs: automaticGroupPrimaryEntryIDs,
                            resolvedReferenceEntryIDs: resolvedReferenceEntryIDs,
                            resolveReference: { entry in
                                referenceTarget = ReferenceResolutionTarget(
                                    file: file, entry: entry)
                            })
                    }
                    if plan.files.isEmpty {
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
                        : "The managed inventory has been refreshed.")
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
                                Text("Importing…")
                            }
                        } else {
                            Text(
                                appliedResult == nil
                                    ? importButtonTitle
                                    : (appliedResult?.projectID == nil ? "Done" : "Open Project"))
                        }
                    }
                    .disabled(isApplying || (appliedResult == nil && selectedFilePaths.isEmpty))
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(.horizontal, 22)
            .frame(height: 58)
        }
        .frame(width: 640, height: 620)
        .alert(
            "Import could not finish",
            isPresented: Binding(
                get: { applyError != nil },
                set: { if !$0 { applyError = nil } })
        ) {
            Button("OK") { applyError = nil }
        } message: {
            Text(applyError ?? "Unknown error")
        }
        .sheet(item: $referenceTarget) { target in
            ReferenceValueSheet(
                target: target,
                sharedSecrets: sharedSecrets,
                resolve: resolveReference,
                completed: {
                    resolvedReferenceEntryIDs.insert(target.id)
                    referenceTarget = nil
                })
        }
    }

    private var importButtonTitle: String {
        let files = plan.files.filter { selectedFilePaths.contains($0.path) }
        let count = files.count
        guard count > 0 else { return "Select Items" }
        let suffix = count == 1 ? "" : "s"
        let actions = Set(files.map(\.action))
        if actions == [.protect] {
            return "Protect \(count) File\(suffix)"
        }
        if actions == [.compose] {
            return "Import \(count) File\(suffix)"
        }
        if actions == [.importSshIdentity] {
            return "Import \(count) Identit\(count == 1 ? "y" : "ies")"
        }
        return "Protect & Import \(count) Item\(suffix)"
    }

    private var hasImportableItems: Bool {
        plan.files.contains(where: \.canApplyDiscovery)
    }

    private var discoveryNote: String {
        var notes = ["Static scan only; project code was not executed."]
        let referenceCount = plan.files.filter { $0.action == .reference }.count
        if referenceCount > 0 {
            notes.append(
                "\(referenceCount) reference file\(referenceCount == 1 ? "" : "s") will remain unchanged."
            )
        }
        let missingCount = max(
            0, plan.summary.missingReferenceEntries - resolvedReferenceEntryIDs.count)
        if missingCount > 0 {
            notes.append(
                "\(missingCount) declared key\(missingCount == 1 ? " has" : "s have") no discovered value."
            )
        }
        let base = notes.joined(separator: " ")
        if selectedFilePaths.isEmpty {
            return hasImportableItems
                ? "\(base) Select at least one importable item."
                : "\(base) No importable \(emptyResultKind) were found."
        }
        guard plan.summary.warnings > 0 else { return base }
        let suffix = plan.summary.warnings == 1 ? "" : "s"
        return "\(selectedFilePaths.count) selected. \(plan.summary.warnings) warning\(suffix) require review."
    }

    private var emptyResultKind: String {
        plan.project.managedProjectID == nil ? "items" : "changes"
    }

    private func applyDiscovery() {
        guard !isApplying else { return }
        isApplying = true
        Task {
            defer { isApplying = false }
            do {
                let selectedFiles = plan.files.filter {
                    selectedFilePaths.contains($0.path)
                }
                let separateEntries = selectedFiles.flatMap { file in
                    file.entries.compactMap { entry in
                        separateEntryIDs.contains(entrySelectionID(file: file, entry: entry))
                            ? DiscoverySeparateEntry(path: file.path, address: entry.address)
                            : nil
                    }
                }
                appliedResult = try await apply(
                    selectedFilePaths.sorted(), separateEntries)
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

    private var automaticGroupMembership: [String: [String]] {
        var membership: [String: [String]] = [:]
        for file in plan.files where selectedFilePaths.contains(file.path) {
            for entry in file.entries {
                let selectionID = entrySelectionID(file: file, entry: entry)
                guard
                    !separateEntryIDs.contains(selectionID),
                    let groupID = entry.action.groupID
                else { continue }
                membership[groupID, default: []].append(selectionID)
            }
        }
        return membership
    }

    private var automaticGroupCounts: [String: Int] {
        automaticGroupMembership.mapValues(\.count)
    }

    private var automaticGroupPrimaryEntryIDs: Set<String> {
        Set(automaticGroupMembership.values.compactMap(\.first))
    }

    private var selectedSecretSummary: (new: Int, reused: Int) {
        var new = 0
        var reused = 0
        var seenGroups = Set<String>()
        for file in plan.files where selectedFilePaths.contains(file.path) {
            for entry in file.entries {
                let selectionID = entrySelectionID(file: file, entry: entry)
                if separateEntryIDs.contains(selectionID) {
                    new += 1
                    continue
                }
                switch entry.action.type {
                case "reuse_shared_secret":
                    reused += 1
                case "create_shared_secret", "reuse_discovered_secret":
                    guard let groupID = entry.action.groupID else {
                        new += 1
                        continue
                    }
                    if seenGroups.insert(groupID).inserted {
                        new += 1
                    } else {
                        reused += 1
                    }
                default:
                    break
                }
            }
        }
        return (new, reused)
    }
}

private struct ReferenceResolutionTarget: Identifiable {
    let file: DiscoveredFile
    let entry: DiscoveredEntry

    var id: String {
        entrySelectionID(file: file, entry: entry)
    }
}

private enum ReferenceValueSourceMode: String, Identifiable {
    case new
    case existing

    var id: String { rawValue }

    var title: String {
        switch self {
        case .new: "New Secret"
        case .existing: "Use Existing"
        }
    }
}

private struct ReferenceValueSheet: View {
    @Environment(\.dismiss) private var dismiss
    let target: ReferenceResolutionTarget
    let sharedSecrets: [WorkspaceResource]
    let resolve:
        (String, String, DiscoveryReferenceSource) async throws
            -> DiscoveryReferenceResolution
    let completed: () -> Void

    @State private var sourceMode: ReferenceValueSourceMode = .new
    @State private var name: String
    @State private var value = ""
    @State private var securityLevel = WorkspaceSecurityLevel.confirmation
    @State private var selectedResourceID: String
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(
        target: ReferenceResolutionTarget,
        sharedSecrets: [WorkspaceResource],
        resolve: @escaping
            (String, String, DiscoveryReferenceSource) async throws
                -> DiscoveryReferenceResolution,
        completed: @escaping () -> Void
    ) {
        self.target = target
        self.sharedSecrets = sharedSecrets.sorted { left, right in
            let leftMatches = left.defaultEnvKey == target.entry.key
            let rightMatches = right.defaultEnvKey == target.entry.key
            if leftMatches != rightMatches { return leftMatches }
            return left.name.localizedStandardCompare(right.name) == .orderedAscending
        }
        self.resolve = resolve
        self.completed = completed
        _name = State(initialValue: target.entry.key)
        _selectedResourceID = State(
            initialValue: self.sharedSecrets.first?.id ?? "")
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "key.fill")
                    .font(.title3)
                    .foregroundStyle(.blue)
                    .frame(width: 38, height: 38)
                    .background(Color.blue.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
                VStack(alignment: .leading, spacing: 2) {
                    Text("Add \(target.entry.key)")
                        .font(.title3.bold())
                    Text("Declared by \(target.file.relativePath)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(20)
            Divider()

            Form {
                Picker("Source", selection: $sourceMode) {
                    Text(ReferenceValueSourceMode.new.title)
                        .tag(ReferenceValueSourceMode.new)
                    if !sharedSecrets.isEmpty {
                        Text(ReferenceValueSourceMode.existing.title)
                            .tag(ReferenceValueSourceMode.existing)
                    }
                }
                .pickerStyle(.segmented)

                if sourceMode == .new {
                    TextField("Name", text: $name)
                    SecureField("Value", text: $value)
                    Picker("Security", selection: $securityLevel) {
                        ForEach(WorkspaceSecurityLevel.allCases, id: \.self) { level in
                            Label(level.title, systemImage: level.systemImage)
                                .tag(level)
                        }
                    }
                } else {
                    Picker("Shared Secret", selection: $selectedResourceID) {
                        ForEach(sharedSecrets) { resource in
                            VStack(alignment: .leading) {
                                Text(resource.name)
                                if let key = resource.defaultEnvKey {
                                    Text(key)
                                }
                            }
                            .tag(resource.id)
                        }
                    }
                    Text(existingSecretNote)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)

            Divider()
            HStack {
                Text("Adds this key only to the matching managed output.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Cancel") { dismiss() }
                    .disabled(isSaving)
                Button(action: save) {
                    if isSaving {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text("Add Value")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave || isSaving)
            }
            .padding(.horizontal, 20)
            .frame(height: 58)
        }
        .frame(width: 460, height: 390)
        .alert(
            "Value could not be added",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private var selectedResource: WorkspaceResource? {
        sharedSecrets.first { $0.id == selectedResourceID }
    }

    private var existingSecretNote: String {
        guard let selectedResource else { return "Choose a Shared Secret." }
        if selectedResource.defaultEnvKey == target.entry.key {
            return "The existing default key already matches this declaration."
        }
        return "This binding will export the secret as \(target.entry.key)."
    }

    private var canSave: Bool {
        guard target.file.managedSurfaceID != nil else { return false }
        switch sourceMode {
        case .new:
            return !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && !value.isEmpty
        case .existing:
            return selectedResource != nil
        }
    }

    private func save() {
        guard let surfaceID = target.file.managedSurfaceID, canSave else { return }
        let source: DiscoveryReferenceSource
        switch sourceMode {
        case .new:
            source = .newSharedSecret(
                name: name.trimmingCharacters(in: .whitespacesAndNewlines),
                value: value,
                enforcement: securityLevel.rawValue,
                metadata: ItemMetadata(
                    note: "Added from \(target.file.relativePath)",
                    links: []))
        case .existing:
            guard let selectedResource else { return }
            source = .existingSharedSecret(resourceID: selectedResource.id)
        }
        isSaving = true
        Task {
            defer { isSaving = false }
            do {
                _ = try await resolve(surfaceID, target.entry.key, source)
                completed()
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
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

private struct DiscoveryFileCard: View {
    let file: DiscoveredFile
    @Binding var selected: Bool
    let result: DiscoveryAppliedFile?
    let locked: Bool
    @Binding var separateEntryIDs: Set<String>
    let sharedGroupCounts: [String: Int]
    let automaticGroupCounts: [String: Int]
    let automaticGroupPrimaryEntryIDs: Set<String>
    let resolvedReferenceEntryIDs: Set<String>
    let resolveReference: (DiscoveredEntry) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack(spacing: 10) {
                Toggle("", isOn: $selected)
                    .labelsHidden()
                    .toggleStyle(.checkbox)
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
                }
                Spacer()
                Text(statusTitle)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(statusColor)
            }
            if !file.entries.isEmpty {
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
            ForEach(file.warnings) { warning in
                Label(
                    warning.line.map { "Line \($0): \(warning.message)" } ?? warning.message,
                    systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
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

    private var detail: String {
        var parts = [file.kind.displayTitle]
        if let environment = file.environment { parts.append(environment) }
        for tag in file.tags
        where !parts.contains(where: { $0.localizedCaseInsensitiveCompare(tag) == .orderedSame }) {
            parts.append(tag)
        }
        return parts.joined(separator: " · ")
    }

    private var actionTitle: String {
        switch file.action {
        case .compose: "\(file.entries.count) value\(file.entries.count == 1 ? "" : "s")"
        case .protect: "Protect in place"
        case .importSshIdentity: "Import identity"
        case .reference: "Reference only"
        case .review: "Review only"
        }
    }

    private var statusTitle: String {
        guard let result else {
            return locked && !selected ? "Not selected" : actionTitle
        }
        return switch result.outcome {
        case "imported": "Imported"
        case "protected": "Protected"
        case "failed": "Failed"
        default: "Skipped"
        }
    }

    private var statusColor: Color {
        guard let result else {
            return file.action == .review || file.action == .reference ? .secondary : color
        }
        return switch result.outcome {
        case "imported", "protected": .green
        case "failed": .red
        default: .secondary
        }
    }

    private var selectionHelp: String {
        if file.action == .reference {
            return "Reference configuration is used for review and remains unchanged."
        }
        if file.action == .review {
            return "Detected for review; automatic import is not supported yet."
        }
        if file.action == .compose && !file.warnings.isEmpty {
            return "Resolve unsupported content before importing this file."
        }
        if file.action == .compose && file.entries.isEmpty {
            return "No statically importable values were found."
        }
        return selected ? "Include in this import" : "Leave this file unchanged"
    }

    private func entryActionTitle(_ type: String) -> String {
        if file.action == .reference {
            return "Declared key"
        }
        if file.action == .review {
            return "Detected"
        }
        return switch type {
        case "reuse_shared_secret": "Reuse"
        case "create_shared_secret": "New secret"
        case "create_env_file_entry": "Keep section"
        case "keep_in_protected_file": "Protect in place"
        default: "Include"
        }
    }

    @ViewBuilder
    private func entryAction(_ entry: DiscoveredEntry) -> some View {
        let selectionID = entrySelectionID(file: file, entry: entry)
        let isSeparate = separateEntryIDs.contains(selectionID)
        if entry.action.type == "reference_entry" {
            if referenceIsCovered(entry) {
                Text("Covered")
                    .font(.caption)
                    .foregroundStyle(.green)
            } else if file.managedSurfaceID != nil {
                Button("Add value…") {
                    resolveReference(entry)
                }
                .font(.caption)
                .buttonStyle(.borderless)
                .foregroundStyle(.orange)
            } else {
                Text("Missing value")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        } else if supportsIsolationChoice(entry) {
            Menu {
                Button {
                    separateEntryIDs.remove(selectionID)
                } label: {
                    if isSeparate {
                        Text(automaticEntryActionTitle(entry, selectionID: selectionID))
                    } else {
                        Label(
                            automaticEntryActionTitle(entry, selectionID: selectionID),
                            systemImage: "checkmark")
                    }
                }
                Button {
                    separateEntryIDs.insert(selectionID)
                } label: {
                    if isSeparate {
                        Label("Create separate secret", systemImage: "checkmark")
                    } else {
                        Text("Create separate secret")
                    }
                }
            } label: {
                Text(
                    isSeparate
                        ? "Separate"
                        : automaticEntryActionTitle(entry, selectionID: selectionID))
                .font(.caption)
                .foregroundStyle(isSeparate ? Color.orange : Color.green)
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(maxWidth: 220, alignment: .trailing)
            }
            .menuStyle(.borderlessButton)
            .disabled(locked || !selected || !file.canApplyDiscovery)
        } else {
            Text(automaticEntryActionTitle(entry, selectionID: selectionID))
                .font(.caption)
                .foregroundStyle(entryActionColor(entry))
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

    private func automaticEntryActionTitle(
        _ entry: DiscoveredEntry, selectionID: String
    ) -> String {
        switch entry.action.type {
        case "reuse_shared_secret":
            return entry.action.resourceName.map { "Reuse \($0)" } ?? "Reuse existing"
        case "create_shared_secret", "reuse_discovered_secret":
            guard
                let groupID = entry.action.groupID,
                automaticGroupCounts[groupID, default: 0] > 1
            else { return "New secret" }
            return automaticGroupPrimaryEntryIDs.contains(selectionID)
                ? "New shared secret"
                : "Share in import"
        case "reference_entry":
            return referenceIsCovered(entry) ? "Covered" : "Missing value"
        default:
            return entryActionTitle(entry.action.type)
        }
    }

    private func entryActionColor(_ entry: DiscoveredEntry) -> Color {
        guard entry.action.type == "reference_entry" else { return .secondary }
        return referenceIsCovered(entry) ? .green : .orange
    }

    private func referenceIsCovered(_ entry: DiscoveredEntry) -> Bool {
        entry.action.matched == true
            || resolvedReferenceEntryIDs.contains(entrySelectionID(file: file, entry: entry))
    }

    private var icon: String {
        switch file.kind {
        case .dotenv: "doc.text"
        case .direnv, .mise: "terminal"
        case .awsCredentials: "cloud"
        case .pgpass: "cylinder"
        case .sshPrivateKey: "key.horizontal.fill"
        }
    }

    private var color: Color {
        switch file.action {
        case .compose: .blue
        case .protect: .orange
        case .importSshIdentity: .green
        case .reference: .secondary
        case .review: .secondary
        }
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
        }
    }
}
