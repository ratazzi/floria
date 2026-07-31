import AppKit
import SwiftUI

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}

private func copyToPasteboard(_ value: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
}

private func openMetadataLink(_ link: ItemLink) {
    guard let url = URL(string: link.url) else { return }
    NSWorkspace.shared.open(url)
}

private struct EditableItemLink: Identifiable {
    let id = UUID()
    var label: String
    var url: String

    init(label: String = "", url: String = "") {
        self.label = label
        self.url = url
    }
}

private func editableLinks(_ metadata: ItemMetadata) -> [EditableItemLink] {
    metadata.links.map { EditableItemLink(label: $0.label, url: $0.url) }
}

private func itemMetadata(note: String, links: [EditableItemLink]) -> ItemMetadata {
    ItemMetadata(
        note: note,
        links: links.map { ItemLink(label: $0.label, url: $0.url) })
}

private struct ItemMetadataEditor: View {
    @Binding var note: String
    @Binding var links: [EditableItemLink]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 7) {
                Text("Note (optional)").font(.callout.weight(.medium))
                TextEditor(text: $note)
                    .scrollContentBackground(.hidden)
                    .padding(7)
                    .frame(height: 66)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 7))
                    .overlay {
                        RoundedRectangle(cornerRadius: 7)
                            .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
                    }
            }

            VStack(alignment: .leading, spacing: 7) {
                HStack {
                    Text("Links").font(.callout.weight(.medium))
                    Spacer()
                    Button("Add Link", systemImage: "plus") {
                        links.append(EditableItemLink())
                    }
                    .buttonStyle(.borderless)
                    .disabled(links.count >= 16)
                }
                ForEach($links) { $link in
                    HStack(spacing: 7) {
                        TextField("Label", text: $link.label)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 135)
                        TextField("https://…", text: $link.url)
                            .textFieldStyle(.roundedBorder)
                        Button(role: .destructive) {
                            links.removeAll { $0.id == link.id }
                        } label: {
                            Image(systemName: "minus.circle.fill")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Remove link")
                    }
                }
                if links.isEmpty {
                    Text("Add dashboards, documentation, or service pages for quick access.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Label(
                "Notes and links are stored as plaintext metadata. Do not put credentials here.",
                systemImage: "info.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private struct SecurityLevelPicker: View {
    @Binding var selection: WorkspaceSecurityLevel

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("Security Level").font(.callout.weight(.medium))
            Picker("Security Level", selection: $selection) {
                ForEach(WorkspaceSecurityLevel.allCases, id: \.self) { level in
                    Label(level.title, systemImage: level.systemImage).tag(level)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            Text(selection.detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private struct SecurityLevelBadge: View {
    let level: WorkspaceSecurityLevel

    private var color: Color {
        switch level {
        case .auditOnly: .secondary
        case .confirmation: .blue
        case .touchID: .orange
        }
    }

    var body: some View {
        Label(level.compactTitle, systemImage: level.systemImage)
            .font(.caption.weight(.medium))
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.1), in: Capsule())
    }
}

private struct SecurityLevelMenu: View {
    let level: WorkspaceSecurityLevel
    let update: (WorkspaceSecurityLevel) async throws -> Void
    @State private var isSaving = false
    @State private var errorMessage: String?

    var body: some View {
        Menu {
            ForEach(WorkspaceSecurityLevel.allCases, id: \.self) { option in
                Button {
                    setLevel(option)
                } label: {
                    Label(
                        option.title,
                        systemImage: option == level ? "checkmark" : option.systemImage)
                }
                .disabled(option == level)
            }
        } label: {
            Group {
                if isSaving {
                    ProgressView()
                        .controlSize(.small)
                        .frame(minWidth: 42)
                } else {
                    SecurityLevelBadge(level: level)
                }
            }
            .contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .disabled(isSaving)
        .help("Change Security Level")
        .accessibilityLabel("Security Level")
        .accessibilityValue(level.title)
        .alert(
            "Couldn't Change Security Level",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func setLevel(_ newLevel: WorkspaceSecurityLevel) {
        guard newLevel != level, !isSaving else { return }
        isSaving = true
        Task {
            defer { isSaving = false }
            do {
                try await update(newLevel)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private func defaultEnvironmentFileName(_ name: String) -> String {
    let slug = name
        .lowercased()
        .replacingOccurrences(of: "[^a-z0-9]+", with: "-", options: .regularExpression)
        .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    return ".env.\(slug.isEmpty ? "environment" : slug)"
}

private func availableEnvironmentFileName(
    _ name: String, in project: WorkspaceProject?
) -> String {
    let base = defaultEnvironmentFileName(name)
    let used = Set(project?.environments.flatMap(\.surfaces).map(\.name) ?? [])
    guard used.contains(base) else { return base }
    var suffix = 2
    while used.contains("\(base).\(suffix)") { suffix += 1 }
    return "\(base).\(suffix)"
}

enum WorkspaceSidebarSelection: Hashable {
    case projects
    case project(WorkspaceProject.ID)
    case library
    case protectedFiles
    case sharedSecrets
    case envFiles
    case sshAgents
    case accessLog
}

/// Main product workspace: choose a project and environment, compose typed bindings,
/// then inspect the concrete file/socket surfaces exposed to local processes.
struct AdvancedWorkspaceView: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var state: AppState
    private let initialSelection: WorkspaceSidebarSelection
    @State private var selection: WorkspaceSidebarSelection?
    @State private var search = ""
    @State private var showingNewProject = false
    @State private var showingProtectFile = false
    @State private var showingNewSharedSecret = false
    @State private var showingNewEnvFile = false
    @State private var showingImportSshIdentity = false
    @State private var showingConnectExternalAgent = false
    @State private var pendingAuditWindow: AuditOnlyWindow?
    @State private var showingAuditConfirmation = false
    @FocusState private var searchIsFocused: Bool

    init(
        state: AppState,
        initialSelection: WorkspaceSidebarSelection = .projects
    ) {
        self.state = state
        self.initialSelection = initialSelection
        _selection = State(initialValue: initialSelection)
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
                .frame(width: 252)
            Divider()
            VStack(spacing: 0) {
                workspaceToolbar
                Divider()
                detail
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .ignoresSafeArea(.container, edges: .top)
        .focusedSceneValue(\.focusAppSearch) {
            searchIsFocused = true
        }
        .onAppear {
            guard case .project(let projectID) = initialSelection else { return }
            state.workspace.selectProject(projectID)
            selection = initialSelection
        }
        .onChange(of: selection) {
            guard case .project(let id) = selection else { return }
            state.workspace.selectProject(id)
        }
        .sheet(isPresented: $showingNewProject) {
            NewProjectSheet(store: state.workspace) { projectID in
                selection = .project(projectID)
            }
        }
        .sheet(isPresented: $showingProtectFile) {
            ProtectExistingFileSheet(store: state.workspace)
        }
        .sheet(isPresented: $showingNewSharedSecret) {
            NewSharedSecretSheet(store: state.workspace)
        }
        .sheet(isPresented: $showingNewEnvFile) {
            NewEnvFileSheet(store: state.workspace)
        }
        .sheet(isPresented: $showingImportSshIdentity) {
            ImportSshIdentitySheet(store: state.workspace)
        }
        .sheet(isPresented: $showingConnectExternalAgent) {
            NewSshAgentSheet(store: state.workspace)
        }
        .alert(
            "Floria could not update the workspace",
            isPresented: Binding(
                get: { state.workspace.lastError != nil },
                set: { if !$0 { state.workspace.lastError = nil } })
        ) {
            Button("OK") { state.workspace.lastError = nil }
        } message: {
            Text(state.workspace.lastError ?? "Unknown error")
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

    private var workspaceToolbar: some View {
        HStack(spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search current view", text: $search)
                    .textFieldStyle(.plain)
                    .focused($searchIsFocused)
                    .onExitCommand {
                        if search.isEmpty {
                            dismiss()
                        } else {
                            search = ""
                        }
                    }
            }
            .padding(.horizontal, 12)
            .frame(maxWidth: 430)
            .frame(height: 34)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.secondary.opacity(0.22), lineWidth: 1)
            }

            Menu {
                Button("New Project", systemImage: "folder.badge.plus") {
                    showingNewProject = true
                }
                Button("Protect Existing File", systemImage: "lock.fill") {
                    showingProtectFile = true
                }
                Button("New Shared Secret", systemImage: "key.fill") {
                    showingNewSharedSecret = true
                }
                Button("New Env File", systemImage: "doc.badge.plus") {
                    showingNewEnvFile = true
                }
                Button("Import SSH Private Key", systemImage: "key.horizontal.fill") {
                    showingImportSshIdentity = true
                }
                Button("Connect External SSH Agent", systemImage: "network") {
                    showingConnectExternalAgent = true
                }
            } label: {
                Image(systemName: "plus")
                    .frame(width: 30, height: 30)
            }
            .buttonStyle(.bordered)
            .accessibilityLabel("Add workspace item")

            Spacer(minLength: 16)

            Menu {
                Button(state.connected ? "Daemon connected" : "Daemon disconnected") { }
                    .disabled(true)
                if state.policyMode.isAuditOnly() {
                    Button("Audit Only is active", systemImage: "eye.fill") { }
                        .disabled(true)
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
                Divider()
                Button("Refresh Library", systemImage: "arrow.clockwise") {
                    Task {
                        await state.workspace.reload(reportErrors: true)
                        await state.reloadPolicyMode()
                    }
                }
                Divider()
                Button("Open Access Log", systemImage: "clock") {
                    selection = .accessLog
                }
            } label: {
                HStack(spacing: 8) {
                    Image(
                        systemName: state.policyMode.isAuditOnly()
                            ? "eye.circle.fill" : "checkmark.shield.fill")
                        .foregroundStyle(
                            state.policyMode.isAuditOnly()
                                ? Color.orange
                                : (state.connected ? Color.green : Color.secondary))
                    Image(systemName: "chevron.down")
                        .font(.caption)
                }
                .frame(height: 30)
            }
            .buttonStyle(.bordered)
            .accessibilityLabel(
                state.policyMode.isAuditOnly()
                    ? "Audit Only policy"
                    : (state.connected ? "Protected policy" : "Daemon offline"))
        }
        .padding(.horizontal, 18)
        .frame(height: 90)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: 8) {
                        FloriaMark()
                            .frame(width: 26, height: 26)
                        Text("Floria")
                            .font(.title2.bold())
                    }
                    .padding(.horizontal, 18)
                    .padding(.top, 55)
                    .padding(.bottom, 24)

                    sidebarSectionTitle("Library")
                    VStack(spacing: 3) {
                        sidebarRow("Projects", systemImage: "folder", tag: .projects)
                        sidebarRow("All Items", systemImage: "books.vertical", tag: .library)
                        sidebarRow(
                            "Access Log",
                            systemImage: "clock.arrow.trianglehead.counterclockwise.rotate.90",
                            tag: .accessLog)
                    }

                    Divider()
                        .padding(.horizontal, 14)
                        .padding(.vertical, 18)

                    sidebarSectionTitle("Projects")
                    VStack(spacing: 3) {
                        ForEach(filteredProjects) { project in
                            sidebarRow(
                                project.name,
                                systemImage: "folder",
                                tag: .project(project.id))
                        }
                    }
                }
                .padding(.bottom, 16)
            }

            Divider()
            HStack(spacing: 7) {
                Circle()
                    .fill(
                        state.policyMode.isAuditOnly()
                            ? Color.orange
                            : (state.connected ? Color.green : Color.secondary.opacity(0.45)))
                    .frame(width: 8, height: 8)
                Text(
                    state.policyMode.isAuditOnly()
                        ? "Audit Only · daemon running"
                        : (state.connected ? "Daemon running" : "Daemon starting"))
                    .font(.caption)
                    .foregroundStyle(
                        state.policyMode.isAuditOnly()
                            ? Color.orange
                            : (state.connected ? Color.green : Color.secondary))
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 8)
            .background(
                state.policyMode.isAuditOnly()
                    ? Color.orange.opacity(0.10)
                    : (state.connected ? Color.green.opacity(0.09) : Color.secondary.opacity(0.08)),
                in: RoundedRectangle(cornerRadius: 7))
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private func sidebarSectionTitle(_ title: String) -> some View {
        Text(title)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 18)
            .padding(.bottom, 7)
    }

    private func sidebarRow(
        _ title: String,
        systemImage: String,
        tag: WorkspaceSidebarSelection
    ) -> some View {
        Button {
            selection = tag
        } label: {
            HStack(spacing: 10) {
                Image(systemName: systemImage)
                    .foregroundStyle(selection == tag ? Color.accentColor : Color.secondary)
                    .frame(width: 18)
                Text(title)
                    .foregroundStyle(selection == tag ? Color.primary : Color.secondary)
                Spacer(minLength: 0)
            }
            .font(.callout)
            .padding(.horizontal, 11)
            .frame(height: 34)
            .contentShape(Rectangle())
            .background(
                selection == tag ? Color.accentColor.opacity(0.11) : Color.clear,
                in: RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 8)
    }

    private var filteredProjects: [WorkspaceProject] {
        guard !search.isEmpty else { return state.workspace.projects }
        return state.workspace.projects.filter {
            $0.name.localizedCaseInsensitiveContains(search)
                || $0.path.localizedCaseInsensitiveContains(search)
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch selection {
        case .projects:
            ProjectCatalogView(
                store: state.workspace, selection: $selection, search: search,
                addProject: { showingNewProject = true })
        case .project:
            if state.workspace.selectedProject != nil {
                ProjectWorkspaceView(
                    store: state.workspace, state: state,
                    onProjectRemoved: { selection = .projects })
            } else {
                ContentUnavailableView("Select a project", systemImage: "folder")
            }
        case .library:
            LibraryCatalogView(store: state.workspace, search: search)
        case .protectedFiles:
            ProtectedFilesView(
                store: state.workspace, search: search,
                protectFile: { showingProtectFile = true })
        case .sharedSecrets:
            ResourceCatalogView(
                store: state.workspace, title: "Shared Secrets",
                subtitle: "Reusable scalar values with a default environment key",
                kinds: [.sharedSecret, .secret], search: search,
                addResourceTitle: "Add Secret", addResource: { showingNewSharedSecret = true })
        case .envFiles:
            ResourceCatalogView(
                store: state.workspace, title: "Env Files",
                subtitle: "Reusable groups of environment variables",
                kinds: [.envFile], search: search,
                addResourceTitle: "Add Env File", addResource: { showingNewEnvFile = true })
        case .sshAgents:
            SshAgentsCatalogView(
                store: state.workspace, search: search,
                importIdentity: { showingImportSshIdentity = true },
                connectExternalAgent: { showingConnectExternalAgent = true })
        case .accessLog:
            AccessLogView(state: state)
        case nil:
            ContentUnavailableView("Select a project", systemImage: "folder")
        }
    }
}

private enum ProjectWorkspaceTab: String, CaseIterable {
    case bindings = "Bindings"
    case preview = "Preview"
    case access = "Access"

    var systemImage: String {
        switch self {
        case .bindings: "link"
        case .preview: "eye"
        case .access: "person.2"
        }
    }
}

private struct ProjectWorkspaceView: View {
    @Bindable var store: WorkspaceStore
    @Bindable var state: AppState
    let onProjectRemoved: () -> Void
    @State private var tab = ProjectWorkspaceTab.bindings
    @State private var showingAddBinding = false
    @State private var showingNewEnvironment = false
    @State private var showingAddDotenvFile = false
    @State private var showingAddDirenvFile = false
    @State private var showingAddIniFile = false
    @State private var showingAddDirectEnvFile = false
    @State private var showingAddLinesFile = false
    @State private var showingAddSshAgent = false
    @State private var confirmingRemoveProject = false
    @State private var confirmingRemoveEnvironment = false

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                projectHeader
                ProjectTabBar(selection: $tab)
                Divider()
                switch tab {
                case .bindings:
                    BindingsPane(store: store, showingAddBinding: $showingAddBinding)
                case .preview:
                    EnvironmentPreviewPane(store: store)
                case .access:
                    ProjectAccessPane(state: state)
                }
            }
            .frame(minWidth: 500, idealWidth: 720)

            Divider()
            SurfaceInspector(
                store: store,
                addDotenvFile: { showingAddDotenvFile = true },
                addDirenvFile: { showingAddDirenvFile = true },
                addIniFile: { showingAddIniFile = true },
                addDirectEnvFile: { showingAddDirectEnvFile = true },
                addLinesFile: { showingAddLinesFile = true },
                addSshAgent: { showingAddSshAgent = true })
                .frame(width: 390)
        }
        .sheet(isPresented: $showingAddBinding) {
            AddBindingSheet(store: store)
        }
        .sheet(isPresented: $showingAddDirectEnvFile) {
            AddDirectEnvFileSurfaceSheet(store: store)
        }
        .sheet(isPresented: $showingAddDotenvFile) {
            AddDotenvSurfaceSheet(store: store)
        }
        .sheet(isPresented: $showingAddDirenvFile) {
            AddDirenvSurfaceSheet(store: store)
        }
        .sheet(isPresented: $showingAddIniFile) {
            AddIniSurfaceSheet(store: store)
        }
        .sheet(isPresented: $showingAddLinesFile) {
            AddLinesSurfaceSheet(store: store)
        }
        .sheet(isPresented: $showingAddSshAgent) {
            AddSshAgentSurfaceSheet(store: store)
        }
        .sheet(isPresented: $showingNewEnvironment) {
            NewEnvironmentSheet(store: store)
        }
        .alert("Remove project from Floria?", isPresented: $confirmingRemoveProject) {
            Button("Cancel", role: .cancel) { }
            Button("Remove Project", role: .destructive) {
                guard let id = store.selectedProject?.id else { return }
                Task {
                    do {
                        try await store.removeProject(id)
                        onProjectRemoved()
                    } catch {
                        store.lastError = error.localizedDescription
                    }
                }
            }
        } message: {
            Text("Managed output links are removed safely. Project files and stored resources are kept.")
        }
        .alert("Remove environment?", isPresented: $confirmingRemoveEnvironment) {
            Button("Cancel", role: .cancel) { }
            Button("Remove Environment", role: .destructive) {
                guard let id = store.selectedEnvironment?.id else { return }
                Task {
                    do {
                        try await store.removeEnvironment(id)
                    } catch {
                        store.lastError = error.localizedDescription
                    }
                }
            }
        } message: {
            Text("Its bindings and outputs are removed. Shared resources are kept.")
        }
        .navigationTitle(store.selectedProject?.name ?? "Project")
    }

    private var projectHeader: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(store.selectedProject?.name ?? "Project")
                        .font(.title2.bold())
                    Text(store.selectedProject?.path ?? "")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Menu {
                    Button("Add Environment", systemImage: "plus") {
                        showingNewEnvironment = true
                    }
                    Button("Open Project in Finder", systemImage: "folder") {
                        guard let path = store.selectedProject?.path else { return }
                        NSWorkspace.shared.open(URL(fileURLWithPath: path))
                    }
                    Button("Copy Project Path", systemImage: "doc.on.doc") {
                        guard let path = store.selectedProject?.path else { return }
                        copyToPasteboard(path)
                    }
                    Divider()
                    Button("Remove Current Environment", systemImage: "minus.circle", role: .destructive) {
                        confirmingRemoveEnvironment = true
                    }
                    .disabled((store.selectedProject?.environments.count ?? 0) <= 1)
                    Button("Remove Project", systemImage: "trash", role: .destructive) {
                        confirmingRemoveProject = true
                    }
                } label: {
                    Image(systemName: "ellipsis")
                }
                .buttonStyle(.bordered)
            }

            HStack(spacing: 10) {
                Text("Environment")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Picker(
                    "Environment",
                    selection: Binding(
                        get: { store.selectedEnvironmentID },
                        set: { store.selectEnvironment($0) })
                ) {
                    ForEach(store.selectedProject?.environments ?? []) { environment in
                        Text(environment.name).tag(environment.id)
                    }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .frame(maxWidth: 260, alignment: .leading)
                Button {
                    showingNewEnvironment = true
                } label: {
                    Image(systemName: "plus")
                }
                .buttonStyle(.borderless)
                .help("Add environment")
            }
        }
        .padding(.horizontal, 24)
        .padding(.top, 20)
        .padding(.bottom, 14)
    }
}

private struct ProjectTabBar: View {
    @Binding var selection: ProjectWorkspaceTab

    var body: some View {
        HStack(spacing: 4) {
            ForEach(ProjectWorkspaceTab.allCases, id: \.self) { tab in
                Button {
                    selection = tab
                } label: {
                    Label(tab.rawValue, systemImage: tab.systemImage)
                        .font(.callout.weight(selection == tab ? .semibold : .regular))
                        .foregroundStyle(selection == tab ? Color.accentColor : Color.secondary)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(selection == tab ? Color.accentColor.opacity(0.09) : Color.clear)
                        .clipShape(RoundedRectangle(cornerRadius: 7))
                }
                .buttonStyle(.plain)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }
}

private struct BindingsPane: View {
    @Bindable var store: WorkspaceStore
    @Binding var showingAddBinding: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Bindings").font(.title3.bold())
                    Text("Compose this environment from reusable resources")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                BindingSection(
                    title: "Shared across environments", bindings: store.commonBindings,
                    store: store)
                BindingSection(
                    title: "\(store.selectedEnvironment?.name ?? "Environment") only",
                    bindings: store.environmentBindings, store: store)

                Button {
                    showingAddBinding = true
                } label: {
                    Label("Add binding", systemImage: "plus")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .overlay {
                    RoundedRectangle(cornerRadius: 9)
                        .stroke(
                            Color.secondary.opacity(0.45),
                            style: StrokeStyle(lineWidth: 1, dash: [5, 4]))
                }

                HStack(spacing: 7) {
                    Image(
                        systemName: store.conflictingKeys.isEmpty
                            ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(store.conflictingKeys.isEmpty ? Color.green : Color.orange)
                    if store.conflictingKeys.isEmpty {
                        Text("\(store.resolvedExports.count) keys · No conflicts")
                    } else {
                        Text("Conflicts: \(store.conflictingKeys.sorted().joined(separator: ", "))")
                    }
                }
                .font(.callout)
                .foregroundStyle(.secondary)
            }
            .padding(24)
        }
    }
}

private struct BindingSection: View {
    let title: String
    let bindings: [WorkspaceBinding]
    @Bindable var store: WorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.callout.weight(.semibold))
                .foregroundStyle(.secondary)
            VStack(spacing: 0) {
                ForEach(Array(bindings.enumerated()), id: \.element.id) { index, binding in
                    if let resource = store.resource(binding.resourceID) {
                        BindingRow(binding: binding, resource: resource, store: store)
                        if index < bindings.count - 1 { Divider().padding(.leading, 56) }
                    }
                }
                if bindings.isEmpty {
                    Text("No bindings in this scope")
                        .font(.callout)
                        .foregroundStyle(.tertiary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                }
            }
            .background(Color.primary.opacity(0.025))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay {
                RoundedRectangle(cornerRadius: 10)
                    .stroke(Color.secondary.opacity(0.18), lineWidth: 1)
            }
        }
    }
}

private struct BindingRow: View {
    let binding: WorkspaceBinding
    let resource: WorkspaceResource
    @Bindable var store: WorkspaceStore

    private var summary: String {
        guard resource.entries.count > 1 else { return resource.exportSummary }
        let selected = binding.selection.addresses(in: resource).count
        return "\(selected) of \(resource.entries.count) entries"
    }

    var body: some View {
        HStack(spacing: 12) {
            ResourceIcon(kind: resource.kind)
            VStack(alignment: .leading, spacing: 3) {
                Text(resource.name)
                    .font(.body.weight(.medium))
                HStack(spacing: 7) {
                    ResourceKindBadge(kind: resource.kind)
                    Text(summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            Spacer(minLength: 8)
            Toggle(
                "",
                isOn: Binding(
                    get: { binding.isEnabled },
                    set: { _ in Task { await store.toggleBinding(binding.id) } })
            )
            .toggleStyle(.switch)
            .labelsHidden()
            .controlSize(.small)
            Menu {
                Button(
                    resource.entries.isEmpty ? "Copy Export Names" : "Copy Entry Addresses",
                    systemImage: "doc.on.doc"
                ) {
                    let values = resource.entries.isEmpty
                        ? resource.exports.map(\.key)
                        : binding.selection.addresses(in: resource)
                    copyToPasteboard(values.joined(separator: "\n"))
                }
                Divider()
                Button("Remove Binding", systemImage: "trash", role: .destructive) {
                    Task {
                        do {
                            try await store.removeBinding(binding.id)
                        } catch {
                            store.lastError = error.localizedDescription
                        }
                    }
                }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .accessibilityLabel("More")
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .opacity(binding.isEnabled ? 1 : 0.52)
    }
}

private struct EnvironmentPreviewPane: View {
    @Bindable var store: WorkspaceStore

    var body: some View {
        List(store.resolvedExports) { export in
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(export.key).font(.body.monospaced())
                    Text(export.resourceName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(export.sensitive ? "••••••••" : export.previewValue)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            .padding(.vertical, 4)
        }
        .overlay {
            if store.resolvedExports.isEmpty {
                ContentUnavailableView("No exported values", systemImage: "eye.slash")
            }
        }
    }
}

private struct ProjectAccessPane: View {
    @Bindable var state: AppState

    var body: some View {
        List(state.recents.prefix(100)) { event in
            HStack(spacing: 10) {
                Circle()
                    .fill(event.allowed ? Color.green : Color.red)
                    .frame(width: 7, height: 7)
                VStack(alignment: .leading, spacing: 2) {
                    Text(event.shownPath)
                    Text("\(event.exe) · \(event.operation)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(event.time)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.tertiary)
            }
            .padding(.vertical, 3)
        }
        .overlay {
            if state.recents.isEmpty {
                ContentUnavailableView("No project access yet", systemImage: "clock")
            }
        }
    }
}

private struct SurfaceInspector: View {
    @Bindable var store: WorkspaceStore
    let addDotenvFile: () -> Void
    let addDirenvFile: () -> Void
    let addIniFile: () -> Void
    let addDirectEnvFile: () -> Void
    let addLinesFile: () -> Void
    let addSshAgent: () -> Void
    @State private var showingManageSurface = false
    @State private var confirmingRemoval = false
    @State private var errorMessage: String?

    var body: some View {
        Group {
            if let surface = store.selectedSurface, let environment = store.selectedEnvironment {
                VStack(spacing: 0) {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Picker(
                                "Surface",
                                selection: Binding(
                                    get: { store.selectedSurfaceID },
                                    set: { store.selectedSurfaceID = $0 })
                            ) {
                                ForEach(environment.surfaces) { surface in
                                    Label(surface.name, systemImage: surface.kind.systemImage)
                                        .tag(surface.id)
                                }
                            }
                            .pickerStyle(.menu)
                            .labelsHidden()
                            .font(.headline)
                            Spacer()
                            Menu {
                                Button("Composed Env Output", systemImage: "doc.text") {
                                    addDotenvFile()
                                }
                                Button("direnv Output", systemImage: "terminal") {
                                    addDirenvFile()
                                }
                                Button("INI Output", systemImage: "list.bullet.rectangle") {
                                    addIniFile()
                                }
                                Button("Direct EnvFile Output", systemImage: "doc.text.fill") {
                                    addDirectEnvFile()
                                }
                                Button("Lines Output", systemImage: "text.line.first.and.arrowtriangle.forward") {
                                    addLinesFile()
                                }
                                Button("SSH Agent Socket", systemImage: "network") {
                                    addSshAgent()
                                }
                            } label: {
                                Image(systemName: "plus")
                            }
                            .buttonStyle(.borderless)
                            .help("Add output surface")
                            Menu {
                                Button("Edit Output…", systemImage: "pencil") {
                                    showingManageSurface = true
                                }
                                Button("Open in Finder", systemImage: "folder") {
                                    revealSurface(surface)
                                }
                                Divider()
                                Button(
                                    "Delete Output…", systemImage: "trash",
                                    role: .destructive
                                ) {
                                    confirmingRemoval = true
                                }
                            } label: {
                                Image(systemName: "ellipsis")
                                    .frame(width: 22, height: 22)
                            }
                            .menuStyle(.borderlessButton)
                            .fixedSize()
                            .accessibilityLabel("Output actions")
                            SurfaceStatusBadge(status: surface.status)
                        }
                        HStack(spacing: 10) {
                            Text(surface.path)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                                .truncationMode(.middle)
                                .textSelection(.enabled)
                            Spacer(minLength: 4)
                            SecurityLevelMenu(level: surface.securityLevel) { securityLevel in
                                try await store.updateSurfaceSecurityLevel(
                                    surface.id, securityLevel: securityLevel)
                            }
                        }
                    }
                    .padding(20)

                    Divider()
                    switch surface.kind {
                    case .dotenvFile:
                        DotenvSurfacePreview(
                            store: store, openInFinder: { revealSurface(surface) },
                            manageLink: { showingManageSurface = true })
                    case .direnvFile:
                        DirenvSurfacePreview(
                            store: store, openInFinder: { revealSurface(surface) },
                            manageLink: { showingManageSurface = true })
                    case .iniFile:
                        IniSurfacePreview(
                            store: store, openInFinder: { revealSurface(surface) },
                            manageLink: { showingManageSurface = true })
                    case .envFileDirect:
                        DirectEnvFileSurfacePreview(
                            store: store, openInFinder: { revealSurface(surface) },
                            manageLink: { showingManageSurface = true })
                    case .linesFile:
                        LinesSurfacePreview(
                            store: store, openInFinder: { revealSurface(surface) },
                            manageLink: { showingManageSurface = true })
                    case .unixSocket:
                        SocketSurfacePreview(
                            store: store, copyPath: { copyToPasteboard(surface.path) },
                            manageSocket: { showingManageSurface = true })
                    }
                }
                .background(Color.primary.opacity(0.018))
            } else {
                VStack(spacing: 12) {
                    ContentUnavailableView("No output surface", systemImage: "doc.badge.plus")
                    Menu("Add Output", systemImage: "plus") {
                        Button("Composed Env Output", action: addDotenvFile)
                        Button("direnv Output", action: addDirenvFile)
                        Button("INI Output", action: addIniFile)
                        Button("Direct EnvFile Output", action: addDirectEnvFile)
                        Button("Lines Output", action: addLinesFile)
                        Button("SSH Agent Socket", action: addSshAgent)
                    }
                    .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.primary.opacity(0.018))
            }
        }
        .sheet(isPresented: $showingManageSurface) {
            if let surface = store.selectedSurface {
                ManageSurfaceSheet(store: store, surface: surface)
            }
        }
        .alert("Delete output?", isPresented: $confirmingRemoval) {
            Button("Cancel", role: .cancel) { }
            Button("Delete Output", role: .destructive) {
                guard let surface = store.selectedSurface else { return }
                Task {
                    do {
                        try await store.deleteSurface(surface.id)
                    } catch {
                        errorMessage = error.localizedDescription
                    }
                }
            }
        } message: {
            Text("Its resources and project bindings are kept. Floria removes only its managed link.")
        }
        .alert(
            "Could not delete output",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func revealSurface(_ surface: WorkspaceSurface) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: surface.path)])
    }
}

private struct IniSurfacePreview: View {
    @Bindable var store: WorkspaceStore
    let openInFinder: () -> Void
    let manageLink: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(store.resolvedIniEntries) { entry in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(entry.label) = ••••••••••••")
                                .font(.callout.monospaced())
                                .lineLimit(2)
                                .truncationMode(.middle)
                            Text(entry.resourceName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        Divider().padding(.leading, 20)
                    }
                    if store.resolvedIniEntries.isEmpty {
                        ContentUnavailableView(
                            "No INI entries", systemImage: "list.bullet.rectangle",
                            description: Text("Bind an INI Env File and select its sections first."))
                            .padding(24)
                    }
                }
            }
            SurfaceFooter(
                primaryTitle: "Manage Link", secondaryTitle: "Open in Finder",
                note: "Generated on open · Read only · Section order preserved",
                primaryAction: manageLink, secondaryAction: openInFinder)
        }
    }
}

private struct LinesSurfacePreview: View {
    @Bindable var store: WorkspaceStore
    let openInFinder: () -> Void
    let manageLink: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(store.resolvedLineEntries) { entry in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("••••••••••••")
                                .font(.callout.monospaced())
                            Text("\(entry.label) · \(entry.resourceName)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        Divider().padding(.leading, 20)
                    }
                    if store.resolvedLineEntries.isEmpty {
                        ContentUnavailableView(
                            "No keyless values",
                            systemImage: "text.line.first.and.arrowtriangle.forward",
                            description: Text(
                                "Bind a Shared Secret without a default environment key first."))
                            .padding(24)
                    }
                }
            }
            SurfaceFooter(
                primaryTitle: "Manage Link", secondaryTitle: "Open in Finder",
                note: "One value per line · Read only · Binding order preserved",
                primaryAction: manageLink, secondaryAction: openInFinder)
        }
    }
}

private struct DotenvSurfacePreview: View {
    @Bindable var store: WorkspaceStore
    let openInFinder: () -> Void
    let manageLink: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(store.resolvedExports) { export in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(export.key)=\(export.sensitive ? "••••••••••••" : export.previewValue)")
                                .font(.callout.monospaced())
                                .lineLimit(2)
                                .truncationMode(.middle)
                            ResourceKindBadge(kind: export.resourceKind, label: export.resourceName)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        Divider().padding(.leading, 20)
                    }
                }
            }
            SurfaceFooter(
                primaryTitle: "Manage Link", secondaryTitle: "Open in Finder",
                note: "Generated on open · Read only",
                primaryAction: manageLink, secondaryAction: openInFinder)
        }
    }
}

private struct DirenvSurfacePreview: View {
    @Bindable var store: WorkspaceStore
    let openInFinder: () -> Void
    let manageLink: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(store.resolvedExports) { export in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("export \(export.key)='\(export.sensitive ? "••••••••••••" : export.previewValue)'")
                                .font(.callout.monospaced())
                                .lineLimit(2)
                                .truncationMode(.middle)
                            ResourceKindBadge(kind: export.resourceKind, label: export.resourceName)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        Divider().padding(.leading, 20)
                    }
                }
            }
            HStack(alignment: .top, spacing: 7) {
                Image(systemName: "exclamationmark.triangle")
                Text("Authorization identifies the shell or direnv session that reads this file, not each child process that inherits the environment.")
            }
            .font(.caption)
            .foregroundStyle(.orange)
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
            SurfaceFooter(
                primaryTitle: "Manage Link", secondaryTitle: "Open in Finder",
                note: "Strictly quoted exports · Read only · Session-level authorization",
                primaryAction: manageLink, secondaryAction: openInFinder)
        }
    }
}

private struct DirectEnvFileSurfacePreview: View {
    @Bindable var store: WorkspaceStore
    let openInFinder: () -> Void
    let manageLink: () -> Void

    private var resource: WorkspaceResource? {
        guard let resourceID = store.selectedSurface?.resourceID else { return nil }
        return store.resource(resourceID)
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(resource?.exports ?? []) { export in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(export.key)=••••••••••••")
                                .font(.callout.monospaced())
                            Text("Editable value · key schema is fixed")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        Divider().padding(.leading, 20)
                    }
                }
            }
            SurfaceFooter(
                primaryTitle: "Manage Link", secondaryTitle: "Open in Finder",
                note: "Stored EnvFile · Editable · Every save creates a version",
                primaryAction: manageLink, secondaryAction: openInFinder)
        }
    }
}

private struct SocketSurfacePreview: View {
    @Bindable var store: WorkspaceStore
    let copyPath: () -> Void
    let manageSocket: () -> Void

    private var resource: WorkspaceResource? {
        guard let resourceID = store.selectedSurface?.resourceID else { return nil }
        return store.resource(resourceID)
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    InspectorSection(title: "Endpoint") {
                        Text(store.selectedSurface?.path ?? "")
                            .font(.caption.monospaced())
                            .lineLimit(3)
                            .truncationMode(.middle)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                    InspectorSection(title: "Capability") {
                        Label(
                            resource?.metadata.note ?? "SSH signing proxy",
                            systemImage: "key.horizontal")
                        Label("Exports SSH_AUTH_SOCK", systemImage: "arrow.turn.down.right")
                        Label("0 active connections", systemImage: "network")
                    }
                    InspectorSection(title: "Authorization") {
                        Text("Identify the peer on connect, then authorize and audit each SSH sign request.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 7) {
                        Image(systemName: "info.circle")
                        Text("Planned surface · daemon proxy is not implemented yet")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(10)
                    .background(Color.orange.opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
                .padding(20)
            }
            SurfaceFooter(
                primaryTitle: "Manage Socket", secondaryTitle: "Copy Path",
                note: "Real Unix socket · Policy on connect and sign",
                primaryAction: manageSocket, secondaryAction: copyPath)
        }
    }
}

private struct InspectorSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct SurfaceFooter: View {
    let primaryTitle: String
    let secondaryTitle: String
    let note: String
    let primaryAction: () -> Void
    let secondaryAction: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            Divider()
            HStack {
                Button(secondaryTitle, action: secondaryAction)
                Spacer()
                Button(primaryTitle, action: primaryAction)
                    .buttonStyle(.borderedProminent)
            }
            Text(note)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(16)
        .background(.bar)
    }
}

private struct ManageSurfaceSheet: View {
    @Bindable var store: WorkspaceStore
    let surface: WorkspaceSurface
    let onRemoved: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var isWorking = false
    @State private var confirmingRemoval = false
    @State private var errorMessage: String?
    @State private var selectedBindingIDs: Set<WorkspaceBinding.ID> = []
    @State private var fileName: String
    @State private var selectedKind: WorkspaceSurfaceKind
    @State private var sshHostPatterns: String
    @State private var sshHostname: String
    @State private var sshUser: String
    @State private var sshPort: String
    @State private var sshForwardAgent: Bool

    init(
        store: WorkspaceStore, surface: WorkspaceSurface,
        onRemoved: @escaping () -> Void = {}
    ) {
        self.store = store
        self.surface = surface
        self.onRemoved = onRemoved
        _fileName = State(initialValue: surface.name)
        _selectedKind = State(initialValue: surface.kind)
        _sshHostPatterns = State(
            initialValue: surface.sshRoute?.hostPatterns.joined(separator: " ") ?? "")
        _sshHostname = State(initialValue: surface.sshRoute?.hostname ?? "")
        _sshUser = State(initialValue: surface.sshRoute?.user ?? "")
        _sshPort = State(initialValue: surface.sshRoute?.port.map(String.init) ?? "")
        _sshForwardAgent = State(initialValue: surface.sshRoute?.forwardAgent ?? false)
    }

    private var isFileSurface: Bool {
        surface.kind == .dotenvFile || surface.kind == .direnvFile || surface.kind == .iniFile
            || surface.kind == .envFileDirect
            || surface.kind == .linesFile
    }

    private var isSocketSurface: Bool { surface.kind == .unixSocket }

    private var isManagedSurface: Bool { isFileSurface || isSocketSurface }

    private var isComposedSurface: Bool {
        selectedKind.isComposed || selectedKind == .unixSocket
    }

    private var bindingCandidates: [WorkspaceBinding] {
        store.compatibleBindings(for: selectedKind)
    }

    private var expectedTarget: String {
        store.expectedLinkTarget(for: surface)
    }

    private var actualTarget: String? {
        store.managedLinkTarget(for: surface)
    }

    private var linkSummary: String {
        guard let actualTarget else { return "Missing — repair will recreate the link" }
        return actualTarget == expectedTarget
            ? "Managed link is healthy"
            : "Conflict — Floria will not replace this link"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Configure \(URL(fileURLWithPath: surface.path).lastPathComponent)")
                    .font(.title2.bold())
                Text(linkSummary)
                    .font(.callout)
                    .foregroundStyle(actualTarget == expectedTarget ? Color.green : Color.orange)
            }

            if isManagedSurface {
                InspectorSection(title: isSocketSurface ? "Socket" : "File") {
                    TextField("File name", text: $fileName)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                    if surface.kind.isComposed {
                        Picker("Format", selection: $selectedKind) {
                            ForEach(WorkspaceSurfaceKind.composedCases, id: \.self) { kind in
                                Label(kind.title, systemImage: kind.systemImage).tag(kind)
                            }
                        }
                        .pickerStyle(.menu)
                    } else {
                        LabeledContent("Format", value: surface.kind.title)
                    }
                }
            }

            InspectorSection(title: "Project path") {
                Text(
                    ((surface.path as NSString).deletingLastPathComponent as NSString)
                        .appendingPathComponent(fileName)
                )
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
            }

            if isComposedSurface {
                InspectorSection(title: "Included content") {
                    ForEach(bindingCandidates) { binding in
                        Toggle(
                            store.resource(binding.resourceID)?.name ?? binding.resourceID,
                            isOn: bindingSelection(binding.id)
                        )
                        .toggleStyle(.checkbox)
                    }
                    if bindingCandidates.isEmpty {
                        Text("No compatible bindings")
                            .foregroundStyle(.secondary)
                    }
                }
            }


            if isSocketSurface {
                InspectorSection(title: "SSH host route") {
                    TextField("Host patterns", text: $sshHostPatterns)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                    TextField("HostName override", text: $sshHostname)
                        .textFieldStyle(.roundedBorder)
                    HStack {
                        TextField("User", text: $sshUser)
                            .textFieldStyle(.roundedBorder)
                        TextField("Port", text: $sshPort)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 80)
                    }
                    Toggle("Forward Agent", isOn: $sshForwardAgent)
                    Text("Space-separated patterns compile to one generated OpenSSH Host block.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if isManagedSurface {
                InspectorSection(title: "Managed path") {
                    Text(expectedTarget)
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                }
                if let actualTarget, actualTarget != expectedTarget {
                    InspectorSection(title: "Current target") {
                        Text(actualTarget)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }

            HStack {
                Button("Copy Path", systemImage: "doc.on.doc") {
                    copyToPasteboard(surface.path)
                }
                Button("Open in Finder", systemImage: "folder") {
                    NSWorkspace.shared.activateFileViewerSelecting(
                        [URL(fileURLWithPath: surface.path)])
                }
                if isManagedSurface {
                    Button("Repair Link", systemImage: "wrench.and.screwdriver", action: repairLink)
                        .disabled(isWorking)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if isManagedSurface {
                    Button("Save Changes", action: saveChanges)
                        .buttonStyle(.borderedProminent)
                        .disabled(
                            isWorking
                                || fileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }

            Divider()
            HStack {
                Text("Removing this configuration keeps its reusable content.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Remove Configuration", systemImage: "trash", role: .destructive) {
                    confirmingRemoval = true
                }
                .disabled(isWorking)
            }
        }
        .padding(24)
        .frame(width: 620)
        .onAppear {
            selectedBindingIDs = Set(surface.bindingIDs)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                for window in NSApp.windows {
                    guard let editor = window.firstResponder as? NSTextView else { continue }
                    editor.setSelectedRange(
                        NSRange(location: editor.string.utf16.count, length: 0))
                    window.makeFirstResponder(nil)
                }
            }
        }
        .onChange(of: selectedKind) { _, kind in
            let allowed = Set(store.compatibleBindings(for: kind).map(\.id))
            selectedBindingIDs.formIntersection(allowed)
        }
        .alert("Remove configuration?", isPresented: $confirmingRemoval) {
            Button("Cancel", role: .cancel) { }
            Button("Remove", role: .destructive, action: removeSurface)
        } message: {
            Text("Floria removes only the managed link. Reusable content stays in the Library.")
        }
        .alert(
            "Could not update item",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func repairLink() {
        Task {
            isWorking = true
            defer { isWorking = false }
            do {
                try await store.repairSurfaceLink(surface.id)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func saveChanges() {
        Task {
            isWorking = true
            defer { isWorking = false }
            do {
                let ordered = bindingCandidates.map(\.id).filter(selectedBindingIDs.contains)
                let route = try sshRoute()
                try await store.updateSurface(
                    surface.id, fileName: fileName, kind: selectedKind,
                    bindingIDs: ordered, sshRoute: route)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func sshRoute() throws -> WorkspaceSshRoute? {
        guard isSocketSurface else { return nil }
        let patterns = sshHostPatterns.split(whereSeparator: \.isWhitespace).map(String.init)
        let port: UInt16?
        if sshPort.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            port = nil
        } else if let parsed = UInt16(sshPort), parsed > 0 {
            port = parsed
        } else {
            throw WorkspaceStoreError.invalid("SSH port must be between 1 and 65535")
        }
        let hostname = sshHostname.trimmingCharacters(in: .whitespacesAndNewlines)
        let user = sshUser.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasOptions = !hostname.isEmpty || !user.isEmpty || port != nil || sshForwardAgent
        guard !patterns.isEmpty || !hasOptions else {
            throw WorkspaceStoreError.invalid("Add a Host pattern before route options")
        }
        return patterns.isEmpty ? nil : WorkspaceSshRoute(
            hostPatterns: patterns, hostname: hostname.nilIfEmpty, user: user.nilIfEmpty,
            port: port, forwardAgent: sshForwardAgent)
    }

    private func bindingSelection(_ id: WorkspaceBinding.ID) -> Binding<Bool> {
        Binding(
            get: { selectedBindingIDs.contains(id) },
            set: { selected in
                if selected { selectedBindingIDs.insert(id) }
                else { selectedBindingIDs.remove(id) }
            })
    }

    private func removeSurface() {
        Task {
            isWorking = true
            defer { isWorking = false }
            do {
                try await store.deleteSurface(surface.id)
                onRemoved()
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct SurfaceStatusBadge: View {
    let status: WorkspaceSurfaceStatus

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: status.isHealthy ? "checkmark.circle.fill" : "stop.circle")
            Text(status.rawValue)
        }
        .font(.caption.weight(.medium))
        .foregroundStyle(status.isHealthy ? Color.green : Color.secondary)
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background((status.isHealthy ? Color.green : Color.secondary).opacity(0.1))
        .clipShape(Capsule())
    }
}

private struct ProjectCatalogView: View {
    @Bindable var store: WorkspaceStore
    @Binding var selection: WorkspaceSidebarSelection?
    let search: String
    let addProject: () -> Void

    private var filtered: [WorkspaceProject] {
        guard !search.isEmpty else { return store.projects }
        return store.projects.filter {
            $0.name.localizedCaseInsensitiveContains(search)
                || $0.path.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Projects").font(.title2.bold())
                    Text("Compose environments and surfaces for each local workspace")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Add Project", systemImage: "plus", action: addProject)
                    .buttonStyle(.borderedProminent)
            }
            .padding(24)

            List(filtered) { project in
                Button {
                    selection = .project(project.id)
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "shippingbox")
                            .font(.title3)
                            .foregroundStyle(.blue)
                            .frame(width: 36, height: 36)
                            .background(Color.blue.opacity(0.1))
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                        VStack(alignment: .leading, spacing: 3) {
                            Text(project.name).font(.body.weight(.medium))
                            Text(project.path).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("\(project.environments.count) environments")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Image(systemName: "chevron.right")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.vertical, 5)
            }
            .overlay {
                if filtered.isEmpty {
                    if search.isEmpty {
                        ContentUnavailableView(
                            "No projects yet", systemImage: "folder.badge.plus",
                            description: Text("Add a local directory to create its Development .env output."))
                    } else {
                        ContentUnavailableView.search(text: search)
                    }
                }
            }
        }
        .navigationTitle("Projects")
    }
}

private enum LibraryCatalogFilter: String, CaseIterable, Identifiable {
    case all
    case files
    case secrets
    case ssh

    var id: Self { self }

    var title: String {
        switch self {
        case .all: "All"
        case .files: "Files"
        case .secrets: "Secrets"
        case .ssh: "SSH"
        }
    }

    func includes(_ item: LibraryCatalogItem) -> Bool {
        switch (self, item) {
        case (.all, _), (.files, .file):
            true
        case (.files, .surface):
            true
        case (.files, .resource(let resource)):
            resource.kind == .envFile
        case (.secrets, .resource(let resource)):
            resource.kind == .sharedSecret || resource.kind == .secret
        case (.ssh, .resource(let resource)):
            resource.kind == .sshIdentity || resource.kind == .sshAgent
        default:
            false
        }
    }
}

enum LibraryCatalogItem: Identifiable {
    case file(WorkspaceProtectedFile)
    case resource(WorkspaceResource)
    case surface(WorkspaceSurface)

    var id: String {
        switch self {
        case .file(let file): "file:\(file.id)"
        case .resource(let resource): "resource:\(resource.id)"
        case .surface(let surface): "surface:\(surface.id)"
        }
    }

    var title: String {
        switch self {
        case .file(let file):
            URL(fileURLWithPath: file.path).lastPathComponent
        case .resource(let resource):
            resource.name
        case .surface(let surface):
            URL(fileURLWithPath: surface.path).lastPathComponent
        }
    }

    var detail: String {
        switch self {
        case .file(let file):
            return (file.path as NSString).abbreviatingWithTildeInPath
        case .resource(let resource):
            if let note = resource.metadata.note { return note }
            if let origin = resource.originSummary { return origin }
            if let key = resource.defaultEnvKey { return key }
            return resource.usageCount == 0
                ? "Not used by a project"
                : "Used by \(resource.usageCount) project\(resource.usageCount == 1 ? "" : "s")"
        case .surface(let surface):
            return (surface.path as NSString).abbreviatingWithTildeInPath
        }
    }

    var typeTitle: String {
        switch self {
        case .file(let file):
            return file.kind.title
        case .resource(let resource):
            return switch resource.kind {
            case .sharedSecret, .secret: "Secret"
            case .envFile:
                resource.originSources.first.map {
                    WorkspaceProtectedFileKind.infer(from: $0.path).title
                } ?? "Env file"
            case .sshIdentity: "SSH identity"
            case .sshAgent: "SSH agent"
            case .literal: "Value"
            case .command: "Command"
            }
        case .surface(let surface):
            let recognized = WorkspaceProtectedFileKind.infer(from: surface.path)
            return recognized == .file ? surface.kind.managedTitle : recognized.title
        }
    }

    var systemImage: String {
        switch self {
        case .file(let file): return file.kind.systemImage
        case .resource(let resource):
            if resource.kind == .envFile, let source = resource.originSources.first {
                return WorkspaceProtectedFileKind.infer(from: source.path).systemImage
            }
            return resource.kind.systemImage
        case .surface(let surface):
            let recognized = WorkspaceProtectedFileKind.infer(from: surface.path)
            return recognized == .file ? surface.kind.systemImage : recognized.systemImage
        }
    }

    var securityLevel: WorkspaceSecurityLevel {
        switch self {
        case .file(let file): file.securityLevel
        case .resource(let resource): resource.securityLevel
        case .surface(let surface): surface.securityLevel
        }
    }

    func matches(_ search: String) -> Bool {
        guard !search.isEmpty else { return true }
        let metadata: ItemMetadata
        switch self {
        case .file(let file): metadata = file.metadata
        case .resource(let resource): metadata = resource.metadata
        case .surface: metadata = .empty
        }
        return title.localizedCaseInsensitiveContains(search)
            || detail.localizedCaseInsensitiveContains(search)
            || typeTitle.localizedCaseInsensitiveContains(search)
            || (metadata.note?.localizedCaseInsensitiveContains(search) == true)
            || metadata.links.contains {
                $0.label.localizedCaseInsensitiveContains(search)
                    || $0.url.localizedCaseInsensitiveContains(search)
            }
    }

}

private struct LibraryCatalogView: View {
    @Bindable var store: WorkspaceStore
    let search: String

    @State private var filter = LibraryCatalogFilter.all
    @State private var selectedItem: LibraryCatalogItem?

    private var items: [LibraryCatalogItem] {
        let all =
            store.protectedFiles.map(LibraryCatalogItem.file)
            + store.resources.map(LibraryCatalogItem.resource)
        return all
            .filter { filter.includes($0) && $0.matches(search) }
            .sorted { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 18) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Library").font(.title2.bold())
                    Text("Everything Floria manages, in one place")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Picker("Type", selection: $filter) {
                    ForEach(LibraryCatalogFilter.allCases) { option in
                        Text(option.title).tag(option)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 420)
            }
            .padding(24)

            List(items) { item in
                HStack(spacing: 12) {
                    Button {
                        selectedItem = item
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: item.systemImage)
                                .font(.title3)
                                .foregroundStyle(.blue)
                                .frame(width: 36, height: 36)
                                .background(Color.blue.opacity(0.1))
                                .clipShape(RoundedRectangle(cornerRadius: 8))

                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.title)
                                    .font(.body.weight(.medium))
                                    .lineLimit(1)
                                Text(item.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }

                            Spacer(minLength: 12)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .frame(maxWidth: .infinity)
                    .accessibilityHint("Open details")

                    Text(item.typeTitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(width: 112, alignment: .leading)

                    SecurityLevelMenu(level: item.securityLevel) { level in
                        try await updateSecurity(item, level: level)
                    }

                    Menu {
                        Button("Details…", systemImage: "info.circle") {
                            selectedItem = item
                        }
                        if case .file(let file) = item {
                            Divider()
                            Button("Reveal in Finder", systemImage: "folder") {
                                NSWorkspace.shared.activateFileViewerSelecting([
                                    URL(fileURLWithPath: file.path)
                                ])
                            }
                            Button("Copy Path", systemImage: "doc.on.doc") {
                                copyToPasteboard(file.path)
                            }
                        }
                    } label: {
                        Image(systemName: "ellipsis")
                            .frame(width: 28, height: 28)
                            .contentShape(Rectangle())
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .accessibilityLabel("More actions for \(item.title)")
                }
                .padding(.vertical, 5)
            }
            .overlay {
                if items.isEmpty {
                    if search.isEmpty {
                        ContentUnavailableView(
                            filter == .all ? "Nothing managed yet" : "No \(filter.title.lowercased())",
                            systemImage: "tray",
                            description: Text(
                                filter == .all
                                    ? "Use Discover or Add to bring an existing item into Floria."
                                    : "Choose another type or add an item."))
                    } else {
                        ContentUnavailableView.search(text: search)
                    }
                }
            }
        }
        .navigationTitle("Library")
        .sheet(item: $selectedItem) { item in
            LibraryItemDetailSheet(store: store, item: item)
        }
    }

    private func updateSecurity(
        _ item: LibraryCatalogItem, level: WorkspaceSecurityLevel
    ) async throws {
        switch item {
        case .file(let file):
            try await store.updateProtectedFileMetadata(
                file.id, securityLevel: level, metadata: file.metadata)
        case .resource(let resource):
            try await store.updateResourceMetadata(
                resource.id, name: resource.name,
                securityLevel: level, metadata: resource.metadata)
        case .surface(let surface):
            try await store.updateSurfaceSecurityLevel(
                surface.id, securityLevel: level)
        }
    }
}

struct LibraryItemDetailSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var store: WorkspaceStore
    let item: LibraryCatalogItem
    let configureProtectedFile: (() async throws -> Void)?

    @State private var editingFile: WorkspaceProtectedFile?
    @State private var editingSharedSecret: WorkspaceResource?
    @State private var editingResource: WorkspaceResource?
    @State private var editingSurface: WorkspaceSurface?
    @State private var historyFile: WorkspaceProtectedFile?
    @State private var confirmingConfiguration = false
    @State private var confirmingRemoval = false
    @State private var isWorking = false
    @State private var errorMessage: String?

    init(
        store: WorkspaceStore, item: LibraryCatalogItem,
        configureProtectedFile: (() async throws -> Void)? = nil
    ) {
        self.store = store
        self.item = item
        self.configureProtectedFile = configureProtectedFile
    }

    private var currentItem: LibraryCatalogItem {
        switch item {
        case .file(let file):
            return store.protectedFiles.first(where: { $0.id == file.id })
                .map(LibraryCatalogItem.file) ?? item
        case .resource(let resource):
            return store.resources.first(where: { $0.id == resource.id })
                .map(LibraryCatalogItem.resource) ?? item
        case .surface(let surface):
            return store.surface(surface.id).map(LibraryCatalogItem.surface) ?? item
        }
    }

    private var metadata: ItemMetadata {
        switch currentItem {
        case .file(let file): file.metadata
        case .resource(let resource): resource.metadata
        case .surface: .empty
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: currentItem.systemImage)
                    .font(.system(size: 24, weight: .medium))
                    .foregroundStyle(Color.blue)
                    .frame(width: 48, height: 48)
                    .background(Color.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 11))

                VStack(alignment: .leading, spacing: 4) {
                    Text(currentItem.title)
                        .font(.title2.bold())
                    Text(currentItem.detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }

                Spacer()

                SecurityLevelMenu(level: currentItem.securityLevel) { level in
                    try await updateSecurity(level)
                }
                .focusable(false)
            }
            .padding(24)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    InspectorSection(title: "Details") {
                        LabeledContent("Type", value: currentItem.typeTitle)
                        switch currentItem {
                        case .file(let file):
                            LabeledContent("Path") {
                                Text((file.path as NSString).abbreviatingWithTildeInPath)
                                    .textSelection(.enabled)
                            }
                            LabeledContent("Current version", value: "v\(file.currentVersion)")
                            LabeledContent(
                                "Size",
                                value: ByteCountFormatter.string(
                                    fromByteCount: Int64(file.size), countStyle: .file))
                        case .resource(let resource):
                            LabeledContent(
                                "Projects",
                                value: resource.usageCount == 0
                                    ? "Not in use"
                                    : "\(resource.usageCount)")
                            if let key = resource.defaultEnvKey {
                                LabeledContent("Default key", value: key)
                            }
                            if let origin = resource.originSummary {
                                LabeledContent("Source") {
                                    Text(origin)
                                        .textSelection(.enabled)
                                }
                            }
                        case .surface(let surface):
                            LabeledContent("Path") {
                                Text((surface.path as NSString).abbreviatingWithTildeInPath)
                                    .textSelection(.enabled)
                            }
                            LabeledContent(
                                "Status",
                                value: surface.status.isHealthy ? "Ready" : "Needs attention")
                        }
                    }

                    if metadata.note != nil || !metadata.links.isEmpty {
                        InspectorSection(title: "Info") {
                            if let note = metadata.note {
                                Text(note)
                                    .font(.callout)
                                    .textSelection(.enabled)
                            }
                            ForEach(metadata.links, id: \.self) { link in
                                Button {
                                    openMetadataLink(link)
                                } label: {
                                    Label(link.label, systemImage: "arrow.up.right.square")
                                }
                                .buttonStyle(.link)
                            }
                        }
                    }

                    InspectorSection(title: "Actions") {
                        HStack(spacing: 10) {
                            switch currentItem {
                            case .file(let file):
                                Button("Edit Info…", systemImage: "pencil") {
                                    editCurrentItem()
                                }
                                if configureProtectedFile != nil, file.kind.isConfigurable {
                                    Button("Configure…", systemImage: "slider.horizontal.3") {
                                        confirmingConfiguration = true
                                    }
                                }
                                Button("History", systemImage: "clock.arrow.circlepath") {
                                    historyFile = file
                                }
                                Button("Reveal in Finder", systemImage: "folder") {
                                    NSWorkspace.shared.activateFileViewerSelecting([
                                        URL(fileURLWithPath: file.path)
                                    ])
                                }
                                Button("Copy Path", systemImage: "doc.on.doc") {
                                    copyToPasteboard(file.path)
                                }
                            case .resource(let resource):
                                Button("Edit Info…", systemImage: "pencil") {
                                    editCurrentItem()
                                }
                                if let source = resource.originSources.first {
                                    Button("Reveal Source", systemImage: "folder") {
                                        NSWorkspace.shared.activateFileViewerSelecting([
                                            URL(fileURLWithPath: source.path)
                                        ])
                                    }
                                }
                            case .surface(let surface):
                                Button("Configure…", systemImage: "slider.horizontal.3") {
                                    editingSurface = surface
                                }
                                Button("Reveal in Finder", systemImage: "folder") {
                                    NSWorkspace.shared.activateFileViewerSelecting([
                                        URL(fileURLWithPath: surface.path)
                                    ])
                                }
                                Button("Copy Path", systemImage: "doc.on.doc") {
                                    copyToPasteboard(surface.path)
                                }
                            }
                        }
                        .buttonStyle(.bordered)
                    }

                    if let removalTitle {
                        Divider()
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(removalTitle)
                                    .font(.callout.weight(.medium))
                                Text(removalDetail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button(removalButtonTitle, role: .destructive) {
                                confirmingRemoval = true
                            }
                            .disabled(isWorking || removalIsBlocked)
                        }
                    }
                }
                .padding(24)
            }

            Divider()

            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 660, height: sheetHeight)
        .onAppear {
            DispatchQueue.main.async {
                NSApp.keyWindow?.makeFirstResponder(nil)
            }
        }
        .sheet(item: $editingFile) { file in
            EditProtectedFileMetadataSheet(store: store, file: file)
        }
        .sheet(item: $editingSharedSecret) { resource in
            EditSharedSecretSheet(store: store, resource: resource)
        }
        .sheet(item: $editingResource) { resource in
            EditResourceMetadataSheet(store: store, resource: resource)
        }
        .sheet(item: $editingSurface) { surface in
            ManageSurfaceSheet(
                store: store, surface: surface,
                onRemoved: { dismiss() })
        }
        .sheet(item: $historyFile) { file in
            ProtectedFileHistorySheet(store: store, file: file)
        }
        .alert(
            "Configure \(currentItem.title)?",
            isPresented: $confirmingConfiguration
        ) {
            Button("Cancel", role: .cancel) {}
            Button("Configure") {
                configureCurrentFile()
            }
        } message: {
            Text(
                "Floria will keep this path, parse its values, and make its contents configurable. Existing encrypted versions are reused."
            )
        }
        .alert(removalConfirmationTitle, isPresented: $confirmingRemoval) {
            Button("Cancel", role: .cancel) {}
            Button(removalButtonTitle, role: .destructive) {
                removeCurrentItem()
            }
        } message: {
            Text(removalConfirmationDetail)
        }
        .alert(
            "Could not update item",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private var sheetHeight: CGFloat {
        var height: CGFloat = removalTitle == nil ? 420 : 470
        if metadata.note != nil { height += 38 }
        height += min(CGFloat(metadata.links.count) * 28, 84)
        return min(height, 540)
    }

    private var removalTitle: String? {
        switch currentItem {
        case .file: "Stop protecting this file"
        case .resource(let resource) where resource.kind == .sharedSecret:
            "Delete this secret"
        case .resource(let resource)
        where resource.kind == .sshIdentity || resource.kind == .sshAgent:
            resource.kind == .sshIdentity ? "Delete this SSH identity" : "Disconnect this SSH agent"
        case .resource:
            nil
        case .surface:
            nil
        }
    }

    private var removalDetail: String {
        switch currentItem {
        case .file:
            "Restore the current plaintext at its original path and delete its encrypted history."
        case .resource(let resource) where resource.usageCount > 0:
            "Remove it from \(resource.usageCount) project\(resource.usageCount == 1 ? "" : "s") first."
        case .resource(let resource) where resource.kind == .sshAgent:
            "The external agent is not changed."
        case .resource:
            "This permanently removes the encrypted value and version history."
        case .surface:
            ""
        }
    }

    private var removalButtonTitle: String {
        switch currentItem {
        case .file: "Stop Protecting…"
        case .resource(let resource) where resource.kind == .sshAgent: "Disconnect…"
        case .resource: "Delete…"
        case .surface: ""
        }
    }

    private var removalIsBlocked: Bool {
        switch currentItem {
        case .file(let file): !file.linked
        case .resource(let resource): resource.usageCount > 0
        case .surface: true
        }
    }

    private var removalConfirmationTitle: String {
        switch currentItem {
        case .file: "Restore plaintext and stop protecting?"
        case .resource(let resource) where resource.kind == .sshAgent:
            "Disconnect SSH agent?"
        case .resource(let resource) where resource.kind == .sshIdentity:
            "Delete SSH identity?"
        case .resource:
            "Delete secret?"
        case .surface:
            "Remove managed item?"
        }
    }

    private var removalConfirmationDetail: String {
        switch currentItem {
        case .file(let file):
            "Floria will restore version \(file.currentVersion) at \(file.path), then permanently delete every encrypted version."
        case .resource(let resource) where resource.kind == .sshIdentity:
            "This permanently removes the encrypted private-key copy from Floria. The original imported file is not changed."
        case .resource(let resource) where resource.kind == .sshAgent:
            "Floria removes only its saved identity metadata. The external agent is not changed."
        case .resource:
            "This permanently removes the encrypted value and version history."
        case .surface:
            ""
        }
    }

    private func editCurrentItem() {
        switch currentItem {
        case .file(let file):
            editingFile = file
        case .resource(let resource) where resource.kind == .sharedSecret:
            editingSharedSecret = resource
        case .resource(let resource):
            editingResource = resource
        case .surface(let surface):
            editingSurface = surface
        }
    }

    private func updateSecurity(_ level: WorkspaceSecurityLevel) async throws {
        switch currentItem {
        case .file(let file):
            try await store.updateProtectedFileMetadata(
                file.id, securityLevel: level, metadata: file.metadata)
        case .resource(let resource):
            try await store.updateResourceMetadata(
                resource.id, name: resource.name,
                securityLevel: level, metadata: resource.metadata)
        case .surface(let surface):
            try await store.updateSurfaceSecurityLevel(
                surface.id, securityLevel: level)
        }
    }

    private func configureCurrentFile() {
        guard let configureProtectedFile else { return }
        isWorking = true
        Task {
            defer { isWorking = false }
            do {
                try await configureProtectedFile()
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func removeCurrentItem() {
        isWorking = true
        Task {
            defer { isWorking = false }
            do {
                switch currentItem {
                case .file(let file):
                    let deleted = try await store.restoreFile(file.id)
                    guard deleted else {
                        errorMessage =
                            "The plaintext file was restored, but its encrypted history could not be deleted."
                        return
                    }
                case .resource(let resource) where resource.kind == .sharedSecret:
                    try await store.deleteSharedSecret(resource.id)
                case .resource(let resource)
                where resource.kind == .sshIdentity || resource.kind == .sshAgent:
                    try await store.removeSshAgentResource(resource.id)
                case .resource:
                    return
                case .surface:
                    return
                }
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct ProtectedFilesView: View {
    @Bindable var store: WorkspaceStore
    let search: String
    let protectFile: () -> Void
    @State private var historyFile: WorkspaceProtectedFile?
    @State private var restoreFile: WorkspaceProtectedFile?
    @State private var editingFile: WorkspaceProtectedFile?
    @State private var errorMessage: String?

    private var filtered: [WorkspaceProtectedFile] {
        guard !search.isEmpty else { return store.protectedFiles }
        return store.protectedFiles.filter {
            $0.path.localizedCaseInsensitiveContains(search)
                || $0.kind.title.localizedCaseInsensitiveContains(search)
                || ($0.metadata.note?.localizedCaseInsensitiveContains(search) == true)
                || $0.metadata.links.contains {
                    $0.label.localizedCaseInsensitiveContains(search)
                        || $0.url.localizedCaseInsensitiveContains(search)
                }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Protected Files").font(.title2.bold())
                    Text("Encrypted files that remain available at their original paths")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Protect Existing File", systemImage: "lock.fill", action: protectFile)
                    .buttonStyle(.borderedProminent)
            }
            .padding(24)

            List(filtered) { file in
                HStack(spacing: 12) {
                    Image(systemName: file.kind.systemImage)
                        .font(.title3)
                        .foregroundStyle(.blue)
                        .frame(width: 36, height: 36)
                        .background(Color.blue.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    VStack(alignment: .leading, spacing: 3) {
                        Text(URL(fileURLWithPath: file.path).lastPathComponent)
                            .font(.body.weight(.medium))
                        if let note = file.metadata.note {
                            Text(note)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Text(file.path)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 3) {
                        HStack(spacing: 7) {
                            Text(file.kind.title)
                                .font(.caption.weight(.medium))
                            SecurityLevelMenu(level: file.securityLevel) { securityLevel in
                                try await store.updateProtectedFileMetadata(
                                    file.id, securityLevel: securityLevel, metadata: file.metadata)
                            }
                        }
                        Text(
                            "\(file.linked ? "Linked" : "Stored only") · v\(file.currentVersion) · \(ByteCountFormatter.string(fromByteCount: Int64(file.size), countStyle: .file)) · \(String(format: "%04o", file.mode))"
                        )
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    }
                    Menu {
                        Button("Version History", systemImage: "clock.arrow.circlepath") {
                            historyFile = file
                        }
                        Button("Edit Security & Info…", systemImage: "pencil") {
                            editingFile = file
                        }
                        if !file.metadata.links.isEmpty {
                            Divider()
                            ForEach(file.metadata.links, id: \.self) { link in
                                Button(link.label, systemImage: "link") {
                                    openMetadataLink(link)
                                }
                            }
                        }
                        Divider()
                        Button("Open in Finder", systemImage: "folder") {
                            NSWorkspace.shared.activateFileViewerSelecting(
                                [URL(fileURLWithPath: file.path)])
                        }
                        Button("Copy Path", systemImage: "doc.on.doc") {
                            copyToPasteboard(file.path)
                        }
                        Button("Copy Recovery ID", systemImage: "number") {
                            copyToPasteboard(file.id)
                        }
                        Divider()
                        Button("Stop Protecting…", systemImage: "lock.open", role: .destructive) {
                            restoreFile = file
                        }
                        .disabled(!file.linked)
                    } label: {
                        Image(systemName: "ellipsis")
                            .frame(width: 28, height: 28)
                            .contentShape(Rectangle())
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .accessibilityLabel("More")
                }
                .padding(.vertical, 5)
            }
            .overlay {
                if filtered.isEmpty {
                    if search.isEmpty {
                        ContentUnavailableView(
                            "No protected files yet", systemImage: "lock.fill",
                            description: Text(
                                "Protect an existing .env, .envrc, .pgpass, AWS credentials file, or any other local file."))
                    } else {
                        ContentUnavailableView.search(text: search)
                    }
                }
            }
        }
        .navigationTitle("Protected Files")
        .sheet(item: $historyFile) { file in
            ProtectedFileHistorySheet(store: store, file: file)
        }
        .sheet(item: $editingFile) { file in
            EditProtectedFileMetadataSheet(store: store, file: file)
        }
        .alert(
            "Restore plaintext and stop protecting?",
            isPresented: Binding(
                get: { restoreFile != nil },
                set: { if !$0 { restoreFile = nil } })
        ) {
            Button("Cancel", role: .cancel) { restoreFile = nil }
            Button("Restore and Delete History", role: .destructive, action: restoreSelectedFile)
        } message: {
            if let restoreFile {
                Text("Floria will restore version \(restoreFile.currentVersion) at \(restoreFile.path) and permanently delete every encrypted version after the plaintext file is safely written.")
            }
        }
        .alert(
            "Could not restore file",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func restoreSelectedFile() {
        guard let file = restoreFile else { return }
        restoreFile = nil
        Task {
            do {
                let deleted = try await store.restoreFile(file.id)
                if !deleted {
                    errorMessage = "The plaintext file was restored, but Floria could not delete its encrypted history. The stored copy remains listed for recovery."
                }
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct EditProtectedFileMetadataSheet: View {
    @Bindable var store: WorkspaceStore
    let file: WorkspaceProtectedFile

    @Environment(\.dismiss) private var dismiss
    @State private var note: String
    @State private var links: [EditableItemLink]
    @State private var securityLevel: WorkspaceSecurityLevel
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(store: WorkspaceStore, file: WorkspaceProtectedFile) {
        self.store = store
        self.file = file
        _note = State(initialValue: file.metadata.note ?? "")
        _links = State(initialValue: editableLinks(file.metadata))
        _securityLevel = State(initialValue: file.securityLevel)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Edit Protected File Info").font(.title2.bold())
                Text(file.path)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
            }

            SecurityLevelPicker(selection: $securityLevel)
            ItemMetadataEditor(note: $note, links: $links)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save Changes", action: save)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving)
            }
        }
        .padding(24)
        .frame(width: 560)
        .alert(
            "Could not update protected file",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func save() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.updateProtectedFileMetadata(
                    file.id, securityLevel: securityLevel,
                    metadata: itemMetadata(note: note, links: links))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct ProtectedFileHistorySheet: View {
    @Bindable var store: WorkspaceStore
    let file: WorkspaceProtectedFile

    @Environment(\.dismiss) private var dismiss
    @State private var versions: [WorkspaceProtectedFileVersion] = []
    @State private var isLoading = true
    @State private var rollingBack: UInt32?
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Version History").font(.title2.bold())
                Text(file.path)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
            }

            List(versions) { version in
                HStack(spacing: 12) {
                    Image(systemName: version.current ? "checkmark.circle.fill" : "clock")
                        .foregroundStyle(version.current ? Color.green : Color.secondary)
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 7) {
                            Text("Version \(version.version)").font(.body.weight(.medium))
                            if version.current {
                                Text("Current")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.green)
                            }
                        }
                        Text(version.created)
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(ByteCountFormatter.string(fromByteCount: Int64(version.size), countStyle: .file))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if !version.current {
                        Button("Roll Back") { rollback(to: version.version) }
                            .disabled(rollingBack != nil)
                    }
                }
                .padding(.vertical, 4)
            }
            .overlay {
                if isLoading {
                    ProgressView().controlSize(.small)
                } else if versions.isEmpty {
                    ContentUnavailableView("No versions", systemImage: "clock")
                }
            }

            HStack {
                Text("Rollback only moves the head; no version is deleted.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(24)
        .frame(width: 620, height: 470)
        .task { await loadHistory() }
        .alert(
            "Could not update history",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func loadHistory() async {
        isLoading = true
        defer { isLoading = false }
        do {
            versions = Array(try await store.protectedFileHistory(file.id).reversed())
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func rollback(to version: UInt32) {
        Task {
            rollingBack = version
            defer { rollingBack = nil }
            do {
                try await store.rollbackProtectedFile(file.id, to: version)
                await loadHistory()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct ImportSshIdentitySheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var name = "SSH Identity"
    @State private var path = ""
    @State private var passphrase = ""
    @State private var securityLevel = WorkspaceSecurityLevel.confirmation
    @State private var note = ""
    @State private var links: [EditableItemLink] = []
    @State private var isSaving = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Import SSH Identity").font(.title2.bold())
                Text("Use a private key directly from Floria's encrypted store.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Name").font(.callout.weight(.medium))
                TextField("Production fleet", text: $name)
                    .textFieldStyle(.roundedBorder)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("OpenSSH private key").font(.callout.weight(.medium))
                HStack {
                    TextField("~/.ssh/id_ed25519", text: $path)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                    Button("Choose…", action: chooseKey)
                }
                SecureField("Passphrase, if the source key is encrypted", text: $passphrase)
                    .textFieldStyle(.roundedBorder)
                Label(
                    "Floria copies the key into encrypted storage. The original file is not changed or removed.",
                    systemImage: "lock.shield")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Supports OpenSSH Ed25519/RSA and unencrypted EC2-style RSA PEM keys.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            SecurityLevelPicker(selection: $securityLevel)
            ItemMetadataEditor(note: $note, links: $links)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Import Identity", action: importIdentity)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        isSaving || path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 620)
        .alert(
            "Could not import SSH identity",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func chooseKey() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.resolvesAliases = false
        if panel.runModal() == .OK, let url = panel.url {
            path = url.path
            if name == "SSH Identity" {
                name = url.lastPathComponent
            }
        }
    }

    private func importIdentity() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.importSshIdentity(
                    name: name, path: path, passphrase: passphrase,
                    securityLevel: securityLevel,
                    metadata: itemMetadata(note: note, links: links))
                passphrase = ""
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct NewSshAgentSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var name = "SSH Agent"
    @State private var endpoint: String
    @State private var identities: [DiscoveredSshIdentity] = []
    @State private var discoveredEndpoint: String?
    @State private var note = ""
    @State private var links: [EditableItemLink] = []
    @State private var isDiscovering = false
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(store: WorkspaceStore) {
        self.store = store
        _endpoint = State(initialValue: ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] ?? "")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Connect External SSH Agent").font(.title2.bold())
                Text("Advanced provider: forward signing to an existing agent socket.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Name").font(.callout.weight(.medium))
                TextField("Work SSH Agent", text: $name)
                    .textFieldStyle(.roundedBorder)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Agent socket").font(.callout.weight(.medium))
                HStack {
                    TextField("/absolute/path/to/agent.sock", text: $endpoint)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                    Button("Discover", action: discover)
                        .disabled(isDiscovering || endpoint.isEmpty)
                }
                    Text("Floria stores only public metadata; signatures continue to be produced by this external agent.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            GroupBox("Advertised identities") {
                if isDiscovering {
                    ProgressView("Querying agent…")
                        .frame(maxWidth: .infinity, minHeight: 110)
                } else if identities.isEmpty {
                    ContentUnavailableView(
                        "Discover an agent first", systemImage: "key.horizontal",
                        description: Text("Its public keys and comments will appear here."))
                        .frame(maxWidth: .infinity, minHeight: 110)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(identities, id: \.address) { identity in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(identity.comment.isEmpty ? "Unnamed identity" : identity.comment)
                                        .font(.callout.weight(.medium))
                                    Text(identity.fingerprint)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding(8)
                    }
                    .frame(maxHeight: 150)
                }
            }

            ItemMetadataEditor(note: $note, links: $links)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Connect Agent", action: create)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        isSaving || identities.isEmpty || discoveredEndpoint != endpoint
                            || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 620)
        .onChange(of: endpoint) { _, value in
            if value != discoveredEndpoint { identities = [] }
        }
        .alert(
            "Could not connect SSH agent",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func discover() {
        Task {
            isDiscovering = true
            defer { isDiscovering = false }
            do {
                identities = try await store.discoverSshIdentities(endpoint: endpoint)
                discoveredEndpoint = endpoint
                if identities.isEmpty {
                    errorMessage = "The agent is reachable but advertises no identities."
                }
            } catch {
                identities = []
                discoveredEndpoint = nil
                errorMessage = error.localizedDescription
            }
        }
    }

    private func create() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.createSshAgentResource(
                    name: name, endpoint: endpoint, identities: identities,
                    metadata: itemMetadata(note: note, links: links))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct AddSshAgentSurfaceSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var resourceID = ""
    @State private var selectedEntries: Set<String> = []
    @State private var socketName = "agent.sock"
    @State private var securityLevel = WorkspaceSecurityLevel.confirmation
    @State private var hostPatterns = ""
    @State private var hostname = ""
    @State private var user = ""
    @State private var port = ""
    @State private var forwardAgent = false
    @State private var isSaving = false
    @State private var errorMessage: String?

    private var resource: WorkspaceResource? {
        store.sshIdentityProviders.first { $0.id == resourceID }
    }

    private var reusableSurface: WorkspaceSurface? {
        store.reusableEmptySshAgentSurface(socketName: socketName)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add SSH Agent Socket").font(.title2.bold())
                Text("Expose a project-specific set of identities through one filtered socket.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if store.sshIdentityProviders.isEmpty {
                ContentUnavailableView(
                    "No SSH Identities", systemImage: "key.horizontal",
                    description: Text("Import a private key from the SSH Identities section first."))
                    .frame(maxWidth: .infinity, minHeight: 180)
            } else {
                VStack(alignment: .leading, spacing: 7) {
                    Text("Signing identity provider").font(.callout.weight(.medium))
                    Picker("Signing identity provider", selection: $resourceID) {
                        ForEach(store.sshIdentityProviders) { resource in
                            Text("\(resource.name) · \(resource.entries.count) identities")
                                .tag(resource.id)
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: .infinity)
                }

                VStack(alignment: .leading, spacing: 7) {
                    Text("Project socket name").font(.callout.weight(.medium))
                    TextField("agent.sock", text: $socketName)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                }

                if let reusableSurface {
                    Label("Attach to existing empty socket", systemImage: "arrow.trianglehead.merge")
                        .font(.callout.weight(.medium))
                    Text(
                        "\(reusableSurface.name) already owns this project path. Floria will keep the socket and attach the selected identity."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                if let resource {
                    GroupBox("Exposed identities") {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 7) {
                                ForEach(resource.entries) { entry in
                                    Toggle(entry.label, isOn: entrySelection(entry.address))
                                        .toggleStyle(.checkbox)
                                }
                            }
                            .padding(8)
                        }
                        .frame(maxHeight: 160)
                    }
                }

                GroupBox("SSH host route (optional)") {
                    VStack(alignment: .leading, spacing: 9) {
                        TextField("Host patterns, e.g. ec2-* github.com", text: $hostPatterns)
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                        HStack {
                            TextField("HostName override", text: $hostname)
                                .textFieldStyle(.roundedBorder)
                            TextField("User", text: $user)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 130)
                            TextField("Port", text: $port)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 75)
                        }
                        Toggle("Forward this filtered agent to the remote host", isOn: $forwardAgent)
                        Text("Floria writes a generated Include file; it does not edit ~/.ssh/config.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(8)
                }

                SecurityLevelPicker(selection: $securityLevel)
            }

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(reusableSurface == nil ? "Create Socket" : "Attach Identity", action: create)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        isSaving || resourceID.isEmpty || selectedEntries.isEmpty
                            || socketName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 580)
        .onAppear {
            if resourceID.isEmpty { selectResource(store.sshIdentityProviders.first?.id ?? "") }
            adoptReusableSurfaceSettings()
        }
        .onChange(of: resourceID) { _, value in selectResource(value) }
        .onChange(of: socketName) { _, _ in adoptReusableSurfaceSettings() }
        .alert(
            "Could not create SSH agent socket",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func selectResource(_ id: String) {
        resourceID = id
        selectedEntries = Set(
            store.sshIdentityProviders.first(where: { $0.id == id })?.entries.map(\.address) ?? [])
    }

    private func adoptReusableSurfaceSettings() {
        guard let surface = reusableSurface else { return }
        securityLevel = surface.securityLevel
        hostPatterns = surface.sshRoute?.hostPatterns.joined(separator: " ") ?? ""
        hostname = surface.sshRoute?.hostname ?? ""
        user = surface.sshRoute?.user ?? ""
        port = surface.sshRoute?.port.map(String.init) ?? ""
        forwardAgent = surface.sshRoute?.forwardAgent ?? false
    }

    private func entrySelection(_ address: String) -> Binding<Bool> {
        Binding(
            get: { selectedEntries.contains(address) },
            set: { selected in
                if selected { selectedEntries.insert(address) }
                else { selectedEntries.remove(address) }
            })
    }

    private func create() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                let patterns = hostPatterns.split(whereSeparator: \.isWhitespace).map(String.init)
                let portValue: UInt16?
                if port.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    portValue = nil
                } else if let parsed = UInt16(port), parsed > 0 {
                    portValue = parsed
                } else {
                    throw WorkspaceStoreError.invalid("SSH port must be between 1 and 65535")
                }
                let hasOptions = !hostname.isEmpty || !user.isEmpty || portValue != nil || forwardAgent
                guard !patterns.isEmpty || !hasOptions else {
                    throw WorkspaceStoreError.invalid("Add a Host pattern before route options")
                }
                let route = patterns.isEmpty ? nil : WorkspaceSshRoute(
                    hostPatterns: patterns,
                    hostname: hostname.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty,
                    user: user.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty,
                    port: portValue, forwardAgent: forwardAgent)
                try await store.createSshAgentSurface(
                    resourceID: resourceID, selectedEntries: selectedEntries,
                    socketName: socketName, securityLevel: securityLevel, route: route)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct SshAgentsCatalogView: View {
    @Bindable var store: WorkspaceStore
    let search: String
    let importIdentity: () -> Void
    let connectExternalAgent: () -> Void

    @State private var integration: SshConfigIntegrationStatus?
    @State private var integrationCheckFailed = false
    @State private var isUpdating = false
    @State private var alert: IntegrationAlert?

    private enum IntegrationAlert: Identifiable {
        case install
        case remove
        case failure(String)

        var id: String {
            switch self {
            case .install: "install"
            case .remove: "remove"
            case .failure(let message): "failure-\(message)"
            }
        }
    }

    private var generatedConfig: String {
        (NSHomeDirectory() as NSString).appendingPathComponent(
            "Library/Application Support/floria/ssh/config")
    }

    private var includeLine: String {
        integration?.includeLine ?? "Include \"\(generatedConfig)\""
    }

    private var integrationTitle: String {
        guard let integration else {
            return integrationCheckFailed
                ? "SSH host routing requires manual setup" : "Checking SSH host routing…"
        }
        switch integration.state {
        case .disabled: return "SSH host routing is not enabled"
        case .managed: return "SSH host routing is enabled"
        case .external: return "SSH host routing is enabled manually"
        case .needsRepair: return "SSH host routing needs repair"
        }
    }

    private var integrationDetail: String {
        guard let integration else {
            return integrationCheckFailed
                ? "Copy the Include line into ~/.ssh/config manually." : includeLine
        }
        if !integration.writable {
            if integration.state == .needsRepair {
                return "The marker block contains unrecognized settings; inspect it manually."
            }
            return "Copy the Include line into the source managed by your dotfiles tool."
        }
        switch integration.state {
        case .disabled:
            return "Floria can add a reversible block at the top of ~/.ssh/config."
        case .managed:
            return "Floria manages only its marked Include block; all other settings stay untouched."
        case .external:
            return "A top-level Include already exists, so Floria will not claim or remove it."
        case .needsRepair:
            return "The marked block is misplaced. Repair moves it before the first Host or Match."
        }
    }

    private var integrationColor: Color {
        guard let integration else { return .secondary }
        switch integration.state {
        case .managed, .external: return .green
        case .disabled, .needsRepair: return .orange
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            ResourceCatalogView(
                store: store, title: "SSH Identities",
                subtitle: "Private keys managed by Floria, with optional external signing providers",
                kinds: [.sshIdentity, .sshAgent], search: search,
                addResourceTitle: "Import Private Key", addResource: importIdentity,
                secondaryResourceTitle: "External Agent",
                secondaryResource: connectExternalAgent)
                .frame(maxHeight: .infinity)
            Divider()
            HStack(spacing: 12) {
                Image(
                    systemName: integration?.state == .managed || integration?.state == .external
                        ? "checkmark.circle.fill" : "terminal")
                    .foregroundStyle(integrationColor)
                VStack(alignment: .leading, spacing: 3) {
                    Text(integrationTitle)
                        .font(.callout.weight(.medium))
                    Text(integrationDetail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                Button("Copy Include", systemImage: "doc.on.doc") {
                    copyToPasteboard(includeLine)
                }
                if let integration, integration.writable {
                    switch integration.state {
                    case .disabled, .needsRepair:
                        Button(integration.state == .disabled ? "Enable" : "Repair") {
                            alert = .install
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isUpdating)
                    case .managed:
                        Button("Disable") { alert = .remove }
                            .disabled(isUpdating)
                    case .external:
                        EmptyView()
                    }
                } else if integration == nil && !integrationCheckFailed {
                    ProgressView().controlSize(.small)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
            .background(.bar)
            .fixedSize(horizontal: false, vertical: true)
            .layoutPriority(1)
        }
        .task { await refreshIntegration() }
        .alert(item: $alert) { alert in
            switch alert {
            case .install:
                Alert(
                    title: Text(
                        integration?.state == .needsRepair
                            ? "Repair SSH Host Routing?" : "Enable SSH Host Routing?"),
                    message: Text(
                        "Floria will place this marked Include block before the first Host or Match in ~/.ssh/config:\n\n\(includeLine)"),
                    primaryButton: .default(Text("Continue")) { updateIntegration(install: true) },
                    secondaryButton: .cancel())
            case .remove:
                Alert(
                    title: Text("Disable SSH Host Routing?"),
                    message: Text(
                        "Floria will remove only its marked Include block. Generated routes and agent sockets remain available."),
                    primaryButton: .destructive(Text("Remove Include")) {
                        updateIntegration(install: false)
                    },
                    secondaryButton: .cancel())
            case .failure(let message):
                Alert(
                    title: Text("Could not update SSH config"), message: Text(message),
                    dismissButton: .default(Text("OK")))
            }
        }
    }

    @MainActor
    private func refreshIntegration() async {
        do {
            integration = try await store.sshConfigStatus()
            integrationCheckFailed = false
        } catch {
            integrationCheckFailed = true
            alert = .failure(error.localizedDescription)
        }
    }

    private func updateIntegration(install: Bool) {
        Task { @MainActor in
            isUpdating = true
            defer { isUpdating = false }
            do {
                if install {
                    integration = try await store.installSshConfig()
                } else {
                    integration = try await store.removeSshConfig()
                }
            } catch {
                alert = .failure(error.localizedDescription)
            }
        }
    }
}

private struct ResourceCatalogView: View {
    @Bindable var store: WorkspaceStore
    let title: String
    let subtitle: String
    let kinds: Set<WorkspaceResourceKind>
    let search: String
    let addResourceTitle: String
    let addResource: (() -> Void)?
    var secondaryResourceTitle: String? = nil
    var secondaryResource: (() -> Void)? = nil
    @State private var editingSharedSecret: WorkspaceResource?
    @State private var editingResourceInfo: WorkspaceResource?
    @State private var deletingSharedSecret: WorkspaceResource?
    @State private var deletingSshAgent: WorkspaceResource?

    private var filtered: [WorkspaceResource] {
        store.resources.filter { resource in
            kinds.contains(resource.kind)
                && (search.isEmpty
                    || resource.name.localizedCaseInsensitiveContains(search)
                    || resource.exportSummary.localizedCaseInsensitiveContains(search)
                    || (resource.metadata.note?.localizedCaseInsensitiveContains(search) == true)
                    || resource.metadata.links.contains {
                        $0.label.localizedCaseInsensitiveContains(search)
                            || $0.url.localizedCaseInsensitiveContains(search)
                    })
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.title2.bold())
                    Text(subtitle).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if let secondaryResourceTitle, let secondaryResource {
                    Button(secondaryResourceTitle, systemImage: "network", action: secondaryResource)
                        .buttonStyle(.bordered)
                }
                if let addResource {
                    Button(addResourceTitle, systemImage: "plus", action: addResource)
                        .buttonStyle(.borderedProminent)
                }
            }
            .padding(24)

            List(filtered) { resource in
                HStack(spacing: 12) {
                    ResourceIcon(kind: resource.kind)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(resource.name).font(.body.weight(.medium))
                        if let originSummary = resource.originSummary {
                            Text(originSummary)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        if let note = resource.metadata.note {
                            Text(note)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Text(resource.exportSummary)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 3) {
                        HStack(spacing: 7) {
                            ResourceKindBadge(kind: resource.kind)
                            SecurityLevelMenu(level: resource.securityLevel) { securityLevel in
                                try await store.updateResourceMetadata(
                                    resource.id, name: resource.name,
                                    securityLevel: securityLevel, metadata: resource.metadata)
                            }
                        }
                        Text("Used by \(resource.usageCount) projects")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if resource.kind == .sharedSecret || resource.kind == .envFile
                        || resource.kind == .sshIdentity || resource.kind == .sshAgent
                    {
                        Menu {
                            if resource.kind == .sharedSecret {
                                Button("Edit Secret…", systemImage: "pencil") {
                                    editingSharedSecret = resource
                                }
                            } else {
                                Button("Edit Security & Info…", systemImage: "pencil") {
                                    editingResourceInfo = resource
                                }
                            }
                            if !resource.metadata.links.isEmpty {
                                Divider()
                                ForEach(resource.metadata.links, id: \.self) { link in
                                    Button(link.label, systemImage: "link") {
                                        openMetadataLink(link)
                                    }
                                }
                            }
                            if resource.kind == .sharedSecret {
                                Divider()
                                Button("Delete Secret…", systemImage: "trash", role: .destructive) {
                                    deletingSharedSecret = resource
                                }
                            } else if resource.kind == .sshIdentity || resource.kind == .sshAgent {
                                Divider()
                                Button(
                                    resource.kind == .sshIdentity
                                        ? "Delete Identity…" : "Disconnect Agent…",
                                    systemImage: "trash", role: .destructive
                                ) {
                                    deletingSshAgent = resource
                                }
                            }
                        } label: {
                            Image(systemName: "ellipsis")
                                .frame(width: 28, height: 28)
                                .contentShape(Rectangle())
                        }
                        .menuStyle(.borderlessButton)
                        .menuIndicator(.hidden)
                        .fixedSize()
                        .accessibilityLabel("More actions for \(resource.name)")
                    }
                }
                .padding(.vertical, 5)
            }
            .overlay {
                if filtered.isEmpty {
                    if search.isEmpty {
                        ContentUnavailableView(
                            "No \(title.lowercased()) yet", systemImage: "tray",
                            description: Text(subtitle))
                    } else {
                        ContentUnavailableView.search(text: search)
                    }
                }
            }
        }
        .navigationTitle(title)
        .sheet(item: $editingSharedSecret) { resource in
            EditSharedSecretSheet(store: store, resource: resource)
        }
        .sheet(item: $editingResourceInfo) { resource in
            EditResourceMetadataSheet(store: store, resource: resource)
        }
        .alert(
            deletingSharedSecret?.usageCount == 0
                ? "Delete Shared Secret?" : "Shared Secret Is In Use",
            isPresented: Binding(
                get: { deletingSharedSecret != nil },
                set: { if !$0 { deletingSharedSecret = nil } })
        ) {
            if let resource = deletingSharedSecret, resource.usageCount == 0 {
                Button("Cancel", role: .cancel) { deletingSharedSecret = nil }
                Button("Delete Secret", role: .destructive) {
                    deleteSharedSecret(resource)
                }
            } else {
                Button("OK") { deletingSharedSecret = nil }
            }
        } message: {
            if let resource = deletingSharedSecret {
                if resource.usageCount == 0 {
                    Text("This permanently removes its encrypted value and version history.")
                } else {
                    Text(
                        "Remove \(resource.name) from its \(resource.usageCount) project binding\(resource.usageCount == 1 ? "" : "s") first."
                    )
                }
            }
        }
        .alert(
            deletingSshAgent?.usageCount == 0
                ? (deletingSshAgent?.kind == .sshIdentity
                    ? "Delete SSH Identity?" : "Disconnect SSH Agent?")
                : "SSH Identity Is In Use",
            isPresented: Binding(
                get: { deletingSshAgent != nil },
                set: { if !$0 { deletingSshAgent = nil } })
        ) {
            if let resource = deletingSshAgent, resource.usageCount == 0 {
                Button("Cancel", role: .cancel) { deletingSshAgent = nil }
                Button(
                    resource.kind == .sshIdentity ? "Delete Identity" : "Disconnect",
                    role: .destructive
                ) {
                    deleteSshAgent(resource)
                }
            } else {
                Button("OK") { deletingSshAgent = nil }
            }
        } message: {
            if let resource = deletingSshAgent {
                if resource.usageCount > 0 {
                    Text("Remove this identity provider from its project bindings first.")
                } else if resource.kind == .sshIdentity {
                    Text("This permanently removes the encrypted private-key copy from Floria. The original imported file is not changed.")
                } else {
                    Text("Floria removes only the saved public identity metadata. The external agent is not changed.")
                }
            }
        }
    }

    private func deleteSharedSecret(_ resource: WorkspaceResource) {
        deletingSharedSecret = nil
        Task {
            do {
                try await store.deleteSharedSecret(resource.id)
            } catch {
                store.lastError = error.localizedDescription
            }
        }
    }

    private func deleteSshAgent(_ resource: WorkspaceResource) {
        deletingSshAgent = nil
        Task {
            do {
                try await store.removeSshAgentResource(resource.id)
            } catch {
                store.lastError = error.localizedDescription
            }
        }
    }
}

private struct EditResourceMetadataSheet: View {
    @Bindable var store: WorkspaceStore
    let resource: WorkspaceResource

    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var note: String
    @State private var links: [EditableItemLink]
    @State private var securityLevel: WorkspaceSecurityLevel
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(store: WorkspaceStore, resource: WorkspaceResource) {
        self.store = store
        self.resource = resource
        _name = State(initialValue: resource.name)
        _note = State(initialValue: resource.metadata.note ?? "")
        _links = State(initialValue: editableLinks(resource.metadata))
        _securityLevel = State(initialValue: resource.securityLevel)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text(editTitle)
                    .font(.title2.bold())
                Text(editDetail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Name").font(.callout.weight(.medium))
                TextField("Team defaults", text: $name)
                    .textFieldStyle(.roundedBorder)
            }
            SecurityLevelPicker(selection: $securityLevel)
            ItemMetadataEditor(note: $note, links: $links)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save Changes", action: save)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        isSaving
                            || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 560)
        .alert(
            "Could not update \(resource.kind.title)",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private var editTitle: String {
        switch resource.kind {
        case .sshIdentity: "Edit SSH Identity"
        case .sshAgent: "Edit External Agent"
        default: "Edit Env File Info"
        }
    }

    private var editDetail: String {
        switch resource.kind {
        case .sshIdentity: "Change the security level and descriptive information for this managed key."
        case .sshAgent: "Change how this external signing provider is identified in Floria."
        default: "Change how this encrypted document is identified in Floria."
        }
    }

    private func save() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.updateResourceMetadata(
                    resource.id, name: name,
                    securityLevel: securityLevel,
                    metadata: itemMetadata(note: note, links: links))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct EditSharedSecretSheet: View {
    @Bindable var store: WorkspaceStore
    let resource: WorkspaceResource

    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var defaultKey: String
    @State private var newValue = ""
    @State private var note: String
    @State private var links: [EditableItemLink]
    @State private var securityLevel: WorkspaceSecurityLevel
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(store: WorkspaceStore, resource: WorkspaceResource) {
        self.store = store
        self.resource = resource
        _name = State(initialValue: resource.name)
        _defaultKey = State(initialValue: resource.defaultEnvKey ?? "")
        _note = State(initialValue: resource.metadata.note ?? "")
        _links = State(initialValue: editableLinks(resource.metadata))
        _securityLevel = State(initialValue: resource.securityLevel)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Edit Shared Secret").font(.title2.bold())
                Text("Change its metadata or rotate the encrypted value.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Name").font(.callout.weight(.medium))
                TextField("Cloudflare API Token", text: $name)
                    .textFieldStyle(.roundedBorder)
            }

            SecurityLevelPicker(selection: $securityLevel)
            ItemMetadataEditor(note: $note, links: $links)
            VStack(alignment: .leading, spacing: 7) {
                Text("Default environment key (optional)")
                    .font(.callout.weight(.medium))
                TextField("CLOUDFLARE_API_TOKEN", text: $defaultKey)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                Text("Leave empty for a keyless value used by Lines outputs.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 7) {
                Text("New secret value (optional)")
                    .font(.callout.weight(.medium))
                SecureField("Leave blank to keep the current value", text: $newValue)
                    .textFieldStyle(.roundedBorder)
                Text("Saving a new value appends an encrypted version; existing history is kept.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if !resource.originSources.isEmpty {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Sources").font(.callout.weight(.medium))
                    ForEach(resource.originSources, id: \.self) { source in
                        HStack(spacing: 6) {
                            Image(systemName: "doc.text")
                            Text((source.path as NSString).abbreviatingWithTildeInPath)
                                .font(.caption.monospaced())
                                .lineLimit(1)
                                .truncationMode(.middle)
                            if let environment = source.environment {
                                Text(environment)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .font(.caption)
                    }
                }
            }

            HStack(spacing: 7) {
                Image(systemName: "exclamationmark.triangle")
                Text("A key change must remain compatible with every output using this secret.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save Changes", action: save)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 500)
        .alert(
            "Could not update secret",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func save() {
        Task {
            isSaving = true
            defer { isSaving = false }
            let submittedValue = newValue
            newValue = ""
            do {
                try await store.updateSharedSecret(
                    resource.id, name: name, defaultEnvKey: defaultKey.uppercased(),
                    newValue: submittedValue,
                    securityLevel: securityLevel,
                    metadata: itemMetadata(note: note, links: links))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct AddBindingSheet: View {
    private struct IniEntryGroup: Identifiable {
        let id: String
        let sectionID: String
        let label: String
        var entries: [WorkspaceEntry]
    }

    @Bindable var store: WorkspaceStore
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""
    @State private var target = WorkspaceBindingTarget.environment
    @State private var outputSurfaceID = ""
    @State private var isSaving = false
    @State private var errorMessage: String?
    @State private var selectedEntries: [WorkspaceResource.ID: Set<String>] = [:]

    private var outputs: [WorkspaceSurface] {
        (store.selectedEnvironment?.surfaces ?? []).filter {
            $0.kind == .dotenvFile || $0.kind == .direnvFile || $0.kind == .iniFile
                || $0.kind == .linesFile || $0.kind == .unixSocket
        }
    }

    // Only resources the selected output can actually compose (an SSH identity
    // has no place in an env file); entry-level selection still gates Add.
    private func isListable(_ resource: WorkspaceResource) -> Bool {
        guard let surface = outputs.first(where: { $0.id == outputSurfaceID }) else {
            return false
        }
        let scope: WorkspaceBindingScope =
            target == .common ? .common : .environment(store.selectedEnvironmentID)
        return store.bindingIsCompatible(
            WorkspaceBinding(
                id: "prospective-binding", resourceID: resource.id, selection: .all,
                keyOverride: nil, isEnabled: true, scope: scope),
            with: surface.kind)
    }

    private var filtered: [WorkspaceResource] {
        let candidates = store.availableResources.filter(isListable)
        guard !search.isEmpty else { return candidates }
        return candidates.filter {
            $0.name.localizedCaseInsensitiveContains(search)
                || $0.kind.title.localizedCaseInsensitiveContains(search)
                || $0.exportSummary.localizedCaseInsensitiveContains(search)
                || $0.entries.contains { $0.label.localizedCaseInsensitiveContains(search) }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Add Binding").font(.title2.bold())
                    Text(
                        "Add to \(store.selectedProject?.name ?? "Project") · \(store.selectedEnvironment?.name ?? "Environment")"
                    )
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(20)

            Divider()
            Picker("Scope", selection: $target) {
                ForEach(WorkspaceBindingTarget.allCases, id: \.self) { target in
                    Text(target.title).tag(target)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 20)
            .padding(.vertical, 12)

            Divider()
            Picker("Output", selection: $outputSurfaceID) {
                ForEach(outputs) { surface in
                    Label(surface.name, systemImage: surface.kind.systemImage).tag(surface.id)
                }
            }
            .pickerStyle(.menu)
            .padding(.horizontal, 20)
            .padding(.vertical, 10)

            Divider()
            List(filtered) { resource in
                let conflicts = prospectiveConflicts(resource)
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 12) {
                        ResourceIcon(kind: resource.kind)
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 7) {
                                Text(resource.name).font(.body.weight(.medium))
                                ResourceKindBadge(kind: resource.kind)
                            }
                            Text(resource.exportSummary)
                                .font(.caption.monospaced())
                                .foregroundStyle(conflicts.isEmpty ? Color.secondary : Color.orange)
                            if !conflicts.isEmpty {
                                Text("Conflicts with \(conflicts.joined(separator: ", "))")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                            }
                        }
                        Spacer()
                        Button("Add") {
                            Task {
                                isSaving = true
                                defer { isSaving = false }
                                do {
                                    try await store.addResource(
                                        resource.id, target: target,
                                        selectedEntries: selectedAddressSet(for: resource),
                                        surfaceID: outputSurfaceID)
                                } catch {
                                    errorMessage = error.localizedDescription
                                }
                            }
                        }
                            .buttonStyle(.bordered)
                            .disabled(
                                !conflicts.isEmpty || !isCompatible(resource) || isSaving
                                    || (resource.entries.count > 1
                                        && selectedAddressSet(for: resource).isEmpty))
                    }

                    if resource.entries.count > 1 {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(
                                resource.codec == .ini
                                    ? "Include sections or entries in source order"
                                    : "Include entries in source order"
                            )
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            if resource.codec == .ini {
                                ForEach(iniEntryGroups(for: resource)) { group in
                                    Toggle(
                                        group.label,
                                        isOn: Binding(
                                            get: {
                                                let selected = selectedAddressSet(for: resource)
                                                return group.entries.allSatisfy {
                                                    selected.contains($0.address)
                                                }
                                            },
                                            set: {
                                                setEntries(
                                                    group.entries, selected: $0, in: resource)
                                            })
                                    )
                                    .toggleStyle(.checkbox)
                                    .font(.callout.weight(.semibold))
                                    ForEach(group.entries) { entry in
                                        Toggle(
                                            entry.key ?? entry.label,
                                            isOn: Binding(
                                                get: {
                                                    selectedAddressSet(for: resource)
                                                        .contains(entry.address)
                                                },
                                                set: {
                                                    setEntry(
                                                        entry.address, selected: $0, in: resource)
                                                })
                                        )
                                        .toggleStyle(.checkbox)
                                        .font(.callout)
                                        .padding(.leading, 18)
                                    }
                                }
                            } else {
                                ForEach(resource.entries) { entry in
                                    Toggle(
                                        entry.label,
                                        isOn: Binding(
                                            get: {
                                                selectedAddressSet(for: resource)
                                                    .contains(entry.address)
                                            },
                                            set: {
                                                setEntry(entry.address, selected: $0, in: resource)
                                            })
                                    )
                                    .toggleStyle(.checkbox)
                                    .font(.callout)
                                }
                            }
                        }
                        .padding(.leading, 46)
                    }
                }
                .padding(.vertical, 5)
            }
            .overlay {
                if filtered.isEmpty {
                    ContentUnavailableView("No bindings available", systemImage: "checkmark.circle")
                }
            }
        }
        .searchable(text: $search, prompt: "Search resources and entries")
        .frame(minWidth: 580, minHeight: 460)
        .onAppear {
            if outputSurfaceID.isEmpty {
                outputSurfaceID = outputs.contains(where: { $0.id == store.selectedSurfaceID })
                    ? store.selectedSurfaceID : outputs.first?.id ?? ""
            }
        }
        .alert(
            "Could not add binding",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func prospectiveConflicts(_ resource: WorkspaceResource) -> [String] {
        guard let kind = outputs.first(where: { $0.id == outputSurfaceID })?.kind else { return [] }
        let selected = selectedAddressSet(for: resource)
        switch kind {
        case .dotenvFile, .direnvFile:
            let current = Set(store.resolvedExports(for: outputSurfaceID).map(\.key))
            return resource.entries
                .filter { selected.contains($0.address) }
                .compactMap(\.key)
                .filter(current.contains)
                .sorted()
        case .iniFile:
            let current = Set(store.bindings(for: outputSurfaceID).flatMap { binding in
                guard let existing = store.resource(binding.resourceID) else { return [String]() }
                let included = Set(binding.selection.addresses(in: existing))
                return existing.entries.filter { included.contains($0.address) }.map(\.address)
            })
            return resource.entries
                .filter { selected.contains($0.address) && current.contains($0.address) }
                .map(\.label)
        case .linesFile, .envFileDirect, .unixSocket:
            return []
        }
    }

    private func isCompatible(_ resource: WorkspaceResource) -> Bool {
        guard let surface = outputs.first(where: { $0.id == outputSurfaceID }) else { return false }
        let addresses = resource.entries.map(\.address).filter {
            selectedAddressSet(for: resource).contains($0)
        }
        let selection: WorkspaceEntrySelection = addresses.count == resource.entries.count
            ? .all : .entries(addresses)
        let scope: WorkspaceBindingScope = target == .common
            ? .common : .environment(store.selectedEnvironmentID)
        return store.bindingIsCompatible(
            WorkspaceBinding(
                id: "prospective-binding", resourceID: resource.id, selection: selection,
                keyOverride: nil, isEnabled: true, scope: scope),
            with: surface.kind)
    }

    private func selectedAddressSet(for resource: WorkspaceResource) -> Set<String> {
        selectedEntries[resource.id] ?? Set(resource.entries.map(\.address))
    }

    private func setEntry(_ address: String, selected: Bool, in resource: WorkspaceResource) {
        var addresses = selectedAddressSet(for: resource)
        if selected { addresses.insert(address) } else { addresses.remove(address) }
        selectedEntries[resource.id] = addresses
    }

    private func setEntries(
        _ entries: [WorkspaceEntry], selected: Bool, in resource: WorkspaceResource
    ) {
        var addresses = selectedAddressSet(for: resource)
        for entry in entries {
            if selected { addresses.insert(entry.address) } else { addresses.remove(entry.address) }
        }
        selectedEntries[resource.id] = addresses
    }

    private func iniEntryGroups(for resource: WorkspaceResource) -> [IniEntryGroup] {
        var groups: [IniEntryGroup] = []
        for entry in resource.entries {
            let identity = iniSectionIdentity(for: entry.address)
            if let index = groups.indices.last, groups[index].sectionID == identity.id {
                groups[index].entries.append(entry)
            } else {
                groups.append(
                    IniEntryGroup(
                        id: "\(identity.id)#\(groups.count)", sectionID: identity.id,
                        label: identity.label, entries: [entry]))
            }
        }
        return groups
    }

    private func iniSectionIdentity(for address: String) -> (id: String, label: String) {
        if address.hasPrefix("root/keys/") {
            return ("root", "Root")
        }
        let prefix = "sections/"
        guard address.hasPrefix(prefix) else {
            return (address, "Other")
        }
        let contentStart = address.index(address.startIndex, offsetBy: prefix.count)
        guard let keys = address.range(of: "/keys/", range: contentStart..<address.endIndex) else {
            return (address, "Other")
        }
        let encoded = String(address[contentStart..<keys.lowerBound])
        let decoded = encoded.replacingOccurrences(of: "~1", with: "/")
            .replacingOccurrences(of: "~0", with: "~")
        return (String(address[..<keys.lowerBound]), decoded)
    }
}

private struct ProtectExistingFileSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var path = ""
    @State private var isSaving = false
    @State private var confirmingProtection = false
    @State private var errorMessage: String?

    private var kind: WorkspaceProtectedFileKind {
        WorkspaceProtectedFileKind.infer(from: path)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Protect Existing File").font(.title2.bold())
                Text("Encrypt a local file and keep applications using its original path.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("File").font(.callout.weight(.medium))
                HStack {
                    TextField("Choose .env, .envrc, .pgpass, or credentials", text: $path)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                    Button("Choose…", action: chooseFile)
                }
            }

            if !path.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: kind.systemImage)
                        .foregroundStyle(.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(kind.title).font(.callout.weight(.medium))
                        Text("Content is preserved byte-for-byte; this preset changes no syntax.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.blue.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            VStack(alignment: .leading, spacing: 9) {
                Label(
                    "Floria encrypts the complete file before atomically replacing the original with a managed link.",
                    systemImage: "lock.fill")
                Label(
                    "The same path remains readable and writable; each successful save creates an immutable version.",
                    systemImage: "arrow.triangle.2.circlepath")
                Label(
                    "The encrypted store is the recovery copy. No plaintext backup is left beside the file.",
                    systemImage: "externaldrive.fill")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            if kind == .direnv {
                Label(
                    "direnv reads this file from the shell session, so authorization cannot distinguish child processes that inherit its values.",
                    systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Protect File") { confirmingProtection = true }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || path.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 620)
        .alert("Replace the original with a Floria link?", isPresented: $confirmingProtection) {
            Button("Cancel", role: .cancel) { }
            Button("Protect File", action: protectFile)
        } message: {
            Text("The plaintext file is removed from disk only after its encrypted copy is safely stored. Applications continue using \(path).")
        }
        .alert(
            "Could not protect file",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.resolvesAliases = false
        if panel.runModal() == .OK, let url = panel.url {
            path = url.path
        }
    }

    private func protectFile() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.protectFile(at: path)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct NewProjectSheet: View {
    @Bindable var store: WorkspaceStore
    let onCreated: (WorkspaceProject.ID) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var path = ""
    @State private var initialFileName = WorkspaceSurfaceKind.dotenvFile.defaultFileName
    @State private var initialSurfaceKind = WorkspaceSurfaceKind.dotenvFile
    @State private var isSaving = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add Project").font(.title2.bold())
                Text("Floria creates a Development environment and its first read-only output.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Project directory").font(.callout.weight(.medium))
                HStack {
                    TextField("Choose a local directory", text: $path)
                        .textFieldStyle(.roundedBorder)
                    Button("Choose…", action: chooseDirectory)
                }
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Name").font(.callout.weight(.medium))
                TextField("Project name", text: $name)
                    .textFieldStyle(.roundedBorder)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Initial output").font(.callout.weight(.medium))
                HStack {
                    Picker(
                        "Format",
                        selection: Binding(
                            get: { initialSurfaceKind },
                            set: { newKind in
                                if initialFileName == initialSurfaceKind.defaultFileName {
                                    initialFileName = newKind.defaultFileName
                                }
                                initialSurfaceKind = newKind
                            })
                    ) {
                        ForEach(WorkspaceSurfaceKind.composedCases, id: \.self) { kind in
                            Text(kind.title).tag(kind)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 180)
                    TextField("File name", text: $initialFileName)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                }
            }

            HStack {
                Image(systemName: "info.circle")
                Text("An existing file or symlink is never replaced.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Project") { createProject() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        isSaving || name.isEmpty || path.isEmpty
                            || initialFileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 520)
        .alert(
            "Could not add project",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func chooseDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = false
        if panel.runModal() == .OK, let url = panel.url {
            path = url.path
            if name.isEmpty { name = url.lastPathComponent }
        }
    }

    private func createProject() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                let projectID = try await store.createProject(
                    name: name, path: path, initialFileName: initialFileName,
                    initialSurfaceKind: initialSurfaceKind)
                onCreated(projectID)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct NewSharedSecretSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var defaultKey = ""
    @State private var value = ""
    @State private var note = ""
    @State private var links: [EditableItemLink] = []
    @State private var securityLevel = WorkspaceSecurityLevel.confirmation
    @State private var isSaving = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("New Shared Secret").font(.title2.bold())
                Text("Create it once, then bind it into any project environment.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            field("Name") {
                TextField("Cloudflare API Token", text: $name)
                    .textFieldStyle(.roundedBorder)
            }
            field("Default environment key (optional)") {
                TextField("CLOUDFLARE_API_TOKEN", text: $defaultKey)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                Text("Leave empty for an opaque, keyless value that can be used by Lines outputs.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            field("Secret value") {
                SecureField("Value", text: $value)
                    .textFieldStyle(.roundedBorder)
            }

            SecurityLevelPicker(selection: $securityLevel)
            ItemMetadataEditor(note: $note, links: $links)

            HStack {
                Image(systemName: "lock.fill")
                Text("The catalog stores only an encrypted-secret reference; previews stay masked.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Secret") { createSecret() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || name.isEmpty || value.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 500)
        .alert(
            "Could not create secret",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func field<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title).font(.callout.weight(.medium))
            content()
        }
    }

    private func createSecret() {
        Task {
            isSaving = true
            defer { isSaving = false }
            let submittedValue = value
            value = ""
            do {
                try await store.createSharedSecret(
                    name: name, defaultEnvKey: defaultKey.uppercased(), value: submittedValue,
                    securityLevel: securityLevel,
                    metadata: itemMetadata(note: note, links: links))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct NewEnvFileSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var codec = WorkspaceResourceCodec.dotenv
    @State private var iniPreset = WorkspaceIniPreset.generic
    @State private var value = ""
    @State private var note = ""
    @State private var links: [EditableItemLink] = []
    @State private var securityLevel = WorkspaceSecurityLevel.confirmation
    @State private var isSaving = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("New Env File").font(.title2.bold())
                    Text("Store one structured document, then select entries for project outputs.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Load File…", action: chooseFile)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Name").font(.callout.weight(.medium))
                TextField("Team defaults", text: $name)
                    .textFieldStyle(.roundedBorder)
            }

            Picker("Format", selection: $codec) {
                Text("Dotenv").tag(WorkspaceResourceCodec.dotenv)
                Text("INI").tag(WorkspaceResourceCodec.ini)
            }
            .pickerStyle(.segmented)

            if codec == .ini {
                VStack(alignment: .leading, spacing: 7) {
                    Text("INI use case").font(.callout.weight(.medium))
                    Picker("INI use case", selection: $iniPreset) {
                        ForEach(WorkspaceIniPreset.allCases, id: \.self) { preset in
                            Text(preset.title).tag(preset)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                    Text(iniPreset.sectionGuidance)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .onChange(of: iniPreset) {
                    if name.isEmpty
                        || WorkspaceIniPreset.allCases.map(\.suggestedResourceName).contains(name)
                    {
                        name = iniPreset.suggestedResourceName
                    }
                }
            }

            VStack(alignment: .leading, spacing: 7) {
                Text(codec == .ini ? "INI content" : "Dotenv content")
                    .font(.callout.weight(.medium))
                TextEditor(text: $value)
                    .font(.body.monospaced())
                    .scrollContentBackground(.hidden)
                    .padding(8)
                    .background(Color(nsColor: .textBackgroundColor))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay {
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
                    }
                    .overlay(alignment: .topLeading) {
                        if value.isEmpty {
                            Text(
                                codec == .ini
                                    ? iniPreset.contentPlaceholder
                                    : "API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug"
                            )
                                .font(.body.monospaced())
                                .foregroundStyle(.tertiary)
                                .padding(13)
                                .allowsHitTesting(false)
                        }
                    }
                    .frame(minHeight: 230)
            }

            SecurityLevelPicker(selection: $securityLevel)
            ItemMetadataEditor(note: $note, links: $links)

            HStack {
                Image(systemName: "lock.fill")
                Text("Values are encrypted in the store; only section and key metadata appears in the catalog.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Env File", action: createEnvFile)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || name.isEmpty || value.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 620, height: 820)
        .alert(
            "Could not create Env File",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            do {
                value = try String(contentsOf: url, encoding: .utf8)
                if name.isEmpty { name = url.lastPathComponent }
                if ["ini", "cfg", "conf"].contains(url.pathExtension.lowercased()) {
                    codec = .ini
                }
            } catch {
                errorMessage = "Could not read \(url.path): \(error.localizedDescription)"
            }
        }
    }

    private func createEnvFile() {
        Task {
            isSaving = true
            defer { isSaving = false }
            let submittedValue = value
            value = ""
            do {
                try await store.createEnvFile(
                    name: name, codec: codec, value: submittedValue,
                    securityLevel: securityLevel,
                    metadata: itemMetadata(note: note, links: links))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct NewEnvironmentSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var fileName = ""
    @State private var customizedFileName = false
    @State private var isSaving = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("New Environment").font(.title2.bold())
                Text("Each environment owns its bindings and can expose multiple output files.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Name").font(.callout.weight(.medium))
                TextField("Staging", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: name) {
                        if !customizedFileName {
                            fileName = availableEnvironmentFileName(name, in: store.selectedProject)
                        }
                    }
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Initial composed output").font(.callout.weight(.medium))
                TextField(
                    ".env.staging",
                    text: Binding(
                        get: { fileName },
                        set: {
                            fileName = $0
                            customizedFileName = true
                        }))
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                Text("The output is read-only and generated from this environment's bindings.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Environment", action: createEnvironment)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || name.isEmpty || fileName.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 540)
        .alert(
            "Could not create environment",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func createEnvironment() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.createEnvironment(name: name, fileName: fileName)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct AddDotenvSurfaceSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var fileName = ""
    @State private var selectedBindingIDs: Set<WorkspaceBinding.ID> = []
    @State private var isSaving = false
    @State private var errorMessage: String?

    private var candidates: [WorkspaceBinding] {
        store.compatibleBindings(for: .dotenvFile)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add Composed Env Output").font(.title2.bold())
                Text("Expose the selected environment's bindings as another read-only dotenv file.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Project file name").font(.callout.weight(.medium))
                TextField(".env.generated", text: $fileName)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Included bindings").font(.callout.weight(.medium))
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(candidates) { binding in
                            Toggle(
                                store.resource(binding.resourceID)?.name ?? binding.resourceID,
                                isOn: bindingSelection(binding.id)
                            )
                            .toggleStyle(.checkbox)
                        }
                        if candidates.isEmpty {
                            Text("No compatible bindings yet. You can add them later.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 170)
            }

            HStack(alignment: .top) {
                Image(systemName: "info.circle")
                Text("Different outputs may later use different projections such as dotenv or direnv. This output currently uses dotenv.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Output", action: createSurface)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || fileName.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 560)
        .onAppear {
            if fileName.isEmpty {
                fileName = availableEnvironmentFileName(
                    store.selectedEnvironment?.name ?? "generated", in: store.selectedProject)
            }
            if selectedBindingIDs.isEmpty {
                selectedBindingIDs = Set(candidates.map(\.id))
            }
        }
        .alert(
            "Could not create output",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func createSurface() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.createDotenvSurface(
                    fileName: fileName,
                    bindingIDs: candidates.map(\.id).filter(selectedBindingIDs.contains))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func bindingSelection(_ id: WorkspaceBinding.ID) -> Binding<Bool> {
        Binding(
            get: { selectedBindingIDs.contains(id) },
            set: { selected in
                if selected { selectedBindingIDs.insert(id) }
                else { selectedBindingIDs.remove(id) }
            })
    }
}

private struct AddDirenvSurfaceSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var fileName = ".envrc"
    @State private var selectedBindingIDs: Set<WorkspaceBinding.ID> = []
    @State private var isSaving = false
    @State private var errorMessage: String?

    private var candidates: [WorkspaceBinding] {
        store.compatibleBindings(for: .direnvFile)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add direnv Output").font(.title2.bold())
                Text("Generate a read-only .envrc containing strictly quoted export statements.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Project file name").font(.callout.weight(.medium))
                TextField(".envrc", text: $fileName)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Included bindings").font(.callout.weight(.medium))
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(candidates) { binding in
                            Toggle(
                                store.resource(binding.resourceID)?.name ?? binding.resourceID,
                                isOn: bindingSelection(binding.id)
                            )
                            .toggleStyle(.checkbox)
                        }
                        if candidates.isEmpty {
                            Text("No compatible keyed bindings yet. You can add them later.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 170)
            }

            HStack(alignment: .top) {
                Image(systemName: "exclamationmark.triangle")
                Text("direnv reads .envrc from the shell session. Floria can authorize that read, but cannot separately identify child processes that inherit the exported values.")
            }
            .font(.caption)
            .foregroundStyle(.orange)

            HStack(alignment: .top) {
                Image(systemName: "lock.fill")
                Text("Resources contribute values only. Shell commands, substitutions, and unquoted fragments cannot be injected into this output.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Output", action: createSurface)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || fileName.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 560)
        .onAppear {
            if selectedBindingIDs.isEmpty {
                selectedBindingIDs = Set(candidates.map(\.id))
            }
        }
        .alert(
            "Could not create direnv output",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func createSurface() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.createDirenvSurface(
                    fileName: fileName,
                    bindingIDs: candidates.map(\.id).filter(selectedBindingIDs.contains))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func bindingSelection(_ id: WorkspaceBinding.ID) -> Binding<Bool> {
        Binding(
            get: { selectedBindingIDs.contains(id) },
            set: { selected in
                if selected { selectedBindingIDs.insert(id) }
                else { selectedBindingIDs.remove(id) }
            })
    }
}

private struct AddIniSurfaceSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var preset = WorkspaceIniPreset.generic
    @State private var fileName = WorkspaceIniPreset.generic.suggestedOutputName
    @State private var customizedFileName = false
    @State private var selectedBindingIDs: Set<WorkspaceBinding.ID> = []
    @State private var isSaving = false
    @State private var errorMessage: String?

    private var candidates: [WorkspaceBinding] {
        store.compatibleBindings(for: .iniFile)
    }

    private var outputPath: String {
        guard let project = store.selectedProject else { return fileName }
        return (project.path as NSString).appendingPathComponent(fileName)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add INI Output").font(.title2.bold())
                Text("Render selected entries from INI resources as a read-only structured file.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Use case").font(.callout.weight(.medium))
                Picker("Use case", selection: $preset) {
                    ForEach(WorkspaceIniPreset.allCases, id: \.self) { item in
                        Text(item.title).tag(item)
                    }
                }
                .labelsHidden()
                .pickerStyle(.segmented)
                Text(preset.sectionGuidance)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .onChange(of: preset) {
                if !customizedFileName { fileName = preset.suggestedOutputName }
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Project file name").font(.callout.weight(.medium))
                TextField(
                    preset.suggestedOutputName,
                    text: Binding(
                        get: { fileName },
                        set: {
                            fileName = $0
                            customizedFileName = true
                        }))
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
            }

            if let environmentKey = preset.pathEnvironmentKey {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("Point AWS to this project-scoped output")
                            .font(.caption.weight(.semibold))
                        Spacer()
                        Button("Copy path") { copyToPasteboard(outputPath) }
                            .controlSize(.small)
                    }
                    Text("\(environmentKey)=\(outputPath)")
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    Text("Floria leaves the global ~/.aws files untouched, so projects and environments do not replace one another.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(10)
                .background(Color.blue.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Included bindings").font(.callout.weight(.medium))
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(candidates) { binding in
                            Toggle(
                                store.resource(binding.resourceID)?.name ?? binding.resourceID,
                                isOn: bindingSelection(binding.id)
                            )
                            .toggleStyle(.checkbox)
                        }
                        if candidates.isEmpty {
                            Text("Bind an INI Env File first, or create an empty output.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 170)
            }

            HStack(alignment: .top) {
                Image(systemName: "lock.fill")
                Text("Only selected entries are rendered. Root entries are placed before sections; duplicate section keys are rejected.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Output", action: createSurface)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || fileName.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 620)
        .onAppear {
            if selectedBindingIDs.isEmpty {
                selectedBindingIDs = Set(candidates.map(\.id))
            }
        }
        .alert(
            "Could not create INI output",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func createSurface() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.createIniSurface(
                    fileName: fileName,
                    bindingIDs: candidates.map(\.id).filter(selectedBindingIDs.contains))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func bindingSelection(_ id: WorkspaceBinding.ID) -> Binding<Bool> {
        Binding(
            get: { selectedBindingIDs.contains(id) },
            set: { selected in
                if selected { selectedBindingIDs.insert(id) }
                else { selectedBindingIDs.remove(id) }
            })
    }
}

private struct AddLinesSurfaceSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var fileName = ".pgpass"
    @State private var selectedBindingIDs: Set<WorkspaceBinding.ID> = []
    @State private var isSaving = false
    @State private var errorMessage: String?

    private var candidates: [WorkspaceBinding] {
        store.compatibleBindings(for: .linesFile)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add Lines Output").font(.title2.bold())
                Text("Compose bound keyless values as a read-only file, one opaque value per line.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("Project file name").font(.callout.weight(.medium))
                TextField(".pgpass", text: $fileName)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Included bindings").font(.callout.weight(.medium))
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(candidates) { binding in
                            Toggle(
                                store.resource(binding.resourceID)?.name ?? binding.resourceID,
                                isOn: bindingSelection(binding.id)
                            )
                            .toggleStyle(.checkbox)
                        }
                        if candidates.isEmpty {
                            Text("Add a keyless scalar binding first, or create an empty output.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 170)
            }

            HStack(alignment: .top) {
                Image(systemName: "lock.fill")
                Text("The file name and value syntax are not interpreted. Binding order determines line order; .pgpass is one possible use.")
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Output", action: createSurface)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || fileName.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 560)
        .onAppear {
            if selectedBindingIDs.isEmpty {
                selectedBindingIDs = Set(candidates.map(\.id))
            }
        }
        .alert(
            "Could not create Lines output",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func createSurface() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.createLinesSurface(
                    fileName: fileName,
                    bindingIDs: candidates.map(\.id).filter(selectedBindingIDs.contains))
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func bindingSelection(_ id: WorkspaceBinding.ID) -> Binding<Bool> {
        Binding(
            get: { selectedBindingIDs.contains(id) },
            set: { selected in
                if selected { selectedBindingIDs.insert(id) }
                else { selectedBindingIDs.remove(id) }
            })
    }
}

private struct AddDirectEnvFileSurfaceSheet: View {
    @Bindable var store: WorkspaceStore

    @Environment(\.dismiss) private var dismiss
    @State private var resourceID = ""
    @State private var fileName = ".env.local"
    @State private var isSaving = false
    @State private var errorMessage: String?

    private var resource: WorkspaceResource? {
        store.envFileResources.first { $0.id == resourceID }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add Direct Env File").font(.title2.bold())
                Text("Expose one stored EnvFile as an editable file in this project.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if store.envFileResources.isEmpty {
                ContentUnavailableView(
                    "No Env Files", systemImage: "doc.badge.plus",
                    description: Text("Create an Env File resource first."))
                    .frame(maxWidth: .infinity, minHeight: 180)
            } else {
                VStack(alignment: .leading, spacing: 7) {
                    Text("Env File").font(.callout.weight(.medium))
                    Picker("Env File", selection: $resourceID) {
                        ForEach(store.envFileResources) { resource in
                            Text("\(resource.name) · \(resource.exportSummary)").tag(resource.id)
                        }
                    }
                    .labelsHidden()
                    .frame(maxWidth: .infinity)
                }

                VStack(alignment: .leading, spacing: 7) {
                    Text("Project file name").font(.callout.weight(.medium))
                    TextField(".env.local", text: $fileName)
                        .textFieldStyle(.roundedBorder)
                        .font(.body.monospaced())
                }

                if let resource {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Editable values").font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Text(resource.exports.map(\.key).joined(separator: " · "))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(3)
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.primary.opacity(0.035))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }

                HStack(alignment: .top) {
                    Image(systemName: "info.circle")
                    Text("Values may be edited through the file. Adding or removing KEYs is rejected because bindings depend on the catalog schema. Existing paths are never replaced.")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Divider()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Create Direct File", action: createSurface)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isSaving || resourceID.isEmpty || fileName.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 560)
        .onAppear {
            if resourceID.isEmpty { resourceID = store.envFileResources.first?.id ?? "" }
        }
        .alert(
            "Could not create direct Env File",
            isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } })
        ) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "Unknown error")
        }
    }

    private func createSurface() {
        Task {
            isSaving = true
            defer { isSaving = false }
            do {
                try await store.createDirectEnvFileSurface(
                    resourceID: resourceID, fileName: fileName)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

private struct ResourceIcon: View {
    let kind: WorkspaceResourceKind

    var body: some View {
        Image(systemName: kind.systemImage)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(kind.tint)
            .frame(width: 34, height: 34)
            .background(kind.tint.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct ResourceKindBadge: View {
    let kind: WorkspaceResourceKind
    var label: String?

    var body: some View {
        Text(label ?? kind.title)
            .font(.caption2.weight(.medium))
            .foregroundStyle(kind.tint)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(kind.tint.opacity(0.09))
            .clipShape(RoundedRectangle(cornerRadius: 5))
    }
}

private extension WorkspaceResourceKind {
    var tint: Color {
        switch self {
        case .sharedSecret, .secret: .orange
        case .envFile: .purple
        case .literal: .secondary
        case .command: .teal
        case .sshIdentity: .indigo
        case .sshAgent: .blue
        }
    }
}
