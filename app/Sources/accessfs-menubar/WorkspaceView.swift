import AppKit
import SwiftUI

private enum WorkspaceSidebarSelection: Hashable {
    case projects
    case project(WorkspaceProject.ID)
    case sharedSecrets
    case envFiles
    case accessLog
}

/// Main product workspace: choose a project and environment, compose typed bindings,
/// then inspect the concrete file/socket surfaces exposed to local processes.
struct DashboardView: View {
    @Bindable var state: AppState
    @State private var selection: WorkspaceSidebarSelection? = .project("floria-web")
    @State private var search = ""

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
        .onChange(of: selection) {
            guard case .project(let id) = selection else { return }
            state.workspace.selectProject(id)
        }
    }

    private var workspaceToolbar: some View {
        HStack(spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search projects and secrets", text: $search)
                    .textFieldStyle(.plain)
            }
            .padding(.horizontal, 12)
            .frame(maxWidth: 430)
            .frame(height: 34)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.secondary.opacity(0.22), lineWidth: 1)
            }

            Button { } label: {
                Image(systemName: "plus")
                    .frame(width: 30, height: 30)
            }
            .buttonStyle(.bordered)

            Spacer(minLength: 16)

            Button { } label: {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(state.connected ? Color.green : Color.secondary)
                    Image(systemName: "chevron.down")
                        .font(.caption)
                }
                .frame(height: 30)
            }
            .buttonStyle(.bordered)
        }
        .padding(.horizontal, 18)
        .frame(height: 90)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Text("floria")
                        .font(.title2.bold())
                        .padding(.horizontal, 18)
                        .padding(.top, 55)
                        .padding(.bottom, 24)

                    sidebarSectionTitle("Workspace")
                    VStack(spacing: 3) {
                        sidebarRow("Projects", systemImage: "folder", tag: .projects)
                        sidebarRow("Shared Secrets", systemImage: "key", tag: .sharedSecrets)
                        sidebarRow("Env Files", systemImage: "doc.badge.gearshape", tag: .envFiles)
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
                                systemImage: "shippingbox",
                                tag: .project(project.id))
                        }
                    }
                }
                .padding(.bottom, 16)
            }

            Divider()
            HStack(spacing: 7) {
                Circle()
                    .fill(state.connected ? Color.green : Color.secondary.opacity(0.45))
                    .frame(width: 8, height: 8)
                Text(state.connected ? "Daemon running" : "Daemon starting")
                    .font(.caption)
                    .foregroundStyle(state.connected ? Color.green : Color.secondary)
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 8)
            .background(
                state.connected ? Color.green.opacity(0.09) : Color.secondary.opacity(0.08),
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
            ProjectCatalogView(store: state.workspace, selection: $selection, search: search)
        case .project:
            ProjectWorkspaceView(store: state.workspace, state: state)
        case .sharedSecrets:
            ResourceCatalogView(
                store: state.workspace, title: "Shared Secrets",
                subtitle: "Reusable scalar values with a default environment key",
                kinds: [.sharedSecret, .secret], search: search)
        case .envFiles:
            ResourceCatalogView(
                store: state.workspace, title: "Env Files",
                subtitle: "Reusable groups of environment variables",
                kinds: [.envFile], search: search)
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
    @State private var tab = ProjectWorkspaceTab.bindings
    @State private var showingAddBinding = false

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
            SurfaceInspector(store: store)
                .frame(width: 390)
        }
        .sheet(isPresented: $showingAddBinding) {
            AddBindingSheet(store: store)
        }
        .navigationTitle(store.selectedProject.name)
    }

    private var projectHeader: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(store.selectedProject.name)
                        .font(.title2.bold())
                    Text(store.selectedProject.path)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button { } label: {
                    Image(systemName: "ellipsis")
                }
                .buttonStyle(.bordered)
            }

            Picker(
                "Environment",
                selection: Binding(
                    get: { store.selectedEnvironmentID },
                    set: { store.selectEnvironment($0) })
            ) {
                ForEach(store.selectedProject.environments) { environment in
                    Text(environment.name).tag(environment.id)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 520)
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
                    title: "\(store.selectedEnvironment.name) only",
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

    var body: some View {
        HStack(spacing: 12) {
            ResourceIcon(kind: resource.kind)
            VStack(alignment: .leading, spacing: 3) {
                Text(resource.name)
                    .font(.body.weight(.medium))
                HStack(spacing: 7) {
                    ResourceKindBadge(kind: resource.kind)
                    Text(resource.exportSummary)
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
                    set: { _ in store.toggleBinding(binding.id) })
            )
            .toggleStyle(.switch)
            .labelsHidden()
            .controlSize(.small)
            Button { } label: { Image(systemName: "ellipsis") }
                .buttonStyle(.plain)
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

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Picker(
                        "Surface",
                        selection: Binding(
                            get: { store.selectedSurfaceID },
                            set: { store.selectedSurfaceID = $0 })
                    ) {
                        ForEach(store.selectedEnvironment.surfaces) { surface in
                            Label(surface.name, systemImage: surface.kind.systemImage).tag(surface.id)
                        }
                    }
                    .pickerStyle(.menu)
                    .labelsHidden()
                    .font(.headline)
                    Spacer()
                    SurfaceStatusBadge(status: store.selectedSurface.status)
                }
                Text(store.selectedSurface.path)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
            }
            .padding(20)

            Divider()
            switch store.selectedSurface.kind {
            case .dotenvFile:
                DotenvSurfacePreview(store: store)
            case .unixSocket:
                SocketSurfacePreview(store: store)
            case .regularFile:
                ContentUnavailableView("No preview", systemImage: "doc")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(Color.primary.opacity(0.018))
    }
}

private struct DotenvSurfacePreview: View {
    @Bindable var store: WorkspaceStore

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
                note: "Generated on open · Read only")
        }
    }
}

private struct SocketSurfacePreview: View {
    @Bindable var store: WorkspaceStore

    private var resource: WorkspaceResource? {
        guard let resourceID = store.selectedSurface.resourceID else { return nil }
        return store.resource(resourceID)
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    InspectorSection(title: "Endpoint") {
                        Text(store.selectedSurface.path)
                            .font(.caption.monospaced())
                            .lineLimit(3)
                            .truncationMode(.middle)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                    InspectorSection(title: "Capability") {
                        Label(resource?.detail ?? "SSH signing proxy", systemImage: "key.horizontal")
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
                note: "Real Unix socket · Policy on connect and sign")
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

    var body: some View {
        VStack(spacing: 10) {
            Divider()
            HStack {
                Button(secondaryTitle) { }
                Spacer()
                Button(primaryTitle) { }
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

    private var filtered: [WorkspaceProject] {
        guard !search.isEmpty else { return store.projects }
        return store.projects.filter {
            $0.name.localizedCaseInsensitiveContains(search)
                || $0.path.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Projects").font(.title2.bold())
                Text("Compose environments and surfaces for each local workspace")
                    .font(.callout)
                    .foregroundStyle(.secondary)
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
        }
        .navigationTitle("Projects")
    }
}

private struct ResourceCatalogView: View {
    @Bindable var store: WorkspaceStore
    let title: String
    let subtitle: String
    let kinds: Set<WorkspaceResourceKind>
    let search: String

    private var filtered: [WorkspaceResource] {
        store.resources.filter { resource in
            kinds.contains(resource.kind)
                && (search.isEmpty
                    || resource.name.localizedCaseInsensitiveContains(search)
                    || resource.exportSummary.localizedCaseInsensitiveContains(search))
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.title2.bold())
                Text(subtitle).font(.callout).foregroundStyle(.secondary)
            }
            .padding(24)

            List(filtered) { resource in
                HStack(spacing: 12) {
                    ResourceIcon(kind: resource.kind)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(resource.name).font(.body.weight(.medium))
                        Text(resource.exportSummary)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 3) {
                        ResourceKindBadge(kind: resource.kind)
                        Text("Used by \(resource.usageCount) projects")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 5)
            }
            .overlay {
                if filtered.isEmpty {
                    ContentUnavailableView.search(text: search)
                }
            }
        }
        .navigationTitle(title)
    }
}

private struct AddBindingSheet: View {
    @Bindable var store: WorkspaceStore
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""

    private var filtered: [WorkspaceResource] {
        guard !search.isEmpty else { return store.availableResources }
        return store.availableResources.filter {
            $0.name.localizedCaseInsensitiveContains(search)
                || $0.kind.title.localizedCaseInsensitiveContains(search)
                || $0.exportSummary.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Add Binding").font(.title2.bold())
                    Text("Add to \(store.selectedProject.name) · \(store.selectedEnvironment.name)")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(20)

            Divider()
            List(filtered) { resource in
                let conflicts = prospectiveConflicts(resource)
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
                    Button("Add") { store.addResource(resource.id) }
                        .buttonStyle(.bordered)
                        .disabled(!conflicts.isEmpty)
                }
                .padding(.vertical, 5)
            }
            .overlay {
                if filtered.isEmpty {
                    ContentUnavailableView("No bindings available", systemImage: "checkmark.circle")
                }
            }
        }
        .searchable(text: $search, prompt: "Search secrets and env files")
        .frame(minWidth: 580, minHeight: 460)
    }

    private func prospectiveConflicts(_ resource: WorkspaceResource) -> [String] {
        let current = Set(store.resolvedExports.map(\.key))
        return resource.exports.map(\.key).filter(current.contains).sorted()
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
        case .sshAgent: .blue
        }
    }
}
