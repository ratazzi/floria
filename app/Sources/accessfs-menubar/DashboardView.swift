import AppKit
import SwiftUI

/// Full access-log browser retained as a top-level destination in the workspace dashboard.
struct AccessLogView: View {
    @Bindable var state: AppState
    @State private var grouping: Grouping = .client
    @State private var selection: SidebarFilter? = SidebarFilter.all
    @State private var search = ""
    @State private var showingClearConfirmation = false

    enum Grouping: String, CaseIterable {
        case client = "By Client"
        case file = "By File"
    }

    enum SidebarFilter: Hashable {
        case all
        case group(String)
    }

    /// (group key, row count), most active first. Key is exe name or shown path.
    private var groups: [(name: String, count: Int)] {
        let keyed = Dictionary(grouping: state.recents) {
            grouping == .client ? $0.exe : $0.shownPath
        }
        return
            keyed
            .map { (name: $0.key, count: $0.value.count) }
            .sorted { ($1.count, $0.name) < ($0.count, $1.name) }
    }

    private var events: [RecentAccess] {
        var rows = state.recents
        if case .group(let name) = selection {
            rows = rows.filter { (grouping == .client ? $0.exe : $0.shownPath) == name }
        }
        guard !search.isEmpty else { return rows }
        return rows.filter {
            $0.shownPath.localizedCaseInsensitiveContains(search)
                || $0.path.localizedCaseInsensitiveContains(search)
                || $0.exe.localizedCaseInsensitiveContains(search)
                || ($0.ruleId ?? "").localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 180, ideal: 220)
        } detail: {
            accessTable
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Filter")
        .navigationTitle("Recent Access")
        .confirmationDialog(
            "Clear recent activity?",
            isPresented: $showingClearConfirmation
        ) {
            Button("Clear \(state.recents.count) Events", role: .destructive) {
                state.clearRecents()
                selection = .all
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This clears only the activity shown in Floria. The daemon audit log on disk is not deleted.")
        }
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            Picker("", selection: $grouping) {
                ForEach(Grouping.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 10)
            .padding(.vertical, 8)

            List(selection: $selection) {
                SidebarRow(
                    name: "All", count: state.recents.count,
                    icon: Image(systemName: "tray.full")
                )
                .tag(SidebarFilter.all)
                ForEach(groups, id: \.name) { g in
                    SidebarRow(name: g.name, count: g.count, icon: icon(for: g.name))
                        .tag(SidebarFilter.group(g.name))
                }
            }
            .listStyle(.sidebar)
        }
        // Groups come and go as events arrive; fall back to All if the selection vanished.
        .onChange(of: grouping) { selection = .all }
    }

    private func icon(for group: String) -> Image {
        if grouping == .file {
            return Image(systemName: "doc.text")
        }
        if let path = state.recents.first(where: { $0.exe == group })?.exePath {
            return Image(nsImage: ExeIcon.lookup(path))
        }
        return Image(systemName: "terminal")
    }

    private var accessTable: some View {
        Table(events) {
            TableColumn("Time") { ev in
                Text(ev.time).font(.body.monospacedDigit()).foregroundStyle(.secondary)
            }
            .width(70)
            TableColumn("Client") { ev in
                HStack(spacing: 6) {
                    if let path = ev.exePath {
                        Image(nsImage: ExeIcon.lookup(path))
                            .resizable()
                            .frame(width: 16, height: 16)
                    }
                    Text(ev.exe)
                }
                .help(ev.chain)
            }
            .width(min: 110, ideal: 150)
            TableColumn("Op") { ev in
                OperationBadge(operation: ev.operation)
            }
            .width(56)
            TableColumn("Decision") { ev in
                HStack(spacing: 5) {
                    Circle()
                        .fill(ev.allowed ? Color.green : Color.red)
                        .frame(width: 7, height: 7)
                    Text(ev.decision).foregroundStyle(.secondary)
                }
            }
            .width(80)
            TableColumn("Rule") { ev in
                Text(ev.ruleId ?? "-").foregroundStyle(.secondary)
            }
            .width(min: 80, ideal: 110)
            TableColumn("Path") { ev in
                Text(ev.shownPath)
                    .truncationMode(.middle)
                    .help(eventDetail(ev))
            }
        }
        .overlay {
            if events.isEmpty {
                if state.accessHistoryLoading {
                    ProgressView("Loading access history…")
                } else {
                    ContentUnavailableView(
                        state.connected ? "No recent access" : "Agent not connected",
                        systemImage: state.connected ? "checkmark.shield" : "shield.slash"
                    )
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            bottomBar
        }
    }

    private func eventDetail(_ event: RecentAccess) -> String {
        if let ssh = event.ssh {
            return "\(event.shownPath)\n\(ssh.key_fingerprint)\nAgent: \(ssh.surface_name)"
        }
        return event.display != nil ? "\(event.shownPath)\n\(event.path)" : event.path
    }

    private var bottomBar: some View {
        HStack {
            Text("\(events.count) of \(state.recents.count) events")
                .font(.callout)
                .foregroundStyle(.secondary)
            Spacer()
            Button("Clear…") { showingClearConfirmation = true }
                .disabled(state.recents.isEmpty)
                .help("Clear the recent activity shown in this window")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }
}

private struct SidebarRow: View {
    let name: String
    let count: Int
    let icon: Image

    var body: some View {
        HStack(spacing: 6) {
            icon
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 16, height: 16)
            Text(name).lineLimit(1).truncationMode(.middle)
            Spacer()
            Text("\(count)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(.quaternary.opacity(0.6))
                .clipShape(Capsule())
        }
    }
}

struct OperationBadge: View {
    let operation: String

    var body: some View {
        Text(operation)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(color.opacity(0.15))
            .clipShape(Capsule())
    }


    private var color: Color {
        switch operation {
        case "write": .orange
        case "sign": .blue
        default: .secondary
        }
    }
}

/// Icon per executable path, resolved once and cached — icon(forFile:) hits the disk.
/// App-bundle helpers get their bundle's icon; bare binaries get the file icon.
enum ExeIcon {
    private static var cache: [String: NSImage] = [:]

    @MainActor
    static func lookup(_ exePath: String) -> NSImage {
        if let hit = cache[exePath] { return hit }
        let target: String
        if let r = exePath.range(of: ".app/") {
            target = String(exePath[..<r.lowerBound]) + ".app"
        } else {
            target = exePath
        }
        let img = NSWorkspace.shared.icon(forFile: target)
        cache[exePath] = img
        return img
    }
}
