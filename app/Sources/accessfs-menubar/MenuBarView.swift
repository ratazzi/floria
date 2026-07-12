import SwiftUI

/// The window-style dropdown: search header, recent-access list, footer actions.
struct MenuBarView: View {
    @Bindable var state: AppState
    @State private var searchText = ""

    private var filtered: [RecentAccess] {
        guard !searchText.isEmpty else { return state.recents }
        let q = searchText
        return state.recents.filter {
            $0.path.localizedCaseInsensitiveContains(q)
                || $0.exe.localizedCaseInsensitiveContains(q)
                || $0.operation.localizedCaseInsensitiveContains(q)
                || $0.decision.localizedCaseInsensitiveContains(q)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            MenuBarHeader(searchText: $searchText, count: filtered.count)
            Divider()
            if filtered.isEmpty {
                emptyState
            } else {
                accessList
            }
            Divider()
            MenuBarFooter(state: state)
        }
        .frame(width: 360)
    }

    private var accessList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                SectionLabel(icon: "clock", title: "Recent Access")
                ForEach(filtered) { ev in
                    AccessRow(ev: ev)
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 6)
        }
        .frame(maxHeight: 380)
    }

    private var emptyState: some View {
        VStack(spacing: 6) {
            Image(systemName: state.connected ? "checkmark.shield" : "shield.slash")
                .font(.title2)
                .foregroundStyle(.tertiary)
            Text(
                searchText.isEmpty
                    ? (state.connected ? "No recent access" : "Agent not connected")
                    : "No matches"
            )
            .font(.callout)
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 28)
    }
}

/// Search field + live count, like the reference design.
private struct MenuBarHeader: View {
    @Binding var searchText: String
    let count: Int

    var body: some View {
        HStack(spacing: 8) {
            HStack(spacing: 4) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.tertiary)
                    .font(.caption)
                TextField("Search...", text: $searchText)
                    .textFieldStyle(.plain)
                    .font(.callout)
                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.tertiary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
            .background(.quaternary.opacity(0.7))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            Text("\(count)")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(.tertiary.opacity(0.3))
                .clipShape(Capsule())
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
    }
}

private struct SectionLabel: View {
    let icon: String
    let title: String

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: icon).font(.caption2)
            Text(title).font(.caption.weight(.semibold))
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 6)
        .padding(.vertical, 4)
    }
}

/// One access event: decision dot, read/write badge, exe + path, timestamp. Hover highlights
/// and the tooltip carries the full path / rule / process chain.
private struct AccessRow: View {
    let ev: RecentAccess
    @State private var hovered = false

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(ev.allowed ? Color.green : Color.red)
                .frame(width: 7, height: 7)
            Text(ev.operation)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(ev.operation == "write" ? Color.orange : Color.secondary)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background((ev.operation == "write" ? Color.orange : Color.secondary).opacity(0.15))
                .clipShape(Capsule())
            VStack(alignment: .leading, spacing: 1) {
                Text(ev.exe)
                    .font(.callout)
                    .lineLimit(1)
                Text(ev.path)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 4)
            Text(ev.time)
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(hovered ? Color.primary.opacity(0.06) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .onHover { hovered = $0 }
        .help("\(ev.path)\nrule: \(ev.ruleId ?? "-")\nchain: \(ev.chain)")
    }
}

/// Footer actions styled as menu items with hover highlight and shortcut hints.
private struct MenuBarFooter: View {
    @Bindable var state: AppState

    var body: some View {
        VStack(spacing: 1) {
            // Labeled connection status (a bare dot reads as noise).
            HStack(spacing: 6) {
                Circle()
                    .fill(state.connected ? Color.green : Color.secondary.opacity(0.4))
                    .frame(width: 6, height: 6)
                Text(state.connected ? "agent connected" : "agent not connected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 10)
            .padding(.top, 2)
            .padding(.bottom, 4)
            MenuItemButton(title: "Clear Recent", icon: "trash", shortcut: "K") {
                state.clearRecents()
            }
            .keyboardShortcut("k")
            MenuItemButton(title: "Quit floria", icon: "power", shortcut: "Q") {
                NSApp.terminate(nil)
            }
            .keyboardShortcut("q")
        }
        .padding(6)
    }
}

private struct MenuItemButton: View {
    let title: String
    let icon: String
    var shortcut: String?
    let action: () -> Void
    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .frame(width: 16)
                    .foregroundStyle(.secondary)
                Text(title)
                Spacer()
                if let shortcut {
                    Text("⌘\(shortcut)")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(hovered ? Color.primary.opacity(0.06) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .onHover { hovered = $0 }
    }
}
