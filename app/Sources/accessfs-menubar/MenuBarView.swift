import SwiftUI

struct MenuBarAccessGroup: Identifiable {
    struct ID: Hashable {
        let path: String
        let shownPath: String
        let operation: String
        let decision: String
        let exePath: String?
        let chain: String
        let ruleID: String?
        let policyMode: String?
        let policyConfiguredEnforcement: String?
        let policyEffectiveEnforcement: String?
        let sshFingerprint: String?
    }

    let id: ID
    let latest: RecentAccess
    var count: Int
}

struct MenuBarAccessFeed {
    static let recentWindow: TimeInterval = 60 * 60
    static let maximumGroups = 30

    let groups: [MenuBarAccessGroup]
    let totalGroupCount: Int
    let isSearching: Bool

    var countLabel: String {
        let count = totalGroupCount > groups.count ? "\(groups.count)+" : "\(totalGroupCount)"
        return isSearching ? count : "1h · \(count)"
    }

    static func make(
        recents: [RecentAccess],
        searchText: String,
        now: Date = Date()
    ) -> MenuBarAccessFeed {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        let isSearching = !query.isEmpty
        let cutoff = now.addingTimeInterval(-recentWindow)
        let candidates = recents
            .filter { recent in
                if isSearching {
                    return recent.matchesMenuBarSearch(query)
                }
                guard let date = recent.date else { return false }
                return date >= cutoff
            }
            .sorted {
                ($0.date ?? .distantPast) > ($1.date ?? .distantPast)
            }

        var groupIndexes: [MenuBarAccessGroup.ID: Int] = [:]
        var groups: [MenuBarAccessGroup] = []
        for recent in candidates {
            let id = MenuBarAccessGroup.ID(recent)
            if let index = groupIndexes[id] {
                groups[index].count += 1
            } else {
                groupIndexes[id] = groups.count
                groups.append(MenuBarAccessGroup(id: id, latest: recent, count: 1))
            }
        }

        return MenuBarAccessFeed(
            groups: Array(groups.prefix(maximumGroups)),
            totalGroupCount: groups.count,
            isSearching: isSearching)
    }
}

private extension MenuBarAccessGroup.ID {
    init(_ recent: RecentAccess) {
        path = recent.path
        shownPath = recent.shownPath
        operation = recent.operation
        decision = recent.decision
        exePath = recent.exePath
        chain = recent.chain
        ruleID = recent.ruleId
        policyMode = recent.policy?.mode
        policyConfiguredEnforcement = recent.policy?.configured_enforcement
        policyEffectiveEnforcement = recent.policy?.effective_enforcement
        sshFingerprint = recent.ssh?.key_fingerprint
    }
}

private extension RecentAccess {
    func matchesMenuBarSearch(_ query: String) -> Bool {
        shownPath.localizedCaseInsensitiveContains(query)
            || path.localizedCaseInsensitiveContains(query)
            || exe.localizedCaseInsensitiveContains(query)
            || operation.localizedCaseInsensitiveContains(query)
            || decision.localizedCaseInsensitiveContains(query)
    }
}

/// The window-style dropdown: search header, recent-access list, footer actions.
struct MenuBarView: View {
    @Bindable var state: AppState
    @State private var searchText = ""
    @State private var listContentHeight: CGFloat = 0
    @State private var pendingConfirmation: MenuBarConfirmation?

    /// The list grows with its content and only scrolls past ~60% of the screen —
    /// menubar dropdowns are expected to run tall rather than scroll early.
    private var maxListHeight: CGFloat {
        (NSScreen.main?.visibleFrame.height ?? 900) * 0.6
    }

    private var accessFeed: MenuBarAccessFeed {
        MenuBarAccessFeed.make(recents: state.recents, searchText: searchText)
    }

    var body: some View {
        VStack(spacing: 0) {
            MenuBarHeader(searchText: $searchText, countLabel: accessFeed.countLabel)
            PolicyModeControl(state: state) { window in
                pendingConfirmation = .auditOnly(window)
            }
            Divider()
            if accessFeed.groups.isEmpty {
                emptyState
            } else {
                accessList
            }
            Divider()
            MenuBarFooter(state: state) {
                pendingConfirmation = .clearRecent(count: state.recents.count)
            }
        }
        .frame(width: 360)
        .task { await state.reloadPolicyMode() }
        .overlay {
            if let pendingConfirmation {
                MenuBarConfirmationOverlay(
                    confirmation: pendingConfirmation,
                    cancel: { self.pendingConfirmation = nil },
                    confirm: { confirm(pendingConfirmation) })
                    .transition(.opacity.combined(with: .scale(scale: 0.98)))
            }
        }
        .onDisappear {
            pendingConfirmation = nil
        }
    }

    // Plain VStack, not LazyVStack: the MenuBarExtra window sizes itself to the content's
    // ideal height, and lazy content measures as zero before it has a viewport — the whole
    // list collapses to nothing. The list is capped at 30 groups, eager layout is cheap.
    // A ScrollView's own ideal height is unrelated to its content's, so the viewport is
    // pinned to the measured content height (scrolling only past the cap).
    private var accessList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 1) {
                SectionLabel(icon: "clock", title: "Recent Access")
                ForEach(accessFeed.groups) { group in
                    AccessRow(group: group)
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 6)
            .onGeometryChange(for: CGFloat.self) { proxy in
                proxy.size.height
            } action: { listContentHeight = $0 }
        }
        .frame(height: min(listContentHeight, maxListHeight))
    }

    private var emptyState: some View {
        VStack(spacing: 6) {
            if state.accessHistoryLoading && searchText.isEmpty {
                ProgressView()
                    .controlSize(.small)
            } else {
                Image(systemName: state.connected ? "checkmark.shield" : "shield.slash")
                    .font(.title2)
                    .foregroundStyle(.tertiary)
            }
            Text(
                searchText.isEmpty
                    ? (state.accessHistoryLoading
                        ? "Loading access history…"
                        : (state.connected ? "No access in the last hour" : "Agent not connected"))
                    : "No matches"
            )
            .font(.callout)
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 28)
    }

    private func confirm(_ confirmation: MenuBarConfirmation) {
        pendingConfirmation = nil
        switch confirmation {
        case .clearRecent:
            state.clearRecents()
        case .auditOnly(let window):
            Task {
                await state.setPolicyMode(.auditOnly, durationSecs: window.durationSecs)
            }
        }
    }
}

enum AuditOnlyWindow: String, Identifiable {
    case oneHour
    case eightHours
    case untilChanged

    var id: String { rawValue }

    var title: String {
        switch self {
        case .oneHour: "1 Hour"
        case .eightHours: "8 Hours"
        case .untilChanged: "Until Turned Off"
        }
    }

    var durationSecs: UInt64? {
        switch self {
        case .oneHour: 3600
        case .eightHours: 8 * 3600
        case .untilChanged: nil
        }
    }
}

private enum MenuBarConfirmation: Equatable {
    case clearRecent(count: Int)
    case auditOnly(AuditOnlyWindow)

    var title: String {
        switch self {
        case .clearRecent: "Clear recent activity?"
        case .auditOnly: "Enable Audit Only?"
        }
    }

    var message: String {
        switch self {
        case .clearRecent:
            "This clears only the activity shown in Floria. The daemon audit log on disk is not deleted."
        case .auditOnly:
            "Ask and Touch ID items will be allowed without interaction. Every access will still be audited, and explicit deny rules remain blocked."
        }
    }

    var confirmTitle: String {
        switch self {
        case .clearRecent(let count): "Clear \(count) Events"
        case .auditOnly(let window): "Enable for \(window.title)"
        }
    }

    var systemImage: String {
        switch self {
        case .clearRecent: "trash.fill"
        case .auditOnly: "eye.circle.fill"
        }
    }

    var tint: Color {
        switch self {
        case .clearRecent: .red
        case .auditOnly: .orange
        }
    }
}

private struct MenuBarConfirmationOverlay: View {
    let confirmation: MenuBarConfirmation
    let cancel: () -> Void
    let confirm: () -> Void

    var body: some View {
        ZStack {
            Color.black.opacity(0.16)
                .contentShape(Rectangle())

            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 9) {
                    Image(systemName: confirmation.systemImage)
                        .font(.title3)
                        .foregroundStyle(confirmation.tint)
                    Text(confirmation.title)
                        .font(.headline)
                    Spacer()
                }
                Text(confirmation.message)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Button("Cancel", action: cancel)
                        .keyboardShortcut(.cancelAction)
                        .frame(maxWidth: .infinity)
                    Button(confirmation.confirmTitle, action: confirm)
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)
                        .tint(confirmation.tint)
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(16)
            .frame(width: 314)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
            .overlay {
                RoundedRectangle(cornerRadius: 14)
                    .stroke(Color.secondary.opacity(0.20), lineWidth: 1)
            }
            .shadow(color: .black.opacity(0.18), radius: 18, y: 8)
            .padding(18)
        }
        .accessibilityElement(children: .contain)
    }
}

/// The daemon remains authoritative; this control only chooses and displays its runtime mode.
private struct PolicyModeControl: View {
    @Bindable var state: AppState
    let requestConfirmation: (AuditOnlyWindow) -> Void

    var body: some View {
        let auditOnly = state.policyMode.isAuditOnly()
        Menu {
            if auditOnly {
                Button("Return to Normal", systemImage: "checkmark.shield") {
                    Task { await state.setPolicyMode(.normal, durationSecs: nil) }
                }
            } else {
                Section("Audit Only") {
                    ForEach(
                        [AuditOnlyWindow.oneHour, .eightHours, .untilChanged]
                    ) { window in
                        Button(window.title) { requestConfirmation(window) }
                    }
                }
            }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: auditOnly ? "eye.circle.fill" : "checkmark.shield.fill")
                    .font(.title3)
                    .foregroundStyle(auditOnly ? Color.orange : Color.green)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(auditOnly ? "Audit Only" : "Protection: Normal")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(auditOnly ? Color.orange : Color.primary)
                    Text(statusDetail(at: Date()))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton)
        .padding(.horizontal, 10)
        .padding(.bottom, state.policyModeError == nil ? 8 : 3)
        if let error = state.policyModeError {
            Text(error)
                .font(.caption2)
                .foregroundStyle(.red)
                .lineLimit(2)
                .padding(.horizontal, 10)
                .padding(.bottom, 6)
        }
    }

    private func statusDetail(at date: Date) -> String {
        guard state.policyMode.isAuditOnly(at: date) else {
            return "Using each item's security level"
        }
        guard let expiry = state.policyMode.expirationDate else {
            return "Allows without prompts until turned off"
        }
        return "Allows without prompts until \(Self.clock.string(from: expiry))"
    }

    private static let clock: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter
    }()
}

/// Search field + live count, like the reference design.
private struct MenuBarHeader: View {
    @Binding var searchText: String
    let countLabel: String

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
            Text(countLabel)
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
    let group: MenuBarAccessGroup
    @State private var hovered = false
    private var ev: RecentAccess { group.latest }

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(ev.allowed ? Color.green : Color.red)
                .frame(width: 7, height: 7)
            Text(ev.operation)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(operationColor)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(operationColor.opacity(0.15))
                .clipShape(Capsule())
            if ev.wasGloballyOverridden {
                Image(systemName: "eye.fill")
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .help("Allowed by global Audit Only mode")
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(ev.exe)
                    .font(.callout)
                    .lineLimit(1)
                Text(ev.shownPath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 4)
            if group.count > 1 {
                Text("×\(group.count)")
                    .font(.caption2.monospacedDigit().weight(.medium))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(.tertiary.opacity(0.18))
                    .clipShape(Capsule())
            }
            Text(ev.time)
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(hovered ? Color.primary.opacity(0.06) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .onHover { hovered = $0 }
        .help(tooltip)
    }

    /// Full detail for the hover tooltip: friendly path, mount path (when distinct), rule, chain.
    private var tooltip: String {
        var lines = [ev.shownPath]
        if let ssh = ev.ssh {
            lines.append(ssh.key_fingerprint)
            lines.append("agent: \(ssh.surface_name)")
        }
        if ev.display != nil { lines.append(ev.path) }
        lines.append("rule: \(ev.ruleId ?? "-")")
        if let policy = ev.policy {
            lines.append(
                "policy: \(policy.configured_enforcement) → \(policy.effective_enforcement) (\(policy.mode))")
        }
        if group.count > 1 {
            lines.append("accesses: \(group.count)")
        }
        lines.append("chain: \(ev.chain)")
        return lines.joined(separator: "\n")
    }

    private var operationColor: Color {
        switch ev.operation {
        case "write": .orange
        case "sign": .blue
        default: .secondary
        }
    }
}

/// Footer actions styled as menu items with hover highlight and shortcut hints.
private struct MenuBarFooter: View {
    @Bindable var state: AppState
    @Environment(\.openWindow) private var openWindow
    let requestClearConfirmation: () -> Void

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
            MenuItemButton(title: "Open Workspace", icon: "rectangle.grid.2x2", shortcut: "D") {
                DockVisibilityController.shared.prepareToShowDashboard()
                openWindow(id: "dashboard")
                // Changing an accessory app back to regular doesn't make it frontmost.
                NSApp.activate(ignoringOtherApps: true)
            }
            .keyboardShortcut("d")
            MenuItemButton(title: "Clear Recent…", icon: "trash", shortcut: "K") {
                requestClearConfirmation()
            }
            .keyboardShortcut("k")
            .disabled(state.recents.isEmpty)
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
