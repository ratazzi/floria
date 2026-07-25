import AppKit
import SwiftUI

private enum AuthorizationPromptLayout {
    static let visualColumnWidth: CGFloat = 58
    static let columnSpacing: CGFloat = 16
    static let cardPadding: CGFloat = 14
    static let processVisualWidth = visualColumnWidth - cardPadding
}

enum PromptGrantScope: Equatable {
    case once
    case timed(seconds: UInt64)

    var title: String {
        switch self {
        case .once: "Once"
        case .timed(let seconds): Self.durationTitle(seconds)
        }
    }

    var wireScope: String {
        switch self {
        case .once: "once"
        case .timed: "ttl"
        }
    }

    var ttlSeconds: UInt64? {
        switch self {
        case .once: nil
        case .timed(let seconds): seconds
        }
    }

    private static func durationTitle(_ seconds: UInt64) -> String {
        if seconds.isMultiple(of: 3_600) {
            let hours = seconds / 3_600
            return "\(hours) \(hours == 1 ? "hour" : "hours")"
        }
        let minutes = seconds / 60
        return "\(minutes) \(minutes == 1 ? "minute" : "minutes")"
    }
}

enum PromptGrantPreset: String, CaseIterable {
    case once
    case fiveMinutes
    case tenMinutes
    case thirtyMinutes
    case oneHour
    case custom

    var title: String {
        switch self {
        case .once: "Once"
        case .fiveMinutes: "5 minutes"
        case .tenMinutes: "10 minutes"
        case .thirtyMinutes: "30 minutes"
        case .oneHour: "1 hour"
        case .custom: "Custom…"
        }
    }

    func scope(customDuration: Int, unit: PromptGrantCustomUnit) -> PromptGrantScope {
        switch self {
        case .once:
            return .once
        case .fiveMinutes:
            return .timed(seconds: 5 * 60)
        case .tenMinutes:
            return .timed(seconds: 10 * 60)
        case .thirtyMinutes:
            return .timed(seconds: 30 * 60)
        case .oneHour:
            return .timed(seconds: 60 * 60)
        case .custom:
            let bounded = min(max(customDuration, unit.range.lowerBound), unit.range.upperBound)
            return .timed(seconds: UInt64(bounded) * unit.secondsMultiplier)
        }
    }
}

enum PromptGrantCustomUnit: String, CaseIterable {
    case minutes
    case hours

    var range: ClosedRange<Int> {
        switch self {
        case .minutes: 1...1_440
        case .hours: 1...24
        }
    }

    var secondsMultiplier: UInt64 {
        switch self {
        case .minutes: 60
        case .hours: 3_600
        }
    }
}

struct PromptProcessNode: Identifiable, Hashable {
    let pid: Int32
    let name: String
    let executable: String?

    var id: String { "\(pid):\(executable ?? name)" }

    var displayName: String {
        Self.applicationName(from: executable) ?? name
    }

    private static func applicationName(from executable: String?) -> String? {
        guard let executable, let range = executable.range(of: ".app/") else { return nil }
        let bundlePath = String(executable[..<range.upperBound]).dropLast()
        return URL(fileURLWithPath: String(bundlePath)).deletingPathExtension().lastPathComponent
    }
}

struct PromptPresentation {
    let targetName: String
    let targetPath: String
    let mountPath: String?
    let operation: String
    let source: PromptProcessNode
    let reader: PromptProcessNode
    let requester: PromptProcessNode
    let processPath: [PromptProcessNode]
    let cwd: String?
    let requiresTouchID: Bool
    let ssh: SshSignView?
    let sshDestination: String?
    let sshHostKeyFingerprint: String?
    let sshUser: String?
    let sshForwardingHops: Int

    init(_ prompt: PromptMsg) {
        ssh = prompt.ssh
        sshDestination = prompt.ssh?.requested_destination
        sshHostKeyFingerprint = prompt.ssh?.verified_host_key_fingerprint
        sshUser = prompt.ssh?.ssh_user
        sshForwardingHops = prompt.ssh?.forwarding_hops ?? 0
        if let ssh = prompt.ssh {
            targetName = ssh.key_label
            targetPath = ssh.key_fingerprint
            mountPath = nil
        } else {
            let originalPath = prompt.display ?? prompt.path
            targetName = URL(fileURLWithPath: originalPath).lastPathComponent
            targetPath = (originalPath as NSString).abbreviatingWithTildeInPath
            mountPath = prompt.display == nil ? nil : prompt.path
        }
        operation = prompt.operation
        cwd = prompt.identity.cwd.map { ($0 as NSString).abbreviatingWithTildeInPath }
        requiresTouchID = prompt.enforcement == "touchid"

        var processes = (prompt.identity.parent_chain ?? []).map {
            PromptProcessNode(pid: $0.pid, name: $0.name, executable: $0.exe)
        }
        let readerName = (prompt.identity.exe as NSString?)?.lastPathComponent
            ?? prompt.identity.cmdline?.first.map { ($0 as NSString).lastPathComponent }
            ?? "Process \(prompt.identity.pid)"
        let direct = PromptProcessNode(
            pid: prompt.identity.pid, name: readerName, executable: prompt.identity.exe)

        if processes.isEmpty {
            let fallbackNames = prompt.identity.chain
                .replacingOccurrences(of: " → ", with: " -> ")
                .components(separatedBy: " -> ")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            processes = fallbackNames.enumerated().map { index, name in
                PromptProcessNode(
                    pid: index == fallbackNames.count - 1 ? prompt.identity.pid : -Int32(index + 1),
                    name: name, executable: index == fallbackNames.count - 1
                        ? prompt.identity.exe : nil)
            }
        }
        if processes.last?.pid != prompt.identity.pid {
            processes.append(direct)
        }

        let applicationIndex = processes.firstIndex {
            $0.executable?.contains(".app/Contents/") == true
        }
        let meaningfulIndex = processes.firstIndex {
            !["launchd"].contains($0.name.lowercased())
        }
        let start = applicationIndex ?? meaningfulIndex ?? max(0, processes.count - 1)
        let visiblePath = processes.isEmpty ? [direct] : Array(processes[start...])
        processPath = visiblePath
        source = visiblePath.first ?? direct
        reader = visiblePath.last ?? direct
        requester = applicationIndex.map { processes[$0] } ?? reader
    }

    var actionTitle: String {
        switch operation {
        case "write": "modify"
        case "sign": "use"
        default: "read"
        }
    }

    var intermediateCount: Int { max(0, processPath.count - 2) }
}

struct AuthorizationPromptView: View {
    let prompt: PromptMsg
    let frameHeight: CGFloat
    let deny: () -> Void
    let allow: (PromptGrantScope) -> Void

    @State private var grantPreset = PromptGrantPreset.once
    @State private var customDuration = 15
    @State private var customUnit = PromptGrantCustomUnit.minutes
    @State private var showsFullPath = false

    private var model: PromptPresentation { PromptPresentation(prompt) }
    private var scope: PromptGrantScope {
        grantPreset.scope(customDuration: customDuration, unit: customUnit)
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 18) {
                    requestHeader
                    processSummary
                    securityNotice
                    HStack(
                        alignment: .top,
                        spacing: AuthorizationPromptLayout.columnSpacing
                    ) {
                        Color.clear
                            .frame(
                                width: AuthorizationPromptLayout.visualColumnWidth,
                                height: 1)
                            .accessibilityHidden(true)
                        AuthorizationScopePicker(
                            preset: $grantPreset,
                            customDuration: $customDuration,
                            customUnit: $customUnit,
                            operation: model.operation)
                        Spacer(minLength: 0)
                    }
                }
                .padding(.horizontal, 26)
                .padding(.vertical, 22)
            }

            Divider()
            HStack {
                Button("Deny", role: .cancel, action: deny)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(primaryButtonTitle) { allow(scope) }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 16)
        }
        .frame(width: 520, height: frameHeight)
    }

    private var requestHeader: some View {
        HStack(spacing: AuthorizationPromptLayout.columnSpacing) {
            endpointIcon(
                process: model.requester,
                size: AuthorizationPromptLayout.visualColumnWidth)
            VStack(alignment: .leading, spacing: 5) {
                Text("Allow \(model.requester.displayName) to \(model.actionTitle) \(model.targetName)?")
                    .font(.title2.weight(.semibold))
                    .multilineTextAlignment(.leading)
                Text(model.targetPath)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                if let destination = model.sshDestination {
                    HStack(spacing: 6) {
                        Image(systemName: "server.rack")
                        Text("Requested server")
                        Text(displayDestination(destination))
                            .font(.callout.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                if let fingerprint = model.sshHostKeyFingerprint {
                    HStack(spacing: 6) {
                        Image(systemName: "checkmark.shield")
                            .foregroundStyle(.green)
                        Text("Verified host key")
                        Text(fingerprint)
                            .font(.caption.monospaced())
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                        if let user = model.sshUser,
                            model.sshDestination == nil || model.sshForwardingHops > 0
                        {
                            Text("· \(user)")
                        }
                        if model.sshForwardingHops > 0 {
                            Text("· \(model.sshForwardingHops) hops")
                        }
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
    }

    private func displayDestination(_ destination: String) -> String {
        guard model.sshForwardingHops == 0,
            let user = model.sshUser, !destination.contains("@")
        else { return destination }
        return "\(user)@\(destination)"
    }

    private var processSummary: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.16)) {
                    showsFullPath.toggle()
                }
            } label: {
                HStack(spacing: AuthorizationPromptLayout.columnSpacing) {
                    HStack(spacing: 8) {
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.tertiary)
                            .rotationEffect(.degrees(showsFullPath ? 90 : 0))
                            .frame(width: 8)
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .font(.title3)
                            .foregroundStyle(.secondary)
                            .frame(width: 28, height: 28)
                    }
                    .frame(
                        width: AuthorizationPromptLayout.processVisualWidth,
                        alignment: .leading)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(processSummaryTitle)
                            .font(.callout.weight(.semibold))
                        Text(processSummarySubtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(processSummaryTitle), \(processSummarySubtitle)")
            .accessibilityValue(showsFullPath ? "Expanded" : "Collapsed")

            if showsFullPath {
                Divider().padding(.vertical, 8)
                VStack(spacing: 0) {
                    ForEach(Array(model.processPath.enumerated()), id: \.element.id) { index, process in
                        processPathRow(process, isLast: index == model.processPath.count - 1)
                    }
                    details
                }
            }
        }
        .padding(AuthorizationPromptLayout.cardPadding)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    @ViewBuilder
    private var securityNotice: some View {
        if model.requiresTouchID {
            HStack(spacing: AuthorizationPromptLayout.columnSpacing) {
                Image(systemName: "touchid")
                    .font(.title2)
                    .foregroundStyle(.orange)
                    .frame(
                        width: AuthorizationPromptLayout.processVisualWidth,
                        alignment: .leading)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Touch ID required")
                        .font(.callout.weight(.semibold))
                    Text("Floria will authenticate before allowing this access.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(AuthorizationPromptLayout.cardPadding)
            .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        }
    }

    private func endpointIcon(process: PromptProcessNode, size: CGFloat) -> some View {
        Image(nsImage: icon(for: process))
            .resizable()
            .scaledToFit()
            .frame(width: size - 16, height: size - 16)
            .frame(width: size, height: size)
            .background(.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: size / 4))
    }

    private func processPathRow(_ process: PromptProcessNode, isLast: Bool) -> some View {
        HStack(spacing: 10) {
            Image(nsImage: icon(for: process))
                .resizable()
                .scaledToFit()
                .frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 1) {
                Text(process.displayName).font(.callout.weight(.medium))
                if let executable = process.executable {
                    Text(executable)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            Spacer()
            Text("PID \(process.pid)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            if !isLast {
                Image(systemName: "chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.vertical, 6)
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 5) {
            if let cwd = model.cwd {
                detailRow("Working directory", value: cwd)
            }
            if let mountPath = model.mountPath {
                detailRow("Internal mount path", value: mountPath)
            }
            if let ssh = model.ssh {
                detailRow("Agent surface", value: ssh.surface_name)
                detailRow("Signer source", value: ssh.resource_id)
            }
        }
        .padding(.top, 8)
    }

    private func detailRow(_ label: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.caption.monospaced())
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
        .font(.caption)
    }

    private var processSummaryTitle: String {
        guard model.source.pid != model.reader.pid else { return model.reader.displayName }
        return "\(model.source.displayName) → \(model.reader.displayName)"
    }

    private var processSummarySubtitle: String {
        let count = model.processPath.count
        if model.requester.pid == model.reader.pid {
            return count == 1 ? "Direct CLI reader" : "Direct CLI reader · \(count)-process path"
        }
        switch model.intermediateCount {
        case 0: return "Direct reader: \(model.reader.displayName)"
        case 1: return "Direct reader: \(model.reader.displayName) · 1 intermediate process"
        default:
            return "Direct reader: \(model.reader.displayName) · \(model.intermediateCount) intermediate processes"
        }
    }

    private var primaryButtonTitle: String {
        if model.requiresTouchID { return "Use Touch ID" }
        return scope == .once ? "Allow Once" : "Allow for \(scope.title.capitalized)"
    }

    private func icon(for process: PromptProcessNode) -> NSImage {
        guard let executable = process.executable else {
            return NSImage(systemSymbolName: "terminal.fill", accessibilityDescription: nil)
                ?? NSImage()
        }
        if let range = executable.range(of: ".app/") {
            let bundlePath = String(executable[..<range.upperBound]).dropLast()
            return NSWorkspace.shared.icon(forFile: String(bundlePath))
        }
        return NSWorkspace.shared.icon(forFile: executable)
    }
}

struct AuthorizationScopePicker: View {
    @Binding var preset: PromptGrantPreset
    @Binding var customDuration: Int
    @Binding var customUnit: PromptGrantCustomUnit
    let operation: String

    private var scope: PromptGrantScope {
        preset.scope(customDuration: customDuration, unit: customUnit)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Authorization scope")
                .font(.headline)
            Picker("Authorization scope", selection: $preset) {
                ForEach(PromptGrantPreset.allCases, id: \.self) { option in
                    Text(option.title).tag(option)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .frame(maxWidth: .infinity, alignment: .leading)
            if preset == .custom {
                HStack(spacing: 8) {
                    Stepper(value: $customDuration, in: customUnit.range) {
                        Text("\(customDuration)")
                            .monospacedDigit()
                            .frame(minWidth: 34, alignment: .trailing)
                    }
                    Picker("Unit", selection: $customUnit) {
                        ForEach(PromptGrantCustomUnit.allCases, id: \.self) { unit in
                            Text(unit.rawValue.capitalized).tag(unit)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.menu)
                }
                .onChange(of: customUnit) { _, unit in
                    customDuration = min(
                        max(customDuration, unit.range.lowerBound),
                        unit.range.upperBound)
                }
            }
            Text(scope == .once
                ? "Allow only this request."
                : operation == "sign"
                    ? "Reuse this approval for the same application or project and SSH identity for \(scope.title)."
                    : "Reuse this approval for the same application or project and file for \(scope.title).")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(width: 280, alignment: .leading)
    }
}
