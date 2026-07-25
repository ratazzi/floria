import AppKit
import SwiftUI

enum PromptGrantScope: String, CaseIterable {
    case once
    case tenMinutes

    var title: String {
        switch self {
        case .once: "Once"
        case .tenMinutes: "10 minutes"
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

    init(_ prompt: PromptMsg) {
        let originalPath = prompt.display ?? prompt.path
        targetName = URL(fileURLWithPath: originalPath).lastPathComponent
        targetPath = (originalPath as NSString).abbreviatingWithTildeInPath
        mountPath = prompt.display == nil ? nil : prompt.path
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
        operation == "write" ? "modify" : "read"
    }

    var intermediateCount: Int { max(0, processPath.count - 2) }
}

struct AuthorizationPromptView: View {
    let prompt: PromptMsg
    let frameHeight: CGFloat
    let deny: () -> Void
    let allow: (PromptGrantScope) -> Void

    @State private var scope = PromptGrantScope.once
    @State private var showsFullPath = false

    private var model: PromptPresentation { PromptPresentation(prompt) }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: 18) {
                    requestHeader
                    processSummary
                    securityNotice
                    scopePicker
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
        HStack(spacing: 16) {
            endpointIcon(process: model.requester, size: 58)
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
            }
            Spacer(minLength: 0)
        }
    }

    private var processSummary: some View {
        DisclosureGroup(isExpanded: $showsFullPath) {
            VStack(spacing: 0) {
                Divider().padding(.vertical, 8)
                VStack(spacing: 0) {
                    ForEach(Array(model.processPath.enumerated()), id: \.element.id) { index, process in
                        processPathRow(process, isLast: index == model.processPath.count - 1)
                    }
                    details
                }
            }
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .frame(width: 28, height: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text(processSummaryTitle)
                        .font(.callout.weight(.semibold))
                    Text(processSummarySubtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .tint(.secondary)
        .padding(14)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    @ViewBuilder
    private var securityNotice: some View {
        if model.requiresTouchID {
            HStack(spacing: 12) {
                Image(systemName: "touchid")
                    .font(.title2)
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Touch ID required")
                        .font(.callout.weight(.semibold))
                    Text("Floria will authenticate before allowing this access.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(14)
            .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        }
    }

    private var scopePicker: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Authorization scope")
                .font(.headline)
            Picker("Authorization scope", selection: $scope) {
                ForEach(PromptGrantScope.allCases, id: \.self) { option in
                    Text(option.title).tag(option)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            Text(scope == .once
                ? "Allow only this request."
                : "Reuse this approval for the same application or project and file for 10 minutes.")
                .font(.caption)
                .foregroundStyle(.secondary)
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
        return scope == .once ? "Allow Once" : "Allow for 10 Minutes"
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
