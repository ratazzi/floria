import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct FolderSyncView: View {
    @Bindable var store: WorkspaceStore
    @Environment(\.dismiss) private var dismiss

    @State private var status: ReplicationStatus?
    @State private var isWorking = false
    @State private var errorMessage: String?
    @State private var showingDisableConfirmation = false
    @State private var showingKeepCurrentConfirmation = false
    @State private var pendingApproval: ReplicationPendingEnrollment?
    @State private var showingApprovalConfirmation = false
    @State private var pendingDeviceRemoval: ReplicationDevice?
    @State private var showingReenrollmentConfirmation = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    if let status {
                        statusHeader(status)
                        statusActions(status)
                        if status.mode == .active, !status.devices.isEmpty {
                            deviceSection(status)
                        }
                    } else if isWorking {
                        HStack(spacing: 10) {
                            ProgressView().controlSize(.small)
                            Text("Checking sync status…")
                                .foregroundStyle(.secondary)
                        }
                    }

                    if let errorMessage {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if status == nil, !isWorking {
                        Button("Try Again", systemImage: "arrow.clockwise") {
                            Task { await refreshStatus() }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(28)
            }

            Divider()
            HStack {
                if status?.mode == .active {
                    Text("Floria checks this folder automatically.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 22)
            .frame(height: 58)
        }
        .frame(width: 620, height: 400)
        .task { await refreshStatus() }
        .confirmationDialog(
            "Stop Syncing?", isPresented: $showingDisableConfirmation
        ) {
            Button("Stop Syncing", role: .destructive) {
                perform { try await store.disableReplication() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "This Mac will stop using the sync folder. The encrypted folder and this Mac’s local Library are not deleted."
            )
        }
        .confirmationDialog(
            "Keep This Mac’s Version?", isPresented: $showingKeepCurrentConfirmation
        ) {
            Button("Keep This Mac’s Version") {
                perform { try await store.resolveReplicationConflictWithCurrent() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "Every Mac will converge to the managed Library currently shown on this Mac. The other signed version remains in encrypted history."
            )
        }
        .confirmationDialog(
            "Approve Another Mac?", isPresented: $showingApprovalConfirmation,
            presenting: pendingApproval
        ) { request in
            Button("Codes Match — Approve") {
                perform { try await store.approveReplicationRequest(deviceID: request.deviceID) }
            }
            Button("Cancel", role: .cancel) {}
        } message: { request in
            Text(
                "Only approve if the other Mac shows exactly this code: \(request.fingerprint). "
                    + "This grants \(request.deviceName ?? "Mac \(shortDeviceID(request.deviceID))") access to the encrypted sync folder."
            )
        }
        .confirmationDialog(
            "Remove This Mac?",
            isPresented: Binding(
                get: { pendingDeviceRemoval != nil },
                set: { if !$0 { pendingDeviceRemoval = nil } }),
            presenting: pendingDeviceRemoval
        ) { device in
            Button("Remove Mac", role: .destructive) {
                pendingDeviceRemoval = nil
                perform { try await store.revokeReplicationDevice(device.deviceID) }
            }
            Button("Cancel", role: .cancel) { pendingDeviceRemoval = nil }
        } message: { device in
            Text(
                "\(deviceDisplayName(device)) will lose access to future changes. Floria will rotate the sync-folder encryption key, and that Mac must request approval with a new identity to return."
            )
        }
        .confirmationDialog(
            "Request Access Again?", isPresented: $showingReenrollmentConfirmation
        ) {
            Button("Create New Approval Request") {
                perform { try await store.requestReplicationReenrollment() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "Floria will replace this Mac’s revoked sync identity. Your local Library is not changed; the Mac that created this sync folder must approve the new identity."
            )
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: 24, weight: .medium))
                .foregroundStyle(.blue)
                .frame(width: 48, height: 48)
                .background(Color.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 3) {
                Text("Sync")
                    .font(.title2.bold())
                Text("Encrypted before it leaves this Mac")
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 24)
        .frame(height: 88)
    }

    @ViewBuilder
    private func statusHeader(_ status: ReplicationStatus) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: statusSymbol(status))
                .font(.title3)
                .foregroundStyle(statusColor(status))
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 5) {
                Text(statusTitle(status))
                    .font(.headline)
                Text(statusDetail(status))
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }

        if let directory = status.directory {
            HStack(spacing: 10) {
                Image(systemName: "folder")
                    .foregroundStyle(.secondary)
                Text(abbreviatedPath(directory))
                    .font(.callout.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(directory)
                Spacer()
                Button("Show in Finder") {
                    showReplicationDirectory(directory)
                }
                .controlSize(.small)
            }
            .padding(12)
            .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 9))
        }
    }

    @ViewBuilder
    private func statusActions(_ status: ReplicationStatus) -> some View {
        switch status.mode {
        case .off:
            VStack(alignment: .leading, spacing: 14) {
                Text(
                    "Choose a folder handled by iCloud Drive, Dropbox, Syncthing, or any other sync tool. Floria writes only encrypted, signed data into it."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 10) {
                    Button("Create Sync Folder…", systemImage: "folder.badge.plus") {
                        chooseNewPackage()
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Open Existing…", systemImage: "folder") {
                        chooseExistingPackage()
                    }
                }
                .disabled(isWorking)
            }

        case .active:
            Group {
                if status.conflicts > 0 {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(
                            "This Mac and another Mac changed the Library independently. Review what this Mac currently shows before choosing it for every Mac."
                        )
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 10) {
                            Button("Keep This Mac’s Version") {
                                showingKeepCurrentConfirmation = true
                            }
                            .buttonStyle(.borderedProminent)
                            Button("Sync Again", systemImage: "arrow.clockwise") {
                                perform { try await store.syncReplicationPackage() }
                            }
                            Button("Stop Syncing…", role: .destructive) {
                                showingDisableConfirmation = true
                            }
                        }
                    }
                } else if status.damaged > 0 {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(
                            "Floria ignored files that could not be verified. Your local Library is unchanged. Let your sync tool finish first; if the same files remain, inspect or restore them from its history."
                        )
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        if !status.damagedFiles.isEmpty {
                            let visibleDamagedFiles = Array(status.damagedFiles.prefix(5))
                            VStack(spacing: 0) {
                                ForEach(Array(visibleDamagedFiles.enumerated()), id: \.element) {
                                    index, path in
                                    HStack(spacing: 10) {
                                        Image(systemName: "doc.badge.exclamationmark")
                                            .foregroundStyle(.orange)
                                            .frame(width: 20)
                                        Text(path)
                                            .font(.caption.monospaced())
                                            .lineLimit(1)
                                            .truncationMode(.middle)
                                        Spacer()
                                        Button("Show") {
                                            showReplicationFile(path, in: status.directory)
                                        }
                                        .controlSize(.small)
                                    }
                                    .padding(.horizontal, 10)
                                    .frame(minHeight: 40)
                                    if index < visibleDamagedFiles.count - 1 {
                                        Divider().padding(.leading, 40)
                                    }
                                }
                            }
                            .background(
                                Color.secondary.opacity(0.06),
                                in: RoundedRectangle(cornerRadius: 9))
                        }
                        HStack(spacing: 10) {
                            Button("Check Again", systemImage: "arrow.clockwise") {
                                perform { try await store.syncReplicationPackage() }
                            }
                            .buttonStyle(.borderedProminent)
                            if let directory = status.directory {
                                Button("Show Sync Folder", systemImage: "folder") {
                                    showReplicationDirectory(directory)
                                }
                            }
                            Button("Stop Syncing…", role: .destructive) {
                                showingDisableConfirmation = true
                            }
                        }
                    }
                } else if status.pending > 0 {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(
                            "Your sync tool has not delivered all encrypted files yet. You can keep using the local Library; Floria will check again automatically."
                        )
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        HStack(spacing: 10) {
                            Button("Check Again", systemImage: "arrow.clockwise") {
                                perform { try await store.syncReplicationPackage() }
                            }
                            .buttonStyle(.borderedProminent)
                            if let directory = status.directory {
                                Button("Show Sync Folder", systemImage: "folder") {
                                    showReplicationDirectory(directory)
                                }
                            }
                            Button("Stop Syncing…", role: .destructive) {
                                showingDisableConfirmation = true
                            }
                        }
                    }
                } else {
                    VStack(alignment: .leading, spacing: 14) {
                        if !status.pendingEnrollments.isEmpty {
                            pendingEnrollmentSection(status)
                        }
                        HStack(spacing: 10) {
                            Button("Sync Now", systemImage: "arrow.clockwise") {
                                perform { try await store.syncReplicationPackage() }
                            }
                            .buttonStyle(.borderedProminent)
                            Button("Stop Syncing…", role: .destructive) {
                                showingDisableConfirmation = true
                            }
                        }
                    }
                }
            }
            .disabled(isWorking)

        case .waitingForEnrollment:
            VStack(alignment: .leading, spacing: 12) {
                Text(
                    "This Mac’s request travels through the sync folder automatically. Open Sync on the Mac that created this folder and approve it there — after checking that it shows exactly this code:"
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                if let fingerprint = status.deviceFingerprint {
                    Text(fingerprint)
                        .font(.title3.monospaced().weight(.semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                        .textSelection(.enabled)
                }
                Button("Check Again", systemImage: "arrow.clockwise") {
                    perform { try await store.syncReplicationPackage() }
                }
                .disabled(isWorking)
            }

        case .removed:
            VStack(alignment: .leading, spacing: 12) {
                Text(
                    "This Mac can no longer decrypt future changes from this sync folder. Create a new identity, then approve it from the Mac that created this sync folder."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Button("Request Access Again") {
                        showingReenrollmentConfirmation = true
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Stop Syncing…", role: .destructive) {
                        showingDisableConfirmation = true
                    }
                }
                .disabled(isWorking)
            }

        case .fenced:
            VStack(alignment: .leading, spacing: 12) {
                Text(
                    "Sync stopped because this Mac’s saved device state moved backwards or conflicted with another copy. Stop syncing here, then reconnect this Mac from a trusted Mac."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                Button("Stop Syncing…", role: .destructive) {
                    showingDisableConfirmation = true
                }
                .disabled(isWorking)
            }

        case .error:
            HStack(spacing: 10) {
                Button("Try Again", systemImage: "arrow.clockwise") {
                    perform { try await store.syncReplicationPackage() }
                }
                .buttonStyle(.borderedProminent)
                Button("Stop Syncing…", role: .destructive) {
                    showingDisableConfirmation = true
                }
            }
            .disabled(isWorking)
        }
    }

    private func deviceSection(_ status: ReplicationStatus) -> some View {
        let activeCount = status.devices.count { $0.revokedGeneration == nil }
        let localCanRemove = status.devices.contains { $0.isCurrent && $0.isGenesis }
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Macs")
                    .font(.headline)
                Spacer()
                Text("\(activeCount) approved")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            VStack(spacing: 0) {
                ForEach(Array(status.devices.enumerated()), id: \.element.id) { index, device in
                    HStack(spacing: 12) {
                        Image(systemName: "laptopcomputer")
                            .foregroundStyle(device.revokedGeneration == nil ? .blue : .secondary)
                            .frame(width: 24)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(deviceDisplayName(device))
                                .font(.callout.weight(.medium))
                            Text(deviceSummary(device))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if localCanRemove && !device.isCurrent && !device.isGenesis
                            && device.revokedGeneration == nil
                        {
                            Button("Remove…", role: .destructive) {
                                pendingDeviceRemoval = device
                            }
                            .controlSize(.small)
                        }
                    }
                    .padding(.horizontal, 12)
                    .frame(minHeight: 52)
                    if index < status.devices.count - 1 {
                        Divider().padding(.leading, 48)
                    }
                }
            }
            .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 9))
        }
    }

    private func refreshStatus() async {
        guard status == nil else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            status = try await store.replicationStatus()
            errorMessage = nil
        } catch {
            errorMessage = displayMessage(for: error)
        }
    }

    private func perform(_ operation: @escaping @MainActor () async throws -> ReplicationStatus) {
        guard !isWorking else { return }
        isWorking = true
        errorMessage = nil
        Task {
            defer { isWorking = false }
            do {
                status = try await operation()
            } catch {
                errorMessage = displayMessage(for: error)
            }
        }
    }

    private func chooseNewPackage() {
        let panel = NSSavePanel()
        panel.title = "Create Floria Sync Folder"
        panel.prompt = "Create"
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "Floria Sync.floriavault"
        panel.isExtensionHidden = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        perform { try await store.createReplicationPackage(at: url.path) }
    }

    private func chooseExistingPackage() {
        let panel = NSOpenPanel()
        panel.title = "Open Floria Sync Folder"
        panel.prompt = "Open"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.treatsFilePackagesAsDirectories = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        perform { try await store.openReplicationPackage(at: url.path) }
    }

    private func pendingEnrollmentSection(_ status: ReplicationStatus) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Macs waiting for approval")
                .font(.headline)
            Text(
                "A new Mac asked to join through the sync folder. Compare the code with the one shown on that Mac before approving."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 0) {
                ForEach(Array(status.pendingEnrollments.enumerated()), id: \.element.id) {
                    index, request in
                    HStack(spacing: 12) {
                        Image(systemName: "laptopcomputer.and.arrow.down")
                            .foregroundStyle(.orange)
                            .frame(width: 24)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(request.deviceName ?? "Mac \(shortDeviceID(request.deviceID))")
                                .font(.callout.weight(.medium))
                            Text(request.fingerprint)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Approve…") {
                            pendingApproval = request
                            showingApprovalConfirmation = true
                        }
                        .controlSize(.small)
                    }
                    .padding(.horizontal, 12)
                    .frame(minHeight: 52)
                    if index < status.pendingEnrollments.count - 1 {
                        Divider().padding(.leading, 48)
                    }
                }
            }
            .background(Color.orange.opacity(0.06), in: RoundedRectangle(cornerRadius: 9))
        }
    }

    private func statusTitle(_ status: ReplicationStatus) -> String {
        if status.conflicts > 0 { return "Choose which version to keep" }
        if status.damaged > 0 { return "Some synced files couldn’t be verified" }
        if status.pending > 0 { return "Waiting for your sync tool" }
        return switch status.mode {
        case .off: "Sync is off"
        case .waitingForEnrollment: "Approval needed"
        case .active: "Sync is on"
        case .removed: "This Mac was removed"
        case .fenced: "Sync stopped to protect your data"
        case .error: "Sync needs attention"
        }
    }

    private func statusDetail(_ status: ReplicationStatus) -> String {
        if let message = status.message, !message.isEmpty {
            return message
        }
        switch status.mode {
        case .off: return "Your Library stays only on this Mac."
        case .waitingForEnrollment:
            return "The Mac that created this sync folder must approve this Mac before it can sync."
        case .removed:
            return "Create a new identity to request access again."
        case .active:
            if status.damaged > 0 {
                return "(status.damaged) encrypted file verification issue\(status.damaged == 1 ? "" : "s") found."
            }
            if status.pending > 0 {
                return "Waiting for \(status.pending) item\(status.pending == 1 ? "" : "s") to arrive."
            }
            return "Your encrypted Library is shared through the selected folder."
        case .fenced: return "No more changes will be written from this Mac."
        case .error: return "Try again, or stop syncing without deleting either copy."
        }
    }

    private func statusSymbol(_ status: ReplicationStatus) -> String {
        if status.conflicts > 0 { return "exclamationmark.triangle.fill" }
        if status.damaged > 0 { return "exclamationmark.triangle.fill" }
        if status.pending > 0 { return "clock.arrow.circlepath" }
        return switch status.mode {
        case .off: "icloud.slash"
        case .waitingForEnrollment: "person.badge.key"
        case .active: "checkmark.icloud"
        case .removed: "laptopcomputer.slash"
        case .fenced: "hand.raised.fill"
        case .error: "exclamationmark.icloud"
        }
    }

    private func statusColor(_ status: ReplicationStatus) -> Color {
        if status.conflicts > 0 || status.damaged > 0 || status.pending > 0 { return .orange }
        return switch status.mode {
        case .active: .green
        case .off: .secondary
        case .waitingForEnrollment, .removed, .fenced, .error: .orange
        }
    }

    private func abbreviatedPath(_ path: String) -> String {
        let home = NSHomeDirectory()
        guard path == home || path.hasPrefix(home + "/") else { return path }
        return "~" + path.dropFirst(home.count)
    }

    private func showReplicationDirectory(_ path: String) {
        NSWorkspace.shared.open(URL(fileURLWithPath: path, isDirectory: true))
    }

    private func showReplicationFile(_ relativePath: String, in directory: String?) {
        guard let directory else { return }
        let file = URL(fileURLWithPath: directory, isDirectory: true)
            .appendingPathComponent(relativePath)
        NSWorkspace.shared.activateFileViewerSelecting([file])
    }

    private func shortDeviceID(_ id: String) -> String {
        id.count > 12 ? String(id.prefix(12)) + "…" : id
    }

    private func deviceDisplayName(_ device: ReplicationDevice) -> String {
        if let name = device.deviceName, !name.isEmpty { return name }
        if device.isGenesis { return "Owner Mac" }
        return "Mac \(shortDeviceID(device.deviceID))"
    }

    private func deviceSummary(_ device: ReplicationDevice) -> String {
        if device.revokedGeneration != nil { return "Removed" }
        if device.isCurrent && device.isGenesis { return "This Mac · Created this sync folder" }
        if device.isCurrent { return "This Mac" }
        if device.isGenesis { return "Created this sync folder" }
        return "Approved"
    }

    private func displayMessage(for error: Error) -> String {
        if let controlError = error as? ControlClientError,
            case .systemCall = controlError
        {
            return "Floria’s background service isn’t ready. Try again after startup completes."
        }
        return error.localizedDescription
    }
}
