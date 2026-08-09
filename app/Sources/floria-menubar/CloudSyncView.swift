import AppKit
import SwiftUI

protocol CloudSyncServicing: Sendable {
    func isEnabled() async -> Bool
    func setEnabled(_ enabled: Bool) async
    func lastSuccessfulSyncAt() async -> Date?
    func pendingVaultID() async -> String?
    func localStatus() async throws -> SyncDomainStatus?
    func reviewConflicts() async throws -> [SyncConflictReview]
    func resolveConflict(entityID: String, selectedRevisionID: String) async throws
        -> SyncDomainStatus
    func projectsWithoutLocalFolder() async throws -> [SyncedProject]
    func attachProject(_ project: SyncedProject, at directory: URL) async throws
    func syncNow() async throws -> SyncDomainStatus
    func discoverVaults() async throws -> [CloudVaultCandidate]
    func authenticateVault(_ vaultID: String) async throws -> SyncVaultBootstrap
    func requestEnrollment(
        in bootstrap: SyncVaultBootstrap,
        deviceName: String?,
        requestedAt: String?
    ) async throws -> SyncEnrollmentPreparation
    func reviewEnrollments(
        in bootstrap: SyncVaultBootstrap
    ) async throws -> [SyncEnrollmentReview]
    func approveEnrollment(
        _ review: SyncEnrollmentReview,
        in bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultBootstrap
    func reviewDevices(in bootstrap: SyncVaultBootstrap) async throws -> [SyncVaultDevice]
    func revokeDevice(
        _ device: SyncVaultDevice,
        in bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultBootstrap
    func activateVault(_ bootstrap: SyncVaultBootstrap) async throws -> SyncVaultActivation
}

extension CloudSyncService: CloudSyncServicing {}

@Observable @MainActor
final class CloudSyncViewModel {
    private let service: any CloudSyncServicing
    private let restartDaemon: @Sendable () async throws -> Void
    private var joiningBootstrap: SyncVaultBootstrap?

    var isEnabled = false
    var isWorking = false
    var status: SyncDomainStatus?
    var lastSuccessfulSyncAt: Date?
    var pendingVaultID: String?
    var candidates = [CloudVaultCandidate]()
    var enrollmentRequest: SyncEnrollmentRequest?
    var approvals = [SyncEnrollmentReview]()
    var devices = [SyncVaultDevice]()
    var projectsWithoutLocalFolder = [SyncedProject]()
    var conflicts = [SyncConflictReview]()
    var notice: String?
    var errorMessage: String?

    var syncStatusSummary: String {
        guard let status else { return "Available only on this Mac until you sync." }
        var parts = [String]()
        if status.outboundTransactions > 0 {
            parts.append("\(status.outboundTransactions) to send")
        }
        if status.inboundTransactions > 0 {
            parts.append("\(status.inboundTransactions) received")
        }
        if status.pendingTransactions > 0 {
            parts.append("\(status.pendingTransactions) waiting")
        }
        if status.conflictingEntities > 0 {
            parts.append("\(status.conflictingEntities) conflicts")
        }
        if status.projectionPending {
            parts.append("Applying changes")
        }
        return parts.isEmpty ? "Up to date" : parts.joined(separator: " · ")
    }

    var syncAttentionMessage: String? {
        guard let status else { return nil }
        if status.conflictingEntities > 0 {
            return "\(status.conflictingEntities) synced item\(status.conflictingEntities == 1 ? " has" : "s have") conflicting changes. Floria kept every version and did not choose one automatically."
        }
        if status.projectionPending {
            return "Downloaded changes are waiting for the local Library update to finish."
        }
        if status.pendingTransactions > 0 {
            return "\(status.pendingTransactions) incomplete synced change\(status.pendingTransactions == 1 ? " is" : "s are") waiting for the rest of its data."
        }
        if status.outboundTransactions > 0 || status.inboundTransactions > 0 {
            return "Sync finished, but some encrypted changes still need another Sync Now."
        }
        return nil
    }

    init(
        service: any CloudSyncServicing,
        restartDaemon: @escaping @Sendable () async throws -> Void
    ) {
        self.service = service
        self.restartDaemon = restartDaemon
    }

    func load() async {
        isEnabled = await service.isEnabled()
        await refreshPersistentState()
        guard isEnabled else { return }
        await refreshLocalStatus()
        await refreshConflicts()
        await refreshProjectsWithoutLocalFolder()
    }

    func setEnabled(_ enabled: Bool) async {
        await service.setEnabled(enabled)
        isEnabled = enabled
        notice = nil
        errorMessage = nil
        if enabled {
            await refreshPersistentState()
            await refreshLocalStatus()
            await refreshConflicts()
            await refreshProjectsWithoutLocalFolder()
        } else {
            candidates = []
            enrollmentRequest = nil
            approvals = []
            devices = []
            projectsWithoutLocalFolder = []
            conflicts = []
            joiningBootstrap = nil
        }
    }

    func syncNow() async {
        await perform {
            do {
                let status = try await self.service.syncNow()
                self.status = status
                try await self.loadConflicts(for: status)
                await self.refreshPersistentState()
                self.notice = self.syncAttentionMessage == nil
                    ? "Your encrypted Library is up to date in iCloud."
                    : nil
                try await self.loadDeviceManagement(for: status.vaultID)
                try await self.loadProjectsWithoutLocalFolder()
            } catch {
                if await self.detectCurrentMacRemoval() {
                    throw CloudSyncViewError.currentMacRemoved
                }
                throw error
            }
        }
    }

    func discover() async {
        await perform {
            let localVaultID = self.status?.vaultID
            self.candidates = try await self.service.discoverVaults().filter {
                $0.vaultID != localVaultID
            }
            self.notice = self.candidates.isEmpty
                ? "No other Floria Library was found in this iCloud account."
                : nil
        }
    }

    func join(_ candidate: CloudVaultCandidate) async {
        await perform {
            let bootstrap = try await self.service.authenticateVault(candidate.vaultID)
            try await self.continueJoining(bootstrap)
        }
    }

    func checkEnrollment() async {
        guard let joiningBootstrap else { return }
        await perform {
            let refreshed = try await self.service.authenticateVault(joiningBootstrap.vaultID)
            try await self.continueJoining(refreshed)
        }
    }

    func resumePendingSetup() async {
        guard let pendingVaultID else { return }
        await perform {
            let bootstrap = try await self.service.authenticateVault(pendingVaultID)
            try await self.continueJoining(bootstrap)
        }
    }

    func approve(_ review: SyncEnrollmentReview) async {
        guard let vaultID = status?.vaultID else { return }
        await perform {
            let bootstrap = try await self.service.authenticateVault(vaultID)
            _ = try await self.service.approveEnrollment(review, in: bootstrap)
            let updated = try await self.service.syncNow()
            self.status = updated
            await self.refreshPersistentState()
            try await self.loadDeviceManagement(for: updated.vaultID)
            self.notice = "\(review.deviceName ?? "The other Mac") can now use this Library."
        }
    }

    func revoke(_ device: SyncVaultDevice) async {
        guard let vaultID = status?.vaultID else { return }
        await perform {
            let bootstrap = try await self.service.authenticateVault(vaultID)
            _ = try await self.service.revokeDevice(device, in: bootstrap)
            let updated = try await self.service.syncNow()
            self.status = updated
            await self.refreshPersistentState()
            try await self.loadDeviceManagement(for: updated.vaultID)
            self.notice = "\(device.deviceName ?? "The other Mac") was removed from this Library."
        }
    }

    func attach(_ project: SyncedProject, at directory: URL) async {
        await perform {
            try await self.service.attachProject(project, at: directory)
            try await self.loadProjectsWithoutLocalFolder()
            self.notice = "\(project.name) is now available on this Mac."
        }
    }

    func resolve(_ review: SyncConflictReview, keeping candidate: SyncConflictCandidate) async {
        await perform {
            self.status = try await self.service.resolveConflict(
                entityID: review.entityID,
                selectedRevisionID: candidate.revisionID)
            self.status = try await self.service.syncNow()
            if let status = self.status {
                try await self.loadConflicts(for: status)
            }
            await self.refreshPersistentState()
            self.notice = self.conflicts.isEmpty
                ? "The conflict was resolved and every version remains in encrypted history."
                : nil
        }
    }

    private func refreshLocalStatus() async {
        do {
            status = try await service.localStatus()
            errorMessage = nil
        } catch {
            errorMessage = CloudSyncErrorPresentation.message(for: error)
        }
    }

    private func refreshProjectsWithoutLocalFolder() async {
        do {
            try await loadProjectsWithoutLocalFolder()
        } catch {
            errorMessage = CloudSyncErrorPresentation.message(for: error)
        }
    }

    private func refreshConflicts() async {
        guard let status else {
            conflicts = []
            return
        }
        do {
            try await loadConflicts(for: status)
        } catch {
            errorMessage = CloudSyncErrorPresentation.message(for: error)
        }
    }

    private func loadConflicts(for status: SyncDomainStatus) async throws {
        conflicts = status.conflictingEntities == 0
            ? []
            : try await service.reviewConflicts()
    }

    private func refreshPersistentState() async {
        lastSuccessfulSyncAt = await service.lastSuccessfulSyncAt()
        pendingVaultID = await service.pendingVaultID()
    }

    private func loadProjectsWithoutLocalFolder() async throws {
        projectsWithoutLocalFolder = try await service.projectsWithoutLocalFolder()
    }

    private func continueJoining(_ bootstrap: SyncVaultBootstrap) async throws {
        joiningBootstrap = bootstrap
        switch try await service.requestEnrollment(
            in: bootstrap,
            deviceName: Host.current().localizedName,
            requestedAt: nil)
        {
        case .request(let request):
            enrollmentRequest = request
            await refreshPersistentState()
            notice = nil
        case .alreadyEnrolled:
            enrollmentRequest = nil
            await refreshPersistentState()
            try await activate(bootstrap)
        }
    }

    private func activate(_ bootstrap: SyncVaultBootstrap) async throws {
        let activation = try await service.activateVault(bootstrap)
        guard case .ready(let vaultID, _, let restartRequired) = activation else {
            return
        }
        if restartRequired {
            notice = "Finishing setup on this Mac…"
            try await restartDaemon()
            try await waitForActivation(vaultID)
        }
        status = try await service.syncNow()
        await refreshPersistentState()
        try await loadProjectsWithoutLocalFolder()
        candidates = []
        joiningBootstrap = nil
        approvals = []
        devices = []
        notice = "This Mac now uses your iCloud Library."
    }

    private func waitForActivation(_ vaultID: String) async throws {
        for _ in 0..<30 {
            try await Task.sleep(nanoseconds: 500_000_000)
            guard let observed = try? await service.localStatus() else { continue }
            if observed.vaultID == vaultID { return }
        }
        throw CloudSyncViewError.daemonRestartTimedOut
    }

    private func loadDeviceManagement(for vaultID: String) async throws {
        let bootstrap = try await service.authenticateVault(vaultID)
        approvals = try await service.reviewEnrollments(in: bootstrap)
        devices = try await service.reviewDevices(in: bootstrap)
    }

    /// Diagnose a failed sync only from a fresh Rust-authenticated lifecycle. A transport error
    /// remains the original error if CloudKit cannot provide enough evidence to prove removal.
    private func detectCurrentMacRemoval() async -> Bool {
        guard let vaultID = status?.vaultID,
              let bootstrap = try? await service.authenticateVault(vaultID),
              let reviewed = try? await service.reviewDevices(in: bootstrap)
        else { return false }
        devices = reviewed
        return reviewed.contains { $0.isCurrent && $0.revokedGeneration != nil }
    }

    private func perform(_ operation: @escaping () async throws -> Void) async {
        guard !isWorking else { return }
        isWorking = true
        errorMessage = nil
        defer { isWorking = false }
        do {
            try await operation()
        } catch {
            errorMessage = CloudSyncErrorPresentation.message(for: error)
        }
    }
}

enum CloudSyncViewError: LocalizedError {
    case daemonRestartTimedOut
    case currentMacRemoved

    var errorDescription: String? {
        switch self {
        case .daemonRestartTimedOut:
            "Floria could not finish switching Libraries. Reopen Floria and try Sync Now."
        case .currentMacRemoved:
            "This Mac was removed from the iCloud Library. Existing local data remains available, but new changes will not sync."
        }
    }
}

private struct ConflictSelection: Identifiable {
    let review: SyncConflictReview
    let candidate: SyncConflictCandidate

    var id: String { "\(review.entityID)/\(candidate.revisionID)" }
}

private extension SyncConflictEntityKind {
    var displayName: String {
        switch self {
        case .project: "Project"
        case .environment: "Environment"
        case .resource: "Resource"
        case .binding: "Binding"
        case .surface: "Managed file"
        case .secret: "Secret"
        }
    }
}

extension SyncConflictCandidate {
    var conflictSourceLabel: String {
        matchesLocalState ? "On this Mac" : "From iCloud"
    }

    var conflictVersionLabel: String {
        "Version \(revisionID.prefix(8))"
    }

    var conflictConfirmationSummary: String {
        "“\(label)” — \(conflictSourceLabel), \(conflictVersionLabel)"
    }
}

struct SyncView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var model: CloudSyncViewModel
    @State private var pendingApproval: SyncEnrollmentReview?
    @State private var pendingRemoval: SyncVaultDevice?
    @State private var pendingConflictSelection: ConflictSelection?

    init(
        service: any CloudSyncServicing,
        restartDaemon: @escaping @Sendable () async throws -> Void
    ) {
        _model = State(
            initialValue: CloudSyncViewModel(
                service: service, restartDaemon: restartDaemon))
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    enableSection
                    if model.isEnabled {
                        currentLibrarySection
                        if !model.conflicts.isEmpty {
                            conflictsSection
                        }
                        if let pendingVaultID = model.pendingVaultID,
                           model.enrollmentRequest == nil
                        {
                            pendingSetupSection(pendingVaultID)
                        }
                        if !model.projectsWithoutLocalFolder.isEmpty {
                            projectsFromICloudSection
                        }
                        if let request = model.enrollmentRequest {
                            enrollmentSection(request)
                        }
                        if !model.approvals.isEmpty {
                            approvalsSection
                        }
                        if !model.devices.isEmpty {
                            devicesSection
                        }
                        if !model.candidates.isEmpty {
                            candidatesSection
                        }
                    }
                    if let notice = model.notice {
                        Label(notice, systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.callout)
                    }
                    if let error = model.errorMessage {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if model.errorMessage == nil,
                       let attention = model.syncAttentionMessage
                    {
                        Label(attention, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(26)
            }
            Divider()
            HStack {
                Text("Floria connects to iCloud only when you use a sync action.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 22)
            .frame(height: 58)
        }
        .frame(width: 640, height: 500)
        .task { await model.load() }
        .confirmationDialog(
            "Keep This Version?",
            isPresented: Binding(
                get: { pendingConflictSelection != nil },
                set: { if !$0 { pendingConflictSelection = nil } }),
            presenting: pendingConflictSelection
        ) { selection in
            Button("Keep This Version") {
                pendingConflictSelection = nil
                Task {
                    await model.resolve(selection.review, keeping: selection.candidate)
                }
            }
            Button("Cancel", role: .cancel) { pendingConflictSelection = nil }
        } message: { selection in
            Text(conflictConfirmationMessage(selection))
        }
        .confirmationDialog(
            "Approve This Mac?",
            isPresented: Binding(
                get: { pendingApproval != nil },
                set: { if !$0 { pendingApproval = nil } }),
            presenting: pendingApproval
        ) { review in
            Button("Codes Match — Approve") {
                pendingApproval = nil
                Task { await model.approve(review) }
            }
            Button("Cancel", role: .cancel) { pendingApproval = nil }
        } message: { review in
            Text(
                "Only approve if \(review.deviceName ?? "the other Mac") shows exactly this code: \(review.fingerprint)"
            )
        }
        .confirmationDialog(
            "Remove Mac from Library?",
            isPresented: Binding(
                get: { pendingRemoval != nil },
                set: { if !$0 { pendingRemoval = nil } }),
            presenting: pendingRemoval
        ) { device in
            Button("Remove Mac", role: .destructive) {
                pendingRemoval = nil
                Task { await model.revoke(device) }
            }
            Button("Cancel", role: .cancel) { pendingRemoval = nil }
        } message: { device in
            Text(
                "\(device.deviceName ?? "This Mac") will keep data it already received, but cannot decrypt future changes. Floria will rotate the Library encryption key."
            )
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "icloud")
                .font(.system(size: 25, weight: .medium))
                .foregroundStyle(.blue)
                .frame(width: 48, height: 48)
                .background(Color.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 3) {
                Text("Sync")
                    .font(.title2.bold())
                Text("Your Library, encrypted before it leaves this Mac")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if model.isWorking {
                ProgressView().controlSize(.small)
            }
        }
        .padding(.horizontal, 24)
        .frame(height: 88)
    }

    private var enableSection: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 3) {
                Text("iCloud Sync")
                    .font(.headline)
                Text(model.isEnabled ? "Manual sync is ready." : "Off by default. Nothing is uploaded.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Toggle(
                "",
                isOn: Binding(
                    get: { model.isEnabled },
                    set: { enabled in Task { await model.setEnabled(enabled) } }))
                .labelsHidden()
        }
        .padding(16)
        .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
        .disabled(model.isWorking)
    }

    private var currentLibrarySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("This Mac")
                .font(.headline)
            HStack(spacing: 12) {
                Image(systemName: "books.vertical")
                    .foregroundStyle(.blue)
                    .frame(width: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Current Library")
                        .font(.callout.weight(.medium))
                    Text(model.syncStatusSummary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(lastSyncDescription)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Sync Now", systemImage: "arrow.clockwise") {
                    Task { await model.syncNow() }
                }
                .buttonStyle(.borderedProminent)
                Button("Use Existing…") {
                    Task { await model.discover() }
                }
            }
        }
        .disabled(model.isWorking)
    }

    private var conflictsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Choose which version to keep")
                    .font(.headline)
                Text("Floria found changes made on different Macs and kept every version.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            ForEach(model.conflicts) { review in
                VStack(alignment: .leading, spacing: 10) {
                    Text(review.candidates.first?.kind.displayName ?? "Synced item")
                        .font(.callout.weight(.semibold))
                    ForEach(review.candidates) { candidate in
                        HStack(spacing: 10) {
                            Image(systemName: candidate.matchesLocalState
                                ? "laptopcomputer" : "icloud.and.arrow.down")
                                .foregroundStyle(candidate.matchesLocalState ? .blue : .secondary)
                                .frame(width: 24)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(candidate.label)
                                    .font(.callout.weight(.medium))
                                    .lineLimit(1)
                                Text("\(candidate.conflictSourceLabel) · \(candidate.conflictVersionLabel) · \(conflictCandidateDetail(candidate))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Keep…") {
                                pendingConflictSelection = ConflictSelection(
                                    review: review, candidate: candidate)
                            }
                        }
                    }
                }
                .padding(14)
                .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
            }
        }
        .disabled(model.isWorking)
    }

    private func conflictCandidateDetail(_ candidate: SyncConflictCandidate) -> String {
        var parts = [candidate.kind.displayName]
        if candidate.lifecycle == .archived {
            parts.append("Archived")
        }
        if let size = candidate.plaintextSize {
            parts.append(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
        }
        return parts.joined(separator: " · ")
    }

    private func conflictConfirmationMessage(_ selection: ConflictSelection) -> String {
        "Floria will use \(selection.candidate.conflictConfirmationSummary). All versions remain in encrypted history."
    }

    private var lastSyncDescription: String {
        guard let date = model.lastSuccessfulSyncAt else {
            return "Not synced with iCloud yet."
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return "Last synced \(formatter.localizedString(for: date, relativeTo: Date()))."
    }

    private func pendingSetupSection(_ vaultID: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.triangle.2.circlepath.icloud")
                .foregroundStyle(.orange)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text("Finish Library Setup")
                    .font(.callout.weight(.medium))
                Text("Continue joining iCloud Library \(shortIdentifier(vaultID)).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Continue…") {
                Task { await model.resumePendingSetup() }
            }
        }
        .padding(12)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
        .disabled(model.isWorking)
    }

    private var projectsFromICloudSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Projects from iCloud")
                .font(.headline)
            ForEach(model.projectsWithoutLocalFolder) { project in
                HStack(spacing: 12) {
                    Image(systemName: "folder")
                        .foregroundStyle(.blue)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(project.name)
                            .font(.callout.weight(.medium))
                        Text("Choose its folder on this Mac to make Managed files available.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Choose Folder…") {
                        chooseFolder(for: project)
                    }
                }
                .padding(12)
                .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
            }
        }
        .disabled(model.isWorking)
    }

    private func chooseFolder(for project: SyncedProject) {
        let panel = NSOpenPanel()
        panel.title = "Choose \(project.name) Folder"
        panel.message = "Choose the existing project folder on this Mac."
        panel.prompt = "Use Folder"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let directory = panel.url else { return }
        Task { await model.attach(project, at: directory) }
    }

    private func enrollmentSection(_ request: SyncEnrollmentRequest) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Waiting for approval", systemImage: "person.badge.key")
                .font(.headline)
            Text("On a Mac that already uses this Library, open Sync and approve this code:")
                .font(.callout)
                .foregroundStyle(.secondary)
            Text(request.fingerprint)
                .font(.body.monospaced().weight(.semibold))
                .textSelection(.enabled)
            Button("Check Again", systemImage: "arrow.clockwise") {
                Task { await model.checkEnrollment() }
            }
        }
        .padding(16)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        .disabled(model.isWorking)
    }

    private var approvalsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Macs requesting access")
                .font(.headline)
            ForEach(model.approvals, id: \.deviceID) { review in
                HStack(spacing: 12) {
                    Image(systemName: "laptopcomputer")
                        .foregroundStyle(.blue)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(review.deviceName ?? "Another Mac")
                            .font(.callout.weight(.medium))
                        Text(review.fingerprint)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    Spacer()
                    Button("Approve") {
                        pendingApproval = review
                    }
                }
                .padding(12)
                .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
            }
        }
        .disabled(model.isWorking)
    }

    private var devicesSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Macs")
                .font(.headline)
            ForEach(model.devices, id: \.deviceID) { device in
                HStack(spacing: 12) {
                    Image(systemName: device.isCurrent ? "laptopcomputer.and.arrow.down" : "laptopcomputer")
                        .foregroundStyle(device.revokedGeneration == nil ? .blue : .secondary)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(device.deviceName ?? "Mac")
                                .font(.callout.weight(.medium))
                            if device.isCurrent {
                                Text("This Mac")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            } else if device.isGenesis {
                                Text("First Mac")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            } else if device.revokedGeneration != nil {
                                Text("Removed")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Text(device.fingerprint)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    Spacer()
                    if canRemoveDevices,
                       !device.isCurrent,
                       !device.isGenesis,
                       device.revokedGeneration == nil
                    {
                        Button("Remove…", role: .destructive) {
                            pendingRemoval = device
                        }
                    }
                }
                .padding(12)
                .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
            }
        }
        .disabled(model.isWorking)
    }

    private var canRemoveDevices: Bool {
        model.devices.contains { $0.isCurrent && $0.isGenesis }
    }

    private var candidatesSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Libraries in iCloud")
                .font(.headline)
            ForEach(model.candidates, id: \.vaultID) { candidate in
                HStack(spacing: 12) {
                    Image(systemName: "books.vertical")
                        .foregroundStyle(.blue)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Floria Library")
                            .font(.callout.weight(.medium))
                        Text(shortIdentifier(candidate.vaultID))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Use This Library") {
                        Task { await model.join(candidate) }
                    }
                }
                .padding(12)
                .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
            }
        }
        .disabled(model.isWorking)
    }

    private func shortIdentifier(_ value: String) -> String {
        String(value.prefix(8))
    }
}
