import AppKit
import SwiftUI

protocol CloudSyncServicing: Sendable {
    func isAvailable() async -> Bool
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
    func syncNow() async throws -> CloudSyncOutcome
    func discoverVaults() async throws -> [CloudVaultCandidate]
    func authenticateVault(_ vaultID: String) async throws -> SyncVaultBootstrap
    func requestEnrollment(
        in bootstrap: SyncVaultBootstrap,
        deviceName: String?,
        requestedAt: String?
    ) async throws -> SyncEnrollmentPreparation
    func requestAccessAgain(
        in bootstrap: SyncVaultBootstrap,
        removedDevice: SyncVaultDevice,
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

struct SyncLibraryReview: Equatable, Identifiable, Sendable {
    let vaultID: String
    let activeDeviceNames: [String]
    let activeDeviceCount: Int

    var id: String { vaultID }
}

@Observable @MainActor
final class CloudSyncViewModel {
    private let service: any CloudSyncServicing
    private let restartDaemon: @Sendable () async throws -> Void
    private var joiningBootstrap: SyncVaultBootstrap?
    private var removedBootstrap: SyncVaultBootstrap?

    var isEnabled = false
    var isAvailable = false
    var isAvailabilityLoaded = false
    var isLocalStatusLoaded = false
    var isWorking = false
    var status: SyncDomainStatus?
    var lastSuccessfulSyncAt: Date?
    var pendingVaultID: String?
    var candidates = [CloudVaultCandidate]()
    var libraryReview: SyncLibraryReview?
    var enrollmentRequest: SyncEnrollmentRequest?
    var approvals = [SyncEnrollmentReview]()
    var devices = [SyncVaultDevice]()
    var removedCurrentMac: SyncVaultDevice?
    var projectsWithoutLocalFolder = [SyncedProject]()
    var conflicts = [SyncConflictReview]()
    var notice: String?
    var errorMessage: String?

    var syncStatusSummary: String {
        guard isLocalStatusLoaded else { return "Checking this Mac…" }
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
        isAvailable = await service.isAvailable()
        isAvailabilityLoaded = true
        isEnabled = await service.isEnabled()
        await refreshPersistentState()
        guard isEnabled, isAvailable else { return }
        await refreshLocalStatus()
        await refreshConflicts()
        await refreshProjectsWithoutLocalFolder()
    }

    func setEnabled(_ enabled: Bool) async {
        guard !enabled || (isAvailabilityLoaded && isAvailable) else {
            errorMessage = CloudSyncServiceError.unavailable.localizedDescription
            return
        }
        await service.setEnabled(enabled)
        isEnabled = enabled
        notice = nil
        errorMessage = nil
        if enabled {
            isLocalStatusLoaded = false
            await refreshPersistentState()
            await refreshLocalStatus()
            await refreshConflicts()
            await refreshProjectsWithoutLocalFolder()
        } else {
            candidates = []
            isLocalStatusLoaded = false
            libraryReview = nil
            enrollmentRequest = nil
            approvals = []
            devices = []
            projectsWithoutLocalFolder = []
            conflicts = []
            joiningBootstrap = nil
            removedBootstrap = nil
            removedCurrentMac = nil
        }
    }

    func syncNow() async {
        await perform {
            do {
                let outcome = try await self.service.syncNow()
                self.status = outcome.status
                await self.refreshPersistentState()
                if self.syncAttentionMessage == nil {
                    self.notice = outcome.appliedRemoteChanges
                        ? "Changes from iCloud were applied to this Mac."
                        : "Your encrypted Library is up to date in iCloud."
                } else {
                    self.notice = nil
                }
                await self.refreshPostSyncDetails(for: outcome.status)
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
            self.libraryReview = nil
            self.joiningBootstrap = nil
            self.candidates = try await self.service.discoverVaults().filter {
                $0.vaultID != localVaultID
            }
            self.notice = self.candidates.isEmpty
                ? "No other Floria Library was found in this iCloud account."
                : nil
        }
    }

    func review(_ candidate: CloudVaultCandidate) async {
        await perform {
            let bootstrap = try await self.service.authenticateVault(candidate.vaultID)
            let activeDevices = try await self.service.reviewDevices(in: bootstrap).filter {
                $0.revokedGeneration == nil
            }
            var names = [String]()
            for name in activeDevices.compactMap(\.deviceName) where !names.contains(name) {
                names.append(name)
            }
            self.joiningBootstrap = bootstrap
            self.libraryReview = SyncLibraryReview(
                vaultID: bootstrap.vaultID,
                activeDeviceNames: names,
                activeDeviceCount: activeDevices.count)
        }
    }

    func joinReviewedLibrary() async {
        guard let joiningBootstrap else { return }
        await perform {
            try await self.continueJoining(joiningBootstrap)
            self.libraryReview = nil
        }
    }

    func checkEnrollment() async {
        guard let joiningBootstrap else { return }
        await perform {
            let refreshed = try await self.service.authenticateVault(joiningBootstrap.vaultID)
            try await self.continueJoining(refreshed)
        }
    }

    func requestAccessAgain() async {
        guard let removedBootstrap, let removedCurrentMac else { return }
        await perform {
            let preparation = try await self.service.requestAccessAgain(
                in: removedBootstrap,
                removedDevice: removedCurrentMac,
                deviceName: Host.current().localizedName,
                requestedAt: nil)
            guard case .request(let request) = preparation else {
                throw CloudSyncViewError.reenrollmentDidNotCreateRequest
            }
            self.joiningBootstrap = removedBootstrap
            self.enrollmentRequest = request
            self.removedBootstrap = nil
            self.removedCurrentMac = nil
            self.devices = []
            await self.refreshPersistentState()
            self.notice = "A new access request is ready for approval on another Mac."
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
            let outcome = try await self.service.syncNow()
            self.status = outcome.status
            await self.refreshPersistentState()
            await self.refreshPostSyncDetails(for: outcome.status)
            self.notice = "\(review.deviceName ?? "The other Mac") can now use this Library."
        }
    }

    func revoke(_ device: SyncVaultDevice) async {
        guard let vaultID = status?.vaultID else { return }
        await perform {
            let bootstrap = try await self.service.authenticateVault(vaultID)
            _ = try await self.service.revokeDevice(device, in: bootstrap)
            let outcome = try await self.service.syncNow()
            self.status = outcome.status
            await self.refreshPersistentState()
            await self.refreshPostSyncDetails(for: outcome.status)
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
            let outcome = try await self.service.syncNow()
            self.status = outcome.status
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
        defer { isLocalStatusLoaded = true }
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

    /// The CloudKit transport has already settled when this runs. These views are useful, but a
    /// failed refresh must not turn a successful sync into an apparent sync failure.
    private func refreshPostSyncDetails(for status: SyncDomainStatus) async {
        var failedSections = [String]()
        do {
            try await loadConflicts(for: status)
        } catch {
            conflicts = []
            failedSections.append("Conflicts")
        }
        do {
            try await loadDeviceManagement(for: status.vaultID)
        } catch {
            approvals = []
            devices = []
            failedSections.append("Macs")
        }
        do {
            try await loadProjectsWithoutLocalFolder()
        } catch {
            projectsWithoutLocalFolder = []
            failedSections.append("Projects")
        }
        guard !failedSections.isEmpty else { return }
        errorMessage =
            "Sync completed, but Floria could not refresh \(joined(failedSections)). "
            + "Try Sync Now again."
    }

    private func joined(_ values: [String]) -> String {
        guard let last = values.last else { return "details" }
        guard values.count > 1 else { return last }
        return values.dropLast().joined(separator: ", ") + " and " + last
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
            candidates = []
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
        let outcome = try await service.syncNow()
        status = outcome.status
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
        guard let removed = reviewed.first(where: {
            $0.isCurrent && $0.revokedGeneration != nil
        }) else { return false }
        removedBootstrap = bootstrap
        removedCurrentMac = removed
        return true
    }

    private func perform(_ operation: @escaping () async throws -> Void) async {
        guard !isWorking else { return }
        isWorking = true
        notice = nil
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
    case reenrollmentDidNotCreateRequest

    var errorDescription: String? {
        switch self {
        case .daemonRestartTimedOut:
            "Floria could not finish switching Libraries. Reopen Floria and try Sync Now."
        case .currentMacRemoved:
            "This Mac was removed from the iCloud Library. Existing local data remains available, but new changes will not sync."
        case .reenrollmentDidNotCreateRequest:
            "Floria could not create a new access request for this Mac."
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
    @State private var pendingLibraryReview: SyncLibraryReview?

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
                    if model.isEnabled && model.isAvailable {
                        currentLibrarySection
                        syncFeedback
                        if let removed = model.removedCurrentMac {
                            removedMacSection(removed)
                        }
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
                    } else {
                        syncFeedback
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
            "Use This iCloud Library?",
            isPresented: Binding(
                get: { pendingLibraryReview != nil },
                set: { if !$0 { pendingLibraryReview = nil } }),
            presenting: pendingLibraryReview
        ) { _ in
            Button("Use This Library") {
                pendingLibraryReview = nil
                Task { await model.joinReviewedLibrary() }
            }
            Button("Cancel", role: .cancel) { pendingLibraryReview = nil }
        } message: { review in
            Text(libraryReviewMessage(review))
        }
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

    @ViewBuilder
    private var syncFeedback: some View {
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
        } else if let attention = model.syncAttentionMessage {
            Label(attention, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
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
                Text(syncAvailabilityDescription)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Toggle(
                "iCloud Sync",
                isOn: Binding(
                    get: { model.isEnabled },
                    set: { enabled in Task { await model.setEnabled(enabled) } }))
                .labelsHidden()
        }
        .padding(16)
        .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 12))
        .disabled(
            model.isWorking || !model.isAvailabilityLoaded
                || (!model.isAvailable && !model.isEnabled))
    }

    private var syncAvailabilityDescription: String {
        if !model.isAvailabilityLoaded {
            return "Checking this build…"
        }
        if !model.isAvailable {
            return "Requires a CloudKit-enabled signed build."
        }
        return model.isEnabled ? "Manual sync is ready." : "Off by default. Nothing is uploaded."
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

    private func removedMacSection(_ device: SyncVaultDevice) -> some View {
        HStack(spacing: 14) {
            Image(systemName: "laptopcomputer.trianglebadge.exclamationmark")
                .foregroundStyle(.orange)
                .font(.title3)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 3) {
                Text("This Mac was removed")
                    .font(.headline)
                Text(
                    "Local data remains available. Request access again with a new device identity to resume syncing."
                )
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                Text("Previous code: \(device.fingerprint)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Request Access Again") {
                Task { await model.requestAccessAgain() }
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(16)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
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
                    Button("Use This Library…") {
                        Task {
                            await model.review(candidate)
                            pendingLibraryReview = model.libraryReview
                        }
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

    private func libraryReviewMessage(_ review: SyncLibraryReview) -> String {
        let knownNames = review.activeDeviceNames.joined(separator: ", ")
        let unnamedCount = max(0, review.activeDeviceCount - review.activeDeviceNames.count)
        let usedBy: String
        if knownNames.isEmpty {
            usedBy = "\(review.activeDeviceCount) active Mac\(review.activeDeviceCount == 1 ? "" : "s")"
        } else if unnamedCount == 0 {
            usedBy = knownNames
        } else {
            usedBy = "\(knownNames) and \(unnamedCount) other Mac\(unnamedCount == 1 ? "" : "s")"
        }
        return "Floria verified Library \(shortIdentifier(review.vaultID)), used by \(usedBy). "
            + "If this Mac does not have access yet, Floria will create an approval request."
    }
}
