import SwiftUI

protocol CloudSyncServicing: Sendable {
    func isEnabled() async -> Bool
    func setEnabled(_ enabled: Bool) async
    func localStatus() async throws -> SyncDomainStatus?
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
    var candidates = [CloudVaultCandidate]()
    var enrollmentRequest: SyncEnrollmentRequest?
    var approvals = [SyncEnrollmentReview]()
    var notice: String?
    var errorMessage: String?

    init(
        service: any CloudSyncServicing,
        restartDaemon: @escaping @Sendable () async throws -> Void
    ) {
        self.service = service
        self.restartDaemon = restartDaemon
    }

    func load() async {
        isEnabled = await service.isEnabled()
        guard isEnabled else { return }
        await refreshLocalStatus()
    }

    func setEnabled(_ enabled: Bool) async {
        await service.setEnabled(enabled)
        isEnabled = enabled
        notice = nil
        errorMessage = nil
        if enabled {
            await refreshLocalStatus()
        } else {
            candidates = []
            enrollmentRequest = nil
            approvals = []
            joiningBootstrap = nil
        }
    }

    func syncNow() async {
        await perform {
            let status = try await self.service.syncNow()
            self.status = status
            self.notice = "Your encrypted Library is up to date in iCloud."
            try await self.loadApprovals(for: status.vaultID)
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

    func approve(_ review: SyncEnrollmentReview) async {
        guard let vaultID = status?.vaultID else { return }
        await perform {
            let bootstrap = try await self.service.authenticateVault(vaultID)
            _ = try await self.service.approveEnrollment(review, in: bootstrap)
            let updated = try await self.service.syncNow()
            self.status = updated
            try await self.loadApprovals(for: updated.vaultID)
            self.notice = "\(review.deviceName ?? "The other Mac") can now use this Library."
        }
    }

    private func refreshLocalStatus() async {
        do {
            status = try await service.localStatus()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
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
            notice = nil
        case .alreadyEnrolled:
            enrollmentRequest = nil
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
        candidates = []
        joiningBootstrap = nil
        approvals = []
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

    private func loadApprovals(for vaultID: String) async throws {
        let bootstrap = try await service.authenticateVault(vaultID)
        approvals = try await service.reviewEnrollments(in: bootstrap)
    }

    private func perform(_ operation: @escaping () async throws -> Void) async {
        guard !isWorking else { return }
        isWorking = true
        errorMessage = nil
        defer { isWorking = false }
        do {
            try await operation()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

enum CloudSyncViewError: LocalizedError {
    case daemonRestartTimedOut

    var errorDescription: String? {
        switch self {
        case .daemonRestartTimedOut:
            "Floria could not finish switching Libraries. Reopen Floria and try Sync Now."
        }
    }
}

struct SyncView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var model: CloudSyncViewModel
    @State private var pendingApproval: SyncEnrollmentReview?

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
                        if let request = model.enrollmentRequest {
                            enrollmentSection(request)
                        }
                        if !model.approvals.isEmpty {
                            approvalsSection
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
                    if let status = model.status {
                        Text("\(status.outboundTransactions) changes to send · \(status.pendingTransactions) waiting")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("Available only on this Mac until you sync.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
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
