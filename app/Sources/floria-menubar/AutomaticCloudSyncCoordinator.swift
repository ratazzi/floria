import Foundation
import os

protocol AutomaticCloudSyncServicing: Sendable {
    func isAvailable() async -> Bool
    func isEnabled() async -> Bool
    func pendingVaultID() async -> String?
    func localStatus() async throws -> SyncDomainStatus?
    func syncNow() async throws -> CloudSyncOutcome
    func authenticateVault(_ vaultID: String) async throws -> SyncVaultBootstrap
    func reviewEnrollments(in bootstrap: SyncVaultBootstrap) async throws
        -> [SyncEnrollmentReview]
    func approveEnrollment(
        _ review: SyncEnrollmentReview,
        in bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultBootstrap
    func requestEnrollment(
        in bootstrap: SyncVaultBootstrap,
        deviceName: String?,
        requestedAt: String?
    ) async throws -> SyncEnrollmentPreparation
    func activateVault(_ bootstrap: SyncVaultBootstrap) async throws -> SyncVaultActivation
}

extension CloudSyncService: AutomaticCloudSyncServicing {}

/// Owns enabled iCloud Sync for the lifetime of the menu bar app.
///
/// Local status is cheap and checked frequently so edits leave this Mac promptly. CloudKit is
/// polled less often for remote changes and enrollment requests. The module never constructs a
/// CloudKit dependency while sync is disabled; manual and automatic calls are coalesced by
/// `CloudSyncService` before they reach CKSyncEngine.
@MainActor
final class AutomaticCloudSyncCoordinator {
    private static let log = Logger(
        subsystem: ProductIdentity.bundleIdentifier, category: "automatic-sync")

    typealias EnrollmentHandler = @MainActor @Sendable (SyncEnrollmentReview) -> Void
    typealias EnrollmentReviewsHandler = @MainActor @Sendable ([SyncEnrollmentReview]) -> Void
    typealias RemoteChangeHandler = @MainActor @Sendable () async -> Void
    typealias DaemonRestarter = @MainActor @Sendable () async throws -> Void

    private let service: any AutomaticCloudSyncServicing
    private let localCheckNanoseconds: UInt64
    private let remotePollInterval: TimeInterval
    private let now: @Sendable () -> Date
    private let restartDaemon: DaemonRestarter
    private var loopTask: Task<Void, Never>?
    private var lastRemoteAttempt: Date?
    private var failedRemoteAttempts = 0
    private var observedEnrollmentKeys = Set<String>()

    var onEnrollmentReview: EnrollmentHandler?
    var onEnrollmentReviewsChanged: EnrollmentReviewsHandler?
    var onRemoteChangesApplied: RemoteChangeHandler?

    init(
        service: any AutomaticCloudSyncServicing,
        localCheckNanoseconds: UInt64 = 3_000_000_000,
        remotePollInterval: TimeInterval = 5 * 60,
        now: @escaping @Sendable () -> Date = { Date() },
        restartDaemon: @escaping DaemonRestarter = {}
    ) {
        self.service = service
        self.localCheckNanoseconds = localCheckNanoseconds
        self.remotePollInterval = remotePollInterval
        self.now = now
        self.restartDaemon = restartDaemon
    }

    func start() {
        guard loopTask == nil else { return }
        loopTask = Task { @MainActor [weak self] in
            guard let self else { return }
            await checkNow(forceRemote: true)
            while !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: localCheckNanoseconds)
                } catch {
                    return
                }
                guard !Task.isCancelled else { return }
                await checkNow()
            }
        }
    }

    func stop() {
        loopTask?.cancel()
        loopTask = nil
    }

    /// Approve exactly the reviewed device and immediately publish the signed lifecycle update.
    func approve(_ review: SyncEnrollmentReview) async throws {
        guard await service.isEnabled() else { throw CloudSyncServiceError.disabled }
        guard await service.isAvailable() else { throw CloudSyncServiceError.unavailable }
        guard let status = try await service.localStatus() else {
            throw AutomaticCloudSyncError.noActiveLibrary
        }
        let bootstrap = try await service.authenticateVault(status.vaultID)
        _ = try await service.approveEnrollment(review, in: bootstrap)
        let outcome = try await service.syncNow()
        observedEnrollmentKeys.remove(Self.enrollmentKey(review))
        if outcome.appliedRemoteChanges {
            await onRemoteChangesApplied?()
        }
    }

    /// Internal test seam and the implementation behind the lifetime loop.
    func checkNow(forceRemote: Bool = false) async {
        guard await service.isAvailable(), await service.isEnabled() else {
            resetDisabledState()
            return
        }

        let currentTime = now()
        let remoteDue = lastRemoteAttempt.map {
            currentTime.timeIntervalSince($0) >= remotePollInterval
        } ?? true

        if let pendingVaultID = await service.pendingVaultID() {
            guard forceRemote || remoteDue else { return }
            lastRemoteAttempt = currentTime
            await resumePendingLibrary(vaultID: pendingVaultID)
            return
        }

        let status: SyncDomainStatus
        do {
            guard let local = try await service.localStatus() else { return }
            status = local
        } catch {
            Self.log.debug("local sync status unavailable: \(error.localizedDescription)")
            return
        }

        let hasLocalWork = status.outboundTransactions > 0
            || status.inboundTransactions > 0
            || status.pendingTransactions > 0
            || status.projectionPending
        let mayRetryLocalWork = hasLocalWork && failedRemoteAttempts == 0
        guard forceRemote || remoteDue || mayRetryLocalWork else { return }
        lastRemoteAttempt = currentTime

        let outcome: CloudSyncOutcome
        do {
            outcome = try await service.syncNow()
            failedRemoteAttempts = 0
        } catch is CancellationError {
            return
        } catch {
            failedRemoteAttempts += 1
            Self.log.notice("automatic sync deferred: \(error.localizedDescription)")
            return
        }

        if outcome.appliedRemoteChanges {
            await onRemoteChangesApplied?()
        }
        await refreshEnrollmentReviews(after: outcome)
    }

    private func resumePendingLibrary(vaultID: String) async {
        do {
            let bootstrap = try await service.authenticateVault(vaultID)
            switch try await service.requestEnrollment(
                in: bootstrap,
                deviceName: Host.current().localizedName,
                requestedAt: nil)
            {
            case .request:
                return
            case .alreadyEnrolled:
                break
            }
            let activation = try await service.activateVault(bootstrap)
            guard case .ready(let activatedVaultID, _, let restartRequired) = activation else {
                return
            }
            if restartRequired {
                try await restartDaemon()
                try await waitForActivatedLibrary(activatedVaultID)
            }
            let outcome = try await service.syncNow()
            failedRemoteAttempts = 0
            lastRemoteAttempt = now()
            if outcome.appliedRemoteChanges {
                await onRemoteChangesApplied?()
            }
        } catch is CancellationError {
            return
        } catch {
            failedRemoteAttempts += 1
            Self.log.notice("pending Library activation deferred: \(error.localizedDescription)")
        }
    }

    private func waitForActivatedLibrary(_ vaultID: String) async throws {
        for _ in 0..<30 {
            try await Task.sleep(nanoseconds: 500_000_000)
            guard let status = try? await service.localStatus() else { continue }
            if status.vaultID == vaultID { return }
        }
        throw AutomaticCloudSyncError.daemonRestartTimedOut
    }

    private func refreshEnrollmentReviews(after outcome: CloudSyncOutcome) async {
        do {
            let bootstrap: SyncVaultBootstrap
            if let authenticated = outcome.authenticatedBootstrap,
               authenticated.vaultID == outcome.status.vaultID
            {
                bootstrap = authenticated
            } else {
                bootstrap = try await service.authenticateVault(outcome.status.vaultID)
            }
            let reviews = try await service.reviewEnrollments(in: bootstrap)
            onEnrollmentReviewsChanged?(reviews)
            let currentKeys = Set(reviews.map(Self.enrollmentKey))
            observedEnrollmentKeys.formIntersection(currentKeys)
            for review in reviews where !observedEnrollmentKeys.contains(Self.enrollmentKey(review)) {
                observedEnrollmentKeys.insert(Self.enrollmentKey(review))
                onEnrollmentReview?(review)
            }
        } catch is CancellationError {
            return
        } catch {
            Self.log.notice("enrollment review refresh deferred: \(error.localizedDescription)")
        }
    }

    private func resetDisabledState() {
        lastRemoteAttempt = nil
        failedRemoteAttempts = 0
        observedEnrollmentKeys.removeAll()
    }

    private static func enrollmentKey(_ review: SyncEnrollmentReview) -> String {
        "\(review.deviceID)/\(review.fingerprint)"
    }
}

enum AutomaticCloudSyncError: LocalizedError {
    case noActiveLibrary
    case daemonRestartTimedOut

    var errorDescription: String? {
        switch self {
        case .noActiveLibrary:
            "This Mac does not have an active iCloud Library."
        case .daemonRestartTimedOut:
            "Floria could not finish activating the approved iCloud Library."
        }
    }
}
