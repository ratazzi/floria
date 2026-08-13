import Foundation
import XCTest

@testable import floria_menubar

@MainActor
final class AutomaticCloudSyncCoordinatorTests: XCTestCase {
    func testDisabledCoordinatorNeverTouchesLocalStateOrCloudKit() async {
        let service = AutomaticSyncServiceStub(enabled: false)
        let coordinator = AutomaticCloudSyncCoordinator(service: service)

        await coordinator.checkNow(forceRemote: true)

        let counts = await service.counts()
        XCTAssertEqual(counts.localStatus, 0)
        XCTAssertEqual(counts.sync, 0)
    }

    func testEnabledCoordinatorSynchronizesAndSurfacesEnrollmentReview() async {
        let review = enrollmentReview()
        let service = AutomaticSyncServiceStub(reviews: [review])
        let coordinator = AutomaticCloudSyncCoordinator(service: service)
        var presented = [SyncEnrollmentReview]()
        coordinator.onEnrollmentReview = { presented.append($0) }

        await coordinator.checkNow(forceRemote: true)
        await coordinator.checkNow(forceRemote: true)

        let counts = await service.counts()
        XCTAssertEqual(counts.sync, 2)
        XCTAssertEqual(presented, [review], "one pending request must not open duplicate windows")
    }

    func testLocalOutboundWorkTriggersSyncBeforeTheRemotePollDeadline() async {
        let clock = MutableDate(Date(timeIntervalSince1970: 1_000))
        let service = AutomaticSyncServiceStub()
        let coordinator = AutomaticCloudSyncCoordinator(
            service: service,
            remotePollInterval: 300,
            now: { clock.value })

        await coordinator.checkNow(forceRemote: true)
        await service.setStatus(status(outbound: 1))
        clock.value = clock.value.addingTimeInterval(1)
        await coordinator.checkNow()

        let counts = await service.counts()
        XCTAssertEqual(counts.sync, 2)
    }

    func testApprovedPendingLibraryActivatesWithoutOpeningSync() async {
        let pendingVaultID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        let service = AutomaticSyncServiceStub(
            pendingVaultID: pendingVaultID,
            enrollment: .alreadyEnrolled(deviceID: "fixture-device"),
            activation: .ready(
                vaultID: pendingVaultID, keyGeneration: 1, restartRequired: false))
        let coordinator = AutomaticCloudSyncCoordinator(service: service)

        await coordinator.checkNow(forceRemote: true)

        let counts = await service.counts()
        XCTAssertEqual(counts.requestedEnrollment, 1)
        XCTAssertEqual(counts.activation, 1)
        XCTAssertEqual(counts.sync, 1)
    }

    func testPendingLibraryChecksCloudKitOnlyAtTheRemotePollInterval() async {
        let clock = MutableDate(Date(timeIntervalSince1970: 1_000))
        let service = AutomaticSyncServiceStub(
            pendingVaultID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        let coordinator = AutomaticCloudSyncCoordinator(
            service: service,
            remotePollInterval: 30,
            now: { clock.value })

        await coordinator.checkNow(forceRemote: true)
        clock.value = clock.value.addingTimeInterval(3)
        await coordinator.checkNow()
        var counts = await service.counts()
        XCTAssertEqual(counts.requestedEnrollment, 1)

        clock.value = clock.value.addingTimeInterval(27)
        await coordinator.checkNow()
        counts = await service.counts()
        XCTAssertEqual(counts.requestedEnrollment, 2)
    }

    func testApprovalPublishesLifecycleUpdateImmediately() async throws {
        let review = enrollmentReview()
        let service = AutomaticSyncServiceStub(reviews: [review])
        let coordinator = AutomaticCloudSyncCoordinator(service: service)

        try await coordinator.approve(review)

        let counts = await service.counts()
        XCTAssertEqual(counts.approvedReviews, [review])
        XCTAssertEqual(counts.sync, 1)
    }

    private func status(outbound: Int = 0) -> SyncDomainStatus {
        SyncDomainStatus(
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            keyGeneration: 1,
            outboundTransactions: outbound,
            inboundTransactions: 0,
            pendingTransactions: 0,
            conflictingEntities: 0,
            projectionPending: false)
    }

    private func enrollmentReview() -> SyncEnrollmentReview {
        SyncEnrollmentReview(
            deviceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            deviceName: "Mac mini",
            requestedAt: "2026-08-14T00:00:00Z",
            fingerprint: "AB12-CD34-EF56")
    }
}

private final class MutableDate: @unchecked Sendable {
    var value: Date
    init(_ value: Date) { self.value = value }
}

private actor AutomaticSyncServiceStub: AutomaticCloudSyncServicing {
    struct Counts: Sendable {
        let localStatus: Int
        let sync: Int
        let requestedEnrollment: Int
        let activation: Int
        let approvedReviews: [SyncEnrollmentReview]
    }
    private let available: Bool
    private let enabled: Bool
    private var status: SyncDomainStatus
    private var pendingID: String?
    private let reviews: [SyncEnrollmentReview]
    private let enrollment: SyncEnrollmentPreparation
    private let activation: SyncVaultActivation
    private(set) var localStatusCount = 0
    private(set) var syncCount = 0
    private(set) var requestedEnrollmentCount = 0
    private(set) var activationCount = 0
    private(set) var approvedReviews = [SyncEnrollmentReview]()

    init(
        available: Bool = true,
        enabled: Bool = true,
        pendingVaultID: String? = nil,
        reviews: [SyncEnrollmentReview] = [],
        enrollment: SyncEnrollmentPreparation = .request(
            SyncEnrollmentRequest(
                deviceID: "fixture-device",
                deviceName: "Fixture Mac",
                requestedAt: "2026-08-14T00:00:00Z",
                fingerprint: "AB12-CD34-EF56",
                documentBase64: "cmVxdWVzdA==")),
        activation: SyncVaultActivation = .ready(
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            keyGeneration: 1,
            restartRequired: false)
    ) {
        self.available = available
        self.enabled = enabled
        pendingID = pendingVaultID
        self.reviews = reviews
        self.enrollment = enrollment
        self.activation = activation
        status = SyncDomainStatus(
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            keyGeneration: 1,
            outboundTransactions: 0,
            inboundTransactions: 0,
            pendingTransactions: 0,
            conflictingEntities: 0,
            projectionPending: false)
    }

    func setStatus(_ status: SyncDomainStatus) { self.status = status }
    func counts() -> Counts {
        Counts(
            localStatus: localStatusCount,
            sync: syncCount,
            requestedEnrollment: requestedEnrollmentCount,
            activation: activationCount,
            approvedReviews: approvedReviews)
    }
    func isAvailable() -> Bool { available }
    func isEnabled() -> Bool { enabled }
    func pendingVaultID() -> String? { pendingID }

    func localStatus() throws -> SyncDomainStatus? {
        localStatusCount += 1
        return status
    }

    func syncNow() -> CloudSyncOutcome {
        syncCount += 1
        if let pendingID { status = statusForVault(pendingID) }
        self.pendingID = nil
        return CloudSyncOutcome(
            status: status,
            appliedRemoteChanges: false,
            authenticatedBootstrap: bootstrap(status.vaultID))
    }

    func authenticateVault(_ vaultID: String) -> SyncVaultBootstrap { bootstrap(vaultID) }

    func reviewEnrollments(in _: SyncVaultBootstrap) -> [SyncEnrollmentReview] { reviews }

    func approveEnrollment(
        _ review: SyncEnrollmentReview,
        in bootstrap: SyncVaultBootstrap
    ) -> SyncVaultBootstrap {
        approvedReviews.append(review)
        return bootstrap
    }

    func requestEnrollment(
        in _: SyncVaultBootstrap,
        deviceName _: String?,
        requestedAt _: String?
    ) -> SyncEnrollmentPreparation {
        requestedEnrollmentCount += 1
        return enrollment
    }

    func activateVault(_ bootstrap: SyncVaultBootstrap) -> SyncVaultActivation {
        activationCount += 1
        return activation
    }

    private func bootstrap(_ vaultID: String) -> SyncVaultBootstrap {
        SyncVaultBootstrap(
            vaultID: vaultID,
            vaultDocumentBase64: "dmF1bHQ=",
            deviceIdentities: [],
            enrollmentRequests: [],
            keyGenerations: [],
            generationEnvelopes: [])
    }

    private func statusForVault(_ vaultID: String) -> SyncDomainStatus {
        SyncDomainStatus(
            vaultID: vaultID,
            keyGeneration: 1,
            outboundTransactions: 0,
            inboundTransactions: 0,
            pendingTransactions: 0,
            conflictingEntities: 0,
            projectionPending: false)
    }
}
