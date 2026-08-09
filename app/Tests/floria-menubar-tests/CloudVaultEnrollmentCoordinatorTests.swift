import CloudKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudVaultEnrollmentCoordinatorTests: XCTestCase {
    func testPublishesRustPreparedRequestWithCreateOnlyIdentity() async throws {
        let bootstrap = fixtureBootstrap()
        let preparation = fixturePreparation()
        let control = VaultEnrollmentControlStub(preparation: preparation)
        let publisher = VaultEnrollmentPublisherStub(mode: .saved)
        let coordinator = CloudVaultEnrollmentCoordinator(
            control: control, publisher: publisher)

        let result = try await coordinator.requestEnrollment(
            in: bootstrap, deviceName: "Studio", requestedAt: "2026-08-08T12:00:00Z")

        XCTAssertEqual(result, preparation)
        let createdRecord = await publisher.createdRecord
        let record = try XCTUnwrap(createdRecord)
        XCTAssertEqual(record.recordType, CloudVaultBootstrapCodec.RecordType.enrollmentRequest)
        XCTAssertEqual(
            record.recordID.zoneID,
            try CloudRecordCodec(vaultID: bootstrap.vaultID).zoneID)
        XCTAssertEqual(record[CloudVaultBootstrapCodec.Field.deviceID] as? String, deviceID)
        let preparationCalls = await control.preparationCalls
        XCTAssertEqual(preparationCalls, 1)
    }

    func testExactImmutableCollisionIsIdempotentButChangedBytesFailClosed() async throws {
        let bootstrap = fixtureBootstrap()
        let preparation = fixturePreparation()
        let exactControl = VaultEnrollmentControlStub(preparation: preparation)
        let exactPublisher = VaultEnrollmentPublisherStub(mode: .collisionExact)
        _ = try await CloudVaultEnrollmentCoordinator(
            control: exactControl, publisher: exactPublisher
        ).requestEnrollment(in: bootstrap, deviceName: nil, requestedAt: "now")

        let changedControl = VaultEnrollmentControlStub(preparation: preparation)
        let changedPublisher = VaultEnrollmentPublisherStub(mode: .collisionChanged)
        do {
            _ = try await CloudVaultEnrollmentCoordinator(
                control: changedControl, publisher: changedPublisher
            ).requestEnrollment(in: bootstrap, deviceName: nil, requestedAt: "now")
            XCTFail("Expected a changed deterministic request to fail")
        } catch let error as CloudVaultEnrollmentCoordinatorError {
            guard case .immutableRequestChanged = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testAlreadyEnrolledDoesNotTouchCloudKit() async throws {
        let bootstrap = fixtureBootstrap()
        let control = VaultEnrollmentControlStub(
            preparation: .alreadyEnrolled(deviceID: deviceID))
        let publisher = VaultEnrollmentPublisherStub(mode: .saved)

        let result = try await CloudVaultEnrollmentCoordinator(
            control: control, publisher: publisher
        ).requestEnrollment(in: bootstrap, deviceName: nil, requestedAt: "now")

        XCTAssertEqual(result, .alreadyEnrolled(deviceID: deviceID))
        let createdRecord = await publisher.createdRecord
        XCTAssertNil(createdRecord)
    }

    func testReenrollmentPreservesReviewedFingerprintAndPublishesTheFreshRequest() async throws {
        let bootstrap = fixtureBootstrap()
        let preparation = fixturePreparation()
        let control = VaultEnrollmentControlStub(preparation: preparation)
        let publisher = VaultEnrollmentPublisherStub(mode: .saved)

        let result = try await CloudVaultEnrollmentCoordinator(
            control: control, publisher: publisher
        ).requestReenrollment(
            in: bootstrap,
            expectedFingerprint: "AB12-CD34-EF56",
            deviceName: "Studio",
            requestedAt: "2026-08-09T12:00:00Z")

        XCTAssertEqual(result, preparation)
        let reenrollmentFingerprint = await control.reenrollmentFingerprint
        let createdRecord = await publisher.createdRecord
        XCTAssertEqual(reenrollmentFingerprint, "AB12-CD34-EF56")
        XCTAssertNotNil(createdRecord)
    }

    func testReviewApprovalPreservesExactFingerprint() async throws {
        let bootstrap = fixtureBootstrap()
        let review = SyncEnrollmentReview(
            deviceID: deviceID, deviceName: "Studio", requestedAt: "now",
            fingerprint: "sha256:fixture")
        let control = VaultEnrollmentControlStub(
            preparation: fixturePreparation(), reviews: [review])
        let coordinator = CloudVaultEnrollmentCoordinator(
            control: control, publisher: VaultEnrollmentPublisherStub(mode: .saved))

        let reviews = try await coordinator.reviews(in: bootstrap)
        let approved = try await coordinator.approve(review, in: bootstrap)
        let approvedFingerprint = await control.approvedFingerprint
        XCTAssertEqual(reviews, [review])
        XCTAssertEqual(approved, bootstrap)
        XCTAssertEqual(approvedFingerprint, review.fingerprint)
    }

    private let deviceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

    private func fixtureBootstrap() -> SyncVaultBootstrap {
        SyncVaultBootstrap(
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            vaultDocumentBase64: Data("vault".utf8).base64EncodedString(),
            deviceIdentities: [], enrollmentRequests: [], keyGenerations: [],
            generationEnvelopes: [])
    }

    private func fixturePreparation() -> SyncEnrollmentPreparation {
        .request(
            SyncEnrollmentRequest(
                deviceID: deviceID, deviceName: "Studio", requestedAt: "now",
                fingerprint: "sha256:fixture",
                documentBase64: Data("request".utf8).base64EncodedString()))
    }
}

private actor VaultEnrollmentControlStub: VaultEnrollmentControlling {
    let preparation: SyncEnrollmentPreparation
    let pendingReviews: [SyncEnrollmentReview]
    private(set) var preparationCalls = 0
    private(set) var approvedFingerprint: String?
    private(set) var reenrollmentFingerprint: String?

    init(
        preparation: SyncEnrollmentPreparation,
        reviews: [SyncEnrollmentReview] = []
    ) {
        self.preparation = preparation
        pendingReviews = reviews
    }

    func prepareRecordSyncVaultEnrollment(
        bootstrap _: SyncVaultBootstrap,
        deviceName _: String?,
        requestedAt _: String
    ) async throws -> SyncEnrollmentPreparation {
        preparationCalls += 1
        return preparation
    }

    func prepareRecordSyncVaultReenrollment(
        bootstrap _: SyncVaultBootstrap,
        expectedFingerprint: String,
        deviceName _: String?,
        requestedAt _: String
    ) async throws -> SyncEnrollmentPreparation {
        reenrollmentFingerprint = expectedFingerprint
        return preparation
    }

    func reviewRecordSyncVaultEnrollments(
        bootstrap _: SyncVaultBootstrap
    ) async throws -> [SyncEnrollmentReview] {
        pendingReviews
    }

    func approveRecordSyncVaultEnrollment(
        bootstrap: SyncVaultBootstrap,
        deviceID _: String,
        expectedFingerprint: String
    ) async throws -> SyncVaultBootstrap {
        approvedFingerprint = expectedFingerprint
        return bootstrap
    }
}

private actor VaultEnrollmentPublisherStub: CloudVaultEnrollmentPublishing {
    enum Mode { case saved, collisionExact, collisionChanged }

    let mode: Mode
    private(set) var createdRecord: CKRecord?

    init(mode: Mode) {
        self.mode = mode
    }

    func create(_ record: CKRecord) async throws -> CloudVaultEnrollmentCreateResult {
        createdRecord = record
        guard let copy = record.copy() as? CKRecord else {
            throw CocoaError(.coderInvalidValue)
        }
        switch mode {
        case .saved:
            return .saved(copy)
        case .collisionExact:
            return .collision(copy)
        case .collisionChanged:
            copy[CloudVaultBootstrapCodec.Field.payload] = Data("changed".utf8) as NSData
            return .collision(copy)
        }
    }
}
