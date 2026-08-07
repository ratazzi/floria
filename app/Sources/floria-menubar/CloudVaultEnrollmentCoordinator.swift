import CloudKit
import Foundation

enum CloudVaultEnrollmentCreateResult {
    case saved(CKRecord)
    case collision(CKRecord)
}

protocol CloudVaultEnrollmentPublishing: Sendable {
    func create(_ record: CKRecord) async throws -> CloudVaultEnrollmentCreateResult
}

/// The only enrollment-request type that writes to CloudKit. A fresh CKRecord has no change tag,
/// so CKDatabase's unchanged-record policy is a create-only write. An existing deterministic ID
/// is accepted only when its immutable bytes exactly match the request Rust just signed.
struct CloudKitVaultEnrollmentPublisher: CloudVaultEnrollmentPublishing, @unchecked Sendable {
    let database: CKDatabase

    func create(_ record: CKRecord) async throws -> CloudVaultEnrollmentCreateResult {
        let result = try await database.modifyRecords(
            saving: [record], deleting: [],
            savePolicy: .ifServerRecordUnchanged, atomically: true)
        guard let saveResult = result.saveResults[record.recordID] else {
            throw CloudVaultEnrollmentTransportError.missingSaveResult(
                record.recordID.recordName)
        }
        switch saveResult {
        case .success(let saved):
            return .saved(saved)
        case .failure(let error as CKError) where error.code == .serverRecordChanged:
            guard let serverRecord = error.serverRecord else {
                throw CloudVaultEnrollmentTransportError.missingServerRecord(
                    record.recordID.recordName)
            }
            return .collision(serverRecord)
        case .failure(let error):
            throw error
        }
    }
}

/// Owns the join lifecycle without giving Swift authority over signed documents. Rust prepares,
/// reviews, and approves; this coordinator only routes one self-signed request to its Vault zone
/// and enforces create-only collision semantics.
struct CloudVaultEnrollmentCoordinator: Sendable {
    private let control: any VaultEnrollmentControlling
    private let publisher: any CloudVaultEnrollmentPublishing

    init(
        control: any VaultEnrollmentControlling,
        publisher: any CloudVaultEnrollmentPublishing
    ) {
        self.control = control
        self.publisher = publisher
    }

    @discardableResult
    func requestEnrollment(
        in bootstrap: SyncVaultBootstrap,
        deviceName: String?,
        requestedAt: String
    ) async throws -> SyncEnrollmentPreparation {
        let preparation = try await control.prepareRecordSyncVaultEnrollment(
            bootstrap: bootstrap, deviceName: deviceName, requestedAt: requestedAt)
        guard case .request(let request) = preparation else { return preparation }

        let codec = try CloudVaultBootstrapCodec(vaultID: bootstrap.vaultID)
        let requestedRecord = try codec.enrollmentRecord(for: request)
        let remoteRecord: CKRecord
        switch try await publisher.create(requestedRecord) {
        case .saved(let saved), .collision(let saved):
            remoteRecord = saved
        }
        guard try codec.equivalent(requestedRecord, remoteRecord) else {
            throw CloudVaultEnrollmentCoordinatorError.immutableRequestChanged(
                requestedRecord.recordID.recordName)
        }
        return preparation
    }

    func reviews(
        in bootstrap: SyncVaultBootstrap
    ) async throws -> [SyncEnrollmentReview] {
        try await control.reviewRecordSyncVaultEnrollments(bootstrap: bootstrap)
    }

    func approve(
        _ review: SyncEnrollmentReview,
        in bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultBootstrap {
        try await control.approveRecordSyncVaultEnrollment(
            bootstrap: bootstrap,
            deviceID: review.deviceID,
            expectedFingerprint: review.fingerprint)
    }
}

enum CloudVaultEnrollmentTransportError: Error, Equatable, LocalizedError {
    case missingSaveResult(String)
    case missingServerRecord(String)

    var errorDescription: String? {
        switch self {
        case .missingSaveResult(let recordName):
            "CloudKit omitted the enrollment save result for \(recordName)"
        case .missingServerRecord(let recordName):
            "CloudKit did not return the existing enrollment request \(recordName)"
        }
    }
}

enum CloudVaultEnrollmentCoordinatorError: Error, Equatable, LocalizedError {
    case immutableRequestChanged(String)

    var errorDescription: String? {
        switch self {
        case .immutableRequestChanged(let recordName):
            "CloudKit enrollment request \(recordName) does not match this Mac"
        }
    }
}
