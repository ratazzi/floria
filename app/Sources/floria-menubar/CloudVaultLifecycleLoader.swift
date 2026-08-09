import CloudKit
import Foundation

protocol CloudVaultLifecycleQuerying: Sendable {
    func records(
        ofType recordType: String,
        in zoneID: CKRecordZone.ID,
        maximumCount: Int
    ) async throws -> [CKRecord]
}

protocol CloudVaultLifecycleLoading: Sendable {
    func loadAndAuthenticate(vaultID: String) async throws -> SyncVaultBootstrap
}

/// Paged CloudKit query adapter used only after the user explicitly asks to
/// discover or join a Vault. It never starts from app launch or opt-in alone.
struct CloudKitVaultLifecycleQuery: CloudVaultLifecycleQuerying, @unchecked Sendable {
    static let pageSize = 200

    let database: CKDatabase

    func records(
        ofType recordType: String,
        in zoneID: CKRecordZone.ID,
        maximumCount: Int
    ) async throws -> [CKRecord] {
        var records = [CKRecord]()
        var cursor: CKQueryOperation.Cursor?

        repeat {
            let remaining = maximumCount + 1 - records.count
            guard remaining > 0 else {
                throw CloudVaultLifecycleLoaderError.tooManyRecords(
                    recordType: recordType, count: records.count)
            }
            let page: (
                matchResults: [(CKRecord.ID, Result<CKRecord, any Error>)],
                queryCursor: CKQueryOperation.Cursor?
            )
            if let cursor {
                page = try await database.records(
                    continuingMatchFrom: cursor,
                    resultsLimit: min(Self.pageSize, remaining))
            } else {
                page = try await database.records(
                    matching: CKQuery(
                        recordType: recordType,
                        predicate: NSPredicate(value: true)),
                    inZoneWith: zoneID,
                    resultsLimit: min(Self.pageSize, remaining))
            }

            for (recordID, result) in page.matchResults {
                switch result {
                case .success(let record):
                    records.append(record)
                case .failure(let error):
                    throw CloudVaultLifecycleLoaderError.couldNotReadRecord(
                        recordID.recordName,
                        CloudSyncErrorPresentation.message(for: error))
                }
            }
            guard records.count <= maximumCount else {
                throw CloudVaultLifecycleLoaderError.tooManyRecords(
                    recordType: recordType, count: records.count)
            }
            cursor = page.queryCursor
        } while cursor != nil

        return records
    }
}

/// Loads one complete lifecycle candidate and delegates all authentication to Rust.
/// No downloaded bytes become authority and no local Vault is modified here.
struct CloudVaultLifecycleLoader: Sendable {
    private let query: any CloudVaultLifecycleQuerying
    private let control: any VaultBootstrapControlling

    init(
        query: any CloudVaultLifecycleQuerying,
        control: any VaultBootstrapControlling
    ) {
        self.query = query
        self.control = control
    }

    func loadAndAuthenticate(vaultID: String) async throws -> SyncVaultBootstrap {
        let codec = try CloudVaultBootstrapCodec(vaultID: vaultID)
        var records = [CKRecord]()

        for recordType in CloudVaultBootstrapCodec.lifecycleRecordLimits.keys.sorted() {
            guard let maximum = CloudVaultBootstrapCodec.lifecycleRecordLimits[recordType] else {
                throw CloudVaultLifecycleLoaderError.unsupportedRecordType(recordType)
            }
            let fetched = try await query.records(
                ofType: recordType,
                in: codec.recordCodec.zoneID,
                maximumCount: maximum)
            for record in fetched {
                guard record.recordType == recordType else {
                    throw CloudVaultLifecycleLoaderError.unexpectedRecordType(
                        expected: recordType, actual: record.recordType)
                }
                _ = try codec.decode(record)
            }
            records.append(contentsOf: fetched)
        }

        let candidate = try codec.bootstrap(from: records)
        let wireSize = try JSONEncoder().encode(candidate).count
        guard wireSize <= CloudVaultBootstrapCodec.maximumWireBytes else {
            throw CloudVaultLifecycleLoaderError.snapshotTooLarge(wireSize)
        }
        return try await control.validateRecordSyncVaultBootstrap(
            candidate, expectedVaultID: codec.recordCodec.vaultID)
    }
}

extension CloudVaultLifecycleLoader: CloudVaultLifecycleLoading {}

enum CloudVaultLifecycleLoaderError: Error, Equatable, LocalizedError {
    case tooManyRecords(recordType: String, count: Int)
    case couldNotReadRecord(String, String)
    case unsupportedRecordType(String)
    case unexpectedRecordType(expected: String, actual: String)
    case snapshotTooLarge(Int)

    var errorDescription: String? {
        switch self {
        case .tooManyRecords(let type, let count):
            "CloudKit returned too many \(type) records (\(count))"
        case .couldNotReadRecord(let name, let message):
            "Could not read lifecycle record \(name): \(message)"
        case .unsupportedRecordType(let type):
            "Unsupported Vault lifecycle record type: \(type)"
        case .unexpectedRecordType(let expected, let actual):
            "Expected Vault lifecycle record type \(expected), received \(actual)"
        case .snapshotTooLarge(let size):
            "Vault lifecycle snapshot exceeds the control-channel limit (\(size) bytes)"
        }
    }
}
