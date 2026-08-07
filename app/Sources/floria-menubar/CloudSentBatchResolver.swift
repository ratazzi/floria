import CloudKit
import Foundation

struct CloudSentBatchResolver {
    let codec: CloudRecordCodec

    func resolve(
        phase: CloudSendPhase,
        savedRecords: [CKRecord],
        failures: [CloudRecordSaveFailure]
    ) throws -> CloudSentBatchResolution {
        let expectedRecords = phase.records
        guard Set(expectedRecords.map(\.recordID)).count == expectedRecords.count,
              Set(savedRecords.map(\.recordID)).count == savedRecords.count,
              Set(failures.map { $0.record.recordID }).count == failures.count
        else {
            return .damaged("CloudKit send results contain duplicate record identifiers")
        }
        let expected = Dictionary(uniqueKeysWithValues: expectedRecords.map { ($0.recordID, $0) })
        let saved = Dictionary(uniqueKeysWithValues: savedRecords.map { ($0.recordID, $0) })
        let failed = Dictionary(uniqueKeysWithValues: failures.map { ($0.record.recordID, $0) })
        let reportedIDs = Set(saved.keys).union(failed.keys)
        let expectedIDs = Set(expected.keys)

        guard reportedIDs.isSubset(of: expectedIDs) else {
            return .damaged("CloudKit reported records outside the active send batch")
        }
        guard reportedIDs == expectedIDs else {
            return .retry
        }

        var acceptedHeads = [String: CKRecord]()
        var hasRetry = false
        var conflictingEntities = Set<String>()

        for (recordID, client) in expected {
            if let server = saved[recordID] {
                if case .head(let entityID, let record) = try codec.decode(server) {
                    acceptedHeads[entityID] = record
                }
                continue
            }
            guard let failure = failed[recordID] else {
                hasRetry = true
                continue
            }

            switch failure.code {
            case .serverRecordChanged:
                guard let server = failure.serverRecord else {
                    return .damaged(
                        "CloudKit omitted the server record for \(recordID.recordName)")
                }
                switch try CloudRecordCollisionResolver(codec: codec).classify(
                    client: client, server: server)
                {
                case .alreadySaved:
                    if case .head(let entityID, let record) = try codec.decode(server) {
                        acceptedHeads[entityID] = record
                    }
                case .headConflict(let entityID):
                    conflictingEntities.insert(entityID)
                case .damaged(let recordName):
                    return .damaged("CloudKit record \(recordName) changed unexpectedly")
                }

            case .networkFailure, .networkUnavailable, .serviceUnavailable,
                .requestRateLimited, .zoneBusy, .operationCancelled, .notAuthenticated,
                .zoneNotFound:
                hasRetry = true

            default:
                return .damaged(
                    "CloudKit could not save \(recordID.recordName): \(failure.code.rawValue)")
            }
        }

        if !conflictingEntities.isEmpty {
            guard case .commit(let commitID, _) = phase else {
                return .damaged("An immutable object was reported as a mutable head conflict")
            }
            return .commitConflict(
                commitID: commitID,
                entityIDs: conflictingEntities.sorted())
        }
        if hasRetry { return .retry }

        switch phase {
        case .objects(let records):
            return .objectsVerified(records)
        case .commit(let commitID, _):
            return .commitAccepted(commitID: commitID, heads: acceptedHeads)
        }
    }
}

enum CloudSendPhase {
    case objects([CKRecord])
    case commit(commitID: String, records: [CKRecord])

    var records: [CKRecord] {
        switch self {
        case .objects(let records), .commit(_, let records):
            records
        }
    }

    var atomicByZone: Bool {
        if case .commit = self { return true }
        return false
    }
}

struct CloudRecordSaveFailure {
    let record: CKRecord
    let code: CKError.Code
    let serverRecord: CKRecord?
}

enum CloudSentBatchResolution {
    case objectsVerified([CKRecord])
    case commitAccepted(commitID: String, heads: [String: CKRecord])
    case commitConflict(commitID: String, entityIDs: [String])
    case retry
    case damaged(String)
}
