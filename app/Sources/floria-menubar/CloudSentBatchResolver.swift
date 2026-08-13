import CloudKit
import Foundation

struct CloudSentBatchResolver {
    let codec: CloudRecordCodec
    let bootstrapCodec: CloudVaultBootstrapCodec?

    init(codec: CloudRecordCodec, bootstrapCodec: CloudVaultBootstrapCodec? = nil) {
        self.codec = codec
        self.bootstrapCodec = bootstrapCodec
    }

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
        var objectCollisionsNeedingFetch = Set<CKRecord.ID>()
        var conflictingEntities = try atomicCommitHeadConflicts(
            phase: phase, failures: failures)

        for (recordID, client) in expected {
            if let server = saved[recordID] {
                if case .bootstrap = phase {
                    guard try bootstrapMatches(client: client, server: server) else {
                        return .damaged(
                            "CloudKit lifecycle record \(recordID.recordName) changed unexpectedly")
                    }
                }
                if server.recordType == CloudRecordCodec.RecordType.head,
                   case .head(let entityID, let record) = try codec.decode(server)
                {
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
                if case .bootstrap = phase {
                    guard try bootstrapMatches(client: client, server: server) else {
                        return .damaged(
                            "CloudKit lifecycle record \(recordID.recordName) changed unexpectedly")
                    }
                    continue
                }
                if objectCollisionNeedsFetch(client: client, server: server) {
                    objectCollisionsNeedingFetch.insert(recordID)
                    continue
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

            case .batchRequestFailed
                where !conflictingEntities.isEmpty
                    && client.recordType != CloudRecordCodec.RecordType.head:
                // CloudKit rolls back the immutable siblings of a failed atomic head CAS. The
                // next phase publishes those siblings without the head before Rust settles it.
                continue

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
        if !objectCollisionsNeedingFetch.isEmpty {
            return .fetchObjectCollisions(
                objectCollisionsNeedingFetch.sorted {
                    $0.recordName < $1.recordName
                })
        }
        if hasRetry { return .retry }

        switch phase {
        case .bootstrap:
            return .bootstrapAccepted
        case .objects(let records):
            return .objectsVerified(records)
        case .commit(let commitID, _):
            return .commitAccepted(commitID: commitID, heads: acceptedHeads)
        case .conflictBranch(let commitID, _):
            return .conflictBranchAccepted(commitID: commitID)
        }
    }

    private func atomicCommitHeadConflicts(
        phase: CloudSendPhase,
        failures: [CloudRecordSaveFailure]
    ) throws -> Set<String> {
        guard case .commit = phase else { return [] }
        var entityIDs = Set<String>()
        for failure in failures where failure.code == .serverRecordChanged {
            guard failure.record.recordType == CloudRecordCodec.RecordType.head,
                  let server = failure.serverRecord
            else { continue }
            if case .headConflict(let entityID) = try CloudRecordCollisionResolver(codec: codec)
                .classify(client: failure.record, server: server)
            {
                entityIDs.insert(entityID)
            }
        }
        return entityIDs
    }

    private func bootstrapMatches(client: CKRecord, server: CKRecord) throws -> Bool {
        guard let bootstrapCodec,
              bootstrapCodec.owns(client),
              bootstrapCodec.owns(server)
        else { return false }
        return try bootstrapCodec.equivalent(client, server)
    }

    /// `CKError.serverRecordChanged` may carry an object record without a local URL for its
    /// `CKAsset`. That conflict envelope is not evidence that ciphertext is missing in iCloud;
    /// an explicit fetch is required before exact-byte collision verification can run.
    private func objectCollisionNeedsFetch(client: CKRecord, server: CKRecord) -> Bool {
        guard client.recordID == server.recordID,
              client.recordType == CloudRecordCodec.RecordType.object,
              server.recordType == CloudRecordCodec.RecordType.object
        else { return false }
        guard let asset = server[CloudRecordCodec.Field.ciphertext] as? CKAsset else {
            return true
        }
        return asset.fileURL == nil
    }
}

enum CloudSendPhase {
    case bootstrap([CKRecord])
    case objects([CKRecord])
    case commit(commitID: String, records: [CKRecord])
    case conflictBranch(commitID: String, records: [CKRecord])

    var records: [CKRecord] {
        switch self {
        case .bootstrap(let records), .objects(let records), .commit(_, let records),
            .conflictBranch(_, let records):
            records
        }
    }

    var atomicByZone: Bool {
        switch self {
        case .bootstrap, .commit:
            return true
        case .objects, .conflictBranch:
            return false
        }
    }
}

struct CloudRecordSaveFailure {
    let record: CKRecord
    let code: CKError.Code
    let serverRecord: CKRecord?
}

enum CloudSentBatchResolution {
    case bootstrapAccepted
    case objectsVerified([CKRecord])
    case commitAccepted(commitID: String, heads: [String: CKRecord])
    case conflictBranchAccepted(commitID: String)
    case commitConflict(commitID: String, entityIDs: [String])
    case fetchObjectCollisions([CKRecord.ID])
    case retry
    case damaged(String)
}
