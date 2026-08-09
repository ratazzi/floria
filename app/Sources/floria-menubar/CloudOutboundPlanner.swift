import CloudKit
import Foundation

/// Pure planning for one manual CloudKit send cycle.
///
/// Objects are uploaded before any commit that might make them reachable. Commits
/// remain in Rust's durable outbox and are considered one at a time, preserving
/// their local order and atomic head CAS boundary.
struct CloudOutboundPlanner {
    static let cloudKitRecordLimit = 250

    let codec: CloudRecordCodec

    func nextAction(
        batch: SyncOutboundBatch,
        verifiedObjectDigests: Set<String>,
        cachedHeads: [String: CKRecord]
    ) throws -> CloudOutboundAction {
        guard let commit = batch.commits.first else { return .idle }

        let missingObjects = batch.objects.filter {
            !verifiedObjectDigests.contains($0.digest)
        }
        if !missingObjects.isEmpty {
            return .saveObjects(
                try missingObjects.prefix(Self.cloudKitRecordLimit).map(codec.objectRecord))
        }

        switch try codec.planCommit(commit, cachedHeads: cachedHeads) {
        case .ready(let records):
            guard records.count <= Self.cloudKitRecordLimit else {
                throw CloudOutboundPlanningError.commitExceedsCloudKitRecordLimit(
                    commitID: commit.commitID,
                    records: records.count)
            }
            return .saveCommit(commitID: commit.commitID, records: records)
        case .needsHeadFetch(let entityIDs):
            return .fetchHeads(
                commitID: commit.commitID,
                recordIDs: entityIDs.map {
                    codec.recordID(prefix: "head", stableID: $0)
                })
        case .conflict(let entityIDs):
            return .saveConflictBranch(
                commitID: commit.commitID,
                entityIDs: entityIDs,
                records: try codec.immutableRecords(for: commit))
        }
    }
}

enum CloudOutboundAction {
    case idle
    case saveObjects([CKRecord])
    case fetchHeads(commitID: String, recordIDs: [CKRecord.ID])
    case saveConflictBranch(commitID: String, entityIDs: [String], records: [CKRecord])
    case saveCommit(commitID: String, records: [CKRecord])
}

enum CloudOutboundPlanningError: Error, Equatable {
    case commitExceedsCloudKitRecordLimit(commitID: String, records: Int)
}

/// Interprets `serverRecordChanged` without turning every create-only retry into
/// a domain conflict. Immutable records may already exist after an ambiguous
/// prior save; they are accepted only when the exact authenticated payload (and,
/// for assets, exact ciphertext bytes) matches. A changed mutable head is the
/// only ordinary CAS conflict.
struct CloudRecordCollisionResolver {
    let codec: CloudRecordCodec

    func classify(client: CKRecord, server: CKRecord) throws -> CloudRecordCollision {
        guard client.recordID == server.recordID,
              client.recordType == server.recordType
        else {
            return .damaged(recordName: server.recordID.recordName)
        }

        let clientDecoded = try codec.decode(client)
        let serverDecoded = try codec.decode(server)
        switch (clientDecoded, serverDecoded) {
        case (.manifest(let clientValue), .manifest(let serverValue)):
            return clientValue == serverValue
                ? .alreadySaved
                : .damaged(recordName: server.recordID.recordName)

        case (.revision(let clientValue), .revision(let serverValue)):
            return clientValue == serverValue
                ? .alreadySaved
                : .damaged(recordName: server.recordID.recordName)

        case (.object(let clientValue), .object(let serverValue)):
            guard clientValue.digest == serverValue.digest,
                  clientValue.ciphertextSize == serverValue.ciphertextSize,
                  try assetMatches(
                      file: serverValue.file,
                      size: serverValue.ciphertextSize,
                      digest: serverValue.digest)
            else {
                return .damaged(recordName: server.recordID.recordName)
            }
            return .alreadySaved

        case (
            .head(let clientEntityID, let clientRecord),
            .head(let serverEntityID, let serverRecord)
        ):
            guard clientEntityID == serverEntityID,
                  let clientRevision = clientRecord[CloudRecordCodec.Field.revisionID] as? String,
                  let serverRevision = serverRecord[CloudRecordCodec.Field.revisionID] as? String
            else {
                return .damaged(recordName: server.recordID.recordName)
            }
            return clientRevision == serverRevision
                ? .alreadySaved
                : .headConflict(entityID: serverEntityID)

        default:
            return .damaged(recordName: server.recordID.recordName)
        }
    }

    private func assetMatches(file: String, size: UInt64, digest: String) throws -> Bool {
        try CloudAssetFile.matches(
            URL(fileURLWithPath: file),
            expectedSize: size,
            expectedDigest: digest)
    }
}

enum CloudRecordCollision: Equatable {
    case alreadySaved
    case headConflict(entityID: String)
    case damaged(recordName: String)
}
