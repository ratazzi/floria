import CloudKit
import CryptoKit
import Foundation

/// Pure planning for one manual CloudKit send cycle.
///
/// Objects are uploaded before any commit that might make them reachable. Commits
/// remain in Rust's durable outbox and are considered one at a time, preserving
/// their local order and atomic head CAS boundary.
struct CloudOutboundPlanner {
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
            return .saveObjects(try missingObjects.map(codec.objectRecord))
        }

        switch try codec.planCommit(commit, cachedHeads: cachedHeads) {
        case .ready(let records):
            return .saveCommit(commitID: commit.commitID, records: records)
        case .needsHeadFetch(let entityIDs):
            return .fetchHeads(
                commitID: commit.commitID,
                recordIDs: entityIDs.map {
                    codec.recordID(prefix: "head", stableID: $0)
                })
        case .conflict(let entityIDs):
            return .settleConflict(commitID: commit.commitID, entityIDs: entityIDs)
        }
    }
}

enum CloudOutboundAction {
    case idle
    case saveObjects([CKRecord])
    case fetchHeads(commitID: String, recordIDs: [CKRecord.ID])
    case settleConflict(commitID: String, entityIDs: [String])
    case saveCommit(commitID: String, records: [CKRecord])
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
        let url = URL(fileURLWithPath: file)
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let fileSize = attributes[.size] as? NSNumber,
              fileSize.uint64Value == size
        else {
            return false
        }

        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        let actual = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return actual == digest
    }
}

enum CloudRecordCollision: Equatable {
    case alreadySaved
    case headConflict(entityID: String)
    case damaged(recordName: String)
}
