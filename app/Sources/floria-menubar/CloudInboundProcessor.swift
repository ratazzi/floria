import CloudKit
import Foundation

/// Converts one fetched CloudKit event into an opaque Rust batch while keeping
/// transport-only heads in Swift. No project or secret semantics cross this
/// boundary.
struct CloudInboundProcessor {
    let codec: CloudRecordCodec
    let assetStager: CloudAssetStager

    func prepare(
        records: [CKRecord],
        deletedRecordIDs: [CKRecord.ID]
    ) throws -> CloudInboundPreparation {
        guard deletedRecordIDs.isEmpty else {
            throw CloudInboundProcessingError.remoteRecordsDeleted(
                deletedRecordIDs.map(\.recordName).sorted())
        }

        var seen = Set<CKRecord.ID>()
        var manifests = [SyncInboundManifest]()
        var revisions = [SyncInboundRevision]()
        var objects = [SyncInboundObject]()
        var heads = [String: CKRecord]()

        for record in records {
            guard seen.insert(record.recordID).inserted else {
                throw CloudInboundProcessingError.duplicateRecord(
                    record.recordID.recordName)
            }
            switch try codec.decode(record) {
            case .manifest(let manifest):
                manifests.append(manifest)
            case .revision(let revision):
                revisions.append(revision)
            case .object(let object):
                objects.append(try assetStager.stage(object))
            case .head(let entityID, let head):
                heads[entityID] = head
            }
        }

        manifests.sort { $0.commitID < $1.commitID }
        revisions.sort { $0.revisionID < $1.revisionID }
        objects.sort { $0.digest < $1.digest }
        return CloudInboundPreparation(
            batch: SyncInboundBatch(
                manifests: manifests,
                revisions: revisions,
                objects: objects),
            heads: heads,
            stagedObjects: objects)
    }

    /// Call only after Rust has durably accepted the corresponding inbound
    /// batch. A crash before cleanup is harmless because staging is verified and
    /// content-addressed; the next fetch reuses the same bytes.
    func removeStagedAssets(after preparation: CloudInboundPreparation) throws {
        for object in preparation.stagedObjects {
            try assetStager.remove(object)
        }
    }
}

struct CloudInboundPreparation {
    let batch: SyncInboundBatch
    let heads: [String: CKRecord]
    let stagedObjects: [SyncInboundObject]

    var hasDomainRecords: Bool {
        !batch.manifests.isEmpty || !batch.revisions.isEmpty || !batch.objects.isEmpty
    }
}

enum CloudInboundProcessingError: Error, Equatable {
    case duplicateRecord(String)
    case remoteRecordsDeleted([String])
}
