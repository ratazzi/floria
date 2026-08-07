import CloudKit
import CryptoKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudOutboundPlannerTests: XCTestCase {
    private let entityID = "11111111-1111-4111-8111-111111111111"
    private let oldRevisionID = "22222222-2222-4222-8222-222222222222"
    private let newRevisionID = "33333333-3333-4333-8333-333333333333"
    private let commitID = "44444444-4444-4444-8444-444444444444"
    private var codec: CloudRecordCodec {
        try! CloudRecordCodec(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    }

    func testUploadsObjectsBeforePlanningOneAtomicCommit() throws {
        let object = try objectFixture()
        defer { try? FileManager.default.removeItem(atPath: object.file) }
        let batch = SyncOutboundBatch(
            commits: [commit(expectedHead: nil)],
            objects: [object])
        let planner = CloudOutboundPlanner(codec: codec)

        guard case .saveObjects(let records) = try planner.nextAction(
            batch: batch, verifiedObjectDigests: [], cachedHeads: [:])
        else {
            return XCTFail("Expected encrypted objects first")
        }
        XCTAssertEqual(records.map(\.recordType), [CloudRecordCodec.RecordType.object])

        guard case .saveCommit(let plannedCommitID, let commitRecords) =
            try planner.nextAction(
                batch: batch,
                verifiedObjectDigests: [object.digest],
                cachedHeads: [:])
        else {
            return XCTFail("Expected one atomic commit")
        }
        XCTAssertEqual(plannedCommitID, commitID)
        XCTAssertEqual(commitRecords.map(\.recordType), [
            CloudRecordCodec.RecordType.commit,
            CloudRecordCodec.RecordType.revision,
            CloudRecordCodec.RecordType.head,
        ])
    }

    func testMissingAndChangedHeadsNeverBecomeBlindCreates() throws {
        let batch = SyncOutboundBatch(
            commits: [commit(expectedHead: oldRevisionID)],
            objects: [])
        let planner = CloudOutboundPlanner(codec: codec)

        guard case .fetchHeads(let fetchCommitID, let recordIDs) =
            try planner.nextAction(
                batch: batch,
                verifiedObjectDigests: [],
                cachedHeads: [:])
        else {
            return XCTFail("Expected an explicit head fetch")
        }
        XCTAssertEqual(fetchCommitID, commitID)
        XCTAssertEqual(recordIDs, [codec.recordID(prefix: "head", stableID: entityID)])

        let changed = headRecord(
            revisionID: "55555555-5555-4555-8555-555555555555")
        guard case .settleConflict(let conflictCommitID, let entities) =
            try planner.nextAction(
                batch: batch,
                verifiedObjectDigests: [],
                cachedHeads: [entityID: changed])
        else {
            return XCTFail("Expected a CAS conflict")
        }
        XCTAssertEqual(conflictCommitID, commitID)
        XCTAssertEqual(entities, [entityID])
    }

    func testImmutableRetryIsAcceptedOnlyWhenExactRemoteBytesMatch() throws {
        let object = try objectFixture()
        defer { try? FileManager.default.removeItem(atPath: object.file) }
        let resolver = CloudRecordCollisionResolver(codec: codec)

        let clientObject = try codec.objectRecord(object)
        let serverObject = try codec.objectRecord(object)
        XCTAssertEqual(
            try resolver.classify(client: clientObject, server: serverObject),
            .alreadySaved)

        let clientCommit = try codec.immutableRecords(for: commit(expectedHead: nil))[0]
        let identicalCommit = try codec.immutableRecords(for: commit(expectedHead: nil))[0]
        XCTAssertEqual(
            try resolver.classify(client: clientCommit, server: identicalCommit),
            .alreadySaved)

        identicalCommit[CloudRecordCodec.Field.manifest] = Data("different".utf8) as NSData
        XCTAssertEqual(
            try resolver.classify(client: clientCommit, server: identicalCommit),
            .damaged(recordName: identicalCommit.recordID.recordName))
    }

    func testOnlyAChangedMutableHeadBecomesDomainConflict() throws {
        let resolver = CloudRecordCollisionResolver(codec: codec)
        let desired = headRecord(revisionID: newRevisionID)

        XCTAssertEqual(
            try resolver.classify(
                client: desired,
                server: headRecord(revisionID: newRevisionID)),
            .alreadySaved)
        XCTAssertEqual(
            try resolver.classify(
                client: desired,
                server: headRecord(revisionID: oldRevisionID)),
            .headConflict(entityID: entityID))
    }

    private func commit(expectedHead: String?) -> SyncOutboundCommit {
        SyncOutboundCommit(
            commitID: commitID,
            manifestBase64: Data("manifest".utf8).base64EncodedString(),
            revisions: [
                SyncOutboundRevision(
                    entityID: entityID,
                    revisionID: newRevisionID,
                    expectedHeadRevisionID: expectedHead,
                    envelopeBase64: Data("revision".utf8).base64EncodedString())
            ],
            createdAt: "2026-08-07T12:00:00Z")
    }

    private func objectFixture() throws -> SyncObjectAsset {
        let bytes = Data("encrypted object bytes".utf8)
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(
            "floria-cloud-object-\(UUID().uuidString).age")
        try bytes.write(to: file)
        return SyncObjectAsset(
            digest: digest,
            ciphertextSize: UInt64(bytes.count),
            file: file.path)
    }

    private func headRecord(revisionID: String) -> CKRecord {
        let record = CKRecord(
            recordType: CloudRecordCodec.RecordType.head,
            recordID: codec.recordID(prefix: "head", stableID: entityID))
        record[CloudRecordCodec.Field.schemaVersion] = NSNumber(
            value: CloudRecordCodec.schemaVersion)
        record[CloudRecordCodec.Field.entityID] = entityID as NSString
        record[CloudRecordCodec.Field.revisionID] = revisionID as NSString
        return record
    }
}
