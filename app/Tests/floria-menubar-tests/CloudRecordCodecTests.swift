import CloudKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudRecordCodecTests: XCTestCase {
    private let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private let entityID = "11111111-1111-4111-8111-111111111111"
    private let oldRevisionID = "22222222-2222-4222-8222-222222222222"
    private let newRevisionID = "33333333-3333-4333-8333-333333333333"
    private let commitID = "44444444-4444-4444-8444-444444444444"
    private var codec: CloudRecordCodec { try! CloudRecordCodec(vaultID: vaultID) }

    func testMapsOpaqueOutboundPayloadsWithoutPlaintextFields() throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("floria-cloud-record-codec-\(UUID().uuidString).age")
        try Data("ciphertext".utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }

        let digest = String(repeating: "a", count: 64)
        let object = try codec.objectRecord(
            SyncObjectAsset(digest: digest, ciphertextSize: 10, file: file.path))
        XCTAssertEqual(object.recordType, CloudRecordCodec.RecordType.object)
        XCTAssertEqual(object.recordID.zoneID, codec.zoneID)
        XCTAssertEqual(object[CloudRecordCodec.Field.digest] as? String, digest)
        XCTAssertEqual(
            object[CloudRecordCodec.Field.ciphertextSize] as? NSNumber,
            NSNumber(value: 10))
        XCTAssertEqual(
            (object[CloudRecordCodec.Field.ciphertext] as? CKAsset)?.fileURL,
            file)

        let records = try codec.immutableRecords(for: outboundCommit())
        XCTAssertEqual(records.map(\.recordType), [
            CloudRecordCodec.RecordType.commit,
            CloudRecordCodec.RecordType.revision,
        ])
        XCTAssertEqual(
            records[0][CloudRecordCodec.Field.manifest] as? Data,
            Data("manifest".utf8))
        XCTAssertEqual(
            records[1][CloudRecordCodec.Field.envelope] as? Data,
            Data("revision".utf8))
        XCTAssertFalse(records.flatMap { $0.allKeys() }.contains("plaintext"))
    }

    func testPlansCreateAndChangeTagPreservingHeadUpdate() throws {
        let create = try codec.planCommit(
            outboundCommit(expectedHead: nil), cachedHeads: [:])
        let createRecords = try readyRecords(create)
        let createdHead = try XCTUnwrap(
            createRecords.first { $0.recordType == CloudRecordCodec.RecordType.head })
        XCTAssertEqual(
            createdHead[CloudRecordCodec.Field.revisionID] as? String,
            newRevisionID)

        let cachedHead = headRecord(revisionID: oldRevisionID)
        let update = try codec.planCommit(
            outboundCommit(expectedHead: oldRevisionID),
            cachedHeads: [entityID: cachedHead])
        let updateRecords = try readyRecords(update)
        let updatedHead = try XCTUnwrap(
            updateRecords.first { $0.recordType == CloudRecordCodec.RecordType.head })
        XCTAssertFalse(updatedHead === cachedHead)
        XCTAssertEqual(updatedHead.recordID, cachedHead.recordID)
        XCTAssertEqual(
            updatedHead[CloudRecordCodec.Field.revisionID] as? String,
            newRevisionID)
        XCTAssertEqual(
            cachedHead[CloudRecordCodec.Field.revisionID] as? String,
            oldRevisionID)
    }

    func testDoesNotGuessWhenHeadMustBeFetchedOrHasChanged() throws {
        let missing = try codec.planCommit(
            outboundCommit(expectedHead: oldRevisionID), cachedHeads: [:])
        guard case .needsHeadFetch(let missingIDs) = missing else {
            return XCTFail("Expected a head fetch")
        }
        XCTAssertEqual(missingIDs, [entityID])

        let changedHead = headRecord(
            revisionID: "55555555-5555-4555-8555-555555555555")
        let changed = try codec.planCommit(
            outboundCommit(expectedHead: oldRevisionID),
            cachedHeads: [entityID: changedHead])
        guard case .conflict(let conflictIDs) = changed else {
            return XCTFail("Expected a head conflict")
        }
        XCTAssertEqual(conflictIDs, [entityID])

        let unexpectedExisting = try codec.planCommit(
            outboundCommit(expectedHead: nil),
            cachedHeads: [entityID: changedHead])
        guard case .conflict(let existingIDs) = unexpectedExisting else {
            return XCTFail("Expected create conflict")
        }
        XCTAssertEqual(existingIDs, [entityID])
    }

    func testDecodesFetchedRecordsBackToOpaqueInboundPayloads() throws {
        let records = try codec.immutableRecords(for: outboundCommit())

        guard case .manifest(let manifest) = try codec.decode(records[0]) else {
            return XCTFail("Expected manifest")
        }
        XCTAssertEqual(manifest.commitID, commitID)
        XCTAssertEqual(manifest.manifestBase64, Data("manifest".utf8).base64EncodedString())

        guard case .revision(let revision) = try codec.decode(records[1]) else {
            return XCTFail("Expected revision")
        }
        XCTAssertEqual(revision.entityID, entityID)
        XCTAssertEqual(revision.revisionID, newRevisionID)
        XCTAssertEqual(revision.envelopeBase64, Data("revision".utf8).base64EncodedString())

        let head = headRecord(revisionID: newRevisionID)
        guard case .head(let decodedEntityID, let decodedHead) =
            try codec.decode(head)
        else {
            return XCTFail("Expected head")
        }
        XCTAssertEqual(decodedEntityID, entityID)
        XCTAssertTrue(decodedHead === head)
    }

    func testDerivesAnIsolatedZoneFromTheAuthenticatedVaultIdentity() throws {
        XCTAssertEqual(
            codec.zoneID.zoneName,
            "FloriaVaultV1-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")

        let other = try CloudRecordCodec(
            vaultID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        let foreign = try other.immutableRecords(for: outboundCommit())[0]
        XCTAssertThrowsError(try codec.decode(foreign)) {
            XCTAssertEqual(
                $0 as? CloudRecordCodecError,
                .wrongZone(other.zoneID.zoneName))
        }

        XCTAssertThrowsError(try CloudRecordCodec(vaultID: "not-a-vault")) {
            XCTAssertEqual(
                $0 as? CloudRecordCodecError,
                .invalidUUID(field: "vaultID", value: "not-a-vault"))
        }
    }

    func testRejectsMalformedTransportMetadataBeforeCloudKit() throws {
        let invalidRevision = SyncOutboundRevision(
            entityID: "not-a-uuid",
            revisionID: newRevisionID,
            expectedHeadRevisionID: nil,
            envelopeBase64: Data("revision".utf8).base64EncodedString())
        let invalidCommit = SyncOutboundCommit(
            commitID: commitID,
            manifestBase64: Data("manifest".utf8).base64EncodedString(),
            revisions: [invalidRevision],
            createdAt: "2026-08-07T12:00:00Z")
        XCTAssertThrowsError(try codec.immutableRecords(for: invalidCommit)) {
            XCTAssertEqual(
                $0 as? CloudRecordCodecError,
                .invalidUUID(field: CloudRecordCodec.Field.entityID, value: "not-a-uuid"))
        }

        XCTAssertThrowsError(
            try codec.objectRecord(
                SyncObjectAsset(digest: "BAD", ciphertextSize: 1, file: "/tmp/object"))) {
            XCTAssertEqual($0 as? CloudRecordCodecError, .invalidDigest("BAD"))
        }

        XCTAssertThrowsError(
            try codec.objectRecord(
                SyncObjectAsset(
                    digest: String(repeating: "a", count: 64),
                    ciphertextSize: 1,
                    file: "relative-object.age"))) {
            XCTAssertEqual(
                $0 as? CloudRecordCodecError,
                .assetPathMustBeAbsolute("relative-object.age"))
        }

        let aliased = try codec.immutableRecords(for: outboundCommit())[0]
        let wrongIDRecord = CKRecord(
            recordType: aliased.recordType,
            recordID: codec.recordID(prefix: "commit", stableID: entityID))
        for key in aliased.allKeys() {
            wrongIDRecord[key] = aliased[key]
        }
        XCTAssertThrowsError(try codec.decode(wrongIDRecord)) {
            XCTAssertEqual(
                $0 as? CloudRecordCodecError,
                .recordIdentityMismatch(
                    recordType: CloudRecordCodec.RecordType.commit,
                    stableID: commitID))
        }
    }

    private func outboundCommit(expectedHead: String? = nil) -> SyncOutboundCommit {
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

    private func readyRecords(_ plan: CloudCommitRecordPlan) throws -> [CKRecord] {
        guard case .ready(let records) = plan else {
            throw XCTSkip("Expected a ready CloudKit record plan")
        }
        return records
    }
}
