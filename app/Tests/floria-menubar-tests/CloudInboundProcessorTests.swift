import CloudKit
import CryptoKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudInboundProcessorTests: XCTestCase {
    private let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private let entityID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private let revisionID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    private let commitID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

    private var root: URL!
    private var codec: CloudRecordCodec!
    private var processor: CloudInboundProcessor!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        codec = try CloudRecordCodec(vaultID: vaultID)
        processor = CloudInboundProcessor(
            codec: codec,
            assetStager: CloudAssetStager(supportDirectory: root, vaultID: vaultID))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    func testSeparatesTransportHeadsAndStagesOpaqueDomainRecords() throws {
        let bytes = Data("encrypted object".utf8)
        let source = root.appendingPathComponent("cloudkit-download.age")
        try bytes.write(to: source)
        let object = try codec.objectRecord(
            SyncObjectAsset(
                digest: digest(bytes),
                ciphertextSize: UInt64(bytes.count),
                file: source.path))
        let commit = SyncOutboundCommit(
            commitID: commitID,
            manifestBase64: Data("manifest".utf8).base64EncodedString(),
            revisions: [
                SyncOutboundRevision(
                    entityID: entityID,
                    revisionID: revisionID,
                    expectedHeadRevisionID: nil,
                    envelopeBase64: Data("revision".utf8).base64EncodedString())
            ],
            createdAt: "2026-08-07T00:00:00Z")
        let commitRecords = try XCTUnwrap(
            readyRecords(try codec.planCommit(commit, cachedHeads: [:])))

        let preparation = try processor.prepare(
            records: [object] + commitRecords,
            deletedRecordIDs: [])

        XCTAssertEqual(preparation.batch.manifests.map(\.commitID), [commitID])
        XCTAssertEqual(preparation.batch.revisions.map(\.revisionID), [revisionID])
        XCTAssertEqual(preparation.batch.objects.map(\.digest), [digest(bytes)])
        XCTAssertEqual(preparation.heads.keys.sorted(), [entityID])
        XCTAssertTrue(preparation.hasDomainRecords)
        let stagedPath = try XCTUnwrap(preparation.batch.objects.first?.file)
        XCTAssertNotEqual(stagedPath, source.path)
        XCTAssertTrue(FileManager.default.fileExists(atPath: stagedPath))

        try processor.removeStagedAssets(after: preparation)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stagedPath))
    }

    func testHeadOnlyFetchDoesNotCreateAnEmptyRustOperation() throws {
        let head = try XCTUnwrap(
            readyRecords(try codec.planCommit(commit(), cachedHeads: [:]))?
                .first { $0.recordType == CloudRecordCodec.RecordType.head })

        let preparation = try processor.prepare(records: [head], deletedRecordIDs: [])

        XCTAssertFalse(preparation.hasDomainRecords)
        XCTAssertEqual(preparation.heads.keys.sorted(), [entityID])
    }

    func testRemoteDeletionIsDamageAndStagesNothing() throws {
        let recordID = codec.recordID(prefix: "head", stableID: entityID)

        XCTAssertThrowsError(
            try processor.prepare(records: [], deletedRecordIDs: [recordID])
        ) {
            XCTAssertEqual(
                $0 as? CloudInboundProcessingError,
                .remoteRecordsDeleted([recordID.recordName]))
        }
    }

    func testDuplicateRecordInOneEventIsRejected() throws {
        let records = try XCTUnwrap(
            readyRecords(try codec.planCommit(commit(), cachedHeads: [:])))
        let head = try XCTUnwrap(
            records.first { $0.recordType == CloudRecordCodec.RecordType.head })

        XCTAssertThrowsError(
            try processor.prepare(records: [head, head], deletedRecordIDs: [])
        ) {
            XCTAssertEqual(
                $0 as? CloudInboundProcessingError,
                .duplicateRecord(head.recordID.recordName))
        }
    }

    private func commit() -> SyncOutboundCommit {
        SyncOutboundCommit(
            commitID: commitID,
            manifestBase64: Data("manifest".utf8).base64EncodedString(),
            revisions: [
                SyncOutboundRevision(
                    entityID: entityID,
                    revisionID: revisionID,
                    expectedHeadRevisionID: nil,
                    envelopeBase64: Data("revision".utf8).base64EncodedString())
            ],
            createdAt: "2026-08-07T00:00:00Z")
    }

    private func readyRecords(_ plan: CloudCommitRecordPlan) -> [CKRecord]? {
        guard case .ready(let records) = plan else { return nil }
        return records
    }

    private func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
