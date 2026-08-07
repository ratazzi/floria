import CloudKit
import CryptoKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudRecordSyncCoordinatorTests: XCTestCase {
    private let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private let entityID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private let revisionID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    private let commitID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

    private var root: URL!
    private var codec: CloudRecordCodec!
    private var control: RecordSyncControlStub!
    private var coordinator: CloudRecordSyncCoordinator!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        codec = try CloudRecordCodec(vaultID: vaultID)
        control = RecordSyncControlStub()
        coordinator = CloudRecordSyncCoordinator(
            control: control,
            codec: codec,
            assetStager: CloudAssetStager(supportDirectory: root, vaultID: vaultID))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    func testVerifiedObjectAdvancesPlannerToAtomicCommit() async throws {
        let bytes = Data("encrypted object".utf8)
        let file = root.appendingPathComponent("object.age")
        try bytes.write(to: file)
        let object = SyncObjectAsset(
            digest: digest(bytes), ciphertextSize: UInt64(bytes.count), file: file.path)
        let batch = SyncOutboundBatch(commits: [commit()], objects: [object])
        await control.setOutbound(batch)

        guard case .saveObjects(let records) = try await coordinator.nextOutboundAction() else {
            return XCTFail("Expected object upload before commit")
        }
        try await coordinator.markObjectsVerified(records)

        guard case .saveCommit(let plannedID, let commitRecords) =
            try await coordinator.nextOutboundAction()
        else {
            return XCTFail("Expected commit after object verification")
        }
        XCTAssertEqual(plannedID, commitID)
        XCTAssertTrue(
            commitRecords.contains { $0.recordType == CloudRecordCodec.RecordType.head })
    }

    func testPlannerConflictIsSettledThroughRust() async throws {
        let existing = try XCTUnwrap(headRecord(revisionID: UUID().uuidString.lowercased()))
        await coordinator.replaceHeads([entityID: existing])
        await control.setOutbound(SyncOutboundBatch(commits: [commit()], objects: []))

        guard case .settleConflict(let plannedID, let entities) =
            try await coordinator.nextOutboundAction()
        else {
            return XCTFail("Expected a domain conflict")
        }
        XCTAssertEqual(plannedID, commitID)
        XCTAssertEqual(entities, [entityID])
        let settlements = await control.settlements
        XCTAssertEqual(
            settlements,
            [SyncDeliveryOutcome(commitID: commitID, disposition: .conflict)])
    }

    func testInboundIsAppliedBeforeStagingCleanupAndHeadCacheUpdate() async throws {
        let records = try XCTUnwrap(readyRecords(codec.planCommit(commit(), cachedHeads: [:])))

        _ = try await coordinator.applyInbound(
            records: records,
            deletedRecordIDs: [],
            observedAt: "2026-08-07T00:00:00Z")

        let inbound = await control.inboundBatches
        XCTAssertEqual(inbound.count, 1)
        XCTAssertEqual(inbound[0].batch.manifests.map(\.commitID), [commitID])
        let heads = await coordinator.cachedHeads()
        XCTAssertEqual(heads.keys.sorted(), [entityID])
    }

    func testFailedRustApplyRetainsStagedObjectForRecovery() async throws {
        let bytes = Data("encrypted object".utf8)
        let source = root.appendingPathComponent("download.age")
        try bytes.write(to: source)
        let record = try codec.objectRecord(
            SyncObjectAsset(
                digest: digest(bytes),
                ciphertextSize: UInt64(bytes.count),
                file: source.path))
        await control.failInbound()

        do {
            _ = try await coordinator.applyInbound(
                records: [record], deletedRecordIDs: [], observedAt: "now")
            XCTFail("Expected Rust apply failure")
        } catch RecordSyncControlStub.Failure.inbound {
            let inboundDirectory = root
                .appendingPathComponent("record-sync/cloudkit/\(vaultID)/inbound")
            let staged = try FileManager.default.contentsOfDirectory(
                at: inboundDirectory, includingPropertiesForKeys: nil)
            XCTAssertEqual(staged.map(\.lastPathComponent), ["\(digest(bytes)).age"])
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

    private func headRecord(revisionID: String) -> CKRecord? {
        let other = SyncOutboundCommit(
            commitID: UUID().uuidString.lowercased(),
            manifestBase64: Data("manifest".utf8).base64EncodedString(),
            revisions: [
                SyncOutboundRevision(
                    entityID: entityID,
                    revisionID: revisionID,
                    expectedHeadRevisionID: nil,
                    envelopeBase64: Data("revision".utf8).base64EncodedString())
            ],
            createdAt: "2026-08-07T00:00:00Z")
        return try? readyRecords(codec.planCommit(other, cachedHeads: [:]))?
            .first { $0.recordType == CloudRecordCodec.RecordType.head }
    }

    private func readyRecords(_ plan: CloudCommitRecordPlan) -> [CKRecord]? {
        guard case .ready(let records) = plan else { return nil }
        return records
    }

    private func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

private actor RecordSyncControlStub: RecordSyncControlling {
    enum Failure: Error {
        case inbound
    }

    private var outbound = SyncOutboundBatch(commits: [], objects: [])
    private(set) var settlements = [SyncDeliveryOutcome]()
    private(set) var inboundBatches = [(batch: SyncInboundBatch, observedAt: String)]()
    private var shouldFailInbound = false

    func setOutbound(_ batch: SyncOutboundBatch) {
        outbound = batch
    }

    func failInbound() {
        shouldFailInbound = true
    }

    func nextRecordSyncOutbound(limit _: Int) async throws -> SyncOutboundBatch {
        outbound
    }

    func settleRecordSyncOutbound(_ outcomes: [SyncDeliveryOutcome]) async throws
        -> SyncSettlementReport
    {
        settlements.append(contentsOf: outcomes)
        return SyncSettlementReport(
            accepted: outcomes.filter { $0.disposition == .accepted }.count,
            conflicts: outcomes.filter { $0.disposition == .conflict }.count,
            retrying: outcomes.filter { $0.disposition == .retry }.count,
            settled: outcomes.filter { $0.disposition != .retry }.count)
    }

    func applyRecordSyncInbound(_ batch: SyncInboundBatch, observedAt: String) async throws
        -> SyncInboundReport
    {
        inboundBatches.append((batch, observedAt))
        if shouldFailInbound { throw Failure.inbound }
        return SyncInboundReport(
            manifestsReceived: batch.manifests.count,
            revisionsReceived: batch.revisions.count,
            objectsInstalled: batch.objects.count,
            objectsAlreadyPresent: 0,
            inboundSettled: 0,
            pendingTransactions: 0,
            conflictingEntities: 0,
            projection: .unchanged)
    }
}
