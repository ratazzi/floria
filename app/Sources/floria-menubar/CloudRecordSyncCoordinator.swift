import CloudKit
import Foundation

protocol RecordSyncControlling: Sendable {
    func nextRecordSyncOutbound(limit: Int) async throws -> SyncOutboundBatch
    func settleRecordSyncOutbound(_ outcomes: [SyncDeliveryOutcome]) async throws
        -> SyncSettlementReport
    func applyRecordSyncInbound(_ batch: SyncInboundBatch, observedAt: String) async throws
        -> SyncInboundReport
}

extension ControlClient: RecordSyncControlling {}

/// Owns the mutable state between Rust's authenticated record graph and one
/// CloudKit transport session. CloudKit callbacks stay thin; domain settlement
/// still happens only through Rust.
actor CloudRecordSyncCoordinator {
    private let control: any RecordSyncControlling
    private let outboundPlanner: CloudOutboundPlanner
    private let inboundProcessor: CloudInboundProcessor
    private var verifiedObjectDigests = Set<String>()
    private var heads: [String: CKRecord]

    init(
        control: any RecordSyncControlling,
        codec: CloudRecordCodec,
        assetStager: CloudAssetStager,
        restoredHeads: [String: CKRecord] = [:]
    ) {
        self.control = control
        outboundPlanner = CloudOutboundPlanner(codec: codec)
        inboundProcessor = CloudInboundProcessor(codec: codec, assetStager: assetStager)
        heads = restoredHeads
    }

    func nextOutboundAction(limit: Int = 8) async throws -> CloudOutboundAction {
        let batch = try await control.nextRecordSyncOutbound(limit: limit)
        let action = try outboundPlanner.nextAction(
            batch: batch,
            verifiedObjectDigests: verifiedObjectDigests,
            cachedHeads: heads)
        if case .settleConflict(let commitID, _) = action {
            _ = try await settle(commitID: commitID, disposition: .conflict)
        }
        return action
    }

    func markObjectsVerified(_ records: [CKRecord]) throws {
        for record in records {
            guard case .object(let object) = try outboundPlanner.codec.decode(record) else {
                continue
            }
            verifiedObjectDigests.insert(object.digest)
        }
    }

    func settle(
        commitID: String,
        disposition: SyncDeliveryDisposition
    ) async throws -> SyncSettlementReport {
        try await control.settleRecordSyncOutbound([
            SyncDeliveryOutcome(commitID: commitID, disposition: disposition)
        ])
    }

    @discardableResult
    func applyInbound(
        records: [CKRecord],
        deletedRecordIDs: [CKRecord.ID],
        observedAt: String
    ) async throws -> SyncInboundReport? {
        let preparation = try inboundProcessor.prepare(
            records: records,
            deletedRecordIDs: deletedRecordIDs)

        let report: SyncInboundReport?
        if preparation.hasDomainRecords {
            report = try await control.applyRecordSyncInbound(
                preparation.batch, observedAt: observedAt)
            try inboundProcessor.removeStagedAssets(after: preparation)
        } else {
            report = nil
        }
        heads.merge(preparation.heads) { _, fetched in fetched }
        return report
    }

    func replaceHeads(_ fetched: [String: CKRecord]) {
        heads = fetched
    }

    func cachedHeads() -> [String: CKRecord] {
        heads
    }

    func resetTransportCache() {
        heads.removeAll()
        verifiedObjectDigests.removeAll()
    }
}
