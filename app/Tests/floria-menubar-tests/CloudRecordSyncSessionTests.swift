import CloudKit
import XCTest

@testable import floria_menubar

final class CloudRecordSyncSessionTests: XCTestCase {
    func testZoneFetchBuffersDomainRecordsUntilCommitted() async throws {
        let state = CloudRecordSyncSessionState(initialEngineState: nil)
        let record = CKRecord(
            recordType: CloudRecordCodec.RecordType.revision,
            recordID: CKRecord.ID(
                recordName: "revision-11111111-1111-4111-8111-111111111111"))

        try await state.beginZoneFetch()
        try await state.stageFetchedDomain(
            CloudVaultFetchPartition(
                domainRecords: [record],
                domainDeletedRecordIDs: []))

        let staged = try await state.stagedFetchedDomain()
        XCTAssertEqual(staged.domainRecords.map(\.recordID), [record.recordID])
        _ = try await state.commitZoneFetch()

        do {
            _ = try await state.stagedFetchedDomain()
            XCTFail("Expected the committed fetch buffer to be closed")
        } catch let error as CloudRecordSyncSessionError {
            guard case .damaged = error else {
                return XCTFail("Expected a damaged fetch boundary")
            }
        }
    }

    func testZoneFetchRejectsDuplicateOrConflictingDomainChanges() async throws {
        let state = CloudRecordSyncSessionState(initialEngineState: nil)
        let recordID = CKRecord.ID(
            recordName: "revision-11111111-1111-4111-8111-111111111111")
        let record = CKRecord(
            recordType: CloudRecordCodec.RecordType.revision,
            recordID: recordID)

        try await state.beginZoneFetch()
        try await state.stageFetchedDomain(
            CloudVaultFetchPartition(
                domainRecords: [record],
                domainDeletedRecordIDs: []))

        do {
            try await state.stageFetchedDomain(
                CloudVaultFetchPartition(
                    domainRecords: [],
                    domainDeletedRecordIDs: [recordID]))
            XCTFail("Expected conflicting changes for one record to fail closed")
        } catch let error as CloudRecordSyncSessionError {
            guard case .damaged = error else {
                return XCTFail("Expected duplicate changes to be damage")
            }
        }
    }

    func testBootstrapSendIsAtomicByZone() {
        XCTAssertTrue(CloudSendPhase.bootstrap([]).atomicByZone)
        XCTAssertTrue(CloudSendPhase.commit(commitID: "commit", records: []).atomicByZone)
        XCTAssertFalse(CloudSendPhase.objects([]).atomicByZone)
        XCTAssertFalse(
            CloudSendPhase.conflictBranch(commitID: "commit", records: []).atomicByZone)
    }

    func testManualSyncOutcomeReportsOnlyNewlyAppliedRemoteChanges() async throws {
        let state = CloudRecordSyncSessionState(initialEngineState: nil)
        let applied = SyncInboundReport(
            manifestsReceived: 1,
            revisionsReceived: 1,
            objectsInstalled: 0,
            objectsAlreadyPresent: 0,
            inboundSettled: 1,
            pendingTransactions: 0,
            conflictingEntities: 0,
            projection: .applied)

        try await state.prepareForManualSync()
        await state.observe(applied)
        let first = await state.manualSyncOutcome()
        XCTAssertTrue(first.appliedRemoteChanges)

        try await state.prepareForManualSync()
        let second = await state.manualSyncOutcome()
        XCTAssertFalse(second.appliedRemoteChanges)
    }
}
