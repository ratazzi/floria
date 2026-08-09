import CloudKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudSentBatchResolverTests: XCTestCase {
    private let entityID = "11111111-1111-4111-8111-111111111111"
    private let oldRevisionID = "22222222-2222-4222-8222-222222222222"
    private let newRevisionID = "33333333-3333-4333-8333-333333333333"
    private let commitID = "44444444-4444-4444-8444-444444444444"
    private var codec: CloudRecordCodec {
        try! CloudRecordCodec(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    }

    func testExactImmutableCollisionIsAnIdempotentSuccess() throws {
        let client = try codec.immutableRecords(for: commit(expectedHead: nil))[0]
        let server = try codec.immutableRecords(for: commit(expectedHead: nil))[0]

        let result = try resolver.resolve(
            phase: .objects([]),
            savedRecords: [],
            failures: [])
        guard case .objectsVerified = result else {
            return XCTFail("Empty object phase should be complete")
        }

        let commitResult = try resolver.resolve(
            phase: .commit(commitID: commitID, records: [client]),
            savedRecords: [],
            failures: [
                CloudRecordSaveFailure(
                    record: client, code: .serverRecordChanged, serverRecord: server)
            ])
        guard case .commitAccepted(let acceptedID, _) = commitResult else {
            return XCTFail("Expected an idempotent prior success")
        }
        XCTAssertEqual(acceptedID, commitID)
    }

    func testConflictBranchSettlesOnlyAfterItsImmutableHistoryExists() throws {
        let records = try codec.immutableRecords(for: commit(expectedHead: oldRevisionID))
        let result = try resolver.resolve(
            phase: .conflictBranch(commitID: commitID, records: records),
            savedRecords: records,
            failures: [])

        guard case .conflictBranchAccepted(let acceptedID) = result else {
            return XCTFail("Expected the immutable branch to be durable")
        }
        XCTAssertEqual(acceptedID, commitID)
        XCTAssertFalse(records.contains { $0.recordType == CloudRecordCodec.RecordType.head })
    }

    func testSameDesiredHeadIsPriorSuccessButDifferentHeadIsConflict() throws {
        let desired = head(revisionID: newRevisionID)

        let accepted = try resolver.resolve(
            phase: .commit(commitID: commitID, records: [desired]),
            savedRecords: [],
            failures: [
                CloudRecordSaveFailure(
                    record: desired,
                    code: .serverRecordChanged,
                    serverRecord: head(revisionID: newRevisionID))
            ])
        guard case .commitAccepted(let acceptedID, let heads) = accepted else {
            return XCTFail("Expected an ambiguous prior success")
        }
        XCTAssertEqual(acceptedID, commitID)
        XCTAssertEqual(heads.keys.sorted(), [entityID])

        let conflict = try resolver.resolve(
            phase: .commit(commitID: commitID, records: [desired]),
            savedRecords: [],
            failures: [
                CloudRecordSaveFailure(
                    record: desired,
                    code: .serverRecordChanged,
                    serverRecord: head(revisionID: oldRevisionID))
            ])
        guard case .commitConflict(let conflictID, let entities) = conflict else {
            return XCTFail("Expected a head conflict")
        }
        XCTAssertEqual(conflictID, commitID)
        XCTAssertEqual(entities, [entityID])
    }

    func testAtomicHeadConflictTreatsRolledBackImmutableSiblingsAsTheSameConflict() throws {
        let immutable = try codec.immutableRecords(for: commit(expectedHead: oldRevisionID))
        let desiredHead = head(revisionID: newRevisionID)
        let records = immutable + [desiredHead]
        let failures = immutable.map {
            CloudRecordSaveFailure(
                record: $0, code: .batchRequestFailed, serverRecord: nil)
        } + [
            CloudRecordSaveFailure(
                record: desiredHead,
                code: .serverRecordChanged,
                serverRecord: head(revisionID: oldRevisionID))
        ]

        let result = try resolver.resolve(
            phase: .commit(commitID: commitID, records: records),
            savedRecords: [],
            failures: failures)

        guard case .commitConflict(let conflictID, let entities) = result else {
            return XCTFail("Expected one atomic CAS conflict")
        }
        XCTAssertEqual(conflictID, commitID)
        XCTAssertEqual(entities, [entityID])
    }

    func testTransientAndIncompleteResultsRetryWithoutSettling() throws {
        let record = try codec.immutableRecords(for: commit(expectedHead: nil))[0]
        let transient = try resolver.resolve(
            phase: .commit(commitID: commitID, records: [record]),
            savedRecords: [],
            failures: [
                CloudRecordSaveFailure(
                    record: record, code: .networkUnavailable, serverRecord: nil)
            ])
        guard case .retry = transient else { return XCTFail("Expected retry") }

        let incomplete = try resolver.resolve(
            phase: .commit(commitID: commitID, records: [record]),
            savedRecords: [],
            failures: [])
        guard case .retry = incomplete else { return XCTFail("Expected retry") }
    }

    func testMismatchedImmutableCollisionIsDamage() throws {
        let client = try codec.immutableRecords(for: commit(expectedHead: nil))[0]
        let server = try codec.immutableRecords(for: commit(expectedHead: nil))[0]
        server[CloudRecordCodec.Field.manifest] = Data("changed".utf8) as NSData

        let result = try resolver.resolve(
            phase: .commit(commitID: commitID, records: [client]),
            savedRecords: [],
            failures: [
                CloudRecordSaveFailure(
                    record: client, code: .serverRecordChanged, serverRecord: server)
            ])
        guard case .damaged(let message) = result else {
            return XCTFail("Expected damaged transport state")
        }
        XCTAssertTrue(message.contains(client.recordID.recordName))
    }

    func testBootstrapCollisionIsAcceptedOnlyWhenLifecycleBytesMatch() throws {
        let bootstrapCodec = try CloudVaultBootstrapCodec(vaultID: codec.vaultID)
        let client = try XCTUnwrap(
            try bootstrapCodec.records(for: bootstrap()).first)
        let exact = try XCTUnwrap(client.copy() as? CKRecord)
        let lifecycleResolver = CloudSentBatchResolver(
            codec: codec, bootstrapCodec: bootstrapCodec)

        let accepted = try lifecycleResolver.resolve(
            phase: .bootstrap([client]),
            savedRecords: [],
            failures: [
                CloudRecordSaveFailure(
                    record: client,
                    code: .serverRecordChanged,
                    serverRecord: exact)
            ])
        guard case .bootstrapAccepted = accepted else {
            return XCTFail("Expected an idempotent lifecycle save")
        }

        let changed = try XCTUnwrap(client.copy() as? CKRecord)
        changed[CloudVaultBootstrapCodec.Field.payload] = Data("changed".utf8) as NSData
        let damaged = try lifecycleResolver.resolve(
            phase: .bootstrap([client]),
            savedRecords: [],
            failures: [
                CloudRecordSaveFailure(
                    record: client,
                    code: .serverRecordChanged,
                    serverRecord: changed)
            ])
        guard case .damaged(let message) = damaged else {
            return XCTFail("Expected changed lifecycle bytes to be damage")
        }
        XCTAssertTrue(message.contains(client.recordID.recordName))
    }

    func testBootstrapSavedResultMustStillMatchTheRequestedRecord() throws {
        let bootstrapCodec = try CloudVaultBootstrapCodec(vaultID: codec.vaultID)
        let client = try XCTUnwrap(
            try bootstrapCodec.records(for: bootstrap()).first)
        let changed = try XCTUnwrap(client.copy() as? CKRecord)
        changed[CloudVaultBootstrapCodec.Field.payload] = Data("changed".utf8) as NSData
        let lifecycleResolver = CloudSentBatchResolver(
            codec: codec, bootstrapCodec: bootstrapCodec)

        let result = try lifecycleResolver.resolve(
            phase: .bootstrap([client]),
            savedRecords: [changed],
            failures: [])
        guard case .damaged = result else {
            return XCTFail("Expected a mismatched saved lifecycle record to be damage")
        }
    }

    private var resolver: CloudSentBatchResolver {
        CloudSentBatchResolver(codec: codec)
    }

    private func commit(expectedHead: String?) -> SyncOutboundCommit {
        SyncOutboundCommit(
            commitID: commitID,
            manifestBase64: Data("manifest".utf8).base64EncodedString(),
            revisions: [
                SyncOutboundRevision(
                    entityID: entityID,
                    revisionID: newRevisionID,
                    expectedHeadRevisionIDs: expectedHead.map { [$0] } ?? [],
                    envelopeBase64: Data("revision".utf8).base64EncodedString())
            ],
            createdAt: "2026-08-07T12:00:00Z")
    }

    private func head(revisionID: String) -> CKRecord {
        let record = CKRecord(
            recordType: CloudRecordCodec.RecordType.head,
            recordID: codec.recordID(prefix: "head", stableID: entityID))
        record[CloudRecordCodec.Field.schemaVersion] = NSNumber(
            value: CloudRecordCodec.schemaVersion)
        record[CloudRecordCodec.Field.entityID] = entityID as NSString
        record[CloudRecordCodec.Field.revisionID] = revisionID as NSString
        return record
    }

    private func bootstrap() -> SyncVaultBootstrap {
        SyncVaultBootstrap(
            vaultID: codec.vaultID,
            vaultDocumentBase64: Data("signed Vault".utf8).base64EncodedString(),
            deviceIdentities: [],
            enrollmentRequests: [],
            keyGenerations: [],
            generationEnvelopes: [])
    }
}
