import CloudKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudVaultBootstrapCoordinatorTests: XCTestCase {
    private let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private let deviceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

    func testSeparatesLifecycleRecordsAndAuthenticatesOnlyTheCompleteSnapshot() async throws {
        let bootstrap = fixtureBootstrap()
        let control = VaultBootstrapControlStub(bootstrap: bootstrap)
        let coordinator = try CloudVaultBootstrapCoordinator(
            control: control, vaultID: vaultID)
        let codec = try CloudVaultBootstrapCodec(vaultID: vaultID)
        let domain = ordinaryRecord(codec: codec.recordCodec)

        let partition = try await coordinator.stageFetched(
            records: try codec.records(for: bootstrap) + [domain],
            deletedRecordIDs: [])
        XCTAssertEqual(partition.domainRecords.map(\.recordID), [domain.recordID])

        let accepted = try await coordinator.finishFetch()
        let validatedCandidates = await control.validatedCandidates
        let cached = await coordinator.cachedBootstrap()
        XCTAssertEqual(accepted, bootstrap)
        XCTAssertEqual(validatedCandidates, [bootstrap])
        XCTAssertEqual(cached, bootstrap)
    }

    func testMergesAValidCreateOnlyIncrementIntoTheAcceptedSnapshot() async throws {
        let original = fixtureBootstrap()
        let request = SyncBootstrapDocument(
            route: deviceID, documentBase64: encoded("enrollment request"))
        let updated = SyncVaultBootstrap(
            vaultID: original.vaultID,
            vaultDocumentBase64: original.vaultDocumentBase64,
            deviceIdentities: original.deviceIdentities,
            enrollmentRequests: [request],
            keyGenerations: original.keyGenerations,
            generationEnvelopes: original.generationEnvelopes)
        let control = VaultBootstrapControlStub(bootstrap: updated)
        let coordinator = try CloudVaultBootstrapCoordinator(
            control: control, vaultID: vaultID, restoredBootstrap: original)
        let codec = try CloudVaultBootstrapCodec(vaultID: vaultID)
        let requestRecord = try XCTUnwrap(try codec.records(for: updated).first {
            $0.recordType == CloudVaultBootstrapCodec.RecordType.enrollmentRequest
        })

        _ = try await coordinator.stageFetched(records: [requestRecord], deletedRecordIDs: [])
        let accepted = try await coordinator.finishFetch()
        XCTAssertEqual(accepted, updated)
    }

    func testChangedOrDeletedLifecycleRecordsAreDamage() async throws {
        let bootstrap = fixtureBootstrap()
        let control = VaultBootstrapControlStub(bootstrap: bootstrap)
        let coordinator = try CloudVaultBootstrapCoordinator(
            control: control, vaultID: vaultID, restoredBootstrap: bootstrap)
        let codec = try CloudVaultBootstrapCodec(vaultID: vaultID)
        let root = try XCTUnwrap(try codec.records(for: bootstrap).first {
            $0.recordType == CloudVaultBootstrapCodec.RecordType.vault
        })
        let changed = try XCTUnwrap(root.copy() as? CKRecord)
        changed[CloudVaultBootstrapCodec.Field.payload] = Data("changed".utf8) as NSData

        _ = try await coordinator.stageFetched(records: [changed], deletedRecordIDs: [])
        do {
            _ = try await coordinator.finishFetch()
            XCTFail("Expected immutable lifecycle collision")
        } catch let error as CloudVaultBootstrapCoordinatorError {
            XCTAssertEqual(error, .lifecycleRecordChanged(root.recordID.recordName))
        }

        let fresh = try CloudVaultBootstrapCoordinator(control: control, vaultID: vaultID)
        do {
            _ = try await fresh.stageFetched(records: [], deletedRecordIDs: [root.recordID])
            XCTFail("Expected lifecycle deletion damage")
        } catch let error as CloudVaultBootstrapCoordinatorError {
            XCTAssertEqual(error, .lifecycleRecordDeleted(root.recordID.recordName))
        }
    }

    func testOutboundRecordsComeOnlyFromRustCapture() async throws {
        let bootstrap = fixtureBootstrap()
        let control = VaultBootstrapControlStub(bootstrap: bootstrap)
        let coordinator = try CloudVaultBootstrapCoordinator(
            control: control, vaultID: vaultID)

        let records = try await coordinator.outboundRecords()
        let captureCount = await control.captureCount

        XCTAssertEqual(records.count, 3)
        XCTAssertEqual(captureCount, 1)
    }

    private func fixtureBootstrap() -> SyncVaultBootstrap {
        SyncVaultBootstrap(
            vaultID: vaultID,
            vaultDocumentBase64: encoded("signed Vault"),
            deviceIdentities: [
                SyncBootstrapDocument(
                    route: deviceID, documentBase64: encoded("signed Device"))
            ],
            enrollmentRequests: [],
            keyGenerations: [
                SyncBootstrapDocument(
                    route: "1", documentBase64: encoded("signed generation"))
            ],
            generationEnvelopes: [])
    }

    private func ordinaryRecord(codec: CloudRecordCodec) -> CKRecord {
        let entityID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        let revisionID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        let record = CKRecord(
            recordType: CloudRecordCodec.RecordType.head,
            recordID: codec.recordID(prefix: "head", stableID: entityID))
        record[CloudRecordCodec.Field.schemaVersion] = NSNumber(
            value: CloudRecordCodec.schemaVersion)
        record[CloudRecordCodec.Field.entityID] = entityID as NSString
        record[CloudRecordCodec.Field.revisionID] = revisionID as NSString
        return record
    }

    private func encoded(_ value: String) -> String {
        Data(value.utf8).base64EncodedString()
    }
}

private actor VaultBootstrapControlStub: VaultBootstrapControlling {
    private let bootstrap: SyncVaultBootstrap
    private(set) var captureCount = 0
    private(set) var validatedCandidates = [SyncVaultBootstrap]()

    init(bootstrap: SyncVaultBootstrap) {
        self.bootstrap = bootstrap
    }

    func recordSyncVaultBootstrap() async throws -> SyncVaultBootstrap {
        captureCount += 1
        return bootstrap
    }

    func validateRecordSyncVaultBootstrap(
        _ candidate: SyncVaultBootstrap,
        expectedVaultID: String
    ) async throws -> SyncVaultBootstrap {
        guard candidate.vaultID == expectedVaultID else {
            throw CloudVaultBootstrapCodecError.vaultMismatch(
                expected: expectedVaultID, actual: candidate.vaultID)
        }
        validatedCandidates.append(candidate)
        return candidate
    }
}
