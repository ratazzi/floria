import CloudKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudSyncStateStoreTests: XCTestCase {
    private let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private let entityID = "11111111-1111-4111-8111-111111111111"
    private let revisionID = "22222222-2222-4222-8222-222222222222"

    func testRoundTripsHeadSystemFieldsInAPrivateVaultCheckpoint() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let head = headRecord(codec: fixture.codec)
        try fixture.store.save(engineState: nil, heads: [entityID: head])
        let restored = try fixture.store.loadRecovering()

        XCTAssertNil(restored.engineState)
        XCTAssertNil(restored.vaultBootstrap)
        let restoredHead = try XCTUnwrap(restored.heads[entityID])
        XCTAssertEqual(restoredHead.recordID, head.recordID)
        XCTAssertEqual(
            restoredHead[CloudRecordCodec.Field.revisionID] as? String,
            revisionID)
        guard case .head(let restoredEntityID, _) = try fixture.codec.decode(restoredHead) else {
            return XCTFail("Expected a restored head")
        }
        XCTAssertEqual(restoredEntityID, entityID)

        XCTAssertEqual(try permissions(of: fixture.directory), 0o700)
        XCTAssertEqual(try permissions(of: fixture.stateURL), 0o600)
    }

    func testRoundTripsAnOpaqueVaultBootstrapWithoutMakingItDomainAuthority() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let deviceID = "33333333-3333-4333-8333-333333333333"
        let bootstrap = SyncVaultBootstrap(
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

        try fixture.store.save(
            engineState: nil,
            heads: [entityID: headRecord(codec: fixture.codec)],
            vaultBootstrap: bootstrap)
        let restored = try fixture.store.loadRecovering()

        XCTAssertEqual(restored.vaultBootstrap, bootstrap)
        XCTAssertEqual(restored.heads.keys.sorted(), [entityID])
    }

    func testDamagedCheckpointIsIsolatedAndRefetchedWithoutDeletingEvidence() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try fixture.store.save(
            engineState: nil,
            heads: [entityID: headRecord(codec: fixture.codec)])
        try Data("not a property list".utf8).write(to: fixture.stateURL, options: .atomic)

        let restored = try fixture.store.loadRecovering()
        XCTAssertTrue(restored.heads.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.stateURL.path))
        let evidence = try FileManager.default.contentsOfDirectory(
            at: fixture.directory,
            includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("state.invalid-") }
        XCTAssertEqual(evidence.count, 1)
        XCTAssertEqual(try permissions(of: try XCTUnwrap(evidence.first)), 0o600)
    }

    func testAccountChangeArchivesOnlyTheTransportCheckpoint() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        try fixture.store.save(
            engineState: nil,
            heads: [entityID: headRecord(codec: fixture.codec)])
        try fixture.store.resetTransportState()

        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.stateURL.path))
        XCTAssertTrue(try fixture.store.loadRecovering().heads.isEmpty)
        let archived = try FileManager.default.contentsOfDirectory(
            at: fixture.directory,
            includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("state.account-changed-") }
        XCTAssertEqual(archived.count, 1)
    }

    private func makeFixture() throws -> (
        root: URL,
        directory: URL,
        stateURL: URL,
        codec: CloudRecordCodec,
        store: CloudSyncStateStore
    ) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "floria-cloud-state-\(UUID().uuidString)", isDirectory: true)
        let codec = try CloudRecordCodec(vaultID: vaultID)
        let directory = root
            .appendingPathComponent("record-sync", isDirectory: true)
            .appendingPathComponent("cloudkit", isDirectory: true)
            .appendingPathComponent(vaultID, isDirectory: true)
        return (
            root,
            directory,
            directory.appendingPathComponent("state.plist"),
            codec,
            CloudSyncStateStore(supportDirectory: root, codec: codec))
    }

    private func headRecord(codec: CloudRecordCodec) -> CKRecord {
        let record = CKRecord(
            recordType: CloudRecordCodec.RecordType.head,
            recordID: codec.recordID(prefix: "head", stableID: entityID))
        record[CloudRecordCodec.Field.schemaVersion] = NSNumber(
            value: CloudRecordCodec.schemaVersion)
        record[CloudRecordCodec.Field.entityID] = entityID as NSString
        record[CloudRecordCodec.Field.revisionID] = revisionID as NSString
        return record
    }

    private func permissions(of url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try XCTUnwrap(attributes[.posixPermissions] as? NSNumber).intValue
    }

    private func encoded(_ value: String) -> String {
        Data(value.utf8).base64EncodedString()
    }
}
