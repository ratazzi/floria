import CloudKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudVaultLifecycleLoaderTests: XCTestCase {
    func testCompleteLifecycleIsOuterValidatedThenAuthenticatedByRust() async throws {
        let bootstrap = fixtureBootstrap()
        let records = try CloudVaultBootstrapCodec(vaultID: bootstrap.vaultID)
            .records(for: bootstrap)
        let query = CloudVaultLifecycleQueryStub(records: records)
        let control = VaultBootstrapValidationStub(expected: bootstrap)

        let accepted = try await CloudVaultLifecycleLoader(query: query, control: control)
            .loadAndAuthenticate(vaultID: bootstrap.vaultID)

        XCTAssertEqual(accepted, bootstrap)
        let calls = await control.calls
        XCTAssertEqual(calls, [bootstrap.vaultID])
        XCTAssertEqual(
            query.requestedLimits,
            CloudVaultBootstrapCodec.lifecycleRecordLimits)
    }

    func testMissingVaultRootNeverReachesRust() async throws {
        let bootstrap = fixtureBootstrap()
        let records = try CloudVaultBootstrapCodec(vaultID: bootstrap.vaultID)
            .records(for: bootstrap)
            .filter { $0.recordType != CloudVaultBootstrapCodec.RecordType.vault }
        let query = CloudVaultLifecycleQueryStub(records: records)
        let control = VaultBootstrapValidationStub(expected: bootstrap)

        do {
            _ = try await CloudVaultLifecycleLoader(query: query, control: control)
                .loadAndAuthenticate(vaultID: bootstrap.vaultID)
            XCTFail("Expected an incomplete lifecycle to fail")
        } catch let error as CloudVaultBootstrapCodecError {
            XCTAssertEqual(error, .missingVaultRoot)
        }
        let calls = await control.calls
        XCTAssertTrue(calls.isEmpty)
    }

    func testQueryReturningAnotherRecordTypeFailsBeforeAuthentication() async throws {
        let bootstrap = fixtureBootstrap()
        let codec = try CloudVaultBootstrapCodec(vaultID: bootstrap.vaultID)
        let records = try codec.records(for: bootstrap)
        let wrong = CKRecord(
            recordType: CloudVaultBootstrapCodec.RecordType.device,
            recordID: codec.recordCodec.recordID(prefix: "vault", stableID: "root"))
        let query = CloudVaultLifecycleQueryStub(
            records: records,
            replacement: (
                requestedType: CloudVaultBootstrapCodec.RecordType.vault,
                records: [wrong]))
        let control = VaultBootstrapValidationStub(expected: bootstrap)

        do {
            _ = try await CloudVaultLifecycleLoader(query: query, control: control)
                .loadAndAuthenticate(vaultID: bootstrap.vaultID)
            XCTFail("Expected a record-type mismatch to fail")
        } catch let error as CloudVaultLifecycleLoaderError {
            XCTAssertEqual(
                error,
                .unexpectedRecordType(
                    expected: CloudVaultBootstrapCodec.RecordType.vault,
                    actual: CloudVaultBootstrapCodec.RecordType.device))
        }
        let calls = await control.calls
        XCTAssertTrue(calls.isEmpty)
    }

    private func fixtureBootstrap() -> SyncVaultBootstrap {
        SyncVaultBootstrap(
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            vaultDocumentBase64: payload("vault"),
            deviceIdentities: [
                SyncBootstrapDocument(
                    route: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    documentBase64: payload("device")),
            ],
            enrollmentRequests: [
                SyncBootstrapDocument(
                    route: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    documentBase64: payload("request")),
            ],
            keyGenerations: [
                SyncBootstrapDocument(route: "1", documentBase64: payload("generation")),
            ],
            generationEnvelopes: [
                SyncBootstrapEnvelope(
                    deviceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    generation: 1,
                    ciphertextBase64: payload("envelope")),
            ])
    }

    private func payload(_ value: String) -> String {
        Data(value.utf8).base64EncodedString()
    }
}

private final class CloudVaultLifecycleQueryStub: CloudVaultLifecycleQuerying,
    @unchecked Sendable
{
    private let recordsByType: [String: [CKRecord]]
    private let replacement: (requestedType: String, records: [CKRecord])?
    private let lock = NSLock()
    private var limits = [String: Int]()

    init(
        records: [CKRecord],
        replacement: (requestedType: String, records: [CKRecord])? = nil
    ) {
        recordsByType = Dictionary(grouping: records, by: \.recordType)
        self.replacement = replacement
    }

    var requestedLimits: [String: Int] {
        lock.withLock { limits }
    }

    func records(
        ofType recordType: String,
        in _: CKRecordZone.ID,
        maximumCount: Int
    ) async throws -> [CKRecord] {
        lock.withLock { limits[recordType] = maximumCount }
        if replacement?.requestedType == recordType {
            return replacement?.records ?? []
        }
        return recordsByType[recordType] ?? []
    }
}

private actor VaultBootstrapValidationStub: VaultBootstrapControlling {
    private let expected: SyncVaultBootstrap
    private(set) var calls = [String]()

    init(expected: SyncVaultBootstrap) {
        self.expected = expected
    }

    func recordSyncVaultBootstrap() async throws -> SyncVaultBootstrap {
        expected
    }

    func validateRecordSyncVaultBootstrap(
        _ bootstrap: SyncVaultBootstrap,
        expectedVaultID: String
    ) async throws -> SyncVaultBootstrap {
        calls.append(expectedVaultID)
        XCTAssertEqual(bootstrap, expected)
        return bootstrap
    }
}
