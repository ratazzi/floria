import CloudKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudVaultBootstrapCodecTests: XCTestCase {
    private let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private let deviceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private var codec: CloudVaultBootstrapCodec {
        try! CloudVaultBootstrapCodec(vaultID: vaultID)
    }

    func testMapsEveryOpaqueBootstrapKindToDeterministicCreateOnlyRecords() throws {
        let records = try codec.records(for: bootstrap())

        XCTAssertEqual(records.count, 5)
        XCTAssertEqual(Set(records.map(\.recordType)), Set([
            CloudVaultBootstrapCodec.RecordType.vault,
            CloudVaultBootstrapCodec.RecordType.device,
            CloudVaultBootstrapCodec.RecordType.enrollmentRequest,
            CloudVaultBootstrapCodec.RecordType.generation,
            CloudVaultBootstrapCodec.RecordType.generationEnvelope,
        ]))
        XCTAssertTrue(records.allSatisfy { $0.recordID.zoneID == codec.recordCodec.zoneID })
        XCTAssertTrue(records.allSatisfy {
            $0[CloudVaultBootstrapCodec.Field.payload] is Data
        })
        XCTAssertFalse(records.flatMap { $0.allKeys() }.contains("plaintext"))

        let repeated = try codec.records(for: bootstrap())
        XCTAssertEqual(records.map(\.recordID), repeated.map(\.recordID))
    }

    func testFetchedRecordsRoundTripWithoutParsingSignedPayloads() throws {
        let original = bootstrap()
        let records = try codec.records(for: original)
        let decoded = try codec.bootstrap(from: records.reversed())

        XCTAssertEqual(decoded, original)
    }

    func testRejectsCrossVaultRoutesDuplicateRecordsAndIdentitySubstitution() throws {
        let foreign = SyncVaultBootstrap(
            vaultID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            vaultDocumentBase64: encoded("vault"),
            deviceIdentities: [], enrollmentRequests: [], keyGenerations: [],
            generationEnvelopes: [])
        XCTAssertThrowsError(try codec.records(for: foreign)) {
            XCTAssertEqual(
                $0 as? CloudVaultBootstrapCodecError,
                .vaultMismatch(expected: vaultID, actual: foreign.vaultID))
        }

        let records = try codec.records(for: bootstrap())
        XCTAssertThrowsError(try codec.bootstrap(from: records + [records[0]])) {
            XCTAssertEqual(
                $0 as? CloudVaultBootstrapCodecError,
                .duplicateRecord(records[0].recordID.recordName))
        }

        let device = try XCTUnwrap(records.first {
            $0.recordType == CloudVaultBootstrapCodec.RecordType.device
        })
        let substituted = CKRecord(
            recordType: device.recordType,
            recordID: codec.recordCodec.recordID(prefix: "device", stableID: vaultID))
        for field in device.allKeys() { substituted[field] = device[field] }
        XCTAssertThrowsError(try codec.decode(substituted)) {
            XCTAssertEqual(
                $0 as? CloudVaultBootstrapCodecError,
                .recordIdentityMismatch(substituted.recordID.recordName))
        }
    }

    func testRejectsInvalidGenerationRoutesAndOversizedPayloads() throws {
        var invalid = bootstrap()
        invalid = SyncVaultBootstrap(
            vaultID: invalid.vaultID,
            vaultDocumentBase64: invalid.vaultDocumentBase64,
            deviceIdentities: invalid.deviceIdentities,
            enrollmentRequests: invalid.enrollmentRequests,
            keyGenerations: [
                SyncBootstrapDocument(route: "01", documentBase64: encoded("generation"))
            ],
            generationEnvelopes: invalid.generationEnvelopes)
        XCTAssertThrowsError(try codec.records(for: invalid)) {
            XCTAssertEqual(
                $0 as? CloudVaultBootstrapCodecError,
                .invalidGenerationRoute("01"))
        }

        let oversized = Data(
            repeating: 0, count: CloudVaultBootstrapCodec.maximumPayloadBytes + 1
        ).base64EncodedString()
        let tooLarge = SyncVaultBootstrap(
            vaultID: vaultID,
            vaultDocumentBase64: oversized,
            deviceIdentities: [], enrollmentRequests: [], keyGenerations: [],
            generationEnvelopes: [])
        XCTAssertThrowsError(try codec.records(for: tooLarge)) {
            XCTAssertEqual(
                $0 as? CloudVaultBootstrapCodecError,
                .payloadTooLarge(CloudVaultBootstrapCodec.maximumPayloadBytes + 1))
        }
    }

    private func bootstrap() -> SyncVaultBootstrap {
        SyncVaultBootstrap(
            vaultID: vaultID,
            vaultDocumentBase64: encoded("vault"),
            deviceIdentities: [
                SyncBootstrapDocument(route: deviceID, documentBase64: encoded("device"))
            ],
            enrollmentRequests: [
                SyncBootstrapDocument(route: deviceID, documentBase64: encoded("request"))
            ],
            keyGenerations: [
                SyncBootstrapDocument(route: "1", documentBase64: encoded("generation"))
            ],
            generationEnvelopes: [
                SyncBootstrapEnvelope(
                    deviceID: deviceID,
                    generation: 1,
                    ciphertextBase64: encoded("envelope"))
            ])
    }

    private func encoded(_ value: String) -> String {
        Data(value.utf8).base64EncodedString()
    }
}
