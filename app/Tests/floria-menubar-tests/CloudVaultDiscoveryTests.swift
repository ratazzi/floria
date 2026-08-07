import CloudKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudVaultDiscoveryTests: XCTestCase {
    func testZoneParserIgnoresUnrelatedZonesAndRejectsNoncanonicalVaultNames() throws {
        let unrelated = CKRecordZone.ID(zoneName: "OtherApplication")
        XCTAssertNil(try CloudRecordCodec.vaultID(from: unrelated))

        let canonical = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        let valid = CKRecordZone.ID(
            zoneName: "\(CloudRecordCodec.zoneNamePrefix)\(canonical)")
        XCTAssertEqual(try CloudRecordCodec.vaultID(from: valid), canonical)

        let uppercase = CKRecordZone.ID(
            zoneName: "\(CloudRecordCodec.zoneNamePrefix)\(canonical.uppercased())")
        XCTAssertThrowsError(try CloudRecordCodec.vaultID(from: uppercase)) { error in
            XCTAssertEqual(
                error as? CloudRecordCodecError,
                .noncanonicalVaultZone(uppercase.zoneName))
        }
    }

    func testDiscoveryReturnsOnlyCompleteOuterValidatedVaultsInStableOrder() async throws {
        let first = "11111111-1111-4111-8111-111111111111"
        let second = "22222222-2222-4222-8222-222222222222"
        let incomplete = "33333333-3333-4333-8333-333333333333"
        let firstRoot = try rootRecord(vaultID: first)
        let secondRoot = try rootRecord(vaultID: second)
        let incompleteID = try rootRecord(vaultID: incomplete).recordID
        let query = CloudVaultZoneQueryStub(
            zones: [
                CKRecordZone(zoneID: secondRoot.recordID.zoneID),
                CKRecordZone(zoneName: "Unrelated"),
                CKRecordZone(zoneID: incompleteID.zoneID),
                CKRecordZone(zoneID: firstRoot.recordID.zoneID),
            ],
            lookups: [
                firstRoot.recordID: .found(firstRoot),
                secondRoot.recordID: .found(secondRoot),
                incompleteID: .missing,
            ])

        let candidates = try await CloudVaultDiscovery(query: query).discover()

        XCTAssertEqual(candidates.map(\.vaultID), [first, second])
        XCTAssertEqual(
            candidates.map(\.vaultDocumentBase64),
            [rootPayload(vaultID: first), rootPayload(vaultID: second)])
        XCTAssertEqual(query.requestedRecordIDs, [firstRoot.recordID, secondRoot.recordID, incompleteID])
    }

    func testDiscoveryRejectsARecordWhoseRouteDoesNotMatchItsZone() async throws {
        let expected = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        let other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        let expectedCodec = try CloudVaultBootstrapCodec(vaultID: expected)
        let wrong = try rootRecord(vaultID: other)
        let wrongRoute = CKRecord(
            recordType: wrong.recordType,
            recordID: expectedCodec.recordCodec.recordID(prefix: "vault", stableID: "root"))
        for field in wrong.allKeys() {
            wrongRoute[field] = wrong[field]
        }
        let query = CloudVaultZoneQueryStub(
            zones: [CKRecordZone(zoneID: wrongRoute.recordID.zoneID)],
            lookups: [wrongRoute.recordID: .found(wrongRoute)])

        do {
            _ = try await CloudVaultDiscovery(query: query).discover()
            XCTFail("Expected the mismatched Vault route to fail")
        } catch let error as CloudVaultBootstrapCodecError {
            XCTAssertEqual(error, .vaultMismatch(expected: expected, actual: other))
        }
    }

    func testDiscoveryRejectsAnOmittedRootLookup() async throws {
        let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        let root = try rootRecord(vaultID: vaultID)
        let query = CloudVaultZoneQueryStub(
            zones: [CKRecordZone(zoneID: root.recordID.zoneID)], lookups: [:])

        do {
            _ = try await CloudVaultDiscovery(query: query).discover()
            XCTFail("Expected an omitted lookup to fail")
        } catch let error as CloudVaultDiscoveryError {
            XCTAssertEqual(error, .omittedRoot(root.recordID.zoneID.zoneName))
        }
    }

    private func rootRecord(vaultID: String) throws -> CKRecord {
        let bootstrap = SyncVaultBootstrap(
            vaultID: vaultID,
            vaultDocumentBase64: rootPayload(vaultID: vaultID),
            deviceIdentities: [],
            enrollmentRequests: [],
            keyGenerations: [],
            generationEnvelopes: [])
        return try XCTUnwrap(
            CloudVaultBootstrapCodec(vaultID: vaultID).records(for: bootstrap).first)
    }

    private func rootPayload(vaultID: String) -> String {
        Data("signed-root-\(vaultID)".utf8).base64EncodedString()
    }
}

private final class CloudVaultZoneQueryStub: CloudVaultZoneQuerying, @unchecked Sendable {
    private let zones: [CKRecordZone]
    private let lookups: [CKRecord.ID: CloudVaultRecordLookup]
    private let lock = NSLock()
    private var requested = [CKRecord.ID]()

    init(
        zones: [CKRecordZone],
        lookups: [CKRecord.ID: CloudVaultRecordLookup]
    ) {
        self.zones = zones
        self.lookups = lookups
    }

    var requestedRecordIDs: [CKRecord.ID] {
        lock.withLock { requested }
    }

    func allRecordZones() async throws -> [CKRecordZone] {
        zones
    }

    func records(for recordIDs: [CKRecord.ID]) async throws
        -> [CKRecord.ID: CloudVaultRecordLookup]
    {
        lock.withLock { requested = recordIDs }
        return lookups
    }
}
