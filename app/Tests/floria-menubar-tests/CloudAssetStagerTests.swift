import CryptoKit
import Foundation
import XCTest

@testable import floria_menubar

final class CloudAssetStagerTests: XCTestCase {
    private var root: URL!
    private var source: URL!
    private var stager: CloudAssetStager!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        source = root.appendingPathComponent("download.age")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        stager = CloudAssetStager(
            supportDirectory: root,
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: root)
    }

    func testStagesVerifiedAssetWithPrivatePermissions() throws {
        let bytes = Data("encrypted object".utf8)
        try bytes.write(to: source)

        let staged = try stager.stage(object(bytes: bytes))

        XCTAssertNotEqual(staged.file, source.path)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: staged.file)), bytes)
        let attributes = try FileManager.default.attributesOfItem(atPath: staged.file)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testRejectsAssetWhoseBytesDoNotMatchDigest() throws {
        let expected = Data("expected".utf8)
        try Data("changed".utf8).write(to: source)

        XCTAssertThrowsError(try stager.stage(object(bytes: expected))) {
            XCTAssertEqual(
                $0 as? CloudAssetStagingError,
                .assetIntegrityMismatch(digest(expected)))
        }
    }

    func testReusesVerifiedAssetButNeverReplacesDamagedExistingBytes() throws {
        let bytes = Data("encrypted object".utf8)
        try bytes.write(to: source)
        let first = try stager.stage(object(bytes: bytes))
        try Data("damaged object!!".utf8).write(to: URL(fileURLWithPath: first.file))

        XCTAssertThrowsError(try stager.stage(object(bytes: bytes))) {
            XCTAssertEqual(
                $0 as? CloudAssetStagingError,
                .damagedExistingAsset(digest(bytes)))
        }
        XCTAssertEqual(
            try Data(contentsOf: URL(fileURLWithPath: first.file)),
            Data("damaged object!!".utf8))
    }

    func testRemoveRefusesPathsOutsideOwnedStagingDirectory() throws {
        let bytes = Data("encrypted object".utf8)
        try bytes.write(to: source)
        let inbound = object(bytes: bytes)

        XCTAssertThrowsError(try stager.remove(inbound)) {
            XCTAssertEqual(
                $0 as? CloudAssetStagingError,
                .pathOutsideStaging(source.path))
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: source.path))
    }

    private func object(bytes: Data) -> SyncInboundObject {
        SyncInboundObject(
            digest: digest(bytes),
            ciphertextSize: UInt64(bytes.count),
            file: source.path)
    }

    private func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
}
