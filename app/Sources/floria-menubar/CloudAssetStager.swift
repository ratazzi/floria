import CryptoKit
import Darwin
import Foundation

/// Copies ephemeral CloudKit assets into Floria-owned storage before an event
/// callback returns. The staged file is only transport input: Rust verifies and
/// installs it into the encrypted object store before it becomes authoritative.
struct CloudAssetStager {
    private let directory: URL
    private let fileManager: FileManager

    init(
        supportDirectory: URL,
        vaultID: String,
        fileManager: FileManager = .default
    ) {
        self.fileManager = fileManager
        directory = supportDirectory
            .appendingPathComponent("record-sync", isDirectory: true)
            .appendingPathComponent("cloudkit", isDirectory: true)
            .appendingPathComponent(vaultID, isDirectory: true)
            .appendingPathComponent("inbound", isDirectory: true)
    }

    func stage(_ object: SyncInboundObject) throws -> SyncInboundObject {
        try ensurePrivateDirectory()
        let destination = directory.appendingPathComponent("\(object.digest).age")

        if fileManager.fileExists(atPath: destination.path) {
            guard try CloudAssetFile.matches(
                destination,
                expectedSize: object.ciphertextSize,
                expectedDigest: object.digest)
            else {
                throw CloudAssetStagingError.damagedExistingAsset(object.digest)
            }
            return stagedObject(object, file: destination)
        }

        let temporary = directory.appendingPathComponent(
            ".\(UUID().uuidString.lowercased()).partial")
        defer { try? fileManager.removeItem(at: temporary) }

        try fileManager.copyItem(at: URL(fileURLWithPath: object.file), to: temporary)
        try setPermissions(0o600, at: temporary)
        guard try CloudAssetFile.matches(
            temporary,
            expectedSize: object.ciphertextSize,
            expectedDigest: object.digest)
        else {
            throw CloudAssetStagingError.assetIntegrityMismatch(object.digest)
        }

        // `link(2)` publishes create-only: a concurrent callback can win, but
        // neither callback can replace bytes already staged under this digest.
        if Darwin.link(temporary.path, destination.path) != 0, errno != EEXIST {
            throw CloudAssetStagingError.cannotPublish(
                object.digest, POSIXErrorCode(rawValue: errno))
        }
        guard try CloudAssetFile.matches(
            destination,
            expectedSize: object.ciphertextSize,
            expectedDigest: object.digest)
        else {
            throw CloudAssetStagingError.damagedExistingAsset(object.digest)
        }
        try setPermissions(0o600, at: destination)
        return stagedObject(object, file: destination)
    }

    func remove(_ object: SyncInboundObject) throws {
        let url = URL(fileURLWithPath: object.file)
        guard url.deletingLastPathComponent().standardizedFileURL
            == directory.standardizedFileURL,
            url.lastPathComponent == "\(object.digest).age"
        else {
            throw CloudAssetStagingError.pathOutsideStaging(object.file)
        }
        if fileManager.fileExists(atPath: url.path) {
            try fileManager.removeItem(at: url)
        }
    }

    private func stagedObject(_ object: SyncInboundObject, file: URL) -> SyncInboundObject {
        SyncInboundObject(
            digest: object.digest,
            ciphertextSize: object.ciphertextSize,
            file: file.path)
    }

    private func ensurePrivateDirectory() throws {
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)])
        try setPermissions(0o700, at: directory)
    }

    private func setPermissions(_ permissions: Int, at url: URL) throws {
        try fileManager.setAttributes(
            [.posixPermissions: NSNumber(value: permissions)],
            ofItemAtPath: url.path)
    }
}

enum CloudAssetFile {
    static func matches(
        _ url: URL,
        expectedSize: UInt64,
        expectedDigest: String
    ) throws -> Bool {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber,
              size.uint64Value == expectedSize
        else {
            return false
        }

        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1024 * 1024) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return digest == expectedDigest
    }
}

enum CloudAssetStagingError: Error, Equatable {
    case assetIntegrityMismatch(String)
    case damagedExistingAsset(String)
    case cannotPublish(String, POSIXErrorCode?)
    case pathOutsideStaging(String)
}
