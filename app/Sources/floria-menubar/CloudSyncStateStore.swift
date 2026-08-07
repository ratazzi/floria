import CloudKit
import Foundation

/// Durable, account-local transport state for one CloudKit Vault zone.
///
/// This checkpoint is a cache, never domain authority. Rust keeps the durable
/// record graph and safely accepts duplicate inbound records. If this file is
/// damaged, Floria isolates it and starts a fresh CloudKit fetch instead of
/// touching the local library.
struct CloudSyncStateStore {
    private static let formatVersion = 2
    private static let maximumStateBytes: UInt64 = 16 * 1024 * 1024

    private let codec: CloudRecordCodec
    private let directory: URL
    private let stateURL: URL
    private let fileManager: FileManager

    init(
        supportDirectory: URL,
        codec: CloudRecordCodec,
        fileManager: FileManager = .default
    ) {
        self.codec = codec
        self.fileManager = fileManager
        directory = supportDirectory
            .appendingPathComponent("record-sync", isDirectory: true)
            .appendingPathComponent("cloudkit", isDirectory: true)
            .appendingPathComponent(codec.vaultID, isDirectory: true)
        stateURL = directory.appendingPathComponent("state.plist")
    }

    func loadRecovering() throws -> CloudSyncRestoredState {
        guard fileManager.fileExists(atPath: stateURL.path) else {
            return .empty
        }

        do {
            return try load()
        } catch {
            try ensurePrivateDirectory()
            let damagedURL = directory.appendingPathComponent(
                "state.invalid-\(UUID().uuidString.lowercased()).plist")
            try fileManager.moveItem(at: stateURL, to: damagedURL)
            try setPermissions(0o600, at: damagedURL)
            return .empty
        }
    }

    func save(
        engineState: CKSyncEngine.State.Serialization?,
        heads: [String: CKRecord],
        vaultBootstrap: SyncVaultBootstrap? = nil
    ) throws {
        try ensurePrivateDirectory()

        let engineStateData: Data?
        if let engineState {
            engineStateData = try PropertyListEncoder().encode(engineState)
        } else {
            engineStateData = nil
        }

        var persistedHeads = [String: PersistedCloudHead]()
        for (entityID, record) in heads {
            guard case .head(let decodedEntityID, _) = try codec.decode(record),
                  decodedEntityID == entityID,
                  let revisionID = record[CloudRecordCodec.Field.revisionID] as? String
            else {
                throw CloudSyncStateError.invalidHead(entityID)
            }
            persistedHeads[entityID] = PersistedCloudHead(
                entityID: entityID,
                revisionID: revisionID,
                systemFields: try encodeSystemFields(record))
        }

        if let vaultBootstrap {
            _ = try CloudVaultBootstrapCodec(vaultID: codec.vaultID)
                .records(for: vaultBootstrap)
        }

        let envelope = CloudSyncStateEnvelope(
            formatVersion: Self.formatVersion,
            vaultID: codec.vaultID,
            engineState: engineStateData,
            heads: persistedHeads,
            vaultBootstrap: vaultBootstrap)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let data = try encoder.encode(envelope)
        try data.write(to: stateURL, options: .atomic)
        try setPermissions(0o600, at: stateURL)
    }

    /// Account sign-out/switch invalidates CloudKit tokens and record change tags,
    /// but never the Rust record journal or encrypted object store.
    func resetTransportState() throws {
        guard fileManager.fileExists(atPath: stateURL.path) else { return }
        try ensurePrivateDirectory()
        let previousURL = directory.appendingPathComponent(
            "state.account-changed-\(UUID().uuidString.lowercased()).plist")
        try fileManager.moveItem(at: stateURL, to: previousURL)
        try setPermissions(0o600, at: previousURL)
    }

    private func load() throws -> CloudSyncRestoredState {
        let attributes = try fileManager.attributesOfItem(atPath: stateURL.path)
        guard let size = attributes[.size] as? NSNumber,
              size.uint64Value <= Self.maximumStateBytes
        else {
            throw CloudSyncStateError.checkpointTooLarge
        }
        let data = try Data(contentsOf: stateURL, options: .mappedIfSafe)
        let envelope = try PropertyListDecoder().decode(CloudSyncStateEnvelope.self, from: data)
        guard envelope.formatVersion == Self.formatVersion else {
            throw CloudSyncStateError.unsupportedFormat(envelope.formatVersion)
        }
        guard envelope.vaultID == codec.vaultID else {
            throw CloudSyncStateError.wrongVault(envelope.vaultID)
        }

        let engineState: CKSyncEngine.State.Serialization?
        if let bytes = envelope.engineState {
            engineState = try PropertyListDecoder().decode(
                CKSyncEngine.State.Serialization.self, from: bytes)
        } else {
            engineState = nil
        }

        var heads = [String: CKRecord]()
        for (entityID, persisted) in envelope.heads {
            guard entityID == persisted.entityID else {
                throw CloudSyncStateError.invalidHead(entityID)
            }
            let record = try decodeSystemFields(persisted.systemFields)
            record[CloudRecordCodec.Field.schemaVersion] = NSNumber(
                value: CloudRecordCodec.schemaVersion)
            record[CloudRecordCodec.Field.entityID] = persisted.entityID as NSString
            record[CloudRecordCodec.Field.revisionID] = persisted.revisionID as NSString
            guard case .head(let decodedEntityID, _) = try codec.decode(record),
                  decodedEntityID == entityID
            else {
                throw CloudSyncStateError.invalidHead(entityID)
            }
            heads[entityID] = record
        }
        if let bootstrap = envelope.vaultBootstrap {
            _ = try CloudVaultBootstrapCodec(vaultID: codec.vaultID)
                .records(for: bootstrap)
        }
        return CloudSyncRestoredState(
            engineState: engineState,
            heads: heads,
            vaultBootstrap: envelope.vaultBootstrap)
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

    private func encodeSystemFields(_ record: CKRecord) throws -> Data {
        let archiver = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: archiver)
        archiver.finishEncoding()
        return archiver.encodedData
    }

    private func decodeSystemFields(_ data: Data) throws -> CKRecord {
        let unarchiver = try NSKeyedUnarchiver(forReadingFrom: data)
        unarchiver.requiresSecureCoding = true
        defer { unarchiver.finishDecoding() }
        guard let record = CKRecord(coder: unarchiver) else {
            throw CloudSyncStateError.invalidSystemFields
        }
        return record
    }
}

struct CloudSyncRestoredState {
    static let empty = CloudSyncRestoredState(
        engineState: nil, heads: [:], vaultBootstrap: nil)

    let engineState: CKSyncEngine.State.Serialization?
    let heads: [String: CKRecord]
    /// Previously authenticated transport snapshot. A consumer must submit it to Rust again
    /// before using it after process restart; this checkpoint is not domain authority.
    let vaultBootstrap: SyncVaultBootstrap?
}

private struct CloudSyncStateEnvelope: Codable {
    let formatVersion: Int
    let vaultID: String
    let engineState: Data?
    let heads: [String: PersistedCloudHead]
    let vaultBootstrap: SyncVaultBootstrap?
}

private struct PersistedCloudHead: Codable {
    let entityID: String
    let revisionID: String
    let systemFields: Data
}

enum CloudSyncStateError: Error, Equatable {
    case unsupportedFormat(Int)
    case wrongVault(String)
    case invalidHead(String)
    case invalidSystemFields
    case checkpointTooLarge
}
