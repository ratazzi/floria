import CloudKit
import Foundation

/// The CloudKit schema for Floria's opaque coordinated-record transport.
///
/// This type deliberately knows nothing about decrypted entities, projects, or
/// secrets. Rust owns those semantics. The Swift adapter only maps authenticated
/// envelopes and encrypted object files to records in one private custom zone.
struct CloudRecordCodec {
    static let schemaVersion: Int64 = 1
    static let zoneNamePrefix = "FloriaVaultV1-"

    let vaultID: String
    let zoneID: CKRecordZone.ID

    init(vaultID: String) throws {
        let canonicalVaultID = try Self.validatedUUID(vaultID, field: "vaultID")
        self.vaultID = canonicalVaultID
        zoneID = CKRecordZone.ID(
            zoneName: "\(Self.zoneNamePrefix)\(canonicalVaultID)")
    }

    /// Decode the canonical Vault UUID carried by a Floria private-zone name.
    /// Unrelated CloudKit zones are ignored. A zone claiming this namespace must
    /// use the one canonical lowercase spelling or it is treated as damaged.
    static func vaultID(from zoneID: CKRecordZone.ID) throws -> String? {
        guard zoneID.zoneName.hasPrefix(zoneNamePrefix) else { return nil }
        let suffix = String(zoneID.zoneName.dropFirst(zoneNamePrefix.count))
        let canonical = try validatedUUID(suffix, field: "zoneVaultID")
        guard suffix == canonical else {
            throw CloudRecordCodecError.noncanonicalVaultZone(zoneID.zoneName)
        }
        return canonical
    }

    enum RecordType {
        static let object = "FloriaObjectV1"
        static let revision = "FloriaRevisionV1"
        static let commit = "FloriaCommitV1"
        static let head = "FloriaHeadV1"
    }

    enum Field {
        static let schemaVersion = "schemaVersion"
        static let digest = "digest"
        static let ciphertextSize = "ciphertextSize"
        static let ciphertext = "ciphertext"
        static let entityID = "entityID"
        static let revisionID = "revisionID"
        static let commitID = "commitID"
        static let envelope = "envelope"
        static let manifest = "manifest"
    }

    func objectRecord(_ asset: SyncObjectAsset) throws -> CKRecord {
        let digest = try validatedDigest(asset.digest)
        guard asset.ciphertextSize <= UInt64(Int64.max) else {
            throw CloudRecordCodecError.invalidCiphertextSize(asset.ciphertextSize)
        }

        guard asset.file.hasPrefix("/") else {
            throw CloudRecordCodecError.assetPathMustBeAbsolute(asset.file)
        }
        let fileURL = URL(fileURLWithPath: asset.file)

        let record = CKRecord(
            recordType: RecordType.object,
            recordID: recordID(prefix: "object", stableID: digest))
        record[Field.schemaVersion] = NSNumber(value: Self.schemaVersion)
        record[Field.digest] = digest as NSString
        record[Field.ciphertextSize] = NSNumber(value: Int64(asset.ciphertextSize))
        record[Field.ciphertext] = CKAsset(fileURL: fileURL)
        return record
    }

    func immutableRecords(for commit: SyncOutboundCommit) throws -> [CKRecord] {
        let commitID = try Self.validatedUUID(commit.commitID, field: Field.commitID)
        let manifest = try decodedEnvelope(commit.manifestBase64, field: Field.manifest)

        let commitRecord = CKRecord(
            recordType: RecordType.commit,
            recordID: recordID(prefix: "commit", stableID: commitID))
        commitRecord[Field.schemaVersion] = NSNumber(value: Self.schemaVersion)
        commitRecord[Field.commitID] = commitID as NSString
        commitRecord[Field.manifest] = manifest as NSData

        let revisionRecords = try commit.revisions.map { revision -> CKRecord in
            let entityID = try Self.validatedUUID(revision.entityID, field: Field.entityID)
            let revisionID = try Self.validatedUUID(revision.revisionID, field: Field.revisionID)
            let envelope = try decodedEnvelope(
                revision.envelopeBase64, field: Field.envelope)
            let record = CKRecord(
                recordType: RecordType.revision,
                recordID: recordID(prefix: "revision", stableID: revisionID))
            record[Field.schemaVersion] = NSNumber(value: Self.schemaVersion)
            record[Field.entityID] = entityID as NSString
            record[Field.revisionID] = revisionID as NSString
            record[Field.envelope] = envelope as NSData
            return record
        }

        return [commitRecord] + revisionRecords
    }

    /// Builds one atomic commit save from cached server heads.
    ///
    /// Existing heads are copied so their CloudKit system fields, especially
    /// `recordChangeTag`, remain attached to the update. A missing cache entry is
    /// not treated as a new record when Rust expected an existing revision.
    func planCommit(
        _ commit: SyncOutboundCommit,
        cachedHeads: [String: CKRecord]
    ) throws -> CloudCommitRecordPlan {
        var heads: [CKRecord] = []
        var needsFetch = Set<String>()
        var conflicts = Set<String>()

        for revision in commit.revisions {
            let entityID = try Self.validatedUUID(revision.entityID, field: Field.entityID)
            let revisionID = try Self.validatedUUID(revision.revisionID, field: Field.revisionID)

            if !revision.expectedHeadRevisionIDs.isEmpty {
                let expectedIDs = Set(try revision.expectedHeadRevisionIDs.map {
                    try Self.validatedUUID($0, field: "expectedHeadRevisionIDs")
                })
                guard let cached = cachedHeads[entityID] else {
                    needsFetch.insert(entityID)
                    continue
                }
                guard expectedIDs.contains(
                    try headRevisionID(cached, expectedEntityID: entityID)
                ) else {
                    conflicts.insert(entityID)
                    continue
                }
                guard let updated = cached.copy() as? CKRecord else {
                    throw CloudRecordCodecError.cannotCopyHead(entityID)
                }
                updated[Field.revisionID] = revisionID as NSString
                heads.append(updated)
            } else if cachedHeads[entityID] != nil {
                conflicts.insert(entityID)
            } else {
                let head = CKRecord(
                    recordType: RecordType.head,
                    recordID: recordID(prefix: "head", stableID: entityID))
                head[Field.schemaVersion] = NSNumber(value: Self.schemaVersion)
                head[Field.entityID] = entityID as NSString
                head[Field.revisionID] = revisionID as NSString
                heads.append(head)
            }
        }

        if !conflicts.isEmpty {
            return .conflict(entityIDs: conflicts.sorted())
        }
        if !needsFetch.isEmpty {
            return .needsHeadFetch(entityIDs: needsFetch.sorted())
        }
        return .ready(records: try immutableRecords(for: commit) + heads)
    }

    func decode(_ record: CKRecord) throws -> CloudDecodedRecord {
        try validateCommonFields(record)
        switch record.recordType {
        case RecordType.object:
            let digest = try validatedDigest(try stringField(Field.digest, in: record))
            try validateRecordID(record, prefix: "object", stableID: digest)
            let size = try nonnegativeIntegerField(Field.ciphertextSize, in: record)
            guard let asset = record[Field.ciphertext] as? CKAsset,
                  let fileURL = asset.fileURL
            else {
                throw CloudRecordCodecError.missingField(
                    recordType: record.recordType, field: Field.ciphertext)
            }
            return .object(
                SyncInboundObject(
                    digest: digest,
                    ciphertextSize: UInt64(size),
                    file: fileURL.path))

        case RecordType.revision:
            let entityID = try Self.validatedUUID(
                try stringField(Field.entityID, in: record), field: Field.entityID)
            let revisionID = try Self.validatedUUID(
                try stringField(Field.revisionID, in: record), field: Field.revisionID)
            try validateRecordID(record, prefix: "revision", stableID: revisionID)
            let envelope = try dataField(Field.envelope, in: record)
            return .revision(
                SyncInboundRevision(
                    entityID: entityID,
                    revisionID: revisionID,
                    envelopeBase64: envelope.base64EncodedString()))

        case RecordType.commit:
            let commitID = try Self.validatedUUID(
                try stringField(Field.commitID, in: record), field: Field.commitID)
            try validateRecordID(record, prefix: "commit", stableID: commitID)
            let manifest = try dataField(Field.manifest, in: record)
            return .manifest(
                SyncInboundManifest(
                    commitID: commitID,
                    manifestBase64: manifest.base64EncodedString()))

        case RecordType.head:
            let entityID = try Self.validatedUUID(
                try stringField(Field.entityID, in: record), field: Field.entityID)
            _ = try headRevisionID(record, expectedEntityID: entityID)
            return .head(entityID: entityID, record: record)

        default:
            throw CloudRecordCodecError.unknownRecordType(record.recordType)
        }
    }

    func recordID(prefix: String, stableID: String) -> CKRecord.ID {
        CKRecord.ID(recordName: "\(prefix)-\(stableID)", zoneID: zoneID)
    }

    private func validateCommonFields(_ record: CKRecord) throws {
        guard record.recordID.zoneID == zoneID else {
            throw CloudRecordCodecError.wrongZone(record.recordID.zoneID.zoneName)
        }
        let version = try nonnegativeIntegerField(Field.schemaVersion, in: record)
        guard version == Self.schemaVersion else {
            throw CloudRecordCodecError.unsupportedSchemaVersion(version)
        }
    }

    private func headRevisionID(
        _ record: CKRecord,
        expectedEntityID: String
    ) throws -> String {
        try validateCommonFields(record)
        guard record.recordType == RecordType.head else {
            throw CloudRecordCodecError.unexpectedRecordType(
                expected: RecordType.head, actual: record.recordType)
        }
        let entityID = try Self.validatedUUID(
            try stringField(Field.entityID, in: record), field: Field.entityID)
        guard entityID == expectedEntityID,
              record.recordID == recordID(prefix: "head", stableID: entityID)
        else {
            throw CloudRecordCodecError.headIdentityMismatch(expectedEntityID)
        }
        return try Self.validatedUUID(
            try stringField(Field.revisionID, in: record), field: Field.revisionID)
    }

    private func validateRecordID(
        _ record: CKRecord,
        prefix: String,
        stableID: String
    ) throws {
        guard record.recordID == recordID(prefix: prefix, stableID: stableID) else {
            throw CloudRecordCodecError.recordIdentityMismatch(
                recordType: record.recordType,
                stableID: stableID)
        }
    }

    private func stringField(_ field: String, in record: CKRecord) throws -> String {
        guard let value = record[field] as? String, !value.isEmpty else {
            throw CloudRecordCodecError.missingField(
                recordType: record.recordType, field: field)
        }
        return value
    }

    private func dataField(_ field: String, in record: CKRecord) throws -> Data {
        guard let value = record[field] as? Data, !value.isEmpty else {
            throw CloudRecordCodecError.missingField(
                recordType: record.recordType, field: field)
        }
        return value
    }

    private func nonnegativeIntegerField(
        _ field: String,
        in record: CKRecord
    ) throws -> Int64 {
        guard let value = record[field] as? NSNumber else {
            throw CloudRecordCodecError.missingField(
                recordType: record.recordType, field: field)
        }
        let integer = value.int64Value
        guard integer >= 0 else {
            throw CloudRecordCodecError.invalidInteger(field: field, value: integer)
        }
        return integer
    }

    private func decodedEnvelope(_ value: String, field: String) throws -> Data {
        guard let data = Data(base64Encoded: value), !data.isEmpty else {
            throw CloudRecordCodecError.invalidBase64(field)
        }
        return data
    }

    private func validatedDigest(_ value: String) throws -> String {
        guard value.utf8.count == 64,
              value.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
              })
        else {
            throw CloudRecordCodecError.invalidDigest(value)
        }
        return value
    }

    private static func validatedUUID(_ value: String, field: String) throws -> String {
        guard let uuid = UUID(uuidString: value), uuid.uuidString.lowercased() == value.lowercased()
        else {
            throw CloudRecordCodecError.invalidUUID(field: field, value: value)
        }
        return uuid.uuidString.lowercased()
    }
}

enum CloudCommitRecordPlan {
    case ready(records: [CKRecord])
    case needsHeadFetch(entityIDs: [String])
    case conflict(entityIDs: [String])
}

enum CloudDecodedRecord {
    case object(SyncInboundObject)
    case revision(SyncInboundRevision)
    case manifest(SyncInboundManifest)
    case head(entityID: String, record: CKRecord)
}

enum CloudRecordCodecError: Error, Equatable, LocalizedError {
    case invalidDigest(String)
    case invalidUUID(field: String, value: String)
    case invalidBase64(String)
    case invalidCiphertextSize(UInt64)
    case assetPathMustBeAbsolute(String)
    case wrongZone(String)
    case unsupportedSchemaVersion(Int64)
    case unknownRecordType(String)
    case unexpectedRecordType(expected: String, actual: String)
    case missingField(recordType: String, field: String)
    case invalidInteger(field: String, value: Int64)
    case headIdentityMismatch(String)
    case recordIdentityMismatch(recordType: String, stableID: String)
    case cannotCopyHead(String)
    case noncanonicalVaultZone(String)

    var errorDescription: String? {
        switch self {
        case .invalidDigest(let value):
            return "Invalid encrypted-object digest: \(value)"
        case .invalidUUID(let field, let value):
            return "Invalid \(field) UUID: \(value)"
        case .invalidBase64(let field):
            return "Invalid Base64 in \(field)"
        case .invalidCiphertextSize(let size):
            return "Encrypted object is too large to describe: \(size) bytes"
        case .assetPathMustBeAbsolute(let path):
            return "CloudKit asset path must be absolute: \(path)"
        case .wrongZone(let zone):
            return "CloudKit record belongs to the wrong zone: \(zone)"
        case .unsupportedSchemaVersion(let version):
            return "Unsupported CloudKit record schema version: \(version)"
        case .unknownRecordType(let type):
            return "Unknown Floria CloudKit record type: \(type)"
        case .unexpectedRecordType(let expected, let actual):
            return "Expected CloudKit record type \(expected), received \(actual)"
        case .missingField(let recordType, let field):
            return "CloudKit \(recordType) record is missing \(field)"
        case .invalidInteger(let field, let value):
            return "CloudKit field \(field) has invalid value \(value)"
        case .headIdentityMismatch(let entityID):
            return "CloudKit head identity does not match entity \(entityID)"
        case .recordIdentityMismatch(let recordType, let stableID):
            return "CloudKit \(recordType) record ID does not match \(stableID)"
        case .cannotCopyHead(let entityID):
            return "CloudKit head for entity \(entityID) could not be copied"
        case .noncanonicalVaultZone(let zone):
            return "Floria CloudKit zone is not canonical: \(zone)"
        }
    }
}
