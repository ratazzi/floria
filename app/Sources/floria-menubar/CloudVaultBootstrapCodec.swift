import CloudKit
import Foundation

/// Maps Rust-authenticated Vault bootstrap material to deterministic create-only CloudKit records.
/// Signed JSON and encrypted envelopes remain opaque; this module owns only transport routes,
/// bounds, and zone identity.
struct CloudVaultBootstrapCodec {
    static let maximumPayloadBytes = 64 * 1024

    let recordCodec: CloudRecordCodec

    enum RecordType {
        static let vault = "FloriaVaultRootV1"
        static let device = "FloriaVaultDeviceV1"
        static let enrollmentRequest = "FloriaVaultEnrollmentRequestV1"
        static let generation = "FloriaVaultGenerationV1"
        static let generationEnvelope = "FloriaVaultGenerationEnvelopeV1"
    }

    enum Field {
        static let schemaVersion = "schemaVersion"
        static let vaultID = "vaultID"
        static let deviceID = "deviceID"
        static let generation = "generation"
        static let payload = "payload"
    }

    init(vaultID: String) throws {
        recordCodec = try CloudRecordCodec(vaultID: vaultID)
    }

    func owns(_ record: CKRecord) -> Bool {
        Self.recordTypes.contains(record.recordType)
    }

    func owns(_ recordID: CKRecord.ID) -> Bool {
        guard recordID.zoneID == recordCodec.zoneID else { return false }
        return Self.recordNamePrefixes.contains { recordID.recordName.hasPrefix($0) }
    }

    func equivalent(_ left: CKRecord, _ right: CKRecord) throws -> Bool {
        guard left.recordID == right.recordID, left.recordType == right.recordType else {
            return false
        }
        return try decode(left) == decode(right)
    }

    func records(for bootstrap: SyncVaultBootstrap) throws -> [CKRecord] {
        guard bootstrap.vaultID.lowercased() == recordCodec.vaultID else {
            throw CloudVaultBootstrapCodecError.vaultMismatch(
                expected: recordCodec.vaultID, actual: bootstrap.vaultID)
        }
        var records: [CKRecord] = []
        var recordNames = Set<String>()

        try append(
            record(
                type: RecordType.vault,
                prefix: "vault",
                stableID: "root",
                routeFields: [Field.vaultID: recordCodec.vaultID as NSString],
                payloadBase64: bootstrap.vaultDocumentBase64),
            to: &records,
            recordNames: &recordNames)

        for document in bootstrap.deviceIdentities {
            let deviceID = try validatedDeviceID(document.route)
            try append(
                record(
                    type: RecordType.device,
                    prefix: "device",
                    stableID: deviceID,
                    routeFields: [Field.deviceID: deviceID as NSString],
                    payloadBase64: document.documentBase64),
                to: &records,
                recordNames: &recordNames)
        }
        for document in bootstrap.enrollmentRequests {
            let deviceID = try validatedDeviceID(document.route)
            try append(
                record(
                    type: RecordType.enrollmentRequest,
                    prefix: "enrollment",
                    stableID: deviceID,
                    routeFields: [Field.deviceID: deviceID as NSString],
                    payloadBase64: document.documentBase64),
                to: &records,
                recordNames: &recordNames)
        }
        for document in bootstrap.keyGenerations {
            let generation = try validatedGenerationRoute(document.route)
            try append(
                record(
                    type: RecordType.generation,
                    prefix: "generation",
                    stableID: String(generation),
                    routeFields: [Field.generation: NSNumber(value: generation)],
                    payloadBase64: document.documentBase64),
                to: &records,
                recordNames: &recordNames)
        }
        for envelope in bootstrap.generationEnvelopes {
            let deviceID = try validatedDeviceID(envelope.deviceID)
            let generation = try validatedGeneration(envelope.generation)
            try append(
                record(
                    type: RecordType.generationEnvelope,
                    prefix: "envelope",
                    stableID: "\(deviceID)-\(generation)",
                    routeFields: [
                        Field.deviceID: deviceID as NSString,
                        Field.generation: NSNumber(value: generation),
                    ],
                    payloadBase64: envelope.ciphertextBase64),
                to: &records,
                recordNames: &recordNames)
        }
        return records.sorted { $0.recordID.recordName < $1.recordID.recordName }
    }

    /// Rebuild one untrusted transport snapshot. Rust must still call `validate_for_vault` before
    /// displaying or activating it.
    func bootstrap(from records: [CKRecord]) throws -> SyncVaultBootstrap {
        var vaultDocument: String?
        var devices: [SyncBootstrapDocument] = []
        var requests: [SyncBootstrapDocument] = []
        var generations: [SyncBootstrapDocument] = []
        var envelopes: [SyncBootstrapEnvelope] = []
        var recordNames = Set<String>()

        for record in records {
            guard recordNames.insert(record.recordID.recordName).inserted else {
                throw CloudVaultBootstrapCodecError.duplicateRecord(record.recordID.recordName)
            }
            switch try decode(record) {
            case .vault(let payload):
                guard vaultDocument == nil else {
                    throw CloudVaultBootstrapCodecError.duplicateVaultRoot
                }
                vaultDocument = payload
            case .device(let document):
                devices.append(document)
            case .enrollmentRequest(let document):
                requests.append(document)
            case .generation(let document):
                generations.append(document)
            case .generationEnvelope(let envelope):
                envelopes.append(envelope)
            }
        }
        guard let vaultDocument else {
            throw CloudVaultBootstrapCodecError.missingVaultRoot
        }
        devices.sort { $0.route < $1.route }
        requests.sort { $0.route < $1.route }
        generations.sort { (UInt32($0.route) ?? 0) < (UInt32($1.route) ?? 0) }
        envelopes.sort {
            ($0.deviceID, $0.generation) < ($1.deviceID, $1.generation)
        }
        return SyncVaultBootstrap(
            vaultID: recordCodec.vaultID,
            vaultDocumentBase64: vaultDocument,
            deviceIdentities: devices,
            enrollmentRequests: requests,
            keyGenerations: generations,
            generationEnvelopes: envelopes)
    }

    func decode(_ record: CKRecord) throws -> CloudDecodedBootstrapRecord {
        try validateCommonFields(record)
        switch record.recordType {
        case RecordType.vault:
            try validateFields(record, allowed: [Field.schemaVersion, Field.vaultID, Field.payload])
            let vaultID = try stringField(Field.vaultID, in: record)
            guard vaultID == recordCodec.vaultID else {
                throw CloudVaultBootstrapCodecError.vaultMismatch(
                    expected: recordCodec.vaultID, actual: vaultID)
            }
            try validateRecordID(record, prefix: "vault", stableID: "root")
            return .vault(documentBase64: try payloadBase64(record))

        case RecordType.device:
            try validateFields(record, allowed: [Field.schemaVersion, Field.deviceID, Field.payload])
            let deviceID = try validatedDeviceID(try stringField(Field.deviceID, in: record))
            try validateRecordID(record, prefix: "device", stableID: deviceID)
            return .device(
                SyncBootstrapDocument(route: deviceID, documentBase64: try payloadBase64(record)))

        case RecordType.enrollmentRequest:
            try validateFields(record, allowed: [Field.schemaVersion, Field.deviceID, Field.payload])
            let deviceID = try validatedDeviceID(try stringField(Field.deviceID, in: record))
            try validateRecordID(record, prefix: "enrollment", stableID: deviceID)
            return .enrollmentRequest(
                SyncBootstrapDocument(route: deviceID, documentBase64: try payloadBase64(record)))

        case RecordType.generation:
            try validateFields(
                record, allowed: [Field.schemaVersion, Field.generation, Field.payload])
            let generation = try generationField(record)
            try validateRecordID(record, prefix: "generation", stableID: String(generation))
            return .generation(
                SyncBootstrapDocument(
                    route: String(generation), documentBase64: try payloadBase64(record)))

        case RecordType.generationEnvelope:
            try validateFields(
                record,
                allowed: [
                    Field.schemaVersion, Field.deviceID, Field.generation, Field.payload,
                ])
            let deviceID = try validatedDeviceID(try stringField(Field.deviceID, in: record))
            let generation = try generationField(record)
            try validateRecordID(
                record, prefix: "envelope", stableID: "\(deviceID)-\(generation)")
            return .generationEnvelope(
                SyncBootstrapEnvelope(
                    deviceID: deviceID,
                    generation: generation,
                    ciphertextBase64: try payloadBase64(record)))

        default:
            throw CloudVaultBootstrapCodecError.unknownRecordType(record.recordType)
        }
    }

    private func record(
        type: String,
        prefix: String,
        stableID: String,
        routeFields: [String: CKRecordValue],
        payloadBase64: String
    ) throws -> CKRecord {
        let record = CKRecord(
            recordType: type,
            recordID: recordCodec.recordID(prefix: prefix, stableID: stableID))
        record[Field.schemaVersion] = NSNumber(value: CloudRecordCodec.schemaVersion)
        for (field, value) in routeFields {
            record[field] = value
        }
        record[Field.payload] = try payloadData(payloadBase64) as NSData
        return record
    }

    private func append(
        _ record: CKRecord,
        to records: inout [CKRecord],
        recordNames: inout Set<String>
    ) throws {
        guard recordNames.insert(record.recordID.recordName).inserted else {
            throw CloudVaultBootstrapCodecError.duplicateRecord(record.recordID.recordName)
        }
        records.append(record)
    }

    private func validateCommonFields(_ record: CKRecord) throws {
        guard record.recordID.zoneID == recordCodec.zoneID else {
            throw CloudVaultBootstrapCodecError.wrongZone(record.recordID.zoneID.zoneName)
        }
        guard let version = record[Field.schemaVersion] as? NSNumber else {
            throw CloudVaultBootstrapCodecError.missingField(Field.schemaVersion)
        }
        guard version.int64Value == CloudRecordCodec.schemaVersion else {
            throw CloudVaultBootstrapCodecError.unsupportedSchemaVersion(version.int64Value)
        }
    }

    private func validateFields(_ record: CKRecord, allowed: Set<String>) throws {
        if let unexpected = Set(record.allKeys()).subtracting(allowed).sorted().first {
            throw CloudVaultBootstrapCodecError.unexpectedField(unexpected)
        }
    }

    private func validateRecordID(_ record: CKRecord, prefix: String, stableID: String) throws {
        guard record.recordID == recordCodec.recordID(prefix: prefix, stableID: stableID) else {
            throw CloudVaultBootstrapCodecError.recordIdentityMismatch(record.recordID.recordName)
        }
    }

    private func stringField(_ field: String, in record: CKRecord) throws -> String {
        guard let value = record[field] as? String, !value.isEmpty else {
            throw CloudVaultBootstrapCodecError.missingField(field)
        }
        return value
    }

    private func generationField(_ record: CKRecord) throws -> UInt32 {
        guard let value = record[Field.generation] as? NSNumber,
              value.int64Value > 0,
              value.int64Value <= Int64(UInt32.max)
        else {
            throw CloudVaultBootstrapCodecError.invalidGeneration
        }
        return UInt32(value.int64Value)
    }

    private func payloadBase64(_ record: CKRecord) throws -> String {
        guard let data = record[Field.payload] as? Data, !data.isEmpty else {
            throw CloudVaultBootstrapCodecError.missingField(Field.payload)
        }
        guard data.count <= Self.maximumPayloadBytes else {
            throw CloudVaultBootstrapCodecError.payloadTooLarge(data.count)
        }
        return data.base64EncodedString()
    }

    private func payloadData(_ base64: String) throws -> Data {
        guard let data = Data(base64Encoded: base64), !data.isEmpty else {
            throw CloudVaultBootstrapCodecError.invalidBase64
        }
        guard data.count <= Self.maximumPayloadBytes else {
            throw CloudVaultBootstrapCodecError.payloadTooLarge(data.count)
        }
        return data
    }

    private func validatedDeviceID(_ value: String) throws -> String {
        guard let uuid = UUID(uuidString: value),
              uuid.uuidString.lowercased() == value.lowercased()
        else {
            throw CloudVaultBootstrapCodecError.invalidDeviceID(value)
        }
        return uuid.uuidString.lowercased()
    }

    private func validatedGenerationRoute(_ value: String) throws -> UInt32 {
        guard let generation = UInt32(value), String(generation) == value else {
            throw CloudVaultBootstrapCodecError.invalidGenerationRoute(value)
        }
        return try validatedGeneration(generation)
    }

    private func validatedGeneration(_ value: UInt32) throws -> UInt32 {
        guard value > 0 else { throw CloudVaultBootstrapCodecError.invalidGeneration }
        return value
    }


    private static let recordTypes = Set([
        RecordType.vault,
        RecordType.device,
        RecordType.enrollmentRequest,
        RecordType.generation,
        RecordType.generationEnvelope,
    ])

    private static let recordNamePrefixes = [
        "vault-", "device-", "enrollment-", "generation-", "envelope-",
    ]
}

enum CloudDecodedBootstrapRecord: Equatable {
    case vault(documentBase64: String)
    case device(SyncBootstrapDocument)
    case enrollmentRequest(SyncBootstrapDocument)
    case generation(SyncBootstrapDocument)
    case generationEnvelope(SyncBootstrapEnvelope)
}

enum CloudVaultBootstrapCodecError: Error, Equatable, LocalizedError {
    case vaultMismatch(expected: String, actual: String)
    case invalidDeviceID(String)
    case invalidGeneration
    case invalidGenerationRoute(String)
    case invalidBase64
    case payloadTooLarge(Int)
    case duplicateRecord(String)
    case duplicateVaultRoot
    case missingVaultRoot
    case wrongZone(String)
    case unsupportedSchemaVersion(Int64)
    case unknownRecordType(String)
    case missingField(String)
    case recordIdentityMismatch(String)
    case unexpectedField(String)

    var errorDescription: String? {
        switch self {
        case .vaultMismatch(let expected, let actual):
            return "Vault bootstrap route \(actual) does not match \(expected)"
        case .invalidDeviceID(let value):
            return "Invalid Vault Device UUID: \(value)"
        case .invalidGeneration:
            return "Vault key generation must start at 1"
        case .invalidGenerationRoute(let value):
            return "Invalid Vault key generation route: \(value)"
        case .invalidBase64:
            return "Invalid Base64 in Vault bootstrap payload"
        case .payloadTooLarge(let size):
            return "Vault bootstrap payload is too large: \(size) bytes"
        case .duplicateRecord(let name):
            return "Vault bootstrap record appears more than once: \(name)"
        case .duplicateVaultRoot:
            return "Vault bootstrap contains more than one root"
        case .missingVaultRoot:
            return "Vault bootstrap has no root"
        case .wrongZone(let zone):
            return "Vault bootstrap record belongs to the wrong zone: \(zone)"
        case .unsupportedSchemaVersion(let version):
            return "Unsupported Vault bootstrap schema version: \(version)"
        case .unknownRecordType(let type):
            return "Unknown Vault bootstrap record type: \(type)"
        case .missingField(let field):
            return "Vault bootstrap record is missing \(field)"
        case .recordIdentityMismatch(let name):
            return "Vault bootstrap record ID does not match its route: \(name)"
        case .unexpectedField(let field):
            return "Vault bootstrap record contains unexpected field \(field)"
        }
    }
}
