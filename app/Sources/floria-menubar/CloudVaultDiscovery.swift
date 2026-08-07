import CloudKit
import Foundation

/// An outer-validated Vault advertised by one private CloudKit zone.
/// The signed root remains opaque and untrusted until Rust validates a complete
/// lifecycle snapshot for this Vault.
struct CloudVaultCandidate: Equatable, Sendable {
    let vaultID: String
    let vaultDocumentBase64: String
}

protocol CloudVaultDiscovering: Sendable {
    func discover() async throws -> [CloudVaultCandidate]
}

enum CloudVaultRecordLookup {
    case found(CKRecord)
    case missing
    case failed(String)
}

protocol CloudVaultZoneQuerying: Sendable {
    func allRecordZones() async throws -> [CKRecordZone]
    func records(for recordIDs: [CKRecord.ID]) async throws
        -> [CKRecord.ID: CloudVaultRecordLookup]
}

/// The only type in discovery that talks to CloudKit. Keeping result conversion
/// here lets the discovery rules remain deterministic and fully offline-testable.
struct CloudKitVaultZoneQuery: CloudVaultZoneQuerying, @unchecked Sendable {
    let database: CKDatabase

    func allRecordZones() async throws -> [CKRecordZone] {
        try await database.allRecordZones()
    }

    func records(for recordIDs: [CKRecord.ID]) async throws
        -> [CKRecord.ID: CloudVaultRecordLookup]
    {
        let fetched = try await database.records(for: recordIDs)
        return fetched.mapValues { result in
            switch result {
            case .success(let record):
                return .found(record)
            case .failure(let error):
                if let cloudError = error as? CKError, cloudError.code == .unknownItem {
                    return .missing
                }
                return .failed(error.localizedDescription)
            }
        }
    }
}

/// Discovers candidate Vaults without selecting one or mutating local state.
///
/// Listing zones and reading deterministic root records is transport discovery,
/// not authentication. A caller must subsequently fetch the complete lifecycle
/// and submit it to Rust before offering enrollment or activation.
struct CloudVaultDiscovery: Sendable {
    static let maximumVaultZones = 64

    private let query: any CloudVaultZoneQuerying

    init(query: any CloudVaultZoneQuerying) {
        self.query = query
    }

    func discover() async throws -> [CloudVaultCandidate] {
        let zones = try await query.allRecordZones()
        var codecs = [CKRecord.ID: CloudVaultBootstrapCodec]()

        for zone in zones {
            guard let vaultID = try CloudRecordCodec.vaultID(from: zone.zoneID) else {
                continue
            }
            let codec = try CloudVaultBootstrapCodec(vaultID: vaultID)
            let recordID = codec.recordCodec.recordID(prefix: "vault", stableID: "root")
            guard codecs.updateValue(codec, forKey: recordID) == nil else {
                throw CloudVaultDiscoveryError.duplicateVault(vaultID)
            }
        }

        guard codecs.count <= Self.maximumVaultZones else {
            throw CloudVaultDiscoveryError.tooManyVaults(codecs.count)
        }
        guard !codecs.isEmpty else { return [] }

        let rootIDs = codecs.keys.sorted { left, right in
            left.zoneID.zoneName < right.zoneID.zoneName
        }
        let fetched = try await query.records(for: rootIDs)
        var candidates = [CloudVaultCandidate]()

        for recordID in rootIDs {
            guard let result = fetched[recordID] else {
                throw CloudVaultDiscoveryError.omittedRoot(recordID.zoneID.zoneName)
            }
            guard let codec = codecs[recordID] else {
                throw CloudVaultDiscoveryError.omittedRoot(recordID.zoneID.zoneName)
            }
            switch result {
            case .missing:
                // A just-created zone may be visible before its atomic bootstrap
                // save. It is not a joinable candidate yet.
                continue
            case .failed(let message):
                throw CloudVaultDiscoveryError.couldNotReadRoot(
                    vaultID: codec.recordCodec.vaultID, message: message)
            case .found(let record):
                guard case .vault(let documentBase64) = try codec.decode(record) else {
                    throw CloudVaultDiscoveryError.invalidRoot(codec.recordCodec.vaultID)
                }
                candidates.append(
                    CloudVaultCandidate(
                        vaultID: codec.recordCodec.vaultID,
                        vaultDocumentBase64: documentBase64))
            }
        }

        return candidates.sorted { $0.vaultID < $1.vaultID }
    }
}

extension CloudVaultDiscovery: CloudVaultDiscovering {}

enum CloudVaultDiscoveryError: Error, Equatable, LocalizedError {
    case duplicateVault(String)
    case tooManyVaults(Int)
    case omittedRoot(String)
    case couldNotReadRoot(vaultID: String, message: String)
    case invalidRoot(String)

    var errorDescription: String? {
        switch self {
        case .duplicateVault(let vaultID):
            "CloudKit returned duplicate zones for Vault \(vaultID)"
        case .tooManyVaults(let count):
            "CloudKit returned too many Floria Vaults (\(count))"
        case .omittedRoot(let zone):
            "CloudKit omitted the Vault root result for zone \(zone)"
        case .couldNotReadRoot(let vaultID, let message):
            "Could not read Vault \(vaultID): \(message)"
        case .invalidRoot(let vaultID):
            "CloudKit returned an invalid root for Vault \(vaultID)"
        }
    }
}
