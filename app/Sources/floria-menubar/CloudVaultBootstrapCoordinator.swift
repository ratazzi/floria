import CloudKit
import Foundation

protocol VaultBootstrapControlling: Sendable {
    func recordSyncVaultBootstrap() async throws -> SyncVaultBootstrap
    func validateRecordSyncVaultBootstrap(
        _ bootstrap: SyncVaultBootstrap,
        expectedVaultID: String
    ) async throws -> SyncVaultBootstrap
}

extension ControlClient: VaultBootstrapControlling {}

protocol VaultEnrollmentControlling: Sendable {
    func prepareRecordSyncVaultEnrollment(
        bootstrap: SyncVaultBootstrap,
        deviceName: String?,
        requestedAt: String
    ) async throws -> SyncEnrollmentPreparation
    func reviewRecordSyncVaultEnrollments(
        bootstrap: SyncVaultBootstrap
    ) async throws -> [SyncEnrollmentReview]
    func approveRecordSyncVaultEnrollment(
        bootstrap: SyncVaultBootstrap,
        deviceID: String,
        expectedFingerprint: String
    ) async throws -> SyncVaultBootstrap
}

extension ControlClient: VaultEnrollmentControlling {}

protocol VaultActivationControlling: Sendable {
    func activateRecordSyncVault(
        bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultActivation
}

extension ControlClient: VaultActivationControlling {}

/// Accumulates one CloudKit lifecycle fetch without letting partial security state enter Rust's
/// entity pipeline. Only a complete candidate accepted by Rust becomes the next checkpoint.
actor CloudVaultBootstrapCoordinator {
    private let control: any VaultBootstrapControlling
    private let codec: CloudVaultBootstrapCodec
    private var acceptedBootstrap: SyncVaultBootstrap?
    private var fetchedRecords = [CKRecord.ID: CKRecord]()

    init(
        control: any VaultBootstrapControlling,
        vaultID: String,
        restoredBootstrap: SyncVaultBootstrap? = nil
    ) throws {
        self.control = control
        codec = try CloudVaultBootstrapCodec(vaultID: vaultID)
        acceptedBootstrap = restoredBootstrap
    }

    /// Capture the local authenticated snapshot immediately before an explicit upload.
    func outboundRecords() async throws -> [CKRecord] {
        let bootstrap = try await control.recordSyncVaultBootstrap()
        return try codec.records(for: bootstrap)
    }

    /// Keep lifecycle records out of the ordinary entity decoder. Per-record outer validation is
    /// immediate; signature and generation-chain validation waits until `finishFetch()`.
    func stageFetched(
        records: [CKRecord],
        deletedRecordIDs: [CKRecord.ID]
    ) throws -> CloudVaultFetchPartition {
        var domainRecords = [CKRecord]()
        var domainDeletedRecordIDs = [CKRecord.ID]()

        for recordID in deletedRecordIDs {
            if codec.owns(recordID) {
                throw CloudVaultBootstrapCoordinatorError.lifecycleRecordDeleted(
                    recordID.recordName)
            }
            domainDeletedRecordIDs.append(recordID)
        }
        for record in records {
            guard codec.owns(record) else {
                domainRecords.append(record)
                continue
            }
            _ = try codec.decode(record)
            if let previous = fetchedRecords[record.recordID],
               try !codec.equivalent(previous, record)
            {
                throw CloudVaultBootstrapCoordinatorError.lifecycleRecordChanged(
                    record.recordID.recordName)
            }
            fetchedRecords[record.recordID] = record
        }
        return CloudVaultFetchPartition(
            domainRecords: domainRecords,
            domainDeletedRecordIDs: domainDeletedRecordIDs)
    }

    /// Finish one zone fetch. A failed candidate remains untrusted and never replaces the last
    /// accepted checkpoint.
    @discardableResult
    func finishFetch() async throws -> SyncVaultBootstrap? {
        guard !fetchedRecords.isEmpty else {
            if let acceptedBootstrap {
                return try await reauthenticate(acceptedBootstrap)
            }
            return nil
        }

        var merged = [CKRecord.ID: CKRecord]()
        if let acceptedBootstrap {
            for record in try codec.records(for: acceptedBootstrap) {
                merged[record.recordID] = record
            }
        }
        for (recordID, fetched) in fetchedRecords {
            if let previous = merged[recordID],
               try !codec.equivalent(previous, fetched)
            {
                throw CloudVaultBootstrapCoordinatorError.lifecycleRecordChanged(
                    recordID.recordName)
            }
            merged[recordID] = fetched
        }

        let candidate = try codec.bootstrap(from: Array(merged.values))
        let validated = try await reauthenticate(candidate)
        acceptedBootstrap = validated
        fetchedRecords.removeAll(keepingCapacity: true)
        return validated
    }

    func cachedBootstrap() -> SyncVaultBootstrap? {
        acceptedBootstrap
    }

    /// Authentication proves that a remote lifecycle snapshot is internally valid. It does not
    /// prove that the current Store has the key generation needed to decrypt records published by
    /// that snapshot. Shared deterministic records must also agree byte-for-byte with local state.
    func ensureReadableByLocalStore(_ remote: SyncVaultBootstrap) async throws {
        let local = try await control.recordSyncVaultBootstrap()
        let localRecords = Dictionary(
            uniqueKeysWithValues: try codec.records(for: local).map { ($0.recordID, $0) })
        let remoteRecords = Dictionary(
            uniqueKeysWithValues: try codec.records(for: remote).map { ($0.recordID, $0) })

        for recordID in Set(localRecords.keys).intersection(remoteRecords.keys) {
            guard let localRecord = localRecords[recordID],
                  let remoteRecord = remoteRecords[recordID],
                  try codec.equivalent(localRecord, remoteRecord)
            else {
                throw CloudVaultBootstrapCoordinatorError.lifecycleRecordChanged(
                    recordID.recordName)
            }
        }

        let localGeneration = latestGeneration(in: local)
        let remoteGeneration = latestGeneration(in: remote)
        guard remoteGeneration <= localGeneration else {
            throw CloudVaultBootstrapCoordinatorError.newerGenerationRequiresActivation(
                local: localGeneration, remote: remoteGeneration)
        }
    }

    func resetTransportCache() {
        acceptedBootstrap = nil
        fetchedRecords.removeAll()
    }

    private func reauthenticate(_ bootstrap: SyncVaultBootstrap) async throws
        -> SyncVaultBootstrap
    {
        try await control.validateRecordSyncVaultBootstrap(
            bootstrap, expectedVaultID: codec.recordCodec.vaultID)
    }

    private func latestGeneration(in bootstrap: SyncVaultBootstrap) -> UInt32 {
        bootstrap.keyGenerations.compactMap { UInt32($0.route) }.max() ?? 0
    }
}

struct CloudVaultFetchPartition {
    let domainRecords: [CKRecord]
    let domainDeletedRecordIDs: [CKRecord.ID]
}

enum CloudVaultBootstrapCoordinatorError: Error, Equatable, LocalizedError {
    case lifecycleRecordDeleted(String)
    case lifecycleRecordChanged(String)
    case newerGenerationRequiresActivation(local: UInt32, remote: UInt32)

    var errorDescription: String? {
        switch self {
        case .lifecycleRecordDeleted(let name):
            "CloudKit deleted immutable Vault lifecycle record \(name)"
        case .lifecycleRecordChanged(let name):
            "CloudKit changed immutable Vault lifecycle record \(name)"
        case .newerGenerationRequiresActivation(let local, let remote):
            "Vault key generation \(remote) must be activated before this Mac can read it (current generation: \(local))"
        }
    }
}
