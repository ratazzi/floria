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
}

struct CloudVaultFetchPartition {
    let domainRecords: [CKRecord]
    let domainDeletedRecordIDs: [CKRecord.ID]
}

enum CloudVaultBootstrapCoordinatorError: Error, Equatable {
    case lifecycleRecordDeleted(String)
    case lifecycleRecordChanged(String)
}
