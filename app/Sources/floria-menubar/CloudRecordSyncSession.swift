import CloudKit
import Foundation

/// One explicitly-triggered CloudKit transport session.
///
/// Creating this value does not initialize `CKSyncEngine` and never starts
/// networking. `syncNow()` is the only entry point that touches CloudKit, which
/// preserves Floria's default no-network behavior.
final class CloudRecordSyncSession: NSObject, CKSyncEngineDelegate, @unchecked Sendable {
    private let codec: CloudRecordCodec
    private let database: CKDatabase
    private let stateStore: CloudSyncStateStore
    private let coordinator: CloudRecordSyncCoordinator
    private let bootstrapCodec: CloudVaultBootstrapCodec
    private let bootstrapCoordinator: CloudVaultBootstrapCoordinator
    private let sessionState: CloudRecordSyncSessionState
    private let restoredEngineState: CKSyncEngine.State.Serialization?

    private lazy var syncEngine: CKSyncEngine = {
        var configuration = CKSyncEngine.Configuration(
            database: database,
            stateSerialization: restoredEngineState,
            delegate: self)
        configuration.automaticallySync = false
        configuration.subscriptionID = "floria-vault-\(codec.vaultID)"
        return CKSyncEngine(configuration)
    }()

    init(
        database: CKDatabase,
        control: any CloudSyncControlling,
        supportDirectory: URL,
        vaultID: String
    ) throws {
        let codec = try CloudRecordCodec(vaultID: vaultID)
        let stateStore = CloudSyncStateStore(
            supportDirectory: supportDirectory, codec: codec)
        let restored = try stateStore.loadRecovering()

        self.codec = codec
        self.database = database
        self.stateStore = stateStore
        restoredEngineState = restored.engineState
        bootstrapCodec = try CloudVaultBootstrapCodec(vaultID: codec.vaultID)
        bootstrapCoordinator = try CloudVaultBootstrapCoordinator(
            control: control,
            vaultID: codec.vaultID,
            restoredBootstrap: restored.vaultBootstrap)
        sessionState = CloudRecordSyncSessionState(initialEngineState: restored.engineState)
        coordinator = CloudRecordSyncCoordinator(
            control: control,
            codec: codec,
            assetStager: CloudAssetStager(
                supportDirectory: supportDirectory, vaultID: codec.vaultID),
            restoredHeads: restored.heads)
        super.init()
    }

    func syncNow() async throws {
        let engine = syncEngine
        try await sessionState.prepareForManualSync()

        engine.state.add(pendingDatabaseChanges: [
            .saveZone(CKRecordZone(zoneID: codec.zoneID))
        ])
        try await engine.sendChanges(.init(scope: .zoneIDs([codec.zoneID])))
        try await throwRecordedFailure()

        try await engine.fetchChanges(.init(scope: .zoneIDs([codec.zoneID])))
        try await throwRecordedFailure()

        let bootstrapRecords = try await bootstrapCoordinator.outboundRecords()
        guard bootstrapRecords.count <= CloudOutboundPlanner.cloudKitRecordLimit else {
            throw CloudRecordSyncSessionError.damaged(
                "Vault lifecycle exceeds the CloudKit atomic record limit")
        }
        try await send(.bootstrap(bootstrapRecords), through: engine)
        _ = try await bootstrapCoordinator.stageFetched(
            records: bootstrapRecords, deletedRecordIDs: [])
        if let accepted = try await bootstrapCoordinator.finishFetch() {
            try await bootstrapCoordinator.ensureReadableByLocalStore(accepted)
        }
        try await saveLatestCheckpoint()

        while true {
            switch try await coordinator.nextOutboundAction() {
            case .idle:
                return

            case .settleConflict:
                continue

            case .fetchHeads(_, let recordIDs):
                try await fetchHeads(recordIDs)

            case .saveObjects(let records):
                try await send(.objects(records), through: engine)

            case .saveCommit(let commitID, let records):
                try await send(
                    .commit(commitID: commitID, records: records), through: engine)
            }
        }
    }

    func handleEvent(_ event: CKSyncEngine.Event, syncEngine: CKSyncEngine) async {
        do {
            switch event {
            case .stateUpdate(let update):
                guard await sessionState.failure == nil else { return }
                if let checkpoint = await sessionState.observeEngineState(
                    update.stateSerialization)
                {
                    try await saveCheckpoint(engineState: checkpoint)
                }

            case .accountChange:
                try stateStore.resetTransportState()
                await coordinator.resetTransportCache()
                await bootstrapCoordinator.resetTransportCache()
                await sessionState.resetTransportCache()
                await sessionState.record(
                    .accountChanged("The iCloud account changed during synchronization"))

            case .fetchedDatabaseChanges(let changes):
                try validateDatabaseChanges(changes)

            case .fetchedRecordZoneChanges(let changes):
                let partition = try await bootstrapCoordinator.stageFetched(
                    records: changes.modifications.map(\.record),
                    deletedRecordIDs: changes.deletions.map(\.recordID))
                try await sessionState.stageFetchedDomain(partition)

            case .willFetchRecordZoneChanges(let changes):
                guard changes.zoneID == codec.zoneID else {
                    throw CloudRecordSyncSessionError.damaged(
                        "CloudKit fetched an unexpected Vault zone")
                }
                try await sessionState.beginZoneFetch()

            case .didFetchRecordZoneChanges(let changes):
                guard changes.zoneID == codec.zoneID else {
                    throw CloudRecordSyncSessionError.damaged(
                        "CloudKit finished an unexpected Vault zone")
                }
                if let error = changes.error {
                    throw CloudRecordSyncSessionError.cloudKit(
                        "Could not fetch Vault records: \(error.localizedDescription)")
                }
                let accepted = try await bootstrapCoordinator.finishFetch()
                if let accepted {
                    try await bootstrapCoordinator.ensureReadableByLocalStore(accepted)
                }
                let domain = try await sessionState.stagedFetchedDomain()
                if accepted == nil,
                   (!domain.domainRecords.isEmpty || !domain.domainDeletedRecordIDs.isEmpty)
                {
                    throw CloudRecordSyncSessionError.damaged(
                        "CloudKit returned Vault records without an authenticated lifecycle")
                }
                _ = try await coordinator.applyInbound(
                    records: domain.domainRecords,
                    deletedRecordIDs: domain.domainDeletedRecordIDs,
                    observedAt: Self.timestamp())
                let checkpoint = try await sessionState.commitZoneFetch()
                try await saveCheckpoint(engineState: checkpoint)

            case .sentDatabaseChanges(let changes):
                if let failure = changes.failedZoneSaves.first {
                    throw CloudRecordSyncSessionError.cloudKit(
                        "Could not create Vault zone: \(failure.error.localizedDescription)")
                }
                if !changes.failedZoneDeletes.isEmpty || !changes.deletedZoneIDs.isEmpty {
                    throw CloudRecordSyncSessionError.damaged(
                        "CloudKit unexpectedly deleted the Floria Vault zone")
                }

            case .sentRecordZoneChanges(let changes):
                try await handleSentRecords(changes, syncEngine: syncEngine)

            case .willFetchChanges, .didFetchChanges,
                .willSendChanges, .didSendChanges:
                break

            @unknown default:
                break
            }
        } catch let error as CloudRecordSyncSessionError {
            await sessionState.record(error)
        } catch let error as CloudVaultBootstrapCoordinatorError {
            switch error {
            case .newerGenerationRequiresActivation:
                await sessionState.record(.activationRequired(error.localizedDescription))
            case .lifecycleRecordDeleted, .lifecycleRecordChanged:
                await sessionState.record(.damaged(error.localizedDescription))
            }
        } catch let error as CloudVaultBootstrapCodecError {
            await sessionState.record(.damaged(error.localizedDescription))
        } catch {
            await sessionState.record(.transport(error.localizedDescription))
        }
    }

    func nextRecordZoneChangeBatch(
        _ context: CKSyncEngine.SendChangesContext,
        syncEngine: CKSyncEngine
    ) async -> CKSyncEngine.RecordZoneChangeBatch? {
        guard let phase = await sessionState.phase else { return nil }
        let pending = syncEngine.state.pendingRecordZoneChanges.filter {
            context.options.scope.contains($0)
        }
        let pendingIDs = Set(pending.compactMap { change -> CKRecord.ID? in
            guard case .saveRecord(let recordID) = change else { return nil }
            return recordID
        })
        let records = phase.records.filter { pendingIDs.contains($0.recordID) }
        guard !records.isEmpty else { return nil }
        return CKSyncEngine.RecordZoneChangeBatch(
            recordsToSave: records,
            atomicByZone: phase.atomicByZone)
    }

    private func send(_ phase: CloudSendPhase, through engine: CKSyncEngine) async throws {
        try await sessionState.begin(phase)
        let pending = phase.records.map {
            CKSyncEngine.PendingRecordZoneChange.saveRecord($0.recordID)
        }
        engine.state.add(pendingRecordZoneChanges: pending)
        do {
            try await engine.sendChanges(
                .init(scope: .recordIDs(phase.records.map(\.recordID))))
        } catch {
            await finish(phase, syncEngine: engine)
            throw error
        }
        try await throwRecordedFailure()
        guard await sessionState.phase == nil else {
            throw CloudRecordSyncSessionError.retryPending
        }
    }

    private func handleSentRecords(
        _ changes: CKSyncEngine.Event.SentRecordZoneChanges,
        syncEngine: CKSyncEngine
    ) async throws {
        guard let phase = await sessionState.phase else {
            if changes.savedRecords.isEmpty && changes.failedRecordSaves.isEmpty { return }
            throw CloudRecordSyncSessionError.damaged(
                "CloudKit returned a record batch that Floria did not send")
        }
        let failures = changes.failedRecordSaves.map {
            CloudRecordSaveFailure(
                record: $0.record,
                code: $0.error.code,
                serverRecord: $0.error.serverRecord)
        }
        let resolution = try CloudSentBatchResolver(
            codec: codec, bootstrapCodec: bootstrapCodec
        ).resolve(
            phase: phase,
            savedRecords: changes.savedRecords,
            failures: failures)

        switch resolution {
        case .bootstrapAccepted:
            await finish(phase, syncEngine: syncEngine)

        case .objectsVerified(let records):
            try await coordinator.markObjectsVerified(records)
            await finish(phase, syncEngine: syncEngine)

        case .commitAccepted(let commitID, let heads):
            await coordinator.mergeHeads(heads)
            _ = try await coordinator.settle(commitID: commitID, disposition: .accepted)
            await finish(phase, syncEngine: syncEngine)

        case .commitConflict(let commitID, _):
            let serverHeads = try failures.compactMap { failure -> (String, CKRecord)? in
                guard let record = failure.serverRecord,
                      record.recordType == CloudRecordCodec.RecordType.head,
                      case .head(let entityID, let head) = try codec.decode(record)
                else { return nil }
                return (entityID, head)
            }
            var fetchedHeads = [String: CKRecord]()
            for (entityID, head) in serverHeads {
                fetchedHeads[entityID] = head
            }
            await coordinator.mergeHeads(fetchedHeads)
            _ = try await coordinator.settle(commitID: commitID, disposition: .conflict)
            await finish(phase, syncEngine: syncEngine)

        case .retry:
            await finish(phase, syncEngine: syncEngine)
            await sessionState.record(.retryPending)

        case .damaged(let message):
            throw CloudRecordSyncSessionError.damaged(message)
        }
    }

    private func finish(_ phase: CloudSendPhase, syncEngine: CKSyncEngine) async {
        syncEngine.state.remove(pendingRecordZoneChanges: phase.records.map {
            .saveRecord($0.recordID)
        })
        await sessionState.finish(phase)
    }

    private func fetchHeads(_ recordIDs: [CKRecord.ID]) async throws {
        let results = try await database.records(for: recordIDs)
        var records = [CKRecord]()
        for recordID in recordIDs {
            guard let result = results[recordID] else {
                throw CloudRecordSyncSessionError.transport(
                    "CloudKit omitted head \(recordID.recordName)")
            }
            switch result {
            case .success(let record):
                records.append(record)
            case .failure(let error):
                throw CloudRecordSyncSessionError.cloudKit(
                    "Could not fetch head \(recordID.recordName): \(error.localizedDescription)")
            }
        }
        _ = try await coordinator.applyInbound(
            records: records, deletedRecordIDs: [], observedAt: Self.timestamp())
    }

    private func validateDatabaseChanges(
        _ changes: CKSyncEngine.Event.FetchedDatabaseChanges
    ) throws {
        if changes.deletions.contains(where: { $0.zoneID == codec.zoneID }) {
            throw CloudRecordSyncSessionError.damaged(
                "The Floria Vault zone was deleted remotely")
        }
        // Other Vault zones may coexist in this private database. Individual
        // records are still strictly rejected unless they belong to this zone.
    }

    private func throwRecordedFailure() async throws {
        if let failure = await sessionState.failure { throw failure }
    }

    private func saveLatestCheckpoint() async throws {
        try await saveCheckpoint(engineState: await sessionState.latestEngineState())
    }

    private func saveCheckpoint(
        engineState: CKSyncEngine.State.Serialization?
    ) async throws {
        try stateStore.save(
            engineState: engineState,
            heads: await coordinator.cachedHeads(),
            vaultBootstrap: await bootstrapCoordinator.cachedBootstrap())
    }

    private static func timestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }
}

actor CloudRecordSyncSessionState {
    private(set) var phase: CloudSendPhase?
    private(set) var failure: CloudRecordSyncSessionError?
    private var fetchInProgress = false
    private var fetchedDomainRecords = [CKRecord.ID: CKRecord]()
    private var fetchedDomainDeletedRecordIDs = Set<CKRecord.ID>()
    private var latestState: CKSyncEngine.State.Serialization?

    init(initialEngineState: CKSyncEngine.State.Serialization?) {
        latestState = initialEngineState
    }

    func begin(_ newPhase: CloudSendPhase) throws {
        guard phase == nil else { throw CloudRecordSyncSessionError.sendAlreadyInProgress }
        phase = newPhase
    }

    func finish(_ completed: CloudSendPhase) {
        guard phase?.records.map(\.recordID) == completed.records.map(\.recordID) else { return }
        phase = nil
    }

    func record(_ error: CloudRecordSyncSessionError) {
        if failure == nil { failure = error }
    }

    func beginZoneFetch() throws {
        guard !fetchInProgress else {
            throw CloudRecordSyncSessionError.damaged(
                "CloudKit began a second Vault fetch before completing the first")
        }
        fetchInProgress = true
        fetchedDomainRecords.removeAll(keepingCapacity: true)
        fetchedDomainDeletedRecordIDs.removeAll(keepingCapacity: true)
    }

    func stageFetchedDomain(_ partition: CloudVaultFetchPartition) throws {
        guard fetchInProgress else {
            throw CloudRecordSyncSessionError.damaged(
                "CloudKit returned Vault records outside a fetch boundary")
        }
        for record in partition.domainRecords {
            guard fetchedDomainRecords[record.recordID] == nil,
                  !fetchedDomainDeletedRecordIDs.contains(record.recordID)
            else {
                throw CloudRecordSyncSessionError.damaged(
                    "CloudKit returned duplicate changes for \(record.recordID.recordName)")
            }
            fetchedDomainRecords[record.recordID] = record
        }
        for recordID in partition.domainDeletedRecordIDs {
            guard fetchedDomainRecords[recordID] == nil,
                  fetchedDomainDeletedRecordIDs.insert(recordID).inserted
            else {
                throw CloudRecordSyncSessionError.damaged(
                    "CloudKit returned duplicate changes for \(recordID.recordName)")
            }
        }
    }

    func stagedFetchedDomain() throws -> CloudVaultFetchPartition {
        guard fetchInProgress else {
            throw CloudRecordSyncSessionError.damaged(
                "CloudKit finished a Vault fetch that was not active")
        }
        return CloudVaultFetchPartition(
            domainRecords: Array(fetchedDomainRecords.values),
            domainDeletedRecordIDs: Array(fetchedDomainDeletedRecordIDs))
    }

    func commitZoneFetch() throws -> CKSyncEngine.State.Serialization? {
        guard fetchInProgress else {
            throw CloudRecordSyncSessionError.damaged(
                "CloudKit finished a Vault fetch that was not active")
        }
        fetchInProgress = false
        fetchedDomainRecords.removeAll(keepingCapacity: true)
        fetchedDomainDeletedRecordIDs.removeAll(keepingCapacity: true)
        return latestState
    }

    /// State tokens observed while a fetch is in progress are retained in memory but not made
    /// durable until lifecycle and entity application both succeed.
    func observeEngineState(
        _ state: CKSyncEngine.State.Serialization
    ) -> CKSyncEngine.State.Serialization? {
        latestState = state
        return fetchInProgress ? nil : state
    }

    func latestEngineState() -> CKSyncEngine.State.Serialization? {
        latestState
    }

    func resetTransportCache() {
        phase = nil
        fetchInProgress = false
        fetchedDomainRecords.removeAll()
        fetchedDomainDeletedRecordIDs.removeAll()
        latestState = nil
    }

    func prepareForManualSync() throws {
        switch failure {
        case nil:
            return
        case .retryPending:
            failure = nil
        case .some(let failure):
            // An inbound or account failure may have advanced only the engine's
            // in-memory token. Reusing it could skip data deliberately omitted
            // from the durable checkpoint, so recovery requires a new session.
            throw failure
        }
    }
}

enum CloudRecordSyncSessionError: Error, Equatable, LocalizedError {
    case activationRequired(String)
    case accountChanged(String)
    case cloudKit(String)
    case damaged(String)
    case transport(String)
    case retryPending
    case sendAlreadyInProgress

    var errorDescription: String? {
        switch self {
        case .activationRequired(let message), .accountChanged(let message),
            .cloudKit(let message), .damaged(let message), .transport(let message):
            message
        case .retryPending:
            "CloudKit has retained this batch for a later retry"
        case .sendAlreadyInProgress:
            "A CloudKit send batch is already in progress"
        }
    }
}
