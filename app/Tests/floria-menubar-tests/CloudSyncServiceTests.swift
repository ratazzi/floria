import Foundation
import XCTest

@testable import floria_menubar

final class CloudSyncServiceTests: XCTestCase {
    func testCloudKitIsNotConstructedUntilEnabledSyncNow() async throws {
        let suiteName = "floria-cloud-sync-tests-\(UUID().uuidString)"
        let preferences = CloudSyncPreferences(suiteName: suiteName)
        let control = CloudSyncControlStub(status: status())
        let session = CloudSyncSessionStub()
        let factory = CloudSyncFactoryProbe(session: session)
        let service = CloudSyncService(
            control: control,
            supportDirectory: FileManager.default.temporaryDirectory,
            preferences: preferences,
            sessionFactory: { control, supportDirectory, vaultID in
                try factory.make(
                    control: control,
                    supportDirectory: supportDirectory,
                    vaultID: vaultID)
            })
        defer { UserDefaults(suiteName: suiteName)?.removePersistentDomain(forName: suiteName) }

        let initiallyEnabled = await service.isEnabled()
        let disabledStatus = try await service.localStatus()
        let disabledStatusCount = await control.statusCount
        XCTAssertFalse(initiallyEnabled)
        XCTAssertNil(disabledStatus)
        XCTAssertEqual(factory.count, 0)
        XCTAssertEqual(disabledStatusCount, 0)

        await service.setEnabled(true)
        let enabled = await service.isEnabled()
        XCTAssertTrue(enabled)
        XCTAssertEqual(factory.count, 0)

        let result = try await service.syncNow()
        let syncCount = await session.syncCount
        let statusCount = await control.statusCount
        XCTAssertEqual(result, status())
        XCTAssertEqual(factory.count, 1)
        XCTAssertEqual(syncCount, 1)
        XCTAssertEqual(statusCount, 2)
    }

    func testDisabledSyncNowDoesNotTouchRustOrCloudKit() async throws {
        let suiteName = "floria-cloud-sync-tests-\(UUID().uuidString)"
        let control = CloudSyncControlStub(status: status())
        let factory = CloudSyncFactoryProbe(session: CloudSyncSessionStub())
        let service = CloudSyncService(
            control: control,
            supportDirectory: FileManager.default.temporaryDirectory,
            preferences: CloudSyncPreferences(suiteName: suiteName),
            sessionFactory: { control, supportDirectory, vaultID in
                try factory.make(
                    control: control,
                    supportDirectory: supportDirectory,
                    vaultID: vaultID)
            })
        defer { UserDefaults(suiteName: suiteName)?.removePersistentDomain(forName: suiteName) }

        do {
            _ = try await service.syncNow()
            XCTFail("Expected disabled sync to fail locally")
        } catch let error as CloudSyncServiceError {
            XCTAssertEqual(error, .disabled)
        }
        let statusCount = await control.statusCount
        XCTAssertEqual(factory.count, 0)
        XCTAssertEqual(statusCount, 0)
    }

    private func status() -> SyncDomainStatus {
        SyncDomainStatus(
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            keyGeneration: 1,
            outboundTransactions: 0,
            inboundTransactions: 0,
            pendingTransactions: 0,
            conflictingEntities: 0,
            projectionPending: false)
    }
}

private final class CloudSyncFactoryProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let session: any CloudSyncSessionRunning
    private var constructions = 0

    init(session: any CloudSyncSessionRunning) {
        self.session = session
    }

    var count: Int {
        lock.withLock { constructions }
    }

    func make(
        control _: any CloudSyncControlling,
        supportDirectory _: URL,
        vaultID _: String
    ) throws -> any CloudSyncSessionRunning {
        lock.withLock { constructions += 1 }
        return session
    }
}

private actor CloudSyncSessionStub: CloudSyncSessionRunning {
    private(set) var syncCount = 0

    func syncNow() async throws {
        syncCount += 1
    }
}

private actor CloudSyncControlStub: CloudSyncControlling {
    private let status: SyncDomainStatus
    private(set) var statusCount = 0

    init(status: SyncDomainStatus) {
        self.status = status
    }

    func recordSyncStatus() async throws -> SyncDomainStatus {
        statusCount += 1
        return status
    }

    func recordSyncVaultBootstrap() async throws -> SyncVaultBootstrap {
        throw CloudSyncServiceError.disabled
    }

    func validateRecordSyncVaultBootstrap(
        _: SyncVaultBootstrap,
        expectedVaultID _: String
    ) async throws -> SyncVaultBootstrap {
        throw CloudSyncServiceError.disabled
    }

    func nextRecordSyncOutbound(limit _: Int) async throws -> SyncOutboundBatch {
        throw CloudSyncServiceError.disabled
    }

    func settleRecordSyncOutbound(_: [SyncDeliveryOutcome]) async throws
        -> SyncSettlementReport
    {
        throw CloudSyncServiceError.disabled
    }

    func applyRecordSyncInbound(_: SyncInboundBatch, observedAt _: String) async throws
        -> SyncInboundReport
    {
        throw CloudSyncServiceError.disabled
    }
}
