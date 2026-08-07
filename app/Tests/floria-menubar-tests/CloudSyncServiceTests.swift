import CloudKit
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

    func testVaultDiscoveryAndAuthenticationAreExplicitAndLazilyConstructed() async throws {
        let suiteName = "floria-cloud-sync-tests-\(UUID().uuidString)"
        let preferences = CloudSyncPreferences(suiteName: suiteName)
        preferences.setEnabled(true)
        let control = CloudSyncControlStub(status: status())
        let discovery = CloudVaultDiscoveryStub(
            candidates: [
                CloudVaultCandidate(
                    vaultID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    vaultDocumentBase64: "dmF1bHQ="),
            ])
        let bootstrap = SyncVaultBootstrap(
            vaultID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            vaultDocumentBase64: "dmF1bHQ=",
            deviceIdentities: [],
            enrollmentRequests: [],
            keyGenerations: [],
            generationEnvelopes: [])
        let loader = CloudVaultLifecycleLoaderStub(bootstrap: bootstrap)
        let discoveryFactory = CloudVaultDiscoveryFactoryProbe(discovery: discovery)
        let loaderFactory = CloudVaultLifecycleFactoryProbe(loader: loader)
        let service = CloudSyncService(
            control: control,
            supportDirectory: FileManager.default.temporaryDirectory,
            preferences: preferences,
            sessionFactory: { _, _, _ in CloudSyncSessionStub() },
            discoveryFactory: { try discoveryFactory.make() },
            lifecycleLoaderFactory: { try loaderFactory.make() })
        defer { UserDefaults(suiteName: suiteName)?.removePersistentDomain(forName: suiteName) }

        XCTAssertEqual(discoveryFactory.count, 0)
        XCTAssertEqual(loaderFactory.count, 0)

        let first = try await service.discoverVaults()
        let second = try await service.discoverVaults()
        let authenticated = try await service.authenticateVault(bootstrap.vaultID)
        let discoveryCalls = await discovery.callCount
        let loaderVaultIDs = await loader.vaultIDs

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.map(\.vaultID), [bootstrap.vaultID])
        XCTAssertEqual(authenticated, bootstrap)
        XCTAssertEqual(discoveryFactory.count, 1)
        XCTAssertEqual(loaderFactory.count, 1)
        XCTAssertEqual(discoveryCalls, 2)
        XCTAssertEqual(loaderVaultIDs, [bootstrap.vaultID])
    }

    func testDisabledVaultDiscoveryConstructsNoCloudKitDependency() async throws {
        let suiteName = "floria-cloud-sync-tests-\(UUID().uuidString)"
        let factory = CloudVaultDiscoveryFactoryProbe(
            discovery: CloudVaultDiscoveryStub(candidates: []))
        let service = CloudSyncService(
            control: CloudSyncControlStub(status: status()),
            supportDirectory: FileManager.default.temporaryDirectory,
            preferences: CloudSyncPreferences(suiteName: suiteName),
            sessionFactory: { _, _, _ in CloudSyncSessionStub() },
            discoveryFactory: { try factory.make() })
        defer { UserDefaults(suiteName: suiteName)?.removePersistentDomain(forName: suiteName) }

        do {
            _ = try await service.discoverVaults()
            XCTFail("Expected disabled discovery to fail locally")
        } catch let error as CloudSyncServiceError {
            XCTAssertEqual(error, .disabled)
        }
        XCTAssertEqual(factory.count, 0)
    }

    func testEnrollmentRequestIsExplicitAndUsesTheAuthenticatedTargetVault() async throws {
        let suiteName = "floria-cloud-sync-tests-\(UUID().uuidString)"
        let preferences = CloudSyncPreferences(suiteName: suiteName)
        preferences.setEnabled(true)
        let control = CloudSyncControlStub(status: status())
        let publisher = CloudSyncEnrollmentPublisherStub()
        let factory = CloudEnrollmentPublisherFactoryProbe(publisher: publisher)
        let bootstrap = SyncVaultBootstrap(
            vaultID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            vaultDocumentBase64: "dmF1bHQ=", deviceIdentities: [], enrollmentRequests: [],
            keyGenerations: [], generationEnvelopes: [])
        let service = CloudSyncService(
            control: control,
            supportDirectory: FileManager.default.temporaryDirectory,
            preferences: preferences,
            sessionFactory: { _, _, _ in CloudSyncSessionStub() },
            enrollmentPublisherFactory: { try factory.make() })
        defer { UserDefaults(suiteName: suiteName)?.removePersistentDomain(forName: suiteName) }

        XCTAssertEqual(factory.count, 0)
        let result = try await service.requestEnrollment(
            in: bootstrap, deviceName: "Studio", requestedAt: "2026-08-08T12:00:00Z")
        guard case .request(let request) = result else {
            return XCTFail("Expected an enrollment request")
        }
        let record = await publisher.record
        XCTAssertEqual(factory.count, 1)
        XCTAssertEqual(record?.recordID.zoneID, try CloudRecordCodec(vaultID: bootstrap.vaultID).zoneID)
        XCTAssertEqual(request.deviceName, "Studio")
    }

    func testDifferentVaultActivationBlocksSyncUntilDaemonReportsTheTargetVault() async throws {
        let suiteName = "floria-cloud-sync-tests-\(UUID().uuidString)"
        let preferences = CloudSyncPreferences(suiteName: suiteName)
        preferences.setEnabled(true)
        let targetVaultID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        let control = CloudSyncControlStub(
            status: status(),
            activation: .ready(
                vaultID: targetVaultID, keyGeneration: 2, restartRequired: true))
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
        let bootstrap = SyncVaultBootstrap(
            vaultID: targetVaultID,
            vaultDocumentBase64: "dmF1bHQ=",
            deviceIdentities: [], enrollmentRequests: [], keyGenerations: [],
            generationEnvelopes: [])
        defer { UserDefaults(suiteName: suiteName)?.removePersistentDomain(forName: suiteName) }

        let activation = try await service.activateVault(bootstrap)
        XCTAssertEqual(
            activation,
            .ready(vaultID: targetVaultID, keyGeneration: 2, restartRequired: true))

        do {
            _ = try await service.syncNow()
            XCTFail("Expected sync to wait for daemon restart")
        } catch let error as CloudSyncServiceError {
            XCTAssertEqual(error, .restartRequired(vaultID: targetVaultID))
        }
        XCTAssertEqual(factory.count, 0)

        await control.setStatus(
            SyncDomainStatus(
                vaultID: targetVaultID,
                keyGeneration: 2,
                outboundTransactions: 0,
                inboundTransactions: 0,
                pendingTransactions: 0,
                conflictingEntities: 0,
                projectionPending: false))
        let status = try await service.syncNow()
        XCTAssertEqual(status.vaultID, targetVaultID)
        XCTAssertEqual(factory.vaultIDs, [targetVaultID])
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
    private var constructedVaultIDs = [String]()

    init(session: any CloudSyncSessionRunning) {
        self.session = session
    }

    var count: Int {
        lock.withLock { constructions }
    }

    var vaultIDs: [String] {
        lock.withLock { constructedVaultIDs }
    }

    func make(
        control _: any CloudSyncControlling,
        supportDirectory _: URL,
        vaultID: String
    ) throws -> any CloudSyncSessionRunning {
        lock.withLock {
            constructions += 1
            constructedVaultIDs.append(vaultID)
        }
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
    private var status: SyncDomainStatus
    private let activation: SyncVaultActivation
    private(set) var statusCount = 0

    init(
        status: SyncDomainStatus,
        activation: SyncVaultActivation? = nil
    ) {
        self.status = status
        self.activation = activation ?? .ready(
            vaultID: status.vaultID,
            keyGeneration: status.keyGeneration,
            restartRequired: false)
    }

    func setStatus(_ status: SyncDomainStatus) {
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

    func prepareRecordSyncVaultEnrollment(
        bootstrap _: SyncVaultBootstrap,
        deviceName: String?,
        requestedAt: String
    ) async throws -> SyncEnrollmentPreparation {
        .request(
            SyncEnrollmentRequest(
                deviceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                deviceName: deviceName,
                requestedAt: requestedAt,
                fingerprint: "sha256:fixture",
                documentBase64: "cmVxdWVzdA=="))
    }

    func reviewRecordSyncVaultEnrollments(
        bootstrap _: SyncVaultBootstrap
    ) async throws -> [SyncEnrollmentReview] {
        []
    }

    func approveRecordSyncVaultEnrollment(
        bootstrap: SyncVaultBootstrap,
        deviceID _: String,
        expectedFingerprint _: String
    ) async throws -> SyncVaultBootstrap {
        bootstrap
    }

    func activateRecordSyncVault(
        bootstrap _: SyncVaultBootstrap
    ) async throws -> SyncVaultActivation {
        activation
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

private actor CloudSyncEnrollmentPublisherStub: CloudVaultEnrollmentPublishing {
    private(set) var record: CKRecord?

    func create(_ record: CKRecord) async throws -> CloudVaultEnrollmentCreateResult {
        self.record = record
        return .saved(record)
    }
}

private final class CloudEnrollmentPublisherFactoryProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let publisher: any CloudVaultEnrollmentPublishing
    private var constructions = 0

    init(publisher: any CloudVaultEnrollmentPublishing) {
        self.publisher = publisher
    }

    var count: Int { lock.withLock { constructions } }

    func make() throws -> any CloudVaultEnrollmentPublishing {
        lock.withLock { constructions += 1 }
        return publisher
    }
}

private actor CloudVaultDiscoveryStub: CloudVaultDiscovering {
    private let candidates: [CloudVaultCandidate]
    private(set) var callCount = 0

    init(candidates: [CloudVaultCandidate]) {
        self.candidates = candidates
    }

    func discover() async throws -> [CloudVaultCandidate] {
        callCount += 1
        return candidates
    }
}

private actor CloudVaultLifecycleLoaderStub: CloudVaultLifecycleLoading {
    private let bootstrap: SyncVaultBootstrap
    private(set) var vaultIDs = [String]()

    init(bootstrap: SyncVaultBootstrap) {
        self.bootstrap = bootstrap
    }

    func loadAndAuthenticate(vaultID: String) async throws -> SyncVaultBootstrap {
        vaultIDs.append(vaultID)
        return bootstrap
    }
}

private final class CloudVaultDiscoveryFactoryProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let discovery: any CloudVaultDiscovering
    private var constructions = 0

    init(discovery: any CloudVaultDiscovering) {
        self.discovery = discovery
    }

    var count: Int {
        lock.withLock { constructions }
    }

    func make() throws -> any CloudVaultDiscovering {
        lock.withLock { constructions += 1 }
        return discovery
    }
}

private final class CloudVaultLifecycleFactoryProbe: @unchecked Sendable {
    private let lock = NSLock()
    private let loader: any CloudVaultLifecycleLoading
    private var constructions = 0

    init(loader: any CloudVaultLifecycleLoading) {
        self.loader = loader
    }

    var count: Int {
        lock.withLock { constructions }
    }

    func make() throws -> any CloudVaultLifecycleLoading {
        lock.withLock { constructions += 1 }
        return loader
    }
}
