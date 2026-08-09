import Foundation
import XCTest

@testable import floria_menubar

@MainActor
final class CloudSyncViewModelTests: XCTestCase {
    func testUnavailableBuildCannotEnableICloudSync() async {
        let service = CloudSyncViewServiceStub(
            available: false,
            enabled: false,
            status: status(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            candidates: [])
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        await model.setEnabled(true)

        XCTAssertFalse(model.isAvailable)
        XCTAssertFalse(model.isEnabled)
        XCTAssertEqual(
            model.errorMessage,
            "This build of Floria is not configured for iCloud Sync. Install a CloudKit-enabled build, then try again.")
    }

    func testDiscoveryFiltersTheLibraryAlreadyActiveOnThisMac() async {
        let active = status(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        let other = CloudVaultCandidate(
            vaultID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            vaultDocumentBase64: "b3RoZXI=")
        let service = CloudSyncViewServiceStub(
            status: active,
            candidates: [
                CloudVaultCandidate(
                    vaultID: active.vaultID,
                    vaultDocumentBase64: "bG9jYWw="),
                other,
            ])
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        await model.discover()

        XCTAssertTrue(model.isEnabled)
        XCTAssertEqual(model.candidates, [other])
    }

    func testJoiningMacShowsTheRustSignedApprovalCode() async {
        let target = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        let request = SyncEnrollmentRequest(
            deviceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            deviceName: "Studio",
            requestedAt: "2026-08-08T12:00:00Z",
            fingerprint: "sha256:fixture",
            documentBase64: "cmVxdWVzdA==")
        let service = CloudSyncViewServiceStub(
            status: status(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            candidates: [],
            bootstrap: bootstrap(vaultID: target),
            enrollment: .request(request))
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        await model.join(
            CloudVaultCandidate(vaultID: target, vaultDocumentBase64: "dmF1bHQ="))

        XCTAssertEqual(model.enrollmentRequest, request)
        XCTAssertNil(model.errorMessage)
    }

    func testAlreadyApprovedLibraryRestartsDaemonBeforeSyncingTheTarget() async {
        let target = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        let restart = RestartProbe()
        let service = CloudSyncViewServiceStub(
            status: status(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            candidates: [],
            bootstrap: bootstrap(vaultID: target),
            enrollment: .alreadyEnrolled(
                deviceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
            activation: .ready(
                vaultID: target, keyGeneration: 1, restartRequired: true))
        let model = CloudSyncViewModel(
            service: service,
            restartDaemon: {
                await restart.record()
                await service.completeRestart(target)
            })

        await model.load()
        await model.join(
            CloudVaultCandidate(vaultID: target, vaultDocumentBase64: "dmF1bHQ="))

        let restartCount = await restart.count
        XCTAssertEqual(restartCount, 1)
        XCTAssertEqual(model.status?.vaultID, target)
        XCTAssertNil(model.enrollmentRequest)
        XCTAssertNil(model.errorMessage)
    }

    func testRevokingAMacUsesTheReviewedDeviceFingerprint() async {
        let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        let device = SyncVaultDevice(
            deviceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            deviceName: "Old Mac",
            fingerprint: "AB12-CD34-EF56",
            enrolledGeneration: 1,
            revokedGeneration: nil,
            isGenesis: false,
            isCurrent: false)
        let service = CloudSyncViewServiceStub(
            status: status(vaultID: vaultID),
            candidates: [],
            bootstrap: bootstrap(vaultID: vaultID),
            devices: [device])
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        await model.syncNow()
        await model.revoke(device)

        let revoked = await service.revokedDevices
        XCTAssertEqual(model.devices, [device])
        XCTAssertEqual(revoked, [device])
        XCTAssertNil(model.errorMessage)
    }

    func testFailedSyncReportsAnAuthenticatedCurrentMacRemoval() async {
        let vaultID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        let removed = SyncVaultDevice(
            deviceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            deviceName: "This Mac",
            fingerprint: "AB12-CD34-EF56",
            enrolledGeneration: 1,
            revokedGeneration: 2,
            isGenesis: false,
            isCurrent: true)
        let service = CloudSyncViewServiceStub(
            status: status(vaultID: vaultID),
            candidates: [],
            bootstrap: bootstrap(vaultID: vaultID),
            enrollment: .request(
                SyncEnrollmentRequest(
                    deviceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    deviceName: "This Mac",
                    requestedAt: "2026-08-09T12:00:00Z",
                    fingerprint: "98-76-54-32-10-AB",
                    documentBase64: "ZnJlc2g=")),
            devices: [removed],
            syncFailure: .activationRequired("Device has no envelope"))
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        await model.syncNow()

        XCTAssertEqual(model.devices, [removed])
        XCTAssertEqual(
            model.errorMessage,
            "This Mac was removed from the iCloud Library. Existing local data remains available, but new changes will not sync.")
        XCTAssertEqual(model.removedCurrentMac, removed)

        await model.requestAccessAgain()

        XCTAssertEqual(model.enrollmentRequest?.fingerprint, "98-76-54-32-10-AB")
        XCTAssertNil(model.removedCurrentMac)
        XCTAssertNil(model.errorMessage)
        let requestedAccessDevices = await service.requestedAccessDevices
        XCTAssertEqual(requestedAccessDevices, [removed])
    }

    func testAttachingProjectMakesItAvailableOnThisMac() async {
        let project = SyncedProject(
            id: "project-a", name: "Floria", defaultEnvironmentID: "development")
        let service = CloudSyncViewServiceStub(
            status: status(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            candidates: [],
            projectsWithoutLocalFolder: [project])
        let model = CloudSyncViewModel(service: service, restartDaemon: {})
        let directory = FileManager.default.temporaryDirectory

        await model.load()
        XCTAssertEqual(model.projectsWithoutLocalFolder, [project])

        await model.attach(project, at: directory)

        XCTAssertEqual(model.projectsWithoutLocalFolder, [])
        let attachedProjectIDs = await service.attachedProjectIDs
        XCTAssertEqual(attachedProjectIDs, [project.id])
        XCTAssertEqual(model.notice, "Floria is now available on this Mac.")
        XCTAssertNil(model.errorMessage)
    }

    func testLoadRestoresLastSuccessfulSyncAndPendingLibrarySetup() async {
        let pendingVaultID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        let lastSync = Date(timeIntervalSince1970: 1_787_000_000)
        let service = CloudSyncViewServiceStub(
            status: status(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            candidates: [],
            lastSuccessfulSyncAt: lastSync,
            pendingVaultID: pendingVaultID)
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()

        XCTAssertEqual(model.lastSuccessfulSyncAt, lastSync)
        XCTAssertEqual(model.pendingVaultID, pendingVaultID)
    }

    func testPendingLibrarySetupCanResumeAfterTheViewModelIsRecreated() async {
        let target = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        let request = SyncEnrollmentRequest(
            deviceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            deviceName: "Studio",
            requestedAt: "2026-08-08T12:00:00Z",
            fingerprint: "sha256:fixture",
            documentBase64: "cmVxdWVzdA==")
        let service = CloudSyncViewServiceStub(
            status: status(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            candidates: [],
            bootstrap: bootstrap(vaultID: target),
            enrollment: .request(request),
            pendingVaultID: target)
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        await model.resumePendingSetup()

        XCTAssertEqual(model.enrollmentRequest, request)
        XCTAssertEqual(model.pendingVaultID, target)
        XCTAssertNil(model.errorMessage)
    }

    func testSyncDoesNotClaimUpToDateWhileDomainChangesNeedAttention() async {
        let conflicted = SyncDomainStatus(
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            keyGeneration: 1,
            outboundTransactions: 1,
            inboundTransactions: 0,
            pendingTransactions: 0,
            conflictingEntities: 2,
            projectionPending: false)
        let service = CloudSyncViewServiceStub(
            status: conflicted,
            candidates: [],
            bootstrap: bootstrap(vaultID: conflicted.vaultID))
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        await model.syncNow()

        XCTAssertEqual(model.syncStatusSummary, "1 to send · 2 conflicts")
        XCTAssertEqual(
            model.syncAttentionMessage,
            "2 synced items have conflicting changes. Floria kept every version and did not choose one automatically.")
        XCTAssertNil(model.notice)
        XCTAssertNil(model.errorMessage)
    }

    func testSyncExplainsWhenChangesFromICloudWereAppliedLocally() async {
        let service = CloudSyncViewServiceStub(
            status: status(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            candidates: [],
            bootstrap: bootstrap(vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            appliedRemoteChanges: true)
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        await model.syncNow()

        XCTAssertEqual(model.notice, "Changes from iCloud were applied to this Mac.")
        XCTAssertNil(model.errorMessage)
    }

    func testReviewedConflictRequiresAnExplicitCandidateAndThenSyncsTheMerge() async {
        let entityID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        let local = SyncConflictCandidate(
            revisionID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            lifecycle: .active,
            kind: .secret,
            label: "Database password",
            versionID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            plaintextSize: 24,
            matchesLocalState: true)
        let remote = SyncConflictCandidate(
            revisionID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            lifecycle: .active,
            kind: .secret,
            label: "Database password",
            versionID: "ffffffff-ffff-4fff-8fff-ffffffffffff",
            plaintextSize: 28,
            matchesLocalState: false)
        let review = SyncConflictReview(entityID: entityID, candidates: [local, remote])
        let conflicted = SyncDomainStatus(
            vaultID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            keyGeneration: 1,
            outboundTransactions: 0,
            inboundTransactions: 0,
            pendingTransactions: 0,
            conflictingEntities: 1,
            projectionPending: false)
        let service = CloudSyncViewServiceStub(
            status: conflicted,
            candidates: [],
            conflicts: [review])
        let model = CloudSyncViewModel(service: service, restartDaemon: {})

        await model.load()
        XCTAssertEqual(model.conflicts, [review])

        await model.resolve(review, keeping: remote)

        XCTAssertTrue(model.conflicts.isEmpty)
        let resolved = await service.resolvedRevisions
        XCTAssertEqual(resolved.count, 1)
        XCTAssertEqual(resolved.first?.entityID, entityID)
        XCTAssertEqual(resolved.first?.revisionID, remote.revisionID)
        XCTAssertNil(model.errorMessage)
    }

    func testConflictCandidatesExposeAStableReviewSummary() {
        let candidate = SyncConflictCandidate(
            revisionID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            lifecycle: .active,
            kind: .secret,
            label: "Database password",
            versionID: "ffffffff-ffff-4fff-8fff-ffffffffffff",
            plaintextSize: 28,
            matchesLocalState: false)

        XCTAssertEqual(candidate.conflictSourceLabel, "From iCloud")
        XCTAssertEqual(candidate.conflictVersionLabel, "Version eeeeeeee")
        XCTAssertEqual(
            candidate.conflictConfirmationSummary,
            "“Database password” — From iCloud, Version eeeeeeee")
    }

    private func status(vaultID: String) -> SyncDomainStatus {
        SyncDomainStatus(
            vaultID: vaultID,
            keyGeneration: 1,
            outboundTransactions: 0,
            inboundTransactions: 0,
            pendingTransactions: 0,
            conflictingEntities: 0,
            projectionPending: false)
    }

    private func bootstrap(vaultID: String) -> SyncVaultBootstrap {
        SyncVaultBootstrap(
            vaultID: vaultID,
            vaultDocumentBase64: "dmF1bHQ=",
            deviceIdentities: [],
            enrollmentRequests: [],
            keyGenerations: [],
            generationEnvelopes: [])
    }
}

private actor RestartProbe {
    private(set) var count = 0

    func record() {
        count += 1
    }
}

private actor CloudSyncViewServiceStub: CloudSyncServicing {
    private let available: Bool
    private var enabled: Bool
    private var status: SyncDomainStatus
    private let candidates: [CloudVaultCandidate]
    private let bootstrap: SyncVaultBootstrap?
    private let enrollment: SyncEnrollmentPreparation
    private let activation: SyncVaultActivation
    private let devices: [SyncVaultDevice]
    private var conflicts: [SyncConflictReview]
    private let syncFailure: CloudRecordSyncSessionError?
    private let appliedRemoteChanges: Bool
    private let lastSuccessfulSync: Date?
    private var pendingVault: String?
    private var projectsWithoutLocalFolder: [SyncedProject]
    private var restartTarget: String?
    private(set) var revokedDevices = [SyncVaultDevice]()
    private(set) var requestedAccessDevices = [SyncVaultDevice]()
    private(set) var attachedProjectIDs = [String]()
    private(set) var resolvedRevisions = [(entityID: String, revisionID: String)]()

    init(
        available: Bool = true,
        enabled: Bool = true,
        status: SyncDomainStatus,
        candidates: [CloudVaultCandidate],
        bootstrap: SyncVaultBootstrap? = nil,
        enrollment: SyncEnrollmentPreparation = .alreadyEnrolled(deviceID: "local"),
        devices: [SyncVaultDevice] = [],
        conflicts: [SyncConflictReview] = [],
        activation: SyncVaultActivation? = nil,
        syncFailure: CloudRecordSyncSessionError? = nil,
        appliedRemoteChanges: Bool = false,
        projectsWithoutLocalFolder: [SyncedProject] = [],
        lastSuccessfulSyncAt: Date? = nil,
        pendingVaultID: String? = nil
    ) {
        self.available = available
        self.enabled = enabled
        self.status = status
        self.candidates = candidates
        self.bootstrap = bootstrap
        self.enrollment = enrollment
        self.devices = devices
        self.conflicts = conflicts
        self.syncFailure = syncFailure
        self.appliedRemoteChanges = appliedRemoteChanges
        self.projectsWithoutLocalFolder = projectsWithoutLocalFolder
        lastSuccessfulSync = lastSuccessfulSyncAt
        pendingVault = pendingVaultID
        self.activation = activation ?? .ready(
            vaultID: status.vaultID,
            keyGeneration: status.keyGeneration,
            restartRequired: false)
    }

    func completeRestart(_ vaultID: String) {
        restartTarget = vaultID
    }

    func isAvailable() async -> Bool { available }

    func isEnabled() async -> Bool { enabled }

    func setEnabled(_ enabled: Bool) async {
        self.enabled = enabled
    }

    func lastSuccessfulSyncAt() async -> Date? { lastSuccessfulSync }

    func pendingVaultID() async -> String? { pendingVault }

    func localStatus() async throws -> SyncDomainStatus? {
        if let restartTarget {
            status = SyncDomainStatus(
                vaultID: restartTarget,
                keyGeneration: status.keyGeneration,
                outboundTransactions: 0,
                inboundTransactions: 0,
                pendingTransactions: 0,
                conflictingEntities: 0,
                projectionPending: false)
            self.restartTarget = nil
        }
        return status
    }

    func reviewConflicts() async throws -> [SyncConflictReview] { conflicts }

    func resolveConflict(
        entityID: String,
        selectedRevisionID: String
    ) async throws -> SyncDomainStatus {
        resolvedRevisions.append((entityID, selectedRevisionID))
        conflicts.removeAll { $0.entityID == entityID }
        status = SyncDomainStatus(
            vaultID: status.vaultID,
            keyGeneration: status.keyGeneration,
            outboundTransactions: status.outboundTransactions + 1,
            inboundTransactions: status.inboundTransactions,
            pendingTransactions: status.pendingTransactions,
            conflictingEntities: conflicts.count,
            projectionPending: false)
        return status
    }

    func projectsWithoutLocalFolder() async throws -> [SyncedProject] {
        projectsWithoutLocalFolder
    }

    func attachProject(_ project: SyncedProject, at _: URL) async throws {
        attachedProjectIDs.append(project.id)
        projectsWithoutLocalFolder.removeAll { $0.id == project.id }
    }

    func syncNow() async throws -> CloudSyncOutcome {
        if let syncFailure { throw syncFailure }
        return CloudSyncOutcome(
            status: status,
            appliedRemoteChanges: appliedRemoteChanges)
    }

    func discoverVaults() async throws -> [CloudVaultCandidate] { candidates }

    func authenticateVault(_ vaultID: String) async throws -> SyncVaultBootstrap {
        guard let bootstrap, bootstrap.vaultID == vaultID else {
            throw CloudSyncServiceError.unconfiguredTestDependency
        }
        return bootstrap
    }

    func requestEnrollment(
        in _: SyncVaultBootstrap,
        deviceName _: String?,
        requestedAt _: String?
    ) async throws -> SyncEnrollmentPreparation {
        enrollment
    }

    func requestAccessAgain(
        in _: SyncVaultBootstrap,
        removedDevice: SyncVaultDevice,
        deviceName _: String?,
        requestedAt _: String?
    ) async throws -> SyncEnrollmentPreparation {
        requestedAccessDevices.append(removedDevice)
        return enrollment
    }

    func reviewEnrollments(
        in _: SyncVaultBootstrap
    ) async throws -> [SyncEnrollmentReview] {
        []
    }

    func approveEnrollment(
        _ _: SyncEnrollmentReview,
        in bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultBootstrap {
        bootstrap
    }

    func reviewDevices(in _: SyncVaultBootstrap) async throws -> [SyncVaultDevice] {
        devices
    }

    func revokeDevice(
        _ device: SyncVaultDevice,
        in bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultBootstrap {
        revokedDevices.append(device)
        return bootstrap
    }

    func activateVault(_ _: SyncVaultBootstrap) async throws -> SyncVaultActivation {
        activation
    }
}
