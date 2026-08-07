import Foundation
import XCTest

@testable import floria_menubar

@MainActor
final class CloudSyncViewModelTests: XCTestCase {
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
    private var enabled = true
    private var status: SyncDomainStatus
    private let candidates: [CloudVaultCandidate]
    private let bootstrap: SyncVaultBootstrap?
    private let enrollment: SyncEnrollmentPreparation
    private let activation: SyncVaultActivation
    private var restartTarget: String?

    init(
        status: SyncDomainStatus,
        candidates: [CloudVaultCandidate],
        bootstrap: SyncVaultBootstrap? = nil,
        enrollment: SyncEnrollmentPreparation = .alreadyEnrolled(deviceID: "local"),
        activation: SyncVaultActivation? = nil
    ) {
        self.status = status
        self.candidates = candidates
        self.bootstrap = bootstrap
        self.enrollment = enrollment
        self.activation = activation ?? .ready(
            vaultID: status.vaultID,
            keyGeneration: status.keyGeneration,
            restartRequired: false)
    }

    func completeRestart(_ vaultID: String) {
        restartTarget = vaultID
    }

    func isEnabled() async -> Bool { enabled }

    func setEnabled(_ enabled: Bool) async {
        self.enabled = enabled
    }

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

    func syncNow() async throws -> SyncDomainStatus { status }

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

    func activateVault(_ _: SyncVaultBootstrap) async throws -> SyncVaultActivation {
        activation
    }
}
