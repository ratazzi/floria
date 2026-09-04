import Darwin
import XCTest
@testable import floria_menubar

final class MacFuseSetupTests: XCTestCase {
    func testKernelLoaderRunsBeforeReadinessCanBecomeTrue() {
        var ready = false
        var operations: [String] = []
        let backend = MacFuseKernelBackend(
            isReady: {
                operations.append("probe")
                return ready
            },
            inspectLoader: {
                operations.append("inspect")
                return .trustedFixture
            },
            runLoader: {
                operations.append("load")
                ready = true
                return 0
            })

        XCTAssertEqual(backend.ensureLoaded(), .ready)
        XCTAssertEqual(operations, ["probe", "inspect", "load", "probe"])
    }

    func testReadyKernelSkipsThePrivilegedLoader() {
        var loaderRan = false
        let backend = MacFuseKernelBackend(
            isReady: { true },
            inspectLoader: { .trustedFixture },
            runLoader: {
                loaderRan = true
                return 0
            })

        XCTAssertEqual(backend.ensureLoaded(), .ready)
        XCTAssertFalse(loaderRan)
    }

    func testACompletedLoadRequestCanStillNeedUserApprovalOrRestart() {
        let backend = MacFuseKernelBackend(
            isReady: { false },
            inspectLoader: { .trustedFixture },
            runLoader: { 27 })

        XCTAssertEqual(backend.ensureLoaded(), .requested(status: 27))
    }

    func testUntrustedLoaderVariantsAreNeverExecuted() {
        let fixtures: [(MacFuseKernelBackend.LoaderMetadata, String)] = [
            (.fixture(isRegularFile: false), "regular file"),
            (.fixture(ownerID: 501), "owned by root"),
            (.fixture(mode: 0o0755), "set-user-ID root"),
            (.fixture(mode: 0o4777), "writable"),
            (.fixture(codeIdentifier: "other_loader"), "identity"),
            (.fixture(teamIdentifier: "AAAAAAAAAA"), "identity"),
        ]

        for (metadata, expectedMessage) in fixtures {
            var loaderRan = false
            let backend = MacFuseKernelBackend(
                isReady: { false },
                inspectLoader: { metadata },
                runLoader: {
                    loaderRan = true
                    return 0
                })

            guard case .failed(let message) = backend.ensureLoaded() else {
                return XCTFail("expected an unsafe loader failure")
            }
            XCTAssertTrue(message.contains(expectedMessage), message)
            XCTAssertFalse(loaderRan)
        }
    }

    func testFallbackCommandUsesTheRunningMacOSMajorVersion() {
        XCTAssertEqual(
            MacFuseKernelBackend.manualLoadCommand(osMajorVersion: 27),
            "/usr/bin/sudo /usr/bin/kmutil load -p "
                + "/Library/Filesystems/macfuse.fs/Contents/Extensions/27/macfuse.kext")
    }

    func testNumberedDeviceNodeIdentifiesTheKernelBackend() {
        XCTAssertFalse(MacFuseSetupStage.kernelBackendReady(deviceNames: []))
        XCTAssertFalse(MacFuseSetupStage.kernelBackendReady(deviceNames: ["macfuse"]))
        XCTAssertFalse(MacFuseSetupStage.kernelBackendReady(deviceNames: ["macfuse-control"]))
        XCTAssertTrue(MacFuseSetupStage.kernelBackendReady(deviceNames: ["macfuse0"]))
        XCTAssertTrue(MacFuseSetupStage.kernelBackendReady(deviceNames: ["macfuse63"]))
    }

    func testFailedDaemonProbeDoesNotBlameAReadyKernelBackend() {
        XCTAssertEqual(
            MacFuseSetupStage.afterFailedDaemonProbe(
                isInstalled: true, kernelBackendReady: true),
            .mountFailed)
        XCTAssertEqual(
            MacFuseSetupStage.afterFailedDaemonProbe(
                isInstalled: true, kernelBackendReady: false),
            .approveKext)
        XCTAssertEqual(
            MacFuseSetupStage.afterFailedDaemonProbe(
                isInstalled: false, kernelBackendReady: false),
            .installMacFuse)
    }

    func testPremountAgentConnectionDoesNotClaimKernelReadiness() {
        XCTAssertFalse(
            MacFuseSetupStage.daemonConnectionProvesReady(
                connected: true,
                kernelBackendReady: false,
                floriaMounted: false))
        XCTAssertFalse(
            MacFuseSetupStage.daemonConnectionProvesReady(
                connected: false,
                kernelBackendReady: true,
                floriaMounted: true))
        XCTAssertFalse(
            MacFuseSetupStage.daemonConnectionProvesReady(
                connected: true,
                kernelBackendReady: true,
                floriaMounted: false))
        XCTAssertTrue(
            MacFuseSetupStage.daemonConnectionProvesReady(
                connected: true,
                kernelBackendReady: true,
                floriaMounted: true))
    }

    func testOnlyMacFuseFilesystemTypesProveTheFloriaMount() {
        XCTAssertTrue(MacFuseSetupStage.filesystemIsMacFuse(typeName: "macfuse"))
        XCTAssertTrue(MacFuseSetupStage.filesystemIsMacFuse(typeName: "osxfuse"))
        XCTAssertFalse(MacFuseSetupStage.filesystemIsMacFuse(typeName: "apfs"))
    }
}

private extension MacFuseKernelBackend.LoaderMetadata {
    static let trustedFixture = fixture()

    static func fixture(
        isRegularFile: Bool = true,
        ownerID: uid_t = 0,
        mode: mode_t = 0o4755,
        codeIdentifier: String = "load_macfuse",
        teamIdentifier: String = "3T5GSNBU6W"
    ) -> MacFuseKernelBackend.LoaderMetadata {
        MacFuseKernelBackend.LoaderMetadata(
            isRegularFile: isRegularFile,
            ownerID: ownerID,
            mode: mode,
            codeIdentifier: codeIdentifier,
            teamIdentifier: teamIdentifier)
    }
}
