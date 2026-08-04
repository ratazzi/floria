import XCTest
@testable import floria_menubar

final class MacFuseSetupTests: XCTestCase {
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
