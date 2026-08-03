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
        XCTAssertNil(
            MacFuseSetupStage.afterFailedDaemonProbe(
                isInstalled: true, kernelBackendReady: true))
        XCTAssertEqual(
            MacFuseSetupStage.afterFailedDaemonProbe(
                isInstalled: true, kernelBackendReady: false),
            .approveKext)
        XCTAssertEqual(
            MacFuseSetupStage.afterFailedDaemonProbe(
                isInstalled: false, kernelBackendReady: false),
            .installMacFuse)
    }
}
