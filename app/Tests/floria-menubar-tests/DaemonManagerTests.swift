import XCTest

@testable import floria_menubar

final class DaemonManagerTests: XCTestCase {
    func testLaunchAgentStateIsNotLoadedWithoutPrintOutput() {
        XCTAssertEqual(DaemonManager.launchAgentState(from: nil), .notLoaded)
    }

    func testLaunchAgentStateIsRunningWhenLaunchdReportsRunning() {
        let output = """
        gui/501/floria.hola.ac.daemon = {
            active count = 1
            state = running
            pid = 945
        }
        """

        XCTAssertEqual(DaemonManager.launchAgentState(from: output), .running)
    }

    func testLaunchAgentStateIsLoadedWhenJobHasNoRunningProcess() {
        let output = """
        gui/501/floria.hola.ac.daemon = {
            active count = 0
            state = waiting
            runs = 3
            last exit code = 1
        }
        """

        XCTAssertEqual(DaemonManager.launchAgentState(from: output), .loaded)
    }

    func testLaunchAgentStateIsLoadedWhenLaunchdOmitsState() {
        let output = """
        gui/501/floria.hola.ac.daemon = {
            active count = 0
            runs = 1
        }
        """

        XCTAssertEqual(DaemonManager.launchAgentState(from: output), .loaded)
    }

    func testBootstrapRetriesLaunchdInputOutputRace() {
        let error = DaemonManager.DaemonError.processFailed(
            executable: "launchctl",
            arguments: ["bootstrap", "gui/501", "/tmp/floria.plist"],
            status: 5,
            output: "Bootstrap failed: 5: Input/output error")

        XCTAssertTrue(DaemonManager.shouldRetryBootstrap(error, completedAttempts: 1))
        XCTAssertFalse(DaemonManager.shouldRetryBootstrap(error, completedAttempts: 5))
    }

    func testBootstrapDoesNotRetryUnrelatedLaunchctlFailure() {
        let error = DaemonManager.DaemonError.processFailed(
            executable: "launchctl",
            arguments: ["bootstrap", "gui/501", "/tmp/floria.plist"],
            status: 78,
            output: "Invalid property list")

        XCTAssertFalse(DaemonManager.shouldRetryBootstrap(error, completedAttempts: 1))
    }
}
