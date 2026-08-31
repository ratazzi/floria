import XCTest

@testable import floria_menubar

final class PromptPresenterTests: XCTestCase {
    @MainActor
    private func makePresenter(lifetimeNanoseconds: UInt64 = 28_000_000_000)
        -> PromptPresenter
    {
        PromptPresenter(
            lifetimeNanoseconds: lifetimeNanoseconds,
            dockVisibilityController: DockVisibilityController { _ in })
    }

    private func fixturePrompt(reqID: UInt64 = 7) -> PromptMsg {
        PromptMsg(
            req_id: reqID,
            path: "secrets/fixture",
            display: NSHomeDirectory() + "/.pgpass",
            operation: "read",
            enforcement: "ask",
            ssh: nil,
            identity: IdentityView(
                pid: 42, uid: 501, exe: "/usr/bin/wc", cwd: nil, chain: "zsh → wc"))
    }

    @MainActor
    func testShowingPromptDoesNotEnterAnApplicationModalLoop() throws {
        let presenter = makePresenter()
        let prompt = fixturePrompt()
        let modalEscape = DispatchWorkItem { NSApp.stopModal() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2, execute: modalEscape)
        let startedAt = ContinuousClock.now

        presenter.show(prompt) { _ in }

        modalEscape.cancel()
        XCTAssertLessThan(
            startedAt.duration(to: .now),
            .milliseconds(100),
            "Showing a prompt must return immediately so menus, quitting, and other windows remain usable")
        let window = try XCTUnwrap(presenter.activeWindow)
        XCTAssertFalse(window is NSPanel)
        XCTAssertFalse(window.isExcludedFromWindowsMenu)
        XCTAssertTrue(window.isVisible)

        window.performClose(nil)
        XCTAssertNil(presenter.activeWindow)
    }

    @MainActor
    func testExpiredPromptDeniesAndDismissesItself() async {
        let presenter = PromptPresenter(
            dockVisibilityController: DockVisibilityController { _ in },
            sleep: { _ in })
        let expired = expectation(description: "expired prompt denied")
        var observed: DecisionMsg?

        presenter.show(fixturePrompt()) { decision in
            observed = decision
            expired.fulfill()
        }

        await fulfillment(of: [expired], timeout: 1)
        XCTAssertEqual(observed?.outcome, "deny")
        XCTAssertNil(observed?.scope)
        XCTAssertNil(observed?.ttl_secs)
        XCTAssertNil(presenter.activeWindow)
    }

    @MainActor
    func testBiometricReasonIdentifiesTheUserFacingFile() {
        let sourcePath = NSHomeDirectory() + "/workspace/fixture-project/.aws/credentials"
        let prompt = PromptMsg(
            req_id: 1,
            path: "secrets/56115177-fdc2-406e-9541-7d4372f1bed1",
            display: sourcePath,
            operation: "read",
            enforcement: "touchid",
            ssh: nil,
            identity: IdentityView(
                pid: 42, uid: 501, exe: "/usr/bin/python3", cwd: nil, chain: "Python"))

        let reason = PromptPresenter.biometricReason(for: prompt)

        XCTAssertEqual(
            reason, "allow Python to read ~/workspace/fixture-project/.aws/credentials")
        XCTAssertFalse(reason.contains("secrets/"))
    }
}
