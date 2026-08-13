import XCTest

@testable import floria_menubar

@MainActor
final class DeviceEnrollmentPresenterTests: XCTestCase {
    func testEnrollmentAppearsAsANonModalReachableWindow() throws {
        let presenter = DeviceEnrollmentPresenter(
            dockVisibilityController: DockVisibilityController { _ in })
        let review = SyncEnrollmentReview(
            deviceID: "fixture-device",
            deviceName: "Mac mini",
            requestedAt: "2026-08-14T00:00:00Z",
            fingerprint: "AB12-CD34-EF56")

        presenter.show(review) { _ in }

        let window = try XCTUnwrap(presenter.activeWindow)
        XCTAssertFalse(window is NSPanel)
        XCTAssertFalse(window.isExcludedFromWindowsMenu)
        XCTAssertTrue(window.isVisible)
        XCTAssertEqual(window.title, "Floria Library Access Request")
        window.performClose(nil)
        XCTAssertNil(presenter.activeWindow)
    }

    func testWindowClosesWhenTheRequestWasHandledElsewhere() {
        let presenter = DeviceEnrollmentPresenter(
            dockVisibilityController: DockVisibilityController { _ in })
        let review = SyncEnrollmentReview(
            deviceID: "fixture-device",
            deviceName: "Mac mini",
            requestedAt: "2026-08-14T00:00:00Z",
            fingerprint: "AB12-CD34-EF56")

        presenter.show(review) { _ in }
        presenter.reconcile([])

        XCTAssertNil(presenter.activeWindow)
    }
}
