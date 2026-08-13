import AppKit
import XCTest

@testable import floria_menubar

@MainActor
final class DockVisibilityControllerTests: XCTestCase {
    func testDockFollowsDashboardPresentation() {
        var policies: [NSApplication.ActivationPolicy] = []
        let controller = DockVisibilityController { policies.append($0) }

        controller.prepareToShowDashboard()
        controller.dashboardDidClose()

        XCTAssertEqual(policies, [.regular, .accessory])
    }

    func testAuthorizationPromptKeepsDockReachableWithoutDashboard() {
        var policies: [NSApplication.ActivationPolicy] = []
        let controller = DockVisibilityController { policies.append($0) }

        controller.authorizationPromptDidOpen()
        controller.dashboardDidClose()
        controller.authorizationPromptDidClose()

        XCTAssertEqual(policies, [.regular, .regular, .accessory])
    }

    func testBackgroundAttentionWindowKeepsDockReachable() {
        var policies: [NSApplication.ActivationPolicy] = []
        let controller = DockVisibilityController { policies.append($0) }

        controller.backgroundAttentionWindowDidOpen()
        controller.dashboardDidClose()
        controller.backgroundAttentionWindowDidClose()

        XCTAssertEqual(policies, [.regular, .regular, .accessory])
    }
}
