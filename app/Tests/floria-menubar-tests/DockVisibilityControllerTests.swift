import AppKit
import XCTest

@testable import floria_menubar

@MainActor
final class DockVisibilityControllerTests: XCTestCase {
    func testDashboardClearsOnlyItsInitialFocus() {
        let controller = DockVisibilityController { _ in }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 300),
            styleMask: [.titled], backing: .buffered, defer: false)
        let initial = FocusableTestView(frame: window.contentView?.bounds ?? .zero)
        let later = FocusableTestView(frame: initial.bounds)
        initial.addSubview(later)
        window.contentView = initial
        XCTAssertTrue(window.makeFirstResponder(initial))

        controller.observeDashboardWindow(window)
        NotificationCenter.default.post(name: NSWindow.didBecomeKeyNotification, object: window)
        XCTAssertFalse(window.firstResponder === initial)

        XCTAssertTrue(window.makeFirstResponder(later))
        NotificationCenter.default.post(name: NSWindow.didBecomeKeyNotification, object: window)
        XCTAssertTrue(window.firstResponder === later)
    }

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

private final class FocusableTestView: NSView {
    override var acceptsFirstResponder: Bool { true }
}
