import AppKit
import SwiftUI
import XCTest

@testable import floria_menubar

@MainActor
final class MenuBarWindowChromeTests: XCTestCase {
    func testBackgroundUsesTheNativeActiveMenuMaterial() {
        let background = MenuBarWindowChrome.makeBackgroundView()

        XCTAssertEqual(background.material, .menu)
        XCTAssertEqual(background.blendingMode, .behindWindow)
        XCTAssertEqual(background.state, .active)
    }

    func testConfigureClipsTheTransparentHostToContinuousRoundedCorners() throws {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 360, height: 290),
            styleMask: .borderless,
            backing: .buffered,
            defer: false)
        let contentView = try XCTUnwrap(window.contentView)

        MenuBarWindowChrome.configure(window)

        XCTAssertFalse(window.isOpaque)
        XCTAssertEqual(window.backgroundColor, .clear)
        XCTAssertTrue(contentView.wantsLayer)
        let layer = try XCTUnwrap(contentView.layer)
        XCTAssertEqual(layer.cornerRadius, MenuBarWindowChrome.cornerRadius)
        XCTAssertEqual(layer.cornerCurve, .continuous)
        XCTAssertTrue(layer.masksToBounds)
    }

    func testProbeConfiguresItsContainingWindow() throws {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 360, height: 290),
            styleMask: .borderless,
            backing: .buffered,
            defer: false)
        let hostingView = NSHostingView(
            rootView: Color.clear.background(MenuBarWindowChrome()))

        window.contentView = hostingView
        hostingView.layoutSubtreeIfNeeded()

        let layer = try XCTUnwrap(hostingView.layer)
        XCTAssertEqual(layer.cornerRadius, MenuBarWindowChrome.cornerRadius)
        XCTAssertEqual(layer.cornerCurve, .continuous)
        XCTAssertTrue(layer.masksToBounds)
    }
}
