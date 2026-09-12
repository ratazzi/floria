import AppKit
import SwiftUI
import XCTest

@testable import floria_menubar

final class MenuItemButtonTests: XCTestCase {
    @MainActor
    func testEntireMenuRowRespondsToClicks() throws {
        try checkRowClicks(isEnabled: true)
    }

    @MainActor
    func testDisabledMenuRowDoesNotRespondToClicks() throws {
        try checkRowClicks(isEnabled: false)
    }

    @MainActor
    private func checkRowClicks(isEnabled: Bool) throws {
        _ = NSApplication.shared
        var clicks = 0
        let host = NSHostingView(rootView:
            MenuItemButton(title: "Open Floria", icon: "macwindow", shortcut: "D") {
                clicks += 1
            }
            .disabled(!isEnabled)
            .frame(width: 348)
        )
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 348, height: host.fittingSize.height),
            styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = host
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        host.layoutSubtreeIfNeeded()
        window.displayIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.05))

        let height = host.bounds.height
        let points: [(String, NSPoint)] = [
            ("icon", NSPoint(x: 16, y: height / 2)),
            ("title", NSPoint(x: 60, y: height / 2)),
            ("spacer", NSPoint(x: 240, y: height / 2)),
            ("leading padding", NSPoint(x: 3, y: height / 2)),
            ("trailing padding", NSPoint(x: 345, y: height / 2)),
            ("top padding", NSPoint(x: 60, y: height - 2)),
            ("bottom padding", NSPoint(x: 60, y: 2)),
        ]
        for (name, point) in points {
            let before = clicks
            let location = host.convert(point, to: nil)
            for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
                let event = try XCTUnwrap(NSEvent.mouseEvent(
                    with: type, location: location, modifierFlags: [],
                    timestamp: ProcessInfo.processInfo.systemUptime,
                    windowNumber: window.windowNumber, context: nil,
                    eventNumber: 0, clickCount: 1, pressure: type == .leftMouseDown ? 1 : 0))
                window.sendEvent(event)
            }
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
            XCTAssertEqual(
                clicks, before + (isEnabled ? 1 : 0),
                "Unexpected action count when clicking \(name), enabled: \(isEnabled)")
        }
    }
}
