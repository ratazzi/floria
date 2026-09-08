import Foundation
import XCTest

final class MenuBarPresentationTests: XCTestCase {
    func testPopoverKeepsConfirmationInsideItsContent() throws {
        let source = try menuBarSource()

        XCTAssertFalse(
            source.contains(".confirmationDialog("),
            "Keep confirmations inside MenuBarView so transient popover dismissal "
                + "does not interrupt the confirmation."
        )
    }

    func testQuitItemUsesProductNameAndStandardCloseSymbol() throws {
        let source = try menuBarSource()

        XCTAssertTrue(source.contains(#"title: "Quit Floria", icon: "xmark.square""#))
    }

    func testMenuBarContentUsesAnArrowlessAppKitPanel() throws {
        let source = try menuBarSource()

        XCTAssertTrue(source.contains(".frame(width: 360)"))
        XCTAssertFalse(source.contains("MenuBarWindowChrome"))
        XCTAssertFalse(source.contains(".presentationCornerRadius"))
        let controller = try self.source("MenuBarController.swift")
        XCTAssertTrue(controller.contains("NSPanel"))
        XCTAssertFalse(controller.contains("= NSPopover()"))
        XCTAssertTrue(controller.contains("styleMask: [.borderless, .fullSizeContentView]"))
        XCTAssertFalse(try appSource().contains("MenuBarExtra"))
    }

    func testStatusItemHasAnAccessibleProductName() throws {
        let source = try source("MenuBarController.swift")
        XCTAssertTrue(source.contains(#"setAccessibilityLabel("Floria")"#))
    }

    func testInteractiveMenuRowsShareOneFullWidthHoverTreatment() throws {
        let source = try menuBarSource()

        XCTAssertTrue(source.contains(".frame(maxWidth: .infinity, alignment: .leading)"))
        XCTAssertTrue(source.contains(".contentShape(Rectangle())"))
        XCTAssertEqual(source.components(separatedBy: ".menuBarHoverRow(isHovered: $hovered)").count - 1, 3)
    }

    private func menuBarSource() throws -> String {
        try source("MenuBarView.swift")
    }

    private func appSource() throws -> String {
        try source("App.swift")
    }

    private func source(_ name: String) throws -> String {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot
            .appendingPathComponent("Sources/floria-menubar")
            .appendingPathComponent(name)
        return try String(contentsOf: sourceURL, encoding: .utf8)
    }
}
