import Foundation
import XCTest

final class MenuBarPresentationTests: XCTestCase {
    func testMenuBarExtraDoesNotHostTransientConfirmationDialogs() throws {
        let source = try menuBarSource()

        XCTAssertFalse(
            source.contains(".confirmationDialog("),
            "MenuBarExtra windows dismiss before transient confirmation panels receive clicks; "
                + "keep confirmations inside MenuBarView's anchored window."
        )
    }

    func testQuitItemUsesProductNameAndStandardCloseSymbol() throws {
        let source = try menuBarSource()

        XCTAssertTrue(source.contains(#"title: "Quit Floria", icon: "xmark.square""#))
    }

    func testMenuBarContentOwnsItsVerticalSize() throws {
        let source = try menuBarSource()

        XCTAssertTrue(
            source.contains(
                ".frame(width: 360)\n"
                    + "        .fixedSize(horizontal: false, vertical: true)"),
            "The MenuBarExtra host must not stretch transparent content above the menu body."
        )
    }

    func testStatusItemHasAnAccessibleProductName() throws {
        let source = try appSource()

        XCTAssertEqual(
            source.components(separatedBy: #".accessibilityLabel("Floria")"#).count - 1,
            2
        )
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
