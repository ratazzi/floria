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

    private func menuBarSource() throws -> String {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot
            .appendingPathComponent("Sources/accessfs-menubar/MenuBarView.swift")
        return try String(contentsOf: sourceURL, encoding: .utf8)
    }
}
