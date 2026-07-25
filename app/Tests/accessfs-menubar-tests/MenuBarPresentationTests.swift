import Foundation
import XCTest

final class MenuBarPresentationTests: XCTestCase {
    func testMenuBarExtraDoesNotHostTransientConfirmationDialogs() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot
            .appendingPathComponent("Sources/accessfs-menubar/MenuBarView.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)

        XCTAssertFalse(
            source.contains(".confirmationDialog("),
            "MenuBarExtra windows dismiss before transient confirmation panels receive clicks; "
                + "keep confirmations inside MenuBarView's anchored window."
        )
    }
}
