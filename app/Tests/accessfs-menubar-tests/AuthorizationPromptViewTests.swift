import AppKit
import SwiftUI
import XCTest

@testable import accessfs_menubar

final class AuthorizationPromptViewTests: XCTestCase {
    @MainActor
    func testAuthorizationScopeWidthDoesNotChangeWithSelection() {
        let once = NSHostingView(
            rootView: AuthorizationScopePicker(scope: .constant(.once), operation: "read"))
        let tenMinutes = NSHostingView(
            rootView: AuthorizationScopePicker(scope: .constant(.tenMinutes), operation: "read"))

        XCTAssertEqual(once.fittingSize.width, tenMinutes.fittingSize.width, accuracy: 0.5)
    }
}
