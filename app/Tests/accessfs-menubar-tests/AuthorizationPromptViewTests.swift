import AppKit
import SwiftUI
import XCTest

@testable import accessfs_menubar

final class AuthorizationPromptViewTests: XCTestCase {
    @MainActor
    func testAuthorizationScopeWidthDoesNotChangeWithSelection() {
        let once = NSHostingView(
            rootView: AuthorizationScopePicker(
                preset: .constant(.once),
                customDuration: .constant(15),
                customUnit: .constant(.minutes),
                operation: "read"))
        let custom = NSHostingView(
            rootView: AuthorizationScopePicker(
                preset: .constant(.custom),
                customDuration: .constant(3),
                customUnit: .constant(.hours),
                operation: "read"))

        XCTAssertEqual(once.fittingSize.width, custom.fittingSize.width, accuracy: 0.5)
    }

    func testPresetAndCustomDurationsResolveToArbitraryTTL() {
        XCTAssertEqual(
            PromptGrantPreset.fiveMinutes.scope(customDuration: 1, unit: .minutes),
            .timed(seconds: 300))
        XCTAssertEqual(
            PromptGrantPreset.oneHour.scope(customDuration: 1, unit: .minutes),
            .timed(seconds: 3_600))
        XCTAssertEqual(
            PromptGrantPreset.custom.scope(customDuration: 3, unit: .hours),
            .timed(seconds: 10_800))
    }

    func testGrantScopeMapsToExistingWireProtocol() {
        XCTAssertEqual(PromptGrantScope.once.wireScope, "once")
        XCTAssertNil(PromptGrantScope.once.ttlSeconds)

        let timed = PromptGrantScope.timed(seconds: 1_800)
        XCTAssertEqual(timed.wireScope, "ttl")
        XCTAssertEqual(timed.ttlSeconds, 1_800)
    }
}
