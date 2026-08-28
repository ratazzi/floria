import AppKit
import SwiftUI
import XCTest

@testable import floria_menubar

final class AuthorizationPromptViewTests: XCTestCase {
    @MainActor
    func testAuthorizationScopeWidthDoesNotChangeWithSelection() {
        let once = NSHostingView(
            rootView: AuthorizationScopePicker(
                preset: .constant(.once),
                customDuration: .constant(15),
                customUnit: .constant(.minutes),
                operation: "read")
                .frame(width: 440))
        let custom = NSHostingView(
            rootView: AuthorizationScopePicker(
                preset: .constant(.custom),
                customDuration: .constant(3),
                customUnit: .constant(.hours),
                operation: "read")
                .frame(width: 440))

        XCTAssertEqual(once.fittingSize.width, custom.fittingSize.width, accuracy: 0.5)
    }

    func testPresetAndCustomDurationsResolveToArbitraryTTL() {
        XCTAssertEqual(
            PromptGrantPreset.oneHour.scope(customDuration: 1, unit: .minutes),
            .timed(seconds: 3_600))
        XCTAssertEqual(
            PromptGrantPreset.custom.scope(customDuration: 3, unit: .hours),
            .timed(seconds: 10_800))
    }

    func testTodayAndLockScopesLeaveLifetimePolicyToTheDaemon() {
        XCTAssertEqual(
            PromptGrantPreset.today.scope(customDuration: 1, unit: .minutes),
            .today)
        XCTAssertEqual(
            PromptGrantPreset.untilMacLocks.scope(customDuration: 1, unit: .minutes),
            .untilLock)
    }

    func testGrantScopeMapsToExistingWireProtocol() {
        XCTAssertEqual(PromptGrantScope.once.wireScope, "once")
        XCTAssertNil(PromptGrantScope.once.ttlSeconds)

        let timed = PromptGrantScope.timed(seconds: 1_800)
        XCTAssertEqual(timed.wireScope, "ttl")
        XCTAssertEqual(timed.ttlSeconds, 1_800)

        let today = PromptGrantScope.today
        XCTAssertEqual(today.wireScope, "today")
        XCTAssertNil(today.ttlSeconds)
        XCTAssertEqual(PromptGrantScope.untilLock.wireScope, "until_lock")
        XCTAssertNil(PromptGrantScope.untilLock.ttlSeconds)
    }
}
