import Foundation
import XCTest

final class MacOS27PresentationTests: XCTestCase {
    func testDashboardChromeOwnsItsBackgroundAndKeepsOnlySearchFlexible() throws {
        let source = try source("CompactDashboardView.swift")

        XCTAssertTrue(
            source.contains(
                "Color(nsColor: .controlBackgroundColor)\n                .ignoresSafeArea()"))
        XCTAssertTrue(source.contains(".frame(maxWidth: .infinity, maxHeight: .infinity)"))
        XCTAssertTrue(source.contains(".layoutPriority(1)"))
        XCTAssertTrue(
            source.contains(".disabled(isDiscovering)\n            .fixedSize()"))
        XCTAssertTrue(
            source.contains(
                ".accessibilityLabel(\"Add Library item\")\n            .fixedSize()"))
        XCTAssertTrue(
            source.contains(
                ".accessibilityLabel(\"More actions\")\n            .fixedSize()"))
    }

    func testAuthorizationPromptMatchesTheDashboardContentBackground() throws {
        let prompt = try source("AuthorizationPromptView.swift")
        let presenter = try source("PromptPresenter.swift")

        XCTAssertTrue(
            prompt.contains(
                ".background(Color(nsColor: .controlBackgroundColor).ignoresSafeArea())"))
        XCTAssertTrue(presenter.contains("window.backgroundColor = .controlBackgroundColor"))
        XCTAssertTrue(presenter.contains("window.isOpaque = true"))
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
