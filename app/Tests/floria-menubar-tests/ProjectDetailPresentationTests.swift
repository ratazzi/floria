import Foundation
import XCTest

final class ProjectDetailPresentationTests: XCTestCase {
    func testProjectDetailUsesTheDashboardContentBackground() throws {
        let source = try compactDashboardSource()
        let start = try XCTUnwrap(source.range(of: "private struct CompactProjectDetailView"))
        let end = try XCTUnwrap(
            source.range(
                of: "private struct ProjectCheckoutsSheet",
                range: start.upperBound..<source.endIndex))
        let detail = source[start.lowerBound..<end.lowerBound]

        XCTAssertTrue(detail.contains(".background(Color(nsColor: .controlBackgroundColor))"))
        XCTAssertFalse(detail.contains(".background(Color(nsColor: .windowBackgroundColor))"))
    }

    private func compactDashboardSource() throws -> String {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = packageRoot
            .appendingPathComponent("Sources/floria-menubar/CompactDashboardView.swift")
        return try String(contentsOf: sourceURL, encoding: .utf8)
    }
}
