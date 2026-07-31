import Foundation
import XCTest

@testable import floria_menubar

final class MenuBarAccessFeedTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_790_000_000)

    func testDefaultFeedUsesOneHourWindowAndGroupsEquivalentAccesses() {
        let recent = makeRecent(secondsBeforeNow: 10, path: "surfaces/project-env")
        let repeated = makeRecent(secondsBeforeNow: 30, path: "surfaces/project-env")
        let write = makeRecent(
            secondsBeforeNow: 60, path: "surfaces/project-env", operation: "write")
        let boundary = makeRecent(secondsBeforeNow: 3_600, path: "surfaces/boundary")
        let expired = makeRecent(secondsBeforeNow: 3_601, path: "surfaces/expired")

        let feed = MenuBarAccessFeed.make(
            recents: [expired, repeated, write, boundary, recent],
            searchText: "",
            now: now)

        XCTAssertEqual(feed.groups.count, 3)
        XCTAssertEqual(feed.totalGroupCount, 3)
        XCTAssertEqual(feed.countLabel, "1h · 3")
        XCTAssertEqual(feed.groups[0].latest.path, "surfaces/project-env")
        XCTAssertEqual(feed.groups[0].latest.operation, "read")
        XCTAssertEqual(feed.groups[0].count, 2)
        XCTAssertTrue(feed.groups.contains { $0.latest.path == "surfaces/boundary" })
        XCTAssertFalse(feed.groups.contains { $0.latest.path == "surfaces/expired" })
    }

    func testSearchIncludesOlderHistoryBeforeGrouping() {
        let oldMatch = makeRecent(
            secondsBeforeNow: 7_200,
            path: "surfaces/legacy",
            display: "/Users/fixture/legacy/.env")
        let recentMiss = makeRecent(secondsBeforeNow: 30, path: "surfaces/current")

        let feed = MenuBarAccessFeed.make(
            recents: [recentMiss, oldMatch],
            searchText: "legacy",
            now: now)

        XCTAssertTrue(feed.isSearching)
        XCTAssertEqual(feed.groups.map(\.latest.path), ["surfaces/legacy"])
        XCTAssertEqual(feed.countLabel, "1")
    }

    func testAccessStormHasAThirtyGroupRenderingBackstop() {
        let recents = (0..<35).map { index in
            makeRecent(
                secondsBeforeNow: TimeInterval(index),
                path: "surfaces/fixture-\(index)")
        }

        let feed = MenuBarAccessFeed.make(
            recents: recents,
            searchText: "",
            now: now)

        XCTAssertEqual(feed.groups.count, 30)
        XCTAssertEqual(feed.totalGroupCount, 35)
        XCTAssertEqual(feed.countLabel, "1h · 30+")
        XCTAssertEqual(feed.groups.first?.latest.path, "surfaces/fixture-0")
        XCTAssertEqual(feed.groups.last?.latest.path, "surfaces/fixture-29")
    }

    func testSharedProjectionGroupsBeforeApplyingDashboardLimit() {
        let latest = makeRecent(secondsBeforeNow: 1, path: "surfaces/repeated")
        let repeated = makeRecent(secondsBeforeNow: 2, path: "surfaces/repeated")
        let second = makeRecent(secondsBeforeNow: 3, path: "surfaces/second")
        let third = makeRecent(secondsBeforeNow: 4, path: "surfaces/third")

        let groups = RecentAccessProjection.grouped(
            [third, repeated, second, latest],
            maximumGroups: 2)

        XCTAssertEqual(groups.count, 2)
        XCTAssertEqual(groups[0].latest.path, "surfaces/repeated")
        XCTAssertEqual(groups[0].count, 2)
        XCTAssertEqual(groups[1].latest.path, "surfaces/second")
    }

    func testSubsecondRelativeTimeUsesNowInsteadOfInZeroSeconds() {
        let recent = makeRecent(secondsBeforeNow: 0.1, path: "surfaces/recent")

        XCTAssertEqual(recent.relativeTime(relativeTo: now), "now")
    }

    private func makeRecent(
        secondsBeforeNow: TimeInterval,
        path: String,
        display: String? = nil,
        operation: String = "read"
    ) -> RecentAccess {
        RecentAccess(
            AccessEventMsg(
                ts: Self.iso.string(from: now.addingTimeInterval(-secondsBeforeNow)),
                path: path,
                display: display,
                operation: operation,
                decision: "allowed",
                rule_id: "fixture-rule",
                policy: nil,
                ssh: nil,
                identity: IdentityView(
                    pid: 42,
                    uid: 501,
                    exe: "/usr/bin/fixture-reader",
                    cwd: "/Users/fixture/project",
                    chain: "zsh -> fixture-reader")))
    }

    private static let iso: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}
