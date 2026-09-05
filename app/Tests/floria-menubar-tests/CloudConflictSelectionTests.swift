import XCTest
@testable import floria_menubar

final class CloudConflictSelectionTests: XCTestCase {
    func testCloudHeadWinsEvenWhenBothCandidatesMatchLocalContents() throws {
        let review = fixture()
        let plan = try CloudConflictSelection.plan(
            reviews: [review], serverHeads: [review.entityID: "remote"])
        XCTAssertEqual(plan.count, 1)
        XCTAssertEqual(plan.first?.revisionID, "remote")
    }

    func testMissingAndStaleCloudHeadsRejectTheWholePlan() {
        for heads in [[:], ["entity": "unfetched"]] {
            XCTAssertThrowsError(try CloudConflictSelection.plan(
                reviews: [fixture()], serverHeads: heads))
        }
        XCTAssertThrowsError(try CloudConflictSelection.plan(
            reviews: [fixture(), fixture(id: "missing")],
            serverHeads: ["entity": "remote"]))
    }

    private func fixture(id: String = "entity") -> SyncConflictReview {
        SyncConflictReview(entityID: id, candidates: ["local", "remote"].map {
            SyncConflictCandidate(
                revisionID: $0, lifecycle: .active, kind: .project, label: "Project",
                versionID: nil, plaintextSize: nil, matchesLocalState: true)
        })
    }
}
