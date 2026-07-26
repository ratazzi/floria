import XCTest

@testable import accessfs_menubar

final class DiscoveryImportPreviewTests: XCTestCase {
    func testReplacingDiscoveredSourceIsExpectedRatherThanAConflict() {
        let preview = DiscoveryImportPreview(
            imports: [
                DiscoveryImport(
                    path: "/workspace/app/.env",
                    destination: .projectOutput(
                        projectPath: "/workspace/app",
                        outputPath: "/workspace/app/.env"),
                    sourceDisposition: .replaceWithSurface)
            ],
            pathExists: { _ in true })

        XCTAssertEqual(preview.replacedSources, 1)
        XCTAssertEqual(preview.createdOutputs, 0)
        XCTAssertTrue(preview.conflicts.isEmpty)
    }

    func testAdditionalProjectOutputReportsAnExistingTarget() {
        let preview = DiscoveryImportPreview(
            imports: [
                DiscoveryImport(
                    path: "/workspace/shared.env",
                    destination: .projectOutputs(outputs: [
                        DiscoveryProjectOutput(
                            projectPath: "/workspace/first",
                            outputPath: "/workspace/first/.env"),
                        DiscoveryProjectOutput(
                            projectPath: "/workspace/second",
                            outputPath: "/workspace/second/.env"),
                    ]),
                    sourceDisposition: .protectInPlace)
            ],
            pathExists: { $0 == "/workspace/second/.env" })

        XCTAssertEqual(preview.createdOutputs, 2)
        XCTAssertEqual(preview.protectedSources, 1)
        XCTAssertEqual(
            preview.conflicts,
            [
                DiscoveryImportPreview.Conflict(
                    kind: .outputExists,
                    path: "/workspace/second/.env",
                    sourcePaths: ["/workspace/shared.env"])
            ])
    }

    func testDuplicateOutputAcrossSelectedFilesIsRejectedBeforeApply() {
        let preview = DiscoveryImportPreview(
            imports: [
                projectImport(source: "/imports/first.env"),
                projectImport(source: "/imports/second.env"),
            ],
            pathExists: { _ in false })

        XCTAssertEqual(preview.createdOutputs, 2)
        XCTAssertEqual(
            preview.conflicts,
            [
                DiscoveryImportPreview.Conflict(
                    kind: .duplicateOutput,
                    path: "/workspace/app/.env",
                    sourcePaths: [
                        "/imports/first.env",
                        "/imports/second.env",
                    ])
            ])
    }

    func testLibraryDispositionSummaryDistinguishesProtectedAndUnchangedSources() {
        let preview = DiscoveryImportPreview(
            imports: [
                DiscoveryImport(
                    path: "/imports/protected.env",
                    destination: .library,
                    sourceDisposition: .protectInPlace),
                DiscoveryImport(
                    path: "/imports/copied.env",
                    destination: .library,
                    sourceDisposition: .leaveUnchanged),
            ],
            pathExists: { _ in false })

        XCTAssertEqual(preview.protectedSources, 1)
        XCTAssertEqual(preview.unchangedSources, 1)
        XCTAssertEqual(
            preview.actionSummary,
            "1 original protected · 1 original unchanged")
    }

    private func projectImport(source: String) -> DiscoveryImport {
        DiscoveryImport(
            path: source,
            destination: .projectOutput(
                projectPath: "/workspace/app",
                outputPath: "/workspace/app/.env"),
            sourceDisposition: .leaveUnchanged)
    }
}
