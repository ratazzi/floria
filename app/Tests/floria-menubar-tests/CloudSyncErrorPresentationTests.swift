import CloudKit
import XCTest

@testable import floria_menubar

final class CloudSyncErrorPresentationTests: XCTestCase {
    func testSignedOutAccountHasAnActionableMessage() {
        let error = cloudError(.notAuthenticated)

        XCTAssertEqual(
            CloudSyncErrorPresentation.message(for: error),
            "Sign in to iCloud in System Settings, then try again.")
    }

    func testOfflineErrorsDoNotExposeCloudKitInternals() {
        let error = cloudError(.networkUnavailable)

        XCTAssertEqual(
            CloudSyncErrorPresentation.message(for: error),
            "Floria could not reach iCloud. Check this Mac's network connection, then try again.")
    }

    func testBuildConfigurationFailureExplainsTheSigningProblem() {
        let error = cloudError(.missingEntitlement)

        XCTAssertEqual(
            CloudSyncErrorPresentation.message(for: error),
            "This build of Floria is not configured for its iCloud container. Install a correctly signed build, then try again.")
    }

    func testNonCloudKitErrorsKeepTheirOriginalDescription() {
        let error = NSError(
            domain: "dev.floria.test", code: 7,
            userInfo: [NSLocalizedDescriptionKey: "Local validation failed"])

        XCTAssertEqual(
            CloudSyncErrorPresentation.message(for: error),
            "Local validation failed")
    }

    private func cloudError(_ code: CKError.Code) -> NSError {
        NSError(domain: CKErrorDomain, code: code.rawValue)
    }
}
