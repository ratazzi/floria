import Foundation
import XCTest

@testable import floria_menubar

final class ApplicationUninstallerTests: XCTestCase {
    func testUninstallIsOnlyOfferedForAnAppDirectlyInsideApplications() {
        XCTAssertTrue(
            ApplicationUninstaller.isAvailable(
                applicationURL: URL(fileURLWithPath: "/Applications/Floria.app")))
        XCTAssertFalse(
            ApplicationUninstaller.isAvailable(
                applicationURL: URL(fileURLWithPath: "/Volumes/Floria/Floria.app")))
        XCTAssertFalse(
            ApplicationUninstaller.isAvailable(
                applicationURL: URL(fileURLWithPath: "/Applications/Preview/Floria.app")))
    }
}
