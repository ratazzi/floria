import XCTest

@testable import floria_menubar

final class PromptPresenterTests: XCTestCase {
    @MainActor
    func testBiometricReasonIdentifiesTheUserFacingFile() {
        let sourcePath = NSHomeDirectory() + "/workspace/fixture-project/.aws/credentials"
        let prompt = PromptMsg(
            req_id: 1,
            path: "secrets/56115177-fdc2-406e-9541-7d4372f1bed1",
            display: sourcePath,
            operation: "read",
            enforcement: "touchid",
            ssh: nil,
            identity: IdentityView(
                pid: 42, uid: 501, exe: "/usr/bin/python3", cwd: nil, chain: "Python"))

        let reason = PromptPresenter.biometricReason(for: prompt)

        XCTAssertEqual(
            reason, "allow Python to read ~/workspace/fixture-project/.aws/credentials")
        XCTAssertFalse(reason.contains("secrets/"))
    }
}
