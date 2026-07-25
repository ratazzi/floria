import XCTest

@testable import accessfs_menubar

/// The Swift wire types mirror `accessfs-agent::protocol` by hand; these tests decode JSON
/// in the exact shape the Rust side serializes (see the Rust `*_wire_shape_*` tests), so
/// schema drift between the two ends fails a test instead of silently dropping messages.
final class ProtocolTests: XCTestCase {
    func testDecodePromptFromRustWireShape() throws {
        let json = """
            {"type":"prompt","req_id":9,"path":"secrets/abc","display":"/Users/me/.env",
             "operation":"write","enforcement":"prompt",
             "identity":{"pid":42,"uid":501,"exe":"/usr/bin/vim","cwd":"/tmp",
             "cmdline":["vim","/Users/me/.env"],"bundle_id":null,"team_id":null,
             "parent_chain":[{"pid":1,"name":"launchd","exe":"/sbin/launchd"},
             {"pid":42,"name":"vim","exe":"/usr/bin/vim"}],"chain":"launchd -> vim"}}
            """
        let m = try JSONDecoder().decode(PromptMsg.self, from: Data(json.utf8))
        XCTAssertEqual(m.req_id, 9)
        XCTAssertEqual(m.path, "secrets/abc")
        XCTAssertEqual(m.display, "/Users/me/.env")
        XCTAssertEqual(m.operation, "write")
        XCTAssertEqual(m.enforcement, "prompt")
        XCTAssertEqual(m.identity.pid, 42)
        XCTAssertEqual(m.identity.exe, "/usr/bin/vim")
        XCTAssertEqual(m.identity.cmdline, ["vim", "/Users/me/.env"])
        XCTAssertEqual(m.identity.parent_chain?.map(\.name), ["launchd", "vim"])
    }

    func testDecodeAccessEventWithNullOptionals() throws {
        // display / rule_id / exe / cwd are Option on the Rust side and serialize as null.
        let json = """
            {"type":"access_event","ts":"2026-07-11T00:00:00.000Z","path":"secrets/abc",
             "display":null,"operation":"read","decision":"denied","rule_id":null,
             "identity":{"pid":7,"uid":501,"exe":null,"cwd":null,"chain":"?"}}
            """
        let m = try JSONDecoder().decode(AccessEventMsg.self, from: Data(json.utf8))
        XCTAssertEqual(m.decision, "denied")
        XCTAssertNil(m.display)
        XCTAssertNil(m.rule_id)
        XCTAssertNil(m.identity.exe)
    }

    func testEncodeDecisionMatchesRustSchema() throws {
        let msg = DecisionMsg(req_id: 9, outcome: "allow", scope: "ttl", ttl_secs: 600)
        let v = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(msg)) as? [String: Any])
        XCTAssertEqual(v["type"] as? String, "decision")
        XCTAssertEqual(v["req_id"] as? UInt64, 9)
        XCTAssertEqual(v["outcome"] as? String, "allow")
        XCTAssertEqual(v["scope"] as? String, "ttl")
        XCTAssertEqual(v["ttl_secs"] as? UInt64, 600)
    }

    func testPromptPresentationMakesSourceAndDirectReaderExplicit() {
        let identity = IdentityView(
            pid: 44, uid: 501, exe: "/bin/cat", cwd: "/Users/me/project",
            chain: "launchd -> Terminal -> login -> zsh -> cat",
            cmdline: ["cat", "/Users/me/.pgpass"],
            parent_chain: [
                ProcessView(pid: 1, name: "launchd", exe: "/sbin/launchd"),
                ProcessView(
                    pid: 10, name: "Terminal",
                    exe: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"),
                ProcessView(pid: 20, name: "login", exe: "/usr/bin/login"),
                ProcessView(pid: 30, name: "zsh", exe: "/bin/zsh"),
                ProcessView(pid: 44, name: "cat", exe: "/bin/cat"),
            ])
        let prompt = PromptMsg(
            req_id: 9, path: "secrets/fixture", display: "/Users/me/.pgpass",
            operation: "read", enforcement: "touchid", identity: identity)

        let presentation = PromptPresentation(prompt)

        XCTAssertEqual(presentation.requester.displayName, "Terminal")
        XCTAssertEqual(presentation.source.displayName, "Terminal")
        XCTAssertEqual(presentation.reader.displayName, "cat")
        XCTAssertEqual(presentation.processPath.map(\.displayName), ["Terminal", "login", "zsh", "cat"])
        XCTAssertEqual(presentation.intermediateCount, 2)
        XCTAssertEqual(presentation.targetName, ".pgpass")
        XCTAssertEqual(presentation.mountPath, "secrets/fixture")
        XCTAssertTrue(presentation.requiresTouchID)
    }

    func testPromptPresentationUsesDirectReaderForPureCLIChain() {
        let identity = IdentityView(
            pid: 44, uid: 501, exe: "/bin/cat", cwd: "/Users/me/project",
            chain: "launchd -> zsh -> cat",
            cmdline: ["cat", "/Users/me/.pgpass"],
            parent_chain: [
                ProcessView(pid: 1, name: "launchd", exe: "/sbin/launchd"),
                ProcessView(pid: 30, name: "zsh", exe: "/bin/zsh"),
                ProcessView(pid: 44, name: "cat", exe: "/bin/cat"),
            ])
        let prompt = PromptMsg(
            req_id: 10, path: "secrets/fixture", display: "/Users/me/.pgpass",
            operation: "read", enforcement: "prompt", identity: identity)

        let presentation = PromptPresentation(prompt)

        XCTAssertEqual(presentation.requester.displayName, "cat")
        XCTAssertEqual(presentation.source.displayName, "zsh")
        XCTAssertEqual(presentation.reader.displayName, "cat")
        XCTAssertEqual(presentation.processPath.map(\.displayName), ["zsh", "cat"])
    }

    func testEncodeHelloMatchesRustSchema() throws {
        let v = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(HelloMsg())) as? [String: Any])
        XCTAssertEqual(v["type"] as? String, "hello")
        XCTAssertEqual(v["version"] as? Int, 1)
    }

    func testRecentAccessParsesFractionalSecondTimestamp() {
        // The daemon's ts carries fractional seconds; a formatter without
        // .withFractionalSeconds would reject it and the row would lose its time.
        let ev = AccessEventMsg(
            ts: "2026-07-11T08:30:15.123Z", path: "secrets/abc",
            display: NSHomeDirectory() + "/.env", operation: "read",
            decision: "allowed", rule_id: "grant",
            policy: PolicyEvaluationView(
                configured_enforcement: "touchid", effective_enforcement: "allow",
                mode: "audit_only"),
            identity: IdentityView(pid: 1, uid: 501, exe: "/bin/cat", cwd: nil, chain: "cat"))
        let row = RecentAccess(ev)
        XCTAssertNotNil(row.date)
        XCTAssertFalse(row.time.isEmpty)
        XCTAssertEqual(row.exe, "cat")
        XCTAssertTrue(row.allowed)
        XCTAssertTrue(row.wasGloballyOverridden)
        // The list shows the tilde-abbreviated source path over the uuid mount path.
        XCTAssertEqual(row.shownPath, "~/.env")
    }
}
