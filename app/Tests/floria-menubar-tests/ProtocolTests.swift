import XCTest

@testable import floria_menubar

/// The Swift wire types mirror `floria-agent::protocol` by hand; these tests decode JSON
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
            operation: "read", enforcement: "touchid", ssh: nil, identity: identity)

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
            operation: "read", enforcement: "prompt", ssh: nil, identity: identity)

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
        XCTAssertEqual(v["version"] as? UInt32, supportedAgentProtocolVersion)
    }

    func testDecodeDaemonHelloAndRejectMismatchedAgentProtocol() throws {
        let hello = try JSONDecoder().decode(
            AgentHelloMsg.self,
            from: Data(#"{"type":"hello","version":1,"daemon_version":"0.1.0"}"#.utf8))
        XCTAssertEqual(hello.version, supportedAgentProtocolVersion)
        XCTAssertEqual(hello.daemon_version, "0.1.0")
        XCTAssertNoThrow(try validateAgentProtocolVersion(hello.version))

        XCTAssertThrowsError(
            try validateAgentProtocolVersion(supportedAgentProtocolVersion + 1)
        ) { error in
            XCTAssertTrue(error.localizedDescription.contains("Restart Floria"))
        }
    }

    func testDecodeAgentProtocolErrorMatchesRustSchema() throws {
        let error = try JSONDecoder().decode(
            AgentProtocolErrorMsg.self,
            from: Data(#"{"type":"protocol_error","expected_version":2,"received_version":1}"#.utf8))
        XCTAssertEqual(error.expected_version, 2)
        XCTAssertEqual(error.received_version, 1)
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
            ssh: nil,
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

    func testRecentAccessIdentityIsStableForPersistedAndLiveCopies() {
        let event = AccessEventMsg(
            ts: "2026-07-24T08:30:15.123Z", path: "surfaces/project-env",
            display: "/Users/me/project/.env", operation: "read",
            decision: "allowed", rule_id: "surface:project-env",
            policy: nil, ssh: nil,
            identity: IdentityView(
                pid: 42, uid: 501, exe: "/usr/bin/cat", cwd: "/Users/me/project",
                chain: "zsh -> cat"))
        let differentProcess = AccessEventMsg(
            ts: event.ts, path: event.path, display: event.display,
            operation: event.operation, decision: event.decision, rule_id: event.rule_id,
            policy: event.policy, ssh: event.ssh,
            identity: IdentityView(
                pid: 43, uid: 501, exe: "/usr/bin/cat", cwd: "/Users/me/project",
                chain: "zsh -> cat"))

        XCTAssertEqual(RecentAccess(event).id, RecentAccess(event).id)
        XCTAssertNotEqual(RecentAccess(event).id, RecentAccess(differentProcess).id)
    }

    func testSshSignPresentationUsesIdentityMetadata() {
        let ssh = SshSignView(
            surface_id: "surface-1", surface_name: "GitHub identities",
            resource_id: "resource-1", key_fingerprint: "SHA256:abc123",
            key_label: "Personal GitHub", identity_source: "~/keys/personal-github",
            requested_destination: "github.com",
            verified_host_key_fingerprint: "SHA256:host123",
            ssh_user: "git", forwarding_hops: 1)
        let prompt = PromptMsg(
            req_id: 11, path: "ssh-agent/surface-1", display: nil,
            operation: "sign", enforcement: "touchid", ssh: ssh,
            identity: IdentityView(
                pid: 55, uid: 501, exe: "/usr/bin/ssh", cwd: "/Users/me/project",
                chain: "zsh -> ssh"))

        let presentation = PromptPresentation(prompt)

        XCTAssertEqual(presentation.actionTitle, "use")
        XCTAssertEqual(presentation.targetName, "Personal GitHub")
        XCTAssertEqual(presentation.targetPath, "SHA256:abc123")
        XCTAssertNil(presentation.mountPath)
        XCTAssertEqual(presentation.sshDestination, "github.com")
        XCTAssertEqual(presentation.sshHostKeyFingerprint, "SHA256:host123")
        XCTAssertEqual(presentation.sshUser, "git")
        XCTAssertEqual(presentation.sshForwardingHops, 1)
        XCTAssertEqual(presentation.ssh?.surface_name, "GitHub identities")
        XCTAssertEqual(presentation.sshIdentitySource, "~/keys/personal-github")
        XCTAssertEqual(presentation.sshAccessName, "GitHub identities")
    }

    func testSshSignDecodesIdentitySourceForAuditPresentation() throws {
        let data = Data(
            #"{"surface_id":"surface-1","surface_name":"GitHub identities","resource_id":"resource-1","key_fingerprint":"SHA256:abc123","key_label":"Personal GitHub","identity_source":"~/keys/personal-github","requested_destination":"github.com","verified_host_key_fingerprint":null,"ssh_user":"git","forwarding_hops":0}"#.utf8)

        let ssh = try JSONDecoder().decode(SshSignView.self, from: data)

        XCTAssertEqual(ssh.identity_source, "~/keys/personal-github")
        let recent = RecentAccess(
            AccessEventMsg(
                ts: "2026-08-17T12:00:00.000Z", path: "surfaces/surface-1", display: nil,
                operation: "sign", decision: "allowed", rule_id: "prompt", policy: nil,
                ssh: ssh,
                identity: IdentityView(
                    pid: 55, uid: 501, exe: "/usr/bin/ssh", cwd: "/Users/me/project",
                    chain: "zsh -> ssh")))
        XCTAssertEqual(
            recent.shownPath,
            "Personal GitHub · ~/keys/personal-github")
    }
}
