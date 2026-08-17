import XCTest

@testable import floria_menubar

@MainActor
final class CompactDashboardTests: XCTestCase {
    func testProjectMatcherIncludesSshSignFromItsSocketSurface() {
        let surface = WorkspaceSurface(
            id: "fixture-ssh-surface", name: "SSH Access", kind: .unixSocket,
            path: nil, linkStatus: nil, input: .sshAgent([], nil))
        let project = WorkspaceProject(
            id: "fixture-project", name: "Fixture", path: "/fixture/project",
            commonBindings: [],
            environments: [
                WorkspaceEnvironment(
                    id: "fixture-environment", name: "Development",
                    bindings: [], surfaces: [surface])
            ])
        let event = RecentAccess(
            AccessEventMsg(
                ts: "2026-08-17T12:33:53.191Z",
                path: "surfaces/fixture-ssh-surface", display: "SSH Access",
                operation: "sign", decision: "allowed", rule_id: "prompt", policy: nil,
                ssh: SshSignView(
                    surface_id: surface.id, surface_name: surface.name,
                    resource_id: "fixture-identity", key_fingerprint: "SHA256:fixture",
                    key_label: "Fixture identity", requested_destination: "example.com",
                    verified_host_key_fingerprint: "SHA256:host", ssh_user: "admin",
                    forwarding_hops: 0),
                identity: IdentityView(
                    pid: 42, uid: 501, exe: "/usr/bin/ssh", cwd: "/tmp",
                    chain: "zsh -> ssh")))

        XCTAssertTrue(ProjectEventMatcher(project).matches(event))
    }
}
