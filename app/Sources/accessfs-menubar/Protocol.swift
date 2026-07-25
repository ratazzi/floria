import Foundation

// Wire types mirroring `accessfs-agent::protocol`. Framing is a 4-byte big-endian
// length prefix followed by that many bytes of JSON.

struct ProcessView: Codable, Hashable, Sendable {
    let pid: Int32
    let name: String
    let exe: String?
}

struct IdentityView: Codable, Sendable {
    let pid: Int32
    let uid: UInt32
    let exe: String?
    let cwd: String?
    let cmdline: [String]?
    let bundle_id: String?
    let team_id: String?
    /// Parent processes in root-first order. Optional while decoding older fixture messages.
    let parent_chain: [ProcessView]?
    /// Parent-process chain, root-first, e.g. "login -> zsh -> node".
    let chain: String

    init(
        pid: Int32, uid: UInt32, exe: String?, cwd: String?, chain: String,
        cmdline: [String]? = nil, bundle_id: String? = nil, team_id: String? = nil,
        parent_chain: [ProcessView]? = nil
    ) {
        self.pid = pid
        self.uid = uid
        self.exe = exe
        self.cwd = cwd
        self.cmdline = cmdline
        self.bundle_id = bundle_id
        self.team_id = team_id
        self.parent_chain = parent_chain
        self.chain = chain
    }
}

struct PolicyEvaluationView: Codable, Sendable {
    let configured_enforcement: String
    let effective_enforcement: String
    let mode: String
}

struct SshSignView: Codable, Sendable {
    let surface_id: String
    let surface_name: String
    let resource_id: String
    let key_fingerprint: String
    let key_label: String
    /// Display-only token from the local ssh command. It is not a verified destination identity.
    let requested_destination: String?
    /// Host-key fingerprint proven by OpenSSH's session-bind extension; identifies a key, not a name.
    let verified_host_key_fingerprint: String?
    /// Account from the user-auth request tied to the verified session.
    let ssh_user: String?
    /// Verified forwarding bindings before the final authentication session.
    let forwarding_hops: Int?
}

// Incoming (daemon -> app)

struct PromptMsg: Decodable {
    let req_id: UInt64
    let path: String
    /// Human-facing name (a secret's original source path); `path` stays the rule key.
    let display: String?
    let operation: String
    let enforcement: String
    let ssh: SshSignView?
    let identity: IdentityView
}

struct AccessEventMsg: Decodable, Sendable {
    let ts: String
    let path: String
    /// Human-facing name (a secret's original source path); `path` stays the rule key.
    let display: String?
    /// "read", "write", or "sign" — decision alone is ambiguous.
    let operation: String
    let decision: String
    let rule_id: String?
    let policy: PolicyEvaluationView?
    let ssh: SshSignView?
    let identity: IdentityView
}

// Outgoing (app -> daemon)

struct HelloMsg: Encodable {
    let type = "hello"
    let version = 1
}

struct DecisionMsg: Encodable {
    let type = "decision"
    let req_id: UInt64
    let outcome: String  // "allow" | "deny"
    let scope: String?   // "once" | "ttl" | "app_file" | "app_project"
    let ttl_secs: UInt64?
}
