import Foundation

// Wire types mirroring `floria-agent::protocol`. Framing is a 4-byte big-endian
// length prefix followed by that many bytes of JSON.

let supportedAgentProtocolVersion: UInt32 = 2

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
    /// Original managed-key path or external-agent endpoint, when known on this Device.
    let identity_source: String?
    /// Display-only token from the local ssh command. It is not a verified destination identity.
    let requested_destination: String?
    /// Host-key fingerprint proven by OpenSSH's session-bind extension; identifies a key, not a name.
    let verified_host_key_fingerprint: String?
    /// Account from the user-auth request tied to the verified session.
    let ssh_user: String?
    /// Verified forwarding bindings before the final authentication session.
    let forwarding_hops: Int?

    init(
        surface_id: String, surface_name: String, resource_id: String,
        key_fingerprint: String, key_label: String, identity_source: String? = nil,
        requested_destination: String?, verified_host_key_fingerprint: String?,
        ssh_user: String?, forwarding_hops: Int?
    ) {
        self.surface_id = surface_id
        self.surface_name = surface_name
        self.resource_id = resource_id
        self.key_fingerprint = key_fingerprint
        self.key_label = key_label
        self.identity_source = identity_source
        self.requested_destination = requested_destination
        self.verified_host_key_fingerprint = verified_host_key_fingerprint
        self.ssh_user = ssh_user
        self.forwarding_hops = forwarding_hops
    }
}

// Incoming (daemon -> app)

struct AgentHelloMsg: Decodable {
    let version: UInt32
    let daemon_version: String?
}

struct AgentProtocolErrorMsg: Decodable {
    let expected_version: UInt32
    let received_version: UInt32?
}

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
    let version = supportedAgentProtocolVersion
}

struct SessionInactiveMsg: Encodable {
    let type = "session_inactive"
}

struct DecisionMsg: Encodable {
    let type = "decision"
    let req_id: UInt64
    let outcome: String  // "allow" | "deny"
    let scope: String?   // "once" | "today" | "until_lock" | "ttl" | app scopes
    let ttl_secs: UInt64?
}
