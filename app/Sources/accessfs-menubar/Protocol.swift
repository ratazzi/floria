import Foundation

// Wire types mirroring `accessfs-agent::protocol`. Framing is a 4-byte big-endian
// length prefix followed by that many bytes of JSON.

struct ProcessView: Codable, Hashable {
    let pid: Int32
    let name: String
    let exe: String?
}

struct IdentityView: Codable {
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

struct PolicyEvaluationView: Codable {
    let configured_enforcement: String
    let effective_enforcement: String
    let mode: String
}

// Incoming (daemon -> app)

struct PromptMsg: Decodable {
    let req_id: UInt64
    let path: String
    /// Human-facing name (a secret's original source path); `path` stays the rule key.
    let display: String?
    let operation: String
    let enforcement: String
    let identity: IdentityView
}

struct AccessEventMsg: Decodable {
    let ts: String
    let path: String
    /// Human-facing name (a secret's original source path); `path` stays the rule key.
    let display: String?
    /// "read" or "write" — with a writable mount, decision alone is ambiguous.
    let operation: String
    let decision: String
    let rule_id: String?
    let policy: PolicyEvaluationView?
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
