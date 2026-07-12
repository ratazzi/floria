import Foundation

// Wire types mirroring `accessfs-agent::protocol`. Framing is a 4-byte big-endian
// length prefix followed by that many bytes of JSON.

struct IdentityView: Codable {
    let pid: Int32
    let uid: UInt32
    let exe: String?
    let cwd: String?
    /// Parent-process chain, root-first, e.g. "login -> zsh -> node".
    let chain: String
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
