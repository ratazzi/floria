import AppKit
import LocalAuthentication
import os

/// Shows the modal authorization alert for a prompt and sends back the user's decision.
/// Owns the focus dance: the alert steals focus from whatever the user was doing, and an
/// accessory app has no window to hand it back to — so remember the frontmost app and
/// re-activate it once the decision (including the async Touch ID leg) is settled.
@MainActor
final class PromptPresenter {
    private static let log = Logger(subsystem: "dev.floria.hola.ac", category: "prompt")

    func show(_ p: PromptMsg, send: @escaping (DecisionMsg) -> Void) {
        Self.log.info("showing alert req_id=\(p.req_id) path=\(p.path)")
        let alert = NSAlert()
        let friendly = p.display.map { ($0 as NSString).abbreviatingWithTildeInPath }
        alert.messageText = "Allow \(p.operation) access to \(friendly ?? p.path)?"
        let exe = (p.identity.exe as NSString?)?.lastPathComponent ?? "?"
        var info =
            "\(p.operation == "write" ? "Writer" : "Reader"): \(exe)\nChain: \(p.identity.chain)\nPID: \(p.identity.pid)   CWD: \(p.identity.cwd ?? "?")"
        if friendly != nil { info += "\nMount path: \(p.path)" }
        if p.enforcement == "touchid" { info += "\n\nTouch ID required to allow." }
        alert.informativeText = info
        alert.addButton(withTitle: "Allow once")
        alert.addButton(withTitle: "Allow 10 min")
        alert.addButton(withTitle: "Deny")

        let previous = NSWorkspace.shared.frontmostApplication
        let refocus = {
            guard let previous,
                previous.processIdentifier != NSRunningApplication.current.processIdentifier
            else { return }
            _ = previous.activate(from: .current)
        }
        let deny = {
            Self.log.info("deny req_id=\(p.req_id)")
            send(DecisionMsg(req_id: p.req_id, outcome: "deny", scope: nil, ttl_secs: nil))
        }

        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            confirmAllow(p, scope: "once", ttl: nil, send: send, deny: deny, then: refocus)
        case .alertSecondButtonReturn:
            confirmAllow(p, scope: "ttl", ttl: 600, send: send, deny: deny, then: refocus)
        default:
            deny()
            refocus()
        }
    }

    /// Send an allow decision, first gating on Touch ID when the path requires it.
    /// `done` runs after the decision is fully settled (Touch ID included) — used to refocus.
    private func confirmAllow(
        _ p: PromptMsg, scope: String, ttl: UInt64?,
        send: @escaping (DecisionMsg) -> Void,
        deny: @escaping () -> Void,
        then done: @escaping () -> Void
    ) {
        let allow = {
            Self.log.info("allow req_id=\(p.req_id) scope=\(scope)")
            send(DecisionMsg(req_id: p.req_id, outcome: "allow", scope: scope, ttl_secs: ttl))
        }
        guard p.enforcement == "touchid" else {
            allow()
            done()
            return
        }
        authenticateBiometric(reason: "allow access to \(p.path)") { ok in
            if ok { allow() } else { deny() }
            done()
        }
    }

    /// Prompt for biometric auth (Touch ID), falling back to password if biometrics are unavailable.
    private func authenticateBiometric(reason: String, completion: @escaping (Bool) -> Void) {
        let ctx = LAContext()
        var err: NSError?
        let policy: LAPolicy =
            ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        ctx.evaluatePolicy(policy, localizedReason: reason) { ok, _ in
            DispatchQueue.main.async { completion(ok) }
        }
    }
}
