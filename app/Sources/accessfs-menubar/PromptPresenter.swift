import AppKit
import LocalAuthentication
import os
import SwiftUI

/// Shows the modal authorization alert for a prompt and sends back the user's decision.
/// Owns the focus dance: the alert steals focus from whatever the user was doing, and an
/// accessory app has no window to hand it back to — so remember the frontmost app and
/// re-activate it once the decision (including the async Touch ID leg) is settled.
@MainActor
final class PromptPresenter {
    private static let log = Logger(subsystem: "dev.floria.hola.ac", category: "prompt")

    func show(_ p: PromptMsg, send: @escaping (DecisionMsg) -> Void) {
        Self.log.info("showing authorization window req_id=\(p.req_id) path=\(p.path)")

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

        enum Choice {
            case deny
            case allow(PromptGrantScope)
        }
        var choice = Choice.deny
        let panelHeight: CGFloat = p.enforcement == "touchid" ? 490 : 420
        let finish: () -> Void = { NSApp.stopModal() }
        let content = AuthorizationPromptView(
            prompt: p,
            frameHeight: panelHeight,
            deny: { finish() },
            allow: { scope in
                choice = .allow(scope)
                finish()
            })
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: panelHeight),
            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = p.operation == "sign"
            ? "Floria SSH Signature Request"
            : "Floria Access Request"
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.moveToActiveSpace]
        panel.contentView = NSHostingView(rootView: content)
        let panelDelegate = PromptPanelDelegate(onClose: finish)
        panel.delegate = panelDelegate
        panel.center()

        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
        NSApp.runModal(for: panel)
        panel.orderOut(nil)

        switch choice {
        case .deny:
            deny()
            refocus()
        case .allow(.once):
            confirmAllow(p, scope: "once", ttl: nil, send: send, deny: deny, then: refocus)
        case .allow(.tenMinutes):
            confirmAllow(p, scope: "ttl", ttl: 600, send: send, deny: deny, then: refocus)
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
        let reason = Self.biometricReason(for: p)
        authenticateBiometric(reason: reason) { ok in
            if ok { allow() } else { deny() }
            done()
        }
    }

    static func biometricReason(for prompt: PromptMsg) -> String {
        let presentation = PromptPresentation(prompt)
        if prompt.operation == "sign" {
            return "allow \(presentation.requester.displayName) to use SSH identity “\(presentation.targetName)”"
        }
        return "allow \(presentation.requester.displayName) to \(presentation.actionTitle) \(presentation.targetPath)"
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

@MainActor
private final class PromptPanelDelegate: NSObject, NSWindowDelegate {
    private let onClose: () -> Void

    init(onClose: @escaping () -> Void) {
        self.onClose = onClose
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        onClose()
        return true
    }
}
