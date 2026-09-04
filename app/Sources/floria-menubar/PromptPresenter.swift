import AppKit
import LocalAuthentication
import os
import SwiftUI

/// Owns the complete lifetime of interactive authorization requests.
///
/// Prompts are ordinary non-modal windows: the app menu, menu bar extra, quitting, Window menu,
/// Mission Control, and other Floria windows must remain usable while a FUSE request waits. One
/// request is shown at a time; later requests stay queued with the same bounded lifetime.
@MainActor
final class PromptPresenter {
    private static let log = Logger(
        subsystem: ProductIdentity.bundleIdentifier, category: "prompt")

    private enum Choice {
        case deny
        case allow(PromptGrantScope)
    }

    private struct PendingPrompt {
        let prompt: PromptMsg
        let send: (DecisionMsg) -> Void
        let deadline: UInt64
    }

    private final class ActivePrompt {
        let pending: PendingPrompt
        let windowController: NSWindowController
        let windowDelegate: PromptWindowDelegate
        var timeoutTask: Task<Void, Never>?
        var authenticationContext: LAContext?
        var isSettling = false

        init(
            pending: PendingPrompt,
            windowController: NSWindowController,
            windowDelegate: PromptWindowDelegate
        ) {
            self.pending = pending
            self.windowController = windowController
            self.windowDelegate = windowDelegate
        }
    }

    private let lifetimeNanoseconds: UInt64
    private let dockVisibilityController: DockVisibilityController
    private let sleep: @Sendable (UInt64) async throws -> Void
    private var queue = [PendingPrompt]()
    private var active: ActivePrompt?
    private var previousApplication: NSRunningApplication?

    var activeWindow: NSWindow? { active?.windowController.window }

    init(
        lifetimeNanoseconds: UInt64 = 28_000_000_000,
        dockVisibilityController: DockVisibilityController? = nil,
        sleep: @escaping @Sendable (UInt64) async throws -> Void = {
            try await Task.sleep(nanoseconds: $0)
        }
    ) {
        self.lifetimeNanoseconds = lifetimeNanoseconds
        self.dockVisibilityController = dockVisibilityController ?? .shared
        self.sleep = sleep
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationDidBecomeActive),
            name: NSApplication.didBecomeActiveNotification,
            object: nil)
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    func show(_ prompt: PromptMsg, send: @escaping (DecisionMsg) -> Void) {
        Self.log.info(
            "queueing authorization window req_id=\(prompt.req_id) path=\(prompt.path)")
        if active == nil, queue.isEmpty {
            previousApplication = NSWorkspace.shared.frontmostApplication
        }
        let now = DispatchTime.now().uptimeNanoseconds
        let (deadline, overflow) = now.addingReportingOverflow(lifetimeNanoseconds)
        queue.append(
            PendingPrompt(
                prompt: prompt,
                send: send,
                deadline: overflow ? UInt64.max : deadline))
        presentNextIfNeeded()
    }

    private func presentNextIfNeeded() {
        guard active == nil else { return }

        while !queue.isEmpty {
            let pending = queue.removeFirst()
            let now = DispatchTime.now().uptimeNanoseconds
            guard pending.deadline > now else {
                Self.log.info("deny expired queued req_id=\(pending.prompt.req_id)")
                pending.send(denyDecision(for: pending.prompt))
                continue
            }

            dockVisibilityController.authorizationPromptDidOpen()
            let window = makeWindow(for: pending.prompt)
            let windowController = NSWindowController(window: window)
            let delegate = PromptWindowDelegate { [weak self] in
                self?.settle(.deny, requestID: pending.prompt.req_id)
            }
            window.delegate = delegate
            let session = ActivePrompt(
                pending: pending,
                windowController: windowController,
                windowDelegate: delegate)
            active = session

            let remaining = pending.deadline - now
            let sleep = self.sleep
            session.timeoutTask = Task { @MainActor [weak self, weak session] in
                do {
                    try await sleep(remaining)
                } catch {
                    return
                }
                guard let self, let session, self.active === session else { return }
                Self.log.info("deny expired visible req_id=\(pending.prompt.req_id)")
                self.expire(session)
            }

            Self.log.info(
                "showing authorization window req_id=\(pending.prompt.req_id) path=\(pending.prompt.path)")
            NSApplication.shared.activate(ignoringOtherApps: true)
            windowController.showWindow(nil)
            window.makeKeyAndOrderFront(nil)
            return
        }

        finishPresentationBatch()
    }

    private func makeWindow(for prompt: PromptMsg) -> NSWindow {
        let height: CGFloat = prompt.enforcement == "touchid" ? 450 : 370
        let content = AuthorizationPromptView(
            prompt: prompt,
            frameHeight: height,
            deny: { [weak self] in
                self?.settle(.deny, requestID: prompt.req_id)
            },
            allow: { [weak self] scope in
                self?.settle(.allow(scope), requestID: prompt.req_id)
            })
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: height),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        window.title = prompt.operation == "sign"
            ? "Floria SSH Signature Request"
            : "Floria Access Request"
        window.isReleasedWhenClosed = false
        window.isExcludedFromWindowsMenu = false
        window.canHide = false
        window.level = .floating
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        window.tabbingMode = .disallowed
        window.backgroundColor = .controlBackgroundColor
        window.isOpaque = true
        window.contentView = NSHostingView(rootView: content)
        window.center()
        return window
    }

    private func settle(_ choice: Choice, requestID: UInt64) {
        guard let session = active,
              session.pending.prompt.req_id == requestID,
              !session.isSettling
        else { return }
        session.isSettling = true
        closeWindow(session)

        switch choice {
        case .deny:
            session.timeoutTask?.cancel()
            complete(session, decision: denyDecision(for: session.pending.prompt))

        case .allow(let scope):
            let prompt = session.pending.prompt
            guard prompt.enforcement == "touchid" else {
                session.timeoutTask?.cancel()
                complete(
                    session,
                    decision: DecisionMsg(
                        req_id: prompt.req_id,
                        outcome: "allow",
                        scope: scope.wireScope,
                        ttl_secs: scope.ttlSeconds))
                return
            }
            authenticateBiometric(
                reason: Self.biometricReason(for: prompt),
                requestID: prompt.req_id,
                scope: scope,
                session: session)
        }
    }

    private func expire(_ session: ActivePrompt) {
        guard active === session else { return }
        session.isSettling = true
        session.timeoutTask?.cancel()
        session.authenticationContext?.invalidate()
        session.authenticationContext = nil
        closeWindow(session)
        complete(session, decision: denyDecision(for: session.pending.prompt))
    }

    private func closeWindow(_ session: ActivePrompt) {
        session.windowController.window?.delegate = nil
        session.windowController.close()
    }

    private func complete(_ session: ActivePrompt, decision: DecisionMsg) {
        guard active === session else { return }
        Self.log.info(
            "\(decision.outcome, privacy: .public) req_id=\(decision.req_id) scope=\(decision.scope ?? "none", privacy: .public)")
        session.pending.send(decision)
        active = nil
        if queue.isEmpty {
            finishPresentationBatch()
        } else {
            presentNextIfNeeded()
        }
    }

    private func finishPresentationBatch() {
        guard active == nil, queue.isEmpty else { return }
        dockVisibilityController.authorizationPromptDidClose()
        defer { previousApplication = nil }
        guard let previousApplication,
              previousApplication.processIdentifier
                != NSRunningApplication.current.processIdentifier
        else { return }
        _ = previousApplication.activate(from: .current)
    }

    private func denyDecision(for prompt: PromptMsg) -> DecisionMsg {
        DecisionMsg(req_id: prompt.req_id, outcome: "deny", scope: nil, ttl_secs: nil)
    }

    @objc private func applicationDidBecomeActive() {
        guard let window = activeWindow else { return }
        window.makeKeyAndOrderFront(nil)
    }

    static func biometricReason(for prompt: PromptMsg) -> String {
        let presentation = PromptPresentation(prompt)
        if prompt.operation == "sign" {
            return "allow \(presentation.requester.displayName) to use SSH identity “\(presentation.targetName)”"
        }
        return "allow \(presentation.requester.displayName) to \(presentation.actionTitle) \(presentation.targetPath)"
    }

    /// Prompt for biometric auth (Touch ID), falling back to password if biometrics are unavailable.
    private func authenticateBiometric(
        reason: String,
        requestID: UInt64,
        scope: PromptGrantScope,
        session: ActivePrompt
    ) {
        let context = LAContext()
        session.authenticationContext = context
        var error: NSError?
        let policy: LAPolicy =
            context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication
        context.evaluatePolicy(policy, localizedReason: reason) { [weak self] allowed, _ in
            Task { @MainActor [weak self] in
                self?.completeBiometric(allowed, requestID: requestID, scope: scope)
            }
        }
    }

    private func completeBiometric(
        _ allowed: Bool,
        requestID: UInt64,
        scope: PromptGrantScope
    ) {
        guard let session = active, session.pending.prompt.req_id == requestID else { return }
        session.authenticationContext = nil
        session.timeoutTask?.cancel()
        let decision = allowed
            ? DecisionMsg(
                req_id: requestID,
                outcome: "allow",
                scope: scope.wireScope,
                ttl_secs: scope.ttlSeconds)
            : denyDecision(for: session.pending.prompt)
        complete(session, decision: decision)
    }
}

@MainActor
private final class PromptWindowDelegate: NSObject, NSWindowDelegate {
    private let onClose: () -> Void

    init(onClose: @escaping () -> Void) {
        self.onClose = onClose
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        onClose()
        return false
    }
}
