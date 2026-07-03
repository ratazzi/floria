import AppKit
import LocalAuthentication

/// Menubar (accessory) app: shows authorization prompts from the daemon and a recent-access list.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var client: AgentClient!
    private var recent: [String] = []
    private var connected = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.image = NSImage(
            systemSymbolName: "lock.shield", accessibilityDescription: "AccessFS")
        rebuildMenu()

        let sock = (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Application Support/floria/agent.sock")
        client = AgentClient(socketPath: sock)
        client.onStateChange = { [weak self] up in
            DispatchQueue.main.async { self?.connected = up; self?.rebuildMenu() }
        }
        client.onAccessEvent = { [weak self] ev in
            DispatchQueue.main.async { self?.addRecent(ev) }
        }
        client.onPrompt = { [weak self] p in
            DispatchQueue.main.async { self?.showPrompt(p) }
        }
        client.start()
    }

    private func addRecent(_ ev: AccessEventMsg) {
        let exe = (ev.identity.exe as NSString?)?.lastPathComponent ?? "?"
        recent.insert("\(ev.decision)  \(exe)  \(ev.path)", at: 0)
        if recent.count > 20 { recent.removeLast() }
        rebuildMenu()
    }

    private func rebuildMenu() {
        let menu = NSMenu()
        menu.addItem(
            NSMenuItem(
                title: connected ? "● agent connected" : "○ agent not connected",
                action: nil, keyEquivalent: ""))
        menu.addItem(.separator())
        if recent.isEmpty {
            menu.addItem(NSMenuItem(title: "No recent access", action: nil, keyEquivalent: ""))
        } else {
            for line in recent {
                menu.addItem(NSMenuItem(title: line, action: nil, keyEquivalent: ""))
            }
        }
        menu.addItem(.separator())
        menu.addItem(
            NSMenuItem(
                title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        statusItem.menu = menu
    }

    private func showPrompt(_ p: PromptMsg) {
        let alert = NSAlert()
        alert.messageText = "Allow access to \(p.path)?"
        let exe = (p.identity.exe as NSString?)?.lastPathComponent ?? "?"
        var info =
            "Reader: \(exe)\nChain: \(p.identity.chain)\nPID: \(p.identity.pid)   CWD: \(p.identity.cwd ?? "?")"
        if p.enforcement == "touchid" { info += "\n\nTouch ID required to allow." }
        alert.informativeText = info
        alert.addButton(withTitle: "Allow once")
        alert.addButton(withTitle: "Allow 10 min")
        alert.addButton(withTitle: "Deny")

        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            confirmAllow(p, scope: "once", ttl: nil)
        case .alertSecondButtonReturn:
            confirmAllow(p, scope: "ttl", ttl: 600)
        default:
            send(deny: p)
        }
    }

    /// Send an allow decision, first gating on Touch ID when the path requires it.
    private func confirmAllow(_ p: PromptMsg, scope: String, ttl: UInt64?) {
        let allow = { [weak self] in
            self?.client.send(
                DecisionMsg(req_id: p.req_id, outcome: "allow", scope: scope, ttl_secs: ttl))
        }
        guard p.enforcement == "touchid" else {
            allow()
            return
        }
        authenticateBiometric(reason: "allow access to \(p.path)") { [weak self] ok in
            if ok { allow() } else { self?.send(deny: p) }
        }
    }

    private func send(deny p: PromptMsg) {
        client.send(DecisionMsg(req_id: p.req_id, outcome: "deny", scope: nil, ttl_secs: nil))
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

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)  // menubar only, no Dock icon, no bundle needed
app.run()
