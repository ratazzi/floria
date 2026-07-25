import Foundation
import Observation

/// One line of the recent-access list, decoded from an AccessEvent.
struct RecentAccess: Identifiable {
    let id: String
    let date: Date?
    let path: String
    /// Tilde-abbreviated original source path, when the daemon knows one (secrets).
    let display: String?
    let operation: String  // "read" | "write" | "sign"
    let decision: String   // "allowed" | "denied"
    let exe: String
    /// Full executable path (icon lookup in the dashboard).
    let exePath: String?
    let chain: String
    let ruleId: String?
    let policy: PolicyEvaluationView?
    let ssh: SshSignView?

    var allowed: Bool { decision == "allowed" }
    var wasGloballyOverridden: Bool {
        policy?.configured_enforcement != policy?.effective_enforcement
            && policy?.mode == "audit_only"
    }

    /// What the list shows: the friendly name over the opaque `secrets/<uuid>` path.
    var shownPath: String { ssh?.key_label ?? display ?? path }

    var time: String {
        guard let date else { return "" }
        return Self.clock.string(from: date)
    }

    private static let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    init(_ ev: AccessEventMsg) {
        id = [
            ev.ts, ev.path, ev.operation, ev.decision, String(ev.identity.pid),
            ev.rule_id ?? "", ev.ssh?.key_fingerprint ?? "",
        ].joined(separator: "\u{1f}")
        date = Self.iso.date(from: ev.ts)
        path = ev.path
        display = ev.display.map { ($0 as NSString).abbreviatingWithTildeInPath }
        operation = ev.operation
        decision = ev.decision
        exe = (ev.identity.exe as NSString?)?.lastPathComponent ?? "?"
        exePath = ev.identity.exe
        chain = ev.identity.chain
        ruleId = ev.rule_id
        policy = ev.policy
        ssh = ev.ssh
    }

    private static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
}

/// App-wide observable state: agent connection, recent access feed, prompt dispatch.
@Observable @MainActor
final class AppState {
    var connected = false
    var recents: [RecentAccess] = []
    var workspace: WorkspaceStore
    var policyMode = RuntimePolicyStatus.normal
    var policyModeError: String?
    var accessHistoryLoading = false

    @ObservationIgnored private var client: AgentClient!
    @ObservationIgnored private let controlClient: ControlClient
    @ObservationIgnored private var policyRefreshTask: Task<Void, Never>?
    @ObservationIgnored private let prompter = PromptPresenter()
    @ObservationIgnored private let daemonManager = DaemonManager()
    @ObservationIgnored private var accessHistoryLoaded = false

    // Sized for the dashboard table; the dropdown only ever renders a screenful.
    private static let maxRecents = 500

    init() {
        let supportDirectory = (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Application Support/floria")
        let sock = (supportDirectory as NSString).appendingPathComponent("agent.sock")
        let controlSock = (supportDirectory as NSString).appendingPathComponent("control.sock")
        let controlClient = ControlClient(socketPath: controlSock)
        self.controlClient = controlClient
        workspace = WorkspaceStore(controlClient: controlClient)

        client = AgentClient(socketPath: sock)
        client.onStateChange = { [weak self] up in
            DispatchQueue.main.async {
                guard let self else { return }
                self.connected = up
                if up {
                    Task {
                        await self.workspace.reload()
                        await self.reloadPolicyMode()
                        await self.loadAccessHistoryIfNeeded()
                    }
                }
            }
        }
        client.onAccessEvent = { [weak self] ev in
            DispatchQueue.main.async { self?.add(ev) }
        }
        client.onPrompt = { [weak self] p in
            DispatchQueue.main.async {
                guard let self else { return }
                self.prompter.show(p) { decision in self.client.send(decision) }
            }
        }
        client.start()
        Task {
            await workspace.reload()
            await reloadPolicyMode()
            await loadAccessHistoryIfNeeded()
        }
        policyRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                guard let self, !Task.isCancelled else { return }
                await self.reloadPolicyMode()
            }
        }

        // A packaged app always reconciles the LaunchAgent definition. DaemonManager makes
        // the same bundle revision a no-op, while a newly installed bundle must replace an
        // older but still-connectable daemon so new control-plane capabilities become live.
        if DaemonManager.isProductionApp {
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 500_000_000)
                guard let self else { return }
                let manager = self.daemonManager
                DispatchQueue.global(qos: .utility).async {
                    manager.ensureRunning()
                }
            }
        }
    }

    func clearRecents() {
        recents.removeAll()
    }

    func loadAccessHistoryIfNeeded() async {
        guard !accessHistoryLoaded, !accessHistoryLoading else { return }
        accessHistoryLoading = true
        defer { accessHistoryLoading = false }
        do {
            merge(try await controlClient.accessHistory(limit: Self.maxRecents))
            accessHistoryLoaded = true
        } catch {
            // A daemon from an older bundle may still be restarting. The next connection event
            // retries; live access events remain available in the meantime.
        }
    }

    func reloadPolicyMode() async {
        do {
            policyMode = try await controlClient.policyMode()
            policyModeError = nil
        } catch {
            policyModeError = error.localizedDescription
        }
    }

    func setPolicyMode(_ mode: RuntimePolicyMode, durationSecs: UInt64?) async {
        do {
            policyMode = try await controlClient.setPolicyMode(mode, durationSecs: durationSecs)
            policyModeError = nil
        } catch {
            policyModeError = error.localizedDescription
        }
    }

    private func add(_ ev: AccessEventMsg) {
        let recent = RecentAccess(ev)
        guard !recents.contains(where: { $0.id == recent.id }) else { return }
        recents.insert(recent, at: 0)
        if recents.count > Self.maxRecents {
            recents.removeLast(recents.count - Self.maxRecents)
        }
    }

    private func merge(_ events: [AccessEventMsg]) {
        var seen = Set(recents.map(\.id))
        for event in events {
            let recent = RecentAccess(event)
            if seen.insert(recent.id).inserted {
                recents.append(recent)
            }
        }
        recents.sort { ($0.date ?? .distantPast) > ($1.date ?? .distantPast) }
        if recents.count > Self.maxRecents {
            recents.removeLast(recents.count - Self.maxRecents)
        }
    }
}
