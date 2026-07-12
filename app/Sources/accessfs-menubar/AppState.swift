import Foundation
import Observation

/// One line of the recent-access list, decoded from an AccessEvent.
struct RecentAccess: Identifiable {
    let id = UUID()
    let date: Date?
    let path: String
    /// Tilde-abbreviated original source path, when the daemon knows one (secrets).
    let display: String?
    let operation: String  // "read" | "write"
    let decision: String   // "allowed" | "denied"
    let exe: String
    let chain: String
    let ruleId: String?

    var allowed: Bool { decision == "allowed" }

    /// What the list shows: the friendly name over the opaque `secrets/<uuid>` path.
    var shownPath: String { display ?? path }

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
        date = Self.iso.date(from: ev.ts)
        path = ev.path
        display = ev.display.map { ($0 as NSString).abbreviatingWithTildeInPath }
        operation = ev.operation
        decision = ev.decision
        exe = (ev.identity.exe as NSString?)?.lastPathComponent ?? "?"
        chain = ev.identity.chain
        ruleId = ev.rule_id
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

    @ObservationIgnored private var client: AgentClient!
    @ObservationIgnored private let prompter = PromptPresenter()

    private static let maxRecents = 50

    init() {
        let sock = (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Application Support/floria/agent.sock")
        client = AgentClient(socketPath: sock)
        client.onStateChange = { [weak self] up in
            DispatchQueue.main.async { self?.connected = up }
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
    }

    func clearRecents() {
        recents.removeAll()
    }

    private func add(_ ev: AccessEventMsg) {
        recents.insert(RecentAccess(ev), at: 0)
        if recents.count > Self.maxRecents {
            recents.removeLast(recents.count - Self.maxRecents)
        }
    }
}
