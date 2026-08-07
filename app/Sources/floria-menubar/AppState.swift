import Foundation
import Observation
import os

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
    var ruleLabel: String { ruleId == "grant" ? "Active grant" : (ruleId ?? "-") }

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
    private static let setupLog = Logger(
        subsystem: ProductIdentity.bundleIdentifier,
        category: "macfuse-setup")

    var connected = false
    /// Non-nil while macFUSE setup is incomplete; drives the setup sheet.
    var macFuseSetupStage: MacFuseSetupStage?
    var macFuseRechecking = false
    var recents: [RecentAccess] = []
    var workspace: WorkspaceStore
    var policyMode = RuntimePolicyStatus.normal
    var policyModeError: String?
    var systemHealth: SystemHealthReport?
    var systemHealthError: String?
    var systemHealthPresentationRequested = false
    var activeGrants: [ActiveGrant] = []
    var activeGrantsError: String?
    var accessHistoryLoading = false
    /// Where the library window should land when opened; the token forces the
    /// window content to re-navigate when a new request targets an open window.
    var workspaceWindowSelection: WorkspaceSidebarSelection = .projects
    var workspaceWindowToken = UUID()

    @ObservationIgnored private var client: AgentClient!
    @ObservationIgnored private let controlClient: ControlClient
    @ObservationIgnored let cloudSyncService: CloudSyncService
    @ObservationIgnored private var policyRefreshTask: Task<Void, Never>?
    @ObservationIgnored private var healthRefreshTask: Task<Void, Never>?
    @ObservationIgnored private var checkoutRefreshTask: Task<Void, Never>?
    @ObservationIgnored private let prompter = PromptPresenter()
    @ObservationIgnored private let daemonManager = DaemonManager()
    @ObservationIgnored private var accessHistoryLoaded = false
    @ObservationIgnored private var macFuseProbeTask: Task<Void, Never>?
    @ObservationIgnored private let macFusePreview =
        ProcessInfo.processInfo.environment["FLORIA_MACFUSE_SETUP_PREVIEW"] != nil

    // Sized for the dashboard table; the dropdown only ever renders a screenful.
    private static let maxRecents = 500

    init() {
        let supportDirectory = (NSHomeDirectory() as NSString)
            .appendingPathComponent("Library/Application Support/floria")
        let sock = (supportDirectory as NSString).appendingPathComponent("agent.sock")
        let controlSock = (supportDirectory as NSString).appendingPathComponent("control.sock")
        let controlClient = ControlClient(socketPath: controlSock)
        self.controlClient = controlClient
        cloudSyncService = CloudSyncService(
            control: controlClient,
            supportDirectory: URL(fileURLWithPath: supportDirectory, isDirectory: true))
        workspace = WorkspaceStore(controlClient: controlClient)

        client = AgentClient(socketPath: sock)
        client.onStateChange = { [weak self] up in
            DispatchQueue.main.async {
                guard let self else { return }
                self.connected = up
                if up {
                    Task {
                        await self.workspace.reload()
                        await self.workspace.refreshProjectCheckoutDiscoveries()
                        await self.reloadSystemHealth()
                        await self.reloadPolicyMode()
                        await self.reloadActiveGrants()
                        await self.loadAccessHistoryIfNeeded()
                    }
                } else {
                    self.systemHealth = nil
                    self.systemHealthError = nil
                    self.scheduleDaemonRecoveryAfterDisconnect()
                }
            }
        }
        client.onCompatibilityError = { [weak self] message in
            DispatchQueue.main.async {
                self?.workspace.lastError = message
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
        // Preview hook for the setup UI on machines where macFUSE is healthy:
        // FLORIA_MACFUSE_SETUP_PREVIEW=install|approve forces a stage (dev + prod builds).
        // The agent/control plumbing stays off so the background doesn't flap between
        // connection states while previewing.
        if macFusePreview {
            macFuseSetupStage =
                ProcessInfo.processInfo.environment["FLORIA_MACFUSE_SETUP_PREVIEW"] == "install"
                    ? .installMacFuse : .approveKext
            return
        }

        client.start()
        Task {
            await workspace.reload()
            await workspace.refreshProjectCheckoutDiscoveries()
            await reloadSystemHealth()
            await reloadPolicyMode()
            await reloadActiveGrants()
            await loadAccessHistoryIfNeeded()
        }
        policyRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                guard let self, !Task.isCancelled else { return }
                await self.reloadPolicyMode()
                await self.reloadActiveGrants()
            }
        }
        healthRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 60_000_000_000)
                guard let self, !Task.isCancelled else { return }
                await self.reloadSystemHealth()
            }
        }
        checkoutRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                guard let self, !Task.isCancelled else { return }
                await self.workspace.refreshProjectCheckoutDiscoveries()
            }
        }

        if DaemonManager.isProductionApp {
            // A packaged app always reconciles the LaunchAgent definition. DaemonManager leaves
            // a running job from the same bundle revision alone, starts it when inactive, and
            // replaces an older but still-connectable daemon so new capabilities become live.
            // macFUSE readiness gates the whole ladder: without it the daemon can only crash-loop.
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 500_000_000)
                self?.evaluateMacFuseSetup(timeoutSeconds: 15)
            }
        }
    }

    /// Run the macFUSE readiness ladder: not installed → stop the daemon (no crash loop)
    /// and show install guidance; installed → start the daemon and require an agent connection,
    /// a numbered kernel device, and an actual Floria macFUSE mount. The agent socket opens
    /// before the blocking mount call, so a connection and global device nodes are not sufficient.
    /// A missing numbered device is
    /// shown after the first probe second so setup does not look inert while launchd, Keychain,
    /// or macFUSE is waiting; the sheet remains provisional and closes only after the mount exists.
    /// Once the numbered device exists, another startup error is shown as a daemon mount failure.
    private func evaluateMacFuseSetup(timeoutSeconds: Int) {
        macFuseProbeTask?.cancel()
        guard DaemonManager.isProductionApp else { return }
        let manager = daemonManager
        guard MacFuseSetupStage.isInstalled else {
            Self.setupLog.notice("macFUSE setup probe found no installation")
            macFuseSetupStage = .installMacFuse
            DispatchQueue.global(qos: .utility).async { manager.stop() }
            return
        }
        Self.setupLog.notice(
            "macFUSE setup probe started; kernel_backend_ready=\(MacFuseSetupStage.isKernelBackendReady, privacy: .public) timeout_seconds=\(timeoutSeconds, privacy: .public)")
        DispatchQueue.global(qos: .utility).async { manager.ensureRunning() }
        macFuseProbeTask = Task { @MainActor [weak self] in
            var loggedPremountConnection = false
            var observedFailedRun = false
            for elapsedSeconds in 0..<timeoutSeconds {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard let self, !Task.isCancelled else { return }
                let kernelBackendReady = MacFuseSetupStage.isKernelBackendReady
                let floriaMounted = MacFuseSetupStage.isFloriaMounted
                if MacFuseSetupStage.daemonConnectionProvesReady(
                    connected: self.connected,
                    kernelBackendReady: kernelBackendReady,
                    floriaMounted: floriaMounted)
                {
                    Self.setupLog.notice("macFUSE setup probe observed the live Floria mount")
                    self.macFuseSetupStage = nil
                    return
                }
                if self.connected && !floriaMounted && !loggedPremountConnection {
                    Self.setupLog.notice(
                        "ignoring a pre-mount agent connection until the Floria mount is live")
                    loggedPremountConnection = true
                }
                if elapsedSeconds == 0 && !kernelBackendReady {
                    Self.setupLog.notice(
                        "presenting provisional macFUSE setup guidance after one probe second")
                    self.macFuseSetupStage = .approveKext
                }
                // launchd reports a completed non-zero run as soon as the mount attempt exits.
                // After a short grace period, use that result instead of making a known-failed
                // setup wait through the full timeout before showing actionable guidance.
                if elapsedSeconds >= 1 {
                    let failed = await Task.detached(priority: .utility) {
                        manager.startupAttemptHasFailed()
                    }.value
                    guard !Task.isCancelled else { return }
                    if failed {
                        Self.setupLog.notice(
                            "macFUSE setup probe observed a failed LaunchAgent run")
                        observedFailedRun = true
                        break
                    }
                }
            }
            guard let self, !Task.isCancelled else { return }
            let stage = MacFuseSetupStage.afterFailedDaemonProbe(
                isInstalled: MacFuseSetupStage.isInstalled,
                kernelBackendReady: MacFuseSetupStage.isKernelBackendReady)
            self.macFuseSetupStage = stage
            if stage == .approveKext || observedFailedRun {
                Self.setupLog.notice("macFUSE setup probe pausing the daemon")
                DispatchQueue.global(qos: .utility).async { manager.stop() }
            } else if stage == .mountFailed {
                // A still-running process may be waiting for the login Keychain authorization
                // dialog. Keep it alive so approving that dialog can resume this exact startup.
                Self.setupLog.notice(
                    "Floria has not mounted yet; leaving the running daemon available to resume")
            }
        }
    }

    /// The socket closes before the mount process has necessarily exited. Let the daemon manager
    /// observe launchd's KeepAlive restart before it actively reconciles the job; immediately
    /// kickstarting a loaded job would leave launchd's throttled restart queued and cause a
    /// second unnecessary daemon generation.
    private func scheduleDaemonRecoveryAfterDisconnect() {
        guard DaemonManager.isProductionApp, MacFuseSetupStage.isInstalled,
              macFuseSetupStage == nil
        else { return }
        let manager = daemonManager
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1) {
            manager.recoverAfterDisconnect()
        }
    }

    func recheckMacFuseSetup() {
        guard !macFusePreview else { return }
        guard !macFuseRechecking else { return }
        macFuseRechecking = true
        evaluateMacFuseSetup(timeoutSeconds: 12)
        let probe = macFuseProbeTask
        Task { @MainActor [weak self] in
            await probe?.value
            self?.macFuseRechecking = false
        }
    }

    /// Finish a durable cross-Vault activation scheduled by Rust. The service blocks further
    /// CloudKit traffic until the replacement daemon reports the authenticated target Vault.
    func restartDaemonForCloudSync() async {
        guard DaemonManager.isProductionApp else { return }
        let manager = daemonManager
        await Task.detached(priority: .utility) { manager.stop() }.value
        try? await Task.sleep(nanoseconds: 250_000_000)
        await Task.detached(priority: .utility) { manager.ensureRunning() }.value
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

    func reloadSystemHealth() async {
        guard connected else { return }
        do {
            systemHealth = try await controlClient.health()
            systemHealthError = nil
        } catch {
            systemHealthError = error.localizedDescription
        }
    }

    func reloadActiveGrants() async {
        do {
            activeGrants = try await controlClient.activeGrants()
            activeGrantsError = nil
        } catch {
            activeGrantsError = error.localizedDescription
        }
    }

    func revokeGrant(id: String) async {
        do {
            activeGrants = try await controlClient.revokeGrant(id: id)
            activeGrantsError = nil
        } catch {
            activeGrantsError = error.localizedDescription
        }
    }

    func clearActiveGrants() async {
        do {
            activeGrants = try await controlClient.clearGrants()
            activeGrantsError = nil
        } catch {
            activeGrantsError = error.localizedDescription
        }
    }

    /// Entering audit-only relaxes every Ask/Touch ID rule daemon-wide, so on a Mac with Touch ID
    /// enrolled it always demands a fresh one, regardless of how recently the user last
    /// authenticated -- unlike per-file touchid grants, there is no narrower scope to fall back
    /// on if this gate is spoofed. Machines with no biometric sensor skip this (callers show a
    /// plain in-app confirmation instead) rather than substituting a device-password prompt.
    /// Leaving audit-only only tightens enforcement, so it stays ungated either way.
    func setPolicyMode(_ mode: RuntimePolicyMode, durationSecs: UInt64?) async {
        if mode == .auditOnly && BiometricAuth.biometricsAvailable() {
            let authenticated = await BiometricAuth.authenticate(
                reason: "enable Audit Only, which allows every Ask and Touch ID item without interaction"
            )
            guard authenticated else {
                policyModeError = "Touch ID is required to enable Audit Only."
                return
            }
        }
        do {
            policyMode = try await controlClient.setPolicyMode(mode, durationSecs: durationSecs)
            policyModeError = nil
            await reloadActiveGrants()
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
        if recent.ruleId == "prompt" {
            Task { await reloadActiveGrants() }
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
