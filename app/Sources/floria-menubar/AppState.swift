import AppKit
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

    var sshIdentitySource: String? {
        ssh?.identity_source.map { ($0 as NSString).abbreviatingWithTildeInPath }
    }

    /// What access lists show: a human name plus the source that disambiguates equal SSH labels.
    var shownPath: String {
        guard let ssh else { return display ?? path }
        return "\(ssh.key_label) · \(sshIdentitySource ?? ssh.key_fingerprint)"
    }
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
    var macFuseLoadError: String?
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
    @ObservationIgnored private var automaticCloudSyncCoordinator: AutomaticCloudSyncCoordinator?
    @ObservationIgnored private var policyRefreshTask: Task<Void, Never>?
    @ObservationIgnored private var healthRefreshTask: Task<Void, Never>?
    @ObservationIgnored private var checkoutRefreshTask: Task<Void, Never>?
    @ObservationIgnored private var workspacePresentations = Set<UUID>()
    @ObservationIgnored private let prompter = PromptPresenter()
    @ObservationIgnored private let enrollmentPresenter = DeviceEnrollmentPresenter()
    @ObservationIgnored private let daemonManager = DaemonManager()
    @ObservationIgnored private var accessHistoryLoaded = false
    @ObservationIgnored private var macFuseProbeTask: Task<Void, Never>?
    @ObservationIgnored private var sessionObserver: NSObjectProtocol?
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
        automaticCloudSyncCoordinator = nil

        client = AgentClient(socketPath: sock)
        client.onStateChange = { [weak self] up in
            DispatchQueue.main.async {
                guard let self else { return }
                self.connected = up
                if up {
                    Task {
                        await self.refreshDaemonState()
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
        sessionObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.sessionDidResignActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                _ = self.client.send(SessionInactiveMsg())
                try? await Task.sleep(nanoseconds: 100_000_000)
                await self.reloadActiveGrants()
            }
        }
        let coordinator = AutomaticCloudSyncCoordinator(
            service: cloudSyncService,
            restartDaemon: { [weak self] in
                await self?.restartDaemonForCloudSync()
            })
        coordinator.onRemoteChangesApplied = { [weak self] in
            guard let self else { return }
            await self.workspace.reload()
            await self.workspace.refreshProjectCheckoutDiscoveries()
        }
        coordinator.onEnrollmentReview = { [weak self, weak coordinator] review in
            guard let self, let coordinator else { return }
            self.enrollmentPresenter.show(review) { review in
                try await coordinator.approve(review)
                await self.workspace.reload()
                await self.workspace.refreshProjectCheckoutDiscoveries()
            }
        }
        coordinator.onEnrollmentReviewsChanged = { [weak self] reviews in
            self?.enrollmentPresenter.reconcile(reviews)
        }
        automaticCloudSyncCoordinator = coordinator
        coordinator.start()
        Task {
            await refreshDaemonState()
        }
        policyRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                guard let self, !Task.isCancelled else { return }
                await self.reloadPolicyMode()
                await self.reloadActiveGrants()
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

    /// Run the macFUSE readiness ladder: not installed → show install guidance; installed but no
    /// numbered kernel device → invoke macFUSE's trusted loader before touching daemon/Keychain
    /// state; ready → start the daemon and require an agent connection plus an actual Floria mount.
    /// The agent socket opens before the blocking mount call, so a connection and a global device
    /// node are not sufficient on their own.
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
        macFuseProbeTask = Task { @MainActor [weak self] in
            guard let self else { return }
            if !MacFuseSetupStage.isKernelBackendReady {
                self.macFuseSetupStage = .approveKext
                self.macFuseLoadError = nil
                Self.setupLog.notice(
                    "requesting the macFUSE kernel backend before starting the daemon")
                let result = await Task.detached(priority: .utility) {
                    MacFuseKernelBackend().ensureLoaded()
                }.value
                guard !Task.isCancelled else { return }
                switch result {
                case .ready:
                    Self.setupLog.notice("macFUSE loader published a numbered device")
                case .requested(let status):
                    Self.setupLog.notice(
                        "macFUSE loader request completed; status=\(status, privacy: .public); waiting for system approval or restart")
                    DispatchQueue.global(qos: .utility).async { manager.stop() }
                    return
                case .failed(let message):
                    self.macFuseLoadError = message
                    Self.setupLog.error(
                        "macFUSE loader request failed: \(message, privacy: .public)")
                    DispatchQueue.global(qos: .utility).async { manager.stop() }
                    return
                }
            }

            self.macFuseLoadError = nil
            Self.setupLog.notice(
                "macFUSE mount probe started; timeout_seconds=\(timeoutSeconds, privacy: .public)")
            DispatchQueue.global(qos: .utility).async { manager.ensureRunning() }
            var loggedPremountConnection = false
            var observedFailedRun = false
            for elapsedSeconds in 0..<timeoutSeconds {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard !Task.isCancelled else { return }
                let kernelBackendReady = MacFuseSetupStage.isKernelBackendReady
                let floriaMounted = MacFuseSetupStage.isFloriaMounted
                if MacFuseSetupStage.daemonConnectionProvesReady(
                    connected: self.connected,
                    kernelBackendReady: kernelBackendReady,
                    floriaMounted: floriaMounted)
                {
                    Self.setupLog.notice("macFUSE setup probe observed the live Floria mount")
                    self.macFuseSetupStage = nil
                    // The agent socket becomes available before the daemon finishes opening its
                    // control socket and mounting macFUSE. Its earlier connection callback may
                    // therefore have observed an empty Workspace. Mount readiness is the first
                    // point where a successful snapshot is guaranteed, so refresh explicitly.
                    await self.refreshDaemonState()
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
                // The daemon can stop cleanly before AgentClient completes its first handshake,
                // so no disconnect callback exists to schedule recovery. Reconciliation is
                // idempotent for a running job and kickstarts a loaded, successfully exited one.
                await Task.detached(priority: .utility) { manager.ensureRunning() }.value
            }
            guard !Task.isCancelled else { return }
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

    private func refreshDaemonState() async {
        await workspace.reload()
        await workspace.refreshProjectCheckoutDiscoveries()
        await reloadSystemHealth()
        await reloadPolicyMode()
        await reloadActiveGrants()
        await loadAccessHistoryIfNeeded()
    }

    func setWorkspacePresentation(_ id: UUID, visible: Bool) {
        if visible {
            workspacePresentations.insert(id)
        } else {
            workspacePresentations.remove(id)
        }
        guard !workspacePresentations.isEmpty else {
            checkoutRefreshTask?.cancel()
            checkoutRefreshTask = nil
            healthRefreshTask?.cancel()
            healthRefreshTask = nil
            return
        }
        if checkoutRefreshTask == nil {
            checkoutRefreshTask = Task { [weak self] in
                guard let self else { return }
                await self.workspace.refreshProjectCheckoutDiscoveries()
                // Git changes advance the daemon's in-memory revision. A full pass once per minute
                // also repairs visible UI state after link changes that Git cannot observe.
                var pollsUntilFullRefresh = 20
                while !Task.isCancelled {
                    do {
                        try await Task.sleep(nanoseconds: 3_000_000_000)
                    } catch {
                        return
                    }
                    guard !Task.isCancelled else { return }
                    pollsUntilFullRefresh -= 1
                    let force = pollsUntilFullRefresh == 0
                    await self.workspace.refreshProjectCheckoutDiscoveries(force: force)
                    if force {
                        pollsUntilFullRefresh = 20
                    }
                }
            }
        }
        if healthRefreshTask == nil {
            healthRefreshTask = Task { [weak self] in
                guard let self else { return }
                await self.reloadSystemHealth()
                while !Task.isCancelled {
                    do {
                        try await Task.sleep(nanoseconds: 60_000_000_000)
                    } catch {
                        return
                    }
                    guard !Task.isCancelled else { return }
                    await self.reloadSystemHealth()
                }
            }
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
