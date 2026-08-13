import Darwin
import Foundation
import os

/// Installs and maintains the bundled Rust mount process as a per-user LaunchAgent.
/// The manager is only active in a packaged app; `swift run` keeps using a manually
/// started daemon so development does not mutate launchd state.
struct DaemonManager: Sendable {
    static let bundleIdentifier = ProductIdentity.bundleIdentifier

    private static let log = Logger(subsystem: bundleIdentifier, category: "daemon")
    private let serviceLabel = ProductIdentity.daemonServiceLabel

    static var isProductionApp: Bool {
        Bundle.main.bundleIdentifier == bundleIdentifier
    }

    private var serviceTarget: String {
        "gui/\(getuid())/\(serviceLabel)"
    }

    private var homeDirectory: URL {
        URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
    }

    private var runtimeDirectory: URL {
        homeDirectory.appendingPathComponent("Library/Application Support/floria", isDirectory: true)
    }

    private var configURL: URL {
        runtimeDirectory.appendingPathComponent("floria.toml")
    }

    private var launchAgentURL: URL {
        homeDirectory
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
            .appendingPathComponent("\(serviceLabel).plist")
    }

    private var reconciliationLockURL: URL {
        runtimeDirectory.appendingPathComponent("daemon-reconcile.lock")
    }

    private var daemonURL: URL? {
        Bundle.main.url(forResource: "floria", withExtension: nil)
    }

    /// Ensure the current bundle's daemon definition is installed and running. A changed
    /// app build rewrites and reloads the job; reopening the same build starts an inactive
    /// job without disturbing one that is already running.
    func ensureRunning() {
        guard Self.isProductionApp else { return }

        do {
            guard let daemonURL, FileManager.default.isExecutableFile(atPath: daemonURL.path) else {
                throw DaemonError.noBinary
            }

            try prepareRuntimeDirectory()
            try withReconciliationLock {
                try prepareRuntimeFiles()
                if installedDefinitionMatches(daemonPath: daemonURL.path) {
                    let status = currentLaunchAgentStatus
                    switch status.state {
                    case .running:
                        Self.log.info("daemon LaunchAgent already running")
                        return
                    case .loaded:
                        if status.restartPending {
                            Self.log.info(
                                "daemon LaunchAgent is already waiting for launchd's scheduled restart")
                            return
                        }
                        try runLaunchctl(["kickstart", serviceTarget])
                        Self.log.info("inactive daemon LaunchAgent started")
                        return
                    case .notLoaded:
                        break
                    }
                }

                try install(daemonURL: daemonURL)
                Self.log.info("daemon LaunchAgent installed and started")
            }
        } catch {
            Self.log.error("failed to start daemon: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Recover an unexpectedly disconnected daemon without racing launchd's KeepAlive restart.
    ///
    /// A stopped KeepAlive job remains loaded while launchd waits for its throttle interval.
    /// Calling `kickstart` during that window starts one process immediately, but does not cancel
    /// the pending restart; launchd then terminates that fresh process and creates a third
    /// generation. Give the scheduled restart one full interval before reconciling manually.
    func recoverAfterDisconnect() {
        guard Self.isProductionApp else { return }

        var recovery = DisconnectRecoveryTracker(initial: currentLaunchAgentStatus)

        for _ in 0..<24 {
            Thread.sleep(forTimeInterval: 0.25)
            switch recovery.observe(currentLaunchAgentStatus) {
            case .recovered:
                Self.log.info("daemon recovered through LaunchAgent KeepAlive")
                return
            case .reconcile:
                ensureRunning()
                return
            case .wait:
                continue
            }
        }
        ensureRunning()
    }

    /// Stop the managed daemon. Used while macFUSE setup is incomplete: without the kext the
    /// daemon can only fail to mount, and KeepAlive would keep it in a restart loop.
    func stop() {
        _ = try? runLaunchctl(["bootout", serviceTarget])
    }

    /// Stop the daemon, detach only the exact Floria mount, and remove its login item.
    /// User config, catalog, encrypted store, backups, logs, and Keychain items are preserved.
    func prepareForUninstall() throws {
        guard Self.isProductionApp else {
            throw DaemonError.notProductionApp
        }
        guard let daemonURL, FileManager.default.isExecutableFile(atPath: daemonURL.path) else {
            throw DaemonError.noBinary
        }

        try prepareRuntimeDirectory()
        try withReconciliationLock {
            _ = try? runLaunchctl(["bootout", serviceTarget])
            try runDaemon(daemonURL, arguments: ["unmount", "--config", configURL.path])
            if FileManager.default.fileExists(atPath: launchAgentURL.path) {
                try FileManager.default.removeItem(at: launchAgentURL)
            }
        }
    }

    /// Install the LaunchAgent plist and bootstrap it with launchd. Existing user config is
    /// preserved; only a missing config and bundled example handler are seeded.
    private func install(daemonURL: URL) throws {
        let plist = try makeLaunchAgentPlist(daemonPath: daemonURL.path)
        let fileManager = FileManager.default

        try fileManager.createDirectory(
            at: launchAgentURL.deletingLastPathComponent(),
            withIntermediateDirectories: true)

        _ = try? runLaunchctl(["enable", serviceTarget])
        _ = try? runLaunchctl(["bootout", serviceTarget])
        // launchd terminates the old process without unwinding Rust's mount session. Explicitly
        // detach the old macFUSE volume before bootstrapping the replacement, otherwise the new
        // daemon sees the mount point as occupied and enters KeepAlive's restart loop.
        _ = try? runDaemon(daemonURL, arguments: ["unmount", "--config", configURL.path])

        try plist.write(to: launchAgentURL, options: .atomic)
        try fileManager.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: launchAgentURL.path)
        try bootstrapLaunchAgent()
    }

    /// launchd can briefly reject a valid replacement job with EIO immediately after bootout.
    /// Retrying only that documented status keeps app updates reliable without hiding malformed
    /// plists, permission failures, or other permanent launchctl errors.
    private func bootstrapLaunchAgent() throws {
        var completedAttempts = 0

        while true {
            completedAttempts += 1
            do {
                try runLaunchctl(["bootstrap", "gui/\(getuid())", launchAgentURL.path])
                return
            } catch {
                guard Self.shouldRetryBootstrap(error, completedAttempts: completedAttempts) else {
                    throw error
                }

                let delay = min(0.25 * pow(2, Double(completedAttempts - 1)), 2)
                Self.log.notice(
                    "launchd is still releasing the previous daemon; retrying bootstrap in \(delay, privacy: .public)s")
                Thread.sleep(forTimeInterval: delay)
            }
        }
    }

    private func prepareRuntimeFiles() throws {
        try prepareRuntimeDirectory()

        let fileManager = FileManager.default
        if !fileManager.fileExists(atPath: configURL.path) {
            guard let bundledConfig = Bundle.main.url(forResource: "floria", withExtension: "toml") else {
                throw DaemonError.missingResource("floria.toml")
            }
            try fileManager.copyItem(at: bundledConfig, to: configURL)
            try fileManager.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: configURL.path)
        }

    }

    private func prepareRuntimeDirectory() throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(
            at: runtimeDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try fileManager.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: runtimeDirectory.path)
    }

    private func withReconciliationLock(_ body: () throws -> Void) throws {
        let fd = open(reconciliationLockURL.path, O_CREAT | O_RDWR, mode_t(0o600))
        guard fd >= 0 else {
            throw DaemonError.systemCall("opening reconciliation lock", errno)
        }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else {
            throw DaemonError.systemCall("locking daemon reconciliation", errno)
        }
        defer { _ = flock(fd, LOCK_UN) }
        try body()
    }

    private var bundleRevision: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "unknown"
        let build = info?["CFBundleVersion"] as? String ?? "unknown"
        return "\(version)+\(build)"
    }

    private func expectedArguments(daemonPath: String) -> [String] {
        [daemonPath, "mount", "--config", configURL.path]
    }

    private func installedDefinitionMatches(daemonPath: String) -> Bool {
        guard
            let data = try? Data(contentsOf: launchAgentURL),
            let object = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil),
            let plist = object as? [String: Any],
            let arguments = plist["ProgramArguments"] as? [String],
            let environment = plist["EnvironmentVariables"] as? [String: String]
        else {
            return false
        }

        return plist["Program"] as? String == daemonPath
            && arguments == expectedArguments(daemonPath: daemonPath)
            && environment["FLORIA_BUNDLE_REVISION"] == bundleRevision
    }

    private func makeLaunchAgentPlist(daemonPath: String) throws -> Data {
        let logsDirectory = runtimeDirectory.appendingPathComponent("logs", isDirectory: true)
        try FileManager.default.createDirectory(
            at: logsDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])

        let plist: [String: Any] = [
            "Label": serviceLabel,
            "AssociatedBundleIdentifiers": Self.bundleIdentifier,
            "Program": daemonPath,
            "ProgramArguments": expectedArguments(daemonPath: daemonPath),
            "WorkingDirectory": runtimeDirectory.path,
            "RunAtLoad": true,
            "KeepAlive": ["SuccessfulExit": false],
            "ThrottleInterval": 5,
            "ExitTimeOut": 20,
            "StandardOutPath": logsDirectory.appendingPathComponent("daemon.stdout.log").path,
            "StandardErrorPath": logsDirectory.appendingPathComponent("daemon.stderr.log").path,
            "EnvironmentVariables": [
                "HOME": homeDirectory.path,
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                "RUST_LOG": "info",
                "FLORIA_BUNDLE_REVISION": bundleRevision,
            ],
        ]
        return try PropertyListSerialization.data(
            fromPropertyList: plist, format: .xml, options: 0)
    }

    enum LaunchAgentState: Equatable, Sendable {
        case notLoaded
        case loaded
        case running
    }

    struct LaunchAgentStatus: Equatable, Sendable {
        let state: LaunchAgentState
        let runs: Int
        let pid: Int?
        let lastExitCode: Int?
        let restartPending: Bool

        init(
            state: LaunchAgentState,
            runs: Int,
            pid: Int?,
            lastExitCode: Int?,
            restartPending: Bool = false
        ) {
            self.state = state
            self.runs = runs
            self.pid = pid
            self.lastExitCode = lastExitCode
            self.restartPending = restartPending
        }

        var hasFailedRun: Bool {
            state != .running && runs > 0 && lastExitCode.map { $0 != 0 } == true
        }
    }

    static func launchAgentStatus(from output: String?) -> LaunchAgentStatus {
        guard let output else {
            return LaunchAgentStatus(state: .notLoaded, runs: 0, pid: nil, lastExitCode: nil)
        }

        let lines = output
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        let isRunning = lines.contains("state = running")
        // `launchctl stop` leaves a KeepAlive job in this transient state while its
        // throttle-window restart is already scheduled. Kickstarting it here creates a short-
        // lived extra generation that launchd terminates when the scheduled restart fires.
        let restartPending = lines.contains("state = SIGTERMed")
        return LaunchAgentStatus(
            state: isRunning ? .running : .loaded,
            runs: integerValue(named: "runs", in: lines) ?? 0,
            pid: integerValue(named: "pid", in: lines),
            lastExitCode: integerValue(named: "last exit code", in: lines),
            restartPending: restartPending)
    }

    enum DisconnectRecoveryAction: Equatable, Sendable {
        case wait
        case recovered
        case reconcile
    }

    /// Tracks the LaunchAgent generation that owned the socket when disconnect recovery began.
    /// The old daemon can close its socket before launchd stops reporting that PID as running, so
    /// seeing that same generation once is not evidence that recovery completed.
    struct DisconnectRecoveryTracker: Sendable {
        private let initialPID: Int?
        private var observedStoppedGeneration: Bool

        init(initial: LaunchAgentStatus) {
            initialPID = initial.pid
            observedStoppedGeneration = initial.state != .running
        }

        mutating func observe(_ status: LaunchAgentStatus) -> DisconnectRecoveryAction {
            switch status.state {
            case .notLoaded:
                return .reconcile
            case .loaded:
                observedStoppedGeneration = true
                return .wait
            case .running:
                if observedStoppedGeneration || status.pid != initialPID {
                    return .recovered
                }
                return .wait
            }
        }
    }

    static func launchAgentState(from output: String?) -> LaunchAgentState {
        launchAgentStatus(from: output).state
    }

    private static func integerValue(named name: String, in lines: [String]) -> Int? {
        let prefix = "\(name) = "
        guard let line = lines.first(where: { $0.hasPrefix(prefix) }) else { return nil }
        return Int(line.dropFirst(prefix.count))
    }

    static func shouldRetryBootstrap(_ error: Error, completedAttempts: Int) -> Bool {
        guard completedAttempts < 5,
              case DaemonError.processFailed(
                  executable: "launchctl", arguments: let arguments, status: 5, output: _) = error,
              arguments.first == "bootstrap"
        else {
            return false
        }
        return true
    }

    private var currentLaunchAgentStatus: LaunchAgentStatus {
        Self.launchAgentStatus(from: try? runLaunchctl(["print", serviceTarget]))
    }

    /// A completed non-zero launchd run is stronger evidence than waiting for the entire
    /// connection timeout. Setup can react as soon as the first mount attempt has failed.
    func startupAttemptHasFailed() -> Bool {
        Self.launchAgentStatus(from: try? runLaunchctl(["print", serviceTarget])).hasFailedRun
    }

    @discardableResult
    private func runLaunchctl(_ arguments: [String]) throws -> String {
        try runProcess(executableURL: URL(fileURLWithPath: "/bin/launchctl"), arguments: arguments)
    }

    @discardableResult
    private func runDaemon(_ daemonURL: URL, arguments: [String]) throws -> String {
        try runProcess(executableURL: daemonURL, arguments: arguments)
    }

    private func runProcess(executableURL: URL, arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments

        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()

        let data = output.fileHandleForReading.readDataToEndOfFile()
        let text = String(decoding: data, as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw DaemonError.processFailed(
                executable: executableURL.lastPathComponent, arguments: arguments,
                status: process.terminationStatus,
                output: text)
        }
        return text
    }

    enum DaemonError: LocalizedError {
        case notProductionApp
        case noBinary
        case missingResource(String)
        case systemCall(String, Int32)
        case processFailed(executable: String, arguments: [String], status: Int32, output: String)

        var errorDescription: String? {
            switch self {
            case .notProductionApp:
                return "Floria can only be uninstalled from a packaged app"
            case .noBinary:
                return "Rust daemon is missing from the app bundle"
            case .missingResource(let name):
                return "Required app resource is missing: \(name)"
            case .systemCall(let operation, let code):
                return "\(operation) failed: \(String(cString: strerror(code)))"
            case .processFailed(let executable, let arguments, let status, let output):
                return "\(executable) \(arguments.joined(separator: " ")) failed (\(status)): \(output)"
            }
        }
    }
}
