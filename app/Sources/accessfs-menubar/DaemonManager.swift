import Darwin
import Foundation
import os

/// Installs and maintains the bundled Rust mount process as a per-user LaunchAgent.
/// The manager is only active in a packaged app; `swift run` keeps using a manually
/// started daemon so development does not mutate launchd state.
struct DaemonManager: Sendable {
    static let bundleIdentifier = "dev.floria.hola.ac"

    private static let log = Logger(subsystem: bundleIdentifier, category: "daemon")
    private let serviceLabel = "dev.floria.hola.ac.daemon"

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
        runtimeDirectory.appendingPathComponent("accessfs.toml")
    }

    private var launchAgentURL: URL {
        homeDirectory
            .appendingPathComponent("Library/LaunchAgents", isDirectory: true)
            .appendingPathComponent("\(serviceLabel).plist")
    }

    private var daemonURL: URL? {
        Bundle.main.url(forResource: "accessfs", withExtension: nil)
    }

    /// Ensure the current bundle's daemon definition is installed and loaded. A changed
    /// app build rewrites and reloads the job; reopening the same build leaves it alone.
    func ensureRunning() {
        guard Self.isProductionApp else { return }

        do {
            guard let daemonURL, FileManager.default.isExecutableFile(atPath: daemonURL.path) else {
                throw DaemonError.noBinary
            }

            try prepareRuntimeFiles()
            if isLoaded && installedDefinitionMatches(daemonPath: daemonURL.path) {
                Self.log.info("daemon LaunchAgent already loaded")
                return
            }

            try install(daemonURL: daemonURL)
            Self.log.info("daemon LaunchAgent installed and started")
        } catch {
            Self.log.error("failed to start daemon: \(error.localizedDescription, privacy: .public)")
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

        try plist.write(to: launchAgentURL, options: .atomic)
        try fileManager.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: launchAgentURL.path)
        try runLaunchctl(["bootstrap", "gui/\(getuid())", launchAgentURL.path])
    }

    private func prepareRuntimeFiles() throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(
            at: runtimeDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try fileManager.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: runtimeDirectory.path)

        if !fileManager.fileExists(atPath: configURL.path) {
            guard let bundledConfig = Bundle.main.url(forResource: "accessfs", withExtension: "toml") else {
                throw DaemonError.missingResource("accessfs.toml")
            }
            try fileManager.copyItem(at: bundledConfig, to: configURL)
            try fileManager.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: configURL.path)
        }

        let scriptsDirectory = runtimeDirectory.appendingPathComponent("scripts", isDirectory: true)
        let handlerURL = scriptsDirectory.appendingPathComponent("render-env")
        if !fileManager.fileExists(atPath: handlerURL.path) {
            guard let bundledHandler = Bundle.main.url(
                forResource: "render-env", withExtension: nil, subdirectory: "scripts")
            else {
                throw DaemonError.missingResource("scripts/render-env")
            }
            try fileManager.createDirectory(
                at: scriptsDirectory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            try fileManager.copyItem(at: bundledHandler, to: handlerURL)
            try fileManager.setAttributes(
                [.posixPermissions: 0o700], ofItemAtPath: handlerURL.path)
        }
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

    private var isLoaded: Bool {
        (try? runLaunchctl(["print", serviceTarget])) != nil
    }

    @discardableResult
    private func runLaunchctl(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments

        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()

        let data = output.fileHandleForReading.readDataToEndOfFile()
        let text = String(decoding: data, as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw DaemonError.launchctlFailed(
                arguments: arguments,
                status: process.terminationStatus,
                output: text)
        }
        return text
    }

    enum DaemonError: LocalizedError {
        case noBinary
        case missingResource(String)
        case launchctlFailed(arguments: [String], status: Int32, output: String)

        var errorDescription: String? {
            switch self {
            case .noBinary:
                return "Rust daemon is missing from the app bundle"
            case .missingResource(let name):
                return "Required app resource is missing: \(name)"
            case .launchctlFailed(let arguments, let status, let output):
                return "launchctl \(arguments.joined(separator: " ")) failed (\(status)): \(output)"
            }
        }
    }
}
