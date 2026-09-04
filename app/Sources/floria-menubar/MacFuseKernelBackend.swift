import Darwin
import Foundation
import Security

/// Requests the installed macFUSE kernel backend without coupling its system approval flow to a
/// Floria mount. macOS still owns every recoveryOS, administrator, approval, and restart step.
struct MacFuseKernelBackend {
    static let loaderPath =
        "/Library/Filesystems/macfuse.fs/Contents/Resources/load_macfuse"

    enum Outcome: Equatable, Sendable {
        case ready
        /// The trusted helper ran, but macOS has not published a device yet. A recoveryOS change,
        /// System Settings approval, or restart can still be required; nonzero is expected here.
        case requested(status: Int32)
        case failed(String)
    }

    struct LoaderMetadata {
        let isRegularFile: Bool
        let ownerID: uid_t
        let mode: mode_t
        let codeIdentifier: String?
        let teamIdentifier: String?
    }

    private static let expectedTeamIdentifier = "3T5GSNBU6W"
    private static let expectedCodeIdentifier = "load_macfuse"
    private static let executionLock = NSLock()

    private let isReady: () -> Bool
    private let inspectLoader: () throws -> LoaderMetadata
    private let runLoader: () throws -> Int32

    init() {
        isReady = { Self.kernelBackendIsReady }
        inspectLoader = Self.inspectInstalledLoader
        runLoader = Self.runInstalledLoader
    }

    /// Internal seam for deterministic tests; production callers use the zero-argument init.
    init(
        isReady: @escaping () -> Bool,
        inspectLoader: @escaping () throws -> LoaderMetadata,
        runLoader: @escaping () throws -> Int32
    ) {
        self.isReady = isReady
        self.inspectLoader = inspectLoader
        self.runLoader = runLoader
    }

    func ensureLoaded() -> Outcome {
        Self.executionLock.lock()
        defer { Self.executionLock.unlock() }

        guard !isReady() else { return .ready }
        do {
            try Self.validate(inspectLoader())
            let status = try runLoader()
            return isReady() ? .ready : .requested(status: status)
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    static var kernelBackendIsReady: Bool {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: "/dev")) ?? []
        return kernelBackendReady(deviceNames: names)
    }

    static func kernelBackendReady(deviceNames: [String]) -> Bool {
        deviceNames.contains(where: { name in
            let prefix = "macfuse"
            guard name.hasPrefix(prefix) else { return false }
            let suffix = name.dropFirst(prefix.count)
            return !suffix.isEmpty && suffix.utf8.allSatisfy { (48...57).contains($0) }
        })
    }

    static func manualLoadCommand(osMajorVersion: Int) -> String {
        "/usr/bin/sudo /usr/bin/kmutil load -p "
            + "/Library/Filesystems/macfuse.fs/Contents/Extensions/"
            + "\(osMajorVersion)/macfuse.kext"
    }

    private static func validate(_ metadata: LoaderMetadata) throws {
        guard metadata.isRegularFile else {
            throw LoaderError.unsafe("the macFUSE loader is not a regular file")
        }
        guard metadata.ownerID == 0 else {
            throw LoaderError.unsafe("the macFUSE loader is not owned by root")
        }
        guard metadata.mode & mode_t(S_ISUID) != 0 else {
            throw LoaderError.unsafe("the macFUSE loader is not set-user-ID root")
        }
        guard metadata.mode & 0o022 == 0 else {
            throw LoaderError.unsafe("the macFUSE loader is writable by group or other users")
        }
        guard metadata.codeIdentifier == expectedCodeIdentifier,
              metadata.teamIdentifier == expectedTeamIdentifier
        else {
            throw LoaderError.unsafe("the macFUSE loader identity is not trusted")
        }
    }

    private static func inspectInstalledLoader() throws -> LoaderMetadata {
        for directory in [
            "/Library",
            "/Library/Filesystems",
            "/Library/Filesystems/macfuse.fs",
            "/Library/Filesystems/macfuse.fs/Contents",
            "/Library/Filesystems/macfuse.fs/Contents/Resources",
        ] {
            try validateTrustedDirectory(directory)
        }

        var status = stat()
        guard loaderPath.withCString({ lstat($0, &status) }) == 0 else {
            throw LoaderError.systemCall("inspecting the macFUSE loader", errno)
        }
        let identity = try loaderSigningIdentity(at: loaderPath)
        return LoaderMetadata(
            isRegularFile: status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
            ownerID: status.st_uid,
            mode: status.st_mode,
            codeIdentifier: identity.codeIdentifier,
            teamIdentifier: identity.teamIdentifier)
    }

    private static func validateTrustedDirectory(_ path: String) throws {
        var status = stat()
        guard path.withCString({ lstat($0, &status) }) == 0 else {
            throw LoaderError.systemCall("inspecting \(path)", errno)
        }
        guard status.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR), status.st_uid == 0,
              status.st_mode & 0o022 == 0
        else {
            throw LoaderError.unsafe(
                "the macFUSE loader directory is not root-owned or is writable by non-root users")
        }
    }

    /// Filesystem ownership is the primary substitution defense for this root helper. Read and
    /// pin its signed identity as defense in depth, but do not require SecStaticCodeCheckValidity:
    /// macOS 27 currently rejects the official macFUSE 5.3.3 universal helpers there even though
    /// their signed identifier and Team ID remain available and the installed mount path uses them.
    private static func loaderSigningIdentity(
        at path: String
    ) throws -> (codeIdentifier: String?, teamIdentifier: String?) {
        var code: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: path) as CFURL, SecCSFlags(), &code)
        guard createStatus == errSecSuccess, let code else {
            throw LoaderError.codeSignature("opening", createStatus)
        }

        var information: CFDictionary?
        let informationStatus = SecCodeCopySigningInformation(
            code, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        guard informationStatus == errSecSuccess,
              let values = information as? [CFString: Any]
        else {
            throw LoaderError.codeSignature("reading", informationStatus)
        }
        return (
            values[kSecCodeInfoIdentifier] as? String,
            values[kSecCodeInfoTeamIdentifier] as? String)
    }

    private static func runInstalledLoader() throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: loaderPath)
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    private enum LoaderError: LocalizedError {
        case unsafe(String)
        case systemCall(String, Int32)
        case codeSignature(String, OSStatus)

        var errorDescription: String? {
            switch self {
            case .unsafe(let message):
                return message
            case .systemCall(let operation, let code):
                return "\(operation) failed: \(String(cString: strerror(code)))"
            case .codeSignature(let operation, let status):
                let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
                return "\(operation) macFUSE loader signature failed: \(detail)"
            }
        }
    }
}
