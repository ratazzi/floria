import CloudKit
import Foundation

protocol CloudSyncControlling: RecordSyncControlling, VaultBootstrapControlling,
    VaultEnrollmentControlling, VaultDeviceControlling, VaultActivationControlling
{
    func recordSyncStatus() async throws -> SyncDomainStatus
    func reviewRecordSyncConflicts() async throws -> [SyncConflictReview]
    func resolveRecordSyncConflict(
        entityID: String, selectedRevisionID: String, resolvedAt: String) async throws
        -> SyncDomainStatus
    func syncedProjectsWithoutLocalFolder() async throws -> [SyncedProject]
    func attachSyncedProject(id: String, path: String) async throws
}

extension ControlClient: CloudSyncControlling {}

protocol CloudSyncSessionRunning: Sendable {
    func syncNow() async throws -> CloudSyncSessionOutcome
}

extension CloudRecordSyncSession: CloudSyncSessionRunning {}

struct CloudSyncSessionOutcome: Equatable, Sendable {
    let appliedRemoteChanges: Bool
}

struct CloudSyncOutcome: Equatable, Sendable {
    let status: SyncDomainStatus
    let appliedRemoteChanges: Bool
}

struct CloudSyncPreferences: Sendable {
    private static let enabledKey = "cloud-sync.enabled"
    private static let lastSuccessfulSyncKey = "cloud-sync.last-successful-sync"
    private static let pendingVaultIDKey = "cloud-sync.pending-vault-id"
    private let suiteName: String?

    init(suiteName: String? = nil) {
        self.suiteName = suiteName
    }

    var isEnabled: Bool {
        defaults.bool(forKey: Self.enabledKey)
    }

    func setEnabled(_ enabled: Bool) {
        defaults.set(enabled, forKey: Self.enabledKey)
    }

    var lastSuccessfulSyncAt: Date? {
        defaults.object(forKey: Self.lastSuccessfulSyncKey) as? Date
    }

    func setLastSuccessfulSyncAt(_ date: Date) {
        defaults.set(date, forKey: Self.lastSuccessfulSyncKey)
    }

    var pendingVaultID: String? {
        defaults.string(forKey: Self.pendingVaultIDKey)
    }

    func setPendingVaultID(_ vaultID: String?) {
        if let vaultID {
            defaults.set(vaultID, forKey: Self.pendingVaultIDKey)
        } else {
            defaults.removeObject(forKey: Self.pendingVaultIDKey)
        }
    }

    private var defaults: UserDefaults {
        if let suiteName, let defaults = UserDefaults(suiteName: suiteName) {
            return defaults
        }
        return .standard
    }
}

/// Explicit opt-in boundary for CloudKit. Constructing this service and reading its disabled
/// state are local-only; CloudKit dependencies are created only by an explicit user operation.
actor CloudSyncService {
    typealias SessionFactory = @Sendable (
        _ control: any CloudSyncControlling,
        _ supportDirectory: URL,
        _ vaultID: String
    ) throws -> any CloudSyncSessionRunning
    typealias DiscoveryFactory = @Sendable () throws -> any CloudVaultDiscovering
    typealias LifecycleLoaderFactory = @Sendable () throws -> any CloudVaultLifecycleLoading
    typealias EnrollmentPublisherFactory =
        @Sendable () throws -> any CloudVaultEnrollmentPublishing

    private let control: any CloudSyncControlling
    private let supportDirectory: URL
    private let preferences: CloudSyncPreferences
    private let sessionFactory: SessionFactory
    private let discoveryFactory: DiscoveryFactory
    private let lifecycleLoaderFactory: LifecycleLoaderFactory
    private let enrollmentPublisherFactory: EnrollmentPublisherFactory
    private let now: @Sendable () -> Date
    private var session: (any CloudSyncSessionRunning)?
    private var sessionVaultID: String?
    private var discovery: (any CloudVaultDiscovering)?
    private var lifecycleLoader: (any CloudVaultLifecycleLoading)?
    private var enrollmentPublisher: (any CloudVaultEnrollmentPublishing)?
    private var pendingRestartVaultID: String?

    init(
        control: any CloudSyncControlling,
        supportDirectory: URL,
        preferences: CloudSyncPreferences = CloudSyncPreferences(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.control = control
        self.supportDirectory = supportDirectory
        self.preferences = preferences
        self.now = now
        sessionFactory = { control, supportDirectory, vaultID in
            let container = CKContainer(
                identifier: ProductIdentity.cloudKitContainerIdentifier)
            return try CloudRecordSyncSession(
                database: container.privateCloudDatabase,
                control: control,
                supportDirectory: supportDirectory,
                vaultID: vaultID)
        }
        discoveryFactory = {
            let container = CKContainer(
                identifier: ProductIdentity.cloudKitContainerIdentifier)
            return CloudVaultDiscovery(
                query: CloudKitVaultZoneQuery(database: container.privateCloudDatabase))
        }
        lifecycleLoaderFactory = { [control] in
            let container = CKContainer(
                identifier: ProductIdentity.cloudKitContainerIdentifier)
            return CloudVaultLifecycleLoader(
                query: CloudKitVaultLifecycleQuery(database: container.privateCloudDatabase),
                control: control)
        }
        enrollmentPublisherFactory = {
            let container = CKContainer(
                identifier: ProductIdentity.cloudKitContainerIdentifier)
            return CloudKitVaultEnrollmentPublisher(database: container.privateCloudDatabase)
        }
    }

    init(
        control: any CloudSyncControlling,
        supportDirectory: URL,
        preferences: CloudSyncPreferences,
        sessionFactory: @escaping SessionFactory,
        discoveryFactory: @escaping DiscoveryFactory = {
            throw CloudSyncServiceError.unconfiguredTestDependency
        },
        lifecycleLoaderFactory: @escaping LifecycleLoaderFactory = {
            throw CloudSyncServiceError.unconfiguredTestDependency
        },
        enrollmentPublisherFactory: @escaping EnrollmentPublisherFactory = {
            throw CloudSyncServiceError.unconfiguredTestDependency
        },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.control = control
        self.supportDirectory = supportDirectory
        self.preferences = preferences
        self.sessionFactory = sessionFactory
        self.discoveryFactory = discoveryFactory
        self.lifecycleLoaderFactory = lifecycleLoaderFactory
        self.enrollmentPublisherFactory = enrollmentPublisherFactory
        self.now = now
    }

    func isEnabled() -> Bool {
        preferences.isEnabled
    }

    func lastSuccessfulSyncAt() -> Date? {
        preferences.lastSuccessfulSyncAt
    }

    func pendingVaultID() -> String? {
        preferences.pendingVaultID
    }

    /// Enabling records user intent but performs no account lookup and creates no CKContainer.
    func setEnabled(_ enabled: Bool) {
        preferences.setEnabled(enabled)
        if !enabled {
            session = nil
            sessionVaultID = nil
            discovery = nil
            lifecycleLoader = nil
            enrollmentPublisher = nil
        }
    }

    func discoverVaults() async throws -> [CloudVaultCandidate] {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let activeDiscovery: any CloudVaultDiscovering
        if let discovery {
            activeDiscovery = discovery
        } else {
            activeDiscovery = try discoveryFactory()
            discovery = activeDiscovery
        }
        return try await activeDiscovery.discover()
    }

    func authenticateVault(_ vaultID: String) async throws -> SyncVaultBootstrap {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let activeLoader: any CloudVaultLifecycleLoading
        if let lifecycleLoader {
            activeLoader = lifecycleLoader
        } else {
            activeLoader = try lifecycleLoaderFactory()
            lifecycleLoader = activeLoader
        }
        return try await activeLoader.loadAndAuthenticate(vaultID: vaultID)
    }

    func requestEnrollment(
        in bootstrap: SyncVaultBootstrap,
        deviceName: String?,
        requestedAt: String? = nil
    ) async throws -> SyncEnrollmentPreparation {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let activePublisher: any CloudVaultEnrollmentPublishing
        if let enrollmentPublisher {
            activePublisher = enrollmentPublisher
        } else {
            activePublisher = try enrollmentPublisherFactory()
            enrollmentPublisher = activePublisher
        }
        let preparation = try await CloudVaultEnrollmentCoordinator(
            control: control, publisher: activePublisher
        ).requestEnrollment(
            in: bootstrap,
            deviceName: deviceName,
            requestedAt: requestedAt ?? Self.timestamp())
        preferences.setPendingVaultID(bootstrap.vaultID)
        return preparation
    }

    func requestAccessAgain(
        in bootstrap: SyncVaultBootstrap,
        removedDevice: SyncVaultDevice,
        deviceName: String?,
        requestedAt: String? = nil
    ) async throws -> SyncEnrollmentPreparation {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let activePublisher: any CloudVaultEnrollmentPublishing
        if let enrollmentPublisher {
            activePublisher = enrollmentPublisher
        } else {
            activePublisher = try enrollmentPublisherFactory()
            enrollmentPublisher = activePublisher
        }
        let preparation = try await CloudVaultEnrollmentCoordinator(
            control: control, publisher: activePublisher
        ).requestReenrollment(
            in: bootstrap,
            expectedFingerprint: removedDevice.fingerprint,
            deviceName: deviceName,
            requestedAt: requestedAt ?? Self.timestamp())
        preferences.setPendingVaultID(bootstrap.vaultID)
        session = nil
        sessionVaultID = nil
        return preparation
    }

    func reviewEnrollments(
        in bootstrap: SyncVaultBootstrap
    ) async throws -> [SyncEnrollmentReview] {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        return try await control.reviewRecordSyncVaultEnrollments(bootstrap: bootstrap)
    }

    /// Approval mutates only Rust-owned lifecycle state. The caller follows it with `syncNow()`
    /// to publish the new signed Device identity and key envelope to CloudKit.
    func approveEnrollment(
        _ review: SyncEnrollmentReview,
        in bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultBootstrap {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let approved = try await control.approveRecordSyncVaultEnrollment(
            bootstrap: bootstrap,
            deviceID: review.deviceID,
            expectedFingerprint: review.fingerprint)
        session = nil
        sessionVaultID = nil
        return approved
    }

    func reviewDevices(in bootstrap: SyncVaultBootstrap) async throws -> [SyncVaultDevice] {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        return try await control.reviewRecordSyncVaultDevices(bootstrap: bootstrap)
    }

    /// Revocation rotates the Rust-owned Vault generation. The next explicit `syncNow()` publishes
    /// the returned create-only lifecycle records to CloudKit.
    func revokeDevice(
        _ device: SyncVaultDevice,
        in bootstrap: SyncVaultBootstrap
    ) async throws -> SyncVaultBootstrap {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let revoked = try await control.revokeRecordSyncVaultDevice(
            bootstrap: bootstrap,
            deviceID: device.deviceID,
            expectedFingerprint: device.fingerprint)
        session = nil
        sessionVaultID = nil
        return revoked
    }

    /// Activate one Rust-authenticated lifecycle snapshot. A different populated Vault is
    /// prepared durably by the daemon and becomes active only after that daemon restarts.
    @discardableResult
    func activateVault(_ bootstrap: SyncVaultBootstrap) async throws -> SyncVaultActivation {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let activation = try await control.activateRecordSyncVault(bootstrap: bootstrap)
        switch activation {
        case .ready(let vaultID, _, let restartRequired):
            guard vaultID == bootstrap.vaultID else {
                throw CloudSyncServiceError.unexpectedActivatedVault(
                    expected: bootstrap.vaultID, actual: vaultID)
            }
            session = nil
            sessionVaultID = nil
            pendingRestartVaultID = restartRequired ? vaultID : nil
            return activation

        case .mergeRequired(let currentVaultID, let targetVaultID, let localItems):
            throw CloudSyncServiceError.mergeRequired(
                currentVaultID: currentVaultID,
                targetVaultID: targetVaultID,
                localItems: localItems)
        }
    }

    func localStatus() async throws -> SyncDomainStatus? {
        guard preferences.isEnabled else { return nil }
        return try await control.recordSyncStatus()
    }

    func reviewConflicts() async throws -> [SyncConflictReview] {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        return try await control.reviewRecordSyncConflicts()
    }

    @discardableResult
    func resolveConflict(
        entityID: String,
        selectedRevisionID: String
    ) async throws -> SyncDomainStatus {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        return try await control.resolveRecordSyncConflict(
            entityID: entityID,
            selectedRevisionID: selectedRevisionID,
            resolvedAt: Self.timestamp())
    }

    func projectsWithoutLocalFolder() async throws -> [SyncedProject] {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        return try await control.syncedProjectsWithoutLocalFolder()
    }

    func attachProject(_ project: SyncedProject, at directory: URL) async throws {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let resolved = directory.standardizedFileURL.resolvingSymlinksInPath()
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: resolved.path, isDirectory: &isDirectory),
              isDirectory.boolValue
        else {
            throw CloudSyncServiceError.invalidProjectDirectory(resolved.path)
        }
        try await control.attachSyncedProject(id: project.id, path: resolved.path)
    }

    @discardableResult
    func syncNow() async throws -> CloudSyncOutcome {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let before = try await control.recordSyncStatus()
        if let pendingRestartVaultID {
            guard before.vaultID == pendingRestartVaultID else {
                throw CloudSyncServiceError.restartRequired(vaultID: pendingRestartVaultID)
            }
            self.pendingRestartVaultID = nil
        }
        let activeSession: any CloudSyncSessionRunning
        if let session, sessionVaultID == before.vaultID {
            activeSession = session
        } else {
            activeSession = try sessionFactory(control, supportDirectory, before.vaultID)
            session = activeSession
            sessionVaultID = before.vaultID
        }
        let sessionOutcome: CloudSyncSessionOutcome
        do {
            sessionOutcome = try await activeSession.syncNow()
        } catch {
            // A failed CKSyncEngine session may have advanced only in-memory tokens or retained a
            // terminal account-change failure. The durable checkpoint and Rust outbox are the
            // recovery boundary, so the user's next explicit Sync Now must start a fresh session.
            if sessionVaultID == before.vaultID {
                session = nil
                sessionVaultID = nil
            }
            throw error
        }
        let after = try await control.recordSyncStatus()
        preferences.setLastSuccessfulSyncAt(now())
        if preferences.pendingVaultID == after.vaultID {
            preferences.setPendingVaultID(nil)
        }
        return CloudSyncOutcome(
            status: after,
            appliedRemoteChanges: sessionOutcome.appliedRemoteChanges)
    }

    private static func timestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }

}

enum CloudSyncServiceError: Error, Equatable, LocalizedError {
    case disabled
    case invalidProjectDirectory(String)
    case mergeRequired(currentVaultID: String, targetVaultID: String, localItems: Int)
    case restartRequired(vaultID: String)
    case unexpectedActivatedVault(expected: String, actual: String)
    case unconfiguredTestDependency

    var errorDescription: String? {
        switch self {
        case .disabled:
            "iCloud Sync is off. Enable it before using iCloud."
        case .invalidProjectDirectory(let path):
            "Choose an existing project folder. \(path) is not a directory."
        case .mergeRequired(let currentVaultID, let targetVaultID, let localItems):
            "Could not prepare \(localItems) local items from Vault \(currentVaultID) for Vault \(targetVaultID)."
        case .restartRequired(let vaultID):
            "Restart the Floria daemon to finish activating Vault \(vaultID)."
        case .unexpectedActivatedVault(let expected, let actual):
            "Floria activated Vault \(actual) instead of authenticated Vault \(expected)."
        case .unconfiguredTestDependency:
            "Cloud sync test dependency is not configured."
        }
    }
}
