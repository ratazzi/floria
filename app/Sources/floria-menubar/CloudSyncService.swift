import CloudKit
import Foundation

protocol CloudSyncControlling: RecordSyncControlling, VaultBootstrapControlling {
    func recordSyncStatus() async throws -> SyncDomainStatus
}

extension ControlClient: CloudSyncControlling {}

protocol CloudSyncSessionRunning: Sendable {
    func syncNow() async throws
}

extension CloudRecordSyncSession: CloudSyncSessionRunning {}

struct CloudSyncPreferences: Sendable {
    private static let enabledKey = "cloud-sync.enabled"
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

    private var defaults: UserDefaults {
        if let suiteName, let defaults = UserDefaults(suiteName: suiteName) {
            return defaults
        }
        return .standard
    }
}

/// Explicit opt-in boundary for CloudKit. Constructing this service and reading its disabled
/// state are local-only; the container factory is called solely from `syncNow()` after opt-in.
actor CloudSyncService {
    typealias SessionFactory = @Sendable (
        _ control: any CloudSyncControlling,
        _ supportDirectory: URL,
        _ vaultID: String
    ) throws -> any CloudSyncSessionRunning
    typealias DiscoveryFactory = @Sendable () throws -> any CloudVaultDiscovering
    typealias LifecycleLoaderFactory = @Sendable () throws -> any CloudVaultLifecycleLoading

    private let control: any CloudSyncControlling
    private let supportDirectory: URL
    private let preferences: CloudSyncPreferences
    private let sessionFactory: SessionFactory
    private let discoveryFactory: DiscoveryFactory
    private let lifecycleLoaderFactory: LifecycleLoaderFactory
    private var session: (any CloudSyncSessionRunning)?
    private var sessionVaultID: String?
    private var discovery: (any CloudVaultDiscovering)?
    private var lifecycleLoader: (any CloudVaultLifecycleLoading)?

    init(
        control: any CloudSyncControlling,
        supportDirectory: URL,
        preferences: CloudSyncPreferences = CloudSyncPreferences()
    ) {
        self.control = control
        self.supportDirectory = supportDirectory
        self.preferences = preferences
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
        }
    ) {
        self.control = control
        self.supportDirectory = supportDirectory
        self.preferences = preferences
        self.sessionFactory = sessionFactory
        self.discoveryFactory = discoveryFactory
        self.lifecycleLoaderFactory = lifecycleLoaderFactory
    }

    func isEnabled() -> Bool {
        preferences.isEnabled
    }

    /// Enabling records user intent but performs no account lookup and creates no CKContainer.
    func setEnabled(_ enabled: Bool) {
        preferences.setEnabled(enabled)
        if !enabled {
            session = nil
            sessionVaultID = nil
            discovery = nil
            lifecycleLoader = nil
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

    func localStatus() async throws -> SyncDomainStatus? {
        guard preferences.isEnabled else { return nil }
        return try await control.recordSyncStatus()
    }

    @discardableResult
    func syncNow() async throws -> SyncDomainStatus {
        guard preferences.isEnabled else { throw CloudSyncServiceError.disabled }
        let before = try await control.recordSyncStatus()
        let activeSession: any CloudSyncSessionRunning
        if let session, sessionVaultID == before.vaultID {
            activeSession = session
        } else {
            activeSession = try sessionFactory(control, supportDirectory, before.vaultID)
            session = activeSession
            sessionVaultID = before.vaultID
        }
        try await activeSession.syncNow()
        return try await control.recordSyncStatus()
    }

}

enum CloudSyncServiceError: Error, Equatable, LocalizedError {
    case disabled
    case unconfiguredTestDependency

    var errorDescription: String? {
        switch self {
        case .disabled:
            "iCloud Sync is off. Enable it before using iCloud."
        case .unconfiguredTestDependency:
            "Cloud sync test dependency is not configured."
        }
    }
}
