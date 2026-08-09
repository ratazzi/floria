import Foundation

enum CloudSyncBuildAvailability {
    private static let infoKey = "FloriaCloudKitEnabled"

    static var isEnabled: Bool {
        Bundle.main.object(forInfoDictionaryKey: infoKey) as? Bool == true
    }
}
