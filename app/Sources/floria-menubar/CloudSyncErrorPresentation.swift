import CloudKit
import Foundation

/// Converts CloudKit transport failures into short, actionable messages at the UI boundary.
/// It does not probe account state or start networking; callers pass only errors from an
/// explicit user operation.
enum CloudSyncErrorPresentation {
    static func message(for error: any Error) -> String {
        let nsError = error as NSError
        guard nsError.domain == CKErrorDomain,
              let code = CKError.Code(rawValue: nsError.code)
        else {
            return error.localizedDescription
        }

        switch code {
        case .notAuthenticated:
            return "Sign in to iCloud in System Settings, then try again."
        case .networkFailure, .networkUnavailable:
            return "Floria could not reach iCloud. Check this Mac's network connection, then try again."
        case .accountTemporarilyUnavailable:
            return "This iCloud account is temporarily unavailable. Wait a moment, then try again."
        case .serviceUnavailable, .zoneBusy, .requestRateLimited:
            return "iCloud is temporarily busy. Wait a moment, then try again."
        case .quotaExceeded:
            return "This iCloud account is out of storage. Free some space, then try again."
        case .badContainer, .missingEntitlement:
            return "This build of Floria is not configured for its iCloud container. Install a correctly signed build, then try again."
        case .permissionFailure:
            return "iCloud denied access to Floria's private Library. Check that this Mac is signed in to the expected iCloud account, then try again."
        default:
            return error.localizedDescription
        }
    }
}
