import LocalAuthentication

/// Shared Touch ID (falling back to device password) gate for security-sensitive actions
/// outside the per-file authorization prompt flow (see `PromptPresenter`).
enum BiometricAuth {
    /// Whether Touch ID (or Face ID) is enrolled and usable right now. Machines with no
    /// biometric sensor at all (e.g. a Mac mini) should not be forced into a device-password
    /// prompt just to stand in for a plain in-app confirmation.
    static func biometricsAvailable() -> Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    static func authenticate(reason: String) async -> Bool {
        await withCheckedContinuation { continuation in
            let ctx = LAContext()
            var err: NSError?
            let policy: LAPolicy =
                ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
                ? .deviceOwnerAuthenticationWithBiometrics
                : .deviceOwnerAuthentication
            ctx.evaluatePolicy(policy, localizedReason: reason) { ok, _ in
                continuation.resume(returning: ok)
            }
        }
    }
}
