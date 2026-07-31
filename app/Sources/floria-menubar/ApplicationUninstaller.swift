import AppKit
import Foundation

enum ApplicationUninstaller {
    static var isAvailable: Bool {
        isAvailable(applicationURL: Bundle.main.bundleURL)
    }

    static func isAvailable(applicationURL: URL) -> Bool {
        applicationURL.deletingLastPathComponent().standardizedFileURL.path == "/Applications"
    }

    @MainActor
    static func uninstall(completion: @escaping (Result<Void, Error>) -> Void) {
        guard isAvailable else {
            completion(.failure(UninstallError.notInstalled))
            return
        }

        let manager = DaemonManager()
        let applicationURL = Bundle.main.bundleURL
        Task.detached {
            do {
                try manager.prepareForUninstall()
            } catch {
                manager.ensureRunning()
                await MainActor.run { completion(.failure(error)) }
                return
            }

            await MainActor.run {
                NSWorkspace.shared.recycle([applicationURL]) { _, error in
                    DispatchQueue.main.async {
                        if let error {
                            DispatchQueue.global(qos: .utility).async {
                                manager.ensureRunning()
                            }
                            completion(.failure(error))
                        } else {
                            completion(.success(()))
                            NSApp.terminate(nil)
                        }
                    }
                }
            }
        }
    }

    enum UninstallError: LocalizedError {
        case notInstalled

        var errorDescription: String? {
            "Floria can only be uninstalled from /Applications."
        }
    }
}
