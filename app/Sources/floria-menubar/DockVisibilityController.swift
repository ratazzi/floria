import AppKit
import SwiftUI

@MainActor
final class DockVisibilityController {
    static let shared = DockVisibilityController()

    private let setActivationPolicy: @MainActor (NSApplication.ActivationPolicy) -> Void
    private weak var dashboardWindow: NSWindow?
    private var closeObserver: NSObjectProtocol?
    private var authorizationPromptVisible = false
    private var backgroundAttentionWindowCount = 0

    init(
        setActivationPolicy: @escaping @MainActor (NSApplication.ActivationPolicy) -> Void = {
            NSApplication.shared.setActivationPolicy($0)
        }
    ) {
        self.setActivationPolicy = setActivationPolicy
    }

    func prepareToShowDashboard() {
        setActivationPolicy(.regular)
    }

    func observeDashboardWindow(_ window: NSWindow) {
        guard dashboardWindow !== window else { return }

        stopObservingDashboardWindow()
        dashboardWindow = window
        setActivationPolicy(.regular)
        closeObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: window,
            queue: .main
        ) { [weak self, weak window] _ in
            guard let self, let window else { return }
            MainActor.assumeIsolated {
                self.dashboardWindowWillClose(window)
            }
        }
    }

    func dashboardDidClose() {
        dashboardWindow = nil
        stopObservingDashboardWindow()
        updateActivationPolicy()
    }

    func authorizationPromptDidOpen() {
        authorizationPromptVisible = true
        updateActivationPolicy()
    }

    func authorizationPromptDidClose() {
        authorizationPromptVisible = false
        updateActivationPolicy()
    }

    func backgroundAttentionWindowDidOpen() {
        backgroundAttentionWindowCount += 1
        updateActivationPolicy()
    }

    func backgroundAttentionWindowDidClose() {
        backgroundAttentionWindowCount = max(0, backgroundAttentionWindowCount - 1)
        updateActivationPolicy()
    }

    private func dashboardWindowWillClose(_ window: NSWindow) {
        guard dashboardWindow === window else { return }
        dashboardDidClose()
    }

    private func stopObservingDashboardWindow() {
        guard let closeObserver else { return }
        NotificationCenter.default.removeObserver(closeObserver)
        self.closeObserver = nil
    }

    private func updateActivationPolicy() {
        setActivationPolicy(
            dashboardWindow != nil || authorizationPromptVisible
                || backgroundAttentionWindowCount > 0
                ? .regular : .accessory)
    }
}

private final class DashboardWindowTrackingView: NSView {
    weak var dockVisibilityController: DockVisibilityController?
    private weak var trackedWindow: NSWindow?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let window {
            trackedWindow = window
            dockVisibilityController?.observeDashboardWindow(window)
        } else if trackedWindow != nil {
            trackedWindow = nil
            dockVisibilityController?.dashboardDidClose()
        }
    }
}

struct DashboardWindowTracker: NSViewRepresentable {
    let dockVisibilityController: DockVisibilityController

    func makeNSView(context: Context) -> NSView {
        let view = DashboardWindowTrackingView()
        view.dockVisibilityController = dockVisibilityController
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        guard let view = nsView as? DashboardWindowTrackingView else { return }
        view.dockVisibilityController = dockVisibilityController
        if let window = view.window {
            dockVisibilityController.observeDashboardWindow(window)
        }
    }
}
