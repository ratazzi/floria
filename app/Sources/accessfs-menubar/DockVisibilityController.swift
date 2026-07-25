import AppKit
import SwiftUI

@MainActor
final class DockVisibilityController {
    static let shared = DockVisibilityController()

    private let setActivationPolicy: @MainActor (NSApplication.ActivationPolicy) -> Void
    private weak var dashboardWindow: NSWindow?
    private var closeObserver: NSObjectProtocol?

    init(
        setActivationPolicy: @escaping @MainActor (NSApplication.ActivationPolicy) -> Void = {
            NSApp.setActivationPolicy($0)
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
        setActivationPolicy(.accessory)
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
