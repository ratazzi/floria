import AppKit
import SwiftUI

/// Menubar (accessory) app: a window-style dropdown (search + recent access + actions)
/// plus modal authorization prompts driven by the daemon.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)  // menubar only, no Dock icon
    }
}

@main
struct FloriaMenuBarApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    // Created at app init (not first click): the socket client must connect at launch so
    // prompts and events flow even if the dropdown has never been opened.
    @State private var state = AppState()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(state: state)
        } label: {
            // Do not put a TimelineView here: on macOS 26 a periodic status-item label caused
            // continuous invalidation (~99% CPU). AppState's refresh task drives mode changes.
            Image(
                systemName: state.policyMode.isAuditOnly()
                    ? "eye.circle.fill" : "lock.shield")
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(state.policyMode.isAuditOnly() ? Color.orange : Color.primary)
        }
        // `.window` turns the dropdown into a real anchored window that hosts arbitrary
        // SwiftUI (search field, hover rows, ...) instead of an NSMenu.
        .menuBarExtraStyle(.window)

        // The daemon owns login-time startup. Launching the GUI is therefore an explicit user
        // action and should present the workspace immediately; the menu bar remains available
        // after the window is closed.
        Window("floria", id: "dashboard") {
            DashboardView(state: state)
        }
        .defaultSize(width: 1240, height: 760)
        .windowStyle(.hiddenTitleBar)
        .defaultLaunchBehavior(.presented)
    }
}
