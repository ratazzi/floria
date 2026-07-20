import AppKit
import SwiftUI

/// Menubar (accessory) app: a window-style dropdown (search + recent access + actions)
/// plus modal authorization prompts driven by the daemon.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)  // menubar only, no Dock icon, no bundle needed
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
            Image(systemName: "lock.shield")
        }
        // `.window` turns the dropdown into a real anchored window that hosts arbitrary
        // SwiftUI (search field, hover rows, ...) instead of an NSMenu.
        .menuBarExtraStyle(.window)

        // Full dashboard: sidebar grouped by client/file + a sortable access table.
        // Suppressed at launch — a menubar app must not open a window on login.
        Window("floria", id: "dashboard") {
            DashboardView(state: state)
        }
        .defaultSize(width: 920, height: 560)
        .defaultLaunchBehavior(.suppressed)
    }
}
