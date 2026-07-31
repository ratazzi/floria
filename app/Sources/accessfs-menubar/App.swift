import AppKit
import SwiftUI

enum FloriaImages {
    static let applicationIcon = load(name: "AppIcon", extension: "icns")
    static let menuBarTemplate: NSImage? = {
        let image = load(name: "MenuBarTemplate", extension: "png")
        image?.size = NSSize(width: 20, height: 20)
        image?.isTemplate = true
        return image
    }()

    private static func load(name: String, extension fileExtension: String) -> NSImage? {
        guard
            let url = Bundle.main.url(forResource: name, withExtension: fileExtension),
            let image = NSImage(contentsOf: url)
        else {
            return nil
        }
        return image
    }
}

private struct DashboardCommands: Commands {
    @FocusedValue(\.focusAppSearch) private var focusSearch

    var body: some Commands {
        CommandGroup(after: .pasteboard) {
            Button("Search") {
                focusSearch?()
            }
            .keyboardShortcut("f", modifiers: .command)
            .disabled(focusSearch == nil)
        }
    }
}

/// Menubar app with a full workspace window and modal authorization prompts.
/// The Dock icon follows the workspace window rather than the background app lifetime.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        if let icon = FloriaImages.applicationIcon {
            NSApp.applicationIconImage = icon
        }
        DockVisibilityController.shared.prepareToShowDashboard()
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
            if let image = FloriaImages.menuBarTemplate {
                Image(nsImage: image)
                    .renderingMode(.template)
                    .foregroundStyle(
                        state.policyMode.isAuditOnly() ? Color.orange : Color.primary)
            } else {
                Image(
                    systemName: state.policyMode.isAuditOnly()
                        ? "eye.circle.fill" : "lock.shield")
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(
                        state.policyMode.isAuditOnly() ? Color.orange : Color.primary)
            }
        }
        // `.window` turns the dropdown into a real anchored window that hosts arbitrary
        // SwiftUI (search field, hover rows, ...) instead of an NSMenu.
        .menuBarExtraStyle(.window)

        // The daemon owns login-time startup. Launching the GUI is therefore an explicit user
        // action and should present the workspace immediately; the menu bar remains available
        // after the window is closed.
        Window("floria", id: "dashboard") {
            DashboardView(state: state)
                .background(
                    DashboardWindowTracker(
                        dockVisibilityController: DockVisibilityController.shared))
                .onDisappear {
                    DockVisibilityController.shared.dashboardDidClose()
                }
        }
        .defaultSize(width: 880, height: 720)
        .windowStyle(.hiddenTitleBar)
        .defaultLaunchBehavior(.presented)
        .commands {
            DashboardCommands()
        }

        // Detailed inventory management as its own window (not a sheet): the
        // full-size view layered over the compact dashboard reads as a glitch.
        Window("Floria Library", id: "workspace") {
            AdvancedWorkspaceView(state: state, initialSelection: state.workspaceWindowSelection)
                .id(state.workspaceWindowToken)
                .frame(minWidth: 1080, minHeight: 680)
        }
        .defaultSize(width: 1180, height: 760)
    }
}
