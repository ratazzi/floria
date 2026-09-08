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

/// Menubar app with a full workspace window and non-modal authorization windows.
/// The Dock icon follows user-facing windows rather than the background app lifetime.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var menuBarController: MenuBarController?

    @MainActor
    func installMenuBar(state: AppState, openDashboard: @escaping () -> Void) {
        guard menuBarController == nil else { return }
        let controller = MenuBarController { [weak self] in
            AnyView(MenuBarView(state: state, openDashboard: {
                self?.menuBarController?.close()
                DockVisibilityController.shared.prepareToShowDashboard()
                openDashboard()
                NSApp.activate(ignoringOtherApps: true)
            }))
        }
        menuBarController = controller
        controller.observePolicy(state)
    }

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
        // The daemon owns login-time startup. Launching the GUI is therefore an explicit user
        // action and should present the workspace immediately; the menu bar remains available
        // after the window is closed.
        Window("floria", id: "dashboard") {
            DashboardView(state: state)
                .background(MenuBarInstallation(state: state, appDelegate: appDelegate))
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
        .windowStyle(.hiddenTitleBar)
    }
}
