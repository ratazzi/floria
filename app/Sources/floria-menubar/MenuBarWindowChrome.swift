import AppKit
import SwiftUI

/// The macOS 27 regression leaves the MenuBarExtra hosting layer with a zero corner radius and
/// an opaque window-like fill. Supply the same vibrancy material as an AppKit menu, then apply
/// the requested shape to the real host instead of painting a rectangular SwiftUI background.
private final class MenuBarWindowMaterialView: NSVisualEffectView {
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let window {
            MenuBarWindowChrome.configure(window)
        }
    }
}

struct MenuBarWindowChrome: NSViewRepresentable {
    static let cornerRadius: CGFloat = 12

    func makeNSView(context: Context) -> NSVisualEffectView {
        Self.makeBackgroundView()
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        Self.configure(nsView)
        if let window = nsView.window {
            Self.configure(window)
        }
    }

    @MainActor
    static func makeBackgroundView() -> NSVisualEffectView {
        let view = MenuBarWindowMaterialView()
        configure(view)
        return view
    }

    @MainActor
    private static func configure(_ view: NSVisualEffectView) {
        view.material = .menu
        view.blendingMode = .behindWindow
        view.state = .active
    }

    @MainActor
    static func configure(_ window: NSWindow) {
        window.isOpaque = false
        window.backgroundColor = .clear

        guard let contentView = window.contentView else { return }
        contentView.wantsLayer = true
        contentView.layer?.cornerRadius = cornerRadius
        contentView.layer?.cornerCurve = .continuous
        contentView.layer?.masksToBounds = true
    }
}
