import AppKit
import SwiftUI

/// The macOS 27 regression leaves the MenuBarExtra hosting layer with a zero corner radius.
/// Apply the requested shape to the real host without painting a rectangular fill.
private final class MenuBarWindowProbeView: NSView {
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let window {
            MenuBarWindowChrome.configure(window)
        }
    }
}

struct MenuBarWindowChrome: NSViewRepresentable {
    static let cornerRadius: CGFloat = 12

    func makeNSView(context: Context) -> NSView {
        MenuBarWindowProbeView()
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        if let window = nsView.window {
            Self.configure(window)
        }
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
