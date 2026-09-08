import AppKit
import Observation
import SwiftUI

private final class MenuBarPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

private struct MeasuredMenuBarContent: View {
    let content: AnyView
    let sizeChanged: (CGSize) -> Void

    var body: some View {
        content
            .fixedSize(horizontal: false, vertical: true)
            .onGeometryChange(for: CGSize.self) { proxy in
                proxy.size
            } action: { sizeChanged($0) }
    }
}

/// A status-item panel without NSPopover's anchor arrow. AppKit still owns the
/// material, placement and event handling; SwiftUI supplies content only.
@MainActor
final class MenuBarController: NSObject {
    static let panelGap: CGFloat = 4
    static let panelCornerRadius: CGFloat = 12

    let panel: NSPanel
    private let statusItem: NSStatusItem
    private let makeContent: () -> AnyView
    private var hostingController: NSViewController?
    private weak var anchorView: NSView?
    private var localEventMonitor: Any?
    private var globalEventMonitor: Any?
    private var resignActiveObserver: NSObjectProtocol?

    init(makeContent: @escaping () -> AnyView) {
        self.makeContent = makeContent
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        panel = MenuBarPanel(
            contentRect: .zero,
            styleMask: [.borderless, .fullSizeContentView],
            backing: .buffered,
            defer: true)
        super.init()

        statusItem.autosaveName = "floria-main"
        statusItem.button?.target = self
        statusItem.button?.action = #selector(toggle)
        statusItem.button?.setAccessibilityLabel("Floria")

        panel.isOpaque = false
        panel.backgroundColor = .clear
        // The content view below supplies a real rounded alpha mask, so the
        // window server can derive a native shadow without exposing the panel's
        // rectangular backing surface.
        panel.hasShadow = true
        panel.level = .popUpMenu
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.isExcludedFromWindowsMenu = true
        panel.collectionBehavior = [.transient, .moveToActiveSpace, .fullScreenAuxiliary]
        updateIcon(auditOnly: false)
    }

    deinit {
        if let localEventMonitor {
            NSEvent.removeMonitor(localEventMonitor)
        }
        if let globalEventMonitor {
            NSEvent.removeMonitor(globalEventMonitor)
        }
        if let resignActiveObserver {
            NotificationCenter.default.removeObserver(resignActiveObserver)
        }
        NSStatusBar.system.removeStatusItem(statusItem)
    }

    func observePolicy(_ state: AppState) {
        withObservationTracking {
            updateIcon(auditOnly: state.policyMode.isAuditOnly())
        } onChange: { [weak self, weak state] in
            Task { @MainActor in
                guard let self, let state else { return }
                self.observePolicy(state)
            }
        }
    }

    private func updateIcon(auditOnly: Bool) {
        statusItem.button?.image = FloriaImages.menuBarTemplate
            ?? NSImage(systemSymbolName: auditOnly ? "eye.circle.fill" : "lock.shield",
                       accessibilityDescription: "Floria")
        statusItem.button?.contentTintColor = auditOnly ? .systemOrange : nil
    }

    @objc func toggle() {
        if panel.isVisible {
            close()
            return
        }
        guard let button = statusItem.button else { return }
        show(relativeTo: button)
    }

    func show(relativeTo anchor: NSView) {
        anchorView = anchor
        prepareContent()
        positionPanel(relativeTo: anchor)
        beginDismissalMonitoring()
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    func prepareContent() {
        let root = MeasuredMenuBarContent(content: makeContent()) { [weak self] size in
            self?.applyContentSize(size)
        }
        let hosting = NSHostingController(rootView: root)
        hosting.sizingOptions = [.intrinsicContentSize]
        let initialSize = hosting.view.fittingSize
        hosting.view.setFrameSize(initialSize)

        let chrome = Self.makeChromeView(frame: NSRect(origin: .zero, size: initialSize))
        hosting.view.frame = chrome.bounds
        hosting.view.autoresizingMask = [.width, .height]
        chrome.addSubview(hosting.view)
        hostingController = hosting
        panel.contentView = chrome
        applyContentSize(initialSize)
        panel.invalidateShadow()
    }

    func close() {
        stopDismissalMonitoring()
        panel.orderOut(nil)
        panel.contentView = nil
        hostingController = nil
        anchorView = nil
    }

    func applyContentSize(_ measured: CGSize) {
        guard let size = Self.contentSize(for: measured), size != panel.contentView?.frame.size else {
            return
        }
        panel.setContentSize(size)
        panel.invalidateShadow()
        if let anchorView, panel.isVisible {
            positionPanel(relativeTo: anchorView)
        }
    }

    static func contentSize(for measured: CGSize) -> CGSize? {
        guard measured.width.isFinite, measured.height.isFinite,
            measured.width > 0, measured.height >= 8 else { return nil }
        return CGSize(width: 360, height: ceil(measured.height))
    }

    static func panelOrigin(
        anchorFrame: NSRect,
        panelSize: CGSize,
        visibleFrame: NSRect
    ) -> NSPoint {
        let horizontalMargin: CGFloat = 8
        let minimumX = visibleFrame.minX + horizontalMargin
        let maximumX = visibleFrame.maxX - panelSize.width - horizontalMargin
        let centeredX = anchorFrame.midX - panelSize.width / 2
        let x = min(max(centeredX, minimumX), max(minimumX, maximumX))
        let belowY = anchorFrame.minY - panelSize.height - panelGap
        let y = belowY >= visibleFrame.minY + horizontalMargin
            ? belowY
            : anchorFrame.maxY + panelGap
        return NSPoint(x: round(x), y: round(y))
    }

    private static func makeChromeView(frame: NSRect) -> NSView {
        // NSGlassEffectView.cornerRadius shapes the glass itself, but does not
        // guarantee that its backdrop or sibling hosting view is clipped. Use a
        // transparent layer-backed parent as the single compositing boundary.
        let clipView = NSView(frame: frame)
        clipView.wantsLayer = true
        clipView.layer?.backgroundColor = NSColor.clear.cgColor
        clipView.layer?.cornerRadius = panelCornerRadius
        clipView.layer?.cornerCurve = .continuous
        clipView.layer?.masksToBounds = true

        let background: NSView
        if #available(macOS 26, *) {
            let glass = NSGlassEffectView(frame: frame)
            glass.style = .regular
            glass.tintColor = nil
            glass.cornerRadius = panelCornerRadius
            background = glass
        } else {
            let material = NSVisualEffectView(frame: frame)
            material.material = .popover
            material.blendingMode = .behindWindow
            material.state = .active
            background = material
        }

        background.frame = clipView.bounds
        background.autoresizingMask = [.width, .height]
        clipView.addSubview(background)
        return clipView
    }

    private func positionPanel(relativeTo anchor: NSView) {
        guard let window = anchor.window else { return }
        let windowRect = anchor.convert(anchor.bounds, to: nil)
        let screenRect = window.convertToScreen(windowRect)
        let visibleFrame = window.screen?.visibleFrame ?? NSScreen.main?.visibleFrame ?? screenRect
        panel.setFrameOrigin(Self.panelOrigin(
            anchorFrame: screenRect,
            panelSize: panel.frame.size,
            visibleFrame: visibleFrame))
    }

    private func beginDismissalMonitoring() {
        stopDismissalMonitoring()
        localEventMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .keyDown]
        ) { [weak self] event in
            guard let self else { return event }
            if event.type == .keyDown, event.keyCode == 53 {
                self.close()
                return nil
            }
            if event.window !== self.panel && event.window !== self.statusItem.button?.window {
                self.close()
            }
            return event
        }
        globalEventMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown]
        ) { [weak self] _ in
            Task { @MainActor in self?.close() }
        }
        resignActiveObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didResignActiveNotification,
            object: NSApp,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.close() }
        }
    }

    private func stopDismissalMonitoring() {
        if let localEventMonitor {
            NSEvent.removeMonitor(localEventMonitor)
            self.localEventMonitor = nil
        }
        if let globalEventMonitor {
            NSEvent.removeMonitor(globalEventMonitor)
            self.globalEventMonitor = nil
        }
        if let resignActiveObserver {
            NotificationCenter.default.removeObserver(resignActiveObserver)
            self.resignActiveObserver = nil
        }
    }
}

/// Capture the scene's real window-opening action, not the default environment of an
/// independently created NSHostingController. The delegate retains the menu after close.
struct MenuBarInstallation: View {
    @Environment(\.openWindow) private var openWindow
    let state: AppState
    let appDelegate: AppDelegate

    var body: some View {
        Color.clear.onAppear {
            appDelegate.installMenuBar(state: state) {
                openWindow(id: "dashboard")
            }
        }
    }
}
