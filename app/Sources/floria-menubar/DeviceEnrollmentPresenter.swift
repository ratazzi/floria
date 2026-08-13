import AppKit
import Observation
import SwiftUI

@Observable @MainActor
private final class DeviceEnrollmentApprovalState {
    let review: SyncEnrollmentReview
    var isWorking = false
    var errorMessage: String?

    init(review: SyncEnrollmentReview) {
        self.review = review
    }
}

private struct DeviceEnrollmentApprovalView: View {
    let state: DeviceEnrollmentApprovalState
    let approve: () -> Void
    let later: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Image(systemName: "laptopcomputer.and.iphone")
                    .font(.system(size: 25, weight: .medium))
                    .foregroundStyle(.blue)
                    .frame(width: 48, height: 48)
                    .background(Color.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 3) {
                    Text("New Mac Wants Access")
                        .font(.title2.bold())
                    Text("Your encrypted Floria Library")
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(.horizontal, 24)
            .frame(height: 88)

            Divider()

            VStack(alignment: .leading, spacing: 18) {
                Text(state.review.deviceName ?? "Another Mac")
                    .font(.title3.bold())
                Text(
                    "Compare this code with the code shown on the Mac requesting access. Approve only when they match exactly."
                )
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                Text(state.review.fingerprint)
                    .font(.system(.title2, design: .monospaced).weight(.semibold))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 15)
                    .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))

                if let errorMessage = state.errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(24)

            Divider()

            HStack {
                Button("Later") { later() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if state.isWorking {
                    ProgressView().controlSize(.small)
                }
                Button("Codes Match — Approve") { approve() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(state.isWorking)
            }
            .padding(.horizontal, 22)
            .frame(height: 58)
        }
        .frame(width: 520, height: 390)
    }
}

/// Presents device enrollment as a normal app window, independent from the Sync sheet.
/// Only one request is shown at a time; the coordinator de-duplicates requests across polls.
@MainActor
final class DeviceEnrollmentPresenter {
    typealias Approval = @MainActor @Sendable (SyncEnrollmentReview) async throws -> Void

    private final class ActiveWindow {
        let state: DeviceEnrollmentApprovalState
        let controller: NSWindowController
        let delegate: DeviceEnrollmentWindowDelegate

        init(
            state: DeviceEnrollmentApprovalState,
            controller: NSWindowController,
            delegate: DeviceEnrollmentWindowDelegate
        ) {
            self.state = state
            self.controller = controller
            self.delegate = delegate
        }
    }

    private let dockVisibilityController: DockVisibilityController
    private var active: ActiveWindow?

    var activeWindow: NSWindow? { active?.controller.window }

    init(dockVisibilityController: DockVisibilityController? = nil) {
        self.dockVisibilityController = dockVisibilityController ?? .shared
    }

    func show(_ review: SyncEnrollmentReview, approve: @escaping Approval) {
        if let active {
            if active.state.review.deviceID == review.deviceID,
               active.state.review.fingerprint == review.fingerprint
            {
                active.controller.window?.makeKeyAndOrderFront(nil)
            }
            return
        }

        let state = DeviceEnrollmentApprovalState(review: review)
        let content = DeviceEnrollmentApprovalView(
            state: state,
            approve: { [weak self] in self?.approve(active: state, operation: approve) },
            later: { [weak self] in self?.close() })
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 390),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        window.title = "Floria Library Access Request"
        window.isReleasedWhenClosed = false
        window.isExcludedFromWindowsMenu = false
        window.canHide = false
        window.level = .floating
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        window.tabbingMode = .disallowed
        window.contentView = NSHostingView(rootView: content)
        window.center()
        let delegate = DeviceEnrollmentWindowDelegate { [weak self] in self?.close() }
        window.delegate = delegate
        let controller = NSWindowController(window: window)
        active = ActiveWindow(state: state, controller: controller, delegate: delegate)

        dockVisibilityController.backgroundAttentionWindowDidOpen()
        NSApplication.shared.activate(ignoringOtherApps: true)
        controller.showWindow(nil)
        window.makeKeyAndOrderFront(nil)
    }

    /// Close a request that was handled through another Floria window or on another poll.
    func reconcile(_ reviews: [SyncEnrollmentReview]) {
        guard let active else { return }
        let isStillPending = reviews.contains {
            $0.deviceID == active.state.review.deviceID
                && $0.fingerprint == active.state.review.fingerprint
        }
        if !isStillPending { close() }
    }

    private func approve(active state: DeviceEnrollmentApprovalState, operation: @escaping Approval) {
        guard active?.state === state, !state.isWorking else { return }
        state.isWorking = true
        state.errorMessage = nil
        Task { @MainActor [weak self, weak state] in
            guard let self, let state else { return }
            do {
                try await operation(state.review)
                self.close()
            } catch {
                guard self.active?.state === state else { return }
                state.isWorking = false
                state.errorMessage = CloudSyncErrorPresentation.message(for: error)
            }
        }
    }

    private func close() {
        guard let active else { return }
        active.controller.window?.delegate = nil
        active.controller.close()
        self.active = nil
        dockVisibilityController.backgroundAttentionWindowDidClose()
    }
}

@MainActor
private final class DeviceEnrollmentWindowDelegate: NSObject, NSWindowDelegate {
    private let onClose: () -> Void

    init(onClose: @escaping () -> Void) {
        self.onClose = onClose
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        onClose()
        return false
    }
}
