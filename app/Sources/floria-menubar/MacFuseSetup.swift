import AppKit
import SwiftUI

/// First-launch readiness ladder for macFUSE. There is no reliable pre-flight API for
/// "kext approved": the kext loads lazily on the first mount and the system policy
/// database needs root. So the ladder is: installed? → let the daemon try to mount →
/// a healthy agent connection is the proof it worked; a timeout with macFUSE installed
/// almost always means the system extension still awaits approval.
enum MacFuseSetupStage: String, Identifiable {
    case installMacFuse
    case approveKext

    var id: String { rawValue }

    static let filesystemBundlePath = "/Library/Filesystems/macfuse.fs"

    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: MacFuseSetupStage.filesystemBundlePath)
    }
}

/// Compact menubar hint that setup is pending; the dashboard sheet carries the details.
struct MacFuseSetupBanner: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button {
            openWindow(id: "dashboard")
            NSApp.activate(ignoringOtherApps: true)
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "externaldrive.badge.exclamationmark")
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text("macFUSE setup required").font(.callout.weight(.medium))
                    Text("Floria is paused until the file system is ready. Click for instructions.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

struct MacFuseSetupView: View {
    @Bindable var state: AppState
    let stage: MacFuseSetupStage
    @Environment(\.dismiss) private var dismiss
    @State private var copiedCommand = false

    private var currentStage: MacFuseSetupStage {
        state.macFuseSetupStage ?? stage
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 13) {
                Image(systemName: "externaldrive.badge.exclamationmark")
                    .font(.title2)
                    .foregroundStyle(.orange)
                    .frame(width: 42, height: 42)
                    .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 2) {
                    Text("Set Up macFUSE").font(.title2.bold())
                    Text("Floria needs the macFUSE file system to serve your secrets as local files.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(22)
            Divider()

            VStack(alignment: .leading, spacing: 16) {
                switch currentStage {
                case .installMacFuse:
                    installContent
                case .approveKext:
                    approveContent
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(22)

            Divider()
            HStack {
                Text("Floria stays paused until the file system is ready.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Later") { dismiss() }
                    .disabled(state.macFuseRechecking)
                Button {
                    state.recheckMacFuseSetup()
                } label: {
                    if state.macFuseRechecking {
                        HStack(spacing: 7) {
                            ProgressView().controlSize(.small)
                            Text("Checking…")
                        }
                    } else {
                        Text("Recheck")
                    }
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(state.macFuseRechecking)
            }
            .padding(.horizontal, 22)
            .frame(height: 58)
        }
        .frame(width: 520)
        .onChange(of: state.macFuseSetupStage) { _, stage in
            if stage == nil { dismiss() }
        }
    }

    @ViewBuilder
    private var installContent: some View {
        Text("macFUSE is not installed. Install it, approve the system extension, then come back and recheck.")
            .font(.callout)

        VStack(alignment: .leading, spacing: 7) {
            Text("Install with Homebrew").font(.callout.weight(.medium))
            HStack(spacing: 8) {
                Text("brew install --cask macfuse")
                    .font(.body.monospaced())
                    .textSelection(.enabled)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 7))
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString("brew install --cask macfuse", forType: .string)
                    copiedCommand = true
                } label: {
                    Label(copiedCommand ? "Copied" : "Copy", systemImage: copiedCommand ? "checkmark" : "doc.on.doc")
                }
            }
            Text("Or download the installer from the macFUSE website.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Link("macfuse.github.io", destination: URL(string: "https://macfuse.github.io/")!)
                .font(.caption)
        }

        approvalSteps
    }

    @ViewBuilder
    private var approveContent: some View {
        Text("macFUSE is installed, but the file system could not start. The most common cause is that the system extension has not been approved yet.")
            .font(.callout)

        approvalSteps

        Text("Still stuck after approving? Run `floria doctor` in Terminal for a detailed self-check.")
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    @ViewBuilder
    private var approvalSteps: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("Approve the kernel extension").font(.callout.weight(.medium))
            Text("Floria's mount attempts make macOS show a \"System Extension Blocked\" dialog — click \"Open System Settings\" there and Allow, then restart your Mac. Missed the dialog? The approval also lives in System Settings → Privacy & Security, Security section (it only appears while macFUSE is waiting; if there is nothing to allow, see the recoveryOS step below).")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Open Privacy & Security") {
                if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security") {
                    NSWorkspace.shared.open(url)
                }
            }
        }

        DisclosureGroup("First kernel extension on this Mac?") {
            Text("Apple Silicon Macs must once lower their security policy before the approval above appears: shut down, hold the power button to enter recoveryOS, open Startup Security Utility, choose Reduced Security and check \"Allow user management of kernel extensions from identified developers\", then reboot and approve macFUSE as above. This is a one-time step.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 4)
        }
        .font(.caption.weight(.medium))
    }
}
