import AppKit
import SwiftUI

/// First-launch readiness ladder for macFUSE. A numbered `/dev/macfuseN` device is
/// definitive positive evidence that the kernel backend is already available. Its absence
/// is not definitive until a mount has been attempted because the backend loads lazily.
enum MacFuseSetupStage: String, Identifiable {
    case installMacFuse
    case approveKext

    var id: String { rawValue }

    static let filesystemBundlePath = "/Library/Filesystems/macfuse.fs"

    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: MacFuseSetupStage.filesystemBundlePath)
    }

    static var isKernelBackendReady: Bool {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: "/dev")) ?? []
        return kernelBackendReady(deviceNames: names)
    }

    static func kernelBackendReady(deviceNames: [String]) -> Bool {
        deviceNames.contains(where: { name in
            let prefix = "macfuse"
            guard name.hasPrefix(prefix) else { return false }
            let suffix = name.dropFirst(prefix.count)
            return !suffix.isEmpty && suffix.utf8.allSatisfy { (48...57).contains($0) }
        })
    }

    /// A daemon can fail for catalog, key, configuration, or launchd reasons. Once the
    /// numbered device exists, a connection timeout must not be presented as macFUSE setup.
    static func afterFailedDaemonProbe(
        isInstalled: Bool,
        kernelBackendReady: Bool
    ) -> MacFuseSetupStage? {
        guard isInstalled else { return .installMacFuse }
        return kernelBackendReady ? nil : .approveKext
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
    @State private var copiedDoctorCommand = false

    private static let doctorCommand =
        #""/Applications/Floria.app/Contents/Resources/floria" doctor --config "$HOME/Library/Application Support/floria/floria.toml""#

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
        .frame(width: 560)
        .onChange(of: state.macFuseSetupStage) { _, stage in
            if stage == nil { dismiss() }
        }
    }

    @ViewBuilder
    private var installContent: some View {
        Text("macFUSE is not installed. Install it, then complete the two one-time system steps below.")
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
        Text("macFUSE is installed, but its kernel backend is not ready. On a new Apple silicon Mac, System Settings can show no Allow button until kernel extensions are enabled in recoveryOS first.")
            .font(.callout)

        approvalSteps

        VStack(alignment: .leading, spacing: 7) {
            Text("Still stuck?").font(.callout.weight(.medium))
            Text("Copy this command into Terminal to check the installed app, key, mount, and macFUSE kernel backend.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(Self.doctorCommand, forType: .string)
                copiedDoctorCommand = true
            } label: {
                Label(
                    copiedDoctorCommand ? "Doctor command copied" : "Copy doctor command",
                    systemImage: copiedDoctorCommand ? "checkmark" : "doc.on.doc")
            }
        }
    }

    @ViewBuilder
    private var approvalSteps: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("1. Enable third-party kernel extensions").font(.callout.weight(.medium))
            Text("Shut down your Mac, then press and hold the power button until startup options appear. Choose Options → Continue. In recoveryOS, open Utilities → Startup Security Utility, select your startup disk, and choose Security Policy…. Select Reduced Security and enable \"Allow user management of kernel extensions from identified developers\", then restart.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("If System Settings has no Allow button yet, that is expected before this step.")
                .font(.caption.weight(.medium))
                .foregroundStyle(.orange)
        }

        VStack(alignment: .leading, spacing: 7) {
            Text("2. Approve macFUSE after restarting").font(.callout.weight(.medium))
            Text("Reopen Floria and click Recheck to trigger a new mount attempt. When macOS shows the system-extension alert, use its Open System Settings button, allow macFUSE, and restart when asked.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Do not enable the macFUSE switches under File System Extensions. Those select the FSKit backend; Floria needs the kernel backend to identify the reading process.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Link(
                "Open the official macFUSE setup guide",
                destination: URL(string: "https://github.com/macfuse/macfuse/wiki/Getting-Started")!)
                .font(.caption)
        }
    }
}
