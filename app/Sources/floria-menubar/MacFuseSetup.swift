import AppKit
import SwiftUI

/// First-launch readiness ladder for macFUSE. A numbered `/dev/macfuseN` device is
/// definitive positive evidence that the kernel backend is already available. Its absence
/// is not definitive until a mount has been attempted because the backend loads lazily.
enum MacFuseSetupStage: String, Identifiable {
    case installMacFuse
    case approveKext
    case mountFailed

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

    static var isFloriaMounted: Bool {
        let mountPath = (NSHomeDirectory() as NSString).appendingPathComponent(".floria")
        var status = statfs()
        guard statfs(mountPath, &status) == 0 else { return false }
        let typeName = withUnsafePointer(to: &status.f_fstypename) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: Int(MFSNAMELEN)) {
                String(cString: $0)
            }
        }
        return filesystemIsMacFuse(typeName: typeName)
    }

    static func filesystemIsMacFuse(typeName: String) -> Bool {
        typeName == "macfuse" || typeName == "osxfuse"
    }

    /// The daemon opens its agent socket before entering the blocking FUSE mount call. A brief
    /// GUI connection therefore proves only that startup reached the agent, not that macFUSE
    /// accepted the mount. Require the numbered kernel device as independent readiness proof.
    static func daemonConnectionProvesReady(
        connected: Bool,
        kernelBackendReady: Bool,
        floriaMounted: Bool
    ) -> Bool {
        connected && kernelBackendReady && floriaMounted
    }

    /// A daemon can fail for catalog, key, configuration, or launchd reasons. Once the
    /// numbered device exists, a connection timeout must not be presented as macFUSE setup.
    static func afterFailedDaemonProbe(
        isInstalled: Bool,
        kernelBackendReady: Bool
    ) -> MacFuseSetupStage? {
        guard isInstalled else { return .installMacFuse }
        return kernelBackendReady ? .mountFailed : .approveKext
    }
}

/// Compact menubar hint that setup is pending; the dashboard sheet carries the details.
struct MacFuseSetupBanner: View {
    let stage: MacFuseSetupStage
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
                    Text(stage == .mountFailed ? "Floria could not start" : "macFUSE setup required")
                        .font(.callout.weight(.medium))
                    Text("Floria is paused until the file system is ready. Click for details.")
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
    @State private var copiedManualLoadCommand = false

    private static let doctorCommand =
        #""/Applications/Floria.app/Contents/Resources/floria" doctor"#
    private static let manualLoadCommand =
        "/usr/bin/sudo /usr/bin/kmutil load -p /Library/Filesystems/macfuse.fs/Contents/Extensions/26/macfuse.kext"

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
                    Text(currentStage == .mountFailed ? "Floria Couldn’t Start" : "Set Up macFUSE")
                        .font(.title2.bold())
                    Text(
                        currentStage == .mountFailed
                            ? "macFUSE is ready, but Floria did not finish mounting."
                            : "Floria needs the macFUSE file system to serve your secrets as local files.")
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
                case .mountFailed:
                    mountFailedContent
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
    private var mountFailedContent: some View {
        Text("The macFUSE kernel backend is available, but Floria did not finish starting its file system. No recoveryOS or System Settings action is needed for this state.")
            .font(.callout)

        VStack(alignment: .leading, spacing: 7) {
            Text("Check for a Keychain prompt").font(.callout.weight(.medium))
            Text("If macOS is asking Floria to access an item in your login Keychain, enter this Mac’s login password and choose Always Allow. Development builds can require this again after the app is replaced. Then return here and click Recheck.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Text("Collect the startup diagnosis").font(.callout.weight(.medium))
            Text("Click Recheck to retry once. If it still fails, copy this command into Terminal and keep its complete output; it checks the installed app, key, mount, daemon, and macFUSE backend without revealing secret plaintext.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
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
            Text("No alert or Allow button after Recheck? Run the official macFUSE troubleshooting command in Terminal, enter your administrator password, then return to Privacy & Security.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(Self.manualLoadCommand, forType: .string)
                copiedManualLoadCommand = true
            } label: {
                Label(
                    copiedManualLoadCommand ? "Manual load command copied" : "Copy manual load command",
                    systemImage: copiedManualLoadCommand ? "checkmark" : "terminal")
            }
            Link(
                "Open the official macFUSE setup guide",
                destination: URL(string: "https://github.com/macfuse/macfuse/wiki/Getting-Started")!)
                .font(.caption)
        }
    }
}
