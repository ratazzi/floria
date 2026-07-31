import AppKit
import SwiftUI

struct RecoveryKeyExportSheet: View {
    let export: @MainActor (String, String) async throws -> RecoveryKeyReport
    let completed: @MainActor (RecoveryKeyReport) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var errorMessage: String?
    @State private var isExporting = false

    private var validationMessage: String? {
        if !passphrase.isEmpty && passphrase.count < 12 {
            return "Use at least 12 characters."
        }
        if !confirmation.isEmpty && passphrase != confirmation {
            return "Passphrases do not match."
        }
        return nil
    }

    private var canExport: Bool {
        passphrase.count >= 12
            && passphrase == confirmation
            && !isExporting
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "key.horizontal.fill")
                    .font(.system(size: 24, weight: .medium))
                    .foregroundStyle(.blue)
                    .frame(width: 48, height: 48)
                    .background(Color.blue.opacity(0.10), in: RoundedRectangle(cornerRadius: 11))

                VStack(alignment: .leading, spacing: 5) {
                    Text("Export Recovery Key")
                        .font(.title2.weight(.semibold))
                    Text(
                        "A backup needs this key to be restored on another Mac. Keep the exported file and its passphrase in separate safe places."
                    )
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }

            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 12) {
                GridRow {
                    Text("Passphrase")
                        .foregroundStyle(.secondary)
                    SecureField("At least 12 characters", text: $passphrase)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 280)
                }
                GridRow {
                    Text("Confirm")
                        .foregroundStyle(.secondary)
                    SecureField("Enter it again", text: $confirmation)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 280)
                }
            }

            if let message = errorMessage ?? validationMessage {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }

            Divider()

            HStack {
                Button("Cancel", role: .cancel) {
                    clearPassphrases()
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                .disabled(isExporting)

                Spacer()

                Button {
                    chooseDestinationAndExport()
                } label: {
                    if isExporting {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text("Choose File…")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canExport)
            }
        }
        .padding(24)
        .frame(width: 520)
    }

    private func chooseDestinationAndExport() {
        guard canExport else { return }
        let panel = NSSavePanel()
        panel.title = "Export Floria Recovery Key"
        panel.prompt = "Export"
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "Floria Recovery Key.age"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        errorMessage = nil
        isExporting = true
        Task {
            do {
                let report = try await export(url.path, passphrase)
                clearPassphrases()
                completed(report)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
                isExporting = false
            }
        }
    }

    private func clearPassphrases() {
        passphrase = ""
        confirmation = ""
    }
}
