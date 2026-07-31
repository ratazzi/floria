import AppKit
import SwiftUI

struct SystemHealthView: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var state: AppState

    private var issues: [SystemHealthCheck] {
        state.systemHealth?.issues ?? []
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                Image(systemName: issues.isEmpty ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 25, weight: .semibold))
                    .foregroundStyle(issues.isEmpty ? Color.green : Color.orange)
                    .frame(width: 48, height: 48)
                    .background(Color.accentColor.opacity(0.09), in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 3) {
                    Text("System Health")
                        .font(.title2.bold())
                    Text(summary)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(24)

            Divider()

            ScrollView {
                if let error = state.systemHealthError {
                    healthError(error)
                        .padding(24)
                } else if issues.isEmpty {
                    ContentUnavailableView(
                        "Floria is ready",
                        systemImage: "checkmark.circle.fill",
                        description: Text("Encryption, storage, and the protected filesystem are available.")
                    )
                    .frame(maxWidth: .infinity, minHeight: 250)
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(issues.enumerated()), id: \.element.id) { index, issue in
                            issueRow(issue)
                            if index < issues.count - 1 {
                                Divider().padding(.leading, 50)
                            }
                        }
                    }
                    .padding(24)
                }
            }

            Divider()
            HStack {
                if !issues.isEmpty || state.systemHealthError != nil {
                    Button("Copy Doctor Command", systemImage: "terminal") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString("floria doctor", forType: .string)
                    }
                }
                Button("Refresh", systemImage: "arrow.clockwise") {
                    Task { await state.reloadSystemHealth() }
                }
                Spacer()
                Button("Done") { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 570, height: 440)
        .task {
            await state.reloadSystemHealth()
        }
    }

    private var summary: String {
        if state.systemHealthError != nil {
            return "Floria could not complete the health check."
        }
        if issues.isEmpty {
            return "All checks passed."
        }
        return "\(issues.count) \(issues.count == 1 ? "item needs" : "items need") attention."
    }

    private func issueRow(_ issue: SystemHealthCheck) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: issue.status == .error ? "xmark.circle.fill" : "exclamationmark.circle.fill")
                .font(.title3)
                .foregroundStyle(issue.status == .error ? Color.red : Color.orange)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 4) {
                Text(issue.title)
                    .font(.headline)
                Text(issue.message)
                    .foregroundStyle(.secondary)
                if let guidance = issue.guidance {
                    Text(guidance)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .padding(.top, 2)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 13)
    }

    private func healthError(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.title3)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 5) {
                Text("Health check unavailable")
                    .font(.headline)
                Text(message)
                    .foregroundStyle(.secondary)
                Text("Refresh after the daemon reconnects, or run `floria doctor` in Terminal.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}
