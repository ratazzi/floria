import AppKit

struct DiagnosticsExportSelection {
    let path: String
    let includePaths: Bool
}

@MainActor
func chooseDiagnosticsExportDestination() -> DiagnosticsExportSelection? {
    let panel = NSSavePanel()
    panel.title = "Export Floria Diagnostics"
    panel.prompt = "Export"
    panel.canCreateDirectories = true
    panel.nameFieldStringValue = "Floria Diagnostics"

    let includePaths = NSButton(
        checkboxWithTitle: "Include local file paths",
        target: nil,
        action: nil)
    includePaths.state = .off
    includePaths.toolTip =
        "Leave this off when sharing diagnostics unless exact locations are needed."
    let accessory = NSStackView(views: [includePaths])
    accessory.orientation = .vertical
    accessory.alignment = .leading
    accessory.edgeInsets = NSEdgeInsets(top: 6, left: 0, bottom: 6, right: 0)
    panel.accessoryView = accessory

    guard panel.runModal() == .OK, let url = panel.url else { return nil }
    return DiagnosticsExportSelection(
        path: url.path,
        includePaths: includePaths.state == .on)
}

@MainActor
func revealDiagnostics(_ report: DiagnosticsReport) {
    NSWorkspace.shared.activateFileViewerSelecting([
        URL(fileURLWithPath: report.path)
    ])
}
