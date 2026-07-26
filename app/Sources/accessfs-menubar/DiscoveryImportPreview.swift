import Foundation

struct DiscoveryImportPreview: Equatable {
    struct Conflict: Equatable, Identifiable {
        enum Kind: Equatable {
            case outputExists
            case duplicateOutput
        }

        let kind: Kind
        let path: String
        let sourcePaths: [String]

        var id: String {
            "\(kind == .outputExists ? "exists" : "duplicate"):\(path)"
        }

        var message: String {
            let displayPath = (path as NSString).abbreviatingWithTildeInPath
            switch kind {
            case .outputExists:
                return "Output already exists: \(displayPath)"
            case .duplicateOutput:
                return "Multiple selected files target \(displayPath)"
            }
        }
    }

    let replacedSources: Int
    let createdOutputs: Int
    let protectedSources: Int
    let unchangedSources: Int
    let conflicts: [Conflict]

    var hasConflicts: Bool {
        !conflicts.isEmpty
    }

    var actionSummary: String {
        var parts: [String] = []
        if replacedSources > 0 {
            parts.append(
                "\(replacedSources) original\(replacedSources == 1 ? "" : "s") replaced")
        }
        if createdOutputs > 0 {
            parts.append(
                "\(createdOutputs) project output\(createdOutputs == 1 ? "" : "s") created")
        }
        if protectedSources > 0 {
            parts.append(
                "\(protectedSources) original\(protectedSources == 1 ? "" : "s") protected")
        }
        if unchangedSources > 0 {
            parts.append(
                "\(unchangedSources) original\(unchangedSources == 1 ? "" : "s") unchanged")
        }
        return parts.isEmpty ? "No filesystem changes selected." : parts.joined(separator: " · ")
    }

    init(
        imports: [DiscoveryImport],
        pathExists: (String) -> Bool
    ) {
        var replacedSources = 0
        var createdOutputs = 0
        var protectedSources = 0
        var unchangedSources = 0
        var outputSources: [String: Set<String>] = [:]

        for item in imports {
            switch item.sourceDisposition {
            case .replaceWithSurface:
                replacedSources += 1
            case .protectInPlace:
                protectedSources += 1
            case .leaveUnchanged:
                unchangedSources += 1
            }

            let sourcePath = Self.standardize(item.path)
            for outputPath in Self.outputPaths(for: item.destination) {
                let outputPath = Self.standardize(outputPath)
                guard outputPath != sourcePath else { continue }
                createdOutputs += 1
                outputSources[outputPath, default: []].insert(sourcePath)
            }
        }

        var conflicts: [Conflict] = []
        for (path, sourcePaths) in outputSources {
            let sortedSources = sourcePaths.sorted()
            if sortedSources.count > 1 {
                conflicts.append(
                    Conflict(
                        kind: .duplicateOutput,
                        path: path,
                        sourcePaths: sortedSources))
            }
            if pathExists(path) {
                conflicts.append(
                    Conflict(
                        kind: .outputExists,
                        path: path,
                        sourcePaths: sortedSources))
            }
        }

        self.replacedSources = replacedSources
        self.createdOutputs = createdOutputs
        self.protectedSources = protectedSources
        self.unchangedSources = unchangedSources
        self.conflicts = conflicts.sorted {
            if $0.path == $1.path {
                return $0.id < $1.id
            }
            return $0.path < $1.path
        }
    }

    private static func outputPaths(
        for destination: DiscoveryImportDestination
    ) -> [String] {
        switch destination {
        case .projectOutput(_, let outputPath):
            return [outputPath]
        case .library:
            return []
        case .projectOutputs(let outputs):
            return outputs.map(\.outputPath)
        }
    }

    private static func standardize(_ path: String) -> String {
        (path as NSString).standardizingPath
    }
}
