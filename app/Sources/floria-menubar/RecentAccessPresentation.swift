import SwiftUI

struct RecentAccessGroup: Identifiable {
    struct ID: Hashable {
        let path: String
        let shownPath: String
        let operation: String
        let decision: String
        let exePath: String?
        let chain: String
        let ruleID: String?
        let policyMode: String?
        let policyConfiguredEnforcement: String?
        let policyEffectiveEnforcement: String?
        let sshFingerprint: String?
    }

    let id: ID
    let latest: RecentAccess
    var count: Int
}

enum RecentAccessProjection {
    static func grouped(
        _ recents: [RecentAccess],
        maximumGroups: Int? = nil
    ) -> [RecentAccessGroup] {
        let candidates = recents.sorted {
            ($0.date ?? .distantPast) > ($1.date ?? .distantPast)
        }
        var groupIndexes: [RecentAccessGroup.ID: Int] = [:]
        var groups: [RecentAccessGroup] = []

        for recent in candidates {
            let id = RecentAccessGroup.ID(recent)
            if let index = groupIndexes[id] {
                groups[index].count += 1
            } else {
                groupIndexes[id] = groups.count
                groups.append(RecentAccessGroup(id: id, latest: recent, count: 1))
            }
        }

        guard let maximumGroups else { return groups }
        return Array(groups.prefix(maximumGroups))
    }
}

struct RecentAccessTimeText: View {
    let event: RecentAccess

    var body: some View {
        Text(event.relativeTime(relativeTo: Date()))
    }
}

extension RecentAccess {
    func relativeTime(relativeTo now: Date) -> String {
        guard let date else { return time }
        if abs(date.timeIntervalSince(now)) < 1 {
            return "now"
        }
        return RecentAccessPresentation.relativeDate.localizedString(
            for: date,
            relativeTo: now)
    }
}

private extension RecentAccessGroup.ID {
    init(_ recent: RecentAccess) {
        path = recent.path
        shownPath = recent.shownPath
        operation = recent.operation
        decision = recent.decision
        exePath = recent.exePath
        chain = recent.chain
        ruleID = recent.ruleId
        policyMode = recent.policy?.mode
        policyConfiguredEnforcement = recent.policy?.configured_enforcement
        policyEffectiveEnforcement = recent.policy?.effective_enforcement
        sshFingerprint = recent.ssh?.key_fingerprint
    }
}

private enum RecentAccessPresentation {
    static let relativeDate: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()
}
