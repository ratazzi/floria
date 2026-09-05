import CloudKit
import Foundation

/// Server heads select candidates; Rust still authenticates each candidate and merges its history.
struct CloudConflictSelection {
    let entityID: String
    let revisionID: String

    static func plan(
        reviews: [SyncConflictReview],
        serverHeads: [String: String]
    ) throws -> [Self] {
        try reviews.map { review in
            guard let revisionID = serverHeads[review.entityID],
                  review.candidates.contains(where: { $0.revisionID == revisionID })
            else {
                throw SelectionError.unavailable
            }
            return Self(entityID: review.entityID, revisionID: revisionID)
        }
    }

    static func fetchPlan(
        reviews: [SyncConflictReview], vaultID: String, database: CKDatabase
    ) async throws -> [Self] {
        let codec = try CloudRecordCodec(vaultID: vaultID)
        var heads = [String: String]()
        for start in stride(from: 0, to: reviews.count, by: 100) {
            let batch = reviews[start..<min(start + 100, reviews.count)]
            let ids = batch.map { codec.recordID(prefix: "head", stableID: $0.entityID) }
            let fetched = try await database.records(for: ids)
            for id in ids {
                guard let result = fetched[id] else { throw SelectionError.unavailable }
                let record = try result.get()
                guard record.recordID == id,
                      case .head(let entityID, _) = try codec.decode(record),
                      let revisionID = record[CloudRecordCodec.Field.revisionID] as? String
                else { throw SelectionError.unavailable }
                heads[entityID] = revisionID
            }
        }
        // Validate the complete selection before resolving the first item.
        return try plan(reviews: reviews, serverHeads: heads)
    }

    enum SelectionError: LocalizedError {
        case unavailable

        var errorDescription: String? {
            "An iCloud version is missing or has changed. Sync again before choosing iCloud versions."
        }
    }
}
