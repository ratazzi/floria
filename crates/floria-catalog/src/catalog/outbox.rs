use super::*;
use crate::domain::ReplicationStoreVersionRef;

pub(super) fn outbox_from(conn: &Connection) -> CatalogResult<Vec<ReplicationOutboxEntry>> {
    let mut statement = conn.prepare(
        "SELECT intent_id, logical_id, parents_json, store_versions_json,
                catalog_payload, created_at
         FROM replication_outbox
         ORDER BY created_at, intent_id",
    )?;
    let entries = statement
        .query_map([], decode_outbox_row)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(CatalogError::from)?;
    Ok(entries)
}

impl Catalog {
    pub fn replication_outbox(&self) -> CatalogResult<Vec<ReplicationOutboxEntry>> {
        self.with_authenticated_read(|_, snapshot| Ok(snapshot.outbox.clone()))
    }

    /// Persist an immutable export intent. An exact retry is accepted; the same intent id may
    /// never be rebound to different catalog state or store versions.
    pub fn enqueue_replication_outbox(
        &self,
        entry: &ReplicationOutboxEntry,
    ) -> CatalogResult<()> {
        validate_outbox_entry(entry)?;
        self.with_authenticated_mutation(|tx| {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO replication_outbox (
                    intent_id, logical_id, parents_json, store_versions_json,
                    catalog_payload, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &entry.intent_id,
                    &entry.logical_id,
                    serde_json::to_string(&entry.parents)?,
                    serde_json::to_string(&entry.store_versions)?,
                    entry.catalog_payload.as_slice(),
                    &entry.created_at,
                ],
            )?;
            if inserted == 0 {
                let existing = tx.query_row(
                    "SELECT intent_id, logical_id, parents_json, store_versions_json,
                            catalog_payload, created_at
                     FROM replication_outbox WHERE intent_id = ?1",
                    params![&entry.intent_id],
                    decode_outbox_row,
                )?;
                if existing != *entry {
                    return Err(CatalogError::Validation(format!(
                        "replication intent {} already names different committed state",
                        entry.intent_id
                    )));
                }
            }
            Ok(())
        })
    }

    pub fn remove_replication_outbox(&self, intent_id: &str) -> CatalogResult<()> {
        require_uuid("replication intent id", intent_id)?;
        self.with_authenticated_mutation(|tx| {
            let changed = tx.execute(
                "DELETE FROM replication_outbox WHERE intent_id = ?1",
                params![intent_id],
            )?;
            if changed == 0 {
                return Err(CatalogError::NotFound(format!(
                    "replication outbox intent {intent_id}"
                )));
            }
            Ok(())
        })
    }
}

fn decode_outbox_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReplicationOutboxEntry> {
    Ok(ReplicationOutboxEntry {
        intent_id: row.get(0)?,
        logical_id: row.get(1)?,
        parents: decode_json(2, &row.get::<_, String>(2)?)?,
        store_versions: decode_json::<Vec<ReplicationStoreVersionRef>>(
            3,
            &row.get::<_, String>(3)?,
        )?,
        catalog_payload: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn validate_outbox_entry(entry: &ReplicationOutboxEntry) -> CatalogResult<()> {
    require_uuid("replication intent id", &entry.intent_id)?;
    if entry.logical_id.trim().is_empty() {
        return Err(CatalogError::Validation(
            "replication outbox logical id cannot be empty".to_string(),
        ));
    }
    if entry.catalog_payload.is_empty() {
        return Err(CatalogError::Validation(
            "replication outbox catalog payload cannot be empty".to_string(),
        ));
    }
    if entry.created_at.trim().is_empty() {
        return Err(CatalogError::Validation(
            "replication outbox creation time cannot be empty".to_string(),
        ));
    }
    for reference in &entry.store_versions {
        require_uuid("replication store secret id", &reference.secret_id)?;
        if reference.version == 0 {
            return Err(CatalogError::Validation(
                "replication store version starts at 1".to_string(),
            ));
        }
    }
    Ok(())
}

fn require_uuid(label: &str, value: &str) -> CatalogResult<()> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| CatalogError::Validation(format!("{label} is not a UUID: {value:?}")))
}
