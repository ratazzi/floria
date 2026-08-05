use super::*;

pub(super) fn migrate(conn: &mut Connection) -> CatalogResult<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version != 0 {
        return Err(CatalogError::UnsupportedSchema {
            found: version,
            expected: SCHEMA_VERSION,
        });
    }

    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            default_environment_id TEXT REFERENCES environments(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE project_checkouts (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            path TEXT NOT NULL UNIQUE,
            environment_id TEXT REFERENCES environments(id) ON DELETE RESTRICT,
            kind TEXT NOT NULL,
            git_common_dir TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE UNIQUE INDEX project_primary_checkout_idx
            ON project_checkouts(project_id) WHERE kind = 'primary';
        CREATE INDEX project_checkouts_project_idx
            ON project_checkouts(project_id, kind, path);

        CREATE TABLE environments (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(project_id, name)
        );

        CREATE TABLE resources (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            shape TEXT NOT NULL,
            codec TEXT NOT NULL,
            default_env_key TEXT,
            entries_json TEXT NOT NULL,
            source_json TEXT NOT NULL,
            enforcement TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            origin_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE resource_endpoints (
            resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
            endpoint TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE bindings (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            environment_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
            resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE RESTRICT,
            key_override TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            allow_override INTEGER NOT NULL DEFAULT 0,
            position INTEGER NOT NULL DEFAULT 0,
            selection_json TEXT NOT NULL DEFAULT '{\"type\":\"all\"}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX bindings_project_idx ON bindings(project_id, environment_id, position);
        CREATE INDEX bindings_resource_idx ON bindings(resource_id);

        CREATE TABLE surfaces (
            id TEXT PRIMARY KEY,
            environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            input_json TEXT NOT NULL,
            enforcement TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CHECK ((kind = 'unix_socket' AND relative_path = '') OR
                   (kind != 'unix_socket' AND relative_path != ''))
        );
        CREATE INDEX surfaces_environment_idx ON surfaces(environment_id, position);

        CREATE TABLE replication_outbox (
            intent_id TEXT PRIMARY KEY,
            logical_id TEXT NOT NULL,
            parents_json TEXT NOT NULL,
            store_versions_json TEXT NOT NULL,
            catalog_payload BLOB NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX replication_outbox_created_idx
            ON replication_outbox(created_at, intent_id);
        PRAGMA user_version = 14;",
    )?;
    tx.commit()?;
    Ok(())
}
