use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use accessfs_core::authz::Enforcement;
use rusqlite::{params, Connection, OptionalExtension};

use crate::domain::{
    Binding, BindingScope, CatalogSnapshot, EntrySelection, Environment, Project, ProjectCheckout,
    ProjectCheckoutKind, ResolvedEnvironment, ResolvedExport, Resource, ResourceBindingUsage,
    ResourceCodec, ResourceKind, ResourceSource, ResourceUsage, Surface, SurfaceInput, SurfaceKind,
    ValueShape,
};
use crate::error::{CatalogError, CatalogResult};

const SCHEMA_VERSION: i64 = 8;

#[derive(Debug, Clone)]
pub struct Catalog {
    path: PathBuf,
}

impl Catalog {
    /// Open or create a private SQLite metadata catalog.
    pub fn open(path: impl Into<PathBuf>) -> CatalogResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| CatalogError::io(parent, e))?;
            }
        }

        if !path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| CatalogError::io(&path, e))?;
        } else {
            let mode = std::fs::metadata(&path)
                .map_err(|e| CatalogError::io(&path, e))?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                return Err(CatalogError::Validation(format!(
                    "{} must not be accessible by group or others (mode {mode:04o})",
                    path.display()
                )));
            }
        }

        let catalog = Catalog { path };
        let mut conn = catalog.connection()?;
        migrate(&mut conn)?;
        Ok(catalog)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schema_version(&self) -> i64 {
        SCHEMA_VERSION
    }

    pub fn snapshot(&self) -> CatalogResult<CatalogSnapshot> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let snapshot = snapshot_from(&tx)?;
        tx.commit()?;
        Ok(snapshot)
    }

    pub fn upsert_project(&self, project: &Project) -> CatalogResult<()> {
        validate_project(project)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO projects (id, name) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                 updated_at = CURRENT_TIMESTAMP",
            params![project.id, project.name],
        )?;
        tx.execute(
            "INSERT INTO project_checkouts
                (id, project_id, path, environment_id, kind, git_common_dir)
             VALUES (?1, ?1, ?2, NULL, 'primary', NULL)
             ON CONFLICT(id) DO UPDATE SET path = excluded.path,
                 updated_at = CURRENT_TIMESTAMP",
            params![project.id, path_string(&project.path)],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_project(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "project id")?;
        remove_one(&self.connection()?, "projects", id, "project")
    }

    pub fn upsert_checkout(&self, checkout: &ProjectCheckout) -> CatalogResult<()> {
        validate_checkout(checkout)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        require_exists(&tx, "projects", &checkout.project_id, "project")?;
        if let Some(environment_id) = &checkout.environment_id {
            let owner = tx
                .query_row(
                    "SELECT project_id FROM environments WHERE id = ?1",
                    [environment_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            match owner {
                Some(owner) if owner == checkout.project_id => {}
                Some(_) => {
                    return Err(CatalogError::Validation(format!(
                        "environment {environment_id:?} does not belong to project {:?}",
                        checkout.project_id
                    )))
                }
                None => {
                    return Err(CatalogError::NotFound(format!(
                        "environment {environment_id}"
                    )))
                }
            }
        }
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT project_id, kind FROM project_checkouts WHERE id = ?1",
                [&checkout.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if existing
            .as_ref()
            .is_some_and(|(project_id, kind)| {
                project_id != &checkout.project_id || kind != checkout.kind.as_str()
            })
        {
            return Err(CatalogError::Validation(format!(
                "checkout {:?} cannot move between projects or change kind",
                checkout.id
            )));
        }
        tx.execute(
            "INSERT INTO project_checkouts
                (id, project_id, path, environment_id, kind, git_common_dir)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET path = excluded.path,
                 environment_id = excluded.environment_id,
                 git_common_dir = excluded.git_common_dir,
                 updated_at = CURRENT_TIMESTAMP",
            params![
                checkout.id,
                checkout.project_id,
                path_string(&checkout.path),
                checkout.environment_id,
                checkout.kind.as_str(),
                checkout.git_common_dir.as_deref().map(path_string),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_checkout(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "checkout id")?;
        let conn = self.connection()?;
        let kind = conn
            .query_row(
                "SELECT kind FROM project_checkouts WHERE id = ?1",
                [id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| CatalogError::NotFound(format!("checkout {id}")))?;
        if kind == ProjectCheckoutKind::Primary.as_str() {
            return Err(CatalogError::Validation(
                "primary checkout is owned by its project and cannot be removed separately"
                    .to_string(),
            ));
        }
        remove_one(&conn, "project_checkouts", id, "checkout")
    }

    pub fn upsert_environment(&self, environment: &Environment) -> CatalogResult<()> {
        validate_environment(environment)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        require_exists(&tx, "projects", &environment.project_id, "project")?;
        let existing_owner: Option<String> = tx
            .query_row(
                "SELECT project_id FROM environments WHERE id = ?1",
                [&environment.id],
                |row| row.get(0),
            )
            .optional()?;
        if existing_owner.as_deref().is_some_and(|owner| owner != environment.project_id) {
            return Err(CatalogError::Validation(format!(
                "environment {:?} cannot move between projects",
                environment.id
            )));
        }
        tx.execute(
            "INSERT INTO environments (id, project_id, name, position) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                 name = excluded.name, position = excluded.position,
                 updated_at = CURRENT_TIMESTAMP",
            params![
                environment.id,
                environment.project_id,
                environment.name,
                environment.position
            ],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_environment(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "environment id")?;
        remove_one(&self.connection()?, "environments", id, "environment")
    }

    pub fn upsert_resource(&self, resource: &Resource) -> CatalogResult<()> {
        validate_resource(resource)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO resources
                (id, name, kind, shape, codec, default_env_key, entries_json, source_json, enforcement, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
                 shape = excluded.shape, codec = excluded.codec,
                 default_env_key = excluded.default_env_key,
                 entries_json = excluded.entries_json,
                 source_json = excluded.source_json, enforcement = excluded.enforcement,
                 metadata_json = excluded.metadata_json,
                 updated_at = CURRENT_TIMESTAMP",
            params![
                resource.id,
                resource.name,
                resource.kind.as_str(),
                resource.shape.as_str(),
                resource.codec.as_str(),
                resource.default_env_key,
                serde_json::to_string(&resource.entries)?,
                serde_json::to_string(&resource.source)?,
                resource.enforcement.as_str(),
                serde_json::to_string(&resource.metadata)?,
            ],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn validate_resource(&self, resource: &Resource) -> CatalogResult<()> {
        validate_resource(resource)
    }

    pub fn create_resource(&self, resource: &Resource) -> CatalogResult<()> {
        validate_resource(resource)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let exists = tx
            .query_row("SELECT 1 FROM resources WHERE id = ?1", [&resource.id], |_| Ok(()))
            .optional()?
            .is_some();
        if exists {
            return Err(CatalogError::AlreadyExists {
                kind: "resource",
                id: resource.id.clone(),
            });
        }
        tx.execute(
            "INSERT INTO resources
                (id, name, kind, shape, codec, default_env_key, entries_json, source_json, enforcement, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                resource.id,
                resource.name,
                resource.kind.as_str(),
                resource.shape.as_str(),
                resource.codec.as_str(),
                resource.default_env_key,
                serde_json::to_string(&resource.entries)?,
                serde_json::to_string(&resource.source)?,
                resource.enforcement.as_str(),
                serde_json::to_string(&resource.metadata)?,
            ],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_resource(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "resource id")?;
        let usage = self.resource_usage(id)?;
        let binding_ids = usage
            .bindings
            .iter()
            .map(|binding| binding.binding_id.clone())
            .collect::<Vec<_>>();
        if !binding_ids.is_empty() || !usage.direct_surface_ids.is_empty() {
            return Err(CatalogError::ResourceInUse {
                resource_id: id.to_string(),
                binding_ids,
                surface_ids: usage.direct_surface_ids,
            });
        }
        remove_one(&self.connection()?, "resources", id, "resource")
    }

    pub fn resource(&self, id: &str) -> CatalogResult<Resource> {
        require_id(id, "resource id")?;
        self.snapshot()?
            .resources
            .into_iter()
            .find(|resource| resource.id == id)
            .ok_or_else(|| CatalogError::NotFound(format!("resource {id}")))
    }

    pub fn resource_usage(&self, id: &str) -> CatalogResult<ResourceUsage> {
        require_id(id, "resource id")?;
        let snapshot = self.snapshot()?;
        if !snapshot.resources.iter().any(|resource| resource.id == id) {
            return Err(CatalogError::NotFound(format!("resource {id}")));
        }
        let mut bindings = Vec::new();
        for binding in snapshot.bindings.iter().filter(|binding| binding.resource_id == id) {
            let environment_ids = match &binding.scope {
                BindingScope::Common => snapshot
                    .environments
                    .iter()
                    .filter(|environment| environment.project_id == binding.project_id)
                    .map(|environment| environment.id.clone())
                    .collect::<Vec<_>>(),
                BindingScope::Environment { environment_id } => vec![environment_id.clone()],
            };
            let surface_ids = snapshot
                .surfaces
                .iter()
                .filter(|surface| {
                    environment_ids.contains(&surface.environment_id)
                        && surface
                            .input
                            .binding_ids()
                            .is_some_and(|binding_ids| binding_ids.contains(&binding.id))
                })
                .map(|surface| surface.id.clone())
                .collect();
            bindings.push(ResourceBindingUsage {
                binding_id: binding.id.clone(),
                project_id: binding.project_id.clone(),
                scope: binding.scope.clone(),
                environment_ids,
                surface_ids,
            });
        }
        let direct_surface_ids = snapshot
            .surfaces
            .iter()
            .filter(|surface| {
                matches!(
                    &surface.input,
                    SurfaceInput::Resource { resource_id } if resource_id == id
                )
            })
            .map(|surface| surface.id.clone())
            .collect();
        Ok(ResourceUsage { resource_id: id.to_string(), bindings, direct_surface_ids })
    }

    pub fn upsert_binding(&self, binding: &Binding) -> CatalogResult<()> {
        validate_binding(binding)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        require_exists(&tx, "projects", &binding.project_id, "project")?;
        require_exists(&tx, "resources", &binding.resource_id, "resource")?;

        let environment_id = match &binding.scope {
            BindingScope::Common => None,
            BindingScope::Environment { environment_id } => {
                let owner: Option<String> = tx
                    .query_row(
                        "SELECT project_id FROM environments WHERE id = ?1",
                        [environment_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                match owner {
                    Some(owner) if owner == binding.project_id => Some(environment_id.as_str()),
                    Some(_) => {
                        return Err(CatalogError::Validation(format!(
                            "environment {environment_id:?} does not belong to project {:?}",
                            binding.project_id
                        )))
                    }
                    None => {
                        return Err(CatalogError::NotFound(format!(
                            "environment {environment_id}"
                        )))
                    }
                }
            }
        };

        if binding.key_override.is_some() {
            let shape: String = tx.query_row(
                "SELECT shape FROM resources WHERE id = ?1",
                [&binding.resource_id],
                |row| row.get(0),
            )?;
            if shape != ValueShape::Scalar.as_str() {
                return Err(CatalogError::Validation(
                    "key_override is only valid for scalar resources".to_string(),
                ));
            }
        }

        tx.execute(
            "INSERT INTO bindings
                (id, project_id, environment_id, resource_id, key_override, enabled,
                 allow_override, position, selection_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                 environment_id = excluded.environment_id, resource_id = excluded.resource_id,
                 key_override = excluded.key_override, enabled = excluded.enabled,
                 allow_override = excluded.allow_override, position = excluded.position,
                 selection_json = excluded.selection_json,
                 updated_at = CURRENT_TIMESTAMP",
            params![
                binding.id,
                binding.project_id,
                environment_id,
                binding.resource_id,
                binding.key_override,
                binding.enabled,
                binding.allow_override,
                binding.position,
                serde_json::to_string(&binding.selection)?,
            ],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_binding(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "binding id")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let snapshot = snapshot_from(&tx)?;
        if !snapshot.bindings.iter().any(|binding| binding.id == id) {
            return Err(CatalogError::NotFound(format!("binding {id}")));
        }
        for surface in &snapshot.surfaces {
            let Some(binding_ids) = surface.input.binding_ids() else { continue };
            if !binding_ids.iter().any(|binding_id| binding_id == id) {
                continue;
            }
            let retained = binding_ids
                .iter()
                .filter(|binding_id| binding_id.as_str() != id)
                .cloned()
                .collect();
            let input = match &surface.input {
                SurfaceInput::Bindings { .. } => {
                    SurfaceInput::Bindings { binding_ids: retained }
                }
                SurfaceInput::SshAgent { route, .. } => SurfaceInput::SshAgent {
                    binding_ids: retained,
                    route: route.clone(),
                },
                SurfaceInput::Resource { .. } => unreachable!("binding input checked above"),
            };
            tx.execute(
                "UPDATE surfaces SET input_json = ?2, updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
                params![surface.id, serde_json::to_string(&input)?],
            )?;
        }
        tx.execute("DELETE FROM bindings WHERE id = ?1", [id])?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn upsert_surface(&self, surface: &Surface) -> CatalogResult<()> {
        validate_surface(surface)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        require_exists(&tx, "environments", &surface.environment_id, "environment")?;
        let project_path = PathBuf::from(tx.query_row(
            "SELECT project_checkouts.path
             FROM environments
             JOIN project_checkouts
               ON project_checkouts.project_id = environments.project_id
              AND project_checkouts.kind = 'primary'
             WHERE environments.id = ?1",
            [&surface.environment_id],
            |row| row.get::<_, String>(0),
        )?);
        let relative_path = surface_relative_path(&surface.path, &project_path)?;
        tx.execute(
            "INSERT INTO surfaces
                (id, environment_id, name, kind, relative_path, input_json, enforcement, position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET environment_id = excluded.environment_id,
                 name = excluded.name, kind = excluded.kind,
                 relative_path = excluded.relative_path,
                 input_json = excluded.input_json, enforcement = excluded.enforcement,
                 position = excluded.position,
                 updated_at = CURRENT_TIMESTAMP",
            params![
                surface.id,
                surface.environment_id,
                surface.name,
                surface.kind.as_str(),
                path_string(relative_path),
                serde_json::to_string(&surface.input)?,
                surface.enforcement.as_str(),
                surface.position,
            ],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_surface(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "surface id")?;
        remove_one(&self.connection()?, "surfaces", id, "surface")
    }

    /// Resolve enabled common and environment bindings to export metadata with provenance.
    /// No secret value is decrypted or returned.
    pub fn resolve_environment(
        &self,
        project_id: &str,
        environment_id: &str,
    ) -> CatalogResult<ResolvedEnvironment> {
        resolve_catalog_snapshot(&self.snapshot()?, project_id, environment_id)
    }

    fn connection(&self) -> CatalogResult<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(2))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(conn)
    }
}

fn migrate(conn: &mut Connection) -> CatalogResult<()> {
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
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX surfaces_environment_idx ON surfaces(environment_id, position);
        PRAGMA user_version = 8;",
    )?;
    tx.commit()?;
    Ok(())
}

fn snapshot_from(conn: &Connection) -> CatalogResult<CatalogSnapshot> {
    let projects = {
        let mut stmt = conn.prepare(
            "SELECT projects.id, projects.name, project_checkouts.path
             FROM projects
             JOIN project_checkouts
               ON project_checkouts.project_id = projects.id
              AND project_checkouts.kind = 'primary'
             ORDER BY projects.name, projects.id",
        )?;
        let values = stmt.query_map([], |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                path: PathBuf::from(row.get::<_, String>(2)?),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let checkouts = {
        let mut stmt = conn.prepare(
            "SELECT id, project_id, path, environment_id, kind, git_common_dir
             FROM project_checkouts
             ORDER BY project_id, kind = 'primary' DESC, path, id",
        )?;
        let values = stmt
            .query_map([], |row| {
                let kind: String = row.get(4)?;
                Ok(ProjectCheckout {
                    id: row.get(0)?,
                    project_id: row.get(1)?,
                    path: PathBuf::from(row.get::<_, String>(2)?),
                    environment_id: row.get(3)?,
                    kind: ProjectCheckoutKind::parse(&kind)
                        .ok_or_else(|| invalid_value(4, kind))?,
                    git_common_dir: row.get::<_, Option<String>>(5)?.map(PathBuf::from),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let environments = {
        let mut stmt = conn.prepare(
            "SELECT id, project_id, name, position
             FROM environments ORDER BY project_id, position, name, id",
        )?;
        let values = stmt.query_map([], |row| {
            Ok(Environment {
                id: row.get(0)?,
                project_id: row.get(1)?,
                name: row.get(2)?,
                position: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let resources = {
        let mut stmt = conn.prepare(
            "SELECT id, name, kind, shape, codec, default_env_key, entries_json, source_json, enforcement, metadata_json
             FROM resources ORDER BY name, id",
        )?;
        let values = stmt.query_map([], |row| {
            let kind: String = row.get(2)?;
            let shape: String = row.get(3)?;
            let codec: String = row.get(4)?;
            let enforcement: String = row.get(8)?;
            Ok(Resource {
                id: row.get(0)?,
                name: row.get(1)?,
                kind: ResourceKind::parse(&kind).ok_or_else(|| invalid_value(2, kind))?,
                shape: ValueShape::parse(&shape).ok_or_else(|| invalid_value(3, shape))?,
                codec: ResourceCodec::parse(&codec).ok_or_else(|| invalid_value(4, codec))?,
                default_env_key: row.get(5)?,
                entries: decode_json(6, &row.get::<_, String>(6)?)?,
                source: decode_json(7, &row.get::<_, String>(7)?)?,
                enforcement: Enforcement::parse(&enforcement)
                    .ok_or_else(|| invalid_value(8, enforcement))?,
                metadata: decode_json(9, &row.get::<_, String>(9)?)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let bindings = {
        let mut stmt = conn.prepare(
            "SELECT id, project_id, environment_id, resource_id, key_override,
                    enabled, allow_override, position, selection_json
             FROM bindings
             ORDER BY project_id, environment_id IS NOT NULL, environment_id, position, id",
        )?;
        let values = stmt.query_map([], |row| {
            let environment_id: Option<String> = row.get(2)?;
            Ok(Binding {
                id: row.get(0)?,
                project_id: row.get(1)?,
                scope: match environment_id {
                    Some(environment_id) => BindingScope::Environment { environment_id },
                    None => BindingScope::Common,
                },
                resource_id: row.get(3)?,
                key_override: row.get(4)?,
                enabled: row.get(5)?,
                allow_override: row.get(6)?,
                position: row.get(7)?,
                selection: decode_json(8, &row.get::<_, String>(8)?)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let surfaces = {
        let mut stmt = conn.prepare(
            "SELECT surfaces.id, surfaces.environment_id, surfaces.name, surfaces.kind,
                    project_checkouts.path, surfaces.relative_path, surfaces.input_json,
                    surfaces.enforcement, surfaces.position
             FROM surfaces
             JOIN environments ON environments.id = surfaces.environment_id
             JOIN project_checkouts
               ON project_checkouts.project_id = environments.project_id
              AND project_checkouts.kind = 'primary'
             ORDER BY surfaces.environment_id, surfaces.position, surfaces.name, surfaces.id",
        )?;
        let values = stmt.query_map([], |row| {
            let kind: String = row.get(3)?;
            let enforcement: String = row.get(7)?;
            let primary_path = PathBuf::from(row.get::<_, String>(4)?);
            let relative_path = PathBuf::from(row.get::<_, String>(5)?);
            Ok(Surface {
                id: row.get(0)?,
                environment_id: row.get(1)?,
                name: row.get(2)?,
                kind: SurfaceKind::parse(&kind).ok_or_else(|| invalid_value(3, kind))?,
                path: primary_path.join(relative_path),
                input: decode_json(6, &row.get::<_, String>(6)?)?,
                enforcement: Enforcement::parse(&enforcement)
                    .ok_or_else(|| invalid_value(7, enforcement))?,
                position: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    Ok(CatalogSnapshot { projects, checkouts, environments, resources, bindings, surfaces })
}

pub fn resolve_catalog_snapshot(
    snapshot: &CatalogSnapshot,
    project_id: &str,
    environment_id: &str,
) -> CatalogResult<ResolvedEnvironment> {
    if !snapshot.projects.iter().any(|project| project.id == project_id) {
        return Err(CatalogError::NotFound(format!("project {project_id}")));
    }
    let environment = snapshot
        .environments
        .iter()
        .find(|environment| environment.id == environment_id)
        .ok_or_else(|| CatalogError::NotFound(format!("environment {environment_id}")))?;
    if environment.project_id != project_id {
        return Err(CatalogError::Validation(format!(
            "environment {environment_id:?} does not belong to project {project_id:?}"
        )));
    }

    Ok(ResolvedEnvironment {
        project_id: project_id.to_string(),
        environment_id: environment_id.to_string(),
        exports: resolve_exports(snapshot, project_id, Some(environment_id), None)?,
    })
}

pub fn resolve_catalog_surface(
    snapshot: &CatalogSnapshot,
    surface_id: &str,
) -> CatalogResult<Vec<ResolvedExport>> {
    let surface = snapshot
        .surfaces
        .iter()
        .find(|surface| surface.id == surface_id)
        .ok_or_else(|| CatalogError::NotFound(format!("surface {surface_id}")))?;
    if !matches!(surface.kind, SurfaceKind::DotenvFile | SurfaceKind::DirenvFile) {
        return Err(CatalogError::Validation(format!(
            "surface {surface_id:?} is not a keyed environment projection"
        )));
    }
    let environment = snapshot
        .environments
        .iter()
        .find(|environment| environment.id == surface.environment_id)
        .ok_or_else(|| CatalogError::NotFound(format!("environment {}", surface.environment_id)))?;
    let SurfaceInput::Bindings { binding_ids } = &surface.input else {
        return Err(CatalogError::Validation(format!(
            "dotenv surface {surface_id:?} requires binding input"
        )));
    };
    let included = binding_ids.iter().map(String::as_str).collect::<HashSet<_>>();
    resolve_exports(
        snapshot,
        &environment.project_id,
        Some(&environment.id),
        Some(&included),
    )
}

fn resolve_exports(
    snapshot: &CatalogSnapshot,
    project_id: &str,
    environment_id: Option<&str>,
    included: Option<&HashSet<&str>>,
) -> CatalogResult<Vec<ResolvedExport>> {
    let resources: HashMap<&str, &Resource> = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    let mut bindings: Vec<&Binding> = snapshot
        .bindings
        .iter()
        .filter(|binding| {
            binding.enabled
                && included.is_none_or(|ids| ids.contains(binding.id.as_str()))
                && binding.project_id == project_id
                && match &binding.scope {
                    BindingScope::Common => true,
                    BindingScope::Environment { environment_id: binding_environment } => {
                        environment_id.is_some_and(|id| binding_environment == id)
                    }
                }
        })
        .collect();
    bindings.sort_by_key(|binding| {
        let scope_order = match binding.scope {
            BindingScope::Common => 0,
            BindingScope::Environment { .. } => 1,
        };
        (scope_order, binding.position, binding.id.as_str())
    });

    let mut exports: Vec<ResolvedExport> = Vec::new();
    let mut by_key: HashMap<String, (usize, bool)> = HashMap::new();
    for binding in bindings {
        let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("resource {}", binding.resource_id))
        })?;
        for entry in resource.entries.iter().filter(|entry| {
            match &binding.selection {
                EntrySelection::All => true,
                EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
            }
        }) {
            let key = if resource.shape == ValueShape::Scalar {
                binding.key_override.as_ref().or(entry.key.as_ref())
            } else {
                entry.key.as_ref()
            };
            let Some(key) = key.cloned() else { continue };
            let current_is_environment = matches!(binding.scope, BindingScope::Environment { .. });
            let resolved = ResolvedExport {
                key: key.clone(),
                source_key: entry.address.clone(),
                binding_id: binding.id.clone(),
                resource_id: resource.id.clone(),
                resource_name: resource.name.clone(),
                sensitive: entry.sensitive,
                overrides_binding_id: None,
            };

            if let Some((existing_index, existing_is_environment)) = by_key.get(&key).copied() {
                if current_is_environment && !existing_is_environment && binding.allow_override {
                    let mut resolved = resolved;
                    resolved.overrides_binding_id = Some(exports[existing_index].binding_id.clone());
                    exports[existing_index] = resolved;
                    by_key.insert(key, (existing_index, true));
                    continue;
                }
                return Err(CatalogError::Conflict {
                    key,
                    binding_ids: vec![
                        exports[existing_index].binding_id.clone(),
                        binding.id.clone(),
                    ],
                });
            }

            let resolved_index = exports.len();
            exports.push(resolved);
            by_key.insert(key, (resolved_index, current_is_environment));
        }
    }

    Ok(exports)
}

fn validate_snapshot_conflicts(snapshot: &CatalogSnapshot) -> CatalogResult<()> {
    validate_binding_selections(snapshot)?;
    validate_surface_inputs(snapshot)?;
    validate_ssh_route_conflicts(snapshot)?;
    for surface in &snapshot.surfaces {
        match surface.kind {
            SurfaceKind::DotenvFile | SurfaceKind::DirenvFile => {
                resolve_catalog_surface(snapshot, &surface.id)?;
            }
            SurfaceKind::IniFile => validate_ini_surface_conflicts(snapshot, surface)?,
            SurfaceKind::UnixSocket => validate_ssh_agent_surface_conflicts(snapshot, surface)?,
            _ => {}
        }
    }
    Ok(())
}

fn validate_binding_selections(snapshot: &CatalogSnapshot) -> CatalogResult<()> {
    let resources: HashMap<&str, &Resource> = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    for binding in &snapshot.bindings {
        let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("resource {}", binding.resource_id))
        })?;
        let selected = match &binding.selection {
            EntrySelection::All => continue,
            EntrySelection::Entries { addresses } => addresses
                .iter()
                .all(|address| resource.entries.iter().any(|entry| entry.address == *address)),
        };
        if !selected {
            return Err(CatalogError::Validation(format!(
                "binding {:?} selects entries not exposed by resource {:?}",
                binding.id, resource.id
            )));
        }
        if resource.entries.is_empty() {
            return Err(CatalogError::Validation(format!(
                "binding {:?} cannot select entries from flat resource {:?}",
                binding.id, resource.id
            )));
        }
    }
    Ok(())
}

fn validate_surface_inputs(snapshot: &CatalogSnapshot) -> CatalogResult<()> {
    let resources: HashMap<&str, &Resource> = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    let bindings: HashMap<&str, &Binding> = snapshot
        .bindings
        .iter()
        .map(|binding| (binding.id.as_str(), binding))
        .collect();
    let environments: HashMap<&str, &Environment> = snapshot
        .environments
        .iter()
        .map(|environment| (environment.id.as_str(), environment))
        .collect();
    for surface in &snapshot.surfaces {
        let environment = environments.get(surface.environment_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("environment {}", surface.environment_id))
        })?;
        match (&surface.kind, &surface.input) {
            (
                SurfaceKind::DotenvFile
                    | SurfaceKind::DirenvFile
                    | SurfaceKind::IniFile
                    | SurfaceKind::LinesFile,
                SurfaceInput::Bindings { binding_ids },
            )
            | (
                SurfaceKind::UnixSocket,
                SurfaceInput::Bindings { binding_ids }
                | SurfaceInput::SshAgent { binding_ids, .. },
            ) => {
                let mut unique = HashSet::new();
                for binding_id in binding_ids {
                    if !unique.insert(binding_id) {
                        return Err(CatalogError::Validation(format!(
                            "surface {:?} includes duplicate binding {:?}",
                            surface.id, binding_id
                        )));
                    }
                    let binding = bindings.get(binding_id.as_str()).ok_or_else(|| {
                        CatalogError::NotFound(format!("binding {binding_id}"))
                    })?;
                    let applies = binding.project_id == environment.project_id
                        && match &binding.scope {
                            BindingScope::Common => true,
                            BindingScope::Environment { environment_id } => {
                                environment_id == &surface.environment_id
                            }
                        };
                    if !applies {
                        return Err(CatalogError::Validation(format!(
                            "binding {binding_id:?} does not apply to surface {:?}",
                            surface.id
                        )));
                    }
                    let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
                        CatalogError::NotFound(format!("resource {}", binding.resource_id))
                    })?;
                    validate_composed_surface_member(surface, binding, resource)?;
                }
            }
            (SurfaceKind::EnvFileDirect, SurfaceInput::Resource { resource_id }) => {
                let resource = resources.get(resource_id.as_str()).ok_or_else(|| {
                    CatalogError::NotFound(format!("resource {resource_id}"))
                })?;
                if resource.kind != ResourceKind::EnvFile
                    || resource.shape != ValueShape::KeyValueSet
                    || resource.codec != ResourceCodec::Dotenv
                    || !matches!(resource.source, ResourceSource::SecretRef { .. })
                {
                    return Err(CatalogError::Validation(format!(
                        "env_file_direct surface {:?} requires an env_file resource",
                        surface.id
                    )));
                }
            }
            (SurfaceKind::RegularFile, SurfaceInput::Resource { resource_id }) => {
                if !resources.contains_key(resource_id.as_str()) {
                    return Err(CatalogError::NotFound(format!("resource {resource_id}")));
                }
            }
            _ => {
                return Err(CatalogError::Validation(format!(
                    "surface kind {} is incompatible with its input",
                    surface.kind.as_str()
                )))
            }
        }
    }
    Ok(())
}

fn validate_composed_surface_member(
    surface: &Surface,
    binding: &Binding,
    resource: &Resource,
) -> CatalogResult<()> {
    let entries = resource.entries.iter().filter(|entry| match &binding.selection {
        EntrySelection::All => true,
        EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
    });
    match surface.kind {
        SurfaceKind::DotenvFile | SurfaceKind::DirenvFile => {
            let compatible_source = matches!(
                (&resource.shape, &resource.codec, &resource.source),
                (
                    ValueShape::Scalar,
                    ResourceCodec::Opaque,
                    ResourceSource::SecretRef { .. } | ResourceSource::Literal { .. }
                ) | (
                    ValueShape::KeyValueSet,
                    ResourceCodec::Dotenv | ResourceCodec::Ini,
                    ResourceSource::SecretRef { .. }
                )
            );
            if !compatible_source
                || entries.into_iter().any(|entry| {
                    resource.shape != ValueShape::Scalar && entry.key.is_none()
                        || resource.shape == ValueShape::Scalar
                            && binding.key_override.as_ref().or(entry.key.as_ref()).is_none()
                        || binding
                            .key_override
                            .as_ref()
                            .or(entry.key.as_ref())
                            .is_some_and(|key| require_env_key(key).is_err())
                })
            {
                return Err(CatalogError::Validation(format!(
                    "binding {:?} cannot feed {} surface {:?}",
                    binding.id,
                    if surface.kind == SurfaceKind::DotenvFile {
                        "dotenv"
                    } else {
                        "direnv"
                    },
                    surface.id
                )));
            }
        }
        SurfaceKind::IniFile => {
            let compatible = resource.kind == ResourceKind::EnvFile
                && resource.shape == ValueShape::KeyValueSet
                && resource.codec == ResourceCodec::Ini
                && binding.key_override.is_none()
                && entries.into_iter().all(|entry| entry.key.is_some())
                && matches!(resource.source, ResourceSource::SecretRef { .. });
            if !compatible {
                return Err(CatalogError::Validation(format!(
                    "binding {:?} cannot feed INI surface {:?}",
                    binding.id, surface.id
                )));
            }
        }
        SurfaceKind::LinesFile => {
            let compatible = resource.shape == ValueShape::Scalar
                && resource.codec == ResourceCodec::Opaque
                && binding.key_override.is_none()
                && entries.into_iter().all(|entry| entry.key.is_none())
                && matches!(
                    resource.source,
                    ResourceSource::SecretRef { .. } | ResourceSource::Literal { .. }
                );
            if !compatible {
                return Err(CatalogError::Validation(format!(
                    "binding {:?} cannot feed lines surface {:?}",
                    binding.id, surface.id
                )));
            }
        }
        SurfaceKind::UnixSocket => {
            let compatible = matches!(
                (&resource.kind, &resource.shape, &resource.source),
                (
                    ResourceKind::SshIdentity,
                    ValueShape::SshIdentity,
                    ResourceSource::SecretRef { .. }
                ) | (
                    ResourceKind::SshAgent,
                    ValueShape::Socket,
                    ResourceSource::Socket { .. }
                )
            )
                && resource.codec == ResourceCodec::Opaque
                && binding.key_override.is_none()
                && entries.into_iter().all(|entry| entry.key.is_none());
            if !compatible {
                return Err(CatalogError::Validation(format!(
                    "binding {:?} cannot feed SSH agent surface {:?}",
                    binding.id, surface.id
                )));
            }
        }
        _ => unreachable!("only composed surfaces call member validation"),
    }
    Ok(())
}

fn validate_ssh_agent_surface_conflicts(
    snapshot: &CatalogSnapshot,
    surface: &Surface,
) -> CatalogResult<()> {
    let Some(binding_ids) = surface.input.binding_ids() else {
        return Err(CatalogError::Validation(format!(
            "SSH agent surface {:?} requires binding input",
            surface.id
        )));
    };
    let bindings: HashMap<&str, &Binding> = snapshot
        .bindings
        .iter()
        .map(|binding| (binding.id.as_str(), binding))
        .collect();
    let resources: HashMap<&str, &Resource> = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect();
    let mut addresses: HashMap<&str, &str> = HashMap::new();

    for binding_id in binding_ids {
        let binding = bindings
            .get(binding_id.as_str())
            .ok_or_else(|| CatalogError::NotFound(format!("binding {binding_id}")))?;
        let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("resource {}", binding.resource_id))
        })?;
        for entry in resource.entries.iter().filter(|entry| match &binding.selection {
            EntrySelection::All => true,
            EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
        }) {
            if let Some(existing) = addresses.insert(&entry.address, binding.id.as_str()) {
                return Err(CatalogError::Conflict {
                    key: entry.address.clone(),
                    binding_ids: vec![existing.to_string(), binding.id.clone()],
                });
            }
        }
    }
    Ok(())
}

fn validate_ini_surface_conflicts(
    snapshot: &CatalogSnapshot,
    surface: &Surface,
) -> CatalogResult<()> {
    let SurfaceInput::Bindings { binding_ids } = &surface.input else {
        return Err(CatalogError::Validation(format!(
            "INI surface {:?} requires binding input",
            surface.id
        )));
    };
    let resources = snapshot
        .resources
        .iter()
        .map(|resource| (resource.id.as_str(), resource))
        .collect::<HashMap<_, _>>();
    let bindings = snapshot
        .bindings
        .iter()
        .map(|binding| (binding.id.as_str(), binding))
        .collect::<HashMap<_, _>>();
    let mut addresses: HashMap<&str, &str> = HashMap::new();
    for binding_id in binding_ids {
        let binding = bindings
            .get(binding_id.as_str())
            .ok_or_else(|| CatalogError::NotFound(format!("binding {binding_id}")))?;
        if !binding.enabled {
            continue;
        }
        let resource = resources.get(binding.resource_id.as_str()).ok_or_else(|| {
            CatalogError::NotFound(format!("resource {}", binding.resource_id))
        })?;
        for entry in resource.entries.iter().filter(|entry| match &binding.selection {
            EntrySelection::All => true,
            EntrySelection::Entries { addresses } => addresses.contains(&entry.address),
        }) {
            if let Some(existing_binding) = addresses.insert(&entry.address, &binding.id) {
                return Err(CatalogError::Conflict {
                    key: entry.address.clone(),
                    binding_ids: vec![existing_binding.to_string(), binding.id.clone()],
                });
            }
        }
    }
    Ok(())
}

fn validate_project(project: &Project) -> CatalogResult<()> {
    require_id(&project.id, "project id")?;
    require_name(&project.name, "project name")?;
    require_normalized_absolute_path(&project.path, "project path")
}

fn validate_checkout(checkout: &ProjectCheckout) -> CatalogResult<()> {
    require_id(&checkout.id, "checkout id")?;
    require_id(&checkout.project_id, "checkout project id")?;
    require_normalized_absolute_path(&checkout.path, "checkout path")?;
    if let Some(git_common_dir) = &checkout.git_common_dir {
        require_normalized_absolute_path(git_common_dir, "checkout git common directory")?;
    }
    match checkout.kind {
        ProjectCheckoutKind::Primary => {
            if checkout.id != checkout.project_id {
                return Err(CatalogError::Validation(
                    "primary checkout id must match its project id".to_string(),
                ));
            }
            if checkout.environment_id.is_some() {
                return Err(CatalogError::Validation(
                    "primary checkout cannot select one environment".to_string(),
                ));
            }
        }
        ProjectCheckoutKind::Worktree => {
            if checkout.environment_id.is_none() {
                return Err(CatalogError::Validation(
                    "worktree checkout must select an environment".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_environment(environment: &Environment) -> CatalogResult<()> {
    require_id(&environment.id, "environment id")?;
    require_id(&environment.project_id, "environment project id")?;
    require_name(&environment.name, "environment name")
}

fn validate_resource(resource: &Resource) -> CatalogResult<()> {
    require_id(&resource.id, "resource id")?;
    require_name(&resource.name, "resource name")?;
    resource.metadata.validate().map_err(CatalogError::Validation)?;
    if let Some(key) = &resource.default_env_key {
        require_env_key(key)?;
    }
    let mut addresses = HashSet::new();
    for entry in &resource.entries {
        require_entry_address(&entry.address)?;
        require_name(&entry.label, "resource entry label")?;
        if let Some(key) = &entry.key {
            if resource.codec == ResourceCodec::Ini {
                require_name(key, "INI entry key")?;
            } else {
                require_env_key(key)?;
            }
        }
        if !addresses.insert(&entry.address) {
            return Err(CatalogError::Validation(format!(
                "resource {:?} exposes duplicate entry address {:?}",
                resource.id, entry.address
            )));
        }
    }

    match resource.shape {
        ValueShape::Scalar if resource.entries.len() != 1 => {
            return Err(CatalogError::Validation(
                "scalar resources require exactly one entry".to_string(),
            ))
        }
        ValueShape::KeyValueSet
            if resource.entries.is_empty()
                || resource.entries.iter().any(|entry| entry.key.is_none()) =>
        {
            return Err(CatalogError::Validation(
                "key_value_set resources require at least one keyed entry".to_string(),
            ))
        }
        ValueShape::Bytes if !resource.entries.is_empty() => {
            return Err(CatalogError::Validation(
                "bytes resources cannot declare entries".to_string(),
            ))
        }
        ValueShape::Socket if resource.entries.iter().any(|entry| entry.key.is_some()) => {
            return Err(CatalogError::Validation(
                "socket capability entries cannot declare environment keys".to_string(),
            ))
        }
        _ => {}
    }

    match (resource.shape, resource.codec) {
        (
            ValueShape::Scalar
                | ValueShape::Bytes
                | ValueShape::SshIdentity
                | ValueShape::Socket,
            ResourceCodec::Opaque,
        )
        | (
            ValueShape::KeyValueSet,
            ResourceCodec::Dotenv | ResourceCodec::Ini,
        ) => {}
        _ => {
            return Err(CatalogError::Validation(format!(
                "resource shape {:?} is incompatible with codec {:?}",
                resource.shape, resource.codec
            )))
        }
    }

    if resource.codec == ResourceCodec::Dotenv {
        let mut keys = HashSet::new();
        if let Some(key) = resource
            .entries
            .iter()
            .filter_map(|entry| entry.key.as_ref())
            .find(|key| !keys.insert(key.as_str()))
        {
            return Err(CatalogError::Validation(format!(
                "dotenv resource {:?} exposes duplicate key {:?}",
                resource.id, key
            )));
        }
    }

    match (&resource.kind, &resource.shape, &resource.source) {
        (ResourceKind::SharedSecret, ValueShape::Scalar, ResourceSource::SecretRef { .. }) => {}
        (ResourceKind::Secret, ValueShape::Scalar | ValueShape::Bytes, ResourceSource::SecretRef { .. }) => {}
        (ResourceKind::EnvFile, ValueShape::KeyValueSet, ResourceSource::SecretRef { .. }) => {}
        (
            ResourceKind::SshIdentity,
            ValueShape::SshIdentity,
            ResourceSource::SecretRef { .. },
        ) => {
            if resource.default_env_key.is_some()
                || resource.entries.len() != 1
                || resource
                    .entries
                    .iter()
                    .any(|entry| !is_ssh_identity_address(&entry.address) || entry.sensitive || entry.key.is_some())
            {
                return Err(CatalogError::Validation(format!(
                    "SSH identity resource {:?} requires exactly one non-sensitive ssh/sha256 identity entry without an environment key",
                    resource.id
                )));
            }
        }
        (ResourceKind::Literal, ValueShape::Scalar, ResourceSource::Literal { .. }) => {}
        (
            ResourceKind::Command,
            ValueShape::Scalar | ValueShape::KeyValueSet | ValueShape::Bytes,
            ResourceSource::Command { argv },
        ) if !argv.is_empty() => {}
        (ResourceKind::SshAgent, ValueShape::Socket, ResourceSource::Socket { endpoint }) => {
            require_absolute_path(endpoint, "ssh agent endpoint")?;
            if resource.default_env_key.is_some()
                || resource
                    .entries
                    .iter()
                    .any(|entry| !is_ssh_identity_address(&entry.address) || entry.sensitive)
            {
                return Err(CatalogError::Validation(format!(
                    "SSH agent resource {:?} requires non-sensitive ssh/sha256 identity entries without an environment key",
                    resource.id
                )));
            }
        }
        _ => {
            return Err(CatalogError::Validation(format!(
                "resource kind {:?}, shape {:?}, and source {:?} are incompatible",
                resource.kind, resource.shape, resource.source
            )))
        }
    }

    match &resource.source {
        ResourceSource::SecretRef { secret_id } => require_id(secret_id, "secret reference")?,
        ResourceSource::Command { argv } if argv.iter().any(|arg| arg.is_empty()) => {
            return Err(CatalogError::Validation(
                "command argv cannot contain empty arguments".to_string(),
            ))
        }
        _ => {}
    }
    if matches!(resource.shape, ValueShape::Scalar)
        && resource.default_env_key != resource.entries[0].key
    {
        return Err(CatalogError::Validation(
            "default_env_key must match the scalar entry key".to_string(),
        ));
    }
    Ok(())
}

fn validate_binding(binding: &Binding) -> CatalogResult<()> {
    require_id(&binding.id, "binding id")?;
    require_id(&binding.project_id, "binding project id")?;
    require_id(&binding.resource_id, "binding resource id")?;
    if let Some(key) = &binding.key_override {
        require_env_key(key)?;
    }
    let selected_addresses = match &binding.selection {
        EntrySelection::All => &[][..],
        EntrySelection::Entries { addresses } => addresses,
    };
    let mut unique = HashSet::new();
    for address in selected_addresses {
        require_entry_address(address)?;
        if !unique.insert(address) {
            return Err(CatalogError::Validation(format!(
                "binding {:?} selects duplicate entry address {:?}",
                binding.id, address
            )));
        }
    }
    if !matches!(&binding.selection, EntrySelection::All) && selected_addresses.is_empty() {
        return Err(CatalogError::Validation(
            "entry selection cannot be empty".to_string(),
        ));
    }
    match &binding.scope {
        BindingScope::Common if binding.allow_override => Err(CatalogError::Validation(
            "allow_override is only valid for environment bindings".to_string(),
        )),
        BindingScope::Environment { environment_id } => {
            require_id(environment_id, "binding environment id")
        }
        BindingScope::Common => Ok(()),
    }
}

fn require_entry_address(value: &str) -> CatalogResult<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|segment| {
            segment.is_empty()
                || !segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        })
    {
        Err(CatalogError::Validation(format!(
            "invalid entry address {value:?}"
        )))
    } else {
        Ok(())
    }
}

fn is_ssh_identity_address(value: &str) -> bool {
    value
        .strip_prefix("ssh/sha256/")
        .is_some_and(|digest| {
            digest.len() == 43
                && digest
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        })
}

fn validate_surface(surface: &Surface) -> CatalogResult<()> {
    require_id(&surface.id, "surface id")?;
    require_path_component(&surface.id, "surface id")?;
    require_id(&surface.environment_id, "surface environment id")?;
    require_name(&surface.name, "surface name")?;
    require_normalized_absolute_path(&surface.path, "surface path")?;
    match &surface.input {
        SurfaceInput::Bindings { binding_ids } => {
            for binding_id in binding_ids {
                require_id(binding_id, "surface binding id")?;
            }
        }
        SurfaceInput::SshAgent { binding_ids, route } => {
            if surface.kind != SurfaceKind::UnixSocket {
                return Err(CatalogError::Validation(
                    "ssh_agent input is only valid for a unix_socket surface".to_string(),
                ));
            }
            for binding_id in binding_ids {
                require_id(binding_id, "surface binding id")?;
            }
            if let Some(route) = route {
                validate_ssh_route(route)?;
            }
        }
        SurfaceInput::Resource { resource_id } => {
            require_id(resource_id, "surface resource id")?;
        }
    }
    Ok(())
}

fn validate_ssh_route(route: &crate::domain::SshRouteSpec) -> CatalogResult<()> {
    if route.host_patterns.is_empty() {
        return Err(CatalogError::Validation(
            "SSH route requires at least one host pattern".to_string(),
        ));
    }
    let mut patterns = HashSet::new();
    for pattern in &route.host_patterns {
        if pattern.is_empty()
            || pattern.starts_with('#')
            || pattern.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return Err(CatalogError::Validation(format!(
                "invalid SSH host pattern {pattern:?}"
            )));
        }
        if !patterns.insert(pattern) {
            return Err(CatalogError::Validation(format!(
                "SSH route repeats host pattern {pattern:?}"
            )));
        }
    }
    for (label, value) in [("HostName", &route.hostname), ("User", &route.user)] {
        if value.as_ref().is_some_and(|value| {
            value.trim().is_empty() || value.chars().any(|ch| ch == '\n' || ch == '\r' || ch == '\0')
        }) {
            return Err(CatalogError::Validation(format!(
                "SSH route {label} contains invalid characters"
            )));
        }
    }
    if route.port == Some(0) {
        return Err(CatalogError::Validation(
            "SSH route port must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn validate_ssh_route_conflicts(snapshot: &CatalogSnapshot) -> CatalogResult<()> {
    let mut owners = HashMap::<&str, &str>::new();
    for surface in &snapshot.surfaces {
        let SurfaceInput::SshAgent { route: Some(route), .. } = &surface.input else {
            continue;
        };
        for pattern in route.host_patterns.iter().filter(|pattern| !pattern.starts_with('!')) {
            if let Some(existing) = owners.insert(pattern, &surface.id) {
                return Err(CatalogError::Validation(format!(
                    "SSH host pattern {pattern:?} is routed by both {existing:?} and {:?}",
                    surface.id
                )));
            }
        }
    }
    Ok(())
}

fn require_id(value: &str, label: &str) -> CatalogResult<()> {
    if value.trim().is_empty() {
        return Err(CatalogError::Validation(format!("{label} cannot be empty")));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(CatalogError::Validation(format!(
            "{label} cannot contain whitespace"
        )));
    }
    Ok(())
}

fn require_name(value: &str, label: &str) -> CatalogResult<()> {
    if value.trim().is_empty() {
        Err(CatalogError::Validation(format!("{label} cannot be empty")))
    } else {
        Ok(())
    }
}

fn require_env_key(key: &str) -> CatalogResult<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(CatalogError::Validation("environment key cannot be empty".to_string()));
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || chars.any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()))
    {
        return Err(CatalogError::Validation(format!(
            "invalid environment key {key:?}"
        )));
    }
    Ok(())
}

fn require_absolute_path(path: &Path, label: &str) -> CatalogResult<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(CatalogError::Validation(format!(
            "{label} must be absolute: {}",
            path.display()
        )))
    }
}

fn require_normalized_absolute_path(path: &Path, label: &str) -> CatalogResult<()> {
    require_absolute_path(path, label)?;
    if path.components().any(|component| {
        matches!(component, std::path::Component::CurDir | std::path::Component::ParentDir)
    }) {
        return Err(CatalogError::Validation(format!(
            "{label} cannot contain . or .. components: {}",
            path.display()
        )));
    }
    Ok(())
}

fn surface_relative_path<'a>(path: &'a Path, project_path: &Path) -> CatalogResult<&'a Path> {
    let relative = path.strip_prefix(project_path).map_err(|_| {
        CatalogError::Validation(format!(
            "surface path {} must be inside project directory {}",
            path.display(),
            project_path.display()
        ))
    })?;
    if relative.as_os_str().is_empty() {
        return Err(CatalogError::Validation(format!(
            "surface path {} must be inside project directory {}",
            path.display(),
            project_path.display()
        )));
    }
    if relative.components().any(|component| {
        !matches!(component, std::path::Component::Normal(_))
    }) {
        return Err(CatalogError::Validation(format!(
            "surface relative path must contain only normal components: {}",
            relative.display()
        )));
    }
    Ok(relative)
}

fn require_path_component(value: &str, label: &str) -> CatalogResult<()> {
    let mut components = Path::new(value).components();
    let is_one_component = matches!(
        components.next(),
        Some(std::path::Component::Normal(component)) if component == value
    ) && components.next().is_none();
    let has_safe_chars = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
    if is_one_component && has_safe_chars {
        Ok(())
    } else {
        Err(CatalogError::Validation(format!(
            "{label} must be one filesystem-safe component: {value:?}"
        )))
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn require_exists(conn: &Connection, table: &str, id: &str, kind: &str) -> CatalogResult<()> {
    let sql = format!("SELECT 1 FROM {table} WHERE id = ?1");
    let exists = conn.query_row(&sql, [id], |_| Ok(())).optional()?.is_some();
    if exists {
        Ok(())
    } else {
        Err(CatalogError::NotFound(format!("{kind} {id}")))
    }
}

fn remove_one(conn: &Connection, table: &str, id: &str, kind: &str) -> CatalogResult<()> {
    let sql = format!("DELETE FROM {table} WHERE id = ?1");
    if conn.execute(&sql, [id])? == 1 {
        Ok(())
    } else {
        Err(CatalogError::NotFound(format!("{kind} {id}")))
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(
    column: usize,
    value: &str,
) -> rusqlite::Result<T> {
    serde_json::from_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn invalid_value(column: usize, value: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown catalog enum value {value:?}"),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EntrySpec, SshRouteSpec};

    fn project() -> Project {
        Project {
            id: "floria".to_string(),
            name: "floria".to_string(),
            path: PathBuf::from("/workspace/floria"),
        }
    }

    fn environment() -> Environment {
        Environment {
            id: "development".to_string(),
            project_id: "floria".to_string(),
            name: "Development".to_string(),
            position: 0,
        }
    }

    fn scalar_resource(id: &str, key: &str) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::SharedSecret,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: Some(key.to_string()),
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: key.to_string(),
                key: Some(key.to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: format!("secret-{id}") },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
        }
    }

    fn env_file_resource(id: &str) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Dotenv,
            default_env_key: None,
            entries: vec![
                EntrySpec {
                    address: "keys/API_HOST".to_string(),
                    label: "API_HOST".to_string(),
                    key: Some("API_HOST".to_string()),
                    sensitive: true,
                },
                EntrySpec {
                    address: "keys/LOG_LEVEL".to_string(),
                    label: "LOG_LEVEL".to_string(),
                    key: Some("LOG_LEVEL".to_string()),
                    sensitive: true,
                },
            ],
            source: ResourceSource::SecretRef { secret_id: format!("secret-{id}") },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
        }
    }

    fn binding(id: &str, resource_id: &str, scope: BindingScope) -> Binding {
        Binding {
            id: id.to_string(),
            project_id: "floria".to_string(),
            scope,
            resource_id: resource_id.to_string(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 0,
        }
    }

    fn catalog() -> (tempfile::TempDir, Catalog) {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog.upsert_project(&project()).unwrap();
        catalog.upsert_environment(&environment()).unwrap();
        (dir, catalog)
    }

    #[test]
    fn rejects_old_schema_during_development() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();

        let error = migrate(&mut conn).unwrap_err();
        assert!(matches!(
            error,
            CatalogError::UnsupportedSchema { found: 1, expected: 8 }
        ));
    }

    #[test]
    fn entry_selection_must_reference_exposed_entries() {
        let (_dir, catalog) = catalog();
        catalog.upsert_resource(&env_file_resource("fixture-env-file")).unwrap();
        let mut selected = binding(
            "env-file-binding",
            "fixture-env-file",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/API_HOST".to_string()],
        };
        catalog.upsert_binding(&selected).unwrap();

        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/MISSING".to_string()],
        };
        let error = catalog.upsert_binding(&selected).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("not exposed")));
    }

    #[test]
    fn entry_selection_projects_only_the_selected_named_values() {
        let (_dir, catalog) = catalog();
        catalog.upsert_resource(&env_file_resource("fixture-sections")).unwrap();
        let mut selected = binding(
            "section-binding",
            "fixture-sections",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec!["keys/LOG_LEVEL".to_string()],
        };
        catalog.upsert_binding(&selected).unwrap();

        let resolved = catalog.resolve_environment("floria", "development").unwrap();
        assert_eq!(resolved.exports.len(), 1);
        assert_eq!(resolved.exports[0].key, "LOG_LEVEL");
        assert_eq!(resolved.exports[0].source_key, "keys/LOG_LEVEL");
    }

    #[test]
    fn ini_keys_are_generic_until_selected_for_a_dotenv_projection() {
        let (_dir, catalog) = catalog();
        let resource = Resource {
            id: "fixture-ini".to_string(),
            name: "Fixture INI".to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Ini,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "sections/fixture/keys/credential-process".to_string(),
                label: "[fixture] credential-process".to_string(),
                key: Some("credential-process".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: "fixture-ini-secret".to_string() },
            enforcement: Enforcement::Prompt,
            metadata: Default::default(),
        };
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding(
                "fixture-ini-binding",
                &resource.id,
                BindingScope::Environment { environment_id: "development".to_string() },
            ))
            .unwrap();

        let error = catalog
            .upsert_surface(&Surface {
                id: "fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::DotenvFile,
                path: PathBuf::from("/workspace/floria/.env"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["fixture-ini-binding".to_string()],
                },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();

        assert!(matches!(error, CatalogError::Validation(message) if message.contains("cannot feed dotenv")));

        let mut ini_surface = Surface {
            id: "fixture-ini-output".to_string(),
            environment_id: "development".to_string(),
            name: "credentials.ini".to_string(),
            kind: SurfaceKind::IniFile,
            path: PathBuf::from("/workspace/floria/credentials.ini"),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["fixture-ini-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&ini_surface).unwrap();

        let mut duplicate = resource.clone();
        duplicate.id = "fixture-ini-duplicate".to_string();
        duplicate.source = ResourceSource::SecretRef {
            secret_id: "fixture-ini-secret-two".to_string(),
        };
        catalog.upsert_resource(&duplicate).unwrap();
        catalog
            .upsert_binding(&binding(
                "fixture-ini-binding-two",
                &duplicate.id,
                BindingScope::Environment { environment_id: "development".to_string() },
            ))
            .unwrap();
        ini_surface.input = SurfaceInput::Bindings {
            binding_ids: vec![
                "fixture-ini-binding".to_string(),
                "fixture-ini-binding-two".to_string(),
            ],
        };
        assert!(matches!(
            catalog.upsert_surface(&ini_surface),
            Err(CatalogError::Conflict { key, .. })
                if key == "sections/fixture/keys/credential-process"
        ));
    }

    #[test]
    fn snapshot_round_trips_typed_metadata_without_secret_values() {
        let (_dir, catalog) = catalog();
        let mut resource = scalar_resource("cloudflare", "CLOUDFLARE_API_TOKEN");
        resource.enforcement = Enforcement::TouchId;
        resource.metadata.note = Some("Deployment token for the documentation zone".to_string());
        resource.metadata.links.push(crate::domain::ItemLink {
            label: "Cloudflare dashboard".to_string(),
            url: "https://dash.cloudflare.com/example/tokens".to_string(),
        });
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("common-cloudflare", "cloudflare", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::DotenvFile,
                path: PathBuf::from("/workspace/floria/.env"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["common-cloudflare".to_string()],
                },
                enforcement: Enforcement::Allow,
                position: 0,
            })
            .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects, vec![project()]);
        assert_eq!(
            snapshot.checkouts,
            vec![ProjectCheckout {
                id: "floria".to_string(),
                project_id: "floria".to_string(),
                path: PathBuf::from("/workspace/floria"),
                environment_id: None,
                kind: ProjectCheckoutKind::Primary,
                git_common_dir: None,
            }]
        );
        assert_eq!(snapshot.environments, vec![environment()]);
        assert_eq!(snapshot.resources, vec![resource]);
        assert_eq!(snapshot.bindings.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(snapshot.surfaces[0].enforcement, Enforcement::Allow);
        assert_eq!(snapshot.resources[0].enforcement, Enforcement::TouchId);
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("plaintext"));
    }

    #[test]
    fn worktree_checkout_requires_an_environment_from_the_same_project() {
        let (_dir, catalog) = catalog();
        let checkout = ProjectCheckout {
            id: "floria-feature".to_string(),
            project_id: "floria".to_string(),
            path: PathBuf::from("/workspace/floria-feature"),
            environment_id: Some("development".to_string()),
            kind: ProjectCheckoutKind::Worktree,
            git_common_dir: Some(PathBuf::from("/workspace/floria/.git")),
        };
        catalog.upsert_checkout(&checkout).unwrap();
        assert_eq!(catalog.snapshot().unwrap().checkouts[1], checkout);

        let mut without_environment = checkout.clone();
        without_environment.id = "floria-unassigned".to_string();
        without_environment.path = PathBuf::from("/workspace/floria-unassigned");
        without_environment.environment_id = None;
        assert!(matches!(
            catalog.upsert_checkout(&without_environment),
            Err(CatalogError::Validation(message))
                if message.contains("must select an environment")
        ));

        assert!(matches!(
            catalog.remove_checkout("floria"),
            Err(CatalogError::Validation(message))
                if message.contains("cannot be removed separately")
        ));
        catalog.remove_checkout(&checkout.id).unwrap();
        assert_eq!(catalog.snapshot().unwrap().checkouts.len(), 1);
    }

    #[test]
    fn surface_paths_are_persisted_relative_to_the_primary_checkout() {
        let (_dir, catalog) = catalog();
        let surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".config/dev.env".to_string(),
            kind: SurfaceKind::DotenvFile,
            path: PathBuf::from("/workspace/floria/.config/dev.env"),
            input: SurfaceInput::Bindings { binding_ids: Vec::new() },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();

        let relative: String = catalog
            .connection()
            .unwrap()
            .query_row(
                "SELECT relative_path FROM surfaces WHERE id = ?1",
                [&surface.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(relative, ".config/dev.env");
        assert_eq!(catalog.snapshot().unwrap().surfaces, vec![surface]);
    }

    #[test]
    fn create_resource_refuses_to_replace_existing_metadata() {
        let (_dir, catalog) = catalog();
        let resource = scalar_resource("fixture-shared", "FIXTURE_TOKEN");
        catalog.create_resource(&resource).unwrap();
        let mut replacement = resource.clone();
        replacement.name = "Replacement".to_string();

        assert!(matches!(
            catalog.create_resource(&replacement),
            Err(CatalogError::AlreadyExists { kind: "resource", .. })
        ));
        assert_eq!(catalog.resource(&resource.id).unwrap().name, resource.name);
    }

    #[test]
    fn resource_usage_expands_common_binding_to_affected_surfaces() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_environment(&Environment {
                id: "staging".to_string(),
                project_id: "floria".to_string(),
                name: "Staging".to_string(),
                position: 1,
            })
            .unwrap();
        let resource = scalar_resource("fixture-shared", "FIXTURE_TOKEN");
        catalog.create_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("fixture-common", &resource.id, BindingScope::Common))
            .unwrap();
        for (id, environment_id, path) in [
            ("fixture-dev-env", "development", "/workspace/floria/.env"),
            ("fixture-stage-env", "staging", "/workspace/floria/.env.staging"),
        ] {
            catalog
                .upsert_surface(&Surface {
                    id: id.to_string(),
                    environment_id: environment_id.to_string(),
                    name: ".env".to_string(),
                    kind: SurfaceKind::DotenvFile,
                    path: PathBuf::from(path),
                    input: SurfaceInput::Bindings {
                        binding_ids: vec!["fixture-common".to_string()],
                    },
                    enforcement: Enforcement::Prompt,
                    position: 0,
                })
                .unwrap();
        }

        let usage = catalog.resource_usage(&resource.id).unwrap();
        assert_eq!(usage.bindings.len(), 1);
        assert_eq!(usage.bindings[0].environment_ids, vec!["development", "staging"]);
        assert_eq!(
            usage.bindings[0].surface_ids,
            vec!["fixture-dev-env", "fixture-stage-env"]
        );
        assert!(usage.direct_surface_ids.is_empty());
        assert!(matches!(
            catalog.remove_resource(&resource.id),
            Err(CatalogError::ResourceInUse { binding_ids, .. })
                if binding_ids == vec!["fixture-common"]
        ));
    }

    #[test]
    fn surface_path_must_stay_inside_its_project() {
        let (_dir, catalog) = catalog();
        let error = catalog
            .upsert_surface(&Surface {
                id: "fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::DotenvFile,
                path: PathBuf::from("/workspace/other/.env"),
                input: SurfaceInput::Bindings { binding_ids: vec![] },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();
        assert!(matches!(error, CatalogError::Validation(_)));
    }

    #[test]
    fn surface_id_must_be_one_safe_path_component() {
        let (_dir, catalog) = catalog();
        let error = catalog
            .upsert_surface(&Surface {
                id: "../fixture-dotenv".to_string(),
                environment_id: "development".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::DotenvFile,
                path: PathBuf::from("/workspace/floria/.env"),
                input: SurfaceInput::Bindings { binding_ids: vec![] },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap_err();
        assert!(matches!(error, CatalogError::Validation(_)));
    }

    #[test]
    fn direct_env_file_surface_requires_and_protects_its_env_file_resource() {
        let (_dir, catalog) = catalog();
        let resource = env_file_resource("fixture-env-file");
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_surface(&Surface {
                id: "fixture-direct-env".to_string(),
                environment_id: "development".to_string(),
                name: ".env.local".to_string(),
                kind: SurfaceKind::EnvFileDirect,
                path: PathBuf::from("/workspace/floria/.env.local"),
                input: SurfaceInput::Resource { resource_id: resource.id.clone() },
                enforcement: Enforcement::Prompt,
                position: 1,
            })
            .unwrap();

        let usage = catalog.resource_usage(&resource.id).unwrap();
        assert_eq!(usage.direct_surface_ids, vec!["fixture-direct-env"]);

        let mut incompatible = resource.clone();
        incompatible.kind = ResourceKind::Command;
        incompatible.source = ResourceSource::Command { argv: vec!["fixture-command".to_string()] };
        assert!(matches!(
            catalog.upsert_resource(&incompatible),
            Err(CatalogError::Validation(_))
        ));
        assert_eq!(catalog.resource(&resource.id).unwrap(), resource);
    }

    #[test]
    fn direct_env_file_surface_rejects_missing_or_scalar_resource() {
        let (_dir, catalog) = catalog();
        let missing = Surface {
            id: "fixture-direct-env".to_string(),
            environment_id: "development".to_string(),
            name: ".env.local".to_string(),
            kind: SurfaceKind::EnvFileDirect,
            path: PathBuf::from("/workspace/floria/.env.local"),
            input: SurfaceInput::Bindings { binding_ids: vec![] },
            enforcement: Enforcement::Prompt,
            position: 1,
        };
        assert!(matches!(
            catalog.upsert_surface(&missing),
            Err(CatalogError::Validation(_))
        ));

        let scalar = scalar_resource("fixture-scalar", "FIXTURE_TOKEN");
        catalog.upsert_resource(&scalar).unwrap();
        assert!(matches!(
            catalog.upsert_surface(&Surface {
                input: SurfaceInput::Resource { resource_id: scalar.id },
                ..missing
            }),
            Err(CatalogError::Validation(_))
        ));
    }

    #[test]
    fn conflicting_surface_membership_is_rejected_and_transaction_rolls_back() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("first", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("second", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("first-binding", "first", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_binding(&binding("second-binding", "second", BindingScope::Common))
            .unwrap();
        let mut surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::DotenvFile,
            path: PathBuf::from("/workspace/floria/.env"),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["first-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();

        surface.input = SurfaceInput::Bindings {
            binding_ids: vec!["first-binding".to_string(), "second-binding".to_string()],
        };
        let error = catalog.upsert_surface(&surface).unwrap_err();
        assert!(matches!(error, CatalogError::Conflict { ref key, .. } if key == "TOKEN"));
        assert_eq!(
            catalog.snapshot().unwrap().surfaces[0].input,
            SurfaceInput::Bindings {
                binding_ids: vec!["first-binding".to_string()]
            }
        );
    }

    #[test]
    fn the_same_key_can_belong_to_separate_surfaces() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("first", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("second", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("first-binding", "first", BindingScope::Common))
            .unwrap();
        catalog
            .upsert_binding(&binding("second-binding", "second", BindingScope::Common))
            .unwrap();

        for (id, name, binding_id, kind) in [
            (
                "first-surface",
                ".env.first",
                "first-binding",
                SurfaceKind::DotenvFile,
            ),
            (
                "second-surface",
                ".envrc",
                "second-binding",
                SurfaceKind::DirenvFile,
            ),
        ] {
            catalog
                .upsert_surface(&Surface {
                    id: id.to_string(),
                    environment_id: "development".to_string(),
                    name: name.to_string(),
                    kind,
                    path: PathBuf::from("/workspace/floria").join(name),
                    input: SurfaceInput::Bindings {
                        binding_ids: vec![binding_id.to_string()],
                    },
                    enforcement: Enforcement::Prompt,
                    position: 0,
                })
                .unwrap();
        }

        assert_eq!(catalog.snapshot().unwrap().surfaces.len(), 2);
    }

    #[test]
    fn surface_rejects_unknown_members_and_binding_removal_detaches_membership() {
        let (_dir, catalog) = catalog();
        let resource = scalar_resource("fixture", "FIXTURE_TOKEN");
        catalog.upsert_resource(&resource).unwrap();
        catalog
            .upsert_binding(&binding("fixture-binding", &resource.id, BindingScope::Common))
            .unwrap();
        let mut surface = Surface {
            id: "fixture-dotenv".to_string(),
            environment_id: "development".to_string(),
            name: ".env".to_string(),
            kind: SurfaceKind::DotenvFile,
            path: PathBuf::from("/workspace/floria/.env"),
            input: SurfaceInput::Bindings {
                binding_ids: vec!["missing-binding".to_string()],
            },
            enforcement: Enforcement::Prompt,
            position: 0,
        };
        assert!(matches!(
            catalog.upsert_surface(&surface),
            Err(CatalogError::NotFound(message)) if message.contains("missing-binding")
        ));

        surface.input = SurfaceInput::Bindings {
            binding_ids: vec!["fixture-binding".to_string()],
        };
        catalog.upsert_surface(&surface).unwrap();
        catalog.remove_binding("fixture-binding").unwrap();

        assert_eq!(
            catalog.snapshot().unwrap().surfaces[0].input,
            SurfaceInput::Bindings { binding_ids: Vec::new() }
        );
    }

    #[test]
    fn environment_binding_can_explicitly_override_common_key() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&scalar_resource("common", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("development-token", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("common-binding", "common", BindingScope::Common))
            .unwrap();
        let mut environment_binding = binding(
            "development-binding",
            "development-token",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        environment_binding.allow_override = true;
        catalog.upsert_binding(&environment_binding).unwrap();

        let resolved = catalog.resolve_environment("floria", "development").unwrap();
        assert_eq!(resolved.exports.len(), 1);
        assert_eq!(resolved.exports[0].binding_id, "development-binding");
        assert_eq!(
            resolved.exports[0].overrides_binding_id.as_deref(),
            Some("common-binding")
        );
    }

    #[test]
    fn key_override_is_only_allowed_for_scalar_resources() {
        let (_dir, catalog) = catalog();
        catalog
            .upsert_resource(&Resource {
                id: "defaults".to_string(),
                name: "Defaults".to_string(),
                kind: ResourceKind::EnvFile,
                shape: ValueShape::KeyValueSet,
                codec: ResourceCodec::Dotenv,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: "keys/LOG_LEVEL".to_string(),
                    label: "LOG_LEVEL".to_string(),
                    key: Some("LOG_LEVEL".to_string()),
                    sensitive: false,
                }],
                source: ResourceSource::SecretRef { secret_id: "secret-defaults".to_string() },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
            })
            .unwrap();
        let mut binding = binding(
            "defaults-binding",
            "defaults",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        binding.key_override = Some("OTHER".to_string());
        let error = catalog.upsert_binding(&binding).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("scalar")));
    }

    #[test]
    fn ssh_agent_surface_composes_managed_and_external_identity_bindings() {
        let (_dir, catalog) = catalog();
        let address =
            "ssh/sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        catalog
            .upsert_resource(&Resource {
                id: "fixture-agent-provider".to_string(),
                name: "Fixture Agent".to_string(),
                kind: ResourceKind::SshAgent,
                shape: ValueShape::Socket,
                codec: ResourceCodec::Opaque,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: address.clone(),
                    label: "Fleet key".to_string(),
                    key: None,
                    sensitive: false,
                }],
                source: ResourceSource::Socket {
                    endpoint: PathBuf::from("/fixture/upstream-agent.sock"),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
            })
            .unwrap();
        let mut selected = binding(
            "fixture-agent-binding",
            "fixture-agent-provider",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        selected.selection = EntrySelection::Entries {
            addresses: vec![address.clone()],
        };
        catalog.upsert_binding(&selected).unwrap();
        let managed_address =
            "ssh/sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string();
        catalog
            .upsert_resource(&Resource {
                id: "fixture-managed-identity".to_string(),
                name: "Fixture Managed Identity".to_string(),
                kind: ResourceKind::SshIdentity,
                shape: ValueShape::SshIdentity,
                codec: ResourceCodec::Opaque,
                default_env_key: None,
                entries: vec![EntrySpec {
                    address: managed_address,
                    label: "Managed fleet key".to_string(),
                    key: None,
                    sensitive: false,
                }],
                source: ResourceSource::SecretRef {
                    secret_id: "fixture-managed-private-key".to_string(),
                },
                enforcement: Enforcement::Prompt,
                metadata: Default::default(),
            })
            .unwrap();
        let managed = binding(
            "fixture-managed-binding",
            "fixture-managed-identity",
            BindingScope::Environment { environment_id: "development".to_string() },
        );
        catalog.upsert_binding(&managed).unwrap();

        let surface = Surface {
            id: "fixture-agent-surface".to_string(),
            environment_id: "development".to_string(),
            name: "AWS fleet".to_string(),
            kind: SurfaceKind::UnixSocket,
            path: PathBuf::from("/workspace/floria/.floria/agent.sock"),
            input: SurfaceInput::SshAgent {
                binding_ids: vec![selected.id.clone(), managed.id],
                route: Some(SshRouteSpec {
                    host_patterns: vec!["ec2-*.example.internal".to_string()],
                    hostname: None,
                    user: Some("ubuntu".to_string()),
                    port: None,
                    forward_agent: true,
                }),
            },
            enforcement: Enforcement::TouchId,
            position: 0,
        };
        catalog.upsert_surface(&surface).unwrap();

        let conflicting_route = Surface {
            id: "fixture-agent-surface-two".to_string(),
            name: "Duplicate route".to_string(),
            path: PathBuf::from("/workspace/floria/.floria/agent-two.sock"),
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&conflicting_route).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("ec2-*.example.internal")));

        let invalid_route = Surface {
            input: SurfaceInput::SshAgent {
                binding_ids: vec!["fixture-agent-binding".to_string()],
                route: Some(SshRouteSpec {
                    host_patterns: vec!["fixture\nHost injected".to_string()],
                    hostname: None,
                    user: None,
                    port: None,
                    forward_agent: false,
                }),
            },
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&invalid_route).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("host pattern")));

        let direct = Surface {
            input: SurfaceInput::Resource {
                resource_id: "fixture-agent-provider".to_string(),
            },
            ..surface.clone()
        };
        let error = catalog.upsert_surface(&direct).unwrap_err();
        assert!(matches!(error, CatalogError::Validation(message) if message.contains("incompatible")));

        let duplicate = Binding {
            id: "fixture-agent-binding-duplicate".to_string(),
            ..selected
        };
        catalog.upsert_binding(&duplicate).unwrap();
        let duplicated_surface = Surface {
            input: SurfaceInput::Bindings {
                binding_ids: vec![
                    "fixture-agent-binding".to_string(),
                    "fixture-agent-binding-duplicate".to_string(),
                ],
            },
            ..surface
        };
        let error = catalog.upsert_surface(&duplicated_surface).unwrap_err();
        assert!(matches!(error, CatalogError::Conflict { key, .. } if key == address));
    }

    #[test]
    fn catalog_file_is_private() {
        let (dir, _catalog) = catalog();
        let mode = std::fs::metadata(dir.path().join("catalog.sqlite"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
