use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};

use crate::domain::{
    Binding, BindingScope, CatalogSnapshot, Environment, Project, ResolvedEnvironment,
    ResolvedExport, Resource, ResourceKind, ResourceSource, Surface, SurfaceKind, ValueShape,
};
use crate::error::{CatalogError, CatalogResult};

const SCHEMA_VERSION: i64 = 1;

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
        snapshot_from(&self.connection()?)
    }

    pub fn upsert_project(&self, project: &Project) -> CatalogResult<()> {
        validate_project(project)?;
        self.connection()?.execute(
            "INSERT INTO projects (id, name, path) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, path = excluded.path,
                 updated_at = CURRENT_TIMESTAMP",
            params![project.id, project.name, path_string(&project.path)],
        )?;
        Ok(())
    }

    pub fn remove_project(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "project id")?;
        remove_one(&self.connection()?, "projects", id, "project")
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
                (id, name, kind, shape, default_env_key, exports_json, source_json, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, kind = excluded.kind,
                 shape = excluded.shape, default_env_key = excluded.default_env_key,
                 exports_json = excluded.exports_json, source_json = excluded.source_json,
                 detail = excluded.detail, updated_at = CURRENT_TIMESTAMP",
            params![
                resource.id,
                resource.name,
                resource.kind.as_str(),
                resource.shape.as_str(),
                resource.default_env_key,
                serde_json::to_string(&resource.exports)?,
                serde_json::to_string(&resource.source)?,
                resource.detail,
            ],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_resource(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "resource id")?;
        remove_one(&self.connection()?, "resources", id, "resource")
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
                 allow_override, position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                 environment_id = excluded.environment_id, resource_id = excluded.resource_id,
                 key_override = excluded.key_override, enabled = excluded.enabled,
                 allow_override = excluded.allow_override, position = excluded.position,
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
            ],
        )?;
        validate_snapshot_conflicts(&snapshot_from(&tx)?)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_binding(&self, id: &str) -> CatalogResult<()> {
        require_id(id, "binding id")?;
        remove_one(&self.connection()?, "bindings", id, "binding")
    }

    pub fn upsert_surface(&self, surface: &Surface) -> CatalogResult<()> {
        validate_surface(surface)?;
        let conn = self.connection()?;
        require_exists(&conn, "environments", &surface.environment_id, "environment")?;
        if let Some(resource_id) = &surface.resource_id {
            require_exists(&conn, "resources", resource_id, "resource")?;
            if surface.kind == SurfaceKind::UnixSocket {
                let shape: String = conn.query_row(
                    "SELECT shape FROM resources WHERE id = ?1",
                    [resource_id],
                    |row| row.get(0),
                )?;
                if shape != ValueShape::Socket.as_str() {
                    return Err(CatalogError::Validation(
                        "unix_socket surfaces require a socket resource".to_string(),
                    ));
                }
            }
        } else if surface.kind == SurfaceKind::UnixSocket {
            return Err(CatalogError::Validation(
                "unix_socket surfaces require resource_id".to_string(),
            ));
        }

        conn.execute(
            "INSERT INTO surfaces
                (id, environment_id, name, kind, path, resource_id, position)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET environment_id = excluded.environment_id,
                 name = excluded.name, kind = excluded.kind, path = excluded.path,
                 resource_id = excluded.resource_id, position = excluded.position,
                 updated_at = CURRENT_TIMESTAMP",
            params![
                surface.id,
                surface.environment_id,
                surface.name,
                surface.kind.as_str(),
                path_string(&surface.path),
                surface.resource_id,
                surface.position,
            ],
        )?;
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
        resolve_snapshot(&self.snapshot()?, project_id, environment_id)
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
            path TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE UNIQUE INDEX projects_path_idx ON projects(path);

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
            default_env_key TEXT,
            exports_json TEXT NOT NULL,
            source_json TEXT NOT NULL,
            detail TEXT,
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
            path TEXT NOT NULL,
            resource_id TEXT REFERENCES resources(id) ON DELETE RESTRICT,
            position INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX surfaces_environment_idx ON surfaces(environment_id, position);
        PRAGMA user_version = 1;",
    )?;
    tx.commit()?;
    Ok(())
}

fn snapshot_from(conn: &Connection) -> CatalogResult<CatalogSnapshot> {
    let projects = {
        let mut stmt = conn.prepare("SELECT id, name, path FROM projects ORDER BY name, id")?;
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
            "SELECT id, name, kind, shape, default_env_key, exports_json, source_json, detail
             FROM resources ORDER BY name, id",
        )?;
        let values = stmt.query_map([], |row| {
            let kind: String = row.get(2)?;
            let shape: String = row.get(3)?;
            Ok(Resource {
                id: row.get(0)?,
                name: row.get(1)?,
                kind: ResourceKind::parse(&kind).ok_or_else(|| invalid_value(2, kind))?,
                shape: ValueShape::parse(&shape).ok_or_else(|| invalid_value(3, shape))?,
                default_env_key: row.get(4)?,
                exports: decode_json(5, &row.get::<_, String>(5)?)?,
                source: decode_json(6, &row.get::<_, String>(6)?)?,
                detail: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let bindings = {
        let mut stmt = conn.prepare(
            "SELECT id, project_id, environment_id, resource_id, key_override,
                    enabled, allow_override, position
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
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    let surfaces = {
        let mut stmt = conn.prepare(
            "SELECT id, environment_id, name, kind, path, resource_id, position
             FROM surfaces ORDER BY environment_id, position, name, id",
        )?;
        let values = stmt.query_map([], |row| {
            let kind: String = row.get(3)?;
            Ok(Surface {
                id: row.get(0)?,
                environment_id: row.get(1)?,
                name: row.get(2)?,
                kind: SurfaceKind::parse(&kind).ok_or_else(|| invalid_value(3, kind))?,
                path: PathBuf::from(row.get::<_, String>(4)?),
                resource_id: row.get(5)?,
                position: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
        values
    };

    Ok(CatalogSnapshot { projects, environments, resources, bindings, surfaces })
}

fn resolve_snapshot(
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
        exports: resolve_exports(snapshot, project_id, Some(environment_id))?,
    })
}

fn resolve_exports(
    snapshot: &CatalogSnapshot,
    project_id: &str,
    environment_id: Option<&str>,
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
        for (index, export) in resource.exports.iter().enumerate() {
            let key = if resource.shape == ValueShape::Scalar && index == 0 {
                binding.key_override.as_ref().unwrap_or(&export.key).clone()
            } else {
                export.key.clone()
            };
            let current_is_environment = matches!(binding.scope, BindingScope::Environment { .. });
            let resolved = ResolvedExport {
                key: key.clone(),
                binding_id: binding.id.clone(),
                resource_id: resource.id.clone(),
                resource_name: resource.name.clone(),
                sensitive: export.sensitive,
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
    for project in &snapshot.projects {
        let environments: Vec<&Environment> = snapshot
            .environments
            .iter()
            .filter(|environment| environment.project_id == project.id)
            .collect();
        if environments.is_empty() {
            resolve_exports(snapshot, &project.id, None)?;
        } else {
            for environment in environments {
                resolve_snapshot(snapshot, &project.id, &environment.id)?;
            }
        }
    }
    Ok(())
}

fn validate_project(project: &Project) -> CatalogResult<()> {
    require_id(&project.id, "project id")?;
    require_name(&project.name, "project name")?;
    require_absolute_path(&project.path, "project path")
}

fn validate_environment(environment: &Environment) -> CatalogResult<()> {
    require_id(&environment.id, "environment id")?;
    require_id(&environment.project_id, "environment project id")?;
    require_name(&environment.name, "environment name")
}

fn validate_resource(resource: &Resource) -> CatalogResult<()> {
    require_id(&resource.id, "resource id")?;
    require_name(&resource.name, "resource name")?;
    if let Some(key) = &resource.default_env_key {
        require_env_key(key)?;
    }
    let mut keys = HashSet::new();
    for export in &resource.exports {
        require_env_key(&export.key)?;
        if !keys.insert(&export.key) {
            return Err(CatalogError::Validation(format!(
                "resource {:?} exports duplicate key {:?}",
                resource.id, export.key
            )));
        }
    }

    match resource.shape {
        ValueShape::Scalar if resource.exports.len() != 1 => {
            return Err(CatalogError::Validation(
                "scalar resources must declare exactly one export".to_string(),
            ))
        }
        ValueShape::KeyValueSet if resource.exports.is_empty() => {
            return Err(CatalogError::Validation(
                "key_value_set resources must declare at least one export".to_string(),
            ))
        }
        ValueShape::Bytes if !resource.exports.is_empty() => {
            return Err(CatalogError::Validation(
                "bytes resources cannot declare environment exports".to_string(),
            ))
        }
        ValueShape::Socket if resource.exports.len() != 1 => {
            return Err(CatalogError::Validation(
                "socket resources must declare exactly one endpoint export".to_string(),
            ))
        }
        _ => {}
    }

    match (&resource.kind, &resource.shape, &resource.source) {
        (ResourceKind::SharedSecret, ValueShape::Scalar, ResourceSource::SecretRef { .. }) => {
            if resource.default_env_key.is_none() {
                return Err(CatalogError::Validation(
                    "shared_secret requires default_env_key".to_string(),
                ));
            }
        }
        (ResourceKind::Secret, ValueShape::Scalar | ValueShape::Bytes, ResourceSource::SecretRef { .. }) => {}
        (ResourceKind::EnvFile, ValueShape::KeyValueSet, ResourceSource::SecretRef { .. }) => {}
        (ResourceKind::Literal, ValueShape::Scalar, ResourceSource::Literal { .. }) => {}
        (
            ResourceKind::Command,
            ValueShape::Scalar | ValueShape::KeyValueSet | ValueShape::Bytes,
            ResourceSource::Command { argv },
        ) if !argv.is_empty() => {}
        (ResourceKind::SshAgent, ValueShape::Socket, ResourceSource::Socket { endpoint }) => {
            require_absolute_path(endpoint, "ssh agent endpoint")?;
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
        && resource.default_env_key.as_ref().is_some_and(|key| key != &resource.exports[0].key)
    {
        return Err(CatalogError::Validation(
            "default_env_key must match the scalar export key".to_string(),
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

fn validate_surface(surface: &Surface) -> CatalogResult<()> {
    require_id(&surface.id, "surface id")?;
    require_id(&surface.environment_id, "surface environment id")?;
    require_name(&surface.name, "surface name")?;
    require_absolute_path(&surface.path, "surface path")
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
    use crate::domain::ExportSpec;

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
            default_env_key: Some(key.to_string()),
            exports: vec![ExportSpec { key: key.to_string(), sensitive: true }],
            source: ResourceSource::SecretRef { secret_id: format!("secret-{id}") },
            detail: None,
        }
    }

    fn binding(id: &str, resource_id: &str, scope: BindingScope) -> Binding {
        Binding {
            id: id.to_string(),
            project_id: "floria".to_string(),
            scope,
            resource_id: resource_id.to_string(),
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
    fn snapshot_round_trips_typed_metadata_without_secret_values() {
        let (_dir, catalog) = catalog();
        let resource = scalar_resource("cloudflare", "CLOUDFLARE_API_TOKEN");
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
                resource_id: None,
                position: 0,
            })
            .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects, vec![project()]);
        assert_eq!(snapshot.environments, vec![environment()]);
        assert_eq!(snapshot.resources, vec![resource]);
        assert_eq!(snapshot.bindings.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("plaintext"));
    }

    #[test]
    fn conflicting_binding_is_rejected_and_transaction_rolls_back() {
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

        let error = catalog
            .upsert_binding(&binding("second-binding", "second", BindingScope::Common))
            .unwrap_err();
        assert!(matches!(error, CatalogError::Conflict { ref key, .. } if key == "TOKEN"));
        assert_eq!(catalog.snapshot().unwrap().bindings.len(), 1);
    }

    #[test]
    fn common_conflict_is_rejected_before_project_has_an_environment() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog.upsert_project(&project()).unwrap();
        catalog
            .upsert_resource(&scalar_resource("first", "TOKEN"))
            .unwrap();
        catalog
            .upsert_resource(&scalar_resource("second", "TOKEN"))
            .unwrap();
        catalog
            .upsert_binding(&binding("first-binding", "first", BindingScope::Common))
            .unwrap();
        let error = catalog
            .upsert_binding(&binding("second-binding", "second", BindingScope::Common))
            .unwrap_err();
        assert!(matches!(error, CatalogError::Conflict { ref key, .. } if key == "TOKEN"));
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
                default_env_key: None,
                exports: vec![ExportSpec { key: "LOG_LEVEL".to_string(), sensitive: false }],
                source: ResourceSource::SecretRef { secret_id: "secret-defaults".to_string() },
                detail: None,
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
