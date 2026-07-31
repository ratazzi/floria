use super::*;

pub(super) fn validate_project(project: &Project) -> CatalogResult<()> {
    require_id(&project.id, "project id")?;
    require_name(&project.name, "project name")?;
    require_normalized_absolute_path(&project.path, "project path")
}

pub(super) fn validate_checkout(checkout: &ProjectCheckout) -> CatalogResult<()> {
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

pub(super) fn validate_environment(environment: &Environment) -> CatalogResult<()> {
    require_id(&environment.id, "environment id")?;
    require_id(&environment.project_id, "environment project id")?;
    require_name(&environment.name, "environment name")
}

pub(super) fn validate_resource(resource: &Resource) -> CatalogResult<()> {
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
        (ResourceKind::SshAgent, ValueShape::Socket, ResourceSource::Socket) => {
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

pub(super) fn validate_binding(binding: &Binding) -> CatalogResult<()> {
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

pub(super) fn require_entry_address(value: &str) -> CatalogResult<()> {
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

pub(super) fn is_ssh_identity_address(value: &str) -> bool {
    value
        .strip_prefix("ssh/sha256/")
        .is_some_and(|digest| {
            digest.len() == 43
                && digest
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        })
}

pub(super) fn validate_surface(surface: &Surface) -> CatalogResult<()> {
    require_id(&surface.id, "surface id")?;
    require_path_component(&surface.id, "surface id")?;
    require_id(&surface.environment_id, "surface environment id")?;
    require_name(&surface.name, "surface name")?;
    match (surface.kind.is_file(), surface.path.as_deref()) {
        (true, Some(path)) => require_normalized_absolute_path(path, "surface path")?,
        (true, None) => {
            return Err(CatalogError::Validation(
                "file surface requires a project path".to_string(),
            ))
        }
        (false, None) => {}
        (false, Some(_)) => {
            return Err(CatalogError::Validation(
                "capability surface cannot have a project path".to_string(),
            ))
        }
    }
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

pub(super) fn validate_ssh_route(route: &crate::domain::SshRouteSpec) -> CatalogResult<()> {
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

pub(super) fn validate_ssh_route_conflicts(snapshot: &CatalogSnapshot) -> CatalogResult<()> {
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

pub(super) fn require_id(value: &str, label: &str) -> CatalogResult<()> {
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

pub(super) fn require_name(value: &str, label: &str) -> CatalogResult<()> {
    if value.trim().is_empty() {
        Err(CatalogError::Validation(format!("{label} cannot be empty")))
    } else {
        Ok(())
    }
}

pub(super) fn require_env_key(key: &str) -> CatalogResult<()> {
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

pub(super) fn require_absolute_path(path: &Path, label: &str) -> CatalogResult<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(CatalogError::Validation(format!(
            "{label} must be absolute: {}",
            path.display()
        )))
    }
}

pub(super) fn require_normalized_absolute_path(path: &Path, label: &str) -> CatalogResult<()> {
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

pub(super) fn surface_relative_path<'a>(path: &'a Path, project_path: &Path) -> CatalogResult<&'a Path> {
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

pub(super) fn require_path_component(value: &str, label: &str) -> CatalogResult<()> {
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

pub(super) fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub(super) fn require_exists(conn: &Connection, table: &str, id: &str, kind: &str) -> CatalogResult<()> {
    let sql = format!("SELECT 1 FROM {table} WHERE id = ?1");
    let exists = conn.query_row(&sql, [id], |_| Ok(())).optional()?.is_some();
    if exists {
        Ok(())
    } else {
        Err(CatalogError::NotFound(format!("{kind} {id}")))
    }
}

pub(super) fn remove_one(conn: &Connection, table: &str, id: &str, kind: &str) -> CatalogResult<()> {
    let sql = format!("DELETE FROM {table} WHERE id = ?1");
    if conn.execute(&sql, [id])? == 1 {
        Ok(())
    } else {
        Err(CatalogError::NotFound(format!("{kind} {id}")))
    }
}

pub(super) fn decode_json<T: serde::de::DeserializeOwned>(
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

pub(super) fn invalid_value(column: usize, value: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown catalog enum value {value:?}"),
        )),
    )
}
