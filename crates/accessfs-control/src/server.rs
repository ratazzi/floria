use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use accessfs_catalog::{
    Catalog, CatalogError, CatalogSnapshot, ExportSpec, Resource, ResourceKind, ResourceSource,
    ValueShape,
};
use accessfs_store::{NewSecret, SecretId, SecretStore, StoreError};

use crate::protocol::{
    read_msg, write_msg, ControlCommand, ControlErrorBody, ControlOutcome, ControlRequest,
    ControlResponse, ControlResult,
};

pub struct ControlServer {
    socket_path: PathBuf,
}

pub trait CatalogObserver: Send + Sync + 'static {
    fn catalog_changed(&self, snapshot: &CatalogSnapshot);
}

impl ControlServer {
    /// Start the catalog control socket. Each connection gets a dedicated request loop;
    /// authorization prompts continue to use the separate agent socket.
    pub fn start(path: &Path, catalog: Catalog) -> io::Result<Self> {
        Self::start_inner(path, catalog, None, None)
    }

    pub fn start_observed(
        path: &Path,
        catalog: Catalog,
        observer: Arc<dyn CatalogObserver>,
    ) -> io::Result<Self> {
        Self::start_inner(path, catalog, None, Some(observer))
    }

    pub fn start_runtime(
        path: &Path,
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        observer: Arc<dyn CatalogObserver>,
    ) -> io::Result<Self> {
        Self::start_inner(path, catalog, Some(store), Some(observer))
    }

    fn start_inner(
        path: &Path,
        catalog: Catalog,
        store: Option<Arc<dyn SecretStore>>,
        observer: Option<Arc<dyn CatalogObserver>>,
    ) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

        let catalog = Arc::new(catalog);
        std::thread::Builder::new()
            .name("accessfs-control-accept".to_string())
            .spawn(move || accept_loop(listener, catalog, store, observer))?;

        Ok(ControlServer { socket_path: path.to_path_buf() })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

fn accept_loop(
    listener: UnixListener,
    catalog: Arc<Catalog>,
    store: Option<Arc<dyn SecretStore>>,
    observer: Option<Arc<dyn CatalogObserver>>,
) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "control socket accept failed");
                continue;
            }
        };
        if !same_uid(&stream) {
            tracing::warn!("rejecting control connection from a different uid");
            continue;
        }
        let catalog = Arc::clone(&catalog);
        let store = store.clone();
        let observer = observer.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("accessfs-control-conn".to_string())
            .spawn(move || handle_connection(stream, catalog, store, observer))
        {
            tracing::warn!(%error, "spawning control connection failed");
        }
    }
}

fn handle_connection(
    mut stream: UnixStream,
    catalog: Arc<Catalog>,
    store: Option<Arc<dyn SecretStore>>,
    observer: Option<Arc<dyn CatalogObserver>>,
) {
    loop {
        let request: ControlRequest = match read_msg(&mut stream) {
            Ok(request) => request,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                tracing::warn!(%error, "invalid control request");
                break;
            }
        };
        let mutates_catalog = mutates_catalog(&request.command);
        let outcome = match dispatch(&catalog, store.as_deref(), request.command) {
            Ok(result) => {
                if mutates_catalog {
                    notify_observer(&catalog, observer.as_deref());
                }
                ControlOutcome::Ok { result }
            }
            Err(error) => ControlOutcome::Error { error: error.body() },
        };
        if let Err(error) = write_msg(
            &mut stream,
            &ControlResponse { request_id: request.request_id, outcome },
        ) {
            tracing::warn!(%error, "writing control response failed");
            break;
        }
    }
}

fn mutates_catalog(command: &ControlCommand) -> bool {
    matches!(
        command,
        ControlCommand::ProjectUpsert { .. }
            | ControlCommand::ProjectCreate { .. }
            | ControlCommand::ProjectRemove { .. }
            | ControlCommand::EnvironmentUpsert { .. }
            | ControlCommand::EnvironmentRemove { .. }
            | ControlCommand::ResourceUpsert { .. }
            | ControlCommand::ResourceRemove { .. }
            | ControlCommand::BindingUpsert { .. }
            | ControlCommand::BindingRemove { .. }
            | ControlCommand::SurfaceUpsert { .. }
            | ControlCommand::SurfaceRemove { .. }
            | ControlCommand::SharedSecretCreate { .. }
    )
}

fn notify_observer(catalog: &Catalog, observer: Option<&dyn CatalogObserver>) {
    let Some(observer) = observer else { return };
    match catalog.snapshot() {
        Ok(snapshot) => observer.catalog_changed(&snapshot),
        Err(error) => tracing::warn!(%error, "loading catalog snapshot for observer failed"),
    }
}

#[derive(Debug)]
enum DispatchError {
    Catalog(CatalogError),
    Store(StoreError),
    Validation(String),
    StoreUnavailable,
}

impl DispatchError {
    fn body(&self) -> ControlErrorBody {
        match self {
            DispatchError::Catalog(error) => ControlErrorBody::from(error),
            DispatchError::Store(error) => ControlErrorBody::from(error),
            DispatchError::Validation(message) => ControlErrorBody {
                code: "validation".to_string(),
                message: message.clone(),
            },
            DispatchError::StoreUnavailable => ControlErrorBody {
                code: "secret_store_unavailable".to_string(),
                message: "secret store is unavailable on this control server".to_string(),
            },
        }
    }
}

impl From<CatalogError> for DispatchError {
    fn from(error: CatalogError) -> Self {
        DispatchError::Catalog(error)
    }
}

impl From<StoreError> for DispatchError {
    fn from(error: StoreError) -> Self {
        DispatchError::Store(error)
    }
}

fn dispatch(
    catalog: &Catalog,
    store: Option<&dyn SecretStore>,
    command: ControlCommand,
) -> Result<ControlResult, DispatchError> {
    match command {
        ControlCommand::Ping => {
            Ok(ControlResult::Pong { schema_version: catalog.schema_version() })
        }
        ControlCommand::Snapshot => Ok(ControlResult::Snapshot(catalog.snapshot()?)),
        ControlCommand::ResolveEnvironment { project_id, environment_id } => Ok(
            ControlResult::ResolvedEnvironment(
                catalog.resolve_environment(&project_id, &environment_id)?,
            ),
        ),
        ControlCommand::ResourceUsage { resource_id } => {
            Ok(ControlResult::ResourceUsage(catalog.resource_usage(&resource_id)?))
        }
        ControlCommand::SharedSecretCreate {
            resource_id,
            name,
            default_env_key,
            value,
        } => create_shared_secret(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            name,
            default_env_key,
            value,
        ),
        ControlCommand::SharedSecretRotate { resource_id, value } => rotate_shared_secret(
            catalog,
            store.ok_or(DispatchError::StoreUnavailable)?,
            resource_id,
            value,
        ),
        ControlCommand::ProjectCreate { project, environment, surface } => {
            create_project_workspace(catalog, project, environment, surface)
        }
        ControlCommand::ProjectUpsert { project } => {
            catalog.upsert_project(&project)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ProjectRemove { id } => {
            catalog.remove_project(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::EnvironmentUpsert { environment } => {
            catalog.upsert_environment(&environment)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::EnvironmentRemove { id } => {
            catalog.remove_environment(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ResourceUpsert { resource } => {
            catalog.upsert_resource(&resource)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::ResourceRemove { id } => {
            catalog.remove_resource(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::BindingUpsert { binding } => {
            catalog.upsert_binding(&binding)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::BindingRemove { id } => {
            catalog.remove_binding(&id)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::SurfaceUpsert { surface } => {
            catalog.upsert_surface(&surface)?;
            Ok(ControlResult::Empty)
        }
        ControlCommand::SurfaceRemove { id } => {
            catalog.remove_surface(&id)?;
            Ok(ControlResult::Empty)
        }
    }
}

fn create_project_workspace(
    catalog: &Catalog,
    project: accessfs_catalog::Project,
    environment: accessfs_catalog::Environment,
    surface: accessfs_catalog::Surface,
) -> Result<ControlResult, DispatchError> {
    if environment.project_id != project.id {
        return Err(DispatchError::Validation(format!(
            "environment project {:?} does not match project {:?}",
            environment.project_id, project.id
        )));
    }
    if surface.environment_id != environment.id {
        return Err(DispatchError::Validation(format!(
            "surface environment {:?} does not match environment {:?}",
            surface.environment_id, environment.id
        )));
    }

    let snapshot = catalog.snapshot()?;
    for (kind, id, exists) in [
        ("project", &project.id, snapshot.projects.iter().any(|item| item.id == project.id)),
        (
            "environment",
            &environment.id,
            snapshot.environments.iter().any(|item| item.id == environment.id),
        ),
        ("surface", &surface.id, snapshot.surfaces.iter().any(|item| item.id == surface.id)),
    ] {
        if exists {
            return Err(DispatchError::Catalog(CatalogError::AlreadyExists {
                kind,
                id: id.clone(),
            }));
        }
    }

    catalog.upsert_project(&project)?;
    if let Err(error) = catalog.upsert_environment(&environment) {
        rollback_project_create(catalog, &project.id);
        return Err(DispatchError::Catalog(error));
    }
    if let Err(error) = catalog.upsert_surface(&surface) {
        rollback_project_create(catalog, &project.id);
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::Empty)
}

fn rollback_project_create(catalog: &Catalog, project_id: &str) {
    if let Err(error) = catalog.remove_project(project_id) {
        tracing::warn!(%project_id, %error, "rolling back project create failed");
    }
}

fn create_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    name: String,
    default_env_key: String,
    value: crate::protocol::SecretValue,
) -> Result<ControlResult, DispatchError> {
    if value.as_bytes().is_empty() {
        return Err(DispatchError::Validation(
            "shared secret value cannot be empty".to_string(),
        ));
    }
    let mut resource = Resource {
        id: resource_id,
        name,
        kind: ResourceKind::SharedSecret,
        shape: ValueShape::Scalar,
        default_env_key: Some(default_env_key.clone()),
        exports: vec![ExportSpec { key: default_env_key, sensitive: true }],
        source: ResourceSource::SecretRef { secret_id: "pending-secret-id".to_string() },
        detail: None,
    };
    catalog.validate_resource(&resource)?;
    match catalog.resource(&resource.id) {
        Ok(_) => {
            return Err(DispatchError::Catalog(CatalogError::AlreadyExists {
                kind: "resource",
                id: resource.id.clone(),
            }))
        }
        Err(CatalogError::NotFound(_)) => {}
        Err(error) => return Err(DispatchError::Catalog(error)),
    }

    let secret_id = store.put(NewSecret::managed(resource.name.clone()), value.as_bytes())?;
    resource.source = ResourceSource::SecretRef { secret_id: secret_id.to_string() };
    if let Err(error) = catalog.create_resource(&resource) {
        if let Err(cleanup_error) = store.delete(&secret_id) {
            tracing::warn!(%secret_id, %cleanup_error, "cleaning up unreferenced shared secret failed");
        }
        return Err(DispatchError::Catalog(error));
    }
    Ok(ControlResult::SharedSecretCreated { resource, version: 1 })
}

fn rotate_shared_secret(
    catalog: &Catalog,
    store: &dyn SecretStore,
    resource_id: String,
    value: crate::protocol::SecretValue,
) -> Result<ControlResult, DispatchError> {
    if value.as_bytes().is_empty() {
        return Err(DispatchError::Validation(
            "shared secret value cannot be empty".to_string(),
        ));
    }
    let resource = catalog.resource(&resource_id)?;
    if resource.kind != ResourceKind::SharedSecret {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} is not a shared secret"
        )));
    }
    let ResourceSource::SecretRef { secret_id } = resource.source else {
        return Err(DispatchError::Validation(format!(
            "resource {resource_id:?} does not reference a stored secret"
        )));
    };
    let secret_id: SecretId = secret_id.parse()?;
    let version = store.append_version(&secret_id, value.as_bytes())?;
    Ok(ControlResult::SharedSecretRotated { resource_id, version })
}

fn same_uid(stream: &UnixStream) -> bool {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: valid socket fd and writable stack out-parameters.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    // SAFETY: geteuid has no preconditions.
    result == 0 && uid == unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ControlClient;
    use accessfs_catalog::{Environment, Project, Surface, SurfaceKind};
    use accessfs_store::{
        SecretOrigin, SecretRecord, StoreResult, VersionRecord,
    };
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    const FIXTURE_SECRET_ID: &str = "00000000-0000-0000-0000-000000000101";

    struct FixtureStore {
        entries: Mutex<HashMap<String, Vec<Vec<u8>>>>,
    }

    impl FixtureStore {
        fn new() -> Self {
            FixtureStore { entries: Mutex::new(HashMap::new()) }
        }
    }

    impl SecretStore for FixtureStore {
        fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId> {
            assert_eq!(
                meta.origin,
                SecretOrigin::Managed { label: "Fixture Shared Secret".to_string() }
            );
            let id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
            self.entries
                .lock()
                .unwrap()
                .insert(id.to_string(), vec![plaintext.to_vec()]);
            Ok(id)
        }

        fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            Ok(Zeroizing::new(entries[id.as_str()].last().unwrap().clone()))
        }

        fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            Ok(Zeroizing::new(entries[id.as_str()][(version - 1) as usize].clone()))
        }

        fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
            let mut entries = self.entries.lock().unwrap();
            let versions = entries.get_mut(id.as_str()).unwrap();
            versions.push(plaintext.to_vec());
            Ok(versions.len() as u32)
        }

        fn history(&self, _id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            unimplemented!()
        }

        fn set_head(&self, _id: &SecretId, _version: u32) -> StoreResult<()> {
            unimplemented!()
        }

        fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            Ok(entries.get(id.as_str()).map(|versions| SecretRecord {
                id: id.clone(),
                origin: SecretOrigin::Managed { label: "Fixture Shared Secret".to_string() },
                mode: 0o600,
                size: versions.last().unwrap().len() as u64,
                created: "fixture-time".to_string(),
                current_version: versions.len() as u32,
            }))
        }

        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            unimplemented!()
        }

        fn get_by_path(&self, _source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            Ok(None)
        }

        fn delete(&self, id: &SecretId) -> StoreResult<()> {
            self.entries.lock().unwrap().remove(id.as_str());
            Ok(())
        }
    }

    struct SnapshotObserver {
        notifications: AtomicUsize,
        latest: Mutex<Option<CatalogSnapshot>>,
    }

    impl CatalogObserver for SnapshotObserver {
        fn catalog_changed(&self, snapshot: &CatalogSnapshot) {
            self.notifications.fetch_add(1, Ordering::Relaxed);
            *self.latest.lock().unwrap() = Some(snapshot.clone());
        }
    }

    #[test]
    fn client_can_mutate_and_snapshot_catalog_over_separate_socket() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let server = ControlServer::start(&socket, catalog).unwrap();
        assert_eq!(
            std::fs::metadata(server.socket_path()).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut client = ControlClient::connect(&socket).unwrap();
        assert_eq!(
            client.request(ControlCommand::Ping).unwrap(),
            ControlResult::Pong { schema_version: 1 }
        );
        client
            .request(ControlCommand::ProjectUpsert {
                project: Project {
                    id: "floria".to_string(),
                    name: "floria".to_string(),
                    path: PathBuf::from("/workspace/floria"),
                },
            })
            .unwrap();
        client
            .request(ControlCommand::EnvironmentUpsert {
                environment: Environment {
                    id: "development".to_string(),
                    project_id: "floria".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                },
            })
            .unwrap();

        let ControlResult::Snapshot(snapshot) =
            client.request(ControlCommand::Snapshot).unwrap()
        else {
            panic!("expected snapshot");
        };
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.environments.len(), 1);
    }

    #[test]
    fn project_create_builds_workspace_with_one_observer_notification() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_observed(
            &socket,
            catalog.clone(),
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        client
            .request(ControlCommand::ProjectCreate {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                },
                environment: Environment {
                    id: "fixture-development".to_string(),
                    project_id: "fixture-project".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                },
                surface: Surface {
                    id: "fixture-dotenv".to_string(),
                    environment_id: "fixture-development".to_string(),
                    name: ".env".to_string(),
                    kind: SurfaceKind::DotenvFile,
                    path: PathBuf::from("/fixture/project/.env"),
                    resource_id: None,
                    position: 0,
                },
            })
            .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.environments.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn project_create_rolls_back_when_surface_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let _server = ControlServer::start(&socket, catalog.clone()).unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let error = client
            .request(ControlCommand::ProjectCreate {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                },
                environment: Environment {
                    id: "fixture-development".to_string(),
                    project_id: "fixture-project".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                },
                surface: Surface {
                    id: "fixture-dotenv".to_string(),
                    environment_id: "fixture-development".to_string(),
                    name: ".env".to_string(),
                    kind: SurfaceKind::DotenvFile,
                    path: PathBuf::from("/outside/.env"),
                    resource_id: None,
                    position: 0,
                },
            })
            .unwrap_err();

        assert!(error.to_string().contains("validation"));
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.projects.is_empty());
        assert!(snapshot.environments.is_empty());
        assert!(snapshot.surfaces.is_empty());
    }

    #[test]
    fn validation_error_returns_structured_control_error() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let _server = ControlServer::start(&socket, catalog).unwrap();
        let mut stream = UnixStream::connect(&socket).unwrap();
        write_msg(
            &mut stream,
            &ControlRequest {
                request_id: 11,
                command: ControlCommand::ProjectUpsert {
                    project: Project {
                        id: "bad project".to_string(),
                        name: "Bad".to_string(),
                        path: PathBuf::from("relative"),
                    },
                },
            },
        )
        .unwrap();
        let response: ControlResponse = read_msg(&mut stream).unwrap();
        assert_eq!(response.request_id, 11);
        match response.outcome {
            ControlOutcome::Error { error } => assert_eq!(error.code, "validation"),
            ControlOutcome::Ok { .. } => panic!("expected validation error"),
        }
    }

    #[test]
    fn successful_mutation_refreshes_observer_but_queries_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_observed(
            &socket,
            catalog,
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        client.request(ControlCommand::Ping).unwrap();
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 0);
        client
            .request(ControlCommand::ProjectUpsert {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                },
            })
            .unwrap();
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
        assert_eq!(
            observer.latest.lock().unwrap().as_ref().unwrap().projects[0].id,
            "fixture-project"
        );
    }

    #[test]
    fn shared_secret_create_and_rotate_over_ipc_only_store_reference_in_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        let observer: Arc<dyn CatalogObserver> = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            observer,
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::SharedSecretCreate {
                resource_id: "fixture-shared-secret".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: "FIXTURE_TOKEN".to_string(),
                value: crate::protocol::SecretValue::new("fixture-value-one"),
            })
            .unwrap();
        assert!(matches!(
            created,
            ControlResult::SharedSecretCreated { version: 1, .. }
        ));
        let resource = catalog.resource("fixture-shared-secret").unwrap();
        assert_eq!(
            resource.source,
            ResourceSource::SecretRef { secret_id: FIXTURE_SECRET_ID.to_string() }
        );
        assert!(!serde_json::to_string(&catalog.snapshot().unwrap())
            .unwrap()
            .contains("fixture-value-one"));

        let rotated = client
            .request(ControlCommand::SharedSecretRotate {
                resource_id: "fixture-shared-secret".to_string(),
                value: crate::protocol::SecretValue::new("fixture-value-two"),
            })
            .unwrap();
        assert_eq!(
            rotated,
            ControlResult::SharedSecretRotated {
                resource_id: "fixture-shared-secret".to_string(),
                version: 2,
            }
        );
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(store.get_version(&secret_id, 1).unwrap().as_slice(), b"fixture-value-one");
        assert_eq!(store.get_version(&secret_id, 2).unwrap().as_slice(), b"fixture-value-two");
    }
}
