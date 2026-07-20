use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use accessfs_catalog::{Catalog, CatalogResult, CatalogSnapshot};

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
        Self::start_inner(path, catalog, None)
    }

    pub fn start_observed(
        path: &Path,
        catalog: Catalog,
        observer: Arc<dyn CatalogObserver>,
    ) -> io::Result<Self> {
        Self::start_inner(path, catalog, Some(observer))
    }

    fn start_inner(
        path: &Path,
        catalog: Catalog,
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
            .spawn(move || accept_loop(listener, catalog, observer))?;

        Ok(ControlServer { socket_path: path.to_path_buf() })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

fn accept_loop(
    listener: UnixListener,
    catalog: Arc<Catalog>,
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
        let observer = observer.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("accessfs-control-conn".to_string())
            .spawn(move || handle_connection(stream, catalog, observer))
        {
            tracing::warn!(%error, "spawning control connection failed");
        }
    }
}

fn handle_connection(
    mut stream: UnixStream,
    catalog: Arc<Catalog>,
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
        let outcome = match dispatch(&catalog, request.command) {
            Ok(result) => {
                if mutates_catalog {
                    notify_observer(&catalog, observer.as_deref());
                }
                ControlOutcome::Ok { result }
            }
            Err(error) => {
                ControlOutcome::Error { error: ControlErrorBody::from(&error) }
            }
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
    !matches!(
        command,
        ControlCommand::Ping
            | ControlCommand::Snapshot
            | ControlCommand::ResolveEnvironment { .. }
    )
}

fn notify_observer(catalog: &Catalog, observer: Option<&dyn CatalogObserver>) {
    let Some(observer) = observer else { return };
    match catalog.snapshot() {
        Ok(snapshot) => observer.catalog_changed(&snapshot),
        Err(error) => tracing::warn!(%error, "loading catalog snapshot for observer failed"),
    }
}

fn dispatch(catalog: &Catalog, command: ControlCommand) -> CatalogResult<ControlResult> {
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
    use accessfs_catalog::{Environment, Project};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

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
}
