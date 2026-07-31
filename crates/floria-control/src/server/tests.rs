    use super::*;
    use floria_catalog::SurfaceInput;
    use floria_core::audit::AuditLog;
    use floria_core::identity::{ProcSummary, ProcessIdentity};
    use floria_platform::{
        PeerVerificationError, SameUserPeerVerifier, SocketPeerVerifier, VerifiedPeer,
    };
    use crate::client::ControlClient;
    use floria_catalog::{
        Binding, BindingScope, EntrySelection, Environment, ItemLink, Project, ProjectCheckout,
        ProjectCheckoutKind, Surface, SurfaceKind,
    };
    use floria_store::{
        SecretOrigin, SecretRecord, StoreResult, VersionRecord,
    };
    use std::collections::{HashMap, HashSet};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    fn test_peer_verifier() -> Arc<dyn SocketPeerVerifier> {
        Arc::new(SameUserPeerVerifier)
    }

    struct RejectAllPeers;

    impl SocketPeerVerifier for RejectAllPeers {
        fn verify(&self, _stream: &UnixStream) -> Result<VerifiedPeer, PeerVerificationError> {
            Err(PeerVerificationError::UntrustedCode {
                pid: std::process::id() as i32,
                executable: "fixture client".to_string(),
                trusted: "fixture trusted app".to_string(),
            })
        }
    }

    struct FixtureBackupService;

    impl BackupService for FixtureBackupService {
        fn create(
            &self,
            _catalog: &Catalog,
            destination: &Path,
        ) -> Result<BackupReport, String> {
            Ok(BackupReport {
                path: destination.to_path_buf(),
                catalog_schema: Catalog::current_schema_version(),
                projects: 1,
                resources: 2,
                secrets: 3,
                versions: 4,
                plaintext_bytes: 5,
                files: 6,
            })
        }

        fn verify(&self, backup: &Path) -> Result<BackupReport, String> {
            Ok(BackupReport {
                path: backup.to_path_buf(),
                catalog_schema: Catalog::current_schema_version(),
                projects: 1,
                resources: 2,
                secrets: 3,
                versions: 4,
                plaintext_bytes: 5,
                files: 6,
            })
        }
    }

    const FIXTURE_SECRET_ID: &str = "00000000-0000-0000-0000-000000000101";

    struct FixtureSecretMetadata {
        origin: SecretOrigin,
        mode: u32,
        enforcement: Enforcement,
        metadata: ItemMetadata,
        environment_ids: Option<Vec<String>>,
    }

    struct FixtureStore {
        entries: Mutex<HashMap<String, Vec<Vec<u8>>>>,
        metadata: Mutex<HashMap<String, FixtureSecretMetadata>>,
        heads: Mutex<HashMap<String, u32>>,
        mutation_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        get_calls: AtomicUsize,
    }

    impl FixtureStore {
        fn new() -> Self {
            FixtureStore {
                entries: Mutex::new(HashMap::new()),
                metadata: Mutex::new(HashMap::new()),
                heads: Mutex::new(HashMap::new()),
                mutation_hook: Mutex::new(None),
                get_calls: AtomicUsize::new(0),
            }
        }

        fn after_next_mutation(&self, hook: impl FnOnce() + Send + 'static) {
            *self.mutation_hook.lock().unwrap() = Some(Box::new(hook));
        }

        fn run_mutation_hook(&self) {
            if let Some(hook) = self.mutation_hook.lock().unwrap().take() {
                hook();
            }
        }
    }

    fn project_output_import(path: &Path, project_path: &Path) -> DiscoveryImport {
        DiscoveryImport {
            path: path.to_path_buf(),
            destination: DiscoveryImportDestination::ProjectOutput {
                project_path: project_path.to_path_buf(),
                output_path: path.to_path_buf(),
            },
            source_disposition: DiscoverySourceDisposition::ReplaceWithSurface,
        }
    }

    fn project_file_import(path: &Path, project_path: &Path) -> DiscoveryImport {
        DiscoveryImport {
            path: path.to_path_buf(),
            destination: DiscoveryImportDestination::ProjectFile {
                project_path: project_path.to_path_buf(),
            },
            source_disposition: DiscoverySourceDisposition::ProtectInPlace,
        }
    }

    fn library_import(
        path: &Path,
        source_disposition: DiscoverySourceDisposition,
    ) -> DiscoveryImport {
        DiscoveryImport {
            path: path.to_path_buf(),
            destination: DiscoveryImportDestination::Library,
            source_disposition,
        }
    }

    #[test]
    fn backup_operations_use_the_runtime_service_and_require_absolute_paths() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let backup = FixtureBackupService;
        let services = DispatchServices {
            backup: Some(&backup),
            ..DispatchServices::default()
        };
        let destination = directory.path().join("new-backup");

        let created = dispatch(
            &catalog,
            services,
            ControlCommand::BackupCreate {
                destination: destination.clone(),
            },
        )
        .unwrap();
        assert!(matches!(
            created,
            ControlResult::Backup(BackupReport { path, versions: 4, .. }) if path == destination
        ));

        let verified = dispatch(
            &catalog,
            services,
            ControlCommand::BackupVerify {
                backup: destination.clone(),
            },
        )
        .unwrap();
        assert!(matches!(
            verified,
            ControlResult::Backup(BackupReport { path, files: 6, .. }) if path == destination
        ));

        let relative = dispatch(
            &catalog,
            services,
            ControlCommand::BackupCreate {
                destination: PathBuf::from("relative-backup"),
            },
        )
        .unwrap_err();
        assert!(matches!(relative, DispatchError::Validation(_)));
    }

    fn project_outputs_import(
        path: &Path,
        outputs: Vec<(&Path, &Path)>,
        source_disposition: DiscoverySourceDisposition,
    ) -> DiscoveryImport {
        DiscoveryImport {
            path: path.to_path_buf(),
            destination: DiscoveryImportDestination::ProjectOutputs {
                outputs: outputs
                    .into_iter()
                    .map(|(project_path, output_path)| crate::protocol::DiscoveryProjectOutput {
                        project_path: project_path.to_path_buf(),
                        output_path: output_path.to_path_buf(),
                    })
                    .collect(),
            },
            source_disposition,
        }
    }

    impl SecretStore for FixtureStore {
        fn put(&self, meta: NewSecret, plaintext: &[u8]) -> StoreResult<SecretId> {
            if let SecretOrigin::Managed { label } = &meta.origin {
                assert!(matches!(
                    label.as_str(),
                    "Fixture Shared Secret"
                        | "Fixture Env File"
                        | "Fixture INI File"
                        | "Fixture SSH Identity"
                        | "id_ed25519"
                        | "DISCOVERED_TOKEN"
                        | "OPTIONAL_NEW_TOKEN"
                        | "credentials"
                        | "DEBUG"
                        | ".env"
                        | ".env.shared"
                ));
            }
            let id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
            self.entries
                .lock()
                .unwrap()
                .insert(id.to_string(), vec![plaintext.to_vec()]);
            self.metadata
                .lock()
                .unwrap()
                .insert(
                    id.to_string(),
                    FixtureSecretMetadata {
                        origin: meta.origin,
                        mode: meta.mode,
                        enforcement: meta.enforcement,
                        metadata: ItemMetadata::default(),
                        environment_ids: None,
                    },
                );
            self.heads.lock().unwrap().insert(id.to_string(), 1);
            self.run_mutation_hook();
            Ok(id)
        }

        fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            self.get_calls.fetch_add(1, Ordering::Relaxed);
            let entries = self.entries.lock().unwrap();
            let head = self.heads.lock().unwrap()[id.as_str()];
            Ok(Zeroizing::new(entries[id.as_str()][(head - 1) as usize].clone()))
        }

        fn get_version(&self, id: &SecretId, version: u32) -> StoreResult<Zeroizing<Vec<u8>>> {
            let entries = self.entries.lock().unwrap();
            Ok(Zeroizing::new(entries[id.as_str()][(version - 1) as usize].clone()))
        }

        fn append_version(&self, id: &SecretId, plaintext: &[u8]) -> StoreResult<u32> {
            let mut entries = self.entries.lock().unwrap();
            let versions = entries.get_mut(id.as_str()).unwrap();
            versions.push(plaintext.to_vec());
            let version = versions.len() as u32;
            drop(entries);
            self.heads.lock().unwrap().insert(id.to_string(), version);
            self.run_mutation_hook();
            Ok(version)
        }

        fn history(&self, id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            let entries = self.entries.lock().unwrap();
            Ok(entries[id.as_str()]
                .iter()
                .enumerate()
                .map(|(index, value)| VersionRecord {
                    version: index as u32 + 1,
                    size: value.len() as u64,
                    created: format!("fixture-time-{}", index + 1),
                    note: None,
                })
                .collect())
        }

        fn set_head(&self, id: &SecretId, version: u32) -> StoreResult<()> {
            let entries = self.entries.lock().unwrap();
            if version == 0 || version as usize > entries[id.as_str()].len() {
                return Err(StoreError::NotFound(format!("version {version}")));
            }
            drop(entries);
            self.heads.lock().unwrap().insert(id.to_string(), version);
            Ok(())
        }

        fn record(&self, id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            let metadata = self.metadata.lock().unwrap();
            let heads = self.heads.lock().unwrap();
            Ok(entries.get(id.as_str()).map(|versions| SecretRecord {
                id: id.clone(),
                origin: metadata[id.as_str()].origin.clone(),
                mode: metadata[id.as_str()].mode,
                size: versions[(heads[id.as_str()] - 1) as usize].len() as u64,
                created: "fixture-time".to_string(),
                current_version: heads[id.as_str()],
                enforcement: metadata[id.as_str()].enforcement,
                environment_ids: metadata[id.as_str()].environment_ids.clone(),
                metadata: metadata[id.as_str()].metadata.clone(),
            }))
        }

        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            let entries = self.entries.lock().unwrap();
            let metadata = self.metadata.lock().unwrap();
            let heads = self.heads.lock().unwrap();
            Ok(entries
                .iter()
                .map(|(id, versions)| SecretRecord {
                    id: id.parse().unwrap(),
                    origin: metadata[id].origin.clone(),
                    mode: metadata[id].mode,
                    size: versions[(heads[id] - 1) as usize].len() as u64,
                    created: "fixture-time".to_string(),
                    current_version: heads[id],
                    enforcement: metadata[id].enforcement,
                    environment_ids: metadata[id].environment_ids.clone(),
                    metadata: metadata[id].metadata.clone(),
                })
                .collect())
        }

        fn get_by_path(&self, source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            let id = self
                .metadata
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, metadata)| match &metadata.origin {
                    SecretOrigin::File { source_path: candidate }
                        if candidate == source_path => Some(id.clone()),
                    _ => None,
                });
            match id {
                Some(id) => self.record(&id.parse().unwrap()),
                None => Ok(None),
            }
        }

        fn update_settings(
            &self,
            id: &SecretId,
            item_metadata: ItemMetadata,
            enforcement: Enforcement,
            environment_ids: Option<Vec<String>>,
        ) -> StoreResult<()> {
            let mut metadata = self.metadata.lock().unwrap();
            let entry = metadata.get_mut(id.as_str()).unwrap();
            entry.metadata = item_metadata;
            entry.enforcement = enforcement;
            entry.environment_ids = environment_ids;
            Ok(())
        }

        fn delete(&self, id: &SecretId) -> StoreResult<()> {
            self.entries.lock().unwrap().remove(id.as_str());
            self.metadata.lock().unwrap().remove(id.as_str());
            self.heads.lock().unwrap().remove(id.as_str());
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

    struct FixturePolicy {
        status: Mutex<PolicyModeStatus>,
        grants: Mutex<Vec<ActiveGrant>>,
    }

    struct FixtureSshDiscovery;

    impl SshIdentityDiscovery for FixtureSshDiscovery {
        fn discover(&self, endpoint: &Path) -> io::Result<Vec<SshIdentity>> {
            Ok(vec![SshIdentity {
                address: "ssh/sha256/fixture-address".to_string(),
                fingerprint: "SHA256:fixture-fingerprint".to_string(),
                comment: endpoint.display().to_string(),
            }])
        }
    }

    impl RuntimePolicyController for FixturePolicy {
        fn policy_mode(&self) -> PolicyModeStatus {
            *self.status.lock().unwrap()
        }

        fn set_policy_mode(
            &self,
            mode: PolicyMode,
            duration_secs: Option<u64>,
        ) -> io::Result<PolicyModeStatus> {
            let status = PolicyModeStatus {
                mode,
                expires_at: duration_secs.map(|seconds| 1_800_000_000 + seconds as i64),
            };
            *self.status.lock().unwrap() = status;
            Ok(status)
        }

        fn active_grants(&self) -> io::Result<Vec<ActiveGrant>> {
            Ok(self.grants.lock().unwrap().clone())
        }

        fn revoke_grant(&self, id: &str) -> io::Result<bool> {
            let mut grants = self.grants.lock().unwrap();
            let before = grants.len();
            grants.retain(|grant| grant.id != id);
            Ok(grants.len() != before)
        }

        fn clear_grants(&self) -> io::Result<()> {
            self.grants.lock().unwrap().clear();
            Ok(())
        }
    }

    #[test]
    fn project_checkout_discovery_and_lifecycle_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("main");
        let worktree = dir.path().join("feature");
        let worktree_git = primary.join(".git/worktrees/feature");
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::create_dir(&worktree).unwrap();
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .unwrap();
        std::fs::write(worktree_git.join("commondir"), "../..\n").unwrap();
        std::fs::write(
            worktree_git.join("gitdir"),
            format!("{}\n", worktree.join(".git").display()),
        )
        .unwrap();
        let primary = std::fs::canonicalize(primary).unwrap();
        let worktree = std::fs::canonicalize(worktree).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary.clone(),
                ..Default::default()
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            })
            .unwrap();
        let result = dispatch(
            &catalog,
            DispatchServices::default(),
            ControlCommand::ProjectCheckoutDiscover {
                project_id: "fixture-project".to_string(),
            },
        )
        .unwrap();
        let ControlResult::ProjectCheckoutDiscovery(discovery) = result else {
            panic!("unexpected checkout discovery result")
        };
        assert_eq!(discovery.checkouts.len(), 2);
        assert_eq!(
            discovery
                .checkouts
                .iter()
                .find(|candidate| candidate.path == worktree)
                .unwrap()
                .managed_checkout_id,
            None
        );

        let result = dispatch(
            &catalog,
            DispatchServices::default(),
            ControlCommand::ProjectCheckoutInventory,
        )
        .unwrap();
        let ControlResult::ProjectCheckoutInventory(inventory) = result else {
            panic!("unexpected checkout inventory result")
        };
        assert_eq!(inventory.revision, 0);
        assert_eq!(inventory.projects, vec![discovery.clone()]);

        let checkout = floria_catalog::ProjectCheckout {
            id: "fixture-worktree".to_string(),
            project_id: "fixture-project".to_string(),
            path: worktree.clone(),
            environment_id: Some("fixture-development".to_string()),
            kind: floria_catalog::ProjectCheckoutKind::Worktree,
            git_common_dir: Some(discovery.common_dir),
        };
        dispatch(
            &catalog,
            DispatchServices::default(),
            ControlCommand::ProjectCheckoutUpsert {
                checkout: checkout.clone(),
            },
        )
        .unwrap();
        assert!(catalog.snapshot().unwrap().checkouts.contains(&checkout));
        dispatch(
            &catalog,
            DispatchServices::default(),
            ControlCommand::ProjectCheckoutRemove {
                id: checkout.id.clone(),
            },
        )
        .unwrap();
        assert!(!catalog.snapshot().unwrap().checkouts.contains(&checkout));
    }

    #[test]
    fn managed_checkout_discovery_reports_a_foreign_protected_file_link() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("main");
        let worktree = dir.path().join("feature");
        let worktree_git = primary.join(".git/worktrees/feature");
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::create_dir(&worktree).unwrap();
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .unwrap();
        std::fs::write(worktree_git.join("commondir"), "../..\n").unwrap();
        std::fs::write(
            worktree_git.join("gitdir"),
            format!("{}\n", worktree.join(".git").display()),
        )
        .unwrap();
        let primary = std::fs::canonicalize(primary).unwrap();
        let worktree = std::fs::canonicalize(worktree).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: primary.clone(),
                ..Default::default()
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            })
            .unwrap();
        catalog
            .upsert_checkout(&ProjectCheckout {
                id: "fixture-worktree".to_string(),
                project_id: "fixture-project".to_string(),
                path: worktree.clone(),
                environment_id: Some("fixture-development".to_string()),
                kind: ProjectCheckoutKind::Worktree,
                ..Default::default()
            })
            .unwrap();
        let store = FixtureStore::new();
        store
            .put(
                NewSecret::file(primary.join(".envrc"), 0o600),
                b"export FIXTURE_VALUE='fixture'\n",
            )
            .unwrap();
        symlink("../main/.envrc", worktree.join(".envrc")).unwrap();
        let mount = dir.path().join("mount");

        let result = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount),
                ..DispatchServices::default()
            },
            ControlCommand::ProjectCheckoutDiscover {
                project_id: "fixture-project".to_string(),
            },
        )
        .unwrap();
        let ControlResult::ProjectCheckoutDiscovery(discovery) = result else {
            panic!("unexpected checkout discovery result")
        };
        let candidate = discovery
            .checkouts
            .iter()
            .find(|candidate| candidate.path == worktree)
            .unwrap();
        assert_eq!(candidate.managed_checkout_id.as_deref(), Some("fixture-worktree"));
        assert_eq!(candidate.link_issues, vec![worktree.join(".envrc")]);

        dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount),
                ..DispatchServices::default()
            },
            ControlCommand::ManagedLinkRepair {
                path: worktree.join(".envrc"),
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read_link(worktree.join(".envrc")).unwrap(),
            mount
                .join(floria_core::config::SECRETS_DIR)
                .join(store.list().unwrap()[0].id.to_string())
        );

        let repaired = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount),
                ..DispatchServices::default()
            },
            ControlCommand::ProjectCheckoutDiscover {
                project_id: "fixture-project".to_string(),
            },
        )
        .unwrap();
        let ControlResult::ProjectCheckoutDiscovery(repaired) = repaired else {
            panic!("unexpected checkout discovery result")
        };
        assert!(repaired
            .checkouts
            .iter()
            .find(|candidate| candidate.path == worktree)
            .unwrap()
            .link_issues
            .is_empty());
    }

    #[test]
    fn repairs_a_managed_ssh_agent_socket_link_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture Project".to_string(),
                path: project.clone(),
                ..Default::default()
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-environment".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            })
            .unwrap();
        let link = project.join("agent.sock");
        catalog
            .upsert_surface(&Surface {
                id: "fixture-agent".to_string(),
                environment_id: "fixture-environment".to_string(),
                name: "agent.sock".to_string(),
                kind: SurfaceKind::UnixSocket,
                path: link.clone(),
                input: SurfaceInput::Bindings { binding_ids: Vec::new() },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap();
        symlink("../foreign/agent.sock", &link).unwrap();
        let runtime_dir = dir.path().join("runtime/sockets");
        let services = || DispatchServices {
            ssh_runtime_dir: Some(&runtime_dir),
            ..DispatchServices::default()
        };

        let ControlResult::Snapshot(snapshot) =
            dispatch(&catalog, services(), ControlCommand::Snapshot).unwrap()
        else {
            panic!("expected workspace snapshot")
        };
        assert_eq!(
            snapshot.managed_links,
            vec![ManagedLink { path: link.clone(), status: ManagedLinkStatus::Replaced }]
        );

        assert_eq!(
            dispatch(
                &catalog,
                services(),
                ControlCommand::ManagedLinkRepair { path: link.clone() },
            )
            .unwrap(),
            ControlResult::Empty
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            floria_ssh::agent_runtime_socket_path(&runtime_dir, "fixture-agent")
        );
        let ControlResult::Snapshot(snapshot) =
            dispatch(&catalog, services(), ControlCommand::Snapshot).unwrap()
        else {
            panic!("expected workspace snapshot")
        };
        assert_eq!(snapshot.managed_links[0].status, ManagedLinkStatus::Linked);
    }

    #[test]
    fn policy_mode_roundtrips_through_the_control_seam() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let policy: Arc<dyn RuntimePolicyController> = Arc::new(FixturePolicy {
            status: Mutex::new(PolicyModeStatus::default()),
            grants: Mutex::new(vec![ActiveGrant {
                id: "fixture-grant".to_string(),
                subject: "exe:/usr/bin/cat".to_string(),
                object: "secrets/fixture".to_string(),
                operation: "read".to_string(),
                enforcement: Enforcement::Prompt,
                expires_at: 1_800_000_600,
                client: "cat".to_string(),
                executable: Some("/usr/bin/cat".to_string()),
                bundle_id: None,
                target: "~/.pgpass".to_string(),
            }]),
        });
        let _server = ControlServer::start_inner(
            &socket,
            catalog,
            ControlDependencies { policy: Some(policy), ..ControlDependencies::default() },
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        assert_eq!(
            client.request(ControlCommand::PolicyModeGet).unwrap(),
            ControlResult::PolicyMode(PolicyModeStatus::default())
        );
        assert_eq!(
            client
                .request(ControlCommand::PolicyModeSet {
                    mode: PolicyMode::AuditOnly,
                    duration_secs: Some(3600),
                })
                .unwrap(),
            ControlResult::PolicyMode(PolicyModeStatus {
                mode: PolicyMode::AuditOnly,
                expires_at: Some(1_800_003_600),
            })
        );
        assert_eq!(
            client.request(ControlCommand::GrantList).unwrap(),
            ControlResult::ActiveGrants(vec![ActiveGrant {
                id: "fixture-grant".to_string(),
                subject: "exe:/usr/bin/cat".to_string(),
                object: "secrets/fixture".to_string(),
                operation: "read".to_string(),
                enforcement: Enforcement::Prompt,
                expires_at: 1_800_000_600,
                client: "cat".to_string(),
                executable: Some("/usr/bin/cat".to_string()),
                bundle_id: None,
                target: "~/.pgpass".to_string(),
            }])
        );
        assert_eq!(
            client
                .request(ControlCommand::GrantRevoke {
                    id: "fixture-grant".to_string(),
                })
                .unwrap(),
            ControlResult::ActiveGrants(Vec::new())
        );
        assert_eq!(
            client.request(ControlCommand::GrantClear).unwrap(),
            ControlResult::ActiveGrants(Vec::new())
        );
    }

    #[test]
    fn asynchronous_discovery_returns_immediately_and_completes_through_status() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join(".env"), "FIXTURE_TOKEN=plain-value\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        dispatch(
            &catalog,
            DispatchServices {
                store: Some(store.as_ref()),
                ..DispatchServices::default()
            },
            ControlCommand::SharedSecretCreate {
                resource_id: "fixture-existing-secret".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("FIXTURE_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("plain-value"),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            },
        )
        .unwrap();
        let _server = ControlServer::start_inner(
            &socket,
            catalog,
            ControlDependencies {
                store: Some(Arc::clone(&store) as Arc<dyn SecretStore>),
                mount_path: Some(dir.path().join("mount")),
                ..ControlDependencies::default()
            },
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let ControlResult::DiscoveryJob(started) = client
            .request(ControlCommand::DiscoverStart { paths: vec![project.clone()] })
            .unwrap()
        else {
            panic!("expected discovery job")
        };
        assert_eq!(started.state, DiscoveryJobState::Queued);
        assert!(started.plan.is_none());

        let completed = (0..100)
            .find_map(|_| {
                let ControlResult::DiscoveryJob(status) = client
                    .request(ControlCommand::DiscoverStatus { id: started.id.clone() })
                    .unwrap()
                else {
                    panic!("expected discovery job status")
                };
                if status.is_terminal() {
                    Some(status)
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    None
                }
            })
            .expect("discovery job did not finish");

        assert_eq!(completed.state, DiscoveryJobState::Completed);
        assert_eq!(completed.progress.phase, DiscoveryJobPhase::Complete);
        let plan = completed.plan.expect("completed discovery plan");
        assert_eq!(plan.discovery.paths, vec![project]);
        assert_eq!(plan.discovery.summary.files, 1);
        assert_eq!(plan.discovery.summary.reused_secrets, 0);
        assert_eq!(plan.discovery.summary.new_secrets, 1);
        assert_eq!(
            store.get_calls.load(Ordering::Relaxed),
            0,
            "preview must not decrypt existing secrets; apply performs exact reuse matching"
        );
    }

    #[test]
    fn access_history_returns_persisted_reader_metadata_with_surface_display_path() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture Project".to_string(),
                path: dir.path().join("project"),
                ..Default::default()
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-environment".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            })
            .unwrap();
        let display_path = dir.path().join("project/.env");
        catalog
            .upsert_surface(&Surface {
                id: "fixture-surface".to_string(),
                environment_id: "fixture-environment".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: display_path.clone(),
                input: SurfaceInput::Bindings { binding_ids: Vec::new() },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap();

        let audit_path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&audit_path).unwrap();
        let mut identity = ProcessIdentity::bare(42, 501, 20);
        identity.exe_path = Some(PathBuf::from("/usr/bin/fixture-reader"));
        identity.cwd = Some(dir.path().join("project"));
        identity.parent_chain = vec![
            ProcSummary {
                pid: 42,
                ppid: 41,
                name: "fixture-reader".to_string(),
                exe_path: Some(PathBuf::from("/usr/bin/fixture-reader")),
            },
            ProcSummary {
                pid: 41,
                ppid: 1,
                name: "fixture-shell".to_string(),
                exe_path: Some(PathBuf::from("/bin/sh")),
            },
        ];
        audit.log_open(
            "surfaces/fixture-surface",
            "read",
            &identity,
            "allowed",
            Some("fixture-rule"),
            None,
            "sha256:fixture-content",
            7,
            32,
            None,
        );

        let result = dispatch(
            &catalog,
            DispatchServices { audit_log: Some(&audit_path), ..DispatchServices::default() },
            ControlCommand::AccessHistory { limit: 500 },
        )
        .unwrap();
        let ControlResult::AccessHistory(events) = result else {
            panic!("expected access history");
        };
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].display.as_deref(), display_path.to_str());
        assert_eq!(events[0].identity.exe.as_deref(), Some("/usr/bin/fixture-reader"));
        assert_eq!(events[0].identity.chain, "fixture-shell -> fixture-reader");
        assert_eq!(
            events[0]
                .identity
                .parent_chain
                .iter()
                .map(|process| process.name.as_str())
                .collect::<Vec<_>>(),
            vec!["fixture-shell", "fixture-reader"]
        );
    }

    #[test]
    fn discovery_reuses_only_an_exact_shared_secret_without_returning_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        std::fs::create_dir(&project_path).unwrap();
        std::fs::write(
            project_path.join(".env"),
            "API_TOKEN=fixture-shared-value\nOTHER=fixture-other-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::SharedSecretCreate {
                resource_id: "fixture-shared-api-token".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("API_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("fixture-shared-value"),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            },
        )
        .unwrap();

        let result = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover { paths: vec![project_path] },
        )
        .unwrap();
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("fixture-shared-value"));
        assert!(!serialized.contains("fixture-other-value"));

        let ControlResult::Discovery(plan) = result else {
            panic!("expected discovery result");
        };
        assert_eq!(plan.summary.reused_secrets, 1);
        assert_eq!(plan.summary.new_secrets, 0);
        assert!(matches!(
            plan.files[0].entries[0].action,
            floria_discover::DiscoveredEntryAction::ReuseSharedSecret {
                ref resource_id,
                ..
            }
                if resource_id == "fixture-shared-api-token"
        ));
        assert!(plan.files[0].entries.iter().any(|entry| {
            entry.key == "OTHER"
                && entry.action == floria_discover::DiscoveredEntryAction::CreateEnvFileEntry
        }));
    }

    #[test]
    fn discovery_without_values_does_not_read_existing_secret_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("empty-project");
        std::fs::create_dir(&project_path).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::SharedSecretCreate {
                resource_id: "fixture-unused-secret".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("UNUSED_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("fixture-unused-value"),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            },
        )
        .unwrap();

        let result = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover { paths: vec![project_path] },
        )
        .unwrap();

        assert!(matches!(result, ControlResult::Discovery(_)));
        assert_eq!(store.get_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn discovery_apply_replaces_dotenv_with_a_composed_surface() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &source_path,
            "DISCOVERED_TOKEN=fixture-discovered-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_output_import(&source_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 1);
        assert_eq!(result.reused_resources, 0);
        assert_eq!(result.files[0].outcome, DiscoveryApplyOutcome::Imported);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.environments.len(), 1);
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.bindings.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(snapshot.resources[0].enforcement, Enforcement::Allow);
        assert_eq!(snapshot.surfaces[0].enforcement, Enforcement::Allow);
        assert_eq!(
            std::fs::read_link(&source_path).unwrap(),
            mount_path
                .join(floria_core::config::SURFACES_DIR)
                .join(&snapshot.surfaces[0].id)
        );
        assert!(!project_path
            .read_dir()
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().contains("floria-import")));
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(
            store.get(&secret_id).unwrap().as_slice(),
            b"fixture-discovered-value"
        );
    }

    #[test]
    fn discovery_manages_parseable_project_files_without_configuring_outputs() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".dev.vars");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(&mount_path).unwrap();
        std::fs::write(
            &source_path,
            "DISCOVERED_TOKEN=fixture-discovered-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_file_import(&source_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.project_ids.len(), 1);
        assert_eq!(result.protected_files, 1);
        assert_eq!(result.created_resources, 0);
        assert_eq!(result.files[0].outcome, DiscoveryApplyOutcome::Protected);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 1);
        assert!(snapshot.resources.is_empty());
        assert!(snapshot.bindings.is_empty());
        assert!(snapshot.surfaces.is_empty());
        assert_eq!(
            std::fs::read_link(&source_path).unwrap(),
            mount_path
                .join(floria_core::config::SECRETS_DIR)
                .join(FIXTURE_SECRET_ID)
        );
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(
            store.record(&secret_id).unwrap().unwrap().environment_ids,
            Some(vec![snapshot.environments[0].id.clone()])
        );
    }

    #[test]
    fn discovery_scopes_an_opaque_environment_file_to_its_named_environment() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join("config/credentials/production.key");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&mount_path).unwrap();
        std::fs::write(&source_path, "fixture-production-key\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_file_import(&source_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.environments[0].name, "Production");
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(
            store.record(&secret_id).unwrap().unwrap().environment_ids,
            Some(vec![snapshot.environments[0].id.clone()])
        );
    }

    #[test]
    fn rediscovering_a_managed_project_does_not_reimport_surface_links() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &source_path,
            "DISCOVERED_TOKEN=fixture-discovered-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();
        let services = DispatchServices {
            store: Some(&store),
            mount_path: Some(&mount_path),
            ..DispatchServices::default()
        };
        let import = project_output_import(&source_path, &project_path);

        dispatch(
            &catalog,
            services,
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![import.clone()]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let managed_snapshot = catalog.snapshot().unwrap();
        let managed_target = std::fs::read_link(&source_path).unwrap();
        let store_reads_before_rediscovery = store.get_calls.load(Ordering::Relaxed);
        let rediscovered = dispatch(
            &catalog,
            services,
            ControlCommand::Discover {
                paths: vec![project_path.clone()],
            },
        )
        .unwrap();

        let ControlResult::Discovery(plan) = rediscovered else {
            panic!("expected discovery plan");
        };
        assert_eq!(
            plan.projects[0].managed_project_id.as_deref(),
            Some(managed_snapshot.projects[0].id.as_str())
        );
        assert_eq!(plan.summary.new_secrets, 0);
        assert_eq!(plan.summary.reused_secrets, 0);
        assert_eq!(
            store.get_calls.load(Ordering::Relaxed),
            store_reads_before_rediscovery
        );
        assert_eq!(plan.managed_items.len(), 1);
        assert_eq!(plan.managed_items[0].path, source_path);
        assert_eq!(plan.managed_items[0].kind, DiscoveryManagedItemKind::Surface);
        assert_eq!(
            plan.managed_items[0].status,
            ManagedLinkStatus::Linked
        );

        let repeated_apply = dispatch(
            &catalog,
            services,
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![import]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        );
        assert!(matches!(
            repeated_apply,
            Err(DispatchError::Validation(message))
                if message.contains("was not part of the reviewed discovery")
        ));

        let repeated_snapshot = catalog.snapshot().unwrap();
        assert_eq!(repeated_snapshot.projects.len(), managed_snapshot.projects.len());
        assert_eq!(
            repeated_snapshot.environments.len(),
            managed_snapshot.environments.len()
        );
        assert_eq!(
            repeated_snapshot.resources.len(),
            managed_snapshot.resources.len()
        );
        assert_eq!(repeated_snapshot.bindings.len(), managed_snapshot.bindings.len());
        assert_eq!(repeated_snapshot.surfaces.len(), managed_snapshot.surfaces.len());
        assert_eq!(std::fs::read_link(&source_path).unwrap(), managed_target);

        std::fs::remove_file(&source_path).unwrap();
        let missing = dispatch(
            &catalog,
            services,
            ControlCommand::Discover {
                paths: vec![project_path.clone()],
            },
        )
        .unwrap();
        let ControlResult::Discovery(missing) = missing else {
            panic!("expected discovery plan");
        };
        assert_eq!(
            missing.managed_items[0].status,
            ManagedLinkStatus::Missing
        );

        std::fs::write(&source_path, "DISCOVERED_TOKEN=fixture-local-replacement\n").unwrap();
        let replaced = dispatch(
            &catalog,
            services,
            ControlCommand::Discover {
                paths: vec![project_path],
            },
        )
        .unwrap();
        let ControlResult::Discovery(replaced) = replaced else {
            panic!("expected discovery plan");
        };
        assert_eq!(
            replaced.managed_items[0].status,
            ManagedLinkStatus::Replaced
        );
        assert_eq!(
            catalog.snapshot().unwrap().resources.len(),
            managed_snapshot.resources.len()
        );
    }

    #[test]
    fn discovery_apply_protects_binary_credentials_without_text_decoding() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join("client-identity.p12");
        let mount_path = dir.path().join("mount");
        let fixture_bytes = b"\x30\x82\x00\x08\xff\x00fixture-p12";
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(&mount_path).unwrap();
        std::fs::write(&source_path, fixture_bytes).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture Project".to_string(),
                path: project_path.clone(),
                ..Default::default()
            })
            .unwrap();
        let import = library_import(
            &source_path,
            DiscoverySourceDisposition::ProtectInPlace,
        );
        let services = DispatchServices {
            store: Some(&store),
            mount_path: Some(&mount_path),
            ..DispatchServices::default()
        };

        let applied = dispatch(
            &catalog,
            services,
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![import.clone()]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.protected_files, 1);
        assert!(std::fs::symlink_metadata(&source_path).unwrap().file_type().is_symlink());
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(store.get(&secret_id).unwrap().as_slice(), fixture_bytes);
        let protected_records = store.list().unwrap();
        let canonical_source_path = canonical_source_path(&source_path).unwrap();
        assert_eq!(protected_records.len(), 1);
        assert_eq!(
            protected_records[0].source_path(),
            Some(canonical_source_path.as_path())
        );

        let managed_snapshot = catalog.snapshot().unwrap();
        let managed_target = std::fs::read_link(&source_path).unwrap();
        let store_reads_before_rediscovery = store.get_calls.load(Ordering::Relaxed);
        let rediscovered = dispatch(
            &catalog,
            services,
            ControlCommand::Discover {
                paths: vec![project_path.clone()],
            },
        )
        .unwrap();
        let ControlResult::Discovery(plan) = rediscovered else {
            panic!("expected discovery plan");
        };
        assert_eq!(
            plan.projects[0].managed_project_id.as_deref(),
            Some("fixture-project")
        );
        assert_eq!(plan.summary.new_secrets, 0);
        assert_eq!(plan.summary.reused_secrets, 0);
        assert_eq!(
            store.get_calls.load(Ordering::Relaxed),
            store_reads_before_rediscovery
        );
        assert_eq!(plan.managed_items.len(), 1);
        assert_eq!(plan.managed_items[0].path, canonical_source_path);
        assert_eq!(
            plan.managed_items[0].kind,
            DiscoveryManagedItemKind::ProtectedFile
        );
        assert_eq!(
            plan.managed_items[0].status,
            ManagedLinkStatus::Linked
        );

        let repeated_apply = dispatch(
            &catalog,
            services,
            ControlCommand::DiscoverApply {
                paths: vec![project_path],
                imports: Some(vec![import]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        );
        assert!(matches!(
            repeated_apply,
            Err(DispatchError::Validation(message))
                if message.contains("was not part of the reviewed discovery")
        ));

        let repeated_snapshot = catalog.snapshot().unwrap();
        assert_eq!(
            repeated_snapshot.resources.len(),
            managed_snapshot.resources.len()
        );
        assert_eq!(
            std::fs::read_link(&source_path).unwrap(),
            managed_target
        );
    }

    #[test]
    fn discovery_apply_handles_multiple_projects_and_an_explicit_file_assignment() {
        let dir = tempfile::tempdir().unwrap();
        let workspace_path = dir.path().join("workspace");
        let first_project_path = workspace_path.join("first-project");
        let second_project_path = workspace_path.join("second-project");
        let first_source_path = first_project_path.join(".env");
        let second_source_path = second_project_path.join(".env");
        let shared_source_path = workspace_path.join(".env.shared");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(first_project_path.join(".git")).unwrap();
        std::fs::create_dir_all(second_project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&first_source_path, "FIRST_MODE=fixture-first\n").unwrap();
        std::fs::write(&second_source_path, "SECOND_MODE=fixture-second\n").unwrap();
        std::fs::write(&shared_source_path, "SHARED_MODE=fixture-shared\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let reviewed = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover { paths: vec![workspace_path.clone()] },
        )
        .unwrap();
        let ControlResult::Discovery(plan) = reviewed else {
            panic!("expected discovery result");
        };
        assert_eq!(plan.projects.len(), 3);
        assert_eq!(
            plan.files
                .iter()
                .find(|file| file.path == shared_source_path)
                .unwrap()
                .assignment
                .state,
            floria_discover::ProjectAssignmentState::NeedsReview
        );

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![workspace_path.clone()],
                imports: Some(vec![
                    project_output_import(&first_source_path, &first_project_path),
                    project_output_import(&second_source_path, &second_project_path),
                    project_output_import(&shared_source_path, &workspace_path),
                ]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.project_ids.len(), 3);
        assert_eq!(result.project_id, None);
        assert_eq!(result.files.len(), 3);
        assert!(
            result
                .files
                .iter()
                .all(|file| file.outcome == DiscoveryApplyOutcome::Imported),
            "{result:#?}"
        );
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 3);
        assert_eq!(snapshot.surfaces.len(), 3);
        for source_path in [first_source_path, second_source_path, shared_source_path] {
            assert!(std::fs::symlink_metadata(source_path)
                .unwrap()
                .file_type()
                .is_symlink());
        }
    }

    #[test]
    fn discovery_apply_imports_composable_content_into_the_library_without_a_project() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(&mount_path).unwrap();
        std::fs::write(&source_path, "DISCOVERED_TOKEN=fixture-library-value\n").unwrap();
        let source_bytes = std::fs::read(&source_path).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path],
                imports: Some(vec![library_import(
                    &source_path,
                    DiscoverySourceDisposition::LeaveUnchanged,
                )]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert!(result.project_ids.is_empty());
        assert_eq!(result.created_resources, 1);
        assert_eq!(result.files[0].outcome, DiscoveryApplyOutcome::Imported);
        assert_eq!(std::fs::read(&source_path).unwrap(), source_bytes);
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.projects.is_empty());
        assert!(snapshot.environments.is_empty());
        assert_eq!(snapshot.resources.len(), 1);
        assert!(snapshot.bindings.is_empty());
        assert!(snapshot.surfaces.is_empty());
        assert_eq!(snapshot.resources[0].kind, ResourceKind::SharedSecret);
        assert_eq!(snapshot.resources[0].origin.sources[0].project_id, None);
    }

    #[test]
    fn discovery_apply_materializes_once_and_shares_outputs_across_projects() {
        let dir = tempfile::tempdir().unwrap();
        let workspace_path = dir.path().join("workspace");
        let first_project_path = workspace_path.join("first-project");
        let second_project_path = workspace_path.join("second-project");
        let source_path = workspace_path.join(".env.shared");
        let first_output_path = first_project_path.join(".env.shared");
        let second_output_path = second_project_path.join(".env.shared");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(first_project_path.join(".git")).unwrap();
        std::fs::create_dir_all(second_project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&source_path, "DISCOVERED_TOKEN=fixture-shared-value\n").unwrap();
        let source_bytes = std::fs::read(&source_path).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![workspace_path],
                imports: Some(vec![project_outputs_import(
                    &source_path,
                    vec![
                        (&first_project_path, &first_output_path),
                        (&second_project_path, &second_output_path),
                    ],
                    DiscoverySourceDisposition::LeaveUnchanged,
                )]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.project_ids.len(), 2);
        assert_eq!(result.created_resources, 1);
        assert_eq!(std::fs::read(&source_path).unwrap(), source_bytes);
        for output_path in [&first_output_path, &second_output_path] {
            assert!(std::fs::symlink_metadata(output_path)
                .unwrap()
                .file_type()
                .is_symlink());
        }
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 2);
        assert_eq!(snapshot.environments.len(), 2);
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.bindings.len(), 2);
        assert_eq!(snapshot.surfaces.len(), 2);
        assert_eq!(
            snapshot
                .bindings
                .iter()
                .map(|binding| binding.resource_id.as_str())
                .collect::<HashSet<_>>()
                .len(),
            1
        );
    }

    #[test]
    fn discovery_apply_splits_plain_values_into_an_env_file_with_origins() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &source_path,
            "DEBUG=true\nDISCOVERED_TOKEN=fixture-discovered-value\nRETRIES=3\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_output_import(&source_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 2);
        let snapshot = catalog.snapshot().unwrap();
        let secret = snapshot
            .resources
            .iter()
            .find(|resource| resource.kind == ResourceKind::SharedSecret)
            .unwrap();
        assert_eq!(secret.name, "DISCOVERED_TOKEN");
        assert_eq!(secret.enforcement, Enforcement::Allow);
        assert_eq!(secret.origin.kind, floria_catalog::OriginKind::Discovered);
        assert_eq!(secret.origin.sources.len(), 1);
        assert_eq!(secret.origin.sources[0].path, source_path);
        let env_file = snapshot
            .resources
            .iter()
            .find(|resource| resource.kind == ResourceKind::EnvFile)
            .unwrap();
        assert_eq!(env_file.name, ".env");
        assert_eq!(env_file.enforcement, Enforcement::Allow);
        assert_eq!(snapshot.surfaces[0].enforcement, Enforcement::Allow);
        assert_eq!(env_file.origin.kind, floria_catalog::OriginKind::Discovered);
        let env_keys = env_file
            .entries
            .iter()
            .filter_map(|entry| entry.key.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(env_keys, ["DEBUG", "RETRIES"]);
        assert_eq!(snapshot.bindings.len(), 2);
        let secret_binding =
            snapshot.bindings.iter().find(|binding| binding.resource_id == secret.id).unwrap();
        let env_binding =
            snapshot.bindings.iter().find(|binding| binding.resource_id == env_file.id).unwrap();
        assert_eq!(env_binding.position, 0);
        assert_eq!(secret_binding.position, 1);
    }

    #[test]
    fn discovery_apply_honors_promote_and_demote_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &source_path,
            "DEBUG=fixture-promoted-value\nDISCOVERED_TOKEN=fixture-demoted-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_output_import(&source_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: vec![crate::protocol::DiscoveryEntryRef {
                    path: source_path.clone(),
                    address: "keys/DEBUG".to_string(),
                }],
                demote_entries: vec![crate::protocol::DiscoveryEntryRef {
                    path: source_path.clone(),
                    address: "keys/DISCOVERED_TOKEN".to_string(),
                }],
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 2);
        let snapshot = catalog.snapshot().unwrap();
        let secret = snapshot
            .resources
            .iter()
            .find(|resource| resource.kind == ResourceKind::SharedSecret)
            .unwrap();
        assert_eq!(secret.name, "DEBUG");
        let env_file = snapshot
            .resources
            .iter()
            .find(|resource| resource.kind == ResourceKind::EnvFile)
            .unwrap();
        let env_keys = env_file
            .entries
            .iter()
            .filter_map(|entry| entry.key.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(env_keys, ["DISCOVERED_TOKEN"]);
    }

    #[test]
    fn discovery_reuse_appends_a_source_to_the_existing_secret_origin() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&source_path, "API_TOKEN=fixture-shared-value\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();
        dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::SharedSecretCreate {
                resource_id: "fixture-shared-api-token".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("API_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("fixture-shared-value"),
                enforcement: Enforcement::TouchId,
                metadata: ItemMetadata::default(),
            },
        )
        .unwrap();

        dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_output_import(&source_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let resource = catalog.resource("fixture-shared-api-token").unwrap();
        assert_eq!(resource.enforcement, Enforcement::TouchId);
        assert_eq!(resource.origin.kind, floria_catalog::OriginKind::Manual);
        assert_eq!(resource.origin.sources.len(), 1);
        assert_eq!(resource.origin.sources[0].path, source_path);
        assert_eq!(
            catalog.snapshot().unwrap().surfaces[0].enforcement,
            Enforcement::TouchId
        );
    }

    #[test]
    fn discovery_apply_mutates_only_reviewed_files() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let development_path = project_path.join(".env");
        let production_path = project_path.join(".env.production");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&development_path, "DEVELOPMENT_TOKEN=fixture-development\n").unwrap();
        std::fs::write(&production_path, "DISCOVERED_TOKEN=fixture-production\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_output_import(&production_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, production_path);
        assert!(std::fs::symlink_metadata(&development_path).unwrap().is_file());
        assert!(std::fs::symlink_metadata(&production_path)
            .unwrap()
            .file_type()
            .is_symlink());
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.surfaces.len(), 1);
        assert_eq!(snapshot.environments[0].name, "Production");
    }

    #[test]
    fn discovery_apply_leaves_dotenv_reference_files_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let reference_path = project_path.join(".env.example");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&source_path, "DISCOVERED_TOKEN=fixture-real-value\n").unwrap();
        let reference_bytes = b"DISCOVERED_TOKEN=replace-me\n\
            OPTIONAL_REUSED_TOKEN=replace-me\n\
            OPTIONAL_NEW_TOKEN=replace-me\n";
        std::fs::write(&reference_path, reference_bytes).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_output_import(&source_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert!(std::fs::symlink_metadata(&source_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::symlink_metadata(&reference_path).unwrap().is_file());
        assert_eq!(std::fs::read(&reference_path).unwrap(), reference_bytes);
        assert!(!result.files.iter().any(|file| file.path == reference_path));
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);

        let rediscovered = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover {
                paths: vec![project_path.clone(), reference_path.clone()],
            },
        )
        .unwrap();
        let ControlResult::Discovery(plan) = rediscovered else {
            panic!("expected discovery result");
        };
        assert_eq!(
            plan.projects[0].managed_project_id.as_deref(),
            Some(snapshot.projects[0].id.as_str())
        );
        assert_eq!(plan.summary.missing_reference_entries, 2);
        let reference = plan
            .files
            .iter()
            .find(|file| file.path == reference_path)
            .expect("reference file");
        assert!(reference.entries.iter().any(|entry| {
            entry.key == "DISCOVERED_TOKEN"
                && entry.action
                    == floria_discover::DiscoveredEntryAction::ReferenceEntry { matched: true }
        }));
        assert!(reference.entries.iter().any(|entry| {
            entry.key == "OPTIONAL_REUSED_TOKEN"
                && entry.action
                    == floria_discover::DiscoveredEntryAction::ReferenceEntry { matched: false }
        }));
        let surface_id = reference.managed_surface_id.clone().expect("managed surface");

        let reused = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::DiscoverReferenceResolve {
                surface_id: surface_id.clone(),
                key: "OPTIONAL_REUSED_TOKEN".to_string(),
                source: DiscoveryReferenceSource::ExistingSharedSecret {
                    resource_id: snapshot.resources[0].id.clone(),
                },
            },
        )
        .unwrap();
        let ControlResult::DiscoveryReferenceResolved(reused) = reused else {
            panic!("expected resolved reference");
        };
        assert_eq!(reused.surface_id, snapshot.surfaces[0].id);
        assert_eq!(reused.resource_id, snapshot.resources[0].id);
        assert_eq!(reused.key, "OPTIONAL_REUSED_TOKEN");

        let mut secondary_surface = snapshot.surfaces[0].clone();
        secondary_surface.id = "fixture-secondary-surface".to_string();
        secondary_surface.name = ".env.secondary".to_string();
        secondary_surface.path = project_path.join(".env.secondary");
        secondary_surface.input = SurfaceInput::Bindings { binding_ids: Vec::new() };
        secondary_surface.position = 1;
        catalog.upsert_surface(&secondary_surface).unwrap();
        let reused_again = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::DiscoverReferenceResolve {
                surface_id: secondary_surface.id.clone(),
                key: "OPTIONAL_REUSED_TOKEN".to_string(),
                source: DiscoveryReferenceSource::ExistingSharedSecret {
                    resource_id: snapshot.resources[0].id.clone(),
                },
            },
        )
        .unwrap();
        let ControlResult::DiscoveryReferenceResolved(reused_again) = reused_again else {
            panic!("expected resolved reference");
        };
        assert_eq!(reused_again.binding_id, reused.binding_id);
        assert_eq!(catalog.snapshot().unwrap().bindings.len(), 2);

        dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::DiscoverReferenceResolve {
                surface_id,
                key: "OPTIONAL_NEW_TOKEN".to_string(),
                source: DiscoveryReferenceSource::NewSharedSecret {
                    name: "OPTIONAL_NEW_TOKEN".to_string(),
                    value: SecretValue::new("fixture-new-reference-value"),
                    enforcement: Enforcement::Prompt,
                    metadata: ItemMetadata::default(),
                },
            },
        )
        .unwrap();

        let resolved_snapshot = catalog.snapshot().unwrap();
        assert_eq!(resolved_snapshot.resources.len(), 2);
        assert_eq!(resolved_snapshot.bindings.len(), 3);
        assert_eq!(
            resolved_snapshot.surfaces[0].input.binding_ids().unwrap().len(),
            3
        );
        let rediscovered = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover {
                paths: vec![project_path, reference_path],
            },
        )
        .unwrap();
        let ControlResult::Discovery(resolved_plan) = rediscovered else {
            panic!("expected discovery result");
        };
        assert_eq!(resolved_plan.summary.missing_reference_entries, 0);
    }

    #[test]
    fn discovery_apply_shares_exact_matches_within_the_import() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let development_path = project_path.join(".env");
        let production_path = project_path.join(".env.production");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &development_path,
            "DISCOVERED_TOKEN=fixture-shared-value\n",
        )
        .unwrap();
        std::fs::write(
            &production_path,
            "DISCOVERED_TOKEN=fixture-shared-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![
                    project_output_import(&development_path, &project_path),
                    project_output_import(&production_path, &project_path),
                ]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 1);
        assert_eq!(result.reused_resources, 1);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.bindings.len(), 2);
        assert_eq!(snapshot.surfaces.len(), 2);
    }

    #[test]
    fn discovery_apply_can_keep_an_exact_match_as_a_separate_secret() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let development_path = project_path.join(".env");
        let production_path = project_path.join(".env.production");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &development_path,
            "DISCOVERED_TOKEN=fixture-shared-value\n",
        )
        .unwrap();
        std::fs::write(
            &production_path,
            "DISCOVERED_TOKEN=fixture-shared-value\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![
                    project_output_import(&development_path, &project_path),
                    project_output_import(&production_path, &project_path),
                ]),
                separate_entries: vec![crate::protocol::DiscoveryEntryRef {
                    path: production_path,
                    address: "keys/DISCOVERED_TOKEN".to_string(),
                }],
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 2);
        assert_eq!(result.reused_resources, 0);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 2);
        assert_eq!(snapshot.bindings.len(), 2);
        assert_eq!(snapshot.surfaces.len(), 2);
    }

    #[test]
    fn discovery_apply_rejects_unreviewed_files_before_mutating_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&source_path, "DISCOVERED_TOKEN=fixture-value\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let error = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_output_import(
                    &project_path.join(".env.not-reviewed"),
                    &project_path,
                )]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap_err();

        assert!(error.body().message.contains("not part of the reviewed discovery"));
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.projects.is_empty());
        assert!(snapshot.resources.is_empty());
        assert!(std::fs::symlink_metadata(source_path).unwrap().is_file());
    }

    #[test]
    fn discovery_apply_reports_a_later_file_failure_without_hiding_successes() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let dotenv_path = project_path.join(".env");
        let ssh_path = project_path.join(".ssh/id_fixture");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(ssh_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(&dotenv_path, "DISCOVERED_TOKEN=fixture-value\n").unwrap();
        std::fs::write(
            &ssh_path,
            concat!(
                "-----BEGIN OPENSSH ",
                "PRIVATE KEY-----\ninvalid\n-----END OPENSSH ",
                "PRIVATE KEY-----\n"
            ),
        )
        .unwrap();
        // Group/world-writable keys are rejected outright (not degraded to plain protection).
        std::fs::set_permissions(&ssh_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![
                    project_output_import(&dotenv_path, &project_path),
                    library_import(&ssh_path, DiscoverySourceDisposition::LeaveUnchanged),
                ]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.files.len(), 2);
        assert!(result
            .files
            .iter()
            .any(|file| file.path == dotenv_path
                && file.outcome == DiscoveryApplyOutcome::Imported));
        assert!(result
            .files
            .iter()
            .any(|file| file.path == ssh_path
                && file.outcome == DiscoveryApplyOutcome::Failed));
        assert!(result.project_id.is_some());
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);
    }

    #[test]
    fn discovery_apply_protects_files_that_fail_ssh_import() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let ssh_path = project_path.join(".ssh/id_fixture");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(ssh_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &ssh_path,
            concat!(
                "-----BEGIN OPENSSH ",
                "PRIVATE KEY-----\ninvalid\n-----END OPENSSH ",
                "PRIVATE KEY-----\n"
            ),
        )
        .unwrap();
        // protect_file replaces the source with a symlink, so canonicalize up front.
        let canonical_ssh_path = ssh_path.canonicalize().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![library_import(
                    &ssh_path,
                    DiscoverySourceDisposition::LeaveUnchanged,
                )]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].outcome, DiscoveryApplyOutcome::Protected);
        assert_eq!(result.imported_ssh_identities, 0);
        assert_eq!(result.protected_files, 1);
        assert!(store.get_by_path(&canonical_ssh_path).unwrap().is_some());
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.resources.is_empty());
    }

    #[test]
    fn discovery_apply_imports_supported_ssh_keys_and_protects_unsupported_algorithms() {
        use ssh_key::{Algorithm, EcdsaCurve, LineEnding, PrivateKey};

        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let ssh_dir = project_path.join(".ssh");
        let ed25519_path = ssh_dir.join("id_ed25519");
        let ecdsa_path = ssh_dir.join("id_ecdsa");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        let ed25519 =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        std::fs::write(&ed25519_path, ed25519.to_openssh(LineEnding::LF).unwrap()).unwrap();
        let ecdsa = PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
        )
        .unwrap();
        std::fs::write(&ecdsa_path, ecdsa.to_openssh(LineEnding::LF).unwrap()).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![
                    library_import(&ed25519_path, DiscoverySourceDisposition::LeaveUnchanged),
                    library_import(&ecdsa_path, DiscoverySourceDisposition::LeaveUnchanged),
                ]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.imported_ssh_identities, 1);
        assert_eq!(result.protected_files, 1);
        assert!(result
            .files
            .iter()
            .any(|file| file.path == ed25519_path
                && file.outcome == DiscoveryApplyOutcome::Imported));
        assert!(result
            .files
            .iter()
            .any(|file| file.path == ecdsa_path
                && file.outcome == DiscoveryApplyOutcome::Protected
                && file.detail.contains("not supported")));
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.resources[0].kind, ResourceKind::SshIdentity);
        assert_eq!(snapshot.resources[0].enforcement, Enforcement::TouchId);
    }

    #[test]
    fn discovery_apply_keeps_aws_credentials_section_aware() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".aws/credentials");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(mount_path.join(floria_core::config::SURFACES_DIR)).unwrap();
        std::fs::write(
            &source_path,
            "[default]\naws_access_key_id=fixture-access-id\n\
             aws_secret_access_key=fixture-secret-value\n\
             [staging]\naws_access_key_id=fixture-staging-id\n",
        )
        .unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();

        let applied = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount_path),
                ..DispatchServices::default()
            },
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_output_import(&source_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.created_resources, 1);
        assert_eq!(result.files[0].outcome, DiscoveryApplyOutcome::Imported);
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.resources[0].kind, ResourceKind::EnvFile);
        assert_eq!(snapshot.resources[0].codec, ResourceCodec::Ini);
        assert_eq!(snapshot.resources[0].enforcement, Enforcement::Prompt);
        assert!(snapshot.resources[0]
            .entries
            .iter()
            .any(|entry| entry.address.contains("default")));
        assert!(snapshot.resources[0]
            .entries
            .iter()
            .any(|entry| entry.address.contains("staging")));
        assert_eq!(snapshot.surfaces[0].kind, SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)));
        assert_eq!(snapshot.surfaces[0].enforcement, Enforcement::Prompt);
        assert!(std::fs::symlink_metadata(source_path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn ssh_identity_discovery_roundtrips_public_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let discovery: Arc<dyn SshIdentityDiscovery> = Arc::new(FixtureSshDiscovery);
        let _server = ControlServer::start_inner(
            &socket,
            catalog,
            ControlDependencies {
                ssh_discovery: Some(discovery),
                ..ControlDependencies::default()
            },
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();
        let endpoint = dir.path().join("upstream.sock");

        assert_eq!(
            client
                .request(ControlCommand::SshAgentDiscover { endpoint: endpoint.clone() })
                .unwrap(),
            ControlResult::SshAgentIdentities(vec![SshIdentity {
                address: "ssh/sha256/fixture-address".to_string(),
                fingerprint: "SHA256:fixture-fingerprint".to_string(),
                comment: endpoint.display().to_string(),
            }])
        );
    }

    #[test]
    fn managed_ssh_identity_lifecycle_keeps_private_key_out_of_catalog() {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, LineEnding, PrivateKey};

        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("fixture-id_ed25519");
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        std::fs::write(
            &source_path,
            private_key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(&source_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            dir.path().join("mount"),
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::SshIdentityImport {
                resource_id: "fixture-ssh-identity".to_string(),
                name: "Fixture SSH Identity".to_string(),
                path: source_path,
                passphrase: None,
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            })
            .unwrap();
        let ControlResult::SshIdentityCreated { resource } = created else {
            panic!("expected managed SSH identity result");
        };
        assert_eq!(resource.kind, ResourceKind::SshIdentity);
        assert_eq!(resource.shape, ValueShape::SshIdentity);
        assert_eq!(resource.entries.len(), 1);
        assert!(resource.entries[0].address.starts_with("ssh/sha256/"));
        assert_eq!(
            resource.source,
            ResourceSource::SecretRef { secret_id: FIXTURE_SECRET_ID.to_string() }
        );
        let catalog_json = serde_json::to_string(&catalog.snapshot().unwrap()).unwrap();
        assert!(!catalog_json.contains("OPENSSH PRIVATE KEY"));
        let stored = store.get(&FIXTURE_SECRET_ID.parse().unwrap()).unwrap();
        let stored_identity = floria_ssh::identity_from_private_key(&stored).unwrap();
        assert_eq!(stored_identity.address, resource.entries[0].address);
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);

        assert_eq!(
            client
                .request(ControlCommand::SshIdentityRemove {
                    resource_id: resource.id,
                })
                .unwrap(),
            ControlResult::Empty
        );
        assert!(catalog.snapshot().unwrap().resources.is_empty());
        assert!(store.record(&FIXTURE_SECRET_ID.parse().unwrap()).unwrap().is_none());
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn ssh_config_integration_roundtrips_through_the_control_seam() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let user_config = dir.path().join(".ssh/config");
        let generated_config = dir.path().join("floria/ssh/config");
        let manager: Arc<dyn SshConfigManager> = Arc::new(crate::ManagedSshConfig::new(
            &user_config,
            &generated_config,
        ));
        let _server = ControlServer::start_inner(
            &socket,
            catalog,
            ControlDependencies {
                ssh_config: Some(manager),
                ..ControlDependencies::default()
            },
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let status = client.request(ControlCommand::SshConfigStatus).unwrap();
        assert!(matches!(
            status,
            ControlResult::SshConfig(SshConfigStatus {
                state: crate::SshConfigState::Disabled,
                writable: true,
                ..
            })
        ));
        let status = client.request(ControlCommand::SshConfigInstall).unwrap();
        assert!(matches!(
            status,
            ControlResult::SshConfig(SshConfigStatus {
                state: crate::SshConfigState::Managed,
                ..
            })
        ));
        assert!(std::fs::read_to_string(&user_config)
            .unwrap()
            .contains(&generated_config.display().to_string()));

        let status = client.request(ControlCommand::SshConfigRemove).unwrap();
        assert!(matches!(
            status,
            ControlResult::SshConfig(SshConfigStatus {
                state: crate::SshConfigState::Disabled,
                ..
            })
        ));
    }

    #[test]
    fn client_can_mutate_and_snapshot_catalog_over_separate_socket() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let server = ControlServer::start(&socket, catalog, test_peer_verifier()).unwrap();
        assert_eq!(
            std::fs::metadata(server.socket_path()).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut client = ControlClient::connect(&socket).unwrap();
        assert_eq!(
            client.request(ControlCommand::Ping).unwrap(),
            ControlResult::Pong {
                protocol_version: crate::protocol::CONTROL_PROTOCOL_VERSION,
                daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                schema_version: 12,
                minimum_schema_version: 12,
                store_format_version: 2,
                minimum_store_format_version: 1,
            }
        );
        client
            .request(ControlCommand::ProjectUpsert {
                project: Project {
                    id: "floria".to_string(),
                    name: "floria".to_string(),
                    path: PathBuf::from("/workspace/floria"),
                    ..Default::default()
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
    fn untrusted_client_cannot_issue_control_commands() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let _server =
            ControlServer::start(&socket, catalog, Arc::new(RejectAllPeers)).unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        assert!(client.request(ControlCommand::Ping).is_err());
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
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        client
            .request(ControlCommand::ProjectCreate {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                    ..Default::default()
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
                    kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                    path: PathBuf::from("/fixture/project/.env"),
                    input: SurfaceInput::Bindings { binding_ids: Vec::new() },
                    enforcement: Enforcement::Prompt,
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
        let _server =
            ControlServer::start(&socket, catalog.clone(), test_peer_verifier()).unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let error = client
            .request(ControlCommand::ProjectCreate {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                    ..Default::default()
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
                    kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                    path: PathBuf::from("/outside/.env"),
                    input: SurfaceInput::Bindings { binding_ids: Vec::new() },
                    enforcement: Enforcement::Prompt,
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
        let _server = ControlServer::start(&socket, catalog, test_peer_verifier()).unwrap();
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
                        ..Default::default()
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
            test_peer_verifier(),
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
                    ..Default::default()
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
    fn observer_classification_defaults_head_changes_to_mutating() {
        assert!(is_read_only(&ControlCommand::Snapshot));
        assert!(is_read_only(&ControlCommand::ProtectedFileHistory {
            id: "fixture".to_string(),
        }));
        assert!(!is_read_only(&ControlCommand::SharedSecretRotate {
            resource_id: "fixture".to_string(),
            value: crate::protocol::SecretValue::new("fixture-value"),
        }));
        assert!(!is_read_only(&ControlCommand::ProtectedFileRollback {
            id: "fixture".to_string(),
            version: 1,
        }));
    }

    #[test]
    fn shared_secret_lifecycle_over_ipc_keeps_plaintext_out_of_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            dir.path().join("mount"),
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::SharedSecretCreate {
                resource_id: "fixture-shared-secret".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("FIXTURE_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("fixture-value-one"),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata {
                    note: Some("Documentation deployment token".to_string()),
                    links: vec![ItemLink {
                        label: "Token dashboard".to_string(),
                        url: "https://example.invalid/tokens".to_string(),
                    }],
                },
            })
            .unwrap();
        assert!(matches!(
            created,
            ControlResult::SharedSecretCreated { version: 1, .. }
        ));
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
        let resource = catalog.resource("fixture-shared-secret").unwrap();
        assert_eq!(
            resource.source,
            ResourceSource::SecretRef { secret_id: FIXTURE_SECRET_ID.to_string() }
        );
        assert_eq!(resource.metadata.note.as_deref(), Some("Documentation deployment token"));
        assert_eq!(resource.metadata.links[0].label, "Token dashboard");
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
        assert_eq!(
            observer.notifications.load(Ordering::Relaxed),
            2,
            "rotating a secret head must refresh managed runtime policy"
        );
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(store.get_version(&secret_id, 1).unwrap().as_slice(), b"fixture-value-one");
        assert_eq!(store.get_version(&secret_id, 2).unwrap().as_slice(), b"fixture-value-two");

        assert_eq!(
            client
                .request(ControlCommand::SharedSecretUpdate {
                    resource_id: "fixture-shared-secret".to_string(),
                    name: "Renamed Shared Secret".to_string(),
                    default_env_key: Some("RENAMED_TOKEN".to_string()),
                    value: Some(crate::protocol::SecretValue::new("fixture-value-three")),
                    enforcement: Enforcement::TouchId,
                    metadata: ItemMetadata {
                        note: Some("Renamed deployment token".to_string()),
                        links: Vec::new(),
                    },
                })
                .unwrap(),
            ControlResult::Empty
        );
        let resource = catalog.resource("fixture-shared-secret").unwrap();
        assert_eq!(resource.name, "Renamed Shared Secret");
        assert_eq!(resource.default_env_key.as_deref(), Some("RENAMED_TOKEN"));
        assert_eq!(resource.entries[0].label, "Renamed Shared Secret");
        assert_eq!(resource.entries[0].key.as_deref(), Some("RENAMED_TOKEN"));
        assert_eq!(resource.enforcement, Enforcement::TouchId);
        assert_eq!(resource.metadata.note.as_deref(), Some("Renamed deployment token"));
        assert_eq!(store.get(&secret_id).unwrap().as_slice(), b"fixture-value-three");
        assert_eq!(store.record(&secret_id).unwrap().unwrap().current_version, 3);

        client
            .request(ControlCommand::SharedSecretUpdate {
                resource_id: "fixture-shared-secret".to_string(),
                name: "Metadata Only Rename".to_string(),
                default_env_key: Some("RENAMED_TOKEN".to_string()),
                value: None,
                enforcement: Enforcement::Allow,
                metadata: ItemMetadata {
                    note: Some("Metadata-only edit".to_string()),
                    links: Vec::new(),
                },
            })
            .unwrap();
        assert_eq!(store.record(&secret_id).unwrap().unwrap().current_version, 3);
        assert_eq!(
            catalog.resource("fixture-shared-secret").unwrap().metadata.note.as_deref(),
            Some("Metadata-only edit")
        );

        assert_eq!(
            client
                .request(ControlCommand::SharedSecretRemove {
                    resource_id: "fixture-shared-secret".to_string(),
                })
                .unwrap(),
            ControlResult::Empty
        );
        assert!(matches!(
            catalog.resource("fixture-shared-secret"),
            Err(CatalogError::NotFound(_))
        ));
        assert!(store.record(&secret_id).unwrap().is_none());
    }

    #[test]
    fn shared_secret_remove_refuses_to_orphan_project_bindings() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let store = Arc::new(FixtureStore::new());
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            dir.path().join("mount"),
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        client
            .request(ControlCommand::SharedSecretCreate {
                resource_id: "fixture-shared-secret".to_string(),
                name: "Fixture Shared Secret".to_string(),
                default_env_key: Some("FIXTURE_TOKEN".to_string()),
                value: crate::protocol::SecretValue::new("fixture-bound-value"),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            })
            .unwrap();
        client
            .request(ControlCommand::ProjectUpsert {
                project: Project {
                    id: "fixture-project".to_string(),
                    name: "Fixture Project".to_string(),
                    path: PathBuf::from("/fixture/project"),
                    ..Default::default()
                },
            })
            .unwrap();
        client
            .request(ControlCommand::BindingUpsert {
                binding: Binding {
                    id: "fixture-binding".to_string(),
                    project_id: "fixture-project".to_string(),
                    scope: BindingScope::Common,
                    resource_id: "fixture-shared-secret".to_string(),
                    selection: EntrySelection::All,
                    key_override: None,
                    enabled: true,
                    allow_override: false,
                    position: 0,
                },
            })
            .unwrap();

        let error = client
            .request(ControlCommand::SharedSecretRemove {
                resource_id: "fixture-shared-secret".to_string(),
            })
            .unwrap_err();
        assert!(error.to_string().contains("resource_in_use"));
        assert!(catalog.resource("fixture-shared-secret").is_ok());
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert!(store.record(&secret_id).unwrap().is_some());
    }

    #[test]
    fn protecting_a_file_preserves_a_save_that_races_with_encryption() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let mount = dir.path().join("mount");
        let source = dir.path().join(".env");
        std::fs::write(&source, b"FIXTURE_VALUE=before\n").unwrap();
        let store = FixtureStore::new();
        let changed_source = source.clone();
        store.after_next_mutation(move || {
            std::fs::write(changed_source, b"FIXTURE_VALUE=after\n").unwrap();
        });

        let error = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount),
                ..DispatchServices::default()
            },
            ControlCommand::FileProtect { path: source.clone() },
        )
        .unwrap_err();

        let DispatchError::Validation(message) = error else {
            panic!("expected concurrent protection validation error");
        };
        assert!(message.contains("changed while it was being protected"));
        assert!(!std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&source).unwrap(), b"FIXTURE_VALUE=after\n");
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn failed_reprotection_restores_the_previous_store_head() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let mount = dir.path().join("mount");
        let source = dir.path().join(".env");
        std::fs::write(&source, b"FIXTURE_VALUE=candidate\n").unwrap();
        let canonical_source = canonical_source_path(&source).unwrap();
        let store = FixtureStore::new();
        let id = store
            .put(
                NewSecret::file(canonical_source, 0o600),
                b"FIXTURE_VALUE=previous\n",
            )
            .unwrap();
        let changed_source = source.clone();
        store.after_next_mutation(move || {
            std::fs::write(changed_source, b"FIXTURE_VALUE=after\n").unwrap();
        });

        let error = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                mount_path: Some(&mount),
                ..DispatchServices::default()
            },
            ControlCommand::FileProtect { path: source.clone() },
        )
        .unwrap_err();

        let DispatchError::Validation(message) = error else {
            panic!("expected concurrent reprotection validation error");
        };
        assert!(message.contains("changed while it was being protected"));
        assert_eq!(std::fs::read(&source).unwrap(), b"FIXTURE_VALUE=after\n");
        assert_eq!(store.get(&id).unwrap().as_slice(), b"FIXTURE_VALUE=previous\n");
        assert_eq!(store.record(&id).unwrap().unwrap().current_version, 1);
    }

    #[test]
    fn protects_an_existing_file_at_its_original_path_and_lists_it() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let mount = dir.path().join("mount");
        let project = dir.path().join("project");
        let worktree = dir.path().join("project-feature");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&worktree).unwrap();
        let project = std::fs::canonicalize(project).unwrap();
        let worktree = std::fs::canonicalize(worktree).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: project.clone(),
                ..Default::default()
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-production".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Production".to_string(),
                position: 1,
            })
            .unwrap();
        catalog
            .upsert_checkout(&ProjectCheckout {
                id: "fixture-feature".to_string(),
                project_id: "fixture-project".to_string(),
                path: worktree.clone(),
                kind: ProjectCheckoutKind::Worktree,
                environment_id: Some("fixture-development".to_string()),
                ..Default::default()
            })
            .unwrap();
        let source = project.join(".envrc");
        std::fs::write(&source, "export FIXTURE_VALUE='fixture-value'\n").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let canonical_source = canonical_source_path(&source).unwrap();
        let store = Arc::new(FixtureStore::new());
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog,
            Arc::clone(&store) as Arc<dyn SecretStore>,
            mount.clone(),
            Arc::clone(&observer) as Arc<dyn CatalogObserver>,
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let protected = client
            .request(ControlCommand::FileProtect { path: source.clone() })
            .unwrap();
        let ControlResult::FileProtected { file, created } = protected else {
            panic!("expected protected file result");
        };
        assert!(created);
        assert_eq!(file.source_path, canonical_source);
        assert_eq!(file.mode, 0o600);
        assert_eq!(file.current_version, 1);
        assert_eq!(file.enforcement, Enforcement::Allow);
        assert!(file.linked);
        assert_eq!(
            file.environment_ids,
            vec!["fixture-development", "fixture-production"]
        );
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
        assert!(std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(&source).unwrap(),
            mount.join(floria_core::config::SECRETS_DIR).join(FIXTURE_SECRET_ID)
        );
        std::fs::remove_file(&source).unwrap();
        symlink("../foreign/.envrc", &source).unwrap();
        assert_eq!(
            client
                .request(ControlCommand::ManagedLinkRepair { path: source.clone() })
                .unwrap(),
            ControlResult::Empty
        );
        assert_eq!(
            std::fs::read_link(&source).unwrap(),
            mount.join(floria_core::config::SECRETS_DIR).join(FIXTURE_SECRET_ID)
        );
        symlink(
            mount.join(floria_core::config::SECRETS_DIR).join(FIXTURE_SECRET_ID),
            worktree.join(".envrc"),
        )
        .unwrap();
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(
            store.get(&secret_id).unwrap().as_slice(),
            b"export FIXTURE_VALUE='fixture-value'\n"
        );

        let listed = client.request(ControlCommand::ProtectedFiles).unwrap();
        let ControlResult::ProtectedFiles(files) = listed else {
            panic!("expected protected files result");
        };
        assert_eq!(files, vec![file.clone()]);

        let file_metadata = ItemMetadata {
            note: Some("Loaded automatically by direnv".to_string()),
            links: vec![ItemLink {
                label: "Project documentation".to_string(),
                url: "https://example.invalid/docs/local-env".to_string(),
            }],
        };
        assert_eq!(
            client
                .request(ControlCommand::ProtectedFileMetadataUpdate {
                    id: FIXTURE_SECRET_ID.to_string(),
                    enforcement: Enforcement::TouchId,
                    environment_ids: vec!["fixture-production".to_string()],
                    metadata: file_metadata.clone(),
                })
                .unwrap(),
            ControlResult::Empty
        );
        let ControlResult::ProtectedFiles(files) =
            client.request(ControlCommand::ProtectedFiles).unwrap()
        else {
            panic!("expected protected files result");
        };
        assert_eq!(files[0].metadata, file_metadata);
        assert_eq!(files[0].environment_ids, vec!["fixture-production"]);
        assert_eq!(files[0].enforcement, Enforcement::TouchId);
        assert_eq!(files[0].current_version, 1);

        let mut expected_file = file.clone();
        expected_file.metadata = file_metadata;
        expected_file.enforcement = Enforcement::TouchId;
        expected_file.environment_ids = vec!["fixture-production".to_string()];
        assert_eq!(
            client
                .request(ControlCommand::FileProtect { path: source.clone() })
                .unwrap(),
            ControlResult::FileProtected {
                file: expected_file.clone(),
                created: false,
            }
        );

        let replacement = dir.path().join("replacement.bin");
        let replacement_bytes = b"\0fixture-binary\xff\n";
        std::fs::write(&replacement, replacement_bytes).unwrap();
        let source_target = std::fs::read_link(&source).unwrap();
        let updated = client
            .request(ControlCommand::ProtectedFileContentsUpdate {
                id: FIXTURE_SECRET_ID.to_string(),
                path: replacement.clone(),
            })
            .unwrap();
        let ControlResult::ProtectedFileUpdated { file: updated_file } = updated else {
            panic!("expected protected file update");
        };
        assert_eq!(updated_file.current_version, 2);
        assert_eq!(updated_file.size, replacement_bytes.len() as u64);
        assert_eq!(updated_file.metadata, expected_file.metadata);
        assert_eq!(updated_file.environment_ids, expected_file.environment_ids);
        assert_eq!(store.get(&secret_id).unwrap().as_slice(), replacement_bytes);
        assert_eq!(std::fs::read_link(&source).unwrap(), source_target);

        let unchanged = client
            .request(ControlCommand::ProtectedFileContentsUpdate {
                id: FIXTURE_SECRET_ID.to_string(),
                path: replacement,
            })
            .unwrap();
        let ControlResult::ProtectedFileUpdated { file: unchanged_file } = unchanged else {
            panic!("expected unchanged protected file update");
        };
        assert_eq!(
            unchanged_file.current_version, 2,
            "selecting identical bytes must not create a redundant version"
        );

        let invalid_update = client
            .request(ControlCommand::ProtectedFileContentsUpdate {
                id: FIXTURE_SECRET_ID.to_string(),
                path: dir.path().to_path_buf(),
            })
            .unwrap_err();
        assert!(invalid_update.to_string().contains("not a regular file"));
        assert_eq!(store.record(&secret_id).unwrap().unwrap().current_version, 2);

        let history = client
            .request(ControlCommand::ProtectedFileHistory {
                id: FIXTURE_SECRET_ID.to_string(),
            })
            .unwrap();
        let ControlResult::ProtectedFileHistory { versions, .. } = history else {
            panic!("expected protected file history");
        };
        assert_eq!(versions.len(), 2);
        assert!(!versions[0].current);
        assert!(versions[1].current);

        let rolled_back = client
            .request(ControlCommand::ProtectedFileRollback {
                id: FIXTURE_SECRET_ID.to_string(),
                version: 1,
            })
            .unwrap();
        let ControlResult::ProtectedFileRolledBack { file } = rolled_back else {
            panic!("expected protected file rollback");
        };
        assert_eq!(file.current_version, 1);
        assert_eq!(
            observer.notifications.load(Ordering::Relaxed),
            7,
            "rolling back a protected-file head must refresh managed runtime policy"
        );

        client
            .request(ControlCommand::ResourceUpsert {
                resource: Resource {
                    id: "fixture-protected-file-resource".to_string(),
                    name: "Fixture Protected File".to_string(),
                    kind: ResourceKind::Secret,
                    shape: ValueShape::Bytes,
                    codec: ResourceCodec::Opaque,
                    default_env_key: None,
                    entries: Vec::new(),
                    source: ResourceSource::SecretRef {
                        secret_id: FIXTURE_SECRET_ID.to_string(),
                    },
                    enforcement: Enforcement::Prompt,
                    metadata: Default::default(),
                    origin: Default::default(),
                },
                endpoint: None,
            })
            .unwrap();
        let restore_error = client
            .request(ControlCommand::FileRestore {
                id: FIXTURE_SECRET_ID.to_string(),
            })
            .unwrap_err();
        assert!(restore_error.to_string().contains("still used by catalog resources"));
        assert!(std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        client
            .request(ControlCommand::ResourceRemove {
                id: "fixture-protected-file-resource".to_string(),
            })
            .unwrap();

        assert_eq!(
            client
                .request(ControlCommand::FileRestore {
                    id: FIXTURE_SECRET_ID.to_string(),
                })
                .unwrap(),
            ControlResult::FileRestored { path: canonical_source, storage_deleted: true }
        );
        assert!(!std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_to_string(&source).unwrap(),
            "export FIXTURE_VALUE='fixture-value'\n"
        );
        assert_eq!(
            std::fs::metadata(&source).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(!worktree.join(".envrc").exists());
        assert!(store.record(&secret_id).unwrap().is_none());
    }

    #[test]
    fn configures_a_managed_env_file_only_after_an_explicit_request() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let mount = dir.path().join("mount");
        let project_path = dir.path().join("project");
        let worktree_path = dir.path().join("worktree");
        std::fs::create_dir_all(&project_path).unwrap();
        std::fs::create_dir_all(&worktree_path).unwrap();
        let project_path = std::fs::canonicalize(project_path).unwrap();
        let worktree_path = std::fs::canonicalize(worktree_path).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture".to_string(),
                path: project_path.clone(),
                ..Default::default()
            })
            .unwrap();
        catalog
            .upsert_environment(&Environment {
                id: "fixture-development".to_string(),
                project_id: "fixture-project".to_string(),
                name: "Development".to_string(),
                position: 0,
            })
            .unwrap();
        catalog
            .upsert_checkout(&ProjectCheckout {
                id: "fixture-worktree".to_string(),
                project_id: "fixture-project".to_string(),
                path: worktree_path.clone(),
                environment_id: Some("fixture-development".to_string()),
                kind: ProjectCheckoutKind::Worktree,
                ..Default::default()
            })
            .unwrap();
        let source = project_path.join(".dev.vars");
        std::fs::write(&source, "FIRST=fixture-one\nSECOND=fixture-two\n").unwrap();
        let store = Arc::new(FixtureStore::new());
        let observer = Arc::new(SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        });
        let _server = ControlServer::start_runtime(
            &socket,
            catalog.clone(),
            Arc::clone(&store) as Arc<dyn SecretStore>,
            mount.clone(),
            observer,
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        client
            .request(ControlCommand::FileProtect { path: source.clone() })
            .unwrap();
        let before = catalog.snapshot().unwrap();
        assert!(before.resources.is_empty());
        assert!(before.bindings.is_empty());
        assert!(before.surfaces.is_empty());

        let configured = client
            .request(ControlCommand::ManagedFileConfigure {
                id: FIXTURE_SECRET_ID.to_string(),
                project_id: "fixture-project".to_string(),
                environment_id: Some("fixture-development".to_string()),
            })
            .unwrap();
        let ControlResult::ManagedFileConfigured { surface } = configured else {
            panic!("expected configured managed file");
        };
        assert_eq!(surface.path, source);
        assert_eq!(
            surface.kind,
            SurfaceKind::File(floria_catalog::FileBacking::Composed(
                floria_catalog::SurfaceFormat::Dotenv
            ))
        );
        assert_eq!(
            std::fs::read_link(&source).unwrap(),
            mount.join(floria_core::config::SURFACES_DIR).join(&surface.id)
        );
        symlink(
            mount.join(floria_core::config::SURFACES_DIR).join(&surface.id),
            worktree_path.join(".dev.vars"),
        )
        .unwrap();

        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.resources[0].kind, ResourceKind::EnvFile);
        assert_eq!(snapshot.resources[0].codec, ResourceCodec::Dotenv);
        assert_eq!(
            snapshot.resources[0].entries.iter().filter_map(|entry| entry.key.as_deref()).collect::<Vec<_>>(),
            vec!["FIRST", "SECOND"]
        );
        assert_eq!(
            snapshot.resources[0].source,
            ResourceSource::SecretRef { secret_id: FIXTURE_SECRET_ID.to_string() }
        );
        assert_eq!(snapshot.bindings.len(), 1);
        assert_eq!(snapshot.surfaces, vec![surface.clone()]);

        let ControlResult::ProtectedFiles(files) =
            client.request(ControlCommand::ProtectedFiles).unwrap()
        else {
            panic!("expected protected files result");
        };
        assert!(
            files.is_empty(),
            "a configured file must have one project-facing representation"
        );
        let ControlResult::ProtectedFile(configured_file) = client
            .request(ControlCommand::ProtectedFileLookup {
                id: None,
                path: Some(source.clone()),
            })
            .unwrap()
        else {
            panic!("expected configured protected file lookup");
        };
        assert_eq!(configured_file.id, FIXTURE_SECRET_ID);
        assert_eq!(configured_file.source_path, source);
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(store.record(&secret_id).unwrap().unwrap().current_version, 1);

        let restored = client
            .request(ControlCommand::ManagedFileRestore {
                id: surface.id.clone(),
            })
            .unwrap();
        assert_eq!(
            restored,
            ControlResult::FileRestored {
                path: source.clone(),
                storage_deleted: true,
            }
        );
        assert!(!std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_to_string(&source).unwrap(),
            "FIRST=fixture-one\nSECOND=fixture-two\n"
        );
        assert_eq!(
            std::fs::read_to_string(worktree_path.join(".dev.vars")).unwrap(),
            "FIRST=fixture-one\nSECOND=fixture-two\n"
        );
        assert!(!std::fs::symlink_metadata(worktree_path.join(".dev.vars"))
            .unwrap()
            .file_type()
            .is_symlink());
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.resources.is_empty());
        assert!(snapshot.bindings.is_empty());
        assert!(snapshot.surfaces.is_empty());
        assert!(store.record(&secret_id).unwrap().is_none());
    }

    #[test]
    fn env_file_create_parses_keys_and_only_stores_a_reference_in_catalog() {
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
            dir.path().join("mount"),
            observer,
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::EnvFileCreate {
                resource_id: "fixture-env-file".to_string(),
                name: "Fixture Env File".to_string(),
                codec: ResourceCodec::Dotenv,
                value: crate::protocol::SecretValue::new(
                    "API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n",
                ),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata {
                    note: Some("Local application defaults".to_string()),
                    links: Vec::new(),
                },
            })
            .unwrap();
        let ControlResult::EnvFileCreated { resource, version } = created else {
            panic!("expected env file creation result");
        };
        assert_eq!(version, 1);
        assert_eq!(resource.kind, ResourceKind::EnvFile);
        assert_eq!(resource.codec, ResourceCodec::Dotenv);
        assert_eq!(resource.metadata.note.as_deref(), Some("Local application defaults"));
        assert_eq!(
            resource.entries.iter().filter_map(|entry| entry.key.as_deref()).collect::<Vec<_>>(),
            vec!["API_HOST", "LOG_LEVEL"]
        );
        let ResourceSource::SecretRef { secret_id } = resource.source else {
            panic!("expected a store reference");
        };
        let id: SecretId = secret_id.parse().unwrap();
        assert_eq!(
            store.get(&id).unwrap().as_slice(),
            b"API_HOST=http://127.0.0.1:8787\nLOG_LEVEL=debug\n"
        );
        let encoded = serde_json::to_string(&catalog.snapshot().unwrap()).unwrap();
        assert!(!encoded.contains("127.0.0.1"));
        assert!(!encoded.contains("LOG_LEVEL=debug"));

        client
            .request(ControlCommand::ResourceMetadataUpdate {
                resource_id: "fixture-env-file".to_string(),
                name: "Renamed Env File".to_string(),
                enforcement: Enforcement::TouchId,
                metadata: ItemMetadata {
                    note: Some("Values imported from the local stack".to_string()),
                    links: Vec::new(),
                },
            })
            .unwrap();
        let updated = catalog.resource("fixture-env-file").unwrap();
        assert_eq!(updated.name, "Renamed Env File");
        assert_eq!(
            updated.metadata.note.as_deref(),
            Some("Values imported from the local stack")
        );
    }

    #[test]
    fn ini_env_file_create_exposes_ordered_section_entries_without_storing_values_in_catalog() {
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
            dir.path().join("mount"),
            observer,
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let created = client
            .request(ControlCommand::EnvFileCreate {
                resource_id: "fixture-ini-file".to_string(),
                name: "Fixture INI File".to_string(),
                codec: ResourceCodec::Ini,
                value: crate::protocol::SecretValue::new(
                    "[fixture-one]\nregion=fixture-region\noutput=fixture-output\n[fixture-two]\nregion=fixture-region-two\n",
                ),
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            })
            .unwrap();
        let ControlResult::EnvFileCreated { resource, version } = created else {
            panic!("expected env file creation result");
        };

        assert_eq!(version, 1);
        assert_eq!(resource.codec, ResourceCodec::Ini);
        assert_eq!(
            resource.entries.iter().map(|entry| entry.address.as_str()).collect::<Vec<_>>(),
            vec![
                "sections/fixture-one/keys/region",
                "sections/fixture-one/keys/output",
                "sections/fixture-two/keys/region",
            ]
        );
        assert_eq!(resource.entries[0].label, "[fixture-one] region");
        let encoded = serde_json::to_string(&catalog.snapshot().unwrap()).unwrap();
        assert!(!encoded.contains("fixture-region-two"));
        assert!(!encoded.contains("fixture-output"));
    }
