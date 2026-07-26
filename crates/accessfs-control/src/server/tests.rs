    use super::*;
    use accessfs_catalog::SurfaceInput;
    use accessfs_core::audit::AuditLog;
    use accessfs_core::identity::{ProcSummary, ProcessIdentity};
    use accessfs_platform::{
        PeerVerificationError, SameUserPeerVerifier, SocketPeerVerifier, VerifiedPeer,
    };
    use crate::client::ControlClient;
    use accessfs_catalog::{
        Binding, BindingScope, EntrySelection, Environment, ItemLink, Project, Surface, SurfaceKind,
    };
    use accessfs_store::{
        SecretOrigin, SecretRecord, StoreResult, VersionRecord,
    };
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
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

    const FIXTURE_SECRET_ID: &str = "00000000-0000-0000-0000-000000000101";

    struct FixtureStore {
        entries: Mutex<HashMap<String, Vec<Vec<u8>>>>,
        metadata: Mutex<HashMap<String, (SecretOrigin, u32, ItemMetadata)>>,
        heads: Mutex<HashMap<String, u32>>,
    }

    impl FixtureStore {
        fn new() -> Self {
            FixtureStore {
                entries: Mutex::new(HashMap::new()),
                metadata: Mutex::new(HashMap::new()),
                heads: Mutex::new(HashMap::new()),
            }
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
                        | "DISCOVERED_TOKEN"
                        | "OPTIONAL_NEW_TOKEN"
                        | "credentials"
                        | "DEBUG"
                        | ".env"
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
                .insert(id.to_string(), (meta.origin, meta.mode, ItemMetadata::default()));
            self.heads.lock().unwrap().insert(id.to_string(), 1);
            Ok(id)
        }

        fn get(&self, id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
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
            self.heads.lock().unwrap().insert(id.to_string(), version);
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
                origin: metadata[id.as_str()].0.clone(),
                mode: metadata[id.as_str()].1,
                size: versions[(heads[id.as_str()] - 1) as usize].len() as u64,
                created: "fixture-time".to_string(),
                current_version: heads[id.as_str()],
                enforcement: Enforcement::Prompt,
                metadata: metadata[id.as_str()].2.clone(),
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
                    origin: metadata[id].0.clone(),
                    mode: metadata[id].1,
                    size: versions[(heads[id] - 1) as usize].len() as u64,
                    created: "fixture-time".to_string(),
                    current_version: heads[id],
                    enforcement: Enforcement::Prompt,
                    metadata: metadata[id].2.clone(),
                })
                .collect())
        }

        fn get_by_path(&self, source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            let id = self
                .metadata
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, (origin, _, _))| match origin {
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
            _enforcement: Enforcement,
        ) -> StoreResult<()> {
            self.metadata.lock().unwrap().get_mut(id.as_str()).unwrap().2 = item_metadata;
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

        let checkout = accessfs_catalog::ProjectCheckout {
            id: "fixture-worktree".to_string(),
            project_id: "fixture-project".to_string(),
            path: worktree.clone(),
            environment_id: Some("fixture-development".to_string()),
            kind: accessfs_catalog::ProjectCheckoutKind::Worktree,
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
    fn access_history_returns_persisted_reader_metadata_with_surface_display_path() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog
            .upsert_project(&Project {
                id: "fixture-project".to_string(),
                name: "Fixture Project".to_string(),
                path: dir.path().join("project"),
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
            ControlCommand::Discover { path: project_path },
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
            accessfs_discover::DiscoveredEntryAction::ReuseSharedSecret {
                ref resource_id,
                ..
            }
                if resource_id == "fixture-shared-api-token"
        ));
        assert!(plan.files[0].entries.iter().any(|entry| {
            entry.key == "OTHER"
                && entry.action == accessfs_discover::DiscoveredEntryAction::CreateEnvFileEntry
        }));
    }

    #[test]
    fn discovery_apply_replaces_dotenv_with_a_composed_surface() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path.clone(),
                files: Some(vec![source_path.clone()]),
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
        assert_eq!(
            std::fs::read_link(&source_path).unwrap(),
            mount_path
                .join(accessfs_core::config::SURFACES_DIR)
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
    fn discovery_apply_splits_plain_values_into_an_env_file_with_origins() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path,
                files: Some(vec![source_path.clone()]),
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
        assert_eq!(secret.enforcement, Enforcement::Prompt);
        assert_eq!(secret.origin.kind, accessfs_catalog::OriginKind::Discovered);
        assert_eq!(secret.origin.sources.len(), 1);
        assert_eq!(secret.origin.sources[0].path, source_path);
        let env_file = snapshot
            .resources
            .iter()
            .find(|resource| resource.kind == ResourceKind::EnvFile)
            .unwrap();
        assert_eq!(env_file.name, ".env");
        assert_eq!(env_file.enforcement, Enforcement::Allow);
        assert_eq!(env_file.origin.kind, accessfs_catalog::OriginKind::Discovered);
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
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path,
                files: Some(vec![source_path.clone()]),
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
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                enforcement: Enforcement::Prompt,
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
                path: project_path,
                files: Some(vec![source_path.clone()]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let resource = catalog.resource("fixture-shared-api-token").unwrap();
        assert_eq!(resource.origin.kind, accessfs_catalog::OriginKind::Manual);
        assert_eq!(resource.origin.sources.len(), 1);
        assert_eq!(resource.origin.sources[0].path, source_path);
    }

    #[test]
    fn discovery_apply_mutates_only_reviewed_files() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let development_path = project_path.join(".env");
        let production_path = project_path.join(".env.production");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path,
                files: Some(vec![production_path.clone()]),
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
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path.clone(),
                files: None,
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
        assert!(result.files.iter().any(|file| {
            file.path == reference_path && file.outcome == DiscoveryApplyOutcome::Skipped
        }));
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.surfaces.len(), 1);

        let rediscovered = dispatch(
            &catalog,
            DispatchServices { store: Some(&store), ..DispatchServices::default() },
            ControlCommand::Discover { path: project_path.clone() },
        )
        .unwrap();
        let ControlResult::Discovery(plan) = rediscovered else {
            panic!("expected discovery result");
        };
        assert_eq!(
            plan.project.managed_project_id.as_deref(),
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
                    == accessfs_discover::DiscoveredEntryAction::ReferenceEntry { matched: true }
        }));
        assert!(reference.entries.iter().any(|entry| {
            entry.key == "OPTIONAL_REUSED_TOKEN"
                && entry.action
                    == accessfs_discover::DiscoveredEntryAction::ReferenceEntry { matched: false }
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
            ControlCommand::Discover { path: project_path },
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
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path,
                files: Some(vec![development_path, production_path]),
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
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path,
                files: Some(vec![development_path, production_path.clone()]),
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
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path.clone(),
                files: Some(vec![project_path.join(".env.not-reviewed")]),
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
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path,
                files: Some(vec![dotenv_path.clone(), ssh_path.clone()]),
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
    fn discovery_apply_keeps_aws_credentials_section_aware() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".aws/credentials");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(mount_path.join(accessfs_core::config::SURFACES_DIR)).unwrap();
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
                path: project_path,
                files: Some(vec![source_path.clone()]),
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
        assert!(snapshot.resources[0]
            .entries
            .iter()
            .any(|entry| entry.address.contains("default")));
        assert!(snapshot.resources[0]
            .entries
            .iter()
            .any(|entry| entry.address.contains("staging")));
        assert_eq!(snapshot.surfaces[0].kind, SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Ini)));
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
        let stored_identity = accessfs_ssh::identity_from_private_key(&stored).unwrap();
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
            ControlResult::Pong { schema_version: 11 }
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
    fn protects_an_existing_file_at_its_original_path_and_lists_it() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let mount = dir.path().join("mount");
        let source = dir.path().join(".envrc");
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
        assert!(file.linked);
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
        assert!(std::fs::symlink_metadata(&source).unwrap().file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(&source).unwrap(),
            mount.join(accessfs_core::config::SECRETS_DIR).join(FIXTURE_SECRET_ID)
        );
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
        assert_eq!(files[0].current_version, 1);

        let mut expected_file = file.clone();
        expected_file.metadata = file_metadata;
        assert_eq!(
            client
                .request(ControlCommand::FileProtect { path: source.clone() })
                .unwrap(),
            ControlResult::FileProtected { file: expected_file, created: false }
        );

        store
            .append_version(&secret_id, b"export FIXTURE_VALUE='fixture-updated'\n")
            .unwrap();
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
            4,
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

