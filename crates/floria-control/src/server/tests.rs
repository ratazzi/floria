    use super::*;
    use floria_catalog::SurfaceInput;
    use floria_core::audit::AuditLog;
    use floria_core::identity::{ProcSummary, ProcessIdentity};
    use floria_platform::{
        PeerAccess, PeerVerificationError, SameUserPeerVerifier, SocketPeerVerifier, VerifiedPeer,
    };
    use crate::client::ControlClient;
    use floria_catalog::{
        Binding, BindingScope, EntrySelection, Environment, ItemLink, Project, ProjectCheckout,
        ProjectCheckoutKind, ReplicatedCatalog, ReplicatedProject, ReplicatedSurface, Surface,
        SurfaceKind,
    };
    use floria_store::{
        SecretOrigin, SecretRecord, StoreResult, VersionRecord,
    };
    use std::collections::{HashMap, HashSet};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Mutex};
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

    struct ReadOnlyPeers;

    impl SocketPeerVerifier for ReadOnlyPeers {
        fn verify(&self, _stream: &UnixStream) -> Result<VerifiedPeer, PeerVerificationError> {
            Ok(VerifiedPeer {
                identity: ProcessIdentity::bare(
                    std::process::id() as i32,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                ),
                access: PeerAccess::ReadOnly,
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

    struct FixtureRecoveryKeyExporter;

    impl RecoveryKeyExporter for FixtureRecoveryKeyExporter {
        fn export(
            &self,
            destination: &Path,
            passphrase: &str,
        ) -> Result<RecoveryKeyReport, String> {
            if passphrase != "fixture recovery phrase" {
                return Err("unexpected recovery passphrase".to_string());
            }
            Ok(RecoveryKeyReport { path: destination.to_path_buf() })
        }
    }

    struct FixtureHealthReporter;

    impl RuntimeHealthReporter for FixtureHealthReporter {
        fn report(&self) -> HealthReport {
            HealthReport::new(vec![crate::protocol::HealthCheck {
                id: "catalog".to_string(),
                status: crate::protocol::HealthStatus::Healthy,
                title: "Catalog".to_string(),
                message: "Ready".to_string(),
                guidance: None,
            }])
        }
    }

    struct FixtureDiagnosticsExporter;

    impl RuntimeDiagnosticsExporter for FixtureDiagnosticsExporter {
        fn export(
            &self,
            destination: &Path,
            include_paths: bool,
        ) -> Result<DiagnosticsReport, String> {
            Ok(DiagnosticsReport {
                path: destination.to_path_buf(),
                paths_included: include_paths,
                files: 4,
                bytes: 512,
            })
        }
    }

    #[derive(Default)]
    struct FixtureRecordSyncService {
        status_calls: AtomicUsize,
        conflict_review_calls: AtomicUsize,
        conflict_resolution_calls: AtomicUsize,
        bootstrap_calls: AtomicUsize,
        bootstrap_validation_calls: AtomicUsize,
        enrollment_preparation_calls: AtomicUsize,
        enrollment_review_calls: AtomicUsize,
        device_review_calls: AtomicUsize,
        enrollment_approval_calls: AtomicUsize,
        device_revocation_calls: AtomicUsize,
        activation_calls: AtomicUsize,
        outbound_calls: AtomicUsize,
        settlement_calls: AtomicUsize,
        inbound_calls: AtomicUsize,
    }

    impl RuntimeRecordSyncService for FixtureRecordSyncService {
        fn status(&self) -> Result<SyncDomainStatus, String> {
            self.status_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SyncDomainStatus::default())
        }

        fn review_conflicts(&self) -> Result<Vec<SyncConflictReview>, String> {
            self.conflict_review_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        }

        fn resolve_conflict(
            &self,
            _entity_id: &str,
            _selected_revision_id: &str,
            _resolved_at: &str,
        ) -> Result<SyncDomainStatus, String> {
            self.conflict_resolution_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SyncDomainStatus::default())
        }

        fn vault_bootstrap(&self) -> Result<SyncVaultBootstrap, String> {
            self.bootstrap_calls.fetch_add(1, Ordering::Relaxed);
            Ok(serde_json::from_value(serde_json::json!({
                "vault_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "vault_document_base64": "dmF1bHQ=",
                "device_identities": [],
                "enrollment_requests": [],
                "key_generations": [],
                "generation_envelopes": []
            }))
            .expect("fixture Vault bootstrap"))
        }

        fn validate_vault_bootstrap(
            &self,
            expected_vault_id: &str,
            bootstrap: SyncVaultBootstrap,
        ) -> Result<SyncVaultBootstrap, String> {
            self.bootstrap_validation_calls
                .fetch_add(1, Ordering::Relaxed);
            if bootstrap.vault_id() != expected_vault_id {
                return Err("fixture Vault route mismatch".to_string());
            }
            Ok(bootstrap)
        }

        fn prepare_vault_enrollment(
            &self,
            _bootstrap: SyncVaultBootstrap,
            _device_name: Option<String>,
            _requested_at: &str,
        ) -> Result<SyncEnrollmentPreparation, String> {
            self.enrollment_preparation_calls
                .fetch_add(1, Ordering::Relaxed);
            Ok(serde_json::from_value(serde_json::json!({
                "status": "already_enrolled",
                "device_id": "fixture-device"
            }))
            .expect("fixture enrollment preparation"))
        }

        fn prepare_vault_reenrollment(
            &self,
            _bootstrap: SyncVaultBootstrap,
            _expected_fingerprint: &str,
            _device_name: Option<String>,
            _requested_at: &str,
        ) -> Result<SyncEnrollmentPreparation, String> {
            self.enrollment_preparation_calls
                .fetch_add(1, Ordering::Relaxed);
            Ok(serde_json::from_value(serde_json::json!({
                "status": "already_enrolled",
                "device_id": "fixture-device"
            }))
            .expect("fixture reenrollment preparation"))
        }

        fn review_vault_enrollments(
            &self,
            _bootstrap: SyncVaultBootstrap,
        ) -> Result<Vec<SyncEnrollmentReview>, String> {
            self.enrollment_review_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        }

        fn review_vault_devices(
            &self,
            _bootstrap: SyncVaultBootstrap,
        ) -> Result<Vec<SyncVaultDevice>, String> {
            self.device_review_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Vec::new())
        }

        fn approve_vault_enrollment(
            &self,
            bootstrap: SyncVaultBootstrap,
            _device_id: &str,
            _expected_fingerprint: &str,
        ) -> Result<SyncVaultBootstrap, String> {
            self.enrollment_approval_calls
                .fetch_add(1, Ordering::Relaxed);
            Ok(bootstrap)
        }

        fn revoke_vault_device(
            &self,
            bootstrap: SyncVaultBootstrap,
            _device_id: &str,
            _expected_fingerprint: &str,
        ) -> Result<SyncVaultBootstrap, String> {
            self.device_revocation_calls.fetch_add(1, Ordering::Relaxed);
            Ok(bootstrap)
        }

        fn activate_vault(
            &self,
            bootstrap: SyncVaultBootstrap,
        ) -> Result<SyncVaultActivation, String> {
            self.activation_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SyncVaultActivation::Ready {
                vault_id: bootstrap.vault_id().to_string(),
                key_generation: 1,
                restart_required: true,
            })
        }

        fn next_outbound(&self, _limit: usize) -> Result<SyncOutboundBatch, String> {
            self.outbound_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SyncOutboundBatch::default())
        }

        fn settle_outbound(
            &self,
            _outcomes: &[SyncDeliveryOutcome],
        ) -> Result<SyncSettlementReport, String> {
            self.settlement_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SyncSettlementReport::default())
        }

        fn apply_inbound(
            &self,
            _catalog: &Catalog,
            _batch: SyncInboundBatch,
            _observed_at: &str,
        ) -> Result<SyncInboundReport, String> {
            self.inbound_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SyncInboundReport::default())
        }
    }

    const FIXTURE_SECRET_ID: &str = "00000000-0000-0000-0000-000000000101";
    const FIXTURE_FILE_SECRET_ID: &str = "00000000-0000-0000-0000-000000000102";

    struct FixtureSecretMetadata {
        origin: SecretOrigin,
        mode: u32,
        enforcement: Enforcement,
        metadata: ItemMetadata,
        environment_ids: Option<Vec<String>>,
        placements: Vec<floria_store::ManagedPlacement>,
    }

    struct FixtureStore {
        entries: Mutex<HashMap<String, Vec<Vec<u8>>>>,
        metadata: Mutex<HashMap<String, FixtureSecretMetadata>>,
        heads: Mutex<HashMap<String, u32>>,
        mutation_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        before_append_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        get_calls: AtomicUsize,
        list_calls: AtomicUsize,
    }

    impl FixtureStore {
        fn new() -> Self {
            FixtureStore {
                entries: Mutex::new(HashMap::new()),
                metadata: Mutex::new(HashMap::new()),
                heads: Mutex::new(HashMap::new()),
                mutation_hook: Mutex::new(None),
                before_append_hook: Mutex::new(None),
                get_calls: AtomicUsize::new(0),
                list_calls: AtomicUsize::new(0),
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

        fn before_next_append(&self, hook: impl FnOnce() + Send + 'static) {
            *self.before_append_hook.lock().unwrap() = Some(Box::new(hook));
        }

        fn run_before_append_hook(&self) {
            if let Some(hook) = self.before_append_hook.lock().unwrap().take() {
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
                project_id: None,
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

    #[test]
    fn recovery_key_export_uses_the_runtime_service_and_requires_an_absolute_path() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let recovery_key = FixtureRecoveryKeyExporter;
        let destination = directory.path().join("Floria Recovery Key.age");

        let result = dispatch(
            &catalog,
            DispatchServices {
                recovery_key: Some(&recovery_key),
                ..DispatchServices::default()
            },
            ControlCommand::RecoveryKeyExport {
                destination: destination.clone(),
                passphrase: SecretValue::new("fixture recovery phrase"),
            },
        )
        .unwrap();

        assert!(matches!(
            result,
            ControlResult::RecoveryKey(RecoveryKeyReport { path }) if path == destination
        ));

        let relative = dispatch(
            &catalog,
            DispatchServices {
                recovery_key: Some(&recovery_key),
                ..DispatchServices::default()
            },
            ControlCommand::RecoveryKeyExport {
                destination: PathBuf::from("Floria Recovery Key.age"),
                passphrase: SecretValue::new("fixture recovery phrase"),
            },
        )
        .unwrap_err();
        assert!(matches!(relative, DispatchError::Validation(_)));
    }

    #[test]
    fn health_uses_the_runtime_reporter() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let health = FixtureHealthReporter;

        let result = dispatch(
            &catalog,
            DispatchServices {
                health: Some(&health),
                ..DispatchServices::default()
            },
            ControlCommand::Health,
        )
        .unwrap();

        assert!(matches!(
            result,
            ControlResult::Health(HealthReport {
                status: crate::protocol::HealthStatus::Healthy,
                checks,
            }) if checks.len() == 1 && checks[0].id == "catalog"
        ));
    }

    #[test]
    fn diagnostics_export_uses_the_runtime_service_and_requires_an_absolute_path() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let diagnostics = FixtureDiagnosticsExporter;
        let destination = directory.path().join("Floria Diagnostics");

        let result = dispatch(
            &catalog,
            DispatchServices {
                diagnostics: Some(&diagnostics),
                ..DispatchServices::default()
            },
            ControlCommand::DiagnosticsExport {
                destination: destination.clone(),
                include_paths: false,
            },
        )
        .unwrap();

        assert!(matches!(
            result,
            ControlResult::Diagnostics(DiagnosticsReport {
                path,
                paths_included: false,
                files: 4,
                bytes: 512,
            }) if path == destination
        ));

        let relative = dispatch(
            &catalog,
            DispatchServices {
                diagnostics: Some(&diagnostics),
                ..DispatchServices::default()
            },
            ControlCommand::DiagnosticsExport {
                destination: PathBuf::from("diagnostics"),
                include_paths: false,
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
                        | "prod.key"
                ));
            }
            let id: SecretId = if matches!(
                &meta.origin,
                SecretOrigin::File { source_path }
                    if source_path.file_name().is_some_and(|name| name == "prod.key")
            )
                && self.entries.lock().unwrap().contains_key(FIXTURE_SECRET_ID)
            {
                FIXTURE_FILE_SECRET_ID.parse().unwrap()
            } else {
                FIXTURE_SECRET_ID.parse().unwrap()
            };
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
                        placements: meta.placements,
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
            self.run_before_append_hook();
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
                    mutation_id: None,
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
                placements: metadata[id.as_str()].placements.clone(),
                metadata: metadata[id.as_str()].metadata.clone(),
            }))
        }

        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            self.list_calls.fetch_add(1, Ordering::Relaxed);
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
                    placements: metadata[id].placements.clone(),
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
            entry.environment_ids = environment_ids.clone();
            for placement in &mut entry.placements {
                if let floria_store::ManagedPlacement::Project {
                    environment_ids: placement_environment_ids,
                    ..
                } = placement
                {
                    *placement_environment_ids = environment_ids.clone().unwrap_or_default();
                }
            }
            Ok(())
        }

        fn update_placements(
            &self,
            id: &SecretId,
            placements: Vec<floria_store::ManagedPlacement>,
        ) -> StoreResult<()> {
            self.metadata.lock().unwrap().get_mut(id.as_str()).unwrap().placements = placements;
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
        assert!(!inventory.unchanged);

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
    fn unchanged_checkout_inventory_skips_catalog_store_composition() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();
        let monitor = GitCheckoutMonitor::start(Vec::new()).unwrap();
        let revision = monitor.inventory().revision;

        let result = dispatch(
            &catalog,
            DispatchServices {
                store: Some(&store),
                checkout_monitor: Some(&monitor),
                ..DispatchServices::default()
            },
            ControlCommand::ProjectCheckoutInventoryIfChanged { revision },
        )
        .unwrap();
        let ControlResult::ProjectCheckoutInventory(inventory) = result else {
            panic!("unexpected checkout inventory result")
        };

        assert_eq!(inventory.revision, revision);
        assert!(inventory.unchanged);
        assert!(inventory.projects.is_empty());
        assert_eq!(store.list_calls.load(Ordering::Relaxed), 0);
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
                .join(floria_core::config::ITEMS_DIR)
                .join(store.list().unwrap()[0].id.to_string())
                .join(".envrc")
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
    fn ssh_agent_surface_is_not_a_project_managed_link() {
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
        catalog
            .upsert_surface(&Surface {
                id: "fixture-agent".to_string(),
                environment_id: "fixture-environment".to_string(),
                name: "Fixture agent".to_string(),
                kind: SurfaceKind::UnixSocket,
                path: None,
                input: SurfaceInput::Bindings { binding_ids: Vec::new() },
                enforcement: Enforcement::Prompt,
                position: 0,
            })
            .unwrap();

        let ControlResult::Snapshot(snapshot) =
            dispatch(&catalog, DispatchServices::default(), ControlCommand::Snapshot).unwrap()
        else {
            panic!("expected workspace snapshot")
        };
        assert!(snapshot.managed_links.is_empty());
        assert!(!project.join("agent.sock").exists());
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
                scope: "today".to_string(),
                expires_at: Some(1_800_000_600),
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
                scope: "today".to_string(),
                expires_at: Some(1_800_000_600),
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
    fn item_history_uses_local_file_paths_and_keeps_deleted_filenames_readable() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let project_path = dir.path().join("project");
        catalog.upsert_project(&Project {
            id: "fixture-project".into(), name: "Fixture".into(),
            path: project_path.clone(), ..Default::default()
        }).unwrap();
        let snapshot = catalog.snapshot().unwrap();
        let source_path = project_path.join(".env.development");
        let mut record = SecretRecord {
            id: "00000000-0000-0000-0000-000000000901".parse().unwrap(),
            origin: SecretOrigin::File { source_path: source_path.clone() },
            mode: 0o600, size: 0, created: "fixture-time".into(), current_version: 1,
            enforcement: Enforcement::Prompt, environment_ids: None,
            placements: Vec::new(), metadata: Default::default(),
        };
        let path = format!("items/{}/.env.development", record.id);
        assert_eq!(history_display(&path, &snapshot, &[record.clone()]),
            Some(source_path.display().to_string()));
        record.origin = SecretOrigin::Managed { label: ".env.development".into() };
        record.placements = vec![ManagedPlacement::project(
            "fixture-project", ".env.development", Vec::new(),
        ).unwrap()];
        assert_eq!(history_display(&path, &snapshot, &[record]),
            Some(source_path.display().to_string()));
        assert_eq!(history_display(&path, &snapshot, &[]), Some(".env.development".into()));
        assert_eq!(history_display("items/missing/", &snapshot, &[]), None);
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
                path: Some(display_path.clone()),
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
        )
        .unwrap();

        let result = dispatch(
            &catalog,
            DispatchServices { audit_log: Some(&audit), ..DispatchServices::default() },
            ControlCommand::AccessHistory { limit: 500 },
        )
        .unwrap();
        let ControlResult::AccessHistory(events) = result else {
            panic!("expected access history");
        };
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].display.as_deref(), display_path.to_str());
        assert_eq!(
            history_display("items/fixture-surface/.env", &catalog.snapshot().unwrap(), &[]),
            Some(display_path.display().to_string()),
            "reloaded item events must keep the same project path as live events",
        );
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
                .join(floria_core::config::ITEMS_DIR)
                .join(&snapshot.surfaces[0].id)
                .join(".env")
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
                .join(floria_core::config::ITEMS_DIR)
                .join(FIXTURE_SECRET_ID)
                .join(".dev.vars")
        );
        let secret_id: SecretId = FIXTURE_SECRET_ID.parse().unwrap();
        assert_eq!(
            store.record(&secret_id).unwrap().unwrap().environment_ids,
            Some(vec![snapshot.environments[0].id.clone()])
        );
    }

    #[test]
    fn discovery_explicitly_attaches_a_matching_synced_project() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("Synced Project");
        let source_path = project_path.join(".env");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(&mount_path).unwrap();
        std::fs::write(&source_path, "SYNCED_TOKEN=fixture-value\n").unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog
            .apply_replicated_catalog(&ReplicatedCatalog {
                projects: vec![ReplicatedProject {
                    id: "synced-project".to_string(),
                    name: "synced-project".to_string(),
                    default_environment_id: None,
                }],
                ..ReplicatedCatalog::default()
            })
            .unwrap();
        let store = FixtureStore::new();
        let services = DispatchServices {
            store: Some(&store),
            mount_path: Some(&mount_path),
            ..DispatchServices::default()
        };

        let ControlResult::Discovery(review) = dispatch(
            &catalog,
            services,
            ControlCommand::Discover { paths: vec![project_path.clone()] },
        )
        .unwrap()
        else {
            panic!("expected discovery review")
        };
        assert_eq!(review.projects[0].managed_project_id, None);
        assert_eq!(review.projects[0].project_matches.len(), 1);
        assert_eq!(
            review.projects[0].project_matches[0].project_id,
            "synced-project"
        );

        let invalid = dispatch(
            &catalog,
            services,
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![DiscoveryImport {
                    path: source_path.clone(),
                    destination: DiscoveryImportDestination::ProjectFile {
                        project_path: project_path.clone(),
                        project_id: Some("stale-project".to_string()),
                    },
                    source_disposition: DiscoverySourceDisposition::ProtectInPlace,
                }]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap_err();
        assert!(invalid.body().message.contains("no longer a discovery match"));
        assert!(catalog.snapshot().unwrap().projects.is_empty());

        let ControlResult::DiscoveryApplied(applied) = dispatch(
            &catalog,
            services,
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![DiscoveryImport {
                    path: source_path.clone(),
                    destination: DiscoveryImportDestination::ProjectFile {
                        project_path: project_path.clone(),
                        project_id: Some("synced-project".to_string()),
                    },
                    source_disposition: DiscoverySourceDisposition::ProtectInPlace,
                }]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap()
        else {
            panic!("expected discovery apply result")
        };
        assert_eq!(applied.project_id.as_deref(), Some("synced-project"));
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.projects[0].id, "synced-project");
        assert_eq!(snapshot.projects[0].path, project_path);
        assert_eq!(catalog.replicated_catalog().unwrap().projects.len(), 1);
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
    fn discovery_protects_a_production_env_file_with_confirmation() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let source_path = project_path.join(".env.production");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(&mount_path).unwrap();
        std::fs::write(&source_path, "PRODUCTION_TOKEN=fixture-production\n").unwrap();
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

        let records = store.list().unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.enforcement, Enforcement::Prompt);
        assert!(std::fs::symlink_metadata(&source_path)
            .unwrap()
            .file_type()
            .is_symlink());
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.environments[0].name, "Production");
        assert_eq!(
            record.environment_ids,
            Some(vec![snapshot.environments[0].id.clone()])
        );
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
        secondary_surface.path = Some(project_path.join(".env.secondary"));
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
    fn discovery_imports_project_ssh_identity_and_protects_its_source_path() {
        use ssh_key::{Algorithm, LineEnding, PrivateKey};

        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let ssh_path = project_path.join("config/credentials/prod.key");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(ssh_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&mount_path).unwrap();
        let private_key =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        std::fs::write(&ssh_path, private_key.to_openssh(LineEnding::LF).unwrap()).unwrap();
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
                imports: Some(vec![project_file_import(&ssh_path, &project_path)]),
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
        assert_eq!(result.project_ids.len(), 1);
        assert_eq!(
            std::fs::read_link(&ssh_path).unwrap(),
            mount_path
                .join(floria_core::config::ITEMS_DIR)
                .join(FIXTURE_FILE_SECRET_ID)
                .join("prod.key")
        );
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.projects.len(), 1);
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.resources[0].kind, ResourceKind::SshIdentity);
        assert!(matches!(
            &snapshot.resources[0].source,
            ResourceSource::SecretRef { managed_source_ids, .. }
                if managed_source_ids == &[FIXTURE_FILE_SECRET_ID.to_string()]
        ));
        assert_eq!(
            snapshot.resources[0].origin.sources[0].project_id.as_deref(),
            Some(snapshot.projects[0].id.as_str())
        );
        let secret_id: SecretId = FIXTURE_FILE_SECRET_ID.parse().unwrap();
        assert_eq!(
            store.record(&secret_id).unwrap().unwrap().environment_ids,
            Some(vec![snapshot.environments[0].id.clone()])
        );
    }

    #[test]
    fn rediscovery_protects_a_source_previously_imported_only_as_an_ssh_identity() {
        use ssh_key::{Algorithm, LineEnding, PrivateKey};

        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("fixture-project");
        let ssh_path = project_path.join("config/credentials/prod.key");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(project_path.join(".git")).unwrap();
        std::fs::create_dir_all(ssh_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&mount_path).unwrap();
        let private_key =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        std::fs::write(&ssh_path, private_key.to_openssh(LineEnding::LF).unwrap()).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();
        let services = DispatchServices {
            store: Some(&store),
            mount_path: Some(&mount_path),
            ..DispatchServices::default()
        };

        dispatch(
            &catalog,
            services,
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
        assert!(std::fs::symlink_metadata(&ssh_path).unwrap().is_file());

        let applied = dispatch(
            &catalog,
            services,
            ControlCommand::DiscoverApply {
                paths: vec![project_path.clone()],
                imports: Some(vec![project_file_import(&ssh_path, &project_path)]),
                separate_entries: Vec::new(),
                promote_entries: Vec::new(),
                demote_entries: Vec::new(),
            },
        )
        .unwrap();

        let ControlResult::DiscoveryApplied(result) = applied else {
            panic!("expected discovery apply result");
        };
        assert_eq!(result.imported_ssh_identities, 0);
        assert_eq!(result.reused_resources, 1);
        assert_eq!(result.protected_files, 1);
        assert!(std::fs::symlink_metadata(&ssh_path)
            .unwrap()
            .file_type()
            .is_symlink());
        let snapshot = catalog.snapshot().unwrap();
        assert_eq!(snapshot.resources.len(), 1);
        assert_eq!(snapshot.projects.len(), 1);
        assert!(matches!(
            &snapshot.resources[0].source,
            ResourceSource::SecretRef { managed_source_ids, .. }
                if managed_source_ids == &[FIXTURE_FILE_SECRET_ID.to_string()]
        ));
        assert_eq!(
            snapshot.resources[0].origin.sources[0].project_id.as_deref(),
            Some(snapshot.projects[0].id.as_str())
        );
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
        let source_bytes = private_key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(&source_path, source_bytes.as_bytes()).unwrap();
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
                path: source_path.clone(),
                passphrase: None,
                manage_source: false,
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
            ResourceSource::SecretRef {
                secret_id: FIXTURE_SECRET_ID.to_string(),
                managed_source_ids: Vec::new(),
            }
        );
        let catalog_json = serde_json::to_string(&catalog.snapshot().unwrap()).unwrap();
        assert!(!catalog_json.contains("OPENSSH PRIVATE KEY"));
        let stored = store.get(&FIXTURE_SECRET_ID.parse().unwrap()).unwrap();
        let stored_identity = floria_ssh::identity_from_private_key(&stored).unwrap();
        assert_eq!(stored_identity.address, resource.entries[0].address);
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
        assert!(std::fs::symlink_metadata(&source_path).unwrap().is_file());

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
        assert_eq!(std::fs::read(&source_path).unwrap(), source_bytes.as_bytes());
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn managed_ssh_identity_can_manage_a_non_project_source_and_restore_it_on_removal() {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, LineEnding, PrivateKey};

        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("prod.key");
        let mount_path = dir.path().join("mount");
        std::fs::create_dir_all(&mount_path).unwrap();
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let source_bytes = private_key.to_openssh(LineEnding::LF).unwrap();
        std::fs::write(&source_path, source_bytes.as_bytes()).unwrap();
        std::fs::set_permissions(&source_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let store = FixtureStore::new();
        let services = DispatchServices {
            store: Some(&store),
            mount_path: Some(&mount_path),
            ..DispatchServices::default()
        };

        let created = dispatch(
            &catalog,
            services,
            ControlCommand::SshIdentityImport {
                resource_id: "fixture-global-identity".to_string(),
                name: "Fixture SSH Identity".to_string(),
                path: source_path.clone(),
                passphrase: None,
                manage_source: true,
                enforcement: Enforcement::Prompt,
                metadata: ItemMetadata::default(),
            },
        )
        .unwrap();
        let ControlResult::SshIdentityCreated { resource } = created else {
            panic!("expected managed SSH identity result");
        };
        assert_eq!(resource.origin.sources[0].project_id, None);
        assert!(matches!(
            &resource.source,
            ResourceSource::SecretRef { managed_source_ids, .. }
                if managed_source_ids == &[FIXTURE_FILE_SECRET_ID.to_string()]
        ));
        assert_eq!(
            std::fs::read_link(&source_path).unwrap(),
            mount_path
                .join(floria_core::config::ITEMS_DIR)
                .join(FIXTURE_FILE_SECRET_ID)
                .join("prod.key")
        );

        dispatch(
            &catalog,
            services,
            ControlCommand::ResourceMetadataUpdate {
                resource_id: resource.id.clone(),
                name: "Personal SSH".to_string(),
                enforcement: Enforcement::TouchId,
                metadata: ItemMetadata {
                    note: Some("Available without a project".to_string()),
                    links: Vec::new(),
                },
            },
        )
        .unwrap();
        let managed_source = store
            .record(&FIXTURE_FILE_SECRET_ID.parse().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(managed_source.enforcement, Enforcement::TouchId);
        assert_eq!(
            managed_source.metadata.note.as_deref(),
            Some("Available without a project")
        );

        assert_eq!(
            dispatch(
                &catalog,
                services,
                ControlCommand::SshIdentityRemove { resource_id: resource.id },
            )
            .unwrap(),
            ControlResult::Empty
        );
        assert_eq!(std::fs::read(&source_path).unwrap(), source_bytes.as_bytes());
        assert!(catalog.snapshot().unwrap().resources.is_empty());
        assert!(store.record(&FIXTURE_SECRET_ID.parse().unwrap()).unwrap().is_none());
        assert!(store.record(&FIXTURE_FILE_SECRET_ID.parse().unwrap()).unwrap().is_none());
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
                schema_version: 14,
                minimum_schema_version: 14,
                store_format_version: floria_store::STORE_FORMAT_VERSION,
                minimum_store_format_version: floria_store::MIN_SUPPORTED_STORE_FORMAT_VERSION,
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
    fn snapshot_exposes_synced_projects_until_this_mac_attaches_a_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        catalog
            .apply_replicated_catalog(&ReplicatedCatalog {
                projects: vec![ReplicatedProject {
                    id: "synced-project".to_string(),
                    name: "Synced Project".to_string(),
                    default_environment_id: Some("synced-development".to_string()),
                }],
                environments: vec![Environment {
                    id: "synced-development".to_string(),
                    project_id: "synced-project".to_string(),
                    name: "Development".to_string(),
                    position: 0,
                }],
                surfaces: vec![ReplicatedSurface {
                    id: "synced-dotenv".to_string(),
                    environment_id: "synced-development".to_string(),
                    name: ".env".to_string(),
                    kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                    relative_path: Some(PathBuf::from(".env")),
                    input: SurfaceInput::Bindings { binding_ids: vec![] },
                    enforcement: Enforcement::Allow,
                    position: 0,
                }],
                ..ReplicatedCatalog::default()
            })
            .unwrap();
        let socket = dir.path().join("control.sock");
        let _server = ControlServer::start(&socket, catalog, test_peer_verifier()).unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        let ControlResult::Snapshot(snapshot) =
            client.request(ControlCommand::Snapshot).unwrap()
        else {
            panic!("expected snapshot");
        };
        assert!(snapshot.projects.is_empty());
        assert_eq!(snapshot.unplaced_projects.len(), 1);
        assert_eq!(snapshot.unplaced_projects[0].id, "synced-project");

        let checkout = dir.path().join("synced-project");
        std::fs::create_dir(&checkout).unwrap();
        client
            .request(ControlCommand::ProjectAttach {
                project_id: "synced-project".to_string(),
                path: checkout.clone(),
            })
            .unwrap();
        let ControlResult::Snapshot(snapshot) =
            client.request(ControlCommand::Snapshot).unwrap()
        else {
            panic!("expected snapshot");
        };
        assert!(snapshot.unplaced_projects.is_empty());
        assert_eq!(
            snapshot.projects[0].path,
            std::fs::canonicalize(&checkout).unwrap()
        );
        assert_eq!(snapshot.projects[0].name, "Synced Project");
        assert_eq!(
            snapshot.projects[0].default_environment_id.as_deref(),
            Some("synced-development")
        );
        let expected_surface_path = std::fs::canonicalize(&checkout).unwrap().join(".env");
        assert_eq!(
            file_surface_instances(&snapshot).unwrap()[0].path.as_ref(),
            Some(&expected_surface_path)
        );

        let moved = dir.path().join("moved");
        std::fs::create_dir(&moved).unwrap();
        let error = client
            .request(ControlCommand::ProjectAttach {
                project_id: "synced-project".to_string(),
                path: moved,
            })
            .unwrap_err();
        assert!(error.to_string().contains("already has a folder"));
    }

    #[test]
    fn platform_adapter_crosses_the_real_control_frame_without_domain_authority() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let record_sync = Arc::new(FixtureRecordSyncService::default());
        let _server = ControlServer::start_inner(
            &socket,
            catalog,
            ControlDependencies {
                record_sync: Some(Arc::clone(&record_sync) as Arc<dyn RuntimeRecordSyncService>),
                ..ControlDependencies::default()
            },
            test_peer_verifier(),
        )
        .unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        assert!(matches!(
            client.request(ControlCommand::RecordSyncStatus).unwrap(),
            ControlResult::RecordSyncStatus(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncReviewConflicts)
                .unwrap(),
            ControlResult::RecordSyncConflicts(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncResolveConflict {
                    entity_id: "11111111-1111-4111-8111-111111111111".to_string(),
                    selected_revision_id: "22222222-2222-4222-8222-222222222222".to_string(),
                    resolved_at: "2026-08-09T12:00:00Z".to_string(),
                })
                .unwrap(),
            ControlResult::RecordSyncStatus(_)
        ));
        let ControlResult::RecordSyncVaultBootstrap(bootstrap) = client
            .request(ControlCommand::RecordSyncVaultBootstrap)
            .unwrap()
        else {
            panic!("expected Vault bootstrap");
        };
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncValidateVaultBootstrap {
                    expected_vault_id: bootstrap.vault_id().to_string(),
                    bootstrap: bootstrap.clone(),
                })
                .unwrap(),
            ControlResult::RecordSyncVaultBootstrap(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncPrepareVaultEnrollment {
                    bootstrap: bootstrap.clone(),
                    device_name: Some("Studio".to_string()),
                    requested_at: "2026-08-08T12:00:00Z".to_string(),
                })
                .unwrap(),
            ControlResult::RecordSyncEnrollmentPreparation(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncPrepareVaultReenrollment {
                    bootstrap: bootstrap.clone(),
                    expected_fingerprint: "AB12-CD34-EF56".to_string(),
                    device_name: Some("Studio".to_string()),
                    requested_at: "2026-08-09T12:00:00Z".to_string(),
                })
                .unwrap(),
            ControlResult::RecordSyncEnrollmentPreparation(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncReviewVaultEnrollments {
                    bootstrap: bootstrap.clone(),
                })
                .unwrap(),
            ControlResult::RecordSyncEnrollmentReviews(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncReviewVaultDevices {
                    bootstrap: bootstrap.clone(),
                })
                .unwrap(),
            ControlResult::RecordSyncVaultDevices(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncApproveVaultEnrollment {
                    bootstrap: bootstrap.clone(),
                    device_id: "fixture-device".to_string(),
                    expected_fingerprint: "sha256:fixture".to_string(),
                })
                .unwrap(),
            ControlResult::RecordSyncVaultBootstrap(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncRevokeVaultDevice {
                    bootstrap: bootstrap.clone(),
                    device_id: "fixture-device".to_string(),
                    expected_fingerprint: "sha256:fixture".to_string(),
                })
                .unwrap(),
            ControlResult::RecordSyncVaultBootstrap(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncActivateVault { bootstrap })
                .unwrap(),
            ControlResult::RecordSyncVaultActivation(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncNextOutbound { limit: 10 })
                .unwrap(),
            ControlResult::RecordSyncOutbound(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncSettleOutbound {
                    outcomes: vec![SyncDeliveryOutcome::new(
                        "commit-1",
                        crate::protocol::SyncDeliveryDisposition::Accepted,
                    )],
                })
                .unwrap(),
            ControlResult::RecordSyncSettlement(_)
        ));
        assert!(matches!(
            client
                .request(ControlCommand::RecordSyncApplyInbound {
                    batch: SyncInboundBatch::default(),
                    observed_at: "2026-08-07T12:00:00Z".to_string(),
                })
                .unwrap(),
            ControlResult::RecordSyncInbound(_)
        ));

        assert_eq!(record_sync.status_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            record_sync.conflict_review_calls.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            record_sync.conflict_resolution_calls.load(Ordering::Relaxed),
            1
        );
        assert_eq!(record_sync.bootstrap_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            record_sync
                .bootstrap_validation_calls
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(record_sync.outbound_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            record_sync
                .enrollment_preparation_calls
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            record_sync.enrollment_review_calls.load(Ordering::Relaxed),
            1
        );
        assert_eq!(record_sync.device_review_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            record_sync.enrollment_approval_calls.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            record_sync.device_revocation_calls.load(Ordering::Relaxed),
            1
        );
        assert_eq!(record_sync.activation_calls.load(Ordering::Relaxed), 1);
        assert_eq!(record_sync.settlement_calls.load(Ordering::Relaxed), 1);
        assert_eq!(record_sync.inbound_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn coordinated_record_sync_mutations_are_never_wrapped_in_the_gate_twice() {
        let service = FixtureRecordSyncService::default();
        let bootstrap = service.vault_bootstrap().unwrap();
        let commands = [
            ControlCommand::RecordSyncResolveConflict {
                entity_id: "11111111-1111-4111-8111-111111111111".to_string(),
                selected_revision_id: "22222222-2222-4222-8222-222222222222".to_string(),
                resolved_at: "2026-08-09T12:00:00Z".to_string(),
            },
            ControlCommand::RecordSyncPrepareVaultReenrollment {
                bootstrap: bootstrap.clone(),
                expected_fingerprint: "AB12-CD34-EF56".to_string(),
                device_name: Some("Studio".to_string()),
                requested_at: "2026-08-09T12:00:00Z".to_string(),
            },
            ControlCommand::RecordSyncApproveVaultEnrollment {
                bootstrap: bootstrap.clone(),
                device_id: "fixture-device".to_string(),
                expected_fingerprint: "sha256:fixture".to_string(),
            },
            ControlCommand::RecordSyncRevokeVaultDevice {
                bootstrap: bootstrap.clone(),
                device_id: "fixture-device".to_string(),
                expected_fingerprint: "sha256:fixture".to_string(),
            },
            ControlCommand::RecordSyncActivateVault {
                bootstrap: bootstrap.clone(),
            },
            ControlCommand::RecordSyncApplyInbound {
                batch: SyncInboundBatch::default(),
                observed_at: "2026-08-09T12:00:00Z".to_string(),
            },
        ];

        for command in &commands {
            assert!(is_self_coordinated(command));
            assert!(!is_read_only(command));
        }
        assert!(is_read_only(&ControlCommand::RecordSyncSettleOutbound {
            outcomes: Vec::new(),
        }));
    }

    #[test]
    fn inbound_projection_refreshes_runtime_but_transport_settlement_does_not() {
        let directory = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        let mutations = ManagedMutationCoordinator::new();
        let record_sync = FixtureRecordSyncService::default();
        let observer = SnapshotObserver {
            notifications: AtomicUsize::new(0),
            latest: Mutex::new(None),
        };
        let services = DispatchServices {
            mutations: Some(&mutations),
            record_sync: Some(&record_sync),
            ..DispatchServices::default()
        };

        dispatch_observed(
            &catalog,
            services,
            ControlCommand::RecordSyncApplyInbound {
                batch: SyncInboundBatch::default(),
                observed_at: "2026-08-09T12:00:00Z".to_string(),
            },
            Some(&observer),
        )
        .unwrap();
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);

        dispatch_observed(
            &catalog,
            services,
            ControlCommand::RecordSyncSettleOutbound {
                outcomes: Vec::new(),
            },
            Some(&observer),
        )
        .unwrap();
        assert_eq!(observer.notifications.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_sync_rejects_relative_asset_paths_before_the_runtime_reads_them() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let record_sync = FixtureRecordSyncService::default();
        let error = dispatch(
            &catalog,
            DispatchServices {
                record_sync: Some(&record_sync),
                ..DispatchServices::default()
            },
            ControlCommand::RecordSyncApplyInbound {
                batch: SyncInboundBatch::new(
                    Vec::new(),
                    Vec::new(),
                    vec![crate::protocol::SyncInboundObject::new(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        9,
                        PathBuf::from("relative-object.age"),
                    )],
                ),
                observed_at: "2026-08-07T12:00:00Z".to_string(),
            },
        )
        .unwrap_err();

        assert!(error.body().message.contains("must be absolute"));
        assert_eq!(record_sync.inbound_calls.load(Ordering::Relaxed), 0);
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
    fn read_only_peer_can_query_but_cannot_mutate_control_state() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(dir.path().join("catalog.sqlite")).unwrap();
        let socket = dir.path().join("control.sock");
        let _server =
            ControlServer::start(&socket, catalog.clone(), Arc::new(ReadOnlyPeers)).unwrap();
        let mut client = ControlClient::connect(&socket).unwrap();

        assert!(matches!(
            client.request(ControlCommand::Ping).unwrap(),
            ControlResult::Pong { .. }
        ));
        let error = client
            .request(ControlCommand::ProjectUpsert {
                project: Project {
                    id: "blocked-project".to_string(),
                    name: "Blocked".to_string(),
                    path: PathBuf::from("/blocked"),
                    ..Default::default()
                },
            })
            .unwrap_err();

        assert!(error.to_string().contains("permission_denied"));
        assert!(catalog.snapshot().unwrap().projects.is_empty());
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
                    path: Some(PathBuf::from("/fixture/project/.env")),
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
                    path: Some(PathBuf::from("/outside/.env")),
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
        assert!(is_read_only(&ControlCommand::RecordSyncStatus));
        assert!(is_read_only(&ControlCommand::RecordSyncVaultBootstrap));
        assert!(is_read_only(
            &ControlCommand::RecordSyncValidateVaultBootstrap {
                expected_vault_id: "fixture-vault".to_string(),
                bootstrap: FixtureRecordSyncService::default()
                    .vault_bootstrap()
                    .unwrap(),
            }
        ));
        let bootstrap = FixtureRecordSyncService::default()
            .vault_bootstrap()
            .unwrap();
        assert!(is_read_only(
            &ControlCommand::RecordSyncPrepareVaultEnrollment {
                bootstrap: bootstrap.clone(),
                device_name: None,
                requested_at: "2026-08-08T12:00:00Z".to_string(),
            }
        ));
        assert!(!is_read_only(
            &ControlCommand::RecordSyncPrepareVaultReenrollment {
                bootstrap: bootstrap.clone(),
                expected_fingerprint: "AB12-CD34-EF56".to_string(),
                device_name: None,
                requested_at: "2026-08-09T12:00:00Z".to_string(),
            }
        ));
        assert!(is_self_coordinated(
            &ControlCommand::RecordSyncPrepareVaultReenrollment {
                bootstrap: bootstrap.clone(),
                expected_fingerprint: "AB12-CD34-EF56".to_string(),
                device_name: None,
                requested_at: "2026-08-09T12:00:00Z".to_string(),
            }
        ));
        assert!(is_read_only(
            &ControlCommand::RecordSyncReviewVaultEnrollments {
                bootstrap: bootstrap.clone(),
            }
        ));
        assert!(is_read_only(
            &ControlCommand::RecordSyncReviewVaultDevices {
                bootstrap: bootstrap.clone(),
            }
        ));
        assert!(!is_read_only(
            &ControlCommand::RecordSyncApproveVaultEnrollment {
                bootstrap: bootstrap.clone(),
                device_id: "fixture-device".to_string(),
                expected_fingerprint: "sha256:fixture".to_string(),
            }
        ));
        assert!(!is_read_only(
            &ControlCommand::RecordSyncRevokeVaultDevice {
                bootstrap: bootstrap.clone(),
                device_id: "fixture-device".to_string(),
                expected_fingerprint: "sha256:fixture".to_string(),
            }
        ));
        assert!(!is_read_only(&ControlCommand::RecordSyncActivateVault {
            bootstrap,
        }));
        assert!(!command_allowed_for_peer(
            PeerAccess::ReadOnly,
            &ControlCommand::RecordSyncStatus,
        ));
        assert!(!command_allowed_for_peer(
            PeerAccess::ReadOnly,
            &ControlCommand::RecordSyncVaultBootstrap,
        ));
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
            ResourceSource::SecretRef {
                secret_id: FIXTURE_SECRET_ID.to_string(),
                managed_source_ids: Vec::new(),
            }
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
    fn concurrent_schema_attachment_and_version_append_cannot_leave_drift() {
        use floria_surface::{commit_secret_version, ManagedMutationCoordinator};

        let dir = tempfile::tempdir().unwrap();
        let catalog_path = dir.path().join("catalog.sqlite");
        let catalog = Catalog::open(&catalog_path).unwrap();
        let store = Arc::new(FixtureStore::new());
        let mutations = Arc::new(ManagedMutationCoordinator::new());
        let id = store
            .put(
                NewSecret::managed("DEBUG"),
                b"FIXTURE_A=before\n",
            )
            .unwrap();
        let (append_entered_tx, append_entered_rx) = mpsc::channel();
        let (release_append_tx, release_append_rx) = mpsc::channel();
        store.before_next_append(move || {
            append_entered_tx.send(()).unwrap();
            release_append_rx.recv().unwrap();
        });

        let commit_catalog = catalog.clone();
        let commit_store = Arc::clone(&store);
        let commit_mutations = Arc::clone(&mutations);
        let commit_id = id.clone();
        let commit = std::thread::spawn(move || {
            commit_secret_version(
                Some(&commit_catalog),
                commit_store.as_ref(),
                commit_mutations.as_ref(),
                &commit_id,
                b"FIXTURE_B=after\n",
            )
        });
        append_entered_rx.recv().unwrap();

        let schema_catalog = catalog.clone();
        let schema_store = Arc::clone(&store);
        let schema_mutations = Arc::clone(&mutations);
        let schema_secret_id = id.to_string();
        let (schema_started_tx, schema_started_rx) = mpsc::channel();
        let schema = std::thread::spawn(move || {
            schema_started_tx.send(()).unwrap();
            dispatch(
                &schema_catalog,
                DispatchServices {
                    store: Some(schema_store.as_ref()),
                    mutations: Some(schema_mutations.as_ref()),
                    ..DispatchServices::default()
                },
                ControlCommand::ResourceUpsert {
                    resource: Resource {
                        id: "fixture-env-resource".to_string(),
                        name: "Fixture Env File".to_string(),
                        kind: ResourceKind::EnvFile,
                        shape: ValueShape::KeyValueSet,
                        codec: ResourceCodec::Dotenv,
                        default_env_key: None,
                        entries: vec![EntrySpec {
                            address: "keys/FIXTURE_A".to_string(),
                            label: "FIXTURE_A".to_string(),
                            key: Some("FIXTURE_A".to_string()),
                            sensitive: true,
                        }],
                        source: ResourceSource::SecretRef {
                            secret_id: schema_secret_id,
                            managed_source_ids: Vec::new(),
                        },
                        enforcement: Enforcement::Allow,
                        metadata: Default::default(),
                        origin: Default::default(),
                    },
                    endpoint: None,
                },
            )
        });
        schema_started_rx.recv().unwrap();
        release_append_tx.send(()).unwrap();

        assert_eq!(commit.join().unwrap().unwrap(), 2);
        assert!(
            schema.join().unwrap().is_err(),
            "the later schema mutation must validate the committed head"
        );
        let snapshot = catalog.snapshot().unwrap();
        assert!(snapshot.resources.is_empty());
        assert!(
            validate_secret_bytes(&snapshot, id.as_str(), &store.get(&id).unwrap()).is_ok(),
            "catalog and store must remain mutually valid"
        );
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
            mount
                .join(floria_core::config::ITEMS_DIR)
                .join(FIXTURE_SECRET_ID)
                .join(".envrc")
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
            mount
                .join(floria_core::config::ITEMS_DIR)
                .join(FIXTURE_SECRET_ID)
                .join(".envrc")
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

        // Simulate a development-era file record created before portable Project placements.
        // A normal metadata edit must repair that declaration rather than leaving the file local
        // to the Mac whose absolute source path happens to be stored in its origin.
        store.update_placements(&secret_id, Vec::new()).unwrap();

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
        assert!(std::fs::symlink_metadata(worktree.join(".envrc")).is_err());
        assert!(matches!(
            store.record(&secret_id).unwrap().unwrap().placements.as_slice(),
            [floria_store::ManagedPlacement::Project {
                project_id,
                relative_path,
                environment_ids,
            }] if project_id == "fixture-project"
                && relative_path == Path::new(".envrc")
                && environment_ids == &["fixture-production".to_string()]
        ));

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
                        managed_source_ids: Vec::new(),
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
        assert_eq!(surface.path, Some(source.clone()));
        assert_eq!(
            surface.kind,
            SurfaceKind::File(floria_catalog::FileBacking::Composed(
                floria_catalog::SurfaceFormat::Dotenv
            ))
        );
        assert_eq!(
            std::fs::read_link(&source).unwrap(),
            mount
                .join(floria_core::config::ITEMS_DIR)
                .join(FIXTURE_SECRET_ID)
                .join(".dev.vars")
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
            ResourceSource::SecretRef {
                secret_id: FIXTURE_SECRET_ID.to_string(),
                managed_source_ids: Vec::new(),
            }
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
        let ResourceSource::SecretRef { secret_id, .. } = resource.source else {
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
