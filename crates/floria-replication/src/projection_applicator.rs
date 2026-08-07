//! Crash-recoverable application of one authenticated desired state to machine-local backends.
//!
//! Catalog and Store intentionally remain separate deep modules and cannot share a physical
//! transaction. This applicator makes their composition recoverable by replaying one exact durable
//! [`crate::record_journal::PendingProjection`] until every idempotent step has completed.

use std::fs;

use floria_catalog::Catalog;
use floria_store::{AgeDirStore, NewSecret, SecretId, SecretOrigin};

use crate::entity_document::EntityLifecycle;
use crate::local_projection::LocalProjectionPlan;
use crate::record_journal::{ProjectionPreparation, RecordJournal};
use crate::{ReplicationError, ReplicationResult};

const PROJECTION_MUTATION_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x0d72f0b4_e973_4e3b_8bc8_613d5e1a4b37);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionApplyOutcome {
    Applied,
    AlreadyApplied,
}

/// The sole coordinator allowed to cross the record journal, Store, and Catalog seams.
pub struct ProjectionApplicator<'a> {
    journal: &'a RecordJournal,
    catalog: &'a Catalog,
    store: &'a AgeDirStore,
}

impl<'a> ProjectionApplicator<'a> {
    pub fn new(
        journal: &'a RecordJournal,
        catalog: &'a Catalog,
        store: &'a AgeDirStore,
    ) -> Self {
        Self {
            journal,
            catalog,
            store,
        }
    }

    /// Fence and apply one plan. Retrying the same plan after success is a no-op.
    pub fn apply(
        &self,
        plan: &LocalProjectionPlan,
        prepared_at: impl Into<String>,
        applied_at: impl Into<String>,
    ) -> ReplicationResult<ProjectionApplyOutcome> {
        let document = plan.encode()?;
        let plan_id = plan.plan_id()?;
        match self.journal.prepare_projection(
            &plan_id,
            &document,
            plan.head_revisions(),
            prepared_at,
        )? {
            ProjectionPreparation::AlreadyApplied => {
                Ok(ProjectionApplyOutcome::AlreadyApplied)
            }
            ProjectionPreparation::Prepared | ProjectionPreparation::AlreadyPrepared => self
                .recover_pending(applied_at)?
                .ok_or_else(|| {
                    ReplicationError::Invalid(
                        "prepared projection disappeared before application".to_string(),
                    )
                }),
        }
    }

    /// Resume the exact pending bytes; never recompile from newer remote records during recovery.
    pub fn recover_pending(
        &self,
        applied_at: impl Into<String>,
    ) -> ReplicationResult<Option<ProjectionApplyOutcome>> {
        let Some(pending) = self.journal.pending_projection()? else {
            return Ok(None);
        };
        let plan = LocalProjectionPlan::decode(pending.document())?;
        if plan.plan_id()? != pending.plan_id()
            || plan.head_revisions() != pending.head_revisions()
        {
            return Err(ReplicationError::Invalid(
                "pending projection identity does not match its decoded plan".to_string(),
            ));
        }

        self.preflight_objects(&plan)?;
        self.apply_store_heads(&plan, pending.plan_id())?;
        self.catalog.apply_replicated_catalog(plan.active_catalog())?;
        self.apply_archives(&plan)?;
        let completed = self.journal.complete_projection(
            pending.plan_id(),
            pending.head_revisions(),
            applied_at,
        )?;
        Ok(Some(if completed {
            ProjectionApplyOutcome::Applied
        } else {
            ProjectionApplyOutcome::AlreadyApplied
        }))
    }

    /// Reject a partial asset arrival before any machine-local state changes.
    fn preflight_objects(&self, plan: &LocalProjectionPlan) -> ReplicationResult<()> {
        let layout = self.store.shared_layout();
        for object in plan.object_refs() {
            let path = layout.object(object.digest());
            let metadata = fs::symlink_metadata(&path).map_err(|source| ReplicationError::Io {
                path: path.clone(),
                source,
            })?;
            if !metadata.file_type().is_file() {
                return Err(ReplicationError::Invalid(format!(
                    "projection object {} is not a regular file",
                    path.display()
                )));
            }
            if metadata.len() != object.ciphertext_size() {
                return Err(ReplicationError::Invalid(format!(
                    "projection object {} has {} bytes, expected {}",
                    object.digest(),
                    metadata.len(),
                    object.ciphertext_size()
                )));
            }
        }
        Ok(())
    }

    fn apply_store_heads(
        &self,
        plan: &LocalProjectionPlan,
        plan_id: &str,
    ) -> ReplicationResult<()> {
        for secret in plan.secrets().values() {
            if secret.lifecycle() != EntityLifecycle::Active {
                continue;
            }
            let secret_id: SecretId = secret.entity_id().parse()?;
            let descriptor = secret.descriptor();
            let version = secret.head();
            let mutation_id = projection_mutation_id(plan_id, secret.entity_id());
            self.store.register_replicated_version(
                &secret_id,
                Some(NewSecret {
                    origin: SecretOrigin::Managed {
                        label: descriptor.label().to_string(),
                    },
                    mode: descriptor.mode(),
                    enforcement: descriptor.enforcement(),
                }),
                version.version_id(),
                version.key_generation(),
                version.plaintext_size(),
                version.object().digest(),
                &mutation_id,
            )?;
            self.store
                .set_head_to_uuid(&secret_id, version.version_id())?;
            self.store.apply_replicated_settings(
                &secret_id,
                descriptor.label(),
                descriptor.mode(),
                descriptor.metadata().clone(),
                descriptor.enforcement(),
                descriptor.environment_ids().map(|ids| ids.to_vec()),
            )?;
        }
        Ok(())
    }

    fn apply_archives(&self, plan: &LocalProjectionPlan) -> ReplicationResult<()> {
        for secret in plan.secrets().values() {
            if secret.lifecycle() == EntityLifecycle::Archived {
                self.store
                    .remove_replicated_heads(&secret.entity_id().parse()?)?;
            }
        }
        Ok(())
    }
}

fn projection_mutation_id(plan_id: &str, secret_id: &str) -> String {
    uuid::Uuid::new_v5(
        &PROJECTION_MUTATION_NAMESPACE,
        format!("{plan_id}/{secret_id}").as_bytes(),
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use age::x25519;
    use floria_integrity::StateAuthenticator;
    use floria_store::{KeyProvider, SecretStore, StoreResult};

    use super::*;
    use crate::entity_document::ReplicatedEntityDocument;
    use crate::record_crypto::RecordCryptor;
    use crate::record_transaction::{EntityChange, SealedRecordTransaction};
    use crate::secret_state::SecretEntityDocument;

    struct LocalKeys(x25519::Identity);

    impl KeyProvider for LocalKeys {
        fn recipients(&self) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
            Ok(vec![Box::new(self.0.to_public())])
        }

        fn identity(&self) -> StoreResult<Box<dyn age::Identity>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    #[test]
    fn pending_projection_rebuilds_store_state_and_completes_once() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            AgeDirStore::open(
                directory.path().join("store"),
                Arc::new(LocalKeys(x25519::Identity::generate())),
            )
            .unwrap(),
        );
        let secret_id = store
            .put(
                NewSecret {
                    origin: SecretOrigin::Managed {
                        label: "Portable fixture".to_string(),
                    },
                    mode: 0o440,
                    enforcement: floria_core::authz::Enforcement::TouchId,
                },
                b"private projection fixture",
            )
            .unwrap();
        let cryptor = RecordCryptor::new(Arc::clone(&store));
        let journal = RecordJournal::open(
            directory.path().join("records.sqlite"),
            &store.vault_document().vault_id,
            Arc::new(StateAuthenticator::for_tests([31; 32])),
        )
        .unwrap();
        let secret = SecretEntityDocument::from_store(
            &store,
            &secret_id,
            EntityLifecycle::Active,
        )
        .unwrap();
        let change = EntityChange::new(
            ReplicatedEntityDocument::Secret(secret),
            None,
            Vec::new(),
        )
        .unwrap();
        SealedRecordTransaction::seal(&cryptor, vec![change])
            .unwrap()
            .queue(&journal, "2026-08-07T00:00:00Z")
            .unwrap();
        let plan =
            LocalProjectionPlan::build(&cryptor, &journal.projection_records().unwrap()).unwrap();
        let document = plan.encode().unwrap();
        let plan_id = plan.plan_id().unwrap();
        journal
            .prepare_projection(
                &plan_id,
                &document,
                plan.head_revisions(),
                "2026-08-07T00:00:01Z",
            )
            .unwrap();

        store.remove_replicated_heads(&secret_id).unwrap();
        let catalog = Catalog::open(directory.path().join("catalog.sqlite")).unwrap();
        {
            let interrupted = ProjectionApplicator::new(&journal, &catalog, &store);
            interrupted.preflight_objects(&plan).unwrap();
            interrupted.apply_store_heads(&plan, &plan_id).unwrap();
        }
        assert!(journal.pending_projection().unwrap().is_some());
        assert!(journal.projection_checkpoint().unwrap().is_none());

        let applicator = ProjectionApplicator::new(&journal, &catalog, &store);
        assert_eq!(
            applicator
                .recover_pending("2026-08-07T00:00:02Z")
                .unwrap(),
            Some(ProjectionApplyOutcome::Applied)
        );

        assert_eq!(
            store.get(&secret_id).unwrap().as_slice(),
            b"private projection fixture"
        );
        let record = store.record(&secret_id).unwrap().unwrap();
        assert_eq!(record.display_name(), "Portable fixture");
        assert_eq!(record.mode, 0o440);
        assert_eq!(
            record.enforcement,
            floria_core::authz::Enforcement::TouchId
        );
        assert!(journal.pending_projection().unwrap().is_none());
        assert_eq!(
            applicator
                .apply(
                    &plan,
                    "2026-08-07T00:00:03Z",
                    "2026-08-07T00:00:04Z",
                )
                .unwrap(),
            ProjectionApplyOutcome::AlreadyApplied
        );

        let previous_head = plan.head_revisions()[secret_id.as_str()].clone();
        let archived = SecretEntityDocument::from_store(
            &store,
            &secret_id,
            EntityLifecycle::Active,
        )
        .unwrap()
        .archived();
        let archive_change = EntityChange::new(
            ReplicatedEntityDocument::Secret(archived),
            Some(previous_head.clone()),
            vec![previous_head],
        )
        .unwrap();
        SealedRecordTransaction::seal(&cryptor, vec![archive_change])
            .unwrap()
            .queue(&journal, "2026-08-07T00:00:05Z")
            .unwrap();
        let archive_plan =
            LocalProjectionPlan::build(&cryptor, &journal.projection_records().unwrap()).unwrap();
        let object_path = store
            .shared_layout()
            .object(archive_plan.object_refs()[0].digest());

        assert_eq!(
            applicator
                .apply(
                    &archive_plan,
                    "2026-08-07T00:00:06Z",
                    "2026-08-07T00:00:07Z",
                )
                .unwrap(),
            ProjectionApplyOutcome::Applied
        );
        assert!(matches!(
            store.get(&secret_id),
            Err(floria_store::StoreError::NotFound(_))
        ));
        assert!(object_path.is_file());
    }
}
