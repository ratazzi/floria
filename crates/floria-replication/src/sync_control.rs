//! Account-independent control boundary between Rust records and a platform sync adapter.
//!
//! The adapter receives opaque encrypted envelopes plus verified ciphertext file paths. It never
//! decides record validity, graph state, projection eligibility, or retry durability.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use floria_store::AgeDirStore;
use serde::{Deserialize, Serialize};

use crate::record_journal::{OutboundCommit, RecordJournal};
use crate::{ReplicationError, ReplicationResult};

const MAX_OUTBOUND_COMMITS: usize = 100;

/// One immutable ciphertext object that a platform adapter may upload as an asset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncObjectAsset {
    digest: String,
    ciphertext_size: u64,
    file: PathBuf,
}

impl SyncObjectAsset {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn ciphertext_size(&self) -> u64 {
        self.ciphertext_size
    }

    pub fn file(&self) -> &Path {
        &self.file
    }
}

/// One opaque encrypted revision and the CAS head expected by its local transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOutboundRevision {
    entity_id: String,
    revision_id: String,
    expected_head_revision_id: Option<String>,
    envelope_base64: String,
}

impl SyncOutboundRevision {
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    pub fn expected_head_revision_id(&self) -> Option<&str> {
        self.expected_head_revision_id.as_deref()
    }

    pub fn envelope_base64(&self) -> &str {
        &self.envelope_base64
    }
}

/// One atomic record transaction ready for a platform-specific CAS publication attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOutboundCommit {
    commit_id: String,
    manifest_base64: String,
    revisions: Vec<SyncOutboundRevision>,
    created_at: String,
}

impl SyncOutboundCommit {
    pub fn commit_id(&self) -> &str {
        &self.commit_id
    }

    pub fn manifest_base64(&self) -> &str {
        &self.manifest_base64
    }

    pub fn revisions(&self) -> &[SyncOutboundRevision] {
        &self.revisions
    }

    pub fn created_at(&self) -> &str {
        &self.created_at
    }
}

/// A bounded delivery batch. Objects are deduplicated across every included transaction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOutboundBatch {
    commits: Vec<SyncOutboundCommit>,
    objects: Vec<SyncObjectAsset>,
}

impl SyncOutboundBatch {
    pub fn commits(&self) -> &[SyncOutboundCommit] {
        &self.commits
    }

    pub fn objects(&self) -> &[SyncObjectAsset] {
        &self.objects
    }
}

/// Result of one platform adapter publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncDeliveryDisposition {
    Accepted,
    Retry,
    Conflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDeliveryOutcome {
    commit_id: String,
    disposition: SyncDeliveryDisposition,
}

impl SyncDeliveryOutcome {
    pub fn new(commit_id: impl Into<String>, disposition: SyncDeliveryDisposition) -> Self {
        Self {
            commit_id: commit_id.into(),
            disposition,
        }
    }

    pub fn commit_id(&self) -> &str {
        &self.commit_id
    }

    pub fn disposition(&self) -> SyncDeliveryDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncSettlementReport {
    accepted: usize,
    conflicts: usize,
    retrying: usize,
    settled: usize,
}

impl SyncSettlementReport {
    pub fn accepted(&self) -> usize {
        self.accepted
    }

    pub fn conflicts(&self) -> usize {
        self.conflicts
    }

    pub fn retrying(&self) -> usize {
        self.retrying
    }

    pub fn settled(&self) -> usize {
        self.settled
    }
}

/// Transport-neutral health visible to either a GUI or a future non-Apple adapter.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDomainStatus {
    outbound_transactions: usize,
    inbound_transactions: usize,
    pending_transactions: usize,
    conflicting_entities: usize,
    projection_pending: bool,
}

impl SyncDomainStatus {
    pub fn outbound_transactions(&self) -> usize {
        self.outbound_transactions
    }

    pub fn inbound_transactions(&self) -> usize {
        self.inbound_transactions
    }

    pub fn pending_transactions(&self) -> usize {
        self.pending_transactions
    }

    pub fn conflicting_entities(&self) -> usize {
        self.conflicting_entities
    }

    pub fn projection_pending(&self) -> bool {
        self.projection_pending
    }
}

/// Deep synchronization seam: the platform owns transport, while Rust owns durable record state.
pub struct RecordSyncControl<'a> {
    journal: &'a RecordJournal,
    store: &'a AgeDirStore,
}

impl<'a> RecordSyncControl<'a> {
    pub fn new(journal: &'a RecordJournal, store: &'a AgeDirStore) -> Self {
        Self { journal, store }
    }

    /// Return oldest durable publications without changing retry state.
    pub fn next_outbound(&self, limit: usize) -> ReplicationResult<SyncOutboundBatch> {
        if limit == 0 || limit > MAX_OUTBOUND_COMMITS {
            return Err(ReplicationError::Invalid(format!(
                "outbound batch limit must be between 1 and {MAX_OUTBOUND_COMMITS}"
            )));
        }

        let outbound = self.journal.outbound()?;
        let mut commits = Vec::new();
        let mut objects = BTreeMap::<String, SyncObjectAsset>::new();
        for item in outbound.into_iter().take(limit) {
            commits.push(self.encode_outbound_commit(&item, &mut objects)?);
        }
        Ok(SyncOutboundBatch {
            commits,
            objects: objects.into_values().collect(),
        })
    }

    /// Retire accepted or CAS-conflicted attempts atomically; retryable attempts remain durable.
    pub fn settle_outbound(
        &self,
        outcomes: &[SyncDeliveryOutcome],
    ) -> ReplicationResult<SyncSettlementReport> {
        let current = self
            .journal
            .outbound()?
            .into_iter()
            .map(|item| item.commit().commit_id().to_string())
            .collect::<BTreeSet<_>>();
        let mut observed = BTreeSet::new();
        let mut finished = BTreeSet::new();
        let mut report = SyncSettlementReport::default();
        for outcome in outcomes {
            if !observed.insert(outcome.commit_id.clone()) {
                return Err(ReplicationError::Invalid(format!(
                    "sync settlement names commit {} more than once",
                    outcome.commit_id
                )));
            }
            match outcome.disposition {
                SyncDeliveryDisposition::Accepted => {
                    report.accepted += 1;
                    finished.insert(outcome.commit_id.clone());
                }
                SyncDeliveryDisposition::Conflict => {
                    report.conflicts += 1;
                    finished.insert(outcome.commit_id.clone());
                }
                SyncDeliveryDisposition::Retry => {
                    if !current.contains(&outcome.commit_id) {
                        return Err(ReplicationError::Invalid(format!(
                            "cannot retry commit {} because it is not pending",
                            outcome.commit_id
                        )));
                    }
                    report.retrying += 1;
                }
            }
        }
        report.settled = self.journal.settle_outbound_batch(&finished)?;
        Ok(report)
    }

    pub fn status(&self) -> ReplicationResult<SyncDomainStatus> {
        let outbound_transactions = self.journal.outbound()?.len();
        let inbound = self.journal.inbound()?;
        let pending_transactions = inbound
            .iter()
            .filter(|item| !item.readiness().is_ready())
            .count();
        let analysis = self.journal.analysis()?;
        let conflicting_entities = analysis
            .heads()
            .values()
            .filter(|heads| heads.len() > 1)
            .count();
        Ok(SyncDomainStatus {
            outbound_transactions,
            inbound_transactions: inbound.len(),
            pending_transactions,
            conflicting_entities,
            projection_pending: self.journal.pending_projection()?.is_some(),
        })
    }

    fn encode_outbound_commit(
        &self,
        item: &OutboundCommit,
        objects: &mut BTreeMap<String, SyncObjectAsset>,
    ) -> ReplicationResult<SyncOutboundCommit> {
        let mut revisions = Vec::with_capacity(item.revisions().len());
        for revision in item.revisions() {
            let expected_head_revision_id = item
                .expected_heads()
                .get(revision.entity_id())
                .ok_or_else(|| {
                    ReplicationError::Invalid(format!(
                        "outbound commit {} has no expected head for entity {}",
                        item.commit().commit_id(),
                        revision.entity_id()
                    ))
                })?
                .clone();
            for object in revision.object_refs() {
                let asset = SyncObjectAsset {
                    digest: object.digest().to_string(),
                    ciphertext_size: object.ciphertext_size(),
                    file: self.store.shared_layout().object(object.digest()),
                };
                match objects.get(&asset.digest) {
                    Some(existing) if existing.ciphertext_size != asset.ciphertext_size => {
                        return Err(ReplicationError::Invalid(format!(
                            "object {} is referenced with conflicting ciphertext sizes",
                            asset.digest
                        )))
                    }
                    Some(_) => {}
                    None => {
                        self.store
                            .verify_replicated_object(&asset.digest, asset.ciphertext_size)?;
                        objects.insert(asset.digest.clone(), asset);
                    }
                }
            }
            revisions.push(SyncOutboundRevision {
                entity_id: revision.entity_id().to_string(),
                revision_id: revision.revision_id().to_string(),
                expected_head_revision_id,
                envelope_base64: encode_record(revision)?,
            });
        }
        Ok(SyncOutboundCommit {
            commit_id: item.commit().commit_id().to_string(),
            manifest_base64: encode_record(item.commit())?,
            revisions,
            created_at: item.created_at().to_string(),
        })
    }
}

fn encode_record<T: Serialize>(record: &T) -> ReplicationResult<String> {
    Ok(BASE64.encode(serde_json::to_vec(record)?))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use age::x25519;
    use floria_integrity::StateAuthenticator;
    use floria_store::{KeyProvider, NewSecret, SecretStore, StoreResult};

    use super::*;
    use crate::entity_document::{EntityLifecycle, ReplicatedEntityDocument};
    use crate::record::{EntityRevision, RevisionCommit};
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

    struct Fixture {
        _directory: tempfile::TempDir,
        store: Arc<AgeDirStore>,
        journal: RecordJournal,
        transaction: SealedRecordTransaction,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let store = Arc::new(
                AgeDirStore::open(
                    directory.path().join("store"),
                    Arc::new(LocalKeys(x25519::Identity::generate())),
                )
                .unwrap(),
            );
            let secret_id = store
                .put(NewSecret::managed("Fixture"), b"private fixture payload")
                .unwrap();
            let document = SecretEntityDocument::from_store(
                &store,
                &secret_id,
                EntityLifecycle::Active,
            )
            .unwrap();
            let cryptor = RecordCryptor::new(Arc::clone(&store));
            let transaction = SealedRecordTransaction::seal(
                &cryptor,
                [EntityChange::new(
                    ReplicatedEntityDocument::Secret(document),
                    None,
                    Vec::new(),
                )
                .unwrap()],
            )
            .unwrap();
            let journal = RecordJournal::open(
                directory.path().join("records.sqlite"),
                &store.vault_document().vault_id,
                Arc::new(StateAuthenticator::for_tests([71; 32])),
            )
            .unwrap();
            transaction
                .queue(&journal, "2026-08-07T00:00:00Z")
                .unwrap();
            Self {
                _directory: directory,
                store,
                journal,
                transaction,
            }
        }

        fn control(&self) -> RecordSyncControl<'_> {
            RecordSyncControl::new(&self.journal, &self.store)
        }
    }

    #[test]
    fn outbound_batch_contains_opaque_records_and_verified_asset_paths() {
        let fixture = Fixture::new();
        let batch = fixture.control().next_outbound(10).unwrap();

        assert_eq!(batch.commits().len(), 1);
        assert_eq!(batch.objects().len(), 1);
        let commit = &batch.commits()[0];
        assert_eq!(commit.commit_id(), fixture.transaction.commit().commit_id());
        assert_eq!(commit.revisions().len(), 1);
        let manifest: RevisionCommit =
            serde_json::from_slice(&BASE64.decode(commit.manifest_base64()).unwrap()).unwrap();
        assert_eq!(&manifest, fixture.transaction.commit());
        let revision: EntityRevision = serde_json::from_slice(
            &BASE64
                .decode(commit.revisions()[0].envelope_base64())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(&revision, &fixture.transaction.revisions()[0]);
        assert!(batch.objects()[0].file().is_file());
        assert_eq!(
            batch.objects()[0].file(),
            &fixture
                .store
                .shared_layout()
                .object(batch.objects()[0].digest())
        );
        assert!(!String::from_utf8_lossy(&BASE64.decode(commit.revisions()[0].envelope_base64()).unwrap())
            .contains("private fixture payload"));
        assert!(fixture.control().next_outbound(0).is_err());
    }

    #[test]
    fn settlement_keeps_retries_and_retires_conflicts_idempotently() {
        let fixture = Fixture::new();
        let commit_id = fixture.transaction.commit().commit_id().to_string();

        let report = fixture
            .control()
            .settle_outbound(&[SyncDeliveryOutcome::new(
                &commit_id,
                SyncDeliveryDisposition::Retry,
            )])
            .unwrap();
        assert_eq!(report.retrying(), 1);
        assert_eq!(report.settled(), 0);
        assert_eq!(fixture.journal.outbound().unwrap().len(), 1);

        let report = fixture
            .control()
            .settle_outbound(&[SyncDeliveryOutcome::new(
                &commit_id,
                SyncDeliveryDisposition::Conflict,
            )])
            .unwrap();
        assert_eq!(report.conflicts(), 1);
        assert_eq!(report.settled(), 1);
        assert!(fixture.journal.outbound().unwrap().is_empty());

        let repeated = fixture
            .control()
            .settle_outbound(&[SyncDeliveryOutcome::new(
                &commit_id,
                SyncDeliveryDisposition::Accepted,
            )])
            .unwrap();
        assert_eq!(repeated.accepted(), 1);
        assert_eq!(repeated.settled(), 0);
        assert!(fixture
            .control()
            .settle_outbound(&[SyncDeliveryOutcome::new(
                uuid::Uuid::new_v4().to_string(),
                SyncDeliveryDisposition::Retry,
            )])
            .is_err());
    }

    #[test]
    fn outbound_refuses_a_tampered_ciphertext_asset() {
        let fixture = Fixture::new();
        let batch = fixture.control().next_outbound(1).unwrap();
        let asset = &batch.objects()[0];
        std::fs::write(asset.file(), vec![0_u8; asset.ciphertext_size() as usize]).unwrap();

        assert!(fixture
            .control()
            .next_outbound(1)
            .unwrap_err()
            .to_string()
            .contains("digest"));
    }

    #[test]
    fn status_reports_transport_neutral_domain_state() {
        let fixture = Fixture::new();
        let status = fixture.control().status().unwrap();

        assert_eq!(status.outbound_transactions(), 1);
        assert_eq!(status.inbound_transactions(), 0);
        assert_eq!(status.pending_transactions(), 0);
        assert_eq!(status.conflicting_entities(), 0);
        assert!(!status.projection_pending());
    }
}
