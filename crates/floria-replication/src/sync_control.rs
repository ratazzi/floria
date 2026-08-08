//! Account-independent control boundary between Rust records and a platform sync adapter.
//!
//! The adapter receives opaque encrypted envelopes plus verified ciphertext file paths. It never
//! decides record validity, graph state, projection eligibility, or retry durability.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use floria_catalog::Catalog;
use floria_store::AgeDirStore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::local_projection::LocalProjectionPlan;
use crate::projection_applicator::{ProjectionApplicator, ProjectionApplyOutcome};
use crate::record::{EntityRevision, ImmutableObjectRef, RevisionCommit, RECORD_FORMAT_VERSION};
use crate::record_crypto::RecordCryptor;
use crate::record_journal::{OutboundCommit, RecordJournal};
use crate::sync_bootstrap::{
    PreparedVaultMerge, SyncEnrollmentPreparation, SyncEnrollmentReview, SyncVaultActivation,
    SyncVaultBootstrap, SyncVaultDevice,
};
use crate::{ReplicationError, ReplicationResult};

const MAX_OUTBOUND_COMMITS: usize = 100;
const MAX_INBOUND_MANIFESTS: usize = 100;
const MAX_INBOUND_REVISIONS: usize = 1_000;
const MAX_INBOUND_OBJECTS: usize = 100;
const MAX_RECORD_DOCUMENT_BYTES: usize = 128 * 1024 * 1024;
const MAX_RECORD_CIPHERTEXT_BYTES: usize = 64 * 1024 * 1024;

/// Compact transport representation. The platform still treats these bytes as opaque.
#[derive(Serialize, Deserialize)]
struct RevisionEnvelope {
    format_version: u32,
    entity_id: String,
    revision_id: String,
    commit_id: String,
    key_generation: u32,
    parents: Vec<String>,
    ciphertext_base64: String,
    object_refs: Vec<ImmutableObjectRef>,
}

#[derive(Serialize, Deserialize)]
struct CommitEnvelope {
    format_version: u32,
    commit_id: String,
    key_generation: u32,
    revision_ids: Vec<String>,
    ciphertext_base64: String,
}

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

/// One opaque commit manifest downloaded by a platform adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncInboundManifest {
    commit_id: String,
    manifest_base64: String,
}

impl SyncInboundManifest {
    pub fn new(commit_id: impl Into<String>, manifest_base64: impl Into<String>) -> Self {
        Self {
            commit_id: commit_id.into(),
            manifest_base64: manifest_base64.into(),
        }
    }
}

/// One opaque entity revision downloaded by a platform adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncInboundRevision {
    entity_id: String,
    revision_id: String,
    envelope_base64: String,
}

impl SyncInboundRevision {
    pub fn new(
        entity_id: impl Into<String>,
        revision_id: impl Into<String>,
        envelope_base64: impl Into<String>,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            revision_id: revision_id.into(),
            envelope_base64: envelope_base64.into(),
        }
    }
}

/// One downloaded ciphertext file. Its path is machine-local and never enters a domain record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncInboundObject {
    digest: String,
    ciphertext_size: u64,
    file: PathBuf,
}

impl SyncInboundObject {
    pub fn new(digest: impl Into<String>, ciphertext_size: u64, file: PathBuf) -> Self {
        Self {
            digest: digest.into(),
            ciphertext_size,
            file,
        }
    }
}

/// An unordered, bounded adapter delivery. Every component is independently idempotent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncInboundBatch {
    manifests: Vec<SyncInboundManifest>,
    revisions: Vec<SyncInboundRevision>,
    objects: Vec<SyncInboundObject>,
}

impl SyncInboundBatch {
    pub fn new(
        manifests: Vec<SyncInboundManifest>,
        revisions: Vec<SyncInboundRevision>,
        objects: Vec<SyncInboundObject>,
    ) -> Self {
        Self {
            manifests,
            revisions,
            objects,
        }
    }

    pub fn manifests(&self) -> &[SyncInboundManifest] {
        &self.manifests
    }

    pub fn revisions(&self) -> &[SyncInboundRevision] {
        &self.revisions
    }

    pub fn objects(&self) -> &[SyncInboundObject] {
        &self.objects
    }
}

impl SyncInboundObject {
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncProjectionDisposition {
    #[default]
    Unchanged,
    Pending,
    Conflict,
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncInboundReport {
    manifests_received: usize,
    revisions_received: usize,
    objects_installed: usize,
    objects_already_present: usize,
    inbound_settled: usize,
    pending_transactions: usize,
    conflicting_entities: usize,
    projection: SyncProjectionDisposition,
}

impl SyncInboundReport {
    pub fn manifests_received(&self) -> usize {
        self.manifests_received
    }

    pub fn revisions_received(&self) -> usize {
        self.revisions_received
    }

    pub fn objects_installed(&self) -> usize {
        self.objects_installed
    }

    pub fn objects_already_present(&self) -> usize {
        self.objects_already_present
    }

    pub fn inbound_settled(&self) -> usize {
        self.inbound_settled
    }

    pub fn pending_transactions(&self) -> usize {
        self.pending_transactions
    }

    pub fn conflicting_entities(&self) -> usize {
        self.conflicting_entities
    }

    pub fn projection(&self) -> SyncProjectionDisposition {
        self.projection
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
    vault_id: String,
    key_generation: u32,
    outbound_transactions: usize,
    inbound_transactions: usize,
    pending_transactions: usize,
    conflicting_entities: usize,
    projection_pending: bool,
}

impl SyncDomainStatus {
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }

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
    store: std::sync::Arc<AgeDirStore>,
}

impl<'a> RecordSyncControl<'a> {
    pub fn new(journal: &'a RecordJournal, store: std::sync::Arc<AgeDirStore>) -> Self {
        Self { journal, store }
    }

    /// Export authenticated Vault identity, Device membership, key-generation documents, and
    /// opaque historical envelopes for a platform bootstrap adapter. This never activates an
    /// imported Vault or exposes private Device/generation keys.
    pub fn vault_bootstrap(&self) -> ReplicationResult<SyncVaultBootstrap> {
        SyncVaultBootstrap::capture(&self.store)
    }

    /// Authenticate one transport-provided bootstrap without installing it or changing the
    /// current Store. `expected_vault_id` must come from the user-selected transport route.
    pub fn validate_vault_bootstrap(
        &self,
        expected_vault_id: &str,
        bootstrap: SyncVaultBootstrap,
    ) -> ReplicationResult<SyncVaultBootstrap> {
        bootstrap.validate_for_vault(expected_vault_id)?;
        Ok(bootstrap)
    }

    /// Prepare this Store's local Device identity to join a user-selected Vault.
    /// This signs an opaque request but does not install or switch any Vault state.
    pub fn prepare_vault_enrollment(
        &self,
        bootstrap: SyncVaultBootstrap,
        device_name: Option<String>,
        requested_at: &str,
    ) -> ReplicationResult<SyncEnrollmentPreparation> {
        bootstrap.validate_for_vault(bootstrap.vault_id())?;
        bootstrap.prepare_enrollment(&self.store.device(), device_name, requested_at)
    }

    /// Project authenticated pending requests into the minimal information a GUI
    /// needs for out-of-band fingerprint comparison.
    pub fn review_vault_enrollments(
        &self,
        bootstrap: SyncVaultBootstrap,
    ) -> ReplicationResult<Vec<SyncEnrollmentReview>> {
        bootstrap.validate_for_vault(self.store.vault_document().vault_id.as_str())?;
        bootstrap.review_enrollments()
    }

    /// Project authenticated enrolled Devices for the management UI.
    pub fn review_vault_devices(
        &self,
        bootstrap: SyncVaultBootstrap,
    ) -> ReplicationResult<Vec<SyncVaultDevice>> {
        bootstrap.validate_for_vault(self.store.vault_document().vault_id.as_str())?;
        bootstrap.review_devices(self.store.device().device_id())
    }

    /// Approve exactly one reviewed request and return the updated authenticated
    /// bootstrap ready for atomic create-only publication.
    pub fn approve_vault_enrollment(
        &self,
        bootstrap: SyncVaultBootstrap,
        device_id: &str,
        expected_fingerprint: &str,
    ) -> ReplicationResult<SyncVaultBootstrap> {
        bootstrap.approve_enrollment(
            std::sync::Arc::clone(&self.store),
            device_id,
            expected_fingerprint,
        )
    }

    /// Remove exactly the Device identity whose fingerprint the user confirmed.
    pub fn revoke_vault_device(
        &self,
        bootstrap: SyncVaultBootstrap,
        device_id: &str,
        expected_fingerprint: &str,
    ) -> ReplicationResult<SyncVaultBootstrap> {
        bootstrap.revoke_device(
            std::sync::Arc::clone(&self.store),
            device_id,
            expected_fingerprint,
        )
    }

    /// Explicitly activate a downloaded, approved Vault. The caller supplies the complete count
    /// of local shared entities so a non-empty different Vault is routed to copy-and-verify.
    pub fn activate_vault_bootstrap(
        &self,
        bootstrap: SyncVaultBootstrap,
        local_items: usize,
    ) -> ReplicationResult<SyncVaultActivation> {
        bootstrap.activate(std::sync::Arc::clone(&self.store), local_items)
    }

    /// Build a disposable, fully verified Store in another Vault without changing live state.
    pub fn prepare_vault_merge(
        &self,
        bootstrap: SyncVaultBootstrap,
        target_root: PathBuf,
    ) -> ReplicationResult<PreparedVaultMerge> {
        bootstrap.prepare_merge(std::sync::Arc::clone(&self.store), target_root)
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

    /// Validate and durably accept one unordered platform delivery, then project only an exact
    /// complete and conflict-free record graph. A transport never writes Catalog or Store heads.
    pub fn apply_inbound(
        &self,
        catalog: &Catalog,
        batch: SyncInboundBatch,
        observed_at: impl Into<String>,
    ) -> ReplicationResult<SyncInboundReport> {
        validate_inbound_limits(&batch)?;
        let observed_at = observed_at.into();
        let cryptor = RecordCryptor::new(std::sync::Arc::clone(&self.store));
        let manifests = decode_manifests(batch.manifests, &cryptor)?;
        let revisions = decode_revisions(batch.revisions, &cryptor)?;
        let objects = canonical_inbound_objects(batch.objects)?;
        let mut report = SyncInboundReport {
            manifests_received: manifests.len(),
            revisions_received: revisions.len(),
            objects_installed: 0,
            objects_already_present: 0,
            inbound_settled: 0,
            pending_transactions: 0,
            conflicting_entities: 0,
            projection: SyncProjectionDisposition::Unchanged,
        };

        for object in objects.into_values() {
            if self.store.install_replicated_object(
                &object.digest,
                object.ciphertext_size,
                &object.file,
            )? {
                report.objects_installed += 1;
            } else {
                report.objects_already_present += 1;
            }
        }
        if !manifests.is_empty() || !revisions.is_empty() {
            self.journal
                .receive_inbound(manifests, revisions, observed_at.clone())?;
        }

        let applicator = ProjectionApplicator::new(self.journal, catalog, &self.store);
        if let Some(outcome) = applicator.recover_pending(observed_at.clone())? {
            report.projection = projection_disposition(outcome);
        }

        let records = match self.journal.projection_records() {
            Ok(records) => records,
            Err(ReplicationError::ProjectionConflict { entity_ids }) => {
                report.conflicting_entities = entity_ids.len();
                report.projection = SyncProjectionDisposition::Conflict;
                report.pending_transactions = self.pending_transaction_count()?;
                return Ok(report);
            }
            Err(error) => return Err(error),
        };
        if records.commits().is_empty() {
            if report.manifests_received != 0 || report.revisions_received != 0 {
                report.projection = SyncProjectionDisposition::Pending;
            }
            report.pending_transactions = self.pending_transaction_count()?;
            return Ok(report);
        }

        let plan = LocalProjectionPlan::build(&cryptor, &records)?;
        report.projection = projection_disposition(applicator.apply(
            &plan,
            observed_at.clone(),
            observed_at,
        )?);
        let ready = self
            .journal
            .ready_inbound()?
            .into_iter()
            .map(|item| item.commit().commit_id().to_string())
            .collect::<BTreeSet<_>>();
        report.inbound_settled = self.journal.settle_inbound_batch(&ready)?;
        report.pending_transactions = self.pending_transaction_count()?;
        Ok(report)
    }

    pub fn status(&self) -> ReplicationResult<SyncDomainStatus> {
        let vault_id = self.store.vault_document().vault_id;
        let key_generation = self.store.current_generation()?;
        let outbound_transactions = self.journal.outbound()?.len();
        let inbound = self.journal.inbound()?;
        let pending_transactions = self.journal.pending_transactions()?;
        let conflicting_entities = match self.journal.projection_records() {
            Ok(_) => 0,
            Err(ReplicationError::ProjectionConflict { entity_ids }) => entity_ids.len(),
            Err(error) => return Err(error),
        };
        Ok(SyncDomainStatus {
            vault_id,
            key_generation,
            outbound_transactions,
            inbound_transactions: inbound.len(),
            pending_transactions,
            conflicting_entities,
            projection_pending: self.journal.pending_projection()?.is_some(),
        })
    }

    fn pending_transaction_count(&self) -> ReplicationResult<usize> {
        self.journal.pending_transactions()
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
                envelope_base64: encode_revision(revision)?,
            });
        }
        Ok(SyncOutboundCommit {
            commit_id: item.commit().commit_id().to_string(),
            manifest_base64: encode_commit(item.commit())?,
            revisions,
            created_at: item.created_at().to_string(),
        })
    }
}

fn projection_disposition(outcome: ProjectionApplyOutcome) -> SyncProjectionDisposition {
    match outcome {
        ProjectionApplyOutcome::Applied => SyncProjectionDisposition::Applied,
        ProjectionApplyOutcome::AlreadyApplied => SyncProjectionDisposition::AlreadyApplied,
    }
}

fn validate_inbound_limits(batch: &SyncInboundBatch) -> ReplicationResult<()> {
    if batch.manifests.len() > MAX_INBOUND_MANIFESTS {
        return Err(ReplicationError::Invalid(format!(
            "inbound batch contains {} manifests, maximum is {MAX_INBOUND_MANIFESTS}",
            batch.manifests.len()
        )));
    }
    if batch.revisions.len() > MAX_INBOUND_REVISIONS {
        return Err(ReplicationError::Invalid(format!(
            "inbound batch contains {} revisions, maximum is {MAX_INBOUND_REVISIONS}",
            batch.revisions.len()
        )));
    }
    if batch.objects.len() > MAX_INBOUND_OBJECTS {
        return Err(ReplicationError::Invalid(format!(
            "inbound batch contains {} objects, maximum is {MAX_INBOUND_OBJECTS}",
            batch.objects.len()
        )));
    }
    Ok(())
}

fn canonical_inbound_objects(
    objects: Vec<SyncInboundObject>,
) -> ReplicationResult<BTreeMap<String, SyncInboundObject>> {
    let mut by_digest = BTreeMap::<String, SyncInboundObject>::new();
    for object in objects {
        match by_digest.get(&object.digest) {
            Some(existing)
                if existing.ciphertext_size == object.ciphertext_size
                    && existing.file == object.file => {}
            Some(_) => {
                return Err(ReplicationError::Invalid(format!(
                    "inbound object {} appears with conflicting delivery metadata",
                    object.digest
                )))
            }
            None => {
                by_digest.insert(object.digest.clone(), object);
            }
        }
    }
    Ok(by_digest)
}

fn decode_manifests(
    manifests: Vec<SyncInboundManifest>,
    cryptor: &RecordCryptor,
) -> ReplicationResult<Vec<RevisionCommit>> {
    let mut by_id = BTreeMap::new();
    for inbound in manifests {
        let commit = decode_commit(&inbound.manifest_base64)?;
        if commit.commit_id() != inbound.commit_id {
            return Err(ReplicationError::Invalid(format!(
                "inbound manifest route {} does not match encrypted commit {}",
                inbound.commit_id,
                commit.commit_id()
            )));
        }
        cryptor.verify_commit(&commit)?;
        match by_id.get(commit.commit_id()) {
            Some(existing) if existing == &commit => {}
            Some(_) => {
                return Err(ReplicationError::Invalid(format!(
                    "inbound commit id {} was reused for different content",
                    commit.commit_id()
                )))
            }
            None => {
                by_id.insert(commit.commit_id().to_string(), commit);
            }
        }
    }
    Ok(by_id.into_values().collect())
}

fn decode_revisions(
    revisions: Vec<SyncInboundRevision>,
    cryptor: &RecordCryptor,
) -> ReplicationResult<Vec<EntityRevision>> {
    let mut by_id = BTreeMap::new();
    for inbound in revisions {
        let revision = decode_revision(&inbound.envelope_base64)?;
        if revision.entity_id() != inbound.entity_id
            || revision.revision_id() != inbound.revision_id
        {
            return Err(ReplicationError::Invalid(format!(
                "inbound revision route {}/{} does not match encrypted revision {}/{}",
                inbound.entity_id,
                inbound.revision_id,
                revision.entity_id(),
                revision.revision_id()
            )));
        }
        cryptor.open_entity_revision(&revision)?;
        match by_id.get(revision.revision_id()) {
            Some(existing) if existing == &revision => {}
            Some(_) => {
                return Err(ReplicationError::Invalid(format!(
                    "inbound revision id {} was reused for different content",
                    revision.revision_id()
                )))
            }
            None => {
                by_id.insert(revision.revision_id().to_string(), revision);
            }
        }
    }
    Ok(by_id.into_values().collect())
}

fn encode_revision(revision: &EntityRevision) -> ReplicationResult<String> {
    encode_document(&RevisionEnvelope {
        format_version: revision.format_version(),
        entity_id: revision.entity_id().to_string(),
        revision_id: revision.revision_id().to_string(),
        commit_id: revision.commit_id().to_string(),
        key_generation: revision.key_generation(),
        parents: revision.parents().to_vec(),
        ciphertext_base64: BASE64.encode(revision.ciphertext()),
        object_refs: revision.object_refs().to_vec(),
    })
}

fn decode_revision(encoded: &str) -> ReplicationResult<EntityRevision> {
    let envelope: RevisionEnvelope = decode_document(encoded, "revision envelope")?;
    require_record_format(envelope.format_version)?;
    EntityRevision::new(
        envelope.entity_id,
        envelope.revision_id,
        envelope.commit_id,
        envelope.key_generation,
        envelope.parents,
        decode_base64(
            &envelope.ciphertext_base64,
            "revision ciphertext",
            MAX_RECORD_CIPHERTEXT_BYTES,
        )?,
        envelope.object_refs,
    )
    .map_err(|error| ReplicationError::Invalid(error.to_string()))
}

fn encode_commit(commit: &RevisionCommit) -> ReplicationResult<String> {
    encode_document(&CommitEnvelope {
        format_version: commit.format_version(),
        commit_id: commit.commit_id().to_string(),
        key_generation: commit.key_generation(),
        revision_ids: commit.revision_ids().to_vec(),
        ciphertext_base64: BASE64.encode(commit.ciphertext()),
    })
}

fn decode_commit(encoded: &str) -> ReplicationResult<RevisionCommit> {
    let envelope: CommitEnvelope = decode_document(encoded, "commit manifest")?;
    require_record_format(envelope.format_version)?;
    RevisionCommit::new(
        envelope.commit_id,
        envelope.key_generation,
        envelope.revision_ids,
        decode_base64(
            &envelope.ciphertext_base64,
            "commit ciphertext",
            MAX_RECORD_CIPHERTEXT_BYTES,
        )?,
    )
    .map_err(|error| ReplicationError::Invalid(error.to_string()))
}

fn require_record_format(format_version: u32) -> ReplicationResult<()> {
    if format_version != RECORD_FORMAT_VERSION {
        return Err(ReplicationError::Invalid(format!(
            "unsupported sync record format {format_version}"
        )));
    }
    Ok(())
}

fn encode_document<T: Serialize>(document: &T) -> ReplicationResult<String> {
    Ok(BASE64.encode(serde_json::to_vec(document)?))
}

fn decode_document<T: DeserializeOwned>(encoded: &str, label: &str) -> ReplicationResult<T> {
    let bytes = decode_base64(encoded, label, MAX_RECORD_DOCUMENT_BYTES)?;
    serde_json::from_slice(&bytes).map_err(ReplicationError::from)
}

fn decode_base64(encoded: &str, label: &str, maximum: usize) -> ReplicationResult<Vec<u8>> {
    let maximum_encoded = maximum.saturating_add(2) / 3 * 4;
    if encoded.len() > maximum_encoded {
        return Err(ReplicationError::Invalid(format!(
            "{label} exceeds the {maximum} byte format limit"
        )));
    }
    let decoded = BASE64
        .decode(encoded)
        .map_err(|error| ReplicationError::Invalid(format!("invalid {label} base64: {error}")))?;
    if decoded.len() > maximum {
        return Err(ReplicationError::Invalid(format!(
            "{label} exceeds the {maximum} byte format limit"
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use age::x25519;
    use floria_catalog::Catalog;
    use floria_integrity::StateAuthenticator;
    use floria_store::{KeyProvider, NewSecret, SecretStore, StoreResult};

    use super::*;
    use crate::entity_document::{EntityLifecycle, ReplicatedEntityDocument};
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
        secret_id: floria_store::SecretId,
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
                secret_id,
            }
        }

        fn control(&self) -> RecordSyncControl<'_> {
            RecordSyncControl::new(&self.journal, Arc::clone(&self.store))
        }
    }

    #[test]
    fn outbound_batch_contains_opaque_records_and_verified_asset_paths() {
        let fixture = Fixture::new();
        let status = fixture.control().status().unwrap();
        assert_eq!(status.vault_id(), fixture.store.vault_document().vault_id);
        assert_eq!(status.key_generation(), fixture.store.current_generation().unwrap());
        let bootstrap = fixture.control().vault_bootstrap().unwrap();
        assert_eq!(bootstrap.vault_id(), status.vault_id());
        let batch = fixture.control().next_outbound(10).unwrap();

        assert_eq!(batch.commits().len(), 1);
        assert_eq!(batch.objects().len(), 1);
        let commit = &batch.commits()[0];
        assert_eq!(commit.commit_id(), fixture.transaction.commit().commit_id());
        assert_eq!(commit.revisions().len(), 1);
        let manifest = decode_commit(commit.manifest_base64()).unwrap();
        assert_eq!(&manifest, fixture.transaction.commit());
        let revision = decode_revision(commit.revisions()[0].envelope_base64()).unwrap();
        assert_eq!(&revision, &fixture.transaction.revisions()[0]);
        assert!(batch.objects()[0].file().is_file());
        assert_eq!(
            batch.objects()[0].file(),
            &fixture
                .store
                .shared_layout()
                .object(batch.objects()[0].digest())
        );
        assert!(!String::from_utf8_lossy(
            &BASE64
                .decode(commit.revisions()[0].envelope_base64())
                .unwrap()
        )
        .contains("private fixture payload"));
        assert!(fixture.control().next_outbound(0).is_err());
    }

    #[test]
    fn downloaded_bootstrap_is_authenticated_without_changing_the_store() {
        let fixture = Fixture::new();
        let original_vault = fixture.store.vault_document();
        let original_generation = fixture.store.current_generation().unwrap();
        let bootstrap = fixture.control().vault_bootstrap().unwrap();

        let validated = fixture
            .control()
            .validate_vault_bootstrap(&original_vault.vault_id, bootstrap.clone())
            .unwrap();
        assert_eq!(validated, bootstrap);
        assert_eq!(fixture.store.vault_document().vault_id, original_vault.vault_id);
        assert_eq!(fixture.store.current_generation().unwrap(), original_generation);

        assert!(fixture
            .control()
            .validate_vault_bootstrap(&uuid::Uuid::new_v4().to_string(), bootstrap)
            .is_err());
        assert_eq!(fixture.store.vault_document().vault_id, original_vault.vault_id);
        assert_eq!(fixture.store.current_generation().unwrap(), original_generation);
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

    #[test]
    fn inbound_partial_arrival_installs_object_then_projects_complete_commit() {
        let fixture = Fixture::new();
        let outbound = fixture.control().next_outbound(1).unwrap();
        let commit = &outbound.commits()[0];
        let object = &outbound.objects()[0];
        let download = fixture._directory.path().join("download.age");
        std::fs::copy(object.file(), &download).unwrap();
        std::fs::remove_file(object.file()).unwrap();

        let inbound_journal = RecordJournal::open(
            fixture._directory.path().join("inbound.sqlite"),
            &fixture.store.vault_document().vault_id,
            Arc::new(StateAuthenticator::for_tests([72; 32])),
        )
        .unwrap();
        let catalog = Catalog::open(fixture._directory.path().join("catalog.sqlite")).unwrap();
        let control = RecordSyncControl::new(&inbound_journal, Arc::clone(&fixture.store));
        let revision = &commit.revisions()[0];
        let first = SyncInboundBatch::new(
            Vec::new(),
            vec![SyncInboundRevision::new(
                revision.entity_id(),
                revision.revision_id(),
                revision.envelope_base64(),
            )],
            vec![SyncInboundObject::new(
                object.digest(),
                object.ciphertext_size(),
                download.clone(),
            )],
        );
        let report = control
            .apply_inbound(&catalog, first, "2026-08-07T00:00:01Z")
            .unwrap();
        assert_eq!(report.objects_installed(), 1);
        assert_eq!(report.projection(), SyncProjectionDisposition::Pending);
        assert_eq!(report.pending_transactions(), 1);
        assert!(object.file().is_file());

        let second = SyncInboundBatch::new(
            vec![SyncInboundManifest::new(
                commit.commit_id(),
                commit.manifest_base64(),
            )],
            Vec::new(),
            Vec::new(),
        );
        let report = control
            .apply_inbound(&catalog, second, "2026-08-07T00:00:02Z")
            .unwrap();
        assert_eq!(report.projection(), SyncProjectionDisposition::Applied);
        assert_eq!(report.inbound_settled(), 1);
        assert_eq!(report.pending_transactions(), 0);
        assert!(inbound_journal.inbound().unwrap().is_empty());
        assert!(inbound_journal.projection_checkpoint().unwrap().is_some());
    }

    #[test]
    fn inbound_rejects_routing_substitution_before_installing_objects() {
        let fixture = Fixture::new();
        let outbound = fixture.control().next_outbound(1).unwrap();
        let commit = &outbound.commits()[0];
        let revision = &commit.revisions()[0];
        let object = &outbound.objects()[0];
        let download = fixture._directory.path().join("untrusted.age");
        std::fs::copy(object.file(), &download).unwrap();
        std::fs::remove_file(object.file()).unwrap();
        let inbound_journal = RecordJournal::open(
            fixture._directory.path().join("rejected.sqlite"),
            &fixture.store.vault_document().vault_id,
            Arc::new(StateAuthenticator::for_tests([73; 32])),
        )
        .unwrap();
        let catalog = Catalog::open(fixture._directory.path().join("rejected-catalog.sqlite"))
            .unwrap();
        let control = RecordSyncControl::new(&inbound_journal, Arc::clone(&fixture.store));
        let batch = SyncInboundBatch::new(
            Vec::new(),
            vec![SyncInboundRevision::new(
                uuid::Uuid::new_v4().to_string(),
                revision.revision_id(),
                revision.envelope_base64(),
            )],
            vec![SyncInboundObject::new(
                object.digest(),
                object.ciphertext_size(),
                download,
            )],
        );

        assert!(control
            .apply_inbound(&catalog, batch, "2026-08-07T00:00:01Z")
            .unwrap_err()
            .to_string()
            .contains("does not match"));
        assert!(!object.file().exists());
        assert!(inbound_journal.analysis().unwrap().heads().is_empty());
    }

    #[test]
    fn inbound_concurrent_heads_report_conflict_without_projecting_a_winner() {
        let fixture = Fixture::new();
        let document = SecretEntityDocument::from_store(
            &fixture.store,
            &fixture.secret_id,
            EntityLifecycle::Active,
        )
        .unwrap();
        let cryptor = RecordCryptor::new(Arc::clone(&fixture.store));
        let concurrent = SealedRecordTransaction::seal(
            &cryptor,
            [EntityChange::new(
                ReplicatedEntityDocument::Secret(document),
                None,
                Vec::new(),
            )
            .unwrap()],
        )
        .unwrap();
        let inbound_journal = RecordJournal::open(
            fixture._directory.path().join("conflict.sqlite"),
            &fixture.store.vault_document().vault_id,
            Arc::new(StateAuthenticator::for_tests([74; 32])),
        )
        .unwrap();
        let catalog =
            Catalog::open(fixture._directory.path().join("conflict-catalog.sqlite")).unwrap();
        let control = RecordSyncControl::new(&inbound_journal, Arc::clone(&fixture.store));
        let transactions = [&fixture.transaction, &concurrent];
        let batch = SyncInboundBatch::new(
            transactions
                .iter()
                .map(|transaction| {
                    SyncInboundManifest::new(
                        transaction.commit().commit_id(),
                        encode_commit(transaction.commit()).unwrap(),
                    )
                })
                .collect(),
            transactions
                .iter()
                .flat_map(|transaction| transaction.revisions())
                .map(|revision| {
                    SyncInboundRevision::new(
                        revision.entity_id(),
                        revision.revision_id(),
                        encode_revision(revision).unwrap(),
                    )
                })
                .collect(),
            Vec::new(),
        );

        let report = control
            .apply_inbound(&catalog, batch, "2026-08-07T00:00:01Z")
            .unwrap();
        assert_eq!(report.projection(), SyncProjectionDisposition::Conflict);
        assert_eq!(report.conflicting_entities(), 1);
        assert_eq!(report.inbound_settled(), 0);
        assert_eq!(inbound_journal.inbound().unwrap().len(), 2);
        assert!(inbound_journal.projection_checkpoint().unwrap().is_none());
        assert_eq!(control.status().unwrap().conflicting_entities(), 1);
    }
}
