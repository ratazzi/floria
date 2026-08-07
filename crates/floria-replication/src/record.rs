//! Transport-neutral encrypted entity revisions.
//!
//! This module is the shared record vocabulary for the coordinated CloudKit transport and a
//! possible future directory transport. It deliberately knows nothing about `CKRecord`, device
//! operation sequences, SQLite, or materialization. The current format-5 runtime does not use it
//! yet; migration happens only after the record model and adapters have independent validation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const RECORD_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("unsupported record format {0}")]
    UnsupportedFormat(u32),
    #[error("{field} must be a UUID: {value}")]
    InvalidUuid { field: &'static str, value: String },
    #[error("entity revision ciphertext cannot be empty")]
    EmptyCiphertext,
    #[error("entity revision key generation must start at 1")]
    InvalidKeyGeneration,
    #[error("revision {revision_id} cannot name itself as a parent")]
    SelfParent { revision_id: String },
    #[error("revision {revision_id} names parent {parent_id} more than once")]
    DuplicateParent {
        revision_id: String,
        parent_id: String,
    },
    #[error("object digest must be 64 lowercase hexadecimal characters: {0}")]
    InvalidObjectDigest(String),
    #[error("revision {revision_id} names object {digest} more than once")]
    DuplicateObject { revision_id: String, digest: String },
    #[error("revision id {revision_id} was reused for different content")]
    RevisionCollision { revision_id: String },
    #[error(
        "revision {revision_id} and parent {parent_id} belong to different entities ({entity_id} and {parent_entity_id})"
    )]
    ParentEntityMismatch {
        revision_id: String,
        entity_id: String,
        parent_id: String,
        parent_entity_id: String,
    },
    #[error("revision graph contains a cycle at {revision_id}")]
    Cycle { revision_id: String },
    #[error("revision commit must contain at least one revision")]
    EmptyCommit,
    #[error("commit {commit_id} names revision {revision_id} more than once")]
    DuplicateCommitRevision {
        commit_id: String,
        revision_id: String,
    },
    #[error("commit {commit_id} contains more than one revision for entity {entity_id}")]
    CommitDuplicateEntity {
        commit_id: String,
        entity_id: String,
    },
}

pub type RecordResult<T> = Result<T, RecordError>;

/// A reference to exact immutable Age ciphertext bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImmutableObjectRef {
    digest: String,
    ciphertext_size: u64,
}

impl ImmutableObjectRef {
    pub fn new(digest: impl Into<String>, ciphertext_size: u64) -> RecordResult<Self> {
        let reference = Self {
            digest: digest.into(),
            ciphertext_size,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn ciphertext_size(&self) -> u64 {
        self.ciphertext_size
    }

    fn validate(&self) -> RecordResult<()> {
        let valid = self.digest.len() == 64
            && self
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if valid {
            Ok(())
        } else {
            Err(RecordError::InvalidObjectDigest(self.digest.clone()))
        }
    }
}

/// One immutable, complete encrypted state of a logical entity.
///
/// `parents` is a causal set: zero parents creates an entity, one is a normal update, and multiple
/// parents explicitly resolve concurrent tips. Adapters must publish the revision create-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRevision {
    format_version: u32,
    entity_id: String,
    revision_id: String,
    key_generation: u32,
    parents: Vec<String>,
    ciphertext: Vec<u8>,
    object_refs: Vec<ImmutableObjectRef>,
}

impl EntityRevision {
    pub fn new(
        entity_id: impl Into<String>,
        revision_id: impl Into<String>,
        key_generation: u32,
        parents: Vec<String>,
        ciphertext: Vec<u8>,
        object_refs: Vec<ImmutableObjectRef>,
    ) -> RecordResult<Self> {
        let mut revision = Self {
            format_version: RECORD_FORMAT_VERSION,
            entity_id: entity_id.into(),
            revision_id: revision_id.into(),
            key_generation,
            parents,
            ciphertext,
            object_refs,
        };
        revision.canonicalize();
        revision.validate()?;
        Ok(revision)
    }

    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }

    pub fn parents(&self) -> &[String] {
        &self.parents
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn object_refs(&self) -> &[ImmutableObjectRef] {
        &self.object_refs
    }

    fn canonicalize(&mut self) {
        self.parents.sort();
        self.object_refs.sort_by(|left, right| {
            left.digest
                .cmp(&right.digest)
                .then(left.ciphertext_size.cmp(&right.ciphertext_size))
        });
    }

    fn validate(&self) -> RecordResult<()> {
        if self.format_version != RECORD_FORMAT_VERSION {
            return Err(RecordError::UnsupportedFormat(self.format_version));
        }
        validate_uuid("entity_id", &self.entity_id)?;
        validate_uuid("revision_id", &self.revision_id)?;
        if self.key_generation == 0 {
            return Err(RecordError::InvalidKeyGeneration);
        }
        if self.ciphertext.is_empty() {
            return Err(RecordError::EmptyCiphertext);
        }

        let mut parents = BTreeSet::new();
        for parent in &self.parents {
            validate_uuid("parent revision_id", parent)?;
            if parent == &self.revision_id {
                return Err(RecordError::SelfParent {
                    revision_id: self.revision_id.clone(),
                });
            }
            if !parents.insert(parent) {
                return Err(RecordError::DuplicateParent {
                    revision_id: self.revision_id.clone(),
                    parent_id: parent.clone(),
                });
            }
        }

        let mut objects = BTreeSet::new();
        for object in &self.object_refs {
            object.validate()?;
            if !objects.insert(object.digest()) {
                return Err(RecordError::DuplicateObject {
                    revision_id: self.revision_id.clone(),
                    digest: object.digest.clone(),
                });
            }
        }
        Ok(())
    }
}

/// An immutable barrier for all entity revisions produced by one local transaction.
///
/// Transport may deliver the manifest, its member revisions, and their ancestors in any order.
/// Projection must wait until [`RevisionSet::commit_readiness`] reports [`CommitReadiness::Ready`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionCommit {
    format_version: u32,
    commit_id: String,
    revision_ids: Vec<String>,
}

impl RevisionCommit {
    pub fn new(
        commit_id: impl Into<String>,
        revision_ids: Vec<String>,
    ) -> RecordResult<Self> {
        let mut commit = Self {
            format_version: RECORD_FORMAT_VERSION,
            commit_id: commit_id.into(),
            revision_ids,
        };
        commit.canonicalize();
        commit.validate()?;
        Ok(commit)
    }

    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    pub fn commit_id(&self) -> &str {
        &self.commit_id
    }

    pub fn revision_ids(&self) -> &[String] {
        &self.revision_ids
    }

    pub(crate) fn canonicalize(&mut self) {
        self.revision_ids.sort();
    }

    pub(crate) fn validate(&self) -> RecordResult<()> {
        if self.format_version != RECORD_FORMAT_VERSION {
            return Err(RecordError::UnsupportedFormat(self.format_version));
        }
        validate_uuid("commit_id", &self.commit_id)?;
        if self.revision_ids.is_empty() {
            return Err(RecordError::EmptyCommit);
        }
        let mut revisions = BTreeSet::new();
        for revision_id in &self.revision_ids {
            validate_uuid("commit revision_id", revision_id)?;
            if !revisions.insert(revision_id) {
                return Err(RecordError::DuplicateCommitRevision {
                    commit_id: self.commit_id.clone(),
                    revision_id: revision_id.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Whether a transaction barrier has all data needed for atomic projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitReadiness {
    Ready,
    Pending { missing_revisions: Vec<String> },
}

impl CommitReadiness {
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    pub fn missing_revisions(&self) -> &[String] {
        match self {
            Self::Ready => &[],
            Self::Pending { missing_revisions } => missing_revisions,
        }
    }
}

/// Idempotent result of adding an immutable revision to a [`RevisionSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertResult {
    Inserted,
    AlreadyPresent,
}

/// A revision whose complete ancestry has not arrived yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRevision {
    entity_id: String,
    revision_id: String,
    missing_parents: Vec<String>,
}

impl PendingRevision {
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    pub fn missing_parents(&self) -> &[String] {
        &self.missing_parents
    }
}

/// Order-independent projection of the revision graph.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevisionAnalysis {
    heads: BTreeMap<String, Vec<String>>,
    pending: Vec<PendingRevision>,
}

impl RevisionAnalysis {
    pub fn heads(&self) -> &BTreeMap<String, Vec<String>> {
        &self.heads
    }

    pub fn heads_for(&self, entity_id: &str) -> &[String] {
        self.heads.get(entity_id).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn pending(&self) -> &[PendingRevision] {
        &self.pending
    }

    pub fn has_conflict(&self, entity_id: &str) -> bool {
        self.heads_for(entity_id).len() > 1
    }
}

/// A validated set of immutable revisions.
///
/// Insertion accepts duplicates with identical canonical content and rejects a revision-id
/// collision. [`RevisionSet::analyze`] is intentionally independent of arrival order.
#[derive(Clone, Debug, Default)]
pub struct RevisionSet {
    revisions: BTreeMap<String, EntityRevision>,
}

impl RevisionSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.revisions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revisions.is_empty()
    }

    pub fn insert(&mut self, mut revision: EntityRevision) -> RecordResult<InsertResult> {
        revision.canonicalize();
        revision.validate()?;
        match self.revisions.get(revision.revision_id()) {
            Some(existing) if existing == &revision => Ok(InsertResult::AlreadyPresent),
            Some(_) => Err(RecordError::RevisionCollision {
                revision_id: revision.revision_id.clone(),
            }),
            None => {
                self.revisions
                    .insert(revision.revision_id.clone(), revision);
                Ok(InsertResult::Inserted)
            }
        }
    }

    pub fn get(&self, revision_id: &str) -> Option<&EntityRevision> {
        self.revisions.get(revision_id)
    }

    pub fn analyze(&self) -> RecordResult<RevisionAnalysis> {
        let mut visits = BTreeMap::new();
        for revision_id in self.revisions.keys() {
            visit_revision(revision_id, &self.revisions, &mut visits)?;
        }

        let complete = visits
            .iter()
            .filter_map(|(revision_id, visit)| match visit {
                Visit::Complete => Some(revision_id.clone()),
                Visit::Pending(_) | Visit::Visiting => None,
            })
            .collect::<BTreeSet<_>>();

        let mut heads = BTreeMap::<String, BTreeSet<String>>::new();
        for revision_id in &complete {
            let revision = &self.revisions[revision_id];
            heads
                .entry(revision.entity_id.clone())
                .or_default()
                .insert(revision_id.clone());
        }
        for revision_id in &complete {
            let revision = &self.revisions[revision_id];
            for parent in &revision.parents {
                if complete.contains(parent) {
                    heads
                        .entry(revision.entity_id.clone())
                        .or_default()
                        .remove(parent);
                }
            }
        }

        let heads = heads
            .into_iter()
            .map(|(entity_id, revision_ids)| (entity_id, revision_ids.into_iter().collect()))
            .collect();
        let pending = visits
            .into_iter()
            .filter_map(|(revision_id, visit)| {
                let Visit::Pending(missing_parents) = visit else {
                    return None;
                };
                let revision = &self.revisions[&revision_id];
                Some(PendingRevision {
                    entity_id: revision.entity_id.clone(),
                    revision_id,
                    missing_parents: missing_parents.into_iter().collect(),
                })
            })
            .collect();

        Ok(RevisionAnalysis { heads, pending })
    }

    pub fn commit_readiness(&self, commit: &RevisionCommit) -> RecordResult<CommitReadiness> {
        commit.validate()?;
        let mut visits = BTreeMap::new();
        let mut missing = BTreeSet::new();
        let mut entities = BTreeSet::new();

        for revision_id in commit.revision_ids() {
            let Some(revision) = self.revisions.get(revision_id) else {
                missing.insert(revision_id.clone());
                continue;
            };
            if !entities.insert(revision.entity_id()) {
                return Err(RecordError::CommitDuplicateEntity {
                    commit_id: commit.commit_id.clone(),
                    entity_id: revision.entity_id.clone(),
                });
            }
            if let Visit::Pending(ancestors) =
                visit_revision(revision_id, &self.revisions, &mut visits)?
            {
                missing.extend(ancestors);
            }
        }

        if missing.is_empty() {
            Ok(CommitReadiness::Ready)
        } else {
            Ok(CommitReadiness::Pending {
                missing_revisions: missing.into_iter().collect(),
            })
        }
    }
}

#[derive(Clone, Debug)]
enum Visit {
    Visiting,
    Complete,
    Pending(BTreeSet<String>),
}

fn visit_revision(
    revision_id: &str,
    revisions: &BTreeMap<String, EntityRevision>,
    visits: &mut BTreeMap<String, Visit>,
) -> RecordResult<Visit> {
    if let Some(visit) = visits.get(revision_id) {
        return match visit {
            Visit::Visiting => Err(RecordError::Cycle {
                revision_id: revision_id.to_string(),
            }),
            Visit::Complete | Visit::Pending(_) => Ok(visit.clone()),
        };
    }

    visits.insert(revision_id.to_string(), Visit::Visiting);
    let revision = &revisions[revision_id];
    let mut missing = BTreeSet::new();
    for parent_id in &revision.parents {
        let Some(parent) = revisions.get(parent_id) else {
            missing.insert(parent_id.clone());
            continue;
        };
        if parent.entity_id != revision.entity_id {
            return Err(RecordError::ParentEntityMismatch {
                revision_id: revision.revision_id.clone(),
                entity_id: revision.entity_id.clone(),
                parent_id: parent.revision_id.clone(),
                parent_entity_id: parent.entity_id.clone(),
            });
        }
        match visit_revision(parent_id, revisions, visits)? {
            Visit::Complete => {}
            Visit::Pending(parent_missing) => missing.extend(parent_missing),
            Visit::Visiting => unreachable!("visiting revisions return a cycle error"),
        }
    }

    let visit = if missing.is_empty() {
        Visit::Complete
    } else {
        Visit::Pending(missing)
    };
    visits.insert(revision_id.to_string(), visit.clone());
    Ok(visit)
}

fn validate_uuid(field: &'static str, value: &str) -> RecordResult<()> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| RecordError::InvalidUuid {
            field,
            value: value.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn revision(entity_id: &str, revision_id: &str, parents: Vec<String>) -> EntityRevision {
        EntityRevision::new(
            entity_id,
            revision_id,
            1,
            parents,
            b"encrypted-fixture-state".to_vec(),
            vec![ImmutableObjectRef::new("ab".repeat(32), 23).unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn object_digest_is_lowercase_sha256() {
        assert!(ImmutableObjectRef::new("ab".repeat(32), 1).is_ok());
        assert!(matches!(
            ImmutableObjectRef::new("AB".repeat(32), 1),
            Err(RecordError::InvalidObjectDigest(_))
        ));
        assert!(matches!(
            ImmutableObjectRef::new("ab".repeat(31), 1),
            Err(RecordError::InvalidObjectDigest(_))
        ));
    }

    #[test]
    fn duplicate_insert_is_idempotent_but_collision_is_rejected() {
        let entity_id = id();
        let revision_id = id();
        let original = revision(&entity_id, &revision_id, Vec::new());
        let mut set = RevisionSet::new();

        assert_eq!(set.insert(original.clone()).unwrap(), InsertResult::Inserted);
        assert_eq!(
            set.insert(original).unwrap(),
            InsertResult::AlreadyPresent
        );

        let collision = EntityRevision::new(
            entity_id,
            revision_id.clone(),
            1,
            Vec::new(),
            b"different-encrypted-state".to_vec(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            set.insert(collision),
            Err(RecordError::RevisionCollision { revision_id })
        );
    }

    #[test]
    fn child_before_parent_is_pending_then_becomes_the_head() {
        let entity_id = id();
        let root_id = id();
        let child_id = id();
        let mut set = RevisionSet::new();

        set.insert(revision(
            &entity_id,
            &child_id,
            vec![root_id.clone()],
        ))
        .unwrap();
        let pending = set.analyze().unwrap();
        assert!(pending.heads_for(&entity_id).is_empty());
        assert_eq!(pending.pending().len(), 1);
        assert_eq!(
            pending.pending()[0].missing_parents(),
            std::slice::from_ref(&root_id)
        );

        set.insert(revision(&entity_id, &root_id, Vec::new()))
            .unwrap();
        let complete = set.analyze().unwrap();
        assert_eq!(complete.heads_for(&entity_id), &[child_id]);
        assert!(complete.pending().is_empty());
    }

    #[test]
    fn concurrent_children_are_conflicting_heads() {
        let entity_id = id();
        let root_id = id();
        let left_id = id();
        let right_id = id();
        let mut set = RevisionSet::new();
        set.insert(revision(&entity_id, &root_id, Vec::new()))
            .unwrap();
        set.insert(revision(
            &entity_id,
            &left_id,
            vec![root_id.clone()],
        ))
        .unwrap();
        set.insert(revision(&entity_id, &right_id, vec![root_id]))
            .unwrap();

        let analysis = set.analyze().unwrap();
        let mut expected = vec![left_id, right_id];
        expected.sort();
        assert_eq!(analysis.heads_for(&entity_id), expected);
        assert!(analysis.has_conflict(&entity_id));
    }

    #[test]
    fn merge_revision_resolves_concurrent_heads() {
        let entity_id = id();
        let root_id = id();
        let left_id = id();
        let right_id = id();
        let merge_id = id();
        let mut set = RevisionSet::new();
        for item in [
            revision(&entity_id, &root_id, Vec::new()),
            revision(&entity_id, &left_id, vec![root_id.clone()]),
            revision(&entity_id, &right_id, vec![root_id]),
            revision(
                &entity_id,
                &merge_id,
                vec![right_id.clone(), left_id.clone()],
            ),
        ] {
            set.insert(item).unwrap();
        }

        let analysis = set.analyze().unwrap();
        assert_eq!(analysis.heads_for(&entity_id), &[merge_id]);
        assert!(!analysis.has_conflict(&entity_id));
    }

    #[test]
    fn a_revision_cannot_parent_across_entities() {
        let first_entity = id();
        let second_entity = id();
        let root_id = id();
        let child_id = id();
        let mut set = RevisionSet::new();
        set.insert(revision(&first_entity, &root_id, Vec::new()))
            .unwrap();
        set.insert(revision(
            &second_entity,
            &child_id,
            vec![root_id.clone()],
        ))
        .unwrap();

        assert_eq!(
            set.analyze(),
            Err(RecordError::ParentEntityMismatch {
                revision_id: child_id,
                entity_id: second_entity,
                parent_id: root_id,
                parent_entity_id: first_entity,
            })
        );
    }

    #[test]
    fn commit_waits_for_members_and_their_ancestors() {
        let entity_id = id();
        let root_id = id();
        let child_id = id();
        let commit = RevisionCommit::new(id(), vec![child_id.clone()]).unwrap();
        let mut set = RevisionSet::new();

        assert_eq!(
            set.commit_readiness(&commit).unwrap().missing_revisions(),
            std::slice::from_ref(&child_id)
        );
        set.insert(revision(
            &entity_id,
            &child_id,
            vec![root_id.clone()],
        ))
        .unwrap();
        assert_eq!(
            set.commit_readiness(&commit).unwrap().missing_revisions(),
            std::slice::from_ref(&root_id)
        );
        set.insert(revision(&entity_id, &root_id, Vec::new()))
            .unwrap();
        assert_eq!(set.commit_readiness(&commit).unwrap(), CommitReadiness::Ready);
    }

    #[test]
    fn commit_has_at_most_one_revision_per_entity() {
        let entity_id = id();
        let first_id = id();
        let second_id = id();
        let commit_id = id();
        let commit =
            RevisionCommit::new(&commit_id, vec![first_id.clone(), second_id.clone()]).unwrap();
        let mut set = RevisionSet::new();
        set.insert(revision(&entity_id, &first_id, Vec::new()))
            .unwrap();
        set.insert(revision(&entity_id, &second_id, Vec::new()))
            .unwrap();

        assert_eq!(
            set.commit_readiness(&commit),
            Err(RecordError::CommitDuplicateEntity {
                commit_id,
                entity_id,
            })
        );
    }
}
