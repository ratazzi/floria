//! Complete decrypted entity documents, independent of transport envelopes.

use serde::{Deserialize, Serialize};

use crate::entity_state::CatalogEntityDocument;
use crate::record::ImmutableObjectRef;
use crate::secret_state::SecretEntityDocument;
use crate::ReplicationResult;

/// Whether an entity participates in the current local projection.
///
/// Archiving retains the last complete encrypted state so a later revision can restore it without
/// resurrecting deleted transport records or plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityLifecycle {
    Active,
    Archived,
}

/// One complete state decoded from an authenticated Entity Revision.
///
/// The tag is inside ciphertext: transports can route stable UUIDs but cannot learn whether a
/// record describes catalog metadata or encrypted content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "entity_type", content = "document", rename_all = "snake_case")]
pub enum ReplicatedEntityDocument {
    Catalog(CatalogEntityDocument),
    Secret(SecretEntityDocument),
}

impl ReplicatedEntityDocument {
    pub fn entity_id(&self) -> &str {
        match self {
            Self::Catalog(document) => document.entity_id(),
            Self::Secret(document) => document.entity_id(),
        }
    }

    pub fn lifecycle(&self) -> EntityLifecycle {
        match self {
            Self::Catalog(document) => document.lifecycle(),
            Self::Secret(document) => document.lifecycle(),
        }
    }

    pub fn object_refs(&self) -> Vec<ImmutableObjectRef> {
        match self {
            Self::Catalog(_) => Vec::new(),
            Self::Secret(document) => vec![document.head().object().clone()],
        }
    }

    pub(crate) fn validate(&self) -> ReplicationResult<()> {
        match self {
            Self::Catalog(document) => document.validate(),
            Self::Secret(document) => document.validate(),
        }
    }
}
