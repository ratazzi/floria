use std::sync::Arc;

use accessfs_core::source::{
    ContentSource, PinnedContent, PinnedVersion, SourceCtx, SourceSnapshot, StorageDisposition,
};
use accessfs_core::{CoreError, Result};

use crate::{SecretId, SecretStore};

#[derive(Clone)]
pub struct StoreSource {
    store: Arc<dyn SecretStore>,
    secret_id: SecretId,
}

impl StoreSource {
    pub fn new(store: Arc<dyn SecretStore>, secret_id: SecretId) -> Self {
        StoreSource { store, secret_id }
    }
}

impl std::fmt::Debug for StoreSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreSource")
            .field("secret_id", &self.secret_id)
            .finish_non_exhaustive()
    }
}

impl ContentSource for StoreSource {
    fn storage_disposition(&self) -> StorageDisposition {
        StorageDisposition::EncryptedReference
    }

    fn pin(&self, _ctx: &SourceCtx<'_>) -> Result<Box<dyn PinnedContent>> {
        let record = self
            .store
            .record(&self.secret_id)
            .map_err(source_error)?
            .ok_or_else(|| CoreError::source(format!("secret {} was not found", self.secret_id)))?;
        Ok(Box::new(PinnedStoreContent {
            store: Arc::clone(&self.store),
            secret_id: self.secret_id.clone(),
            pinned: PinnedVersion {
                secret_id: self.secret_id.to_string(),
                version: record.current_version,
            },
        }))
    }
}

struct PinnedStoreContent {
    store: Arc<dyn SecretStore>,
    secret_id: SecretId,
    pinned: PinnedVersion,
}

impl PinnedContent for PinnedStoreContent {
    fn pinned_version(&self) -> Option<&PinnedVersion> {
        Some(&self.pinned)
    }

    fn read(self: Box<Self>) -> Result<SourceSnapshot> {
        let PinnedStoreContent { store, secret_id, pinned } = *self;
        let bytes = store
            .get_version(&secret_id, pinned.version)
            .map_err(source_error)?;
        Ok(SourceSnapshot { bytes, pinned: Some(pinned) })
    }
}

fn source_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::source(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    use accessfs_core::authz::Operation;
    use accessfs_core::metadata::ItemMetadata;
    use accessfs_core::source::StorageDisposition;
    use zeroize::Zeroizing;

    use crate::{
        NewSecret, SecretOrigin, SecretRecord, StoreResult, VersionRecord,
    };

    struct FixtureStore {
        id: SecretId,
        head: AtomicU32,
        reads: AtomicUsize,
    }

    impl FixtureStore {
        fn new(id: SecretId) -> Self {
            FixtureStore {
                id,
                head: AtomicU32::new(1),
                reads: AtomicUsize::new(0),
            }
        }
    }

    impl SecretStore for FixtureStore {
        fn put(&self, _meta: NewSecret, _plaintext: &[u8]) -> StoreResult<SecretId> {
            unimplemented!()
        }

        fn get(&self, _id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            unimplemented!()
        }

        fn get_version(
            &self,
            _id: &SecretId,
            version: u32,
        ) -> StoreResult<Zeroizing<Vec<u8>>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(Zeroizing::new(match version {
                1 => b"first".to_vec(),
                2 => b"second".to_vec(),
                _ => unreachable!(),
            }))
        }

        fn append_version(&self, _id: &SecretId, _plaintext: &[u8]) -> StoreResult<u32> {
            unimplemented!()
        }

        fn history(&self, _id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            unimplemented!()
        }

        fn set_head(&self, _id: &SecretId, version: u32) -> StoreResult<()> {
            self.head.store(version, Ordering::Relaxed);
            Ok(())
        }

        fn record(&self, _id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            Ok(Some(SecretRecord {
                id: self.id.clone(),
                origin: SecretOrigin::Managed { label: "Fixture".to_string() },
                mode: 0o600,
                size: 6,
                created: "fixture-time".to_string(),
                current_version: self.head.load(Ordering::Relaxed),
                enforcement: accessfs_core::authz::Enforcement::Prompt,
                environment_ids: None,
                metadata: ItemMetadata::default(),
            }))
        }

        fn list(&self) -> StoreResult<Vec<SecretRecord>> {
            unimplemented!()
        }

        fn get_by_path(&self, _source_path: &Path) -> StoreResult<Option<SecretRecord>> {
            unimplemented!()
        }

        fn update_settings(
            &self,
            _id: &SecretId,
            _metadata: ItemMetadata,
            _enforcement: accessfs_core::authz::Enforcement,
            _environment_ids: Option<Vec<String>>,
        ) -> StoreResult<()> {
            unimplemented!()
        }

        fn delete(&self, _id: &SecretId) -> StoreResult<()> {
            unimplemented!()
        }
    }

    #[test]
    fn pins_head_metadata_before_decrypting_that_immutable_version() {
        let id: SecretId = "00000000-0000-0000-0000-000000000901".parse().unwrap();
        let store = Arc::new(FixtureStore::new(id.clone()));
        let source =
            StoreSource::new(Arc::clone(&store) as Arc<dyn SecretStore>, id.clone());
        assert_eq!(
            source.storage_disposition(),
            StorageDisposition::EncryptedReference
        );

        let pinned = source
            .pin(&SourceCtx {
                virtual_path: "secrets/fixture",
                request_uid: 501,
                request_pid: 42,
                operation: Operation::Read,
            })
            .unwrap();
        assert_eq!(pinned.pinned_version().unwrap().version, 1);
        assert_eq!(store.reads.load(Ordering::Relaxed), 0);
        store.set_head(&id, 2).unwrap();

        let snapshot = pinned.read().unwrap();
        assert_eq!(snapshot.bytes.as_slice(), b"first");
        assert_eq!(snapshot.pinned.unwrap().version, 1);
        assert_eq!(store.reads.load(Ordering::Relaxed), 1);
    }
}
