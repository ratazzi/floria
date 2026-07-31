use std::sync::Arc;

use floria_catalog::ResourceSource;
use floria_core::source::{CommandSource, ContentSource, LiteralSource};
use floria_store::{SecretId, SecretStore, StoreSource};

use crate::error::{SurfaceError, SurfaceResult};

/// Compile catalog source data into runtime behavior.
///
/// This is the only `ResourceSource` to `ContentSource` registry. Adding a new
/// value source requires one `ContentSource` implementation and one arm here;
/// filesystem, resolver, and audit drivers remain unchanged.
pub fn compile_source(
    source: &ResourceSource,
    store: &Arc<dyn SecretStore>,
) -> SurfaceResult<Arc<dyn ContentSource>> {
    let source: Arc<dyn ContentSource> = match source {
        ResourceSource::SecretRef { secret_id } => {
            let id: SecretId = secret_id.parse()?;
            Arc::new(StoreSource::new(Arc::clone(store), id))
        }
        ResourceSource::Literal { value } => {
            Arc::new(LiteralSource::new(Arc::new(value.as_bytes().to_vec())))
        }
        ResourceSource::Command { argv } => Arc::new(CommandSource::new(argv.clone())),
        ResourceSource::Socket => {
            return Err(SurfaceError::IncompatibleResource {
                resource_id: "<resource-source>".to_string(),
                reason: "socket source is not byte content".to_string(),
            });
        }
    };
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use floria_core::source::StorageDisposition;
    use floria_store::{
        NewSecret, SecretRecord, StoreResult, VersionRecord,
    };
    use std::path::Path;
    use zeroize::Zeroizing;

    struct UnusedStore;

    impl SecretStore for UnusedStore {
        fn put(&self, _meta: NewSecret, _plaintext: &[u8]) -> StoreResult<SecretId> {
            unimplemented!()
        }

        fn get(&self, _id: &SecretId) -> StoreResult<Zeroizing<Vec<u8>>> {
            unimplemented!()
        }

        fn get_version(
            &self,
            _id: &SecretId,
            _version: u32,
        ) -> StoreResult<Zeroizing<Vec<u8>>> {
            unimplemented!()
        }

        fn append_version(&self, _id: &SecretId, _plaintext: &[u8]) -> StoreResult<u32> {
            unimplemented!()
        }

        fn history(&self, _id: &SecretId) -> StoreResult<Vec<VersionRecord>> {
            unimplemented!()
        }

        fn set_head(&self, _id: &SecretId, _version: u32) -> StoreResult<()> {
            unimplemented!()
        }

        fn record(&self, _id: &SecretId) -> StoreResult<Option<SecretRecord>> {
            unimplemented!()
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
            _metadata: floria_core::metadata::ItemMetadata,
            _enforcement: floria_core::authz::Enforcement,
            _environment_ids: Option<Vec<String>>,
        ) -> StoreResult<()> {
            unimplemented!()
        }

        fn delete(&self, _id: &SecretId) -> StoreResult<()> {
            unimplemented!()
        }
    }

    fn store() -> Arc<dyn SecretStore> {
        Arc::new(UnusedStore)
    }

    #[test]
    fn compiles_catalog_byte_sources_with_explicit_storage_dispositions() {
        let store = store();
        let secret = compile_source(
            &ResourceSource::SecretRef {
                secret_id: "00000000-0000-0000-0000-000000000901".to_string(),
            },
            &store,
        )
        .unwrap();
        let literal = compile_source(
            &ResourceSource::Literal {
                value: "fixture".to_string(),
            },
            &store,
        )
        .unwrap();
        let command = compile_source(
            &ResourceSource::Command {
                argv: vec!["/fixture/command".to_string()],
            },
            &store,
        )
        .unwrap();

        assert_eq!(
            secret.storage_disposition(),
            StorageDisposition::EncryptedReference
        );
        assert_eq!(
            literal.storage_disposition(),
            StorageDisposition::InlinePlaintext
        );
        assert_eq!(
            command.storage_disposition(),
            StorageDisposition::Computed
        );
    }

    #[test]
    fn rejects_socket_sources_as_non_byte_content() {
        assert!(matches!(
            compile_source(
                &ResourceSource::Socket,
                &store(),
            ),
            Err(SurfaceError::IncompatibleResource { .. })
        ));
    }
}
