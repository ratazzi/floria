//! Access to the vault's key generations from this device's point of view.
//!
//! Generations live only in the shared half as signed documents (`generations/<NNNN>.json`):
//! the generation public key and recovery recipient ride in the document (encrypt without
//! unlocking anything), and the per-device envelopes — inline in the document or as
//! `devices/<id>/envelopes/<N>.age` files — wrap the generation identity to each device.
//! There is no machine-local key copy, hence nothing to reconcile.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Mutex;

use age::x25519;

use crate::device::DeviceKeyMaterial;
use crate::error::{StoreError, StoreResult};
use crate::vault::{
    decode, decrypt_with_identity, load_key_generations, read_untrusted_file, KeyGenerationDocument,
    SharedLayout, VaultDocument, MAX_DESCRIPTOR_BYTES,
};

pub(crate) struct GenerationAccess {
    cache: Mutex<GenerationCache>,
}

#[derive(Default)]
struct GenerationCache {
    documents: BTreeMap<u32, KeyGenerationDocument>,
    identities: HashMap<u32, x25519::Identity>,
}

impl GenerationAccess {
    pub(crate) fn new() -> Self {
        GenerationAccess { cache: Mutex::new(GenerationCache::default()) }
    }

    /// Drop unwrapped identities (a rotated device identity invalidates them).
    pub(crate) fn clear_identity_cache(&self) {
        self.cache.lock().expect("generation cache poisoned").identities.clear();
    }

    /// Reload the signed generation chain from the shared half.
    pub(crate) fn refresh(
        &self,
        layout: &SharedLayout,
        vault: &VaultDocument,
    ) -> StoreResult<()> {
        let documents = load_key_generations(layout, vault)?;
        let mut cache = self.cache.lock().expect("generation cache poisoned");
        cache.identities.retain(|generation, _| documents.contains_key(generation));
        cache.documents = documents;
        Ok(())
    }

    fn with_current<T>(
        &self,
        layout: &SharedLayout,
        vault: &VaultDocument,
        read: impl Fn(&KeyGenerationDocument) -> StoreResult<T>,
    ) -> StoreResult<T> {
        {
            let cache = self.cache.lock().expect("generation cache poisoned");
            if let Some(document) = cache.documents.values().next_back() {
                return read(document);
            }
        }
        self.refresh(layout, vault)?;
        let cache = self.cache.lock().expect("generation cache poisoned");
        let document = cache.documents.values().next_back().ok_or_else(|| {
            StoreError::Invalid("Vault has no signed key generation".to_string())
        })?;
        read(document)
    }

    /// The generation new versions are encrypted under right now.
    pub(crate) fn current(
        &self,
        layout: &SharedLayout,
        vault: &VaultDocument,
    ) -> StoreResult<u32> {
        self.with_current(layout, vault, |document| Ok(document.generation))
    }

    /// Encryption recipients (current generation + recovery), straight from the signed
    /// document — no private key involved.
    pub(crate) fn recipients(
        &self,
        layout: &SharedLayout,
        vault: &VaultDocument,
    ) -> StoreResult<Vec<Box<dyn age::Recipient + Send>>> {
        self.current_recipients(layout, vault)
            .map(|(_, recipients)| recipients)
    }

    /// Return the generation label and its recipients from the same signed document.
    pub(crate) fn current_recipients(
        &self,
        layout: &SharedLayout,
        vault: &VaultDocument,
    ) -> StoreResult<(u32, Vec<Box<dyn age::Recipient + Send>>)> {
        self.with_current(layout, vault, |document| {
            let generation = x25519::Recipient::from_str(document.generation_public.trim())
                .map_err(|error| {
                    StoreError::Invalid(format!("invalid generation public key: {error}"))
                })?;
            let recovery = x25519::Recipient::from_str(document.recovery_public.trim())
                .map_err(|error| {
                    StoreError::Invalid(format!("invalid recovery recipient: {error}"))
                })?;
            Ok((
                document.generation,
                vec![
                    Box::new(generation) as Box<dyn age::Recipient + Send>,
                    Box::new(recovery) as Box<dyn age::Recipient + Send>,
                ],
            ))
        })
    }

    pub(crate) fn recovery_public(
        &self,
        layout: &SharedLayout,
        vault: &VaultDocument,
    ) -> StoreResult<String> {
        self.with_current(layout, vault, |document| Ok(document.recovery_public.clone()))
    }

    /// Unwrap (and cache) the identity for `generation` using this device's wrapping key.
    /// The envelope comes from the generation document, falling back to the device's
    /// envelope file.
    pub(crate) fn identity(
        &self,
        layout: &SharedLayout,
        vault: &VaultDocument,
        device: &DeviceKeyMaterial,
        generation: u32,
    ) -> StoreResult<x25519::Identity> {
        {
            let cache = self.cache.lock().expect("generation cache poisoned");
            if let Some(identity) = cache.identities.get(&generation) {
                return Ok(identity.clone());
            }
        }
        let document = {
            let cache = self.cache.lock().expect("generation cache poisoned");
            cache.documents.get(&generation).cloned()
        };
        let document = match document {
            Some(document) => Some(document),
            None => {
                self.refresh(layout, vault)?;
                let cache = self.cache.lock().expect("generation cache poisoned");
                cache.documents.get(&generation).cloned()
            }
        };
        let envelope = match document
            .as_ref()
            .and_then(|document| document.envelopes.get(device.device_id()))
        {
            Some(envelope) => decode("Vault key envelope", envelope)?,
            None => read_untrusted_file(
                &layout.envelope(device.device_id(), generation),
                MAX_DESCRIPTOR_BYTES,
            )
            .map_err(|error| match error {
                StoreError::Io { source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    StoreError::Key(format!(
                        "this device has no envelope for key generation {generation}"
                    ))
                }
                error => error,
            })?,
        };
        let plaintext = decrypt_with_identity(device.wrapping_identity(), &envelope)?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| {
            StoreError::Key(format!("generation {generation} envelope is not text"))
        })?;
        let identity = x25519::Identity::from_str(text.trim()).map_err(|error| {
            StoreError::Key(format!("parse generation {generation} identity: {error}"))
        })?;
        self.cache
            .lock()
            .expect("generation cache poisoned")
            .identities
            .insert(generation, identity.clone());
        Ok(identity)
    }
}
