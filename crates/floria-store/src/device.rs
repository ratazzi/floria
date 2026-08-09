//! Local device identity: the Ed25519 signing key and X25519 wrapping key that represent this
//! installation inside a vault. Private halves never leave the machine; the encrypted at-rest
//! copy is wrapped by the same [`KeyProvider`] that unlocks the store, so enabling replication
//! adds no plaintext key file and no second platform credential source.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use age::secrecy::ExposeSecret;
use age::x25519;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{StoreError, StoreResult};
use crate::keys::KeyProvider;
use crate::vault::{
    decode, encode, ensure_private_directory, read_untrusted_file, require_private_file,
    require_uuid, sign_struct, write_new_atomic, write_replace_atomic, DeviceEnrollment,
    EnrollmentRequestDocument, EnrollmentRequestUnsigned, VaultDocument,
    ENROLLMENT_REQUEST_SIGNATURE_CONTEXT, MAX_DESCRIPTOR_BYTES, VAULT_FORMAT_VERSION,
};

pub struct DeviceKeyMaterial {
    device_id: String,
    signing_key: SigningKey,
    wrapping_identity: x25519::Identity,
}

impl DeviceKeyMaterial {
    pub fn generate() -> StoreResult<Self> {
        let mut signing_seed = [0_u8; 32];
        getrandom::getrandom(&mut signing_seed).map_err(|error| {
            StoreError::Crypto(format!("generate Device signing key: {error}"))
        })?;
        let material = Self::new(
            uuid::Uuid::new_v4().to_string(),
            signing_seed,
            x25519::Identity::generate(),
        );
        signing_seed.zeroize();
        material
    }

    pub fn new(
        device_id: impl Into<String>,
        signing_seed: [u8; 32],
        wrapping_identity: x25519::Identity,
    ) -> StoreResult<Self> {
        let device_id = device_id.into();
        require_uuid("device id", &device_id)?;
        Ok(Self {
            device_id,
            signing_key: SigningKey::from_bytes(&signing_seed),
            wrapping_identity,
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn wrapping_identity(&self) -> &x25519::Identity {
        &self.wrapping_identity
    }

    pub fn enrollment(&self) -> DeviceEnrollment {
        self.enrollment_named(None)
    }

    pub fn enrollment_named(&self, device_name: Option<String>) -> DeviceEnrollment {
        DeviceEnrollment {
            device_id: self.device_id.clone(),
            signing_public_key: encode(self.verifying_key().as_bytes()),
            wrapping_recipient: self.wrapping_identity.to_public().to_string(),
            device_name,
        }
    }

    /// Build the self-signed enrollment request this device drops into its own namespace of an
    /// untrusted sync directory. The signature proves key possession only; authorization is the
    /// genesis Mac's fingerprint comparison.
    pub fn enrollment_request(
        &self,
        vault: &VaultDocument,
        device_name: Option<String>,
        requested_at: &str,
    ) -> StoreResult<EnrollmentRequestDocument> {
        let enrollment = self.enrollment_named(device_name);
        let unsigned = EnrollmentRequestUnsigned {
            format_version: VAULT_FORMAT_VERSION,
            vault_id: vault.vault_id.clone(),
            device_id: enrollment.device_id.clone(),
            signing_public_key: enrollment.signing_public_key.clone(),
            wrapping_recipient: enrollment.wrapping_recipient.clone(),
            device_name: enrollment.device_name.clone(),
            requested_at: requested_at.to_string(),
        };
        let signature =
            sign_struct(ENROLLMENT_REQUEST_SIGNATURE_CONTEXT, &unsigned, &self.signing_key)?;
        Ok(EnrollmentRequestDocument {
            format_version: unsigned.format_version,
            vault_id: unsigned.vault_id,
            device_id: unsigned.device_id,
            signing_public_key: unsigned.signing_public_key,
            wrapping_recipient: unsigned.wrapping_recipient,
            device_name: unsigned.device_name,
            requested_at: unsigned.requested_at,
            signature,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct LocalDeviceSecretDocument {
    format_version: u32,
    device_id: String,
    signing_seed: String,
    wrapping_identity: String,
}

impl Drop for LocalDeviceSecretDocument {
    fn drop(&mut self) {
        self.signing_seed.zeroize();
        self.wrapping_identity.zeroize();
    }
}

/// Encrypted, machine-local persistence for one Device identity.
pub struct DeviceKeyStore {
    path: PathBuf,
    keys: Arc<dyn KeyProvider>,
}

pub(crate) struct PreparedDeviceKeyRotation {
    material: DeviceKeyMaterial,
    ciphertext: Vec<u8>,
}

impl PreparedDeviceKeyRotation {
    pub(crate) fn material(&self) -> &DeviceKeyMaterial {
        &self.material
    }
}

impl DeviceKeyStore {
    pub fn new(path: impl Into<PathBuf>, keys: Arc<dyn KeyProvider>) -> Self {
        Self { path: path.into(), keys }
    }

    pub fn load_or_create(&self) -> StoreResult<DeviceKeyMaterial> {
        let parent = self.path.parent().ok_or_else(|| {
            StoreError::Invalid(format!("{} has no parent directory", self.path.display()))
        })?;
        ensure_private_directory(parent)?;
        match fs::symlink_metadata(&self.path) {
            Ok(_) => self.load(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let material = DeviceKeyMaterial::generate()?;
                self.persist(&material)?;
                Ok(material)
            }
            Err(source) => Err(StoreError::io(&self.path, source)),
        }
    }

    pub fn load(&self) -> StoreResult<DeviceKeyMaterial> {
        require_private_file(&self.path)?;
        let ciphertext = read_untrusted_file(&self.path, MAX_DESCRIPTOR_BYTES)?;
        let plaintext = decrypt_with_provider(self.keys.as_ref(), &ciphertext)?;
        let document: LocalDeviceSecretDocument = serde_json::from_slice(&plaintext)
            .map_err(|error| StoreError::Invalid(format!("device key document: {error}")))?;
        if document.format_version != VAULT_FORMAT_VERSION {
            return Err(StoreError::Invalid(format!(
                "unsupported local Device key format {}",
                document.format_version
            )));
        }
        let signing_seed = decode("Device signing seed", &document.signing_seed)?;
        let mut signing_seed: [u8; 32] = signing_seed.try_into().map_err(|_| {
            StoreError::Invalid("Device signing seed must be 32 bytes".to_string())
        })?;
        let wrapping_identity = document
            .wrapping_identity
            .parse::<x25519::Identity>()
            .map_err(|error| {
                StoreError::Invalid(format!("invalid Device wrapping identity: {error}"))
            })?;
        let material = DeviceKeyMaterial::new(
            document.device_id.clone(),
            signing_seed,
            wrapping_identity,
        );
        signing_seed.zeroize();
        material
    }

    /// Replace a revoked local identity with a fresh Device id and keypair. Callers must only
    /// expose this after a signed Vault generation identifies the current identity as revoked.
    pub fn rotate(&self) -> StoreResult<DeviceKeyMaterial> {
        self.commit_rotation(self.prepare_rotation()?)
    }

    pub(crate) fn prepare_rotation(&self) -> StoreResult<PreparedDeviceKeyRotation> {
        self.load()?;
        let material = DeviceKeyMaterial::generate()?;
        let ciphertext = self.encrypt_material(&material)?;
        Ok(PreparedDeviceKeyRotation { material, ciphertext })
    }

    pub(crate) fn commit_rotation(
        &self,
        prepared: PreparedDeviceKeyRotation,
    ) -> StoreResult<DeviceKeyMaterial> {
        write_replace_atomic(&self.path, &prepared.ciphertext)?;
        Ok(prepared.material)
    }

    fn persist(&self, material: &DeviceKeyMaterial) -> StoreResult<()> {
        let ciphertext = self.encrypt_material(material)?;
        write_new_atomic(&self.path, &ciphertext)
    }

    fn encrypt_material(&self, material: &DeviceKeyMaterial) -> StoreResult<Vec<u8>> {
        let document = LocalDeviceSecretDocument {
            format_version: VAULT_FORMAT_VERSION,
            device_id: material.device_id.clone(),
            signing_seed: encode(&material.signing_key.to_bytes()),
            wrapping_identity: material
                .wrapping_identity
                .to_string()
                .expose_secret()
                .to_string(),
        };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&document)
                .map_err(|error| StoreError::Invalid(error.to_string()))?,
        );
        encrypt_with_provider(self.keys.as_ref(), &plaintext)
    }
}

fn encrypt_with_provider(provider: &dyn KeyProvider, plaintext: &[u8]) -> StoreResult<Vec<u8>> {
    let recipients = provider.recipients()?;
    let encryptor = age::Encryptor::with_recipients(recipients)
        .ok_or_else(|| StoreError::Crypto("no recipients configured".to_string()))?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|error| StoreError::Crypto(error.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|error| StoreError::Crypto(error.to_string()))?;
    writer
        .finish()
        .map_err(|error| StoreError::Crypto(error.to_string()))?;
    Ok(ciphertext)
}

fn decrypt_with_provider(
    provider: &dyn KeyProvider,
    ciphertext: &[u8],
) -> StoreResult<Zeroizing<Vec<u8>>> {
    let identity = provider.identity()?;
    let decryptor = match age::Decryptor::new(ciphertext)
        .map_err(|error| StoreError::Crypto(error.to_string()))?
    {
        age::Decryptor::Recipients(decryptor) => decryptor,
        age::Decryptor::Passphrase(_) => {
            return Err(StoreError::Crypto(
                "expected recipient-encrypted bytes".to_string(),
            ))
        }
    };
    let mut reader = decryptor
        .decrypt(std::iter::once(identity.as_ref()))
        .map_err(|error| StoreError::Crypto(error.to_string()))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|error| StoreError::Crypto(error.to_string()))?;
    Ok(plaintext)
}
