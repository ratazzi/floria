//! The shared half's document model: vault identity, device trust, and key generations.
//!
//! Everything under `shared/` is a plain, immutable, signed file that sync tools move as-is.
//! The store owns this layout because the shared half IS the storage (format 5); replication
//! builds its operation log on top using the same primitives. All content is treated as
//! untrusted input: documents are validated and signature-checked on every read.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{StoreError, StoreResult};

/// Format version shared by every signed document in the vault.
pub const VAULT_FORMAT_VERSION: u32 = 1;
pub const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;

pub const VAULT_SIGNATURE_CONTEXT: &[u8] = b"floria-vault-v1\0";
pub const DEVICE_SIGNATURE_CONTEXT: &[u8] = b"floria-device-v1\0";
pub const KEY_GENERATION_SIGNATURE_CONTEXT: &[u8] = b"floria-key-generation-v1\0";
pub const ENROLLMENT_REQUEST_SIGNATURE_CONTEXT: &[u8] = b"floria-enrollment-request-v1\0";
pub const OPERATION_SIGNATURE_CONTEXT: &[u8] = b"floria-operation-v1\0";
pub const CHECKPOINT_SIGNATURE_CONTEXT: &[u8] = b"floria-checkpoint-v1\0";

/// Path helpers for the shared half. The layout is part of the on-disk format.
#[derive(Clone, Debug)]
pub struct SharedLayout {
    root: PathBuf,
}

impl SharedLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        SharedLayout { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn vault_json(&self) -> PathBuf {
        self.root.join("vault.json")
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    pub fn object(&self, digest: &str) -> PathBuf {
        self.objects_dir().join(format!("{digest}.age"))
    }

    pub fn devices_dir(&self) -> PathBuf {
        self.root.join("devices")
    }

    pub fn device_dir(&self, device_id: &str) -> PathBuf {
        self.devices_dir().join(device_id)
    }

    pub fn device_identity(&self, device_id: &str) -> PathBuf {
        self.device_dir(device_id).join("identity.json")
    }

    pub fn enrollment_request(&self, device_id: &str) -> PathBuf {
        self.device_dir(device_id).join("request.json")
    }

    pub fn envelopes_dir(&self, device_id: &str) -> PathBuf {
        self.device_dir(device_id).join("envelopes")
    }

    pub fn envelope(&self, device_id: &str, generation: u32) -> PathBuf {
        self.envelopes_dir(device_id).join(envelope_filename(generation))
    }

    pub fn generations_dir(&self) -> PathBuf {
        self.root.join("generations")
    }

    pub fn generation_document(&self, generation: u32) -> PathBuf {
        self.generations_dir().join(generation_filename(generation))
    }

    pub fn operations_dir(&self) -> PathBuf {
        self.root.join("operations")
    }

    pub fn device_operations_dir(&self, device_id: &str) -> PathBuf {
        self.operations_dir().join(device_id)
    }

    pub fn checkpoints_dir(&self) -> PathBuf {
        self.root.join("checkpoints")
    }

    pub fn device_checkpoints_dir(&self, device_id: &str) -> PathBuf {
        self.checkpoints_dir().join(device_id)
    }
}

pub fn generation_filename(generation: u32) -> String {
    format!("{generation:020}.json")
}

pub fn envelope_filename(generation: u32) -> String {
    format!("{generation}.age")
}

/// Public material approved by (or requesting approval from) the genesis Device. Safe to move
/// between machines while the corresponding private keys remain local.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnrollment {
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VaultUnsigned {
    pub format_version: u32,
    pub vault_id: String,
    pub genesis_device_id: String,
    pub genesis_public_key: String,
    pub created_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultDocument {
    pub format_version: u32,
    pub vault_id: String,
    pub genesis_device_id: String,
    pub genesis_public_key: String,
    pub created_at: String,
    pub signature: String,
}

impl VaultDocument {
    pub fn unsigned(&self) -> VaultUnsigned {
        VaultUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            genesis_device_id: self.genesis_device_id.clone(),
            genesis_public_key: self.genesis_public_key.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceUnsigned {
    pub format_version: u32,
    pub vault_id: String,
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub authorized_by: String,
    pub enrolled_generation: u32,
}

/// Genesis-signed device identity: the authority that a device is trusted.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceDocument {
    pub format_version: u32,
    pub vault_id: String,
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub authorized_by: String,
    pub enrolled_generation: u32,
    pub signature: String,
}

impl DeviceDocument {
    pub fn unsigned(&self) -> DeviceUnsigned {
        DeviceUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
            signing_public_key: self.signing_public_key.clone(),
            wrapping_recipient: self.wrapping_recipient.clone(),
            device_name: self.device_name.clone(),
            authorized_by: self.authorized_by.clone(),
            enrolled_generation: self.enrolled_generation,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EnrollmentRequestUnsigned {
    pub format_version: u32,
    pub vault_id: String,
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub requested_at: String,
}

/// Self-signed enrollment request a joining device drops into its own namespace
/// (`devices/<id>/request.json`). It carries no trust — the self-signature only proves key
/// possession; the sync directory is an untrusted channel, so approval on the genesis Mac MUST
/// show the signing-key fingerprint for out-of-band comparison.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollmentRequestDocument {
    pub format_version: u32,
    pub vault_id: String,
    pub device_id: String,
    pub signing_public_key: String,
    pub wrapping_recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub requested_at: String,
    pub signature: String,
}

impl EnrollmentRequestDocument {
    pub fn unsigned(&self) -> EnrollmentRequestUnsigned {
        EnrollmentRequestUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
            signing_public_key: self.signing_public_key.clone(),
            wrapping_recipient: self.wrapping_recipient.clone(),
            device_name: self.device_name.clone(),
            requested_at: self.requested_at.clone(),
        }
    }

    pub fn enrollment(&self) -> DeviceEnrollment {
        DeviceEnrollment {
            device_id: self.device_id.clone(),
            signing_public_key: self.signing_public_key.clone(),
            wrapping_recipient: self.wrapping_recipient.clone(),
            device_name: self.device_name.clone(),
        }
    }

    /// Short fingerprint of the signing public key for on-screen comparison (number matching).
    pub fn fingerprint(&self) -> String {
        signing_key_fingerprint(&self.signing_public_key)
    }
}

/// Uppercase hex prefix of sha256(signing public key bytes), grouped for reading aloud.
pub fn signing_key_fingerprint(encoded_signing_public_key: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(encoded_signing_public_key.as_bytes());
    digest[..6]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|pair| pair.concat())
        .collect::<Vec<_>>()
        .join("-")
}

#[derive(Serialize, Deserialize)]
pub struct KeyGenerationUnsigned {
    pub format_version: u32,
    pub vault_id: String,
    pub generation: u32,
    pub previous_generation: Option<u32>,
    pub authorized_by: String,
    pub envelopes: BTreeMap<String, String>,
    pub revoked_devices: BTreeMap<String, u64>,
    /// The generation's public key: lets any holder of the shared half encrypt new versions
    /// without unlocking anything.
    pub generation_public: String,
    /// The vault-wide recovery recipient every version file is also encrypted to.
    pub recovery_public: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyGenerationDocument {
    pub format_version: u32,
    pub vault_id: String,
    pub generation: u32,
    pub previous_generation: Option<u32>,
    pub authorized_by: String,
    pub envelopes: BTreeMap<String, String>,
    pub revoked_devices: BTreeMap<String, u64>,
    pub generation_public: String,
    pub recovery_public: String,
    pub signature: String,
}

impl KeyGenerationDocument {
    pub fn unsigned(&self) -> KeyGenerationUnsigned {
        KeyGenerationUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            generation: self.generation,
            previous_generation: self.previous_generation,
            authorized_by: self.authorized_by.clone(),
            envelopes: self.envelopes.clone(),
            revoked_devices: self.revoked_devices.clone(),
            generation_public: self.generation_public.clone(),
            recovery_public: self.recovery_public.clone(),
        }
    }
}

pub fn require_uuid(label: &str, value: &str) -> StoreResult<()> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| StoreError::Invalid(format!("{label} is not a UUID: {value:?}")))
}

pub fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(label: &str, value: &str) -> StoreResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| StoreError::Invalid(format!("{label} is not Base64: {error}")))
}

pub fn sign_struct<T: Serialize>(
    context: &[u8],
    value: &T,
    key: &SigningKey,
) -> StoreResult<String> {
    let message = signing_bytes(context, value)?;
    Ok(encode(&key.sign(&message).to_bytes()))
}

pub fn verify_struct<T: Serialize>(
    context: &[u8],
    value: &T,
    encoded_signature: &str,
    key: &VerifyingKey,
) -> StoreResult<()> {
    let bytes = decode("signature", encoded_signature)?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| StoreError::Crypto("Ed25519 signature must be 64 bytes".to_string()))?;
    key.verify(&signing_bytes(context, value)?, &Signature::from_bytes(&bytes))
        .map_err(|error| StoreError::Crypto(format!("signature verification failed: {error}")))
}

fn signing_bytes<T: Serialize>(context: &[u8], value: &T) -> StoreResult<Vec<u8>> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| StoreError::Invalid(format!("serialize signed document: {error}")))?;
    let mut message = Vec::with_capacity(context.len() + encoded.len());
    message.extend_from_slice(context);
    message.extend_from_slice(&encoded);
    Ok(message)
}

pub fn verifying_key(label: &str, encoded: &str) -> StoreResult<VerifyingKey> {
    let bytes = decode(label, encoded)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::Invalid(format!("{label} must be 32 bytes")))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| StoreError::Invalid(format!("invalid {label}: {error}")))
}

/// age-encrypt to a single x25519 recipient (envelopes and payloads).
pub fn encrypt_to_recipient(
    recipient: &x25519::Recipient,
    plaintext: &[u8],
) -> StoreResult<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .ok_or_else(|| StoreError::Crypto("no recipient".to_string()))?;
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

pub fn decrypt_with_identity(
    identity: &x25519::Identity,
    ciphertext: &[u8],
) -> StoreResult<Zeroizing<Vec<u8>>> {
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
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|error| StoreError::Crypto(error.to_string()))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|error| StoreError::Crypto(error.to_string()))?;
    Ok(plaintext)
}

pub fn validate_vault(vault: &VaultDocument) -> StoreResult<()> {
    if vault.format_version != VAULT_FORMAT_VERSION {
        return Err(StoreError::Invalid(format!(
            "unsupported Vault format {}",
            vault.format_version
        )));
    }
    require_uuid("vault id", &vault.vault_id)?;
    require_uuid("genesis device id", &vault.genesis_device_id)?;
    let key = verifying_key("genesis public key", &vault.genesis_public_key)?;
    verify_struct(VAULT_SIGNATURE_CONTEXT, &vault.unsigned(), &vault.signature, &key)
}

pub fn validate_enrollment(enrollment: &DeviceEnrollment) -> StoreResult<()> {
    require_uuid("device id", &enrollment.device_id)?;
    if let Some(device_name) = &enrollment.device_name {
        if device_name.is_empty()
            || device_name.trim() != device_name
            || device_name.chars().count() > 80
            || device_name.chars().any(char::is_control)
        {
            return Err(StoreError::Invalid(
                "Device name must be 1-80 printable characters without surrounding whitespace"
                    .to_string(),
            ));
        }
    }
    verifying_key("Device public key", &enrollment.signing_public_key)?;
    enrollment
        .wrapping_recipient
        .parse::<x25519::Recipient>()
        .map_err(|error| {
            StoreError::Invalid(format!("invalid Device wrapping recipient: {error}"))
        })?;
    Ok(())
}

pub fn validate_device_identity(
    identity: &DeviceDocument,
    vault: &VaultDocument,
) -> StoreResult<()> {
    if identity.format_version != VAULT_FORMAT_VERSION
        || identity.vault_id != vault.vault_id
        || identity.authorized_by != vault.genesis_device_id
        || identity.enrolled_generation == 0
    {
        return Err(StoreError::Invalid(
            "Device identity does not match vault.json".to_string(),
        ));
    }
    validate_enrollment(&DeviceEnrollment {
        device_id: identity.device_id.clone(),
        signing_public_key: identity.signing_public_key.clone(),
        wrapping_recipient: identity.wrapping_recipient.clone(),
        device_name: identity.device_name.clone(),
    })?;
    if identity.device_id == vault.genesis_device_id
        && identity.signing_public_key != vault.genesis_public_key
    {
        return Err(StoreError::Invalid(
            "genesis Device identity does not match vault.json".to_string(),
        ));
    }
    let key = verifying_key("genesis public key", &vault.genesis_public_key)?;
    verify_struct(
        DEVICE_SIGNATURE_CONTEXT,
        &identity.unsigned(),
        &identity.signature,
        &key,
    )
}

/// Validate a self-signed enrollment request. Passing proves only key possession and vault
/// targeting — never trust; the human fingerprint comparison is the authorization step.
pub fn validate_enrollment_request(
    request: &EnrollmentRequestDocument,
    vault: &VaultDocument,
) -> StoreResult<()> {
    if request.format_version != VAULT_FORMAT_VERSION || request.vault_id != vault.vault_id {
        return Err(StoreError::Invalid(
            "enrollment request does not match vault.json".to_string(),
        ));
    }
    validate_enrollment(&request.enrollment())?;
    let key = verifying_key("Device public key", &request.signing_public_key)?;
    verify_struct(
        ENROLLMENT_REQUEST_SIGNATURE_CONTEXT,
        &request.unsigned(),
        &request.signature,
        &key,
    )
}

pub fn validate_key_generation(
    document: &KeyGenerationDocument,
    vault: &VaultDocument,
) -> StoreResult<()> {
    if document.format_version != VAULT_FORMAT_VERSION
        || document.vault_id != vault.vault_id
        || document.authorized_by != vault.genesis_device_id
        || document.generation == 0
    {
        return Err(StoreError::Invalid(
            "key generation does not match vault.json".to_string(),
        ));
    }
    document
        .generation_public
        .parse::<x25519::Recipient>()
        .map_err(|error| {
            StoreError::Invalid(format!("invalid generation public key: {error}"))
        })?;
    document
        .recovery_public
        .parse::<x25519::Recipient>()
        .map_err(|error| StoreError::Invalid(format!("invalid recovery recipient: {error}")))?;
    for (device_id, envelope) in &document.envelopes {
        require_uuid("envelope Device id", device_id)?;
        let bytes = decode("Vault key envelope", envelope)?;
        if bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
            return Err(StoreError::Invalid(
                "Vault key envelope exceeds the format limit".to_string(),
            ));
        }
    }
    for device_id in document.revoked_devices.keys() {
        require_uuid("revoked Device id", device_id)?;
        if document.envelopes.contains_key(device_id) {
            return Err(StoreError::Invalid(format!(
                "revoked Device {device_id} still has an envelope in generation {}",
                document.generation
            )));
        }
    }
    let genesis_key = verifying_key("genesis public key", &vault.genesis_public_key)?;
    verify_struct(
        KEY_GENERATION_SIGNATURE_CONTEXT,
        &document.unsigned(),
        &document.signature,
        &genesis_key,
    )
}

pub fn read_vault(layout: &SharedLayout) -> StoreResult<VaultDocument> {
    let bytes = read_untrusted_file(&layout.vault_json(), MAX_DESCRIPTOR_BYTES)?;
    let vault: VaultDocument = serde_json::from_slice(&bytes)
        .map_err(|error| StoreError::Invalid(format!("vault.json: {error}")))?;
    validate_vault(&vault)?;
    Ok(vault)
}

pub fn read_device_identity(
    path: &Path,
    vault: &VaultDocument,
) -> StoreResult<DeviceDocument> {
    let bytes = read_untrusted_file(path, MAX_DESCRIPTOR_BYTES)?;
    let identity: DeviceDocument = serde_json::from_slice(&bytes)
        .map_err(|error| StoreError::Invalid(format!("device identity: {error}")))?;
    validate_device_identity(&identity, vault)?;
    Ok(identity)
}

pub fn read_enrollment_request(
    path: &Path,
    vault: &VaultDocument,
) -> StoreResult<EnrollmentRequestDocument> {
    let bytes = read_untrusted_file(path, MAX_DESCRIPTOR_BYTES)?;
    let request: EnrollmentRequestDocument = serde_json::from_slice(&bytes)
        .map_err(|error| StoreError::Invalid(format!("enrollment request: {error}")))?;
    validate_enrollment_request(&request, vault)?;
    Ok(request)
}

pub fn write_device_identity(
    path: &Path,
    vault: &VaultDocument,
    enrollment: &DeviceEnrollment,
    enrolled_generation: u32,
    genesis_signing_key: &SigningKey,
) -> StoreResult<()> {
    validate_enrollment(enrollment)?;
    if genesis_signing_key.verifying_key()
        != verifying_key("genesis public key", &vault.genesis_public_key)?
    {
        return Err(StoreError::Invalid(
            "Device enrollment signer is not the genesis Device".to_string(),
        ));
    }
    if enrolled_generation == 0 {
        return Err(StoreError::Invalid(
            "Device enrollment generation starts at 1".to_string(),
        ));
    }
    let unsigned = DeviceUnsigned {
        format_version: VAULT_FORMAT_VERSION,
        vault_id: vault.vault_id.clone(),
        device_id: enrollment.device_id.clone(),
        signing_public_key: enrollment.signing_public_key.clone(),
        wrapping_recipient: enrollment.wrapping_recipient.clone(),
        device_name: enrollment.device_name.clone(),
        authorized_by: vault.genesis_device_id.clone(),
        enrolled_generation,
    };
    let signature = sign_struct(DEVICE_SIGNATURE_CONTEXT, &unsigned, genesis_signing_key)?;
    let document = DeviceDocument {
        format_version: unsigned.format_version,
        vault_id: unsigned.vault_id,
        device_id: unsigned.device_id,
        signing_public_key: unsigned.signing_public_key,
        wrapping_recipient: unsigned.wrapping_recipient,
        device_name: unsigned.device_name,
        authorized_by: unsigned.authorized_by,
        enrolled_generation: unsigned.enrolled_generation,
        signature,
    };
    write_new_atomic(
        path,
        &serde_json::to_vec_pretty(&document)
            .map_err(|error| StoreError::Invalid(error.to_string()))?,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_key_generation(
    path: &Path,
    vault: &VaultDocument,
    generation: u32,
    previous_generation: Option<u32>,
    vault_identity: &x25519::Identity,
    recipients: &BTreeMap<String, x25519::Recipient>,
    revoked_devices: BTreeMap<String, u64>,
    recovery_public: &str,
    genesis_signing_key: &SigningKey,
) -> StoreResult<()> {
    if generation == 0
        || previous_generation != generation.checked_sub(1).filter(|previous| *previous > 0)
    {
        return Err(StoreError::Invalid(
            "Vault key generations must form a consecutive chain starting at 1".to_string(),
        ));
    }
    if genesis_signing_key.verifying_key()
        != verifying_key("genesis public key", &vault.genesis_public_key)?
    {
        return Err(StoreError::Invalid(
            "key generation signer is not the genesis Device".to_string(),
        ));
    }
    let encoded_identity = vault_identity.to_string();
    let envelopes = recipients
        .iter()
        .map(|(device_id, recipient)| {
            require_uuid("envelope Device id", device_id)?;
            Ok((
                device_id.clone(),
                encode(&encrypt_to_recipient(
                    recipient,
                    encoded_identity.expose_secret().as_bytes(),
                )?),
            ))
        })
        .collect::<StoreResult<BTreeMap<_, _>>>()?;
    let unsigned = KeyGenerationUnsigned {
        format_version: VAULT_FORMAT_VERSION,
        vault_id: vault.vault_id.clone(),
        generation,
        previous_generation,
        authorized_by: vault.genesis_device_id.clone(),
        envelopes,
        revoked_devices,
        generation_public: vault_identity.to_public().to_string(),
        recovery_public: recovery_public.to_string(),
    };
    let signature = sign_struct(
        KEY_GENERATION_SIGNATURE_CONTEXT,
        &unsigned,
        genesis_signing_key,
    )?;
    let document = KeyGenerationDocument {
        format_version: unsigned.format_version,
        vault_id: unsigned.vault_id,
        generation: unsigned.generation,
        previous_generation: unsigned.previous_generation,
        authorized_by: unsigned.authorized_by,
        envelopes: unsigned.envelopes,
        revoked_devices: unsigned.revoked_devices,
        generation_public: unsigned.generation_public,
        recovery_public: unsigned.recovery_public,
        signature,
    };
    write_new_atomic(
        path,
        &serde_json::to_vec_pretty(&document)
            .map_err(|error| StoreError::Invalid(error.to_string()))?,
    )
}

/// All signed key-generation documents, validated as a gapless chain starting at 1.
pub fn load_key_generations(
    layout: &SharedLayout,
    vault: &VaultDocument,
) -> StoreResult<BTreeMap<u32, KeyGenerationDocument>> {
    let generations_root = layout.generations_dir();
    let mut by_generation: BTreeMap<u32, (Vec<u8>, KeyGenerationDocument)> = BTreeMap::new();
    for path in regular_files_recursively(&generations_root)? {
        let bytes = read_untrusted_file(&path, MAX_DESCRIPTOR_BYTES)?;
        let document: KeyGenerationDocument = serde_json::from_slice(&bytes)
            .map_err(|error| StoreError::Invalid(format!("key generation: {error}")))?;
        validate_key_generation(&document, vault)?;
        match by_generation.get(&document.generation) {
            Some((existing, _)) if existing != &bytes => {
                return Err(StoreError::Invalid(format!(
                    "Vault key generation {} has multiple signed documents",
                    document.generation
                )));
            }
            Some(_) => {}
            None => {
                by_generation.insert(document.generation, (bytes, document));
            }
        }
    }
    if by_generation.is_empty() {
        return Err(StoreError::Invalid(
            "Vault has no signed key generation".to_string(),
        ));
    }
    let mut expected = 1;
    for (generation, (_, document)) in &by_generation {
        if *generation != expected
            || document.previous_generation
                != generation.checked_sub(1).filter(|previous| *previous > 0)
        {
            return Err(StoreError::Invalid(format!(
                "Vault key generation history has a gap before {generation}"
            )));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| StoreError::Invalid("Vault key generation overflow".to_string()))?;
    }
    Ok(by_generation
        .into_iter()
        .map(|(generation, (_, document))| (generation, document))
        .collect())
}

pub fn read_untrusted_file(path: &Path, maximum: u64) -> StoreResult<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| StoreError::io(path, source))?;
    let metadata = file.metadata().map_err(|source| StoreError::io(path, source))?;
    if !metadata.is_file() {
        return Err(StoreError::Invalid(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(StoreError::Invalid(format!(
            "{} exceeds the {} byte format limit",
            path.display(),
            maximum
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|source| StoreError::io(path, source))?;
    Ok(bytes)
}

/// Publish an immutable file: identical existing bytes are accepted, different bytes never
/// overwritten.
pub fn publish_immutable(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    match read_untrusted_file(path, bytes.len() as u64) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {
            return Err(StoreError::Invalid(format!(
                "immutable path {} already contains different bytes",
                path.display()
            )));
        }
        Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    write_new_atomic(path, bytes)
}

pub fn write_new_atomic(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    let parent = path.parent().ok_or_else(|| {
        StoreError::Invalid(format!("{} has no parent directory", path.display()))
    })?;
    let temporary = parent.join(format!(".floria-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|source| StoreError::io(&temporary, source))?;
    file.write_all(bytes).map_err(|source| StoreError::io(&temporary, source))?;
    file.sync_all().map_err(|source| StoreError::io(&temporary, source))?;
    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            fs::remove_file(&temporary)
                .map_err(|source| StoreError::io(&temporary, source))?;
        }
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            return publish_immutable(path, bytes);
        }
        Err(source) => {
            let _ = fs::remove_file(&temporary);
            return Err(StoreError::io(path, source));
        }
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| StoreError::io(parent, source))
}

pub fn write_replace_atomic(path: &Path, bytes: &[u8]) -> StoreResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| StoreError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StoreError::Invalid(format!(
            "replacement path {} is not a regular file",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        StoreError::Invalid(format!("{} has no parent directory", path.display()))
    })?;
    let temporary = parent.join(format!(".floria-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|source| StoreError::io(&temporary, source))?;
        file.write_all(bytes).map_err(|source| StoreError::io(&temporary, source))?;
        file.sync_all().map_err(|source| StoreError::io(&temporary, source))?;
        fs::rename(&temporary, path).map_err(|source| StoreError::io(path, source))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| StoreError::io(parent, source))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn create_private_directory(path: &Path) -> StoreResult<()> {
    fs::DirBuilder::new()
        .recursive(false)
        .mode(0o700)
        .create(path)
        .map_err(|source| StoreError::io(path, source))
}

pub fn ensure_private_directory(path: &Path) -> StoreResult<()> {
    match fs::DirBuilder::new().recursive(true).mode(0o700).create(path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(StoreError::io(path, source)),
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| StoreError::io(path, source))?;
    if !metadata.is_dir() {
        return Err(StoreError::Invalid(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    Ok(())
}

pub fn regular_files_recursively(root: &Path) -> StoreResult<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(StoreError::io(&directory, source)),
        };
        for entry in entries {
            let entry = entry.map_err(|source| StoreError::io(&directory, source))?;
            let path = entry.path();
            let file_type =
                entry.file_type().map_err(|source| StoreError::io(&path, source))?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }
    Ok(files)
}

/// Permission check used by loaders of private files.
pub fn require_private_file(path: &Path) -> StoreResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| StoreError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StoreError::Invalid(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StoreError::Invalid(format!(
            "{} must not be accessible by group or others",
            path.display()
        )));
    }
    Ok(())
}
