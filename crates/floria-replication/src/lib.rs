//! Untrusted-directory format for Floria replication packages.
//!
//! [`ReplicationPackage`] is the storage-format module underneath the future
//! `ReplicationEngine`. It owns canonical signing bytes, age encryption, immutable publication,
//! digest validation, conflict-copy normalization, and hostile-directory parsing. Catalog
//! outboxes, device enrollment, sequence self-fencing, and Local Projection application remain
//! above this interface.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use age::x25519;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};
use thiserror::Error;
use zeroize::Zeroizing;

const FORMAT_VERSION: u32 = 1;
const VAULT_SIGNATURE_CONTEXT: &[u8] = b"floria-vault-v1\0";
const DEVICE_SIGNATURE_CONTEXT: &[u8] = b"floria-device-v1\0";
const OPERATION_SIGNATURE_CONTEXT: &[u8] = b"floria-operation-v1\0";
const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_OPERATION_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ReplicationError {
    #[error("replication I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid replication package: {0}")]
    Invalid(String),
    #[error("replication encoding failed: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("replication encryption failed: {0}")]
    Encryption(String),
    #[error("replication signature failed: {0}")]
    Signature(String),
}

pub type ReplicationResult<T> = Result<T, ReplicationError>;

/// Device-local material. The signing seed and Vault identity never enter the Replication
/// Directory; stage 3 will replace this value constructor with Keychain/enrollment adapters.
pub struct DeviceKeyMaterial {
    device_id: String,
    signing_key: SigningKey,
    vault_identity: Arc<x25519::Identity>,
}

impl DeviceKeyMaterial {
    pub fn new(
        device_id: impl Into<String>,
        signing_seed: [u8; 32],
        vault_identity: x25519::Identity,
    ) -> ReplicationResult<Self> {
        let device_id = device_id.into();
        require_uuid("device id", &device_id)?;
        Ok(Self {
            device_id,
            signing_key: SigningKey::from_bytes(&signing_seed),
            vault_identity: Arc::new(vault_identity),
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn vault_recipient(&self) -> x25519::Recipient {
        self.vault_identity.to_public()
    }
}

/// One already-sequenced local mutation. `operation_id` and `sequence` are supplied by the
/// durable outbox layer so a crash can persist and retry exactly one signed envelope.
pub struct PackageMutation<'a> {
    pub sequence: u64,
    pub operation_id: &'a str,
    pub logical_id: &'a str,
    pub parents: &'a [String],
    pub value: &'a [u8],
}

/// Fully encrypted, signed bytes. Persist this value locally before calling `publish`; retrying a
/// crash must reuse these exact bytes instead of encrypting or signing the slot again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPublication {
    pub sequence: u64,
    pub operation_id: String,
    pub object_id: String,
    object: Vec<u8>,
    operation: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMutation {
    pub device_id: String,
    pub sequence: u64,
    pub operation_id: String,
    pub logical_id: String,
    pub parents: Vec<String>,
    pub object_id: String,
    pub value: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOperation {
    pub device_id: String,
    pub sequence: u64,
    pub operation_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DamagedFile {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackageScan {
    pub verified: Vec<VerifiedMutation>,
    pub pending: Vec<PendingOperation>,
    pub damaged: Vec<DamagedFile>,
    pub duplicate_files: usize,
}

#[derive(Serialize, Deserialize)]
struct VaultUnsigned {
    format_version: u32,
    vault_id: String,
    genesis_device_id: String,
    genesis_public_key: String,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
struct VaultDocument {
    format_version: u32,
    vault_id: String,
    genesis_device_id: String,
    genesis_public_key: String,
    created_at: String,
    signature: String,
}

impl VaultDocument {
    fn unsigned(&self) -> VaultUnsigned {
        VaultUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            genesis_device_id: self.genesis_device_id.clone(),
            genesis_public_key: self.genesis_public_key.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct DeviceUnsigned {
    format_version: u32,
    vault_id: String,
    device_id: String,
    signing_public_key: String,
}

#[derive(Serialize, Deserialize)]
struct DeviceDocument {
    format_version: u32,
    vault_id: String,
    device_id: String,
    signing_public_key: String,
    signature: String,
}

impl DeviceDocument {
    fn unsigned(&self) -> DeviceUnsigned {
        DeviceUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
            signing_public_key: self.signing_public_key.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct OperationUnsigned {
    format_version: u32,
    vault_id: String,
    device_id: String,
    sequence: u64,
    operation_id: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct OperationDocument {
    format_version: u32,
    vault_id: String,
    device_id: String,
    sequence: u64,
    operation_id: String,
    ciphertext: String,
    signature: String,
}

impl OperationDocument {
    fn unsigned(&self) -> OperationUnsigned {
        OperationUnsigned {
            format_version: self.format_version,
            vault_id: self.vault_id.clone(),
            device_id: self.device_id.clone(),
            sequence: self.sequence,
            operation_id: self.operation_id.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct OperationPayload {
    format_version: u32,
    logical_id: String,
    parents: Vec<String>,
    object: ObjectReference,
}

#[derive(Serialize, Deserialize)]
struct ObjectReference {
    id: String,
    ciphertext_size: u64,
}

/// Immutable package-format module. It deliberately has no transport adapter: a normal directory
/// is the only production representation in v1.
pub struct ReplicationPackage {
    root: PathBuf,
    vault: VaultDocument,
    device: DeviceKeyMaterial,
}

impl ReplicationPackage {
    pub fn create(
        root: impl Into<PathBuf>,
        vault_id: impl Into<String>,
        created_at: impl Into<String>,
        device: DeviceKeyMaterial,
    ) -> ReplicationResult<Self> {
        let root = root.into();
        let vault_id = vault_id.into();
        require_uuid("vault id", &vault_id)?;
        if path_exists(&root)? {
            return Err(ReplicationError::Invalid(format!(
                "replication package already exists at {}",
                root.display()
            )));
        }
        let parent = root.parent().ok_or_else(|| {
            ReplicationError::Invalid(format!("{} has no parent directory", root.display()))
        })?;
        let temporary = parent.join(format!(".floria-vault-{}.tmp", uuid::Uuid::new_v4()));
        create_private_directory(&temporary)?;

        let result = (|| {
            create_private_directory(&temporary.join("devices"))?;
            create_private_directory(&temporary.join("operations"))?;
            create_private_directory(&temporary.join("objects"))?;
            create_private_directory(&temporary.join("checkpoints"))?;

            let unsigned = VaultUnsigned {
                format_version: FORMAT_VERSION,
                vault_id: vault_id.clone(),
                genesis_device_id: device.device_id.clone(),
                genesis_public_key: encode(device.verifying_key().as_bytes()),
                created_at: created_at.into(),
            };
            let signature = sign_struct(VAULT_SIGNATURE_CONTEXT, &unsigned, &device.signing_key)?;
            let vault = VaultDocument {
                format_version: unsigned.format_version,
                vault_id: unsigned.vault_id,
                genesis_device_id: unsigned.genesis_device_id,
                genesis_public_key: unsigned.genesis_public_key,
                created_at: unsigned.created_at,
                signature,
            };
            write_new_atomic(
                &temporary.join("vault.json"),
                &serde_json::to_vec_pretty(&vault)?,
            )?;

            let device_directory = temporary.join("devices").join(&device.device_id);
            create_private_directory(&device_directory)?;
            create_private_directory(&device_directory.join("envelopes"))?;
            create_private_directory(&temporary.join("operations").join(&device.device_id))?;
            create_private_directory(&temporary.join("checkpoints").join(&device.device_id))?;
            write_genesis_device(&device_directory.join("identity.json"), &vault, &device)?;
            sync_directory(&temporary)?;
            rename_directory_exclusive(&temporary, &root)?;
            sync_directory(parent)?;
            Ok(vault)
        })();
        let vault = match result {
            Ok(vault) => vault,
            Err(error) => {
                let _ = fs::remove_dir_all(&temporary);
                return Err(error);
            }
        };

        Ok(Self { root, vault, device })
    }

    pub fn open(
        root: impl Into<PathBuf>,
        device: DeviceKeyMaterial,
    ) -> ReplicationResult<Self> {
        let root = root.into();
        let bytes = read_untrusted_file(&root.join("vault.json"), MAX_DESCRIPTOR_BYTES)?;
        let vault: VaultDocument = serde_json::from_slice(&bytes)?;
        validate_vault(&vault)?;
        if vault.genesis_device_id != device.device_id {
            return Err(ReplicationError::Invalid(format!(
                "device {} is not enrolled in this stage-2 package",
                device.device_id
            )));
        }
        if vault.genesis_public_key != encode(device.verifying_key().as_bytes()) {
            return Err(ReplicationError::Invalid(
                "device signing key does not match the package identity".to_string(),
            ));
        }
        let identity_path = root.join("devices").join(&device.device_id).join("identity.json");
        let identity: DeviceDocument = serde_json::from_slice(&read_untrusted_file(
            &identity_path,
            MAX_DESCRIPTOR_BYTES,
        )?)?;
        validate_device(&identity, &vault)?;
        Ok(Self { root, vault, device })
    }

    pub fn vault_id(&self) -> &str {
        &self.vault.vault_id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn prepare(&self, mutation: PackageMutation<'_>) -> ReplicationResult<PreparedPublication> {
        if mutation.sequence == 0 {
            return Err(ReplicationError::Invalid(
                "operation sequence starts at 1".to_string(),
            ));
        }
        require_uuid("operation id", mutation.operation_id)?;
        if mutation.logical_id.is_empty() {
            return Err(ReplicationError::Invalid("logical id is empty".to_string()));
        }
        let object = encrypt(&self.device.vault_recipient(), mutation.value)?;
        let object_id = digest(&object);
        let payload = OperationPayload {
            format_version: FORMAT_VERSION,
            logical_id: mutation.logical_id.to_string(),
            parents: mutation.parents.to_vec(),
            object: ObjectReference {
                id: object_id.clone(),
                ciphertext_size: object.len() as u64,
            },
        };
        let ciphertext = encrypt(&self.device.vault_recipient(), &serde_json::to_vec(&payload)?)?;
        let unsigned = OperationUnsigned {
            format_version: FORMAT_VERSION,
            vault_id: self.vault.vault_id.clone(),
            device_id: self.device.device_id.clone(),
            sequence: mutation.sequence,
            operation_id: mutation.operation_id.to_string(),
            ciphertext: encode(&ciphertext),
        };
        let signature = sign_struct(
            OPERATION_SIGNATURE_CONTEXT,
            &unsigned,
            &self.device.signing_key,
        )?;
        let operation = serde_json::to_vec(&OperationDocument {
            format_version: unsigned.format_version,
            vault_id: unsigned.vault_id,
            device_id: unsigned.device_id,
            sequence: unsigned.sequence,
            operation_id: unsigned.operation_id.clone(),
            ciphertext: unsigned.ciphertext,
            signature,
        })?;
        Ok(PreparedPublication {
            sequence: mutation.sequence,
            operation_id: unsigned.operation_id,
            object_id,
            object,
            operation,
        })
    }

    /// Publish the Object before the Operation. Existing identical immutable bytes are accepted;
    /// a colliding canonical path with different bytes is never overwritten.
    pub fn publish(&self, prepared: &PreparedPublication) -> ReplicationResult<()> {
        self.verify_prepared(prepared)?;
        publish_immutable(
            &self.root.join("objects").join(format!("{}.age", prepared.object_id)),
            &prepared.object,
        )?;
        publish_immutable(&self.operation_path(prepared), &prepared.operation)?;
        Ok(())
    }

    pub fn scan(&self) -> ReplicationResult<PackageScan> {
        let mut report = PackageScan::default();
        let objects = scan_objects(&self.root.join("objects"), &mut report)?;
        let operations_root = self.root.join("operations");
        let mut slots: BTreeMap<(String, u64), (PathBuf, Vec<u8>, OperationDocument)> =
            BTreeMap::new();
        let mut operation_ids: HashMap<String, Vec<u8>> = HashMap::new();
        let mut equivocated = HashSet::new();

        for path in regular_files_recursively(&operations_root)? {
            let bytes = match read_untrusted_file(&path, MAX_OPERATION_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    report.damaged.push(DamagedFile { path, reason: error.to_string() });
                    continue;
                }
            };
            let operation: OperationDocument = match serde_json::from_slice(&bytes) {
                Ok(operation) => operation,
                Err(error) => {
                    report.damaged.push(DamagedFile {
                        path,
                        reason: format!("operation JSON is invalid: {error}"),
                    });
                    continue;
                }
            };
            if let Err(error) = self.validate_operation(&operation) {
                report.damaged.push(DamagedFile { path, reason: error.to_string() });
                continue;
            }
            if let Some(existing) = operation_ids.get(&operation.operation_id) {
                if existing == &bytes {
                    report.duplicate_files += 1;
                    continue;
                }
                report.damaged.push(DamagedFile {
                    path,
                    reason: format!(
                        "operation id {} has multiple valid envelopes",
                        operation.operation_id
                    ),
                });
                continue;
            }
            operation_ids.insert(operation.operation_id.clone(), bytes.clone());
            let slot = (operation.device_id.clone(), operation.sequence);
            if equivocated.contains(&slot) {
                report.damaged.push(DamagedFile {
                    path,
                    reason: format!(
                        "device {} equivocated at sequence {}",
                        operation.device_id, operation.sequence
                    ),
                });
                continue;
            }
            if let Some((existing_path, existing_bytes, _)) = slots.get(&slot) {
                if existing_bytes == &bytes {
                    report.duplicate_files += 1;
                } else {
                    report.damaged.push(DamagedFile {
                        path: existing_path.clone(),
                        reason: format!(
                            "device {} equivocated at sequence {}",
                            operation.device_id, operation.sequence
                        ),
                    });
                    report.damaged.push(DamagedFile {
                        path,
                        reason: format!(
                            "device {} equivocated at sequence {}",
                            operation.device_id, operation.sequence
                        ),
                    });
                    slots.remove(&slot);
                    equivocated.insert(slot);
                }
                continue;
            }
            slots.insert(slot, (path, bytes, operation));
        }

        let mut expected_sequences: HashMap<String, u64> = HashMap::new();
        for ((device_id, sequence), (path, _, operation)) in slots {
            let expected = expected_sequences.entry(device_id.clone()).or_insert(1);
            if sequence != *expected {
                report.pending.push(PendingOperation {
                    device_id,
                    sequence,
                    operation_id: operation.operation_id,
                    reason: format!("sequence {} has not arrived", *expected),
                });
                continue;
            }
            if self.materialize_verified(path, operation, &objects, &mut report)? {
                *expected += 1;
            }
        }
        report.verified.sort_by(|left, right| {
            left.device_id
                .cmp(&right.device_id)
                .then(left.sequence.cmp(&right.sequence))
        });
        Ok(report)
    }

    fn operation_path(&self, prepared: &PreparedPublication) -> PathBuf {
        self.root
            .join("operations")
            .join(&self.device.device_id)
            .join(format!(
                "{:020}-{}.op",
                prepared.sequence, prepared.operation_id
            ))
    }

    fn verify_prepared(&self, prepared: &PreparedPublication) -> ReplicationResult<()> {
        if digest(&prepared.object) != prepared.object_id {
            return Err(ReplicationError::Invalid(
                "prepared object digest does not match its id".to_string(),
            ));
        }
        let operation: OperationDocument = serde_json::from_slice(&prepared.operation)?;
        self.validate_operation(&operation)?;
        if operation.sequence != prepared.sequence
            || operation.operation_id != prepared.operation_id
        {
            return Err(ReplicationError::Invalid(
                "prepared publication metadata does not match its signed operation".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_operation(&self, operation: &OperationDocument) -> ReplicationResult<()> {
        if operation.format_version != FORMAT_VERSION {
            return Err(ReplicationError::Invalid(format!(
                "unsupported operation format {}",
                operation.format_version
            )));
        }
        if operation.vault_id != self.vault.vault_id {
            return Err(ReplicationError::Invalid(
                "operation belongs to a different Vault".to_string(),
            ));
        }
        if operation.device_id != self.vault.genesis_device_id {
            return Err(ReplicationError::Invalid(format!(
                "operation device {} is not enrolled",
                operation.device_id
            )));
        }
        require_uuid("operation id", &operation.operation_id)?;
        if operation.sequence == 0 {
            return Err(ReplicationError::Invalid(
                "operation sequence starts at 1".to_string(),
            ));
        }
        verify_struct(
            OPERATION_SIGNATURE_CONTEXT,
            &operation.unsigned(),
            &operation.signature,
            &self.device.verifying_key(),
        )
    }

    fn materialize_verified(
        &self,
        operation_path: PathBuf,
        operation: OperationDocument,
        objects: &HashMap<String, Vec<u8>>,
        report: &mut PackageScan,
    ) -> ReplicationResult<bool> {
        let ciphertext = decode("operation ciphertext", &operation.ciphertext)?;
        let plaintext = match decrypt(self.device.vault_identity.as_ref(), &ciphertext) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                report.damaged.push(DamagedFile {
                    path: operation_path,
                    reason: error.to_string(),
                });
                return Ok(false);
            }
        };
        let payload: OperationPayload = match serde_json::from_slice(&plaintext) {
            Ok(payload) => payload,
            Err(error) => {
                report.damaged.push(DamagedFile {
                    path: operation_path,
                    reason: format!("operation payload is invalid: {error}"),
                });
                return Ok(false);
            }
        };
        if payload.format_version != FORMAT_VERSION {
            report.damaged.push(DamagedFile {
                path: operation_path,
                reason: format!(
                    "unsupported operation payload format {}",
                    payload.format_version
                ),
            });
            return Ok(false);
        }
        let Some(object) = objects.get(&payload.object.id) else {
            report.pending.push(PendingOperation {
                device_id: operation.device_id,
                sequence: operation.sequence,
                operation_id: operation.operation_id,
                reason: format!("object {} has not arrived", payload.object.id),
            });
            return Ok(false);
        };
        if object.len() as u64 != payload.object.ciphertext_size {
            report.damaged.push(DamagedFile {
                path: self
                    .root
                    .join("objects")
                    .join(format!("{}.age", payload.object.id)),
                reason: format!("object {} has the wrong size", payload.object.id),
            });
            return Ok(false);
        }
        let value = match decrypt(self.device.vault_identity.as_ref(), object) {
            Ok(value) => value,
            Err(error) => {
                report.damaged.push(DamagedFile {
                    path: self
                        .root
                        .join("objects")
                        .join(format!("{}.age", payload.object.id)),
                    reason: error.to_string(),
                });
                return Ok(false);
            }
        };
        report.verified.push(VerifiedMutation {
            device_id: operation.device_id,
            sequence: operation.sequence,
            operation_id: operation.operation_id,
            logical_id: payload.logical_id,
            parents: payload.parents,
            object_id: payload.object.id,
            value,
        });
        Ok(true)
    }
}

fn write_genesis_device(
    path: &Path,
    vault: &VaultDocument,
    device: &DeviceKeyMaterial,
) -> ReplicationResult<()> {
    let unsigned = DeviceUnsigned {
        format_version: FORMAT_VERSION,
        vault_id: vault.vault_id.clone(),
        device_id: device.device_id.clone(),
        signing_public_key: encode(device.verifying_key().as_bytes()),
    };
    let signature = sign_struct(DEVICE_SIGNATURE_CONTEXT, &unsigned, &device.signing_key)?;
    let document = DeviceDocument {
        format_version: unsigned.format_version,
        vault_id: unsigned.vault_id,
        device_id: unsigned.device_id,
        signing_public_key: unsigned.signing_public_key,
        signature,
    };
    write_new_atomic(path, &serde_json::to_vec_pretty(&document)?)
}

fn validate_vault(vault: &VaultDocument) -> ReplicationResult<()> {
    if vault.format_version != FORMAT_VERSION {
        return Err(ReplicationError::Invalid(format!(
            "unsupported Vault format {}",
            vault.format_version
        )));
    }
    require_uuid("vault id", &vault.vault_id)?;
    require_uuid("genesis device id", &vault.genesis_device_id)?;
    let key = verifying_key("genesis public key", &vault.genesis_public_key)?;
    verify_struct(VAULT_SIGNATURE_CONTEXT, &vault.unsigned(), &vault.signature, &key)
}

fn validate_device(identity: &DeviceDocument, vault: &VaultDocument) -> ReplicationResult<()> {
    if identity.format_version != FORMAT_VERSION
        || identity.vault_id != vault.vault_id
        || identity.device_id != vault.genesis_device_id
        || identity.signing_public_key != vault.genesis_public_key
    {
        return Err(ReplicationError::Invalid(
            "genesis Device identity does not match vault.json".to_string(),
        ));
    }
    let key = verifying_key("Device public key", &identity.signing_public_key)?;
    verify_struct(
        DEVICE_SIGNATURE_CONTEXT,
        &identity.unsigned(),
        &identity.signature,
        &key,
    )
}

fn sign_struct<T: Serialize>(
    context: &[u8],
    value: &T,
    key: &SigningKey,
) -> ReplicationResult<String> {
    let message = signing_bytes(context, value)?;
    Ok(encode(&key.sign(&message).to_bytes()))
}

fn verify_struct<T: Serialize>(
    context: &[u8],
    value: &T,
    encoded_signature: &str,
    key: &VerifyingKey,
) -> ReplicationResult<()> {
    let bytes = decode("signature", encoded_signature)?;
    let bytes: [u8; 64] = bytes.try_into().map_err(|_| {
        ReplicationError::Signature("Ed25519 signature must be 64 bytes".to_string())
    })?;
    key.verify(&signing_bytes(context, value)?, &Signature::from_bytes(&bytes))
        .map_err(|error| ReplicationError::Signature(error.to_string()))
}

fn signing_bytes<T: Serialize>(context: &[u8], value: &T) -> ReplicationResult<Vec<u8>> {
    let encoded = serde_json::to_vec(value)?;
    let mut message = Vec::with_capacity(context.len() + encoded.len());
    message.extend_from_slice(context);
    message.extend_from_slice(&encoded);
    Ok(message)
}

fn verifying_key(label: &str, encoded: &str) -> ReplicationResult<VerifyingKey> {
    let bytes = decode(label, encoded)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        ReplicationError::Invalid(format!("{label} must be 32 bytes"))
    })?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| ReplicationError::Invalid(format!("invalid {label}: {error}")))
}

fn encrypt(recipient: &x25519::Recipient, plaintext: &[u8]) -> ReplicationResult<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .ok_or_else(|| ReplicationError::Encryption("Vault has no recipient".to_string()))?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    writer
        .finish()
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    Ok(ciphertext)
}

fn decrypt(identity: &x25519::Identity, ciphertext: &[u8]) -> ReplicationResult<Zeroizing<Vec<u8>>> {
    let decryptor = match age::Decryptor::new(ciphertext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?
    {
        age::Decryptor::Recipients(decryptor) => decryptor,
        age::Decryptor::Passphrase(_) => {
            return Err(ReplicationError::Encryption(
                "passphrase-encrypted data is not a Vault object".to_string(),
            ));
        }
    };
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut plaintext)
        .map_err(|error| ReplicationError::Encryption(error.to_string()))?;
    Ok(plaintext)
}

fn scan_objects(
    root: &Path,
    report: &mut PackageScan,
) -> ReplicationResult<HashMap<String, Vec<u8>>> {
    let mut objects = HashMap::new();
    for path in regular_files_recursively(root)? {
        let bytes = match read_untrusted_file(&path, MAX_OBJECT_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                report.damaged.push(DamagedFile { path, reason: error.to_string() });
                continue;
            }
        };
        let id = digest(&bytes);
        if let Some(claimed) = canonical_object_id(&path) {
            if claimed != id {
                report.damaged.push(DamagedFile {
                    path,
                    reason: format!(
                        "canonical object name claims digest {claimed}, actual digest is {id}"
                    ),
                });
                continue;
            }
        }
        if objects.insert(id.clone(), bytes.clone()).is_some() {
            report.duplicate_files += 1;
        }
        let canonical = root.join(format!("{id}.age"));
        if path != canonical && !canonical.exists() {
            if let Err(error) = publish_immutable(&canonical, &bytes) {
                report.damaged.push(DamagedFile {
                    path: path.clone(),
                    reason: format!("cannot normalize object conflict copy: {error}"),
                });
            }
        }
    }
    Ok(objects)
}

fn regular_files_recursively(root: &Path) -> ReplicationResult<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| io_error(&directory, source))?;
        for entry in entries {
            let entry = entry.map_err(|source| io_error(&directory, source))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|source| io_error(&path, source))?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn read_untrusted_file(path: &Path, maximum: u64) -> ReplicationResult<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.is_file() {
        return Err(ReplicationError::Invalid(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(ReplicationError::Invalid(format!(
            "{} exceeds the {} byte format limit",
            path.display(), maximum
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|source| io_error(path, source))?;
    Ok(bytes)
}

fn publish_immutable(path: &Path, bytes: &[u8]) -> ReplicationResult<()> {
    match read_untrusted_file(path, bytes.len() as u64) {
        Ok(existing) if existing == bytes => return Ok(()),
        Ok(_) => {
            return Err(ReplicationError::Invalid(format!(
                "immutable path {} already contains different bytes",
                path.display()
            )));
        }
        Err(ReplicationError::Io { source, .. })
            if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    write_new_atomic(path, bytes)
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> ReplicationResult<()> {
    let parent = path.parent().ok_or_else(|| {
        ReplicationError::Invalid(format!("{} has no parent directory", path.display()))
    })?;
    let temporary = parent.join(format!(".floria-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|source| io_error(&temporary, source))?;
    file.write_all(bytes).map_err(|source| io_error(&temporary, source))?;
    file.sync_all().map_err(|source| io_error(&temporary, source))?;
    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            fs::remove_file(&temporary).map_err(|source| io_error(&temporary, source))?;
        }
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            return publish_immutable(path, bytes);
        }
        Err(source) => {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(path, source));
        }
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(parent, source))
}

fn canonical_object_id(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let id = name.strip_suffix(".age")?;
    (id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| id.to_ascii_lowercase())
}

fn create_private_directory(path: &Path) -> ReplicationResult<()> {
    fs::DirBuilder::new()
        .recursive(false)
        .mode(0o700)
        .create(path)
        .map_err(|source| io_error(path, source))
}

fn path_exists(path: &Path) -> ReplicationResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn sync_directory(path: &Path) -> ReplicationResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

#[cfg(target_os = "macos")]
fn rename_directory_exclusive(source: &Path, target: &Path) -> ReplicationResult<()> {
    let source_bytes = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        ReplicationError::Invalid(format!("{} contains a NUL byte", source.display()))
    })?;
    let target_bytes = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
        ReplicationError::Invalid(format!("{} contains a NUL byte", target.display()))
    })?;
    // SAFETY: both pointers are valid NUL-terminated paths for the duration of the call.
    let result = unsafe {
        libc::renamex_np(
            source_bytes.as_ptr(),
            target_bytes.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io_error(target, io::Error::last_os_error()))
    }
}

#[cfg(not(target_os = "macos"))]
fn rename_directory_exclusive(source: &Path, target: &Path) -> ReplicationResult<()> {
    if path_exists(target)? {
        return Err(ReplicationError::Invalid(format!(
            "replication package already exists at {}",
            target.display()
        )));
    }
    fs::rename(source, target).map_err(|error| io_error(target, error))
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode(label: &str, value: &str) -> ReplicationResult<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| ReplicationError::Invalid(format!("{label} is not Base64: {error}")))
}

fn require_uuid(label: &str, value: &str) -> ReplicationResult<()> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ReplicationError::Invalid(format!("{label} is not a UUID: {value:?}")))
}

fn io_error(path: &Path, source: io::Error) -> ReplicationError {
    ReplicationError::Io { path: path.to_path_buf(), source }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_ID: &str = "22222222-2222-4222-8222-222222222222";
    const OPERATION_ID: &str = "33333333-3333-4333-8333-333333333333";

    fn keys(seed: u8, vault_identity: x25519::Identity) -> DeviceKeyMaterial {
        DeviceKeyMaterial::new(DEVICE_ID, [seed; 32], vault_identity).unwrap()
    }

    fn package() -> (tempfile::TempDir, ReplicationPackage) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        let package = ReplicationPackage::create(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, x25519::Identity::generate()),
        )
        .unwrap();
        (directory, package)
    }

    #[test]
    fn create_open_and_single_device_round_trip() {
        let (directory, package) = package();
        let identity = (*package.device.vault_identity).clone();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload, not a credential",
            })
            .unwrap();
        package.publish(&prepared).unwrap();

        let reopened = ReplicationPackage::open(
            directory.path().join("Personal.floriavault"),
            keys(7, identity),
        )
        .unwrap();
        let scan = reopened.scan().unwrap();

        assert!(scan.pending.is_empty());
        assert!(scan.damaged.is_empty());
        assert_eq!(scan.verified.len(), 1);
        assert_eq!(scan.verified[0].logical_id, "managed-item-1");
        assert_eq!(&*scan.verified[0].value, b"fixture payload, not a credential");
    }

    #[test]
    fn operation_waits_when_object_has_not_arrived() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
            })
            .unwrap();
        publish_immutable(&package.operation_path(&prepared), &prepared.operation).unwrap();

        let pending = package.scan().unwrap();
        assert_eq!(pending.pending.len(), 1);
        assert!(pending.pending[0].reason.contains("has not arrived"));

        publish_immutable(
            &package.root.join("objects").join(format!("{}.age", prepared.object_id)),
            &prepared.object,
        )
        .unwrap();
        let complete = package.scan().unwrap();
        assert_eq!(complete.verified.len(), 1);
        assert!(complete.pending.is_empty());
    }

    #[test]
    fn object_conflict_copy_is_validated_and_normalized_by_digest() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
            })
            .unwrap();
        let conflict_copy = package.root.join("objects/object (conflicted copy).age");
        fs::write(&conflict_copy, &prepared.object).unwrap();
        publish_immutable(&package.operation_path(&prepared), &prepared.operation).unwrap();

        let scan = package.scan().unwrap();
        assert_eq!(scan.verified.len(), 1);
        assert!(package
            .root
            .join("objects")
            .join(format!("{}.age", prepared.object_id))
            .is_file());
    }

    #[test]
    fn tampered_operation_is_rejected_before_decryption() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
            })
            .unwrap();
        package.publish(&prepared).unwrap();
        let path = package.operation_path(&prepared);
        let mut operation: OperationDocument =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        operation.sequence = 2;
        fs::write(&path, serde_json::to_vec(&operation).unwrap()).unwrap();

        let scan = package.scan().unwrap();
        assert!(scan.verified.is_empty());
        assert_eq!(scan.damaged.len(), 1);
        assert!(scan.damaged[0].reason.contains("signature"));
    }

    #[test]
    fn sequence_gap_keeps_later_operation_pending() {
        let (_directory, package) = package();
        let prepared = package
            .prepare(PackageMutation {
                sequence: 2,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"fixture payload",
            })
            .unwrap();
        package.publish(&prepared).unwrap();

        let scan = package.scan().unwrap();
        assert!(scan.verified.is_empty());
        assert_eq!(scan.pending.len(), 1);
        assert_eq!(scan.pending[0].reason, "sequence 1 has not arrived");
    }

    #[test]
    fn two_valid_envelopes_for_one_device_slot_are_equivocation() {
        let (_directory, package) = package();
        let first = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: OPERATION_ID,
                logical_id: "managed-item-1",
                parents: &[],
                value: b"first fixture payload",
            })
            .unwrap();
        let second = package
            .prepare(PackageMutation {
                sequence: 1,
                operation_id: "44444444-4444-4444-8444-444444444444",
                logical_id: "managed-item-1",
                parents: &[],
                value: b"second fixture payload",
            })
            .unwrap();
        package.publish(&first).unwrap();
        package.publish(&second).unwrap();

        let scan = package.scan().unwrap();
        assert!(scan.verified.is_empty());
        assert_eq!(scan.damaged.len(), 2);
        assert!(scan
            .damaged
            .iter()
            .all(|damaged| damaged.reason.contains("equivocated")));
    }

    #[test]
    fn immutable_publication_never_overwrites_existing_bytes() {
        let (_directory, package) = package();
        let path = package.root.join("objects/collision.age");
        publish_immutable(&path, b"first").unwrap();

        let error = publish_immutable(&path, b"second").unwrap_err();

        assert!(error.to_string().contains("different bytes"));
        assert_eq!(fs::read(path).unwrap(), b"first");
    }

    #[test]
    fn package_creation_never_replaces_an_existing_directory() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Personal.floriavault");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("keep"), b"existing package marker").unwrap();

        let error = ReplicationPackage::create(
            &root,
            VAULT_ID,
            "2026-08-06T00:00:00Z",
            keys(7, x25519::Identity::generate()),
        )
        .err()
        .unwrap();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read(root.join("keep")).unwrap(), b"existing package marker");
    }

    #[test]
    fn canonical_object_name_with_wrong_digest_is_damaged() {
        let (_directory, package) = package();
        let path = package
            .root
            .join("objects")
            .join(format!("{}.age", "0".repeat(64)));
        fs::write(path, b"not an age ciphertext").unwrap();

        let scan = package.scan().unwrap();

        assert_eq!(scan.damaged.len(), 1);
        assert!(scan.damaged[0].reason.contains("actual digest"));
    }

    #[test]
    fn vault_descriptor_has_stable_signing_vector() {
        let unsigned = VaultUnsigned {
            format_version: 1,
            vault_id: VAULT_ID.to_string(),
            genesis_device_id: DEVICE_ID.to_string(),
            genesis_public_key: encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()),
            created_at: "2026-08-06T00:00:00Z".to_string(),
        };
        assert_eq!(
            String::from_utf8(signing_bytes(VAULT_SIGNATURE_CONTEXT, &unsigned).unwrap()).unwrap(),
            "floria-vault-v1\0{\"format_version\":1,\"vault_id\":\"11111111-1111-4111-8111-111111111111\",\"genesis_device_id\":\"22222222-2222-4222-8222-222222222222\",\"genesis_public_key\":\"6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw\",\"created_at\":\"2026-08-06T00:00:00Z\"}"
        );
        assert_eq!(
            sign_struct(VAULT_SIGNATURE_CONTEXT, &unsigned, &SigningKey::from_bytes(&[7; 32]))
                .unwrap(),
            "iGeZuPC-ulM5c5tLijmtXWaKPNQsaQX7djOuLPjM1o0hmI91TNixOcqsMBTnLA9GOIexEoS6-ydW4G5PJsx6BA"
        );
    }
}
