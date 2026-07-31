//! Managed SSH private keys behind a small signing interface.
//!
//! This crate owns private-key parsing, canonicalization, public identity derivation, and raw SSH
//! signature encoding. Catalog, control, and agent callers never depend on a concrete key library.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256, Sha512};
use signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::{Algorithm, Certificate, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

const RUNTIME_SOCKET_HASH_BYTES: usize = 12;

/// Return the short, deterministic Unix socket path used by one managed SSH Agent Surface.
///
/// Keeping this derivation in the SSH domain crate gives the runtime and control plane one source
/// of truth without exposing the runtime's listener implementation.
pub fn agent_runtime_socket_path(
    runtime_dir: &std::path::Path,
    surface_id: &str,
) -> std::path::PathBuf {
    let digest = Sha256::digest(surface_id.as_bytes());
    let name = URL_SAFE_NO_PAD.encode(&digest[..RUNTIME_SOCKET_HASH_BYTES]);
    runtime_dir.join(format!("{name}.sock"))
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedKeyError {
    #[error("invalid SSH private key: {0}")]
    Invalid(String),
    #[error("the private key is encrypted; enter its passphrase")]
    PassphraseRequired,
    #[error("could not decrypt the private key; check its passphrase")]
    DecryptionFailed,
    #[error("SSH key algorithm {0} is not supported yet; import an Ed25519 or RSA key")]
    UnsupportedAlgorithm(String),
    #[error("RSA private keys must be at least 2048 bits")]
    WeakRsaKey,
    #[error("unsupported SSH signing flags {0:#x}")]
    UnsupportedFlags(u32),
    #[error("SSH signing failed")]
    SigningFailed,
    #[error("invalid SSH public-key signature: {0}")]
    InvalidPublicSignature(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    pub key_blob: Vec<u8>,
    pub address: String,
    pub fingerprint: String,
    pub comment: String,
}

pub struct ImportedPrivateKey {
    canonical: Zeroizing<String>,
    pub identity: PublicIdentity,
}

impl ImportedPrivateKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }
}

/// Parse and normalize one private key for encrypted storage. OpenSSH keys may be encrypted;
/// unencrypted PKCS#1/PKCS#8 RSA PEM is accepted for compatibility with EC2 key downloads. The
/// canonical bytes are unencrypted OpenSSH because the Floria store is the at-rest boundary.
pub fn import_private_key(
    encoded: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<ImportedPrivateKey, ManagedKeyError> {
    let private_key = parse_and_decrypt(encoded, passphrase)?;
    require_supported_algorithm(&private_key)?;
    let identity = public_identity(&private_key)?;
    let canonical = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|error| ManagedKeyError::Invalid(error.to_string()))?;
    Ok(ImportedPrivateKey { canonical, identity })
}

/// Recover public identity metadata from canonical private-key bytes held by the encrypted store.
pub fn identity_from_private_key(encoded: &[u8]) -> Result<PublicIdentity, ManagedKeyError> {
    let private_key = PrivateKey::from_openssh(encoded)
        .map_err(|error| ManagedKeyError::Invalid(error.to_string()))?;
    if private_key.is_encrypted() {
        return Err(ManagedKeyError::PassphraseRequired);
    }
    require_supported_algorithm(&private_key)?;
    public_identity(&private_key)
}

/// Sign the exact SSH agent request payload and return the RFC4253 signature blob (algorithm
/// string followed by signature string). The caller wraps it in SSH_AGENT_SIGN_RESPONSE.
pub fn sign(
    encoded: &[u8],
    message: &[u8],
    flags: u32,
) -> Result<Vec<u8>, ManagedKeyError> {
    let private_key = PrivateKey::from_openssh(encoded)
        .map_err(|error| ManagedKeyError::Invalid(error.to_string()))?;
    if private_key.is_encrypted() {
        return Err(ManagedKeyError::PassphraseRequired);
    }
    require_supported_algorithm(&private_key)?;
    let signature = sign_with_algorithm(&private_key, message, flags)?;
    let mut encoded = Vec::new();
    put_string(&mut encoded, signature.algorithm().as_str().as_bytes());
    put_string(&mut encoded, signature.as_bytes());
    Ok(encoded)
}

/// Verify an RFC4253 signature blob against an SSH public-key blob. OpenSSH uses this to prove
/// that a `session-bind@openssh.com` request came from the host that completed the key exchange.
/// Certificate host keys are verified with the public key embedded in the certificate.
pub fn verify_public_signature(
    key_blob: &[u8],
    message: &[u8],
    signature_blob: &[u8],
) -> Result<(), ManagedKeyError> {
    let signature = Signature::try_from(signature_blob)
        .map_err(|error| ManagedKeyError::InvalidPublicSignature(error.to_string()))?;
    let algorithm = ssh_algorithm_name(key_blob)?;
    if algorithm.ends_with("-cert-v01@openssh.com") {
        let certificate = Certificate::from_bytes(key_blob)
            .map_err(|error| ManagedKeyError::InvalidPublicSignature(error.to_string()))?;
        Verifier::verify(certificate.public_key(), message, &signature)
            .map_err(|_| ManagedKeyError::InvalidPublicSignature("verification failed".into()))
    } else {
        let public_key = PublicKey::from_bytes(key_blob)
            .map_err(|error| ManagedKeyError::InvalidPublicSignature(error.to_string()))?;
        Verifier::verify(&public_key, message, &signature)
            .map_err(|_| ManagedKeyError::InvalidPublicSignature("verification failed".into()))
    }
}

fn ssh_algorithm_name(key_blob: &[u8]) -> Result<&str, ManagedKeyError> {
    let length = key_blob
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| ManagedKeyError::InvalidPublicSignature("truncated key blob".into()))?
        as usize;
    let value = key_blob
        .get(4..4 + length)
        .ok_or_else(|| ManagedKeyError::InvalidPublicSignature("truncated key algorithm".into()))?;
    std::str::from_utf8(value)
        .map_err(|_| ManagedKeyError::InvalidPublicSignature("key algorithm is not UTF-8".into()))
}

fn parse_and_decrypt(
    encoded: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<PrivateKey, ManagedKeyError> {
    let private_key = match parse_openssh_private_key(encoded) {
        Ok(private_key) => private_key,
        Err(open_ssh_error) => parse_legacy_rsa(encoded).map_err(|legacy_error| {
            ManagedKeyError::Invalid(format!(
                "OpenSSH parse failed ({open_ssh_error}); RSA PEM parse failed ({legacy_error})"
            ))
        })?,
    };
    if !private_key.is_encrypted() {
        return Ok(private_key);
    }
    let passphrase = passphrase.filter(|value| !value.is_empty()).ok_or(
        ManagedKeyError::PassphraseRequired,
    )?;
    private_key
        .decrypt(passphrase)
        .map_err(|_| ManagedKeyError::DecryptionFailed)
}

/// `ssh-encoding` intentionally decodes OpenSSH PEM at OpenSSH's historical 70-character wrap
/// width. In practice, several key managers emit the same container using RFC 7468's 64-character
/// width, which OpenSSH itself accepts. Fall back to decoding the armor independently and then
/// parse the exact OpenSSH binary container.
fn parse_openssh_private_key(encoded: &[u8]) -> Result<PrivateKey, String> {
    match PrivateKey::from_openssh(encoded) {
        Ok(private_key) => Ok(private_key),
        Err(strict_error) => {
            let decoded = decode_openssh_armor(encoded).map_err(|armor_error| {
                format!("{strict_error}; flexible PEM parse failed ({armor_error})")
            })?;
            PrivateKey::from_bytes(decoded.as_slice()).map_err(|binary_error| {
                format!("{strict_error}; decoded OpenSSH parse failed ({binary_error})")
            })
        }
    }
}

fn decode_openssh_armor(encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    const BEGIN: &str = concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----");
    const END: &str = concat!("-----END OPENSSH ", "PRIVATE KEY-----");

    let text = std::str::from_utf8(encoded).map_err(|_| "armor is not UTF-8".to_string())?;
    let mut lines = text.lines();
    if lines.next() != Some(BEGIN) {
        return Err("missing OpenSSH private-key header".to_string());
    }

    let mut body = Zeroizing::new(String::new());
    let mut found_end = false;
    for line in &mut lines {
        if line == END {
            found_end = true;
            break;
        }
        if line.is_empty() || !line.bytes().all(is_base64_byte) {
            return Err("armor body contains invalid Base64 text".to_string());
        }
        body.push_str(line);
    }
    if !found_end {
        return Err("missing OpenSSH private-key footer".to_string());
    }
    if lines.any(|line| !line.trim().is_empty()) {
        return Err("unexpected data after OpenSSH private-key footer".to_string());
    }

    let mut decoded = Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(body.as_bytes(), &mut decoded)
        .map_err(|_| "armor body contains invalid Base64 text".to_string())?;
    Ok(decoded)
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn require_supported_algorithm(private_key: &PrivateKey) -> Result<(), ManagedKeyError> {
    match private_key.algorithm() {
        Algorithm::Ed25519 => Ok(()),
        Algorithm::Rsa { .. } => {
            let rsa = private_key
                .key_data()
                .rsa()
                .ok_or(ManagedKeyError::WeakRsaKey)?;
            let modulus = rsa::BigUint::try_from(&rsa.public.n)
                .map_err(|_| ManagedKeyError::WeakRsaKey)?;
            if modulus.bits() >= 2048 {
                Ok(())
            } else {
                Err(ManagedKeyError::WeakRsaKey)
            }
        }
        algorithm => Err(ManagedKeyError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

fn parse_legacy_rsa(encoded: &[u8]) -> Result<PrivateKey, String> {
    let pem = std::str::from_utf8(encoded).map_err(|error| error.to_string())?;
    let rsa = rsa::RsaPrivateKey::from_pkcs1_pem(pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs8_pem(pem))
        .map_err(|error| error.to_string())?;
    let keypair = ssh_key::private::RsaKeypair::try_from(rsa)
        .map_err(|error| error.to_string())?;
    PrivateKey::new(keypair.into(), "").map_err(|error| error.to_string())
}

fn sign_with_algorithm(
    private_key: &PrivateKey,
    message: &[u8],
    flags: u32,
) -> Result<Signature, ManagedKeyError> {
    match private_key.algorithm() {
        Algorithm::Ed25519 => {
            if flags != 0 {
                return Err(ManagedKeyError::UnsupportedFlags(flags));
            }
            private_key
                .try_sign(message)
                .map_err(|_| ManagedKeyError::SigningFailed)
        }
        Algorithm::Rsa { .. } => sign_rsa(private_key, message, flags),
        algorithm => Err(ManagedKeyError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

fn sign_rsa(
    private_key: &PrivateKey,
    message: &[u8],
    flags: u32,
) -> Result<Signature, ManagedKeyError> {
    const RSA_SHA2_256: u32 = 1 << 1;
    const RSA_SHA2_512: u32 = 1 << 2;

    let keypair = private_key
        .key_data()
        .rsa()
        .ok_or(ManagedKeyError::SigningFailed)?;
    let key = rsa::RsaPrivateKey::from_components(
        rsa::BigUint::try_from(&keypair.public.n)
            .map_err(|_| ManagedKeyError::SigningFailed)?,
        rsa::BigUint::try_from(&keypair.public.e)
            .map_err(|_| ManagedKeyError::SigningFailed)?,
        rsa::BigUint::try_from(&keypair.private.d)
            .map_err(|_| ManagedKeyError::SigningFailed)?,
        vec![
            rsa::BigUint::try_from(&keypair.private.p)
                .map_err(|_| ManagedKeyError::SigningFailed)?,
            rsa::BigUint::try_from(&keypair.private.q)
                .map_err(|_| ManagedKeyError::SigningFailed)?,
        ],
    )
    .map_err(|_| ManagedKeyError::SigningFailed)?;
    let (algorithm, signature) = match flags {
        RSA_SHA2_256 => {
            let signature = rsa::pkcs1v15::SigningKey::<Sha256>::new(key)
                .try_sign(message)
                .map_err(|_| ManagedKeyError::SigningFailed)?;
            (HashAlg::Sha256, signature.to_vec())
        }
        RSA_SHA2_512 => {
            let signature = rsa::pkcs1v15::SigningKey::<Sha512>::new(key)
                .try_sign(message)
                .map_err(|_| ManagedKeyError::SigningFailed)?;
            (HashAlg::Sha512, signature.to_vec())
        }
        _ => return Err(ManagedKeyError::UnsupportedFlags(flags)),
    };
    Signature::new(Algorithm::Rsa { hash: Some(algorithm) }, signature)
        .map_err(|_| ManagedKeyError::SigningFailed)
}

fn public_identity(private_key: &PrivateKey) -> Result<PublicIdentity, ManagedKeyError> {
    let public_key = private_key.public_key();
    let key_blob = public_key
        .to_bytes()
        .map_err(|error| ManagedKeyError::Invalid(error.to_string()))?;
    let digest = Sha256::digest(&key_blob);
    Ok(PublicIdentity {
        key_blob,
        address: format!("ssh/sha256/{}", URL_SAFE_NO_PAD.encode(digest)),
        fingerprint: format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)),
        comment: public_key.comment().to_string(),
    })
}

fn put_string(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buffer.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;

    #[test]
    fn managed_agent_socket_path_is_stable_and_short() {
        let runtime_dir = std::path::Path::new(
            "/Users/fixture-account/Library/Application Support/floria/runtime/sockets",
        );
        let path = agent_runtime_socket_path(
            runtime_dir,
            "ssh-agent-d56d57b2-3503-40e9-86d0-48a6ca9168fd",
        );

        assert_eq!(path.file_name().unwrap(), "3YUjhPR-lx4my6EW.sock");
        assert!(path.as_os_str().len() < 104);
    }

    #[test]
    fn imports_and_signs_generated_ed25519_key_without_source_fixture() {
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let source = private_key.to_openssh(LineEnding::LF).unwrap();
        let imported = import_private_key(source.as_bytes(), None).unwrap();
        assert!(imported.identity.address.starts_with("ssh/sha256/"));
        assert!(imported.identity.fingerprint.starts_with("SHA256:"));

        let message = b"fixture SSH user-auth payload";
        let encoded_signature = sign(imported.as_bytes(), message, 0).unwrap();
        let mut reader = Reader::new(&encoded_signature);
        assert_eq!(reader.string(), b"ssh-ed25519");
        let signature = Signature::new(Algorithm::Ed25519, reader.string().to_vec()).unwrap();
        assert!(reader.finished());
        signature::Verifier::verify(private_key.public_key(), message, &signature).unwrap();
    }

    #[test]
    fn verifies_generated_host_key_signature_and_rejects_tampering() {
        use ssh_key::EcdsaCurve;

        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        ] {
            let private_key = PrivateKey::random(&mut OsRng, algorithm).unwrap();
            let message = b"fixture SSH session identifier";
            let signature = private_key.try_sign(message).unwrap();
            let signature_blob = Vec::<u8>::try_from(signature).unwrap();
            let key_blob = private_key.public_key().to_bytes().unwrap();

            verify_public_signature(&key_blob, message, &signature_blob).unwrap();
            assert!(matches!(
                verify_public_signature(
                    &key_blob,
                    b"different session identifier",
                    &signature_blob
                ),
                Err(ManagedKeyError::InvalidPublicSignature(_))
            ));
        }
    }

    #[test]
    fn encrypted_import_requires_and_consumes_passphrase() {
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let encrypted = private_key.encrypt(&mut OsRng, b"fixture passphrase").unwrap();
        let source = encrypted.to_openssh(LineEnding::LF).unwrap();

        assert!(matches!(
            import_private_key(source.as_bytes(), None),
            Err(ManagedKeyError::PassphraseRequired)
        ));
        let imported = import_private_key(source.as_bytes(), Some(b"fixture passphrase")).unwrap();
        assert!(identity_from_private_key(imported.as_bytes()).is_ok());
    }

    #[test]
    fn imports_openssh_key_with_64_character_base64_lines() {
        let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let source = private_key.to_openssh(LineEnding::LF).unwrap();
        let rewrapped = rewrap_fixture(&source, 64);

        let imported = import_private_key(rewrapped.as_bytes(), None).unwrap();
        assert_eq!(imported.identity.key_blob, private_key.public_key().to_bytes().unwrap());
    }

    #[test]
    fn imports_generated_pkcs1_rsa_pem_and_honors_agent_sha2_flags() {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding as PemLineEnding};
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::traits::PublicKeyParts;

        let rsa_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let source = rsa_key.to_pkcs1_pem(PemLineEnding::LF).unwrap();
        let imported = import_private_key(source.as_bytes(), None).unwrap();
        assert!(imported.identity.key_blob.starts_with(&[0, 0, 0, 7]));
        let pkcs8 = rsa_key.to_pkcs8_pem(PemLineEnding::LF).unwrap();
        let imported_pkcs8 = import_private_key(pkcs8.as_bytes(), None).unwrap();
        assert_eq!(imported_pkcs8.identity, imported.identity);

        let message = b"fixture RSA SSH user-auth payload";
        for (flags, algorithm) in [(2, HashAlg::Sha256), (4, HashAlg::Sha512)] {
            let encoded_signature = sign(imported.as_bytes(), message, flags).unwrap();
            let mut reader = Reader::new(&encoded_signature);
            let expected = Algorithm::Rsa { hash: Some(algorithm) };
            assert_eq!(reader.string(), expected.as_str().as_bytes());
            let signature_bytes = reader.string().to_vec();
            assert!(reader.finished());
            let parsed = PrivateKey::from_openssh(imported.as_bytes()).unwrap();
            let parsed_rsa = parsed.key_data().rsa().unwrap();
            assert_eq!(rsa::BigUint::try_from(&parsed_rsa.public.n).unwrap(), *rsa_key.n());
            let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice()).unwrap();
            match algorithm {
                HashAlg::Sha256 => signature::Verifier::verify(
                    &rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_key.to_public_key()),
                    message,
                    &signature,
                )
                .unwrap(),
                HashAlg::Sha512 => signature::Verifier::verify(
                    &rsa::pkcs1v15::VerifyingKey::<Sha512>::new(rsa_key.to_public_key()),
                    message,
                    &signature,
                )
                .unwrap(),
                _ => unreachable!("fixture covers the two RSA SHA-2 algorithms"),
            }
        }
        assert!(matches!(
            sign(imported.as_bytes(), message, 0),
            Err(ManagedKeyError::UnsupportedFlags(0))
        ));
    }

    #[test]
    fn rejects_generated_rsa_keys_smaller_than_2048_bits() {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding as PemLineEnding};

        let rsa_key = rsa::RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let source = rsa_key.to_pkcs1_pem(PemLineEnding::LF).unwrap();
        assert!(matches!(
            import_private_key(source.as_bytes(), None),
            Err(ManagedKeyError::WeakRsaKey)
        ));
    }

    fn rewrap_fixture(source: &str, width: usize) -> Zeroizing<String> {
        let lines = source.lines().collect::<Vec<_>>();
        let body = Zeroizing::new(lines[1..lines.len() - 1].concat());
        let mut rewrapped = Zeroizing::new(String::new());
        rewrapped.push_str(lines[0]);
        rewrapped.push('\n');
        for chunk in body.as_bytes().chunks(width) {
            rewrapped.push_str(std::str::from_utf8(chunk).unwrap());
            rewrapped.push('\n');
        }
        rewrapped.push_str(lines[lines.len() - 1]);
        rewrapped.push('\n');
        rewrapped
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        offset: usize,
    }

    impl<'a> Reader<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Reader { bytes, offset: 0 }
        }

        fn string(&mut self) -> &'a [u8] {
            let length = u32::from_be_bytes(
                self.bytes[self.offset..self.offset + 4].try_into().unwrap(),
            ) as usize;
            self.offset += 4;
            let value = &self.bytes[self.offset..self.offset + length];
            self.offset += length;
            value
        }

        fn finished(&self) -> bool {
            self.offset == self.bytes.len()
        }
    }
}
