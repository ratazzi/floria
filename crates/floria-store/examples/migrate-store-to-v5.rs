//! One-time development migration: store format 4 (private digest blobs + flat local `keys/`)
//! into a NEW format-5 data root (shared/local split, store-is-vault).
//!
//! Format 4 payloads carry the `FLORIA\0\x04` binding and are encrypted under the v4 local
//! generation key, so this is a one-time transcription (the v4 bytes never entered any vault —
//! sync did not exist for them). Ids, ordinals, heads, enforcement and metadata are preserved;
//! per-version created timestamps and notes are not.
//!
//! Usage:
//!   cargo run -p floria-store --example migrate-store-to-v5 -- \
//!       <v4-store-dir> <new-data-root> <ssh-private-key> [passphrase via FLORIA_KEY_PASSPHRASE]
//!
//! Afterwards (daemon stopped): back up and swap the store directory, then delete the Keychain
//! checkpoint for `encrypted-store-security-state` so the development build reseals.

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use zeroize::Zeroizing;

use floria_store::{AgeDirStore, NewSecret, SecretId, SecretStore, SshKeyProvider};

const V4_MAGIC: &[u8; 8] = b"FLORIA\0\x04";

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(old_root), Some(new_root), Some(key_path)) = (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: migrate-store-to-v5 <v4-store-dir> <new-data-root> <ssh-private-key>");
        std::process::exit(2);
    };
    let old_root = PathBuf::from(old_root);
    let new_root = PathBuf::from(new_root);
    if new_root.exists() {
        eprintln!("refusing to write into existing {}", new_root.display());
        std::process::exit(2);
    }
    let passphrase = std::env::var("FLORIA_KEY_PASSPHRASE").ok().map(Zeroizing::new);

    let device_identity = load_ssh_identity(Path::new(&key_path), passphrase.clone());
    let generation_identity = unwrap_v4_generation(&old_root, device_identity.as_ref());
    let provider = Arc::new(SshKeyProvider::new(PathBuf::from(&key_path), passphrase));
    let new_store = AgeDirStore::open(new_root.clone(), provider).expect("open new store");

    let mut migrated = 0usize;
    let mut versions_total = 0usize;
    for entry in std::fs::read_dir(&old_root).expect("read old store") {
        let entry = entry.expect("read old store entry");
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(id) = name.parse::<SecretId>() else {
            continue; // keys/, lock files, non-entry dirs
        };
        let meta = read_v4_meta(&entry.path(), &id);
        let versions = read_v4_versions(&entry.path(), &id, &generation_identity);
        assert!(!versions.is_empty(), "{id} has no versions");

        let new_secret = match (&meta.source_path, &meta.managed_label) {
            (Some(path), None) => NewSecret::file(PathBuf::from(path), meta.mode),
            (None, Some(label)) => NewSecret::managed(label.clone()),
            _ => panic!("{id}: meta.toml must contain exactly one origin"),
        }
        .with_enforcement(meta.enforcement);

        let mutation = uuid::Uuid::new_v4().to_string();
        let (first_ordinal, first_plaintext) = &versions[0];
        assert_eq!(*first_ordinal, 1, "{id}: version ordinals must start at 1");
        new_store
            .put_identified(id.clone(), new_secret, first_plaintext, &mutation)
            .expect("write version 1");
        for (ordinal, plaintext) in versions.iter().skip(1) {
            let assigned = new_store.append_version(&id, plaintext).expect("append version");
            assert_eq!(assigned, *ordinal, "{id}: non-contiguous version ordinals");
        }
        new_store.set_head(&id, meta.current_version).expect("restore head");
        new_store
            .update_settings(&id, meta.metadata, meta.enforcement, meta.environment_ids)
            .expect("restore settings");

        versions_total += versions.len();
        migrated += 1;
        println!("migrated {id} ({} versions, head v{})", versions.len(), meta.current_version);
    }

    let verification = new_store.verify_all().expect("verify migrated store");
    assert_eq!(verification.secrets, migrated);
    println!(
        "done: {migrated} secrets, {versions_total} versions -> {} (verified {} versions)",
        new_root.display(),
        verification.versions
    );
    println!("next: stop the daemon, back up and swap the store directory, then delete the");
    println!("Keychain checkpoint for `encrypted-store-security-state` so the dev build reseals.");
}

struct V4Meta {
    source_path: Option<String>,
    managed_label: Option<String>,
    mode: u32,
    current_version: u32,
    enforcement: floria_core::authz::Enforcement,
    environment_ids: Option<Vec<String>>,
    metadata: floria_core::metadata::ItemMetadata,
}

fn read_v4_meta(entry_dir: &Path, id: &SecretId) -> V4Meta {
    let text = std::fs::read_to_string(entry_dir.join("meta.toml")).expect("read meta.toml");
    let value: toml::Value = toml::from_str(&text).expect("parse meta.toml");
    let table = value.as_table().expect("meta.toml is a table");
    assert_eq!(
        table.get("id").and_then(|v| v.as_str()),
        Some(id.as_str()),
        "meta.toml id mismatch"
    );
    let format = table.get("format").and_then(|v| v.as_integer()).unwrap_or(0);
    assert_eq!(format, 4, "{id}: expected a format 4 entry, found {format}");
    V4Meta {
        source_path: table.get("source_path").and_then(|v| v.as_str()).map(str::to_owned),
        managed_label: table.get("managed_label").and_then(|v| v.as_str()).map(str::to_owned),
        mode: table.get("mode").and_then(|v| v.as_integer()).expect("mode") as u32,
        current_version: table
            .get("current_version")
            .and_then(|v| v.as_integer())
            .expect("current_version") as u32,
        enforcement: table
            .get("enforcement")
            .cloned()
            .map(|v| v.try_into().expect("parse enforcement"))
            .unwrap_or(floria_core::authz::Enforcement::Prompt),
        environment_ids: table.get("environment_ids").map(|v| {
            v.as_array()
                .expect("environment_ids array")
                .iter()
                .map(|item| item.as_str().expect("environment id").to_owned())
                .collect()
        }),
        metadata: table
            .get("metadata")
            .cloned()
            .map(|v| v.try_into().expect("parse metadata"))
            .unwrap_or_default(),
    }
}

/// All versions of a v4 entry as (ordinal, plaintext), oldest first. v4 sidecars are
/// `v/<digest>.toml` carrying the ordinal, uuid and generation.
fn read_v4_versions(
    entry_dir: &Path,
    id: &SecretId,
    generation_identity: &age::x25519::Identity,
) -> Vec<(u32, Zeroizing<Vec<u8>>)> {
    let vdir = entry_dir.join("v");
    let mut rows: Vec<(u32, String, String)> = Vec::new(); // (ordinal, digest, uuid)
    for entry in std::fs::read_dir(&vdir).expect("read versions dir") {
        let name = entry.expect("read version entry").file_name();
        let Some(digest) = name.to_string_lossy().strip_suffix(".toml").map(str::to_owned)
        else {
            continue;
        };
        let text =
            std::fs::read_to_string(vdir.join(format!("{digest}.toml"))).expect("read sidecar");
        let value: toml::Value = toml::from_str(&text).expect("parse sidecar");
        let table = value.as_table().expect("sidecar is a table");
        let ordinal =
            table.get("version").and_then(|v| v.as_integer()).expect("version ordinal") as u32;
        let uuid = table
            .get("version_uuid")
            .and_then(|v| v.as_str())
            .expect("version uuid")
            .to_string();
        rows.push((ordinal, digest, uuid));
    }
    rows.sort_by_key(|(ordinal, _, _)| *ordinal);
    rows.into_iter()
        .map(|(ordinal, digest, uuid)| {
            let ciphertext =
                std::fs::read(vdir.join(format!("{digest}.age"))).expect("read version blob");
            let plaintext = age_decrypt(&ciphertext, generation_identity);
            (ordinal, strip_v4_binding(id, &uuid, plaintext))
        })
        .collect()
}

fn strip_v4_binding(
    id: &SecretId,
    version_uuid: &str,
    payload: Zeroizing<Vec<u8>>,
) -> Zeroizing<Vec<u8>> {
    assert!(payload.starts_with(V4_MAGIC), "payload has no v4 binding");
    let mut cursor = V4_MAGIC.len();
    let id_len =
        u16::from_be_bytes(payload[cursor..cursor + 2].try_into().expect("id length")) as usize;
    cursor += 2;
    let actual_id = &payload[cursor..cursor + id_len];
    cursor += id_len;
    let uuid_len =
        u16::from_be_bytes(payload[cursor..cursor + 2].try_into().expect("uuid length")) as usize;
    cursor += 2;
    let actual_uuid = &payload[cursor..cursor + uuid_len];
    cursor += uuid_len;
    assert_eq!(actual_id, id.as_str().as_bytes(), "payload bound to a different secret");
    assert_eq!(actual_uuid, version_uuid.as_bytes(), "payload bound to a different version");
    Zeroizing::new(payload[cursor..].to_vec())
}

/// Unwrap the v4 store's current generation identity from its flat local `keys/` directory.
fn unwrap_v4_generation(
    old_root: &Path,
    device_identity: &dyn age::Identity,
) -> age::x25519::Identity {
    let keys_dir = old_root.join("keys");
    let mut generations: Vec<u32> = std::fs::read_dir(&keys_dir)
        .expect("read v4 keys dir")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .strip_suffix(".age")
                .and_then(|stem| stem.parse::<u32>().ok())
        })
        .collect();
    generations.sort_unstable();
    assert!(!generations.is_empty(), "v4 store has no generation envelopes");
    // v4 dev stores only ever reached generation 1; decrypting all versions with the highest
    // generation is correct as long as no rotation happened.
    assert_eq!(generations, vec![1], "v4 store rotated generations; extend this tool");
    let envelope =
        std::fs::read(keys_dir.join("1.age")).expect("read v4 generation envelope");
    let secret = age_decrypt(&envelope, device_identity);
    age::x25519::Identity::from_str(std::str::from_utf8(&secret).expect("utf8").trim())
        .expect("parse v4 generation identity")
}

fn load_ssh_identity(
    path: &Path,
    passphrase: Option<Zeroizing<String>>,
) -> Box<dyn age::Identity> {
    let data = std::fs::read(path).expect("read ssh private key");
    let identity = age::ssh::Identity::from_buffer(
        BufReader::new(&data[..]),
        Some(path.display().to_string()),
    )
    .expect("parse ssh private key");
    if let age::ssh::Identity::Unsupported(kind) = &identity {
        panic!("unsupported ssh key: {kind:?}");
    }
    match passphrase {
        Some(passphrase) => Box::new(identity.with_callbacks(Passphrase(passphrase))),
        None => Box::new(identity),
    }
}

#[derive(Clone)]
struct Passphrase(Zeroizing<String>);

impl age::Callbacks for Passphrase {
    fn display_message(&self, _message: &str) {}
    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }
    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }
    fn request_passphrase(&self, _description: &str) -> Option<age::secrecy::Secret<String>> {
        Some(age::secrecy::Secret::new(self.0.to_string()))
    }
}

fn age_decrypt(ciphertext: &[u8], identity: &dyn age::Identity) -> Zeroizing<Vec<u8>> {
    let decryptor = match age::Decryptor::new(ciphertext).expect("open age blob") {
        age::Decryptor::Recipients(d) => d,
        age::Decryptor::Passphrase(_) => panic!("blob is passphrase-encrypted"),
    };
    let mut reader = decryptor.decrypt(std::iter::once(identity)).expect("decrypt blob");
    let mut out = Zeroizing::new(Vec::new());
    reader.read_to_end(&mut out).expect("read blob");
    out
}
