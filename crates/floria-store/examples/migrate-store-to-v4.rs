//! One-time development migration: store format 1–3 (`v/NNNN.age`, device-key encrypted)
//! into a NEW format-4 store (digest-named blobs, generation data keys).
//!
//! Throwaway tooling per the project convention (manual migration, vN-backup, no product
//! migration code). The old store is only read; the migrated store is written to a fresh
//! directory which you then swap into place by hand.
//!
//! Usage:
//!   cargo run -p floria-store --example migrate-store-to-v4 -- \
//!       <old-store-dir> <new-store-dir> <ssh-private-key> [passphrase via FLORIA_KEY_PASSPHRASE]
//!
//! Afterwards (daemon stopped):
//!   1. mv store store.v3-backup-<date> && mv <new-store-dir> store
//!   2. delete the old sidecar `store/.integrity.json` if it was copied (it was not — the tool
//!      never writes one) and delete the Keychain checkpoint for domain
//!      `encrypted-store-security-state` (service `floria.hola.ac.integrity`) so the
//!      development build reseals the migrated store on next start.
//!
//! Known, accepted losses: per-version `created` timestamps, notes, and mutation ids are not
//! carried over (the public API assigns fresh ones); version ordinals and head are preserved.

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::Zeroizing;

use floria_store::{AgeDirStore, NewSecret, SecretId, SecretStore, SshKeyProvider};

const V3_MAGIC: &[u8; 8] = b"FLORIA\0\x03";

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(old_root), Some(new_root), Some(key_path)) = (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: migrate-store-to-v4 <old-store-dir> <new-store-dir> <ssh-private-key>");
        std::process::exit(2);
    };
    let old_root = PathBuf::from(old_root);
    let new_root = PathBuf::from(new_root);
    if new_root.exists() {
        eprintln!("refusing to write into existing {}", new_root.display());
        std::process::exit(2);
    }
    let passphrase = std::env::var("FLORIA_KEY_PASSPHRASE").ok().map(Zeroizing::new);

    let identity = load_ssh_identity(Path::new(&key_path), passphrase.clone());
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
        let meta = read_old_meta(&entry.path(), &id);
        let versions = read_old_versions(&entry.path(), &id, identity.as_ref());
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

    // Round-trip check: every version in the new store must decrypt.
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

struct OldMeta {
    source_path: Option<String>,
    managed_label: Option<String>,
    mode: u32,
    current_version: u32,
    enforcement: floria_core::authz::Enforcement,
    environment_ids: Option<Vec<String>>,
    metadata: floria_core::metadata::ItemMetadata,
}

fn read_old_meta(entry_dir: &Path, id: &SecretId) -> OldMeta {
    let text = std::fs::read_to_string(entry_dir.join("meta.toml")).expect("read meta.toml");
    let value: toml::Value = toml::from_str(&text).expect("parse meta.toml");
    let table = value.as_table().expect("meta.toml is a table");
    assert_eq!(
        table.get("id").and_then(|v| v.as_str()),
        Some(id.as_str()),
        "meta.toml id mismatch"
    );
    let format = table.get("format").and_then(|v| v.as_integer()).unwrap_or(0);
    assert!((1..=3).contains(&format), "{id}: unexpected source format {format}");
    OldMeta {
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

/// All versions of an old entry as (ordinal, plaintext), oldest first.
fn read_old_versions(
    entry_dir: &Path,
    id: &SecretId,
    identity: &dyn age::Identity,
) -> Vec<(u32, Zeroizing<Vec<u8>>)> {
    let vdir = entry_dir.join("v");
    let mut ordinals = Vec::new();
    for entry in std::fs::read_dir(&vdir).expect("read versions dir") {
        let name = entry.expect("read version entry").file_name();
        if let Some(stem) = name.to_string_lossy().strip_suffix(".age") {
            ordinals.push(stem.parse::<u32>().expect("NNNN.age version file name"));
        }
    }
    ordinals.sort_unstable();
    ordinals
        .into_iter()
        .map(|ordinal| {
            let ciphertext =
                std::fs::read(vdir.join(format!("{ordinal:04}.age"))).expect("read version blob");
            let plaintext = age_decrypt(&ciphertext, identity);
            (ordinal, strip_v3_binding(id, ordinal, plaintext))
        })
        .collect()
}

/// Format 3 bound (magic, id, ordinal) into the payload; formats 1–2 stored raw plaintext.
fn strip_v3_binding(id: &SecretId, ordinal: u32, payload: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    if !payload.starts_with(V3_MAGIC) {
        return payload;
    }
    let mut cursor = V3_MAGIC.len();
    let id_len =
        u16::from_be_bytes(payload[cursor..cursor + 2].try_into().expect("id length")) as usize;
    cursor += 2;
    let actual_id = &payload[cursor..cursor + id_len];
    cursor += id_len;
    let actual_ordinal =
        u32::from_be_bytes(payload[cursor..cursor + 4].try_into().expect("ordinal"));
    cursor += 4;
    assert_eq!(actual_id, id.as_str().as_bytes(), "payload bound to a different secret");
    assert_eq!(actual_ordinal, ordinal, "payload bound to a different version");
    Zeroizing::new(payload[cursor..].to_vec())
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
