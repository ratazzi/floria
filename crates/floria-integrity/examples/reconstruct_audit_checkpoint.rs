//! Prepare a checkpoint replacement without changing the live audit log or Keychain.
//! Usage: reconstruct_audit_checkpoint <audit.jsonl> <new-output.json>

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use floria_integrity::StateAuthenticator;
use serde::{Deserialize, Serialize};

const CHECKPOINT_DOMAIN: &str = "audit-log-checkpoint";

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    sequence: u64,
    head: String,
    file_size: u64,
}

#[derive(Deserialize)]
struct Event {
    format: u32,
    sequence: u64,
    previous: String,
    event: serde_json::Value,
    tag: String,
}

fn reconstruct(
    authority: &StateAuthenticator,
    file: &File,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut candidates = vec![Checkpoint {
        sequence: 0,
        head: "genesis".into(),
        file_size: 0,
    }];
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    loop {
        line.clear();
        let count = reader.read_until(b'\n', &mut line)?;
        if count == 0 { break; }
        if line.last() != Some(&b'\n') {
            return Err("audit log has a partial final row".into());
        }
        let event: Event = serde_json::from_slice(&line)?;
        let previous = candidates.last().expect("genesis exists");
        if event.format != 1 || event.sequence != previous.sequence + 1
            || event.previous != previous.head
        {
            return Err("audit chain is discontinuous".into());
        }
        let payload = serde_json::to_vec(&(
            event.format, event.sequence, &event.previous, &event.event,
        ))?;
        authority.verify_detached("audit-log-event", &payload, &event.tag)?;
        candidates.push(Checkpoint {
            sequence: event.sequence,
            head: event.tag,
            file_size: previous.file_size + count as u64,
        });
    }
    if candidates.last().expect("genesis exists").file_size != file.metadata()?.len() {
        return Err("audit log changed during verification".into());
    }
    Ok(authority.reconstruct_checkpointed_state(CHECKPOINT_DOMAIN, candidates)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: reconstruct_audit_checkpoint <audit.jsonl> <new-output.json>".into());
    }
    let authority = StateAuthenticator::keychain()?;
    let input = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&args[0])?;
    let encoded = reconstruct(&authority, &input)?;
    let output_path = Path::new(&args[1]);
    let mut output = OpenOptions::new().write(true).create_new(true).mode(0o600).open(output_path)?;
    output.write_all(&encoded)?;
    output.sync_all()?;
    let verified = authority.load::<Checkpoint>(output_path, CHECKPOINT_DOMAIN)?;
    let checkpoint = verified.value.ok_or("reconstructed checkpoint is missing")?;
    println!("Verified complete audit chain; reconstructed trusted generation {}, sequence {}, byte offset {}. Live state and Keychain unchanged.",
        verified.generation, checkpoint.sequence, checkpoint.file_size);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_the_full_authenticated_chain_even_after_the_committed_tail() {
        let authority = StateAuthenticator::for_tests([17; 32]);
        let dir = tempfile::tempdir().unwrap();
        let checkpoint_path = dir.path().join("checkpoint.json");
        let event = serde_json::json!({"event": "test"});
        let payload = serde_json::to_vec(&(1, 1_u64, "genesis", &event)).unwrap();
        let tag = authority.authenticate_detached("audit-log-event", &payload);
        let row = serde_json::json!({
            "format": 1, "sequence": 1, "previous": "genesis", "event": event, "tag": tag,
        });
        let mut bytes = serde_json::to_vec(&row).unwrap();
        bytes.push(b'\n');
        authority.persist(&checkpoint_path, CHECKPOINT_DOMAIN, 0, &Checkpoint {
            sequence: 1, head: tag, file_size: bytes.len() as u64,
        }).unwrap();
        let log_path = dir.path().join("audit.jsonl");
        std::fs::write(&log_path, &bytes).unwrap();
        assert_eq!(reconstruct(&authority, &File::open(&log_path).unwrap()).unwrap(),
            std::fs::read(&checkpoint_path).unwrap());
        bytes.extend_from_slice(b"{\"partial\":");
        std::fs::write(&log_path, bytes).unwrap();
        assert!(reconstruct(&authority, &File::open(log_path).unwrap()).is_err());
    }
}
