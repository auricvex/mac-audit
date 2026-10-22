//! Tamper-evident, append-only audit log.
//!
//! Each entry is one JSON line containing the SHA-256 hash of the
//! previous entry (`prev_hash`) and its own hash, forming a chain.
//! Editing, deleting, or reordering any entry breaks verification
//! in `verify_chain` / `mac-audit log verify`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    /// Unix seconds.
    pub ts: u64,
    pub prev_hash: String,
    /// Event kind, e.g. `session.login`. Names only — never content.
    pub event: String,
    /// Local account name the event belongs to.
    pub actor: String,
    /// Subject name only (app/process name), never file content or input.
    pub subject: String,
    pub hash: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn compute_hash(
    seq: u64,
    ts: u64,
    prev_hash: &str,
    event: &str,
    actor: &str,
    subject: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_string().as_bytes());
    h.update(b"|");
    h.update(ts.to_string().as_bytes());
    h.update(b"|");
    h.update(prev_hash.as_bytes());
    h.update(b"|");
    h.update(event.as_bytes());
    h.update(b"|");
    h.update(actor.as_bytes());
    h.update(b"|");
    h.update(subject.as_bytes());
    format!("{:x}", h.finalize())
}

/// Read all entries from a log file (missing file = empty log).
pub fn read_entries(path: &Path) -> std::io::Result<Vec<AuditEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        out.push(entry);
    }
    Ok(out)
}

/// Append one event to the chain and return the stored entry.
pub fn append(path: &Path, event: &str, actor: &str, subject: &str) -> std::io::Result<AuditEntry> {
    let entries = read_entries(path)?;
    let (seq, prev_hash) = match entries.last() {
        Some(last) => (last.seq + 1, last.hash.clone()),
        None => (0, GENESIS_HASH.to_string()),
    };
    let ts = now_unix();
    let hash = compute_hash(seq, ts, &prev_hash, event, actor, subject);
    let entry = AuditEntry {
        seq,
        ts,
        prev_hash,
        event: event.to_string(),
        actor: actor.to_string(),
        subject: subject.to_string(),
        hash,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(&entry).unwrap_or_default()
    )?;
    Ok(entry)
}

/// Verify the whole chain. `Ok(n)` = n entries valid.
/// `Err(msg)` describes the first break (tamper / reorder / edit).
pub fn verify_chain(path: &Path) -> Result<usize, String> {
    let entries = read_entries(path).map_err(|e| e.to_string())?;
    let mut prev = GENESIS_HASH.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(format!("seq gap/reorder at index {i}: found seq {}", e.seq));
        }
        if e.prev_hash != prev {
            return Err(format!("prev_hash mismatch at seq {}", e.seq));
        }
        let expect = compute_hash(e.seq, e.ts, &e.prev_hash, &e.event, &e.actor, &e.subject);
        if expect != e.hash {
            return Err(format!("hash mismatch at seq {} (entry was edited)", e.seq));
        }
        prev.clone_from(&e.hash);
    }
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_log(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mac-audit-test-{}-{}.log",
            std::process::id(),
            name
        ))
    }

    #[test]
    fn append_and_verify_chain() {
        let path = temp_log("chain");
        let _ = std::fs::remove_file(&path);
        append(&path, "system.boot", "root", "daemon").unwrap();
        append(&path, "session.login", "ade", "loginwindow").unwrap();
        append(&path, "app.launch", "ade", "Safari").unwrap();
        assert_eq!(verify_chain(&path).unwrap(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_entry_is_detected() {
        let path = temp_log("tamper");
        let _ = std::fs::remove_file(&path);
        append(&path, "session.login", "ade", "loginwindow").unwrap();
        append(&path, "app.launch", "ade", "Safari").unwrap();
        // Edit the subject of the first entry without fixing its hash.
        let mut entries = read_entries(&path).unwrap();
        entries[0].subject = "Terminal".to_string();
        let mut text = String::new();
        for e in &entries {
            text.push_str(&serde_json::to_string(e).unwrap());
            text.push('\n');
        }
        std::fs::write(&path, text).unwrap();
        let err = verify_chain(&path).unwrap_err();
        assert!(err.contains("hash mismatch"), "unexpected: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deleted_entry_is_detected() {
        let path = temp_log("delete");
        let _ = std::fs::remove_file(&path);
        append(&path, "system.boot", "root", "daemon").unwrap();
        append(&path, "session.login", "ade", "loginwindow").unwrap();
        let entries = read_entries(&path).unwrap();
        std::fs::write(&path, serde_json::to_string(&entries[1]).unwrap() + "\n").unwrap();
        assert!(verify_chain(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
