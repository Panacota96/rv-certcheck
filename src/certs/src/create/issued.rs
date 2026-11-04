//! OWNER: B. The issuance log `issued.jsonl`: one [`IssuedRecord`] per line, hash-chained exactly like the
//! Rakvor audit.jsonl (rv_certcheck_core::audit, reproduced here because this crate does not depend on core):
//!
//! ```text
//! entry_hash      = SHA-256( canonical JSON of the record without `entry_hash` )
//! canonical       = keys sorted, no whitespace, UTF-8 (serde_json Map = BTreeMap; Python json.dumps(sort_keys=True,
//!                   separators=(",",":"), ensure_ascii=False))
//! prev_entry_hash = the previous line's entry_hash; 64 zeros for the first line; seq = 1, 2, 3...
//! ```
//! Editing, deleting, inserting or re-ordering any line breaks verification from that line on. Records hold
//! serials, profiles, subjects, certificate SHA-256s and key *locations*; never a key, password or PIN.

use super::keys::io_err;
use crate::model::*;
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const FILE: &str = "issued.jsonl";

fn entry_hash(v: &Value) -> String {
    let mut m = v.as_object().cloned().unwrap_or_default();
    m.remove("entry_hash");
    hex(&openssl::sha::sha256(
        serde_json::to_string(&Value::Object(m))
            .expect("serializable")
            .as_bytes(),
    ))
}

/// Verifies the chain. Ok(records) when intact, Err(problems, one per line) otherwise.
pub fn verify(path: &Path) -> Result<Vec<IssuedRecord>, Vec<String>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| vec![format!("cannot read {}: {e}", path.display())])?;
    let mut problems = vec![];
    let mut out = vec![];
    let mut prev = GENESIS.to_string();
    let mut expected = 1u64;
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if line.trim().is_empty() {
            problems.push(format!("line {n}: empty line"));
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                problems.push(format!("line {n}: not valid JSON ({e})"));
                continue;
            }
        };
        let seq = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
        if seq != expected {
            problems.push(format!(
                "line {n}: sequence {seq} where {expected} was expected (deleted, inserted or re-ordered record)"
            ));
        }
        if v.get("prev_entry_hash").and_then(Value::as_str) != Some(prev.as_str()) {
            problems.push(format!(
                "line {n}: prev_entry_hash does not link to the previous record"
            ));
        }
        let stored = v
            .get("entry_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if entry_hash(&v) != stored {
            problems.push(format!(
                "line {n}: entry_hash does not match its content (edited record)"
            ));
        }
        match serde_json::from_value::<IssuedRecord>(v) {
            Ok(r) => out.push(r),
            Err(e) => problems.push(format!("line {n}: not an issued record ({e})")),
        }
        prev = stored;
        expected = seq + 1;
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(problems)
    }
}

pub fn verify_or_err(ca_dir: &Path) -> CertResult<Vec<IssuedRecord>> {
    verify(&ca_dir.join(FILE)).map_err(|p| {
        CertError::new(
            ErrorKind::Policy,
            format!(
                "{} does not verify, nothing will be issued until it is investigated: {}",
                ca_dir.join(FILE).display(),
                p.join("; ")
            ),
        )
    })
}

/// Appends `rec` after `prev` (the verified records): fills seq, prev_entry_hash, entry_hash.
pub fn append(
    ca_dir: &Path,
    prev: &[IssuedRecord],
    mut rec: IssuedRecord,
) -> CertResult<IssuedRecord> {
    rec.seq = prev.last().map(|r| r.seq).unwrap_or(0) + 1;
    rec.prev_entry_hash = prev
        .last()
        .map(|r| r.entry_hash.clone())
        .unwrap_or_else(|| GENESIS.to_string());
    rec.entry_hash = String::new();
    if rec.tool_version.is_empty() {
        rec.tool_version = super::tool_version().to_string();
    }
    let mut v = serde_json::to_value(&rec).expect("serializable");
    let h = entry_hash(&v);
    v.as_object_mut()
        .expect("object")
        .insert("entry_hash".into(), Value::String(h.clone()));
    rec.entry_hash = h;
    let path = ca_dir.join(FILE);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(io_err(&path))?;
    let mut line = serde_json::to_string(&v).expect("serializable");
    line.push('\n');
    f.write_all(line.as_bytes()).map_err(io_err(&path))?;
    f.sync_all().map_err(io_err(&path))?;
    Ok(rec)
}

/// Exclusive lock of a CA folder for one operation (`issued.lock`, removed on drop). A stale lock after a crash
/// is reported, never silently broken.
#[derive(Debug)]
pub struct Lock(PathBuf);

impl Lock {
    pub fn take(ca_dir: &Path) -> CertResult<Lock> {
        let p = ca_dir.join("issued.lock");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
        {
            Ok(mut f) => {
                let _ = writeln!(f, "pid {}", std::process::id());
                Ok(Lock(p))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(CertError::new(
                ErrorKind::Policy,
                format!(
                    "{} exists: another operation is running on this CA, or one crashed (then check issued.jsonl with pki open and delete the lock)",
                    p.display()
                ),
            )),
            Err(e) => Err(CertError::new(
                ErrorKind::Io,
                format!("{}: {e}", p.display()),
            )),
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
