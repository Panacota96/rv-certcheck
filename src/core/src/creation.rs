//! The audited run of a creation operation (pki, csr, lab, tokens, trust-list import), for front-ends that are not
//! the CLI (the GUI). Same files and the same audit actions as the CLI's creation commands:
//!
//! ```text
//! <OUT>/logs/<RUN-ID>/audit.jsonl | audit.log | environment.json
//! <OUT>/reports/<RUN-ID>/report.json | report.txt        (schema rakvor.certcheck-creation-report/1)
//! run_started ─► [front-end preamble: ui_* actions] ─► environment_recorded ─► <operation records>
//!             ─► file_written (path + SHA-256) ─► ca_log_appended ─► report_written ─► run_finished
//! ```
//! The log records what was done, never a password, PIN or key: callers pass key *locations* only. Nothing here
//! prints; the outcome is returned.

use crate::audit::AuditLog;
use crate::hash::{HashAlgo, hash_bytes};
use crate::{TOOL_NAME, TOOL_VERSION};
use rv_certcheck_certs::{self as certs, CertError, ErrorKind, IssuedRecord};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Schema id of report.json.
pub const SCHEMA_CREATION_REPORT: &str = "rakvor.certcheck-creation-report/1";

/// What a finished (or failed) creation run produced.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CreationOutcome {
    pub run_id: String,
    pub command: String,
    /// Done (true), or failed / refused / findings (false).
    pub ok: bool,
    /// The CLI exit code the same operation gives (0 done, 1 error, 2 usage, 3 refused or findings).
    pub exit_code: u8,
    /// Human-readable summary lines (what the CLI prints).
    pub summary: Vec<String>,
    /// The error message when the operation failed.
    pub error: Option<String>,
    /// Files the operation wrote: (role, path, sha256).
    pub files: Vec<(String, PathBuf, String)>,
    pub result: Value,
    pub log_dir: PathBuf,
    pub report_dir: PathBuf,
}

pub struct CreationRun {
    log: AuditLog,
    run_id: String,
    actor: String,
    log_dir: PathBuf,
    report_dir: PathBuf,
    command: String,
    files: Vec<Value>,
}

fn run_id() -> String {
    let seed = format!(
        "{:?}-{}-{}",
        std::time::SystemTime::now(),
        std::process::id(),
        crate::env::hostname()
    );
    format!(
        "{}-{}",
        crate::time::utc_compact(),
        &hash_bytes(seed.as_bytes(), HashAlgo::Sha256)[..6]
    )
}

fn sha256_file(p: &Path) -> Option<String> {
    std::fs::read(p)
        .ok()
        .map(|b| hash_bytes(&b, HashAlgo::Sha256))
}

/// The issued.jsonl records of a CA folder, in order (empty when missing).
pub fn issued_records(ca: &Path) -> Vec<IssuedRecord> {
    std::fs::read_to_string(ca.join("issued.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// A path recorded relative to the CA folder, made absolute.
pub fn resolve(ca: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        ca.join(path)
    }
}

/// The notice written into every creation report of the PKI.
pub fn internal_notice() -> String {
    format!(
        "{} Client certificates (profile client-internal) wait for Rakvor's CP/CPS (rv-certcheck#2).",
        certs::RAKVOR_INTERNAL_NOTICE
    )
}

pub const LAB_NOTICE: &str = "Lab material: every key, salt and serial of a lab set derives from its seed and is public. Never use a lab certificate or key for anything real.";

impl CreationRun {
    /// Opens `<out>/logs/<RUN-ID>/`, records `run_started` (frontend, command, parameters), then the front-end's
    /// `preamble` actions in order, then environment.json.
    pub fn start(
        out: &Path,
        actor: &str,
        frontend: &str,
        command: &str,
        params: Value,
        preamble: &[(String, Value)],
        command_line: &[String],
    ) -> std::io::Result<CreationRun> {
        let id = run_id();
        let log_dir = out.join("logs").join(&id);
        let report_dir = out.join("reports").join(&id);
        let mut log = AuditLog::create(&log_dir, &id, actor)?;
        log.record(
            "run_started",
            None,
            json!({"tool": TOOL_NAME, "version": TOOL_VERSION, "frontend": frontend, "command": command,
                   "parameters": params, "openssl": certs::openssl_version()}),
        )?;
        for (action, details) in preamble {
            log.record(action, None, details.clone())?;
        }
        let env = crate::env::describe(TOOL_NAME, TOOL_VERSION, frontend, command_line);
        let env_bytes = serde_json::to_vec_pretty(&env).unwrap_or_default();
        std::fs::write(log_dir.join("environment.json"), &env_bytes)?;
        log.record(
            "environment_recorded",
            Some("environment.json"),
            json!({"sha256": hash_bytes(&env_bytes, HashAlgo::Sha256)}),
        )?;
        Ok(CreationRun {
            log,
            run_id: id,
            actor: actor.to_string(),
            log_dir,
            report_dir,
            command: command.into(),
            files: vec![],
        })
    }

    pub fn actor(&self) -> String {
        self.actor.clone()
    }

    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    pub fn record(&mut self, action: &str, item: Option<&str>, details: Value) {
        // A failing audit write must not be silent: it is reported in the outcome by the next file check.
        let _ = self.log.record(action, item, details);
    }

    /// Records a file the operation wrote (path and SHA-256).
    pub fn file(&mut self, role: &str, p: &Path) {
        if let Some(h) = sha256_file(p) {
            let v = json!({"role": role, "path": p.display().to_string(), "sha256": h});
            self.record("file_written", Some(&p.display().to_string()), v.clone());
            self.files.push(v);
        }
    }

    /// Records the issued.jsonl record an operation appended (links the two hash chains).
    pub fn issued(&mut self, ca: &Path, rec: &IssuedRecord) {
        self.record(
            "ca_log_appended",
            Some(&ca.join("issued.jsonl").display().to_string()),
            json!({"ca_id": rec.ca_id, "seq": rec.seq, "action": rec.action, "entry_hash": rec.entry_hash,
                   "serial": rec.serial_hex, "cert_sha256": rec.cert_sha256}),
        );
    }

    fn outcome(
        &self,
        ok: bool,
        exit_code: u8,
        summary: Vec<String>,
        result: Value,
    ) -> CreationOutcome {
        CreationOutcome {
            run_id: self.run_id.clone(),
            command: self.command.clone(),
            ok,
            exit_code,
            summary,
            error: None,
            files: self
                .files
                .iter()
                .map(|f| {
                    (
                        f["role"].as_str().unwrap_or_default().to_string(),
                        PathBuf::from(f["path"].as_str().unwrap_or_default()),
                        f["sha256"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect(),
            result,
            log_dir: self.log_dir.clone(),
            report_dir: self.report_dir.clone(),
        }
    }

    /// The operation failed: `operation_failed` + `run_finished` (status error), exit code as the CLI.
    pub fn fail(mut self, e: &CertError) -> CreationOutcome {
        let code = match e.kind {
            ErrorKind::InvalidInput => 2,
            ErrorKind::Policy => 3,
            _ => 1,
        };
        self.record(
            "operation_failed",
            None,
            json!({"kind": e.kind, "error": e.message}),
        );
        self.record(
            "run_finished",
            None,
            json!({"status": "error", "exit_code": code}),
        );
        let mut o = self.outcome(false, code, vec![], Value::Null);
        o.error = Some(e.message.clone());
        o
    }

    /// Writes report.json / report.txt and closes the log (`run_finished` with the CLI's status and exit code).
    pub fn finish(
        mut self,
        result: Value,
        summary: Vec<String>,
        notice: &str,
        exit_code: u8,
    ) -> CreationOutcome {
        let report = json!({
            "schema": SCHEMA_CREATION_REPORT,
            "tool": TOOL_NAME, "version": TOOL_VERSION, "run_id": self.run_id, "command": self.command,
            "result": result, "files": self.files, "notice": notice,
        });
        let files = if self.files.is_empty() {
            "  (none)".to_string()
        } else {
            self.files
                .iter()
                .map(|f| {
                    format!(
                        "  {}  {}  ({})",
                        f["sha256"].as_str().unwrap_or(""),
                        f["path"].as_str().unwrap_or(""),
                        f["role"].as_str().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        let mut text = format!(
            "RV CertCheck {TOOL_VERSION}: {cmd}\nRun {id}\n\n{body}\n\nFiles:\n{files}\n\n{notice}\n",
            cmd = self.command,
            id = self.run_id,
            body = summary.join("\n"),
        );
        text.push_str(&format!(
            "\nAudit log: {}\n",
            self.log_dir.join("audit.jsonl").display()
        ));
        let _ = std::fs::create_dir_all(&self.report_dir);
        for (name, bytes) in [
            (
                "report.json",
                serde_json::to_vec_pretty(&report).unwrap_or_default(),
            ),
            ("report.txt", text.into_bytes()),
        ] {
            let p = self.report_dir.join(name);
            if std::fs::write(&p, &bytes).is_ok() {
                self.record(
                    "report_written",
                    Some(name),
                    json!({"sha256": hash_bytes(&bytes, HashAlgo::Sha256)}),
                );
            }
        }
        self.record(
            "run_finished",
            None,
            json!({"status": if exit_code == 0 { "ok" } else { "findings" }, "exit_code": exit_code}),
        );
        self.outcome(exit_code == 0, exit_code, summary, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_creation_run_is_a_verifiable_log_with_a_report() {
        let d = tempfile::tempdir().unwrap();
        let mut r = CreationRun::start(
            d.path(),
            "tester",
            "gui",
            "pki show",
            json!({"ca": "x"}),
            &[("ui_tab_changed".into(), json!({"tab": "create"}))],
            &["rv-certcheck-gui".into()],
        )
        .unwrap();
        let f = d.path().join("f.txt");
        std::fs::write(&f, "x").unwrap();
        r.file("test file", &f);
        let o = r.finish(json!({"ok": true}), vec!["done".into()], "", 0);
        assert!(o.ok && o.exit_code == 0);
        assert_eq!(o.files.len(), 1);
        let log = o.log_dir.join("audit.jsonl");
        assert_eq!(crate::audit::verify(&log).unwrap(), 7);
        let t = std::fs::read_to_string(&log).unwrap();
        for a in [
            "run_started",
            "ui_tab_changed",
            "environment_recorded",
            "file_written",
            "report_written",
            "run_finished",
        ] {
            assert!(t.contains(&format!("\"{a}\"")), "{a}");
        }
        let rep: Value =
            serde_json::from_slice(&std::fs::read(o.report_dir.join("report.json")).unwrap())
                .unwrap();
        assert_eq!(rep["schema"], SCHEMA_CREATION_REPORT);
        let r = CreationRun::start(d.path(), "t", "gui", "pki issue", json!({}), &[], &[]).unwrap();
        let o = r.fail(&CertError::new(ErrorKind::Policy, "refused"));
        assert_eq!((o.ok, o.exit_code), (false, 3));
        assert_eq!(o.error.as_deref(), Some("refused"));
    }
}
