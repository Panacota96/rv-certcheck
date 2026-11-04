//! The Trust lists tab: import an EU LOTL/TL XML or the curated Colombian CSV (an audited `trust-list import` run),
//! list the stored snapshots with their date and SHA-256, inspect one snapshot's services, and use a snapshot as
//! an Analyze anchor (`tl:<list>@<id>`).

use super::UiLog;
use super::create::{OpKind, PreparedOp};
use rv_certcheck_core::certs::{
    self, TrustListKind, TrustListSnapshot, TrustListSummary, TrustService,
};
use rv_certcheck_core::i18n::Catalog;
use serde_json::json;
use std::path::PathBuf;

#[derive(Debug)]
pub struct TrustState {
    /// Snapshot folder (the tool's data folder by default; `RV_CERTCHECK_DATA` overrides it).
    pub store_dir: String,
    pub import_list: TrustListKind,
    pub import_file: String,
    pub snapshots: Vec<TrustListSummary>,
    pub error: Option<String>,
    pub selected: Option<TrustListSnapshot>,
    /// Filters the services of the selected snapshot (name, TSP, type, country; case-insensitive).
    pub filter: String,
}

impl Default for TrustState {
    fn default() -> Self {
        TrustState {
            store_dir: certs::trust_list::default_store_dir().display().to_string(),
            import_list: TrustListKind::Eu,
            import_file: String::new(),
            snapshots: vec![],
            error: None,
            selected: None,
            filter: String::new(),
        }
    }
}

impl TrustState {
    pub fn store(&self) -> PathBuf {
        PathBuf::from(self.store_dir.trim().trim_matches('"'))
    }

    /// Reads the stored snapshots (newest first). A missing folder is an empty list.
    pub fn refresh(&mut self) {
        match certs::trust_list::list(&self.store()) {
            Ok(l) => {
                self.snapshots = l;
                self.error = None;
            }
            Err(e) => {
                self.snapshots.clear();
                self.error = Some(e.message);
            }
        }
    }

    pub fn set_import_list(&mut self, log: &mut UiLog, k: TrustListKind) {
        if self.import_list != k {
            self.import_list = k;
            log.note("ui_trust_list_kind_changed", json!({"list": k.name()}));
        }
    }

    /// The audited import run.
    pub fn import(
        &mut self,
        log: &mut UiLog,
        actor: &str,
        out_dir: &str,
        c: &Catalog,
    ) -> Result<PreparedOp, String> {
        let file = PathBuf::from(self.import_file.trim().trim_matches('"'));
        if !file.is_file() {
            return Err(format!("{}: {}", c.ui("err_tl_file"), file.display()));
        }
        if out_dir.trim().is_empty() {
            return Err(c.ui("err_out_dir"));
        }
        let store = self.store();
        let params = json!({"list": self.import_list.name(), "file": file.display().to_string(),
            "store": store.display().to_string()});
        log.note(
            "ui_operation_started",
            json!({"command": "trust-list import", "parameters": params}),
        );
        Ok(PreparedOp {
            kind: OpKind::TrustImport {
                list: self.import_list,
                file,
                store,
            },
            command: "trust-list import",
            params,
            out: PathBuf::from(out_dir.trim()),
            actor: actor.into(),
            preamble: log.drain(),
        })
    }

    /// Loads one snapshot (its recorded SHA-256 is checked by `trust_list::load`).
    pub fn inspect(&mut self, log: &mut UiLog, i: usize) {
        let Some(s) = self.snapshots.get(i) else {
            return;
        };
        let kind = if s.list == "co" {
            TrustListKind::Co
        } else {
            TrustListKind::Eu
        };
        log.note(
            "ui_trust_list_inspected",
            json!({"id": s.id, "sha256": s.sha256}),
        );
        match certs::trust_list::load(&self.store(), kind, &s.id) {
            Ok(snap) => {
                self.selected = Some(snap);
                self.error = None;
            }
            Err(e) => {
                self.selected = None;
                self.error = Some(e.message);
            }
        }
    }

    /// Services of the selected snapshot that match the filter, with the number of certificates of each.
    pub fn services(&self) -> Vec<(&TrustService, usize)> {
        let Some(s) = &self.selected else {
            return vec![];
        };
        let f = self.filter.trim().to_lowercase();
        s.services
            .iter()
            .filter(|x| {
                f.is_empty()
                    || [
                        &x.service_name,
                        &x.tsp_name,
                        &x.service_type,
                        &x.country,
                        &x.current_status,
                    ]
                    .iter()
                    .any(|v| v.to_lowercase().contains(&f))
            })
            .map(|x| {
                (
                    x,
                    s.entries
                        .iter()
                        .filter(|e| e.service_index == x.index)
                        .count(),
                )
            })
            .collect()
    }
}

/// The `--anchor` spelling of a snapshot.
pub fn anchor_spec(s: &TrustListSummary) -> String {
    format!("tl:{}@{}", s.list, s.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_list_inspect_a_colombian_csv() {
        let d = tempfile::tempdir().unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let der = std::fs::read(root.join("examples/sample/anchors/rakvor-lab-root.crt")).unwrap();
        let pem = String::from_utf8(der).unwrap();
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let csv = format!(
            "ecd_name,service_name,service_type,status,status_from,status_until,certificate_pem_or_b64,source_url,checked_utc\n\
             Lab ECD,Lab Root,CA,accredited,2025-01-01T00:00:00Z,,{b64},https://onac.example/lab,2026-11-01T00:00:00Z\n"
        );
        let f = d.path().join("co.csv");
        std::fs::write(&f, csv).unwrap();
        let mut t = TrustState {
            store_dir: d.path().join("store").display().to_string(),
            import_list: TrustListKind::Co,
            import_file: f.display().to_string(),
            ..Default::default()
        };
        let mut log = UiLog::default();
        let c = rv_certcheck_core::i18n::catalog("en");
        let op = t
            .import(
                &mut log,
                "tester",
                &d.path().join("runs").display().to_string(),
                c,
            )
            .unwrap();
        assert!(op.preamble.iter().any(|(a, _)| a == "ui_operation_started"));
        let r = super::super::create::execute(op);
        assert!(r.outcome.ok, "{:?}", r.outcome.error);
        let log_file = r.outcome.log_dir.join("audit.jsonl");
        assert!(rv_certcheck_core::audit::verify(&log_file).is_ok());
        assert!(
            std::fs::read_to_string(&log_file)
                .unwrap()
                .contains("\"trust_list_imported\"")
        );
        t.refresh();
        assert_eq!(t.snapshots.len(), 1);
        assert_eq!(t.snapshots[0].sha256.len(), 64);
        assert!(anchor_spec(&t.snapshots[0]).starts_with("tl:co@co-"));
        t.inspect(&mut log, 0);
        assert_eq!(t.services().len(), 1);
        t.filter = "nothing-like-this".into();
        assert!(t.services().is_empty());
    }
}
