//! Everything the window shows and every rule it enforces, without any drawing code.
//! Kept separate from `app.rs` so it can be unit-tested headless (CI has no display).
//!
//! ```text
//! GuiState ── Analyze tab: inputs, AnalyzeOptions (anchors, at, purpose, CRL/OCSP, online, PKCS#12 password),
//!          │               hashes, reports, trust ──► to_config ──► rv_certcheck_core::run (worker thread)
//!          │               ──► events (progress) ──► results table (chain::load_rows) ──► chain view (chain.rs)
//!          ├─ Create tab: create::CreateState (CA folder, wizards) ──► create::execute (worker thread)
//!          ├─ Trust lists tab: trust::TrustState ──► create::execute (trust-list import)
//!          └─ UiLog: every ui_* action with at_utc, written as the preamble of the next audited run
//! ```
//! Secrets (PKCS#12 password, key passwords, PINs) live in [`MaskedField`]s only: moved into a zeroizing
//! [`Secret`] for exactly one operation, never cloned, never printed, never in a ui_* action.

pub mod chain;
pub mod create;
pub mod trust;

use rv_certcheck_core::certs::{AnchorSpec, AtTime, Purpose, Secret, ValidationOptions};
use rv_certcheck_core::{
    CASE_ROLE, CertOptions, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, case, hash, i18n,
    time::human_duration,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    Idle,
    Running,
    Finished,
    Cancelled,
    Failed(String),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub elapsed_ms: u64,
    pub eta_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Outcome {
    pub items: u64,
    pub errors: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub report: PathBuf,
    pub report_dir: PathBuf,
    pub log_dir: PathBuf,
}

/// One item's link to the case registry, shown in the result panel.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceLink {
    pub index: u64,
    pub path: String,
    pub evidence_id: Option<String>,
    /// registered | already_registered | verified | mismatch | not_in_registry
    pub status: String,
}

pub const LANG_CHOICES: [(&str, &str); 4] = [
    ("en", "English"),
    ("es", "Español"),
    ("fr", "Français"),
    ("all", "All three (EN + ES + FR)"),
];

/// A password or PIN field. The text is moved (never copied) into a zeroizing [`Secret`] for one operation, and
/// zeroized when wiped or dropped. `Debug` never shows it.
#[derive(Default)]
pub struct MaskedField(String);

impl MaskedField {
    /// The buffer a masked text edit writes into.
    pub fn buffer(&mut self) -> &mut String {
        &mut self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Same text as `other` (confirmation fields), without exposing either.
    pub fn same_as(&self, other: &MaskedField) -> bool {
        self.0 == other.0
    }
    /// Moves the text into a Secret; the field is empty afterwards.
    pub fn take(&mut self) -> Secret {
        Secret::new(std::mem::take(&mut self.0))
    }
    /// None when empty; the field is empty afterwards either way.
    pub fn take_opt(&mut self) -> Option<Secret> {
        if self.0.is_empty() {
            None
        } else {
            Some(self.take())
        }
    }
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for MaskedField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() {
            "MaskedField(empty)"
        } else {
            "MaskedField(***)"
        })
    }
}

impl Drop for MaskedField {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The user actions recorded since the last audited run (each with `at_utc`), written as its preamble.
#[derive(Clone, Debug, Default)]
pub struct UiLog {
    pub actions: Vec<(String, Value)>,
}

impl UiLog {
    pub fn note(&mut self, action: &str, mut details: Value) {
        if let Some(o) = details.as_object_mut() {
            o.insert("at_utc".into(), json!(rv_certcheck_core::time::utc_now()));
        }
        self.actions.push((action.to_string(), details));
    }
    pub fn drain(&mut self) -> Vec<(String, Value)> {
        std::mem::take(&mut self.actions)
    }
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Analyze,
    Create,
    TrustLists,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Analyze, Tab::Create, Tab::TrustLists];
    pub fn name(&self) -> &'static str {
        match self {
            Tab::Analyze => "analyze",
            Tab::Create => "create",
            Tab::TrustLists => "trust_lists",
        }
    }
    pub fn key(&self) -> &'static str {
        match self {
            Tab::Analyze => "tab_analyze",
            Tab::Create => "tab_create",
            Tab::TrustLists => "tab_trust_lists",
        }
    }
}

/// The moment chains are judged at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AtChoice {
    #[default]
    Now,
    /// The date (or RFC 3339 time) in `AnalyzeOptions::at_date`.
    Date,
    /// The object's own signing time (timestamp genTime).
    SigningTime,
}

/// Which revocation file list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevFile {
    Crl,
    Ocsp,
}

/// The Analyze tab's certificate options (`analyze --anchor --at --purpose --crl --ocsp --online`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AnalyzeOptions {
    pub anchor_rakvor: bool,
    pub anchor_system: bool,
    pub anchor_files: Vec<PathBuf>,
    /// Trust-list snapshots used as anchors (`tl:eu@ID`, `tl:co@latest`).
    pub anchor_lists: Vec<String>,
    pub at: AtChoice,
    /// `YYYY-MM-DD` or RFC 3339.
    pub at_date: String,
    pub purpose: Purpose,
    pub crl_files: Vec<PathBuf>,
    pub ocsp_files: Vec<PathBuf>,
    pub online: bool,
}

impl AnalyzeOptions {
    /// The `--anchor` values in the CLI's order: rakvor, system, files, trust lists.
    pub fn anchors(&self) -> Result<Vec<AnchorSpec>, String> {
        let mut a = vec![];
        if self.anchor_rakvor {
            a.push(AnchorSpec::Rakvor);
        }
        if self.anchor_system {
            a.push(AnchorSpec::System);
        }
        for f in &self.anchor_files {
            a.push(AnchorSpec::File { path: f.clone() });
        }
        for l in &self.anchor_lists {
            a.push(AnchorSpec::parse(l).map_err(|e| e.message)?);
        }
        Ok(a)
    }

    pub fn at_time(&self) -> Result<AtTime, String> {
        match self.at {
            AtChoice::Now => Ok(AtTime::Now),
            AtChoice::SigningTime => Ok(AtTime::SigningTime),
            AtChoice::Date => AtTime::parse(&self.at_date).map_err(|e| e.message),
        }
    }

    /// The same ValidationOptions the CLI builds from its options (files checked to exist, as the CLI does).
    pub fn validation(&self, trust_list_dir: Option<PathBuf>) -> Result<ValidationOptions, String> {
        for f in self
            .crl_files
            .iter()
            .chain(&self.ocsp_files)
            .chain(&self.anchor_files)
        {
            if !f.is_file() {
                return Err(format!("no such file: {}", f.display()));
            }
        }
        Ok(ValidationOptions {
            anchors: self.anchors()?,
            at: self.at_time()?,
            purpose: self.purpose,
            crl_files: self.crl_files.clone(),
            ocsp_files: self.ocsp_files.clone(),
            online: self.online,
            trust_list_dir,
        })
    }
}

#[derive(Debug)]
pub struct GuiState {
    pub tab: Tab,
    pub inputs: Vec<PathBuf>,
    pub path_entry: String,
    pub recursive: bool,
    pub selected: Vec<HashAlgo>,
    pub lang: String,
    pub out_dir: String,
    pub actor: String,
    pub case_id: String,
    pub phase: Phase,
    pub progress: Progress,
    pub current_item: String,
    pub warnings: Vec<String>,
    pub outcome: Option<Outcome>,
    /// User actions recorded before the next audited run; handed to the core as audit preamble entries.
    pub ui: UiLog,
    /// Interface language (en/es/fr), independent from the report language.
    pub ui_lang: String,
    pub jurisdiction: String,
    pub timestamp: bool,
    pub tsa_url: String,
    pub sign_cert: String,
    /// Report-signing certificate password: one run only.
    pub sign_password: MaskedField,
    /// Shared case folder; when set, the output folder is derived from it and locked.
    pub case_dir: String,
    /// Evidence ids reported by the last run (case folder only).
    pub evidence: Vec<EvidenceLink>,
    pub analysis: AnalyzeOptions,
    /// Path being typed for an anchor / CRL / OCSP file.
    pub anchor_entry: String,
    pub crl_entry: String,
    pub ocsp_entry: String,
    /// Opens PKCS#12 items and encrypted keys among the evidence: one run only.
    pub p12_password: MaskedField,
    /// Results of the last run, one row per item.
    pub rows: Vec<chain::ResultRow>,
    /// The selected item's chain view.
    pub item: Option<chain::ItemView>,
    pub create: create::CreateState,
    pub trust: trust::TrustState,
}

impl Default for GuiState {
    fn default() -> Self {
        GuiState {
            tab: Tab::Analyze,
            inputs: vec![],
            path_entry: String::new(),
            recursive: true,
            selected: vec![HashAlgo::Sha256],
            lang: "en".into(),
            out_dir: "rakvor-out".into(),
            actor: rv_certcheck_core::env::os_user(),
            case_id: String::new(),
            phase: Phase::Idle,
            progress: Progress::default(),
            current_item: String::new(),
            warnings: vec![],
            outcome: None,
            ui: UiLog::default(),
            ui_lang: "en".into(),
            jurisdiction: "co".into(),
            timestamp: true,
            tsa_url: rv_certcheck_core::trust::DEFAULT_TSA.into(),
            sign_cert: String::new(),
            sign_password: MaskedField::default(),
            case_dir: String::new(),
            evidence: vec![],
            analysis: AnalyzeOptions::default(),
            anchor_entry: String::new(),
            crl_entry: String::new(),
            ocsp_entry: String::new(),
            p12_password: MaskedField::default(),
            rows: vec![],
            item: None,
            create: create::CreateState {
                out_dir: "rakvor-out".into(),
                ..Default::default()
            },
            trust: trust::TrustState::default(),
        }
    }
}

fn clean_path(s: &str) -> String {
    s.trim().trim_matches('"').trim().to_string()
}

impl GuiState {
    /// Records a user action with the time it happened (written to the audit log when the next run starts).
    fn note(&mut self, action: &str, details: Value) {
        self.ui.note(action, details);
    }

    /// The interface catalogue (static, so it can be held while a sub-state is borrowed mutably).
    pub fn catalog(&self) -> &'static i18n::Catalog {
        i18n::catalog(&self.ui_lang)
    }

    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }

    pub fn set_tab(&mut self, t: Tab) {
        if self.tab != t {
            self.tab = t;
            self.note("ui_tab_changed", json!({"tab": t.name()}));
            if t == Tab::TrustLists {
                self.trust.refresh();
            }
        }
    }

    /// A checkbox is clickable if it can be unticked (more than one ticked) or ticked (fewer than two ticked).
    pub fn can_toggle(&self, a: HashAlgo) -> bool {
        if self.selected.contains(&a) {
            self.selected.len() > 1
        } else {
            self.selected.len() < HashAlgo::MAX_SELECTED
        }
    }

    pub fn toggle_algo(&mut self, a: HashAlgo) -> Result<(), String> {
        if !self.can_toggle(a) {
            return Err(if self.selected.contains(&a) {
                "At least one hash algorithm is required.".into()
            } else {
                format!(
                    "At most {} hash algorithms can be selected.",
                    HashAlgo::MAX_SELECTED
                )
            });
        }
        if let Some(i) = self.selected.iter().position(|x| *x == a) {
            self.selected.remove(i);
        } else {
            self.selected.push(a);
        }
        self.note(
            "ui_hash_selection_changed",
            json!({"algorithms": self.selected}),
        );
        Ok(())
    }

    pub fn add_input(&mut self, p: PathBuf) {
        if !self.inputs.contains(&p) {
            self.note("ui_input_added", json!({"path": p.display().to_string()}));
            self.inputs.push(p);
        }
    }

    pub fn add_typed_path(&mut self) {
        let t = clean_path(&self.path_entry);
        if !t.is_empty() {
            self.add_input(PathBuf::from(t));
            self.path_entry.clear();
        }
    }

    pub fn remove_input(&mut self, i: usize) {
        if i < self.inputs.len() {
            let p = self.inputs.remove(i);
            self.note("ui_input_removed", json!({"path": p.display().to_string()}));
        }
    }

    pub fn set_lang(&mut self, l: &str) {
        if self.lang != l {
            self.lang = l.to_string();
            self.note("ui_language_changed", json!({"lang": l}));
        }
    }

    pub fn set_recursive(&mut self, r: bool) {
        if self.recursive != r {
            self.recursive = r;
            self.note("ui_recursive_changed", json!({"recursive": r}));
        }
    }

    // ---- certificate options --------------------------------------------------------------------------------

    pub fn set_anchor_builtin(&mut self, which: &str, on: bool) {
        let slot = match which {
            "rakvor" => &mut self.analysis.anchor_rakvor,
            "system" => &mut self.analysis.anchor_system,
            _ => return,
        };
        if *slot != on {
            *slot = on;
            self.note("ui_anchor_changed", json!({"anchor": which, "on": on}));
        }
    }

    /// Adds the path typed in `anchor_entry` (or `p`) as a trusted certificate file.
    pub fn add_anchor_file(&mut self, p: Option<PathBuf>) {
        let p = p.unwrap_or_else(|| PathBuf::from(clean_path(&self.anchor_entry)));
        if p.as_os_str().is_empty() || self.analysis.anchor_files.contains(&p) {
            return;
        }
        self.anchor_entry.clear();
        self.note(
            "ui_anchor_changed",
            json!({"anchor": format!("file:{}", p.display()), "on": true}),
        );
        self.analysis.anchor_files.push(p);
    }

    pub fn remove_anchor_file(&mut self, i: usize) {
        if i < self.analysis.anchor_files.len() {
            let p = self.analysis.anchor_files.remove(i);
            self.note(
                "ui_anchor_changed",
                json!({"anchor": format!("file:{}", p.display()), "on": false}),
            );
        }
    }

    /// Adds (or removes) a trust-list snapshot anchor `tl:<list>@<id>`.
    pub fn set_anchor_list(&mut self, spec: &str, on: bool) {
        let has = self.analysis.anchor_lists.iter().any(|s| s == spec);
        if on && !has {
            self.analysis.anchor_lists.push(spec.to_string());
        } else if !on && has {
            self.analysis.anchor_lists.retain(|s| s != spec);
        } else {
            return;
        }
        self.note("ui_anchor_changed", json!({"anchor": spec, "on": on}));
    }

    pub fn set_at(&mut self, at: AtChoice, date: &str) {
        let date = date.trim().to_string();
        if self.analysis.at != at || (at == AtChoice::Date && self.analysis.at_date != date) {
            self.analysis.at = at;
            self.analysis.at_date = date.clone();
            let shown = match at {
                AtChoice::Now => "now".to_string(),
                AtChoice::SigningTime => "signing-time".to_string(),
                AtChoice::Date => date,
            };
            self.note("ui_at_changed", json!({"at": shown}));
        } else {
            self.analysis.at_date = date;
        }
    }

    pub fn set_purpose(&mut self, p: Purpose) {
        if self.analysis.purpose != p {
            self.analysis.purpose = p;
            self.note("ui_purpose_changed", json!({"purpose": p.name()}));
        }
    }

    pub fn add_revocation_file(&mut self, kind: RevFile, p: Option<PathBuf>) {
        let entry = match kind {
            RevFile::Crl => &mut self.crl_entry,
            RevFile::Ocsp => &mut self.ocsp_entry,
        };
        let p = p.unwrap_or_else(|| PathBuf::from(clean_path(entry)));
        entry.clear();
        let list = match kind {
            RevFile::Crl => &mut self.analysis.crl_files,
            RevFile::Ocsp => &mut self.analysis.ocsp_files,
        };
        if p.as_os_str().is_empty() || list.contains(&p) {
            return;
        }
        list.push(p.clone());
        let k = if kind == RevFile::Crl { "crl" } else { "ocsp" };
        self.note(
            "ui_revocation_file_added",
            json!({"kind": k, "path": p.display().to_string()}),
        );
    }

    pub fn remove_revocation_file(&mut self, kind: RevFile, i: usize) {
        let list = match kind {
            RevFile::Crl => &mut self.analysis.crl_files,
            RevFile::Ocsp => &mut self.analysis.ocsp_files,
        };
        if i < list.len() {
            let p = list.remove(i);
            let k = if kind == RevFile::Crl { "crl" } else { "ocsp" };
            self.note(
                "ui_revocation_file_removed",
                json!({"kind": k, "path": p.display().to_string()}),
            );
        }
    }

    pub fn set_online(&mut self, on: bool) {
        if self.analysis.online != on {
            self.analysis.online = on;
            self.note("ui_online_revocation_changed", json!({"online": on}));
        }
    }

    /// Validation options as the CLI would build them; trust-list anchors resolve in the Trust lists tab's folder.
    pub fn validation_options(&self) -> Result<ValidationOptions, String> {
        self.analysis.validation(Some(self.trust.store()))
    }

    /// GUI text in the interface language.
    pub fn tr(&self, key: &str) -> String {
        i18n::catalog(&self.ui_lang).ui(key)
    }

    pub fn set_ui_lang(&mut self, l: &str) {
        if self.ui_lang != l && ["en", "es", "fr"].contains(&l) {
            self.ui_lang = l.to_string();
            self.note("ui_interface_language_changed", json!({"ui_lang": l}));
        }
    }

    pub fn set_jurisdiction(&mut self, j: &str) {
        if self.jurisdiction != j && (j == "co" || j == "fr") {
            self.jurisdiction = j.to_string();
            self.note("ui_jurisdiction_changed", json!({"jurisdiction": j}));
        }
    }

    pub fn set_timestamp(&mut self, on: bool, url: &str) {
        let url = url.trim().to_string();
        if self.timestamp != on || self.tsa_url != url {
            self.timestamp = on;
            self.tsa_url = url.clone();
            self.note(
                "ui_timestamp_changed",
                json!({"enabled": on, "tsa_url": url}),
            );
        }
    }

    pub fn set_sign_cert(&mut self, path: &str) {
        let path = clean_path(path);
        if self.sign_cert != path {
            self.sign_cert = path.clone();
            self.note(
                "ui_signing_certificate_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }}),
            );
        }
    }

    /// Rule: with a case folder the output folder is `<case>/runs/<tool>/<RUN-ID>` and cannot be edited.
    pub fn set_case_dir(&mut self, path: &str) {
        let path = clean_path(path);
        if self.case_dir != path {
            self.case_dir = path.clone();
            self.note(
                "ui_case_dir_changed",
                json!({"path": if path.is_empty() { Value::Null } else { json!(path) }, "role": CASE_ROLE.name()}),
            );
        }
    }

    /// The case folder given by RV Hub (`--case-dir`): preset like a typed folder (`ui_case_dir_changed`) and
    /// recorded as `ui_case_dir_from_launcher`, so the audit log shows the folder was not chosen in the GUI.
    pub fn set_case_dir_from_launcher(&mut self, path: &std::path::Path) {
        let shown = path.display().to_string();
        self.note("ui_case_dir_from_launcher", json!({"path": shown}));
        self.set_case_dir(&shown);
    }

    /// A launch argument that was ignored (e.g. `--case-dir` without a folder), recorded in the audit log.
    pub fn note_launch_problem(&mut self, problem: &str) {
        self.note("ui_launch_argument_ignored", json!({"problem": problem}));
    }

    pub fn out_locked(&self) -> bool {
        !self.case_dir.trim().is_empty()
    }

    /// What the output-folder field shows: the derived run folder when a case folder is set.
    pub fn out_dir_display(&self) -> String {
        if self.out_locked() {
            PathBuf::from(self.case_dir.trim())
                .join("runs")
                .join(TOOL_NAME)
                .join("<RUN-ID>")
                .display()
                .to_string()
        } else {
            self.out_dir.clone()
        }
    }

    /// Result-panel lines: "E0001  acta.txt  — Verified: identical to the registered evidence".
    pub fn evidence_lines(&self) -> Vec<String> {
        let c = i18n::catalog(&self.ui_lang);
        self.evidence
            .iter()
            .map(|e| {
                let name = Path::new(&e.path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| e.path.clone());
                format!(
                    "{}  {}  \u{2014} {}",
                    e.evidence_id.as_deref().unwrap_or("\u{2014}"),
                    name,
                    c.label(&format!("case_status_{}", e.status))
                )
            })
            .collect()
    }

    pub fn can_start(&self) -> bool {
        !self.is_running()
            && (!self.inputs.is_empty() || self.out_locked())
            && (self.out_locked() || !self.out_dir.trim().is_empty())
    }

    /// Builds the run configuration; the recorded UI actions become audit preamble entries. Only once every check
    /// has passed are the PKCS#12 and signing passwords moved out of their fields into the configuration (they
    /// are dropped, zeroized, with it when the run ends).
    pub fn to_config(&mut self) -> Result<RunConfig, String> {
        if self.inputs.is_empty() && !self.out_locked() {
            return Err("Add at least one file or folder.".into());
        }
        hash::validate_selection(&self.selected)?;
        let case_id = Some(self.case_id.trim().to_string()).filter(|s| !s.is_empty());
        if self.out_locked() {
            case::preflight(Path::new(self.case_dir.trim()), case_id.as_deref(), &[])
                .map_err(|e| e.message)?;
        }
        let langs = i18n::parse_langs(&self.lang)?;
        if !self.sign_cert.is_empty() && !Path::new(&self.sign_cert).is_file() {
            return Err(format!("Signing certificate not found: {}", self.sign_cert));
        }
        let validation = self.validation_options()?;
        let mut preamble = self.ui.actions.clone();
        let anchors: Vec<String> = validation.anchors.iter().map(|a| a.describe()).collect();
        preamble.push(("ui_start_clicked".into(), json!({"algorithms": self.selected, "lang": self.lang, "recursive": self.recursive,
            "inputs": self.inputs.len(), "jurisdiction": self.jurisdiction, "timestamp": self.timestamp,
            "pdf_signing": !self.sign_cert.is_empty(), "case_dir": if self.out_locked() { json!(self.case_dir.trim()) } else { Value::Null },
            "anchors": anchors, "at": validation.at.describe(), "purpose": validation.purpose.name(),
            "crl_files": validation.crl_files.len(), "ocsp_files": validation.ocsp_files.len(), "online": validation.online,
            "p12_password": if self.p12_password.is_empty() { "none" } else { "supplied (not recorded)" },
            "at_utc": rv_certcheck_core::time::utc_now()})));
        let list = |v: &[PathBuf]| {
            v.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(";")
        };
        let settings = vec![
            format!("{} (gui)", TOOL_NAME),
            format!("inputs={}", list(&self.inputs)),
            format!(
                "hash={}",
                self.selected
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            format!("lang={}", self.lang),
            format!("recursive={}", self.recursive),
            format!("out={}", self.out_dir_display().trim()),
            format!(
                "case_dir={}",
                if self.out_locked() {
                    self.case_dir.trim()
                } else {
                    "none"
                }
            ),
            format!("jurisdiction={}", self.jurisdiction),
            format!(
                "tsa={}",
                if self.timestamp {
                    self.tsa_url.as_str()
                } else {
                    "off"
                }
            ),
            format!(
                "sign_cert={}",
                if self.sign_cert.is_empty() {
                    "none"
                } else {
                    self.sign_cert.as_str()
                }
            ),
            format!("anchor={}", anchors.join(";")),
            format!("at={}", validation.at.describe()),
            format!("purpose={}", validation.purpose.name()),
            format!("crl={}", list(&validation.crl_files)),
            format!("ocsp={}", list(&validation.ocsp_files)),
            format!("online={}", validation.online),
        ];
        // Every check passed: the secrets move into the configuration.
        let p12_password = self.p12_password.take_opt();
        let sign_password = self
            .sign_password
            .take_opt()
            .map(|s| s.expose().to_string());
        Ok(RunConfig {
            inputs: self.inputs.clone(),
            input_list: None,
            recursive: self.recursive,
            algorithms: self.selected.clone(),
            out_dir: PathBuf::from(self.out_dir.trim()),
            langs,
            actor: if self.actor.trim().is_empty() {
                rv_certcheck_core::env::os_user()
            } else {
                self.actor.trim().to_string()
            },
            case_id,
            frontend: "gui".into(),
            preamble,
            command_line: settings,
            tool_name: TOOL_NAME.into(),
            tool_version: TOOL_VERSION.into(),
            jurisdiction: self.jurisdiction.clone(),
            tsa_url: if self.timestamp {
                Some(self.tsa_url.clone())
            } else {
                None
            },
            sign_cert: if self.sign_cert.is_empty() {
                None
            } else {
                Some(PathBuf::from(&self.sign_cert))
            },
            sign_password,
            case_dir: if self.out_locked() {
                Some(PathBuf::from(self.case_dir.trim()))
            } else {
                None
            },
            evidence_ids: vec![],
            case_role: CASE_ROLE,
            cert: CertOptions {
                validation,
                p12_password,
            },
        })
    }

    pub fn start(&mut self) {
        self.phase = Phase::Running;
        self.progress = Progress::default();
        self.current_item.clear();
        self.warnings.clear();
        self.outcome = None;
        self.evidence.clear();
        self.rows.clear();
        self.item = None;
        // Recorded actions now belong to this run's audit log.
        self.ui.actions.clear();
        // Nothing secret stays in the window once the run has its own copy.
        self.p12_password.wipe();
        self.sign_password.wipe();
    }

    pub fn apply(&mut self, e: &Event) {
        match e {
            Event::RunStarted {
                total_items,
                total_bytes,
                ..
            } => {
                self.progress.total = *total_items;
                self.progress.bytes_total = *total_bytes;
            }
            Event::ItemStarted { path, .. } => self.current_item = path.clone(),
            Event::EvidenceLinked {
                index,
                path,
                evidence_id,
                status,
            } => self.evidence.push(EvidenceLink {
                index: *index,
                path: path.clone(),
                evidence_id: evidence_id.clone(),
                status: status.clone(),
            }),
            Event::Progress {
                done,
                total,
                bytes_done,
                bytes_total,
                elapsed_ms,
                eta_ms,
            } => {
                self.progress = Progress {
                    done: *done,
                    total: *total,
                    bytes_done: *bytes_done,
                    bytes_total: *bytes_total,
                    elapsed_ms: *elapsed_ms,
                    eta_ms: *eta_ms,
                };
            }
            Event::Error { path, message } => {
                self.warnings
                    .push(format!("{}: {}", path.as_deref().unwrap_or("-"), message))
            }
            Event::Timestamp { status, reason, .. } if status != "ok" => self
                .warnings
                .push(format!("timestamp: {}", reason.as_deref().unwrap_or("-"))),
            Event::RunFinished {
                items,
                errors,
                high,
                medium,
                low,
                info,
                report_dir,
                log_dir,
                cancelled,
                elapsed_ms,
                ..
            } => {
                self.progress.elapsed_ms = *elapsed_ms;
                self.progress.eta_ms = None;
                let lang = if self.lang == "all" {
                    "en".to_string()
                } else {
                    self.lang.clone()
                };
                self.outcome = Some(Outcome {
                    items: *items,
                    errors: *errors,
                    high: *high,
                    medium: *medium,
                    low: *low,
                    info: *info,
                    report: PathBuf::from(report_dir).join(format!("statistics.{}.html", lang)),
                    report_dir: PathBuf::from(report_dir),
                    log_dir: PathBuf::from(log_dir),
                });
                self.phase = if *cancelled {
                    Phase::Cancelled
                } else {
                    Phase::Finished
                };
                self.current_item.clear();
                match chain::load_rows(Path::new(report_dir)) {
                    Ok(r) => self.rows = r,
                    Err(e) => self.warnings.push(e),
                }
            }
            _ => {}
        }
    }

    pub fn fail(&mut self, msg: String) {
        self.phase = Phase::Failed(msg);
    }

    /// Opens the chain view of result row `i` (audited as ui_item_selected).
    pub fn select_row(&mut self, i: usize) {
        let Some(r) = self.rows.get(i) else { return };
        if self.item.as_ref().map(|v| v.row) == Some(i) {
            return;
        }
        let details = json!({"index": r.index, "path": r.path});
        self.item = Some(chain::load_item(i, r));
        self.note("ui_item_selected", details);
    }

    /// Shows the fields of node `node` of tree `tree` in the chain view.
    pub fn select_node(&mut self, tree: usize, node: usize) {
        if let Some(v) = &mut self.item
            && v.trees.get(tree).is_some_and(|t| node < t.nodes.len())
        {
            v.selected = Some((tree, node));
        }
    }

    /// 0.0..=1.0, by bytes (or by files when every file is empty).
    pub fn fraction(&self) -> f32 {
        let p = &self.progress;
        if p.bytes_total > 0 {
            (p.bytes_done as f64 / p.bytes_total as f64).clamp(0.0, 1.0) as f32
        } else if p.total > 0 {
            (p.done as f64 / p.total as f64) as f32
        } else if matches!(self.phase, Phase::Finished) {
            1.0
        } else {
            0.0
        }
    }

    /// `live_elapsed_ms` is measured by the window clock so the timer keeps moving between events.
    pub fn timing_text(&self, live_elapsed_ms: Option<u64>) -> String {
        let elapsed = live_elapsed_ms
            .unwrap_or(self.progress.elapsed_ms)
            .max(self.progress.elapsed_ms);
        let eta = match self.progress.eta_ms {
            Some(ms) if self.is_running() => human_duration(ms),
            _ => "\u{2014}".into(),
        };
        format!(
            "{}: {}   \u{00B7}   {}: {}",
            self.tr("elapsed"),
            human_duration(elapsed),
            self.tr("remaining"),
            eta
        )
    }

    pub fn progress_text(&self) -> String {
        format!(
            "{} / {} {}  \u{00B7}  {:.0}%",
            self.progress.done,
            self.progress.total,
            self.tr("files"),
            self.fraction() * 100.0
        )
    }

    // ---- Create and Trust lists tabs ------------------------------------------------------------------------

    /// The actor of creation runs (the Analyze tab's examiner field).
    pub fn actor_name(&self) -> String {
        if self.actor.trim().is_empty() {
            rv_certcheck_core::env::os_user()
        } else {
            self.actor.trim().to_string()
        }
    }

    pub fn create_open_ca(&mut self) -> Result<create::PreparedOp, String> {
        let (c, actor) = (self.catalog(), self.actor_name());
        self.create.open_ca(&mut self.ui, &actor, c)
    }

    pub fn create_verify_ca(&mut self) -> Result<create::PreparedOp, String> {
        let (c, actor) = (self.catalog(), self.actor_name());
        self.create.verify_ca(&mut self.ui, &actor, c)
    }

    pub fn create_list_tokens(&mut self) -> Result<create::PreparedOp, String> {
        let (c, actor) = (self.catalog(), self.actor_name());
        self.create.list_tokens(&mut self.ui, &actor, c)
    }

    pub fn create_set_wizard(&mut self, w: Option<create::Wizard>) {
        self.create.set_wizard(&mut self.ui, w);
    }

    pub fn create_set_profile(
        &mut self,
        p: rv_certcheck_core::certs::IssueProfile,
    ) -> Result<(), String> {
        let c = self.catalog();
        self.create.set_profile(&mut self.ui, p, c)
    }

    pub fn create_set_key_mode(&mut self, w: create::Wizard, m: create::KeyMode) {
        self.create.set_key_mode(&mut self.ui, w, m);
    }

    pub fn create_set_confirm_root(&mut self, on: bool) {
        self.create.set_confirm_root(&mut self.ui, on);
    }

    pub fn create_use_token(&mut self, w: create::Wizard, serial: &str) {
        self.create.use_token(&mut self.ui, w, serial);
    }

    pub fn create_prepare(&mut self) -> Result<create::PreparedOp, String> {
        let (c, actor) = (self.catalog(), self.actor_name());
        self.create.prepare(&mut self.ui, &actor, c)
    }

    pub fn create_finish(&mut self, r: create::OpResult) {
        let snapshots = matches!(r.outcome.command.as_str(), "trust-list import");
        self.create.finish(r);
        if snapshots {
            self.trust.refresh();
        }
    }

    pub fn trust_import(&mut self) -> Result<create::PreparedOp, String> {
        let (c, actor) = (self.catalog(), self.actor_name());
        let out = self.create.out_dir.clone();
        self.trust.import(&mut self.ui, &actor, &out, c)
    }

    pub fn trust_set_import_list(&mut self, k: rv_certcheck_core::certs::TrustListKind) {
        self.trust.set_import_list(&mut self.ui, k);
    }

    pub fn trust_inspect(&mut self, i: usize) {
        self.trust.inspect(&mut self.ui, i);
    }
}

#[cfg(test)]
mod tests {
    use super::create::{KeyMode, Wizard, execute};
    use super::*;
    use rv_certcheck_core::certs::IssueProfile;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn issue_key_type_follows_the_library_default_per_profile_and_examiner_stays_rsa() {
        use rv_certcheck_core::certs::{KeySpec, pki};
        let mut s = GuiState::default();
        assert_eq!(s.create.issue.profile, IssueProfile::Examiner);
        assert_eq!(s.create.issue.key_type, KeySpec::Rsa3072);
        assert_eq!(s.create.root.key_type, KeySpec::Rsa4096);
        for (p, want) in [
            (IssueProfile::Intermediate, KeySpec::P384),
            (IssueProfile::Tsa, KeySpec::P256),
            (IssueProfile::TlsServer, KeySpec::P256),
            (IssueProfile::CodeSigning, KeySpec::Rsa3072),
            (IssueProfile::Examiner, KeySpec::Rsa3072),
        ] {
            s.create_set_profile(p).unwrap();
            assert_eq!(s.create.issue.key_type, want, "{p:?}");
            assert_eq!(pki::default_key_spec(p), want);
        }
        // An EC examiner key is refused in the form, before any key is made.
        s.set_tab(Tab::Create);
        s.create_set_wizard(Some(Wizard::Issue));
        let i = &mut s.create.issue;
        i.subject = "C=CO,O=Rakvor Test,CN=Ana Ruiz".into();
        i.key_type = KeySpec::P256;
        i.ca_secret.buffer().push_str("ca-pw");
        i.p12_password.buffer().push_str("p12-pw");
        i.p12_again.buffer().push_str("p12-pw");
        let e = match s.create_prepare() {
            Ok(_) => panic!("an EC examiner key must be refused"),
            Err(e) => e,
        };
        assert!(e.contains("RSA"), "{e}");
    }

    #[test]
    fn at_most_two_and_at_least_one_algorithm() {
        let mut s = GuiState::default();
        assert_eq!(s.selected, vec![HashAlgo::Sha256]);
        assert!(
            !s.can_toggle(HashAlgo::Sha256),
            "cannot untick the last one"
        );
        assert!(s.toggle_algo(HashAlgo::Sha256).is_err());
        s.toggle_algo(HashAlgo::Md5).unwrap();
        assert!(
            !s.can_toggle(HashAlgo::Blake3),
            "third checkbox is disabled"
        );
        assert!(s.toggle_algo(HashAlgo::Blake3).is_err());
        s.toggle_algo(HashAlgo::Sha256).unwrap();
        assert_eq!(s.selected, vec![HashAlgo::Md5]);
    }

    #[test]
    fn settings_changes_become_audit_preamble() {
        let mut s = GuiState::default();
        assert!(s.to_config().is_err(), "no input yet");
        s.path_entry = "\"C:\\evidence\"".into();
        s.add_typed_path();
        s.toggle_algo(HashAlgo::Blake3).unwrap();
        s.set_lang("es");
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.inputs, vec![PathBuf::from("C:\\evidence")]);
        assert_eq!(cfg.frontend, "gui");
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "ui_input_added",
                "ui_hash_selection_changed",
                "ui_language_changed",
                "ui_start_clicked"
            ]
        );
        assert!(cfg.preamble.iter().all(|(_, d)| d["at_utc"].is_string()));
        s.start();
        assert!(s.ui.is_empty());
    }

    #[test]
    fn analysis_options_map_to_validation_options() {
        let mut s = GuiState::default();
        let anchor = root().join("examples/sample/anchors/rakvor-lab-root.crt");
        let crl = root().join("examples/sample/evidence/intermediate.crl");
        // Defaults are the CLI's defaults: no anchor, now, any purpose, offline.
        let v = s.validation_options().unwrap();
        assert_eq!(
            (v.anchors.clone(), v.at.clone(), v.purpose, v.online),
            (vec![], AtTime::Now, Purpose::Any, false)
        );
        s.set_anchor_builtin("rakvor", true);
        s.anchor_entry = format!("\"{}\"", anchor.display());
        s.add_anchor_file(None);
        s.set_anchor_list("tl:co@latest", true);
        s.set_at(AtChoice::Date, "2026-06-01");
        s.set_purpose(Purpose::TlsServer);
        s.add_revocation_file(RevFile::Crl, Some(crl.clone()));
        s.set_online(true);
        let v = s.validation_options().unwrap();
        assert_eq!(
            v,
            ValidationOptions {
                anchors: vec![
                    AnchorSpec::Rakvor,
                    AnchorSpec::File {
                        path: anchor.clone()
                    },
                    AnchorSpec::TrustList {
                        list: rv_certcheck_core::certs::TrustListKind::Co,
                        snapshot: "latest".into()
                    },
                ],
                at: AtTime::Fixed("2026-06-01T00:00:00Z".into()),
                purpose: Purpose::TlsServer,
                crl_files: vec![crl.clone()],
                ocsp_files: vec![],
                online: true,
                trust_list_dir: Some(s.trust.store()),
            }
        );
        s.set_at(AtChoice::SigningTime, "");
        assert_eq!(s.validation_options().unwrap().at, AtTime::SigningTime);
        s.set_at(AtChoice::Date, "yesterday");
        assert!(s.validation_options().is_err(), "a bad date is refused");
        s.set_at(AtChoice::Date, "2026-06-01T14:00:00+02:00");
        assert_eq!(
            s.validation_options().unwrap().at,
            AtTime::Fixed("2026-06-01T12:00:00Z".into())
        );
        s.add_revocation_file(RevFile::Ocsp, Some(PathBuf::from("missing.der")));
        assert!(
            s.validation_options().is_err(),
            "a missing OCSP file is refused"
        );
        s.remove_revocation_file(RevFile::Ocsp, 0);
        s.add_input(PathBuf::from("."));
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.cert.validation.purpose, Purpose::TlsServer);
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        for a in [
            "ui_anchor_changed",
            "ui_at_changed",
            "ui_purpose_changed",
            "ui_revocation_file_added",
            "ui_online_revocation_changed",
        ] {
            assert!(actions.contains(&a), "{a} audited");
        }
        let start = &cfg.preamble.last().unwrap().1;
        assert_eq!(start["at"], "2026-06-01T12:00:00Z");
        assert_eq!(start["online"], true);
    }

    #[test]
    fn masked_fields_are_wiped_after_use_and_never_shown() {
        let mut f = MaskedField::default();
        f.buffer().push_str("Pa55-word!");
        assert_eq!(format!("{f:?}"), "MaskedField(***)");
        let s = f.take();
        assert!(f.is_empty(), "taken = moved out");
        assert_eq!(s.expose(), "Pa55-word!");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        f.buffer().push_str("again");
        f.wipe();
        assert!(f.is_empty());

        // Analyze: the PKCS#12 and signing passwords go into one run's configuration, then the fields are empty.
        let mut g = GuiState::default();
        g.add_input(PathBuf::from("."));
        g.p12_password.buffer().push_str("p12-Secret-1");
        g.sign_password.buffer().push_str("sign-Secret-2");
        assert!(
            !format!("{g:?}").contains("p12-Secret-1"),
            "Debug of the state hides secrets"
        );
        g.set_at(AtChoice::Date, "not a date");
        assert!(g.to_config().is_err());
        assert!(
            !g.p12_password.is_empty(),
            "a refused start keeps what was typed"
        );
        g.set_at(AtChoice::Now, "");
        let cfg = g.to_config().unwrap();
        assert!(g.p12_password.is_empty() && g.sign_password.is_empty());
        assert_eq!(
            cfg.cert.p12_password.as_ref().unwrap().expose(),
            "p12-Secret-1"
        );
        assert_eq!(cfg.sign_password.as_deref(), Some("sign-Secret-2"));
        let audit = serde_json::to_string(&cfg.preamble).unwrap() + &cfg.command_line.join(" ");
        assert!(!audit.contains("p12-Secret-1") && !audit.contains("sign-Secret-2"));
        assert!(audit.contains("supplied (not recorded)"));

        // Create: switching wizard wipes what was typed for the previous one.
        g.create_set_wizard(Some(Wizard::Crl));
        g.create.crl.ca_secret.buffer().push_str("ca-Secret-3");
        g.create_set_wizard(Some(Wizard::Lab));
        assert!(g.create.secrets_empty());
    }

    #[test]
    fn wizard_rules_san_client_internal_and_confirm_root() {
        let mut s = GuiState::default();
        let c = s.catalog();
        // Root on a token needs the explicit confirm-root checkbox.
        s.create_set_wizard(Some(Wizard::NewRoot));
        s.create.root.ca_dir = "x/root".into();
        s.create.root.ca_id = "rakvor-root-test".into();
        s.create.root.subject = "C=CO,O=Rakvor,CN=Test Root".into();
        s.create_set_key_mode(Wizard::NewRoot, KeyMode::Token);
        s.create.root.key.module = "/usr/lib/softhsm/libsofthsm2.so".into();
        s.create.root.key.token_serial = "1234".into();
        s.create.root.key.pin.buffer().push_str("123456");
        assert_eq!(s.create_prepare().unwrap_err(), c.ui("err_confirm_root"));
        assert!(
            !s.create.root.key.pin.is_empty(),
            "nothing taken from a refused form"
        );
        s.create_set_confirm_root(true);
        let op = s
            .create_prepare()
            .expect("confirmed token root is accepted by the form");
        assert!(s.create.secrets_empty(), "the PIN moved into the request");
        let params = op.params.to_string();
        assert!(!params.contains("123456") && params.contains("\"confirm_root\":true"));
        assert!(
            op.preamble
                .iter()
                .any(|(a, _)| a == "ui_confirm_root_changed")
        );
        drop(op);

        // client-internal is shown disabled with its reason, and refused.
        let choices = create::profile_choices();
        let ci = choices
            .iter()
            .find(|(p, ..)| *p == IssueProfile::ClientInternal)
            .unwrap();
        assert_eq!(
            (ci.1, ci.2),
            (false, Some("profile_client_internal_reason"))
        );
        assert!(choices.iter().filter(|(_, on, _)| *on).count() == 5);
        assert_eq!(
            s.create_set_profile(IssueProfile::ClientInternal)
                .unwrap_err(),
            c.ui("profile_client_internal_reason")
        );
        s.create_set_wizard(Some(Wizard::Issue));
        s.create.issue.profile = IssueProfile::ClientInternal; // even when forced past the dropdown
        assert_eq!(
            s.create_prepare().unwrap_err(),
            c.ui("profile_client_internal_reason")
        );

        // tls-server needs a dns: or ip: SAN.
        s.create_set_profile(IssueProfile::TlsServer).unwrap();
        s.create.issue.subject = "C=CO,O=Rakvor,CN=hub".into();
        s.create.issue.sans = "email:ops@rakvor.co".into();
        s.create.issue.ca_secret.buffer().push_str("ca-pass");
        s.create.issue.key.password.buffer().push('k');
        s.create.issue.key.password_again.buffer().push('k');
        assert_eq!(s.create_prepare().unwrap_err(), c.ui("err_tls_san"));
        s.create.issue.sans = "dns:hub.rakvor.local".into();
        assert_eq!(
            s.create_prepare().unwrap_err(),
            c.ui("err_open_ca_first"),
            "the form is valid; it needs an open CA folder"
        );
        // A mistyped confirmation is refused.
        s.create.issue.key.password_again.wipe();
        s.create.issue.key.password_again.buffer().push_str("other");
        s.create.ca = None;
        assert_eq!(
            s.create_prepare().unwrap_err(),
            c.ui("err_passwords_differ")
        );
    }

    /// Every `tr("…")` key app.rs uses exists, and en/es/fr have exactly the same `ui` keys.
    #[test]
    fn ui_key_sets_are_identical_and_complete() {
        let keys = |l: &str| -> std::collections::BTreeSet<String> {
            let v: Value = serde_json::from_slice(
                &std::fs::read(root().join(format!("i18n/{l}.json"))).unwrap(),
            )
            .unwrap();
            v["ui"].as_object().unwrap().keys().cloned().collect()
        };
        let (en, es, fr) = (keys("en"), keys("es"), keys("fr"));
        assert_eq!(en, es, "es ui keys differ from en");
        assert_eq!(en, fr, "fr ui keys differ from en");
        let mut used = std::collections::BTreeSet::new();
        let sources = [
            include_str!("app.rs"),
            include_str!("state/chain.rs"),
            include_str!("state/create.rs"),
            include_str!("state/trust.rs"),
            include_str!("state.rs"),
        ];
        for src in sources {
            // Code only (the tests type arbitrary strings).
            let src = src.split("#[cfg(test)]").next().unwrap_or_default();
            for pat in ["tr(\"", "c.ui(\"", "t(\""] {
                for (at, _) in src.match_indices(pat) {
                    let before = src[..at].chars().next_back().unwrap_or(' ');
                    if before.is_alphanumeric() || before == '_' {
                        continue; // e.g. id_salt("…"), not t("…")
                    }
                    let rest = &src[at + pat.len()..];
                    if let Some(k) = rest.split('"').next()
                        && !k.is_empty()
                        && k.chars()
                            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
                    {
                        used.insert(k.to_string());
                    }
                }
            }
        }
        // Keys built at run time.
        for k in [
            "status_ok",
            "status_attention",
            "status_problem",
            "wz_new_root_help",
            "wz_import_help",
            "wz_issue_help",
            "wz_revoke_help",
            "wz_crl_help",
            "wz_csr_help",
            "wz_lab_help",
        ]
        .into_iter()
        .map(String::from)
        .chain(
            IssueProfile::ALL
                .iter()
                .map(|p| format!("profile_{}_help", p.name().replace('-', "_"))),
        ) {
            used.insert(k);
        }
        for k in chain::cert_fields(&Default::default())
            .iter()
            .map(|(k, _)| *k)
            .chain([
                "badge_ok",
                "badge_error",
                "badge_incomplete",
                "chain_valid",
                "chain_untrusted",
                "chain_invalid",
            ])
            .chain(Tab::ALL.iter().map(|t| t.key()))
        {
            used.insert(k.to_string());
        }
        for w in Wizard::ALL {
            used.insert(w.key());
        }
        let missing: Vec<&String> = used.iter().filter(|k| !en.contains(*k)).collect();
        assert!(
            missing.is_empty(),
            "ui keys used but missing in i18n: {missing:?}"
        );
    }

    #[test]
    fn interface_language_and_trust_settings_are_audited() {
        let mut s = GuiState::default();
        s.set_ui_lang("fr");
        assert_eq!(s.tr("start"), "Lancer l'analyse");
        s.set_ui_lang("es");
        assert_eq!(s.tr("start"), "Iniciar revisión");
        s.set_jurisdiction("fr");
        s.set_timestamp(false, "http://tsa.example");
        s.set_sign_cert("missing.p12");
        s.set_tab(Tab::Create);
        s.add_input(PathBuf::from("."));
        assert!(s.to_config().is_err(), "missing certificate refused");
        s.set_sign_cert("");
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.jurisdiction, "fr");
        assert!(cfg.tsa_url.is_none());
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert!(
            actions.contains(&"ui_interface_language_changed")
                && actions.contains(&"ui_timestamp_changed")
                && actions.contains(&"ui_tab_changed")
        );
    }

    #[test]
    fn case_folder_locks_the_output_folder_and_shows_evidence_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp = tmp.path();
        std::fs::create_dir_all(tmp.join("ev")).unwrap();
        std::fs::write(tmp.join("ev/a.txt"), "a").unwrap();
        std::fs::write(tmp.join("ev/b.txt"), "b").unwrap();
        let mut s = GuiState {
            timestamp: false,
            ..Default::default()
        };
        assert!(!s.can_start());
        let case_dir = tmp.join("CASE-G");
        s.set_case_dir(&format!("\"{}\"", case_dir.display()));
        assert!(
            s.out_locked() && s.can_start(),
            "a case folder alone can start (registered items)"
        );
        assert!(s.out_dir_display().contains("runs") && s.out_dir_display().ends_with("<RUN-ID>"));
        assert!(s.to_config().is_err(), "creating a case needs a case id");
        s.case_id = "CASE-G".into();
        s.add_input(tmp.join("ev"));
        if CASE_ROLE == rv_certcheck_core::CaseRole::Analysis {
            // An analysis tool verifies against a registry: create it with an explicit intake run first.
            let seed = RunConfig {
                inputs: vec![tmp.join("ev")],
                case_id: Some("CASE-G".into()),
                case_dir: Some(case_dir.clone()),
                case_role: rv_certcheck_core::CaseRole::Intake,
                ..Default::default()
            };
            let off = std::sync::atomic::AtomicBool::new(false);
            rv_certcheck_core::run(&seed, &mut |_| {}, &off).unwrap();
        }
        let cfg = s.to_config().unwrap();
        assert_eq!(cfg.case_dir.as_deref(), Some(case_dir.as_path()));
        let actions: Vec<&str> = cfg.preamble.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(actions[0], "ui_case_dir_changed");
        s.start();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let summary = rv_certcheck_core::run(&cfg, &mut |e| s.apply(e), &cancel).unwrap();
        assert_eq!(s.phase, Phase::Finished);
        assert!(summary.log_dir.starts_with(&case_dir));
        let ids: Vec<Option<&str>> = s
            .evidence
            .iter()
            .map(|e| e.evidence_id.as_deref())
            .collect();
        assert_eq!(ids, vec![Some("E0001"), Some("E0002")]);
        assert!(s.evidence_lines()[0].starts_with("E0001  a.txt"));
        s.set_case_dir("");
        assert!(!s.out_locked() && s.out_dir_display() == "rakvor-out");
    }

    /// The sample analysed at 2026-06-01 with the lab root: results table, chain tree of the revoked leaf, its
    /// fields and certificate.txt; the run is audited with the GUI's settings.
    #[test]
    fn sample_run_gives_results_and_a_chain_view() {
        let out = tempfile::tempdir().unwrap();
        let sample = root().join("examples/sample");
        let mut s = GuiState {
            timestamp: false,
            ..Default::default()
        };
        s.add_input(sample.join("evidence"));
        s.add_anchor_file(Some(sample.join("anchors/rakvor-lab-root.crt")));
        s.set_at(AtChoice::Date, "2026-06-01T00:00:00Z");
        s.out_dir = out.path().display().to_string();
        let cfg = s.to_config().unwrap();
        s.start();
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let summary = rv_certcheck_core::run(&cfg, &mut |e| s.apply(e), &cancel).unwrap();
        assert_eq!(s.phase, Phase::Finished);
        assert_eq!(s.rows.len(), 13);
        let i = s
            .rows
            .iter()
            .position(|r| r.name == "leaf-revoked.crt")
            .unwrap();
        assert_eq!(s.rows[i].kind, "certificate");
        assert!(
            s.rows[i].findings.iter().any(|f| f == "CERT_REVOKED"),
            "{:?}",
            s.rows[i].findings
        );
        s.select_row(i);
        let v = s.item.as_ref().unwrap();
        let t = &v.trees[0];
        assert_eq!(t.status_key, "chain_invalid");
        assert!(t.nodes[0].subject.contains("revoked.lab.rakvor.test"));
        assert_eq!(t.nodes[0].badge, chain::Badge::Error);
        assert_eq!(t.nodes[0].reason, "certificate revoked");
        assert!(
            t.reaches_anchor && t.nodes.len() == 3,
            "leaf → intermediate → anchor"
        );
        assert!(v.certificate_text.contains("Certificate:"));
        s.select_node(0, 2);
        assert!(
            s.item
                .as_ref()
                .unwrap()
                .selected_node()
                .unwrap()
                .anchor
                .is_some()
        );
        let valid = s.rows.iter().position(|r| r.name == "leaf.crt").unwrap();
        s.select_row(valid);
        assert_eq!(s.item.as_ref().unwrap().trees[0].status_key, "chain_valid");
        let plain = s.rows.iter().position(|r| r.name == "data.txt").unwrap();
        s.select_row(plain);
        assert!(s.item.as_ref().unwrap().trees.is_empty());
        let log = std::fs::read_to_string(summary.log_dir.join("audit.jsonl")).unwrap();
        assert!(
            log.contains("\"ui_anchor_changed\"")
                && log.contains("\"ui_start_clicked\"")
                && log.contains("\"frontend\":\"gui\"")
        );
        assert!(s.ui.actions.iter().any(|(a, _)| a == "ui_item_selected"));
    }

    fn openssl(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
        let mut c = std::process::Command::new("openssl");
        c.args(args);
        for (k, v) in env {
            c.env(k, v);
        }
        let o = c.output().expect("openssl CLI");
        (
            o.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
        )
    }

    /// Root → intermediate → (import) → examiner .p12 → revoke → CRL, all through `state` as a user would, checked
    /// with `openssl verify`; then no password typed anywhere appears in any file written (logs, reports, CA).
    #[test]
    fn full_create_flow_through_state_verified_by_openssl() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path();
        let (root_pw, int_pw, exam_pw, p12_pw) = (
            "Root-Key-Pw-7781",
            "Int-Key-Pw-1290",
            "Exam-Key-Pw-5543",
            "P12-Pw-3378",
        );
        let mut s = GuiState::default();
        s.create.out_dir = base.join("runs").display().to_string();
        let run = |s: &mut GuiState, op: Result<create::PreparedOp, String>| {
            let r = execute(op.expect("valid form"));
            let ok = r.outcome.ok;
            let err = r.outcome.error.clone();
            s.create_finish(r);
            assert!(ok, "{err:?}");
            assert!(
                s.create.secrets_empty(),
                "every masked field is empty after the operation"
            );
        };
        let typed = |f: &mut MaskedField, v: &str| f.buffer().push_str(v);

        // 1. New root, key in an encrypted file.
        s.set_tab(Tab::Create);
        s.create_set_wizard(Some(Wizard::NewRoot));
        let r = &mut s.create.root;
        r.ca_dir = base.join("root").display().to_string();
        r.ca_id = "rakvor-root-test".into();
        r.subject = "C=CO,O=Rakvor Test,CN=Rakvor Test Root".into();
        r.key_type = rv_certcheck_core::certs::KeySpec::P256;
        typed(&mut r.key.password, root_pw);
        typed(&mut r.key.password_again, root_pw);
        let op = s.create_prepare();
        run(&mut s, op);
        let root_ca = s
            .create
            .ca
            .as_ref()
            .expect("the new root is opened")
            .dir
            .clone();
        assert_eq!(root_ca, base.join("root"));

        // 2. The intermediate, issued by the root; Import is pre-filled from it.
        s.create_set_wizard(Some(Wizard::Issue));
        s.create_set_profile(IssueProfile::Intermediate).unwrap();
        let i = &mut s.create.issue;
        i.subject = "C=CO,O=Rakvor Test,CN=Rakvor Test Issuing".into();
        i.key_type = rv_certcheck_core::certs::KeySpec::P256;
        i.validity_days = "1825".into();
        i.key.key_file = base.join("issuing.key.p8").display().to_string();
        typed(&mut i.key.password, int_pw);
        typed(&mut i.key.password_again, int_pw);
        typed(&mut i.ca_secret, root_pw);
        let op = s.create_prepare();
        run(&mut s, op);
        assert_eq!(s.create.ca.as_ref().unwrap().issued.len(), 1);
        let int_cert = PathBuf::from(&s.create.import.cert_file);
        assert!(
            int_cert.is_file(),
            "Import pre-filled with the intermediate"
        );

        // 3. Import it as its own CA folder.
        s.create_set_wizard(Some(Wizard::Import));
        let m = &mut s.create.import;
        m.ca_dir = base.join("issuing").display().to_string();
        m.ca_id = "rakvor-issuing-test".into();
        typed(&mut m.key.password, int_pw);
        let op = s.create_prepare();
        run(&mut s, op);
        assert_eq!(s.create.ca.as_ref().unwrap().dir, base.join("issuing"));

        // 4. An examiner certificate with its .p12.
        s.create_set_wizard(Some(Wizard::Issue));
        s.create_set_profile(IssueProfile::Examiner).unwrap();
        let i = &mut s.create.issue;
        i.subject = "C=CO,O=Rakvor Test,CN=Ana Ruiz".into();
        i.sans = "email:ana.ruiz@rakvor.test".into();
        assert_eq!(
            i.key_type,
            rv_certcheck_core::certs::KeySpec::Rsa3072,
            "examiner defaults to RSA-3072 (rv-hashinv signs PDFs with RSA only)"
        );
        typed(&mut i.key.password, exam_pw);
        typed(&mut i.key.password_again, exam_pw);
        typed(&mut i.ca_secret, int_pw);
        typed(&mut i.p12_password, p12_pw);
        typed(&mut i.p12_again, p12_pw);
        let op = s.create_prepare();
        run(&mut s, op);
        let last = s.create.last.clone().unwrap();
        let file = |role: &str| {
            last.files
                .iter()
                .find(|f| f.0 == role)
                .map(|f| f.1.clone())
                .unwrap()
        };
        let (exam_cert, p12) = (file("certificate"), file("examiner PKCS#12"));
        assert!(
            s.create.last_folder.as_ref().unwrap().is_dir(),
            "Open folder target"
        );

        let root_crt = root_ca.join("certs/ca.crt");
        let (ok, out) = openssl(
            &[
                "verify",
                "-CAfile",
                &root_crt.display().to_string(),
                "-untrusted",
                &int_cert.display().to_string(),
                &exam_cert.display().to_string(),
            ],
            &[],
        );
        assert!(ok && out.contains(": OK"), "openssl verify: {out}");
        let (ok, out) = openssl(
            &[
                "pkcs12",
                "-in",
                &p12.display().to_string(),
                "-passin",
                "env:RV_P12",
                "-nokeys",
                "-clcerts",
            ],
            &[("RV_P12", p12_pw)],
        );
        assert!(
            ok && out.contains("Ana Ruiz"),
            "the .p12 opens with its password: {out}"
        );

        // 5. Revoke the examiner, publish a CRL: the issued list shows it revoked, openssl agrees.
        let serial = s.create.ca.as_ref().unwrap().issued[0].serial.clone();
        s.create_set_wizard(Some(Wizard::Revoke));
        s.create.revoke.serial = serial.clone();
        s.create.revoke.reason = "keyCompromise".into();
        let op = s.create_prepare();
        run(&mut s, op);
        s.create_set_wizard(Some(Wizard::Crl));
        typed(&mut s.create.crl.ca_secret, int_pw);
        let op = s.create_prepare();
        run(&mut s, op);
        let row = &s.create.ca.as_ref().unwrap().issued[0];
        assert!(row.revoked.as_deref().unwrap().starts_with("keyCompromise"));
        let crl = base.join("issuing/crl/latest.crl");
        let chain = base.join("chain.pem");
        std::fs::write(
            &chain,
            [
                std::fs::read(&root_crt).unwrap(),
                std::fs::read(&int_cert).unwrap(),
            ]
            .concat(),
        )
        .unwrap();
        let (ok, out) = openssl(
            &[
                "verify",
                "-crl_check",
                "-CAfile",
                &chain.display().to_string(),
                "-CRLfile",
                &crl.display().to_string(),
                &exam_cert.display().to_string(),
            ],
            &[],
        );
        assert!(
            !ok && out.contains("revoked"),
            "openssl sees the revocation: {out}"
        );

        // 6. pki verify through the GUI.
        let op = s.create_verify_ca();
        run(&mut s, op);
        assert!(matches!(s.create.verify, Some(Ok(n)) if n >= 4));

        // No password appears in any file written (audit logs, reports, CA folders, issued.jsonl), nor in the
        // ui_* actions still pending.
        let mut checked = 0;
        for e in walkdir(base) {
            let bytes = std::fs::read(&e).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            for pw in [root_pw, int_pw, exam_pw, p12_pw] {
                assert!(!text.contains(pw), "{pw} found in {}", e.display());
            }
            checked += 1;
        }
        assert!(checked > 30, "{checked} files checked");
        let pending = serde_json::to_string(&s.ui.actions).unwrap();
        assert!(
            [root_pw, int_pw, exam_pw, p12_pw]
                .iter()
                .all(|pw| !pending.contains(pw))
        );
        // Every run is a verifiable log with the GUI as front-end and the ui_* actions in it.
        let logs: Vec<PathBuf> = walkdir(&base.join("runs"))
            .into_iter()
            .filter(|p| p.ends_with("audit.jsonl"))
            .collect();
        assert_eq!(logs.len(), 7);
        let mut all = String::new();
        for l in &logs {
            assert!(
                rv_certcheck_core::audit::verify(l).is_ok(),
                "{}",
                l.display()
            );
            all.push_str(&std::fs::read_to_string(l).unwrap());
        }
        for a in [
            "ui_wizard_opened",
            "ui_wizard_submitted",
            "ui_profile_changed",
            "ca_created",
            "certificate_issued",
            "ca_imported",
            "certificate_revoked",
            "crl_signed",
            "ca_folder_verified",
            "\"frontend\":\"gui\"",
        ] {
            assert!(all.contains(a), "{a} in the audit logs");
        }
    }

    fn walkdir(d: &Path) -> Vec<PathBuf> {
        let mut out = vec![];
        let mut stack = vec![d.to_path_buf()];
        while let Some(p) = stack.pop() {
            for e in std::fs::read_dir(&p).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        out
    }
}
