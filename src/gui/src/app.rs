//! The window. Drawing only: rules live in `state.rs` (and `state/*`), work lives in the core and the certificate
//! layer, on worker threads. Rakvor dark theme; interface language EN/ES/FR switchable at any time (texts from
//! i18n "ui"). Masked fields are drawn as password edits over `MaskedField::buffer`.

use crate::state::chain::{Badge, cert_fields};
use crate::state::create::{KeyForm, KeyMode, OpResult, PreparedOp, Wizard, profile_choices};
use crate::state::trust::anchor_spec;
use crate::state::{AtChoice, GuiState, MaskedField, Phase, RevFile, Tab};
use eframe::egui;
use rv_certcheck_core::certs::{IssueProfile, KeySpec, Purpose, REVOCATION_REASONS, TrustListKind};
use rv_certcheck_core::i18n::Catalog;
use rv_certcheck_core::{Event, HashAlgo, RunConfig, RunSummary, TOOL_VERSION};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

// Rakvor palette
const NIGHT: egui::Color32 = egui::Color32::from_rgb(0x0D, 0x11, 0x17);
const NIGHT2: egui::Color32 = egui::Color32::from_rgb(0x1A, 0x1F, 0x26);
const BLUE: egui::Color32 = egui::Color32::from_rgb(0x2A, 0x5C, 0xFF);
const VIOLET: egui::Color32 = egui::Color32::from_rgb(0x6B, 0x00, 0xFF);
const CYAN: egui::Color32 = egui::Color32::from_rgb(0x00, 0xE5, 0xFF);
const MIST: egui::Color32 = egui::Color32::from_rgb(0xE6, 0xE6, 0xE6);
const GREEN: egui::Color32 = egui::Color32::from_rgb(0x3F, 0xB9, 0x50);
const RED: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x6B, 0x6B);
const AMBER: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xB0, 0x40);
const UI_LANGS: [(&str, &str); 3] = [("en", "English"), ("es", "Español"), ("fr", "Français")];

enum Msg {
    Event(Event),
    Done(Result<RunSummary, String>),
}

pub struct HashInvApp {
    state: GuiState,
    rx: Option<Receiver<Msg>>,
    op_rx: Option<Receiver<OpResult>>,
    cancel: Arc<AtomicBool>,
    started: Option<Instant>,
    notice: Option<String>,
    create_notice: Option<String>,
    trust_notice: Option<String>,
    themed: bool,
    /// Case folder being typed; applied (and audited) when the field loses focus.
    case_entry: String,
}

/// Applies the Rakvor dark theme.
pub fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = NIGHT;
    v.window_fill = NIGHT2;
    v.extreme_bg_color = NIGHT2; // text fields
    let line = egui::Stroke::new(1.0, egui::Color32::from_rgb(0x2B, 0x32, 0x40));
    v.widgets.inactive.bg_stroke = line;
    v.widgets.noninteractive.bg_stroke = line;
    v.faint_bg_color = egui::Color32::from_rgb(0x14, 0x19, 0x20);
    v.override_text_color = Some(MIST);
    v.selection.bg_fill = BLUE;
    v.hyperlink_color = CYAN;
    v.widgets.inactive.bg_fill = NIGHT2;
    v.widgets.inactive.weak_bg_fill = NIGHT2;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, CYAN);
    v.widgets.active.bg_fill = BLUE;
    ctx.set_visuals(v);
}

/// A file or folder picker button (Windows); elsewhere nothing is drawn and paths are typed.
#[allow(unused_variables)]
fn browse(ui: &mut egui::Ui, label: &str, folder: bool) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if ui.button(label).clicked() {
            return if folder {
                rfd::FileDialog::new().pick_folder()
            } else {
                rfd::FileDialog::new().pick_file()
            };
        }
    }
    None
}

fn masked(ui: &mut egui::Ui, f: &mut MaskedField, width: f32) -> egui::Response {
    let out = egui::TextEdit::singleline(f.buffer())
        .password(true)
        .desired_width(width)
        .show(ui);
    // egui's undo history keeps copies of the text: a masked field has none.
    let mut st = out.state;
    st.clear_undoer();
    st.store(ui.ctx(), out.response.response.id);
    out.response.response
}

fn entry(ui: &mut egui::Ui, s: &mut String, hint: &str, width: f32) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(s)
            .hint_text(hint)
            .desired_width(width),
    )
}

fn section_title(ui: &mut egui::Ui, text: String) {
    ui.add_space(6.0);
    ui.label(egui::RichText::new(text).color(CYAN).strong().size(15.0));
}

fn badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.22))
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(5, 1))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(color).size(11.0).strong());
        });
}

fn status_color(status: &str) -> egui::Color32 {
    match status {
        "problem" => RED,
        "attention" => AMBER,
        _ => GREEN,
    }
}

fn open_path(p: &Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(p).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(p).spawn();
}

fn key_type_combo(ui: &mut egui::Ui, id: &str, k: &mut KeySpec) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(k.name())
        .show_ui(ui, |ui| {
            for s in KeySpec::ALL {
                ui.selectable_value(k, s, s.name());
            }
        });
}

impl HashInvApp {
    pub fn new() -> Self {
        Self::from_state(GuiState::default())
    }

    /// The window over a prepared state (the screenshot example uses it).
    pub fn from_state(state: GuiState) -> Self {
        HashInvApp {
            state,
            rx: None,
            op_rx: None,
            cancel: Arc::new(AtomicBool::new(false)),
            started: None,
            notice: None,
            create_notice: None,
            trust_notice: None,
            themed: false,
            case_entry: String::new(),
        }
    }

    pub fn state(&self) -> &GuiState {
        &self.state
    }

    /// Starts with evidence already selected (paths given to the executable).
    pub fn with_inputs(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut app = Self::new();
        for p in paths {
            app.state.add_input(p);
        }
        app
    }

    /// Starts from the executable's arguments: input paths plus `--case-dir DIR` (RV Hub).
    pub fn from_launch(args: crate::launch::LaunchArgs) -> Self {
        let mut app = Self::with_inputs(args.inputs);
        if let Some(dir) = args.case_dir {
            app.state.set_case_dir_from_launcher(&dir);
            app.case_entry = dir.display().to_string();
        }
        for n in &args.notes {
            app.state.note_launch_problem(n);
        }
        if !args.notes.is_empty() {
            app.notice = Some(args.notes.join("\n"));
        }
        app
    }

    fn start(&mut self, ctx: &egui::Context) {
        let cfg: RunConfig = match self.state.to_config() {
            Ok(c) => c,
            Err(e) => {
                self.notice = Some(e);
                return;
            }
        };
        self.notice = None;
        self.state.start();
        self.cancel.store(false, Ordering::SeqCst);
        self.started = Some(Instant::now());
        let (tx, rx) = channel();
        self.rx = Some(rx);
        let cancel = self.cancel.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let r2 = repaint.clone();
            let mut sink = move |e: &Event| {
                let _ = tx2.send(Msg::Event(e.clone()));
                r2.request_repaint();
            };
            // The configuration (and the passwords in it) is dropped, zeroized, when the run returns.
            let result = rv_certcheck_core::run(&cfg, &mut sink, &cancel);
            drop(cfg);
            let _ = tx.send(Msg::Done(result));
            repaint.request_repaint();
        });
    }

    /// Runs a Create / Trust-lists operation on a worker thread.
    fn spawn_op(&mut self, ctx: &egui::Context, op: Result<PreparedOp, String>, trust: bool) {
        let op = match op {
            Ok(op) => op,
            Err(e) => {
                if trust {
                    self.trust_notice = Some(e);
                } else {
                    self.create_notice = Some(e);
                }
                return;
            }
        };
        self.create_notice = None;
        self.trust_notice = None;
        self.state.create.busy = true;
        let (tx, rx) = channel();
        self.op_rx = Some(rx);
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let r = crate::state::create::execute(op);
            let _ = tx.send(r);
            repaint.request_repaint();
        });
    }

    fn drain(&mut self) {
        if let Some(rx) = &self.op_rx
            && let Ok(r) = rx.try_recv()
        {
            self.state.create_finish(r);
            self.op_rx = None;
        }
        let Some(rx) = &self.rx else { return };
        let mut finished = false;
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Event(e) => self.state.apply(&e),
                Msg::Done(Ok(_)) => finished = true,
                Msg::Done(Err(e)) => {
                    self.state.fail(e);
                    finished = true;
                }
            }
        }
        if finished {
            self.rx = None;
            self.started = None;
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(38.0, 38.0), egui::Sense::hover());
            ui.painter().rect(
                rect,
                8.0,
                NIGHT2,
                egui::Stroke::new(2.0, BLUE),
                egui::StrokeKind::Inside,
            );
            ui.painter().text(
                rect.center() - egui::vec2(0.0, 3.0),
                egui::Align2::CENTER_CENTER,
                "RV",
                egui::FontId::proportional(16.0),
                MIST,
            );
            ui.painter().line_segment(
                [
                    rect.center() + egui::vec2(-8.0, 10.0),
                    rect.center() + egui::vec2(8.0, 10.0),
                ],
                egui::Stroke::new(2.0, CYAN),
            );
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new("R A K V O R  ·  RV CertCheck")
                        .strong()
                        .size(16.0),
                );
                let desc = c.brand()["descriptor"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                ui.label(egui::RichText::new(desc).color(CYAN).size(10.0));
            });
            ui.add_space(24.0);
            let busy = self.state.is_running() || self.state.create.busy;
            for t in Tab::ALL {
                let txt = egui::RichText::new(c.ui(t.key())).size(15.0).strong();
                if ui
                    .add_enabled(
                        !busy || self.state.tab == t,
                        egui::Button::selectable(self.state.tab == t, txt),
                    )
                    .clicked()
                {
                    self.state.set_tab(t);
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let current = UI_LANGS
                    .iter()
                    .find(|(k, _)| *k == self.state.ui_lang)
                    .map(|(_, v)| *v)
                    .unwrap_or("English");
                let mut chosen = None;
                egui::ComboBox::from_id_salt("ui-lang")
                    .selected_text(current)
                    .show_ui(ui, |ui| {
                        for (k, v) in UI_LANGS {
                            if ui.selectable_label(self.state.ui_lang == k, v).clicked() {
                                chosen = Some(k);
                            }
                        }
                    });
                if let Some(k) = chosen {
                    self.state.set_ui_lang(k);
                }
                ui.label(c.ui("ui_lang"));
                ui.weak(format!("v{}", TOOL_VERSION));
            });
        });
        ui.weak(c.ui("audit_note"));
        let (r, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 3.0), egui::Sense::hover());
        let third = r.width() / 3.0;
        for (i, col) in [BLUE, VIOLET, CYAN].iter().enumerate() {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(
                    r.min + egui::vec2(third * i as f32, 0.0),
                    egui::vec2(third, 3.0),
                ),
                0.0,
                *col,
            );
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // Analyze tab
    // ---------------------------------------------------------------------------------------------------------

    fn evidence_section(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        section_title(ui, t("evidence"));
        ui.label(t("evidence_help"));
        ui.horizontal(|ui| {
            #[cfg(windows)]
            {
                if ui.button(t("add_files")).clicked()
                    && let Some(files) = rfd::FileDialog::new().pick_files()
                {
                    for f in files {
                        self.state.add_input(f);
                    }
                }
                if let Some(d) = browse(ui, &t("add_folder"), true) {
                    self.state.add_input(d);
                }
            }
            let r = entry(ui, &mut self.state.path_entry, &t("path_hint"), 280.0);
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button(t("add_path")).clicked() || enter {
                self.state.add_typed_path();
            }
        });
        let dropped: Vec<PathBuf> = ui.ctx().input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        });
        for p in dropped {
            self.state.add_input(p);
        }
        let mut remove = None;
        egui::ScrollArea::vertical()
            .max_height(80.0)
            .id_salt("inputs")
            .show(ui, |ui| {
                if self.state.inputs.is_empty() {
                    ui.weak(t("no_evidence"));
                }
                for (i, p) in self.state.inputs.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button("x").clicked() {
                            remove = Some(i);
                        }
                        ui.monospace(p.display().to_string());
                    });
                }
            });
        if let Some(i) = remove {
            self.state.remove_input(i);
        }
        let mut rec = self.state.recursive;
        if ui.checkbox(&mut rec, t("subfolders")).changed() {
            self.state.set_recursive(rec);
        }
        ui.horizontal(|ui| {
            ui.label(t("case_dir"));
            let r = entry(ui, &mut self.case_entry, &t("case_dir_hint"), 260.0);
            if r.lost_focus() {
                let e = self.case_entry.clone();
                self.state.set_case_dir(&e);
            }
            if let Some(d) = browse(ui, &t("browse"), true) {
                self.case_entry = d.display().to_string();
                let e = self.case_entry.clone();
                self.state.set_case_dir(&e);
            }
        });
    }

    fn file_list(ui: &mut egui::Ui, id: &str, files: &[PathBuf], empty: &str) -> Option<usize> {
        let mut remove = None;
        ui.push_id(id, |ui| {
            if files.is_empty() {
                ui.weak(empty);
            }
            for (i, p) in files.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.small_button("x").clicked() {
                        remove = Some(i);
                    }
                    ui.monospace(p.display().to_string());
                });
            }
        });
        remove
    }

    fn options_section(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        section_title(ui, t("cert_options"));
        // Anchors
        ui.label(egui::RichText::new(t("anchors")).strong());
        ui.horizontal_wrapped(|ui| {
            let mut on = self.state.analysis.anchor_rakvor;
            if ui.checkbox(&mut on, t("anchor_rakvor")).changed() {
                self.state.set_anchor_builtin("rakvor", on);
            }
            let mut on = self.state.analysis.anchor_system;
            if ui.checkbox(&mut on, t("anchor_system")).changed() {
                self.state.set_anchor_builtin("system", on);
            }
        });
        ui.horizontal(|ui| {
            let r = entry(
                ui,
                &mut self.state.anchor_entry,
                &t("anchor_file_hint"),
                280.0,
            );
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button(t("add_path")).clicked() || enter {
                self.state.add_anchor_file(None);
            }
            if let Some(p) = browse(ui, &t("browse"), false) {
                self.state.add_anchor_file(Some(p));
            }
        });
        if let Some(i) = Self::file_list(ui, "anchors", &self.state.analysis.anchor_files, "") {
            self.state.remove_anchor_file(i);
        }
        let lists = self.state.analysis.anchor_lists.clone();
        for l in &lists {
            ui.horizontal(|ui| {
                if ui.small_button("x").clicked() {
                    self.state.set_anchor_list(l, false);
                }
                ui.monospace(l);
            });
        }
        if !self.state.trust.snapshots.is_empty() {
            let mut chosen = None;
            egui::ComboBox::from_id_salt("anchor-tl")
                .selected_text(t("anchor_tl"))
                .show_ui(ui, |ui| {
                    for s in &self.state.trust.snapshots {
                        let spec = anchor_spec(s);
                        if ui.selectable_label(lists.contains(&spec), &spec).clicked() {
                            chosen = Some(spec);
                        }
                    }
                });
            if let Some(s) = chosen {
                self.state.set_anchor_list(&s, true);
            }
        } else {
            ui.weak(t("anchor_tl_none"));
        }
        if self
            .state
            .validation_options()
            .is_ok_and(|v| v.anchors.is_empty())
        {
            ui.colored_label(AMBER, t("no_anchor_warning"));
        }
        ui.add_space(4.0);
        egui::Grid::new("opt-grid")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label(t("at"));
                ui.horizontal(|ui| {
                    let mut at = self.state.analysis.at;
                    let mut date = self.state.analysis.at_date.clone();
                    ui.radio_value(&mut at, AtChoice::Now, t("at_now"));
                    ui.radio_value(&mut at, AtChoice::Date, t("at_date"));
                    ui.radio_value(&mut at, AtChoice::SigningTime, t("at_signing"));
                    let r = ui.add_enabled(
                        at == AtChoice::Date,
                        egui::TextEdit::singleline(&mut date)
                            .hint_text("2026-06-01")
                            .desired_width(150.0),
                    );
                    if at != self.state.analysis.at || r.lost_focus() {
                        self.state.set_at(at, &date);
                    } else {
                        self.state.analysis.at_date = date;
                    }
                });
                ui.end_row();
                ui.label(t("purpose"));
                let mut p = self.state.analysis.purpose;
                egui::ComboBox::from_id_salt("purpose")
                    .selected_text(p.name())
                    .show_ui(ui, |ui| {
                        for x in Purpose::ALL {
                            ui.selectable_value(&mut p, x, x.name());
                        }
                    });
                if p != self.state.analysis.purpose {
                    self.state.set_purpose(p);
                }
                ui.end_row();
                for (kind, label, key) in [
                    (RevFile::Crl, t("crl_files"), "crl"),
                    (RevFile::Ocsp, t("ocsp_files"), "ocsp"),
                ] {
                    ui.label(label);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            let buf = if kind == RevFile::Crl {
                                &mut self.state.crl_entry
                            } else {
                                &mut self.state.ocsp_entry
                            };
                            let r = entry(ui, buf, &t("path_hint_short"), 220.0);
                            let enter =
                                r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                            if ui.button(t("add_path")).clicked() || enter {
                                self.state.add_revocation_file(kind, None);
                            }
                            if let Some(p) = browse(ui, &t("browse"), false) {
                                self.state.add_revocation_file(kind, Some(p));
                            }
                        });
                        let files = if kind == RevFile::Crl {
                            self.state.analysis.crl_files.clone()
                        } else {
                            self.state.analysis.ocsp_files.clone()
                        };
                        if let Some(i) = Self::file_list(ui, key, &files, "") {
                            self.state.remove_revocation_file(kind, i);
                        }
                    });
                    ui.end_row();
                }
                ui.label(t("online"));
                ui.vertical(|ui| {
                    let mut on = self.state.analysis.online;
                    if ui.checkbox(&mut on, t("online_box")).changed() {
                        self.state.set_online(on);
                    }
                    if on {
                        ui.colored_label(AMBER, t("online_warning"));
                    }
                });
                ui.end_row();
                ui.label(t("p12_password"));
                ui.vertical(|ui| {
                    masked(ui, &mut self.state.p12_password, 220.0);
                    ui.weak(t("p12_password_note"));
                });
                ui.end_row();
            });
    }

    fn hashing_section(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        section_title(ui, c.ui("hashes"));
        ui.horizontal_wrapped(|ui| {
            for a in HashAlgo::ALL {
                let mut on = self.state.selected.contains(&a);
                let can = self.state.can_toggle(a);
                let r = ui.add_enabled(can, egui::Checkbox::new(&mut on, a.name()));
                let r = if can {
                    r
                } else if self.state.selected.contains(&a) {
                    r.on_disabled_hover_text(c.ui("hash_tip_one"))
                } else {
                    r.on_disabled_hover_text(c.ui("hash_tip_two"))
                };
                if r.changed()
                    && let Err(e) = self.state.toggle_algo(a)
                {
                    self.notice = Some(e);
                }
            }
        });
    }

    fn report_section(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        section_title(ui, t("reports"));
        egui::Grid::new("report-grid")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label(t("report_lang"));
                let choices = [
                    ("en", "English".to_string()),
                    ("es", "Español".to_string()),
                    ("fr", "Français".to_string()),
                    ("all", t("lang_all")),
                ];
                let current = choices
                    .iter()
                    .find(|(k, _)| *k == self.state.lang)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let mut chosen = None;
                egui::ComboBox::from_id_salt("lang")
                    .selected_text(current)
                    .show_ui(ui, |ui| {
                        for (k, v) in &choices {
                            if ui.selectable_label(self.state.lang == *k, v).clicked() {
                                chosen = Some(*k);
                            }
                        }
                    });
                if let Some(k) = chosen {
                    self.state.set_lang(k);
                }
                ui.end_row();
                ui.label(t("out_dir"));
                ui.horizontal(|ui| {
                    if self.state.out_locked() {
                        let mut shown = self.state.out_dir_display();
                        ui.add_enabled(
                            false,
                            egui::TextEdit::singleline(&mut shown).desired_width(260.0),
                        )
                        .on_disabled_hover_text(t("out_from_case"));
                    } else {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.state.out_dir)
                                .desired_width(260.0),
                        );
                        if let Some(d) = browse(ui, &t("browse"), true) {
                            self.state.out_dir = d.display().to_string();
                        }
                    }
                });
                ui.end_row();
                ui.label(t("examiner"));
                ui.add(egui::TextEdit::singleline(&mut self.state.actor).desired_width(260.0));
                ui.end_row();
                ui.label(t("case"));
                entry(ui, &mut self.state.case_id, &t("case_hint"), 260.0);
                ui.end_row();
            });
    }

    fn trust_section(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        section_title(ui, t("trust"));
        egui::Grid::new("trust-grid")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label(t("jurisdiction"));
                let (co, fr) = (t("jur_co"), t("jur_fr"));
                let mut chosen = None;
                egui::ComboBox::from_id_salt("jur")
                    .selected_text(if self.state.jurisdiction == "fr" {
                        fr.clone()
                    } else {
                        co.clone()
                    })
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(self.state.jurisdiction == "co", &co)
                            .clicked()
                        {
                            chosen = Some("co");
                        }
                        if ui
                            .selectable_label(self.state.jurisdiction == "fr", &fr)
                            .clicked()
                        {
                            chosen = Some("fr");
                        }
                    });
                if let Some(j) = chosen {
                    self.state.set_jurisdiction(j);
                }
                ui.end_row();
                ui.label(t("tsa"));
                ui.horizontal(|ui| {
                    let mut on = self.state.timestamp;
                    let mut url = self.state.tsa_url.clone();
                    let cb = ui.checkbox(&mut on, "");
                    let te = ui.add_enabled(
                        on,
                        egui::TextEdit::singleline(&mut url).desired_width(240.0),
                    );
                    if cb.changed() || te.lost_focus() {
                        self.state.set_timestamp(on, &url);
                    } else {
                        self.state.tsa_url = url;
                    }
                });
                ui.end_row();
                ui.label(t("sign_cert"));
                ui.horizontal(|ui| {
                    let mut path = self.state.sign_cert.clone();
                    let r = ui.add(egui::TextEdit::singleline(&mut path).desired_width(240.0));
                    if r.lost_focus() || r.changed() {
                        self.state.set_sign_cert(&path);
                    }
                    if let Some(f) = browse(ui, &t("browse"), false) {
                        self.state.set_sign_cert(&f.display().to_string());
                    }
                });
                ui.end_row();
                ui.label(t("sign_pass"));
                masked(ui, &mut self.state.sign_password, 240.0);
                ui.end_row();
            });
    }

    fn run_section(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if self.state.is_running() {
                if ui.button(t("cancel")).clicked() {
                    self.cancel.store(true, Ordering::SeqCst);
                    self.notice = Some(t("cancelling"));
                }
            } else {
                let start = egui::Button::new(
                    egui::RichText::new(t("start"))
                        .strong()
                        .color(egui::Color32::WHITE),
                )
                .fill(BLUE);
                if ui.add_enabled(self.state.can_start(), start).clicked() {
                    let ctx = ui.ctx().clone();
                    self.start(&ctx);
                }
            }
            if let Some(n) = &self.notice {
                ui.colored_label(AMBER, n);
            }
        });
        ui.add_space(4.0);
        ui.add(
            egui::ProgressBar::new(self.state.fraction())
                .text(self.state.progress_text())
                .fill(BLUE)
                .animate(self.state.is_running()),
        );
        let live = self.started.map(|s| s.elapsed().as_millis() as u64);
        ui.label(self.state.timing_text(live));
        if !self.state.current_item.is_empty() {
            ui.weak(format!("{}: {}", t("now"), self.state.current_item));
        }
        match &self.state.phase {
            Phase::Failed(e) => {
                ui.colored_label(RED, format!("{}: {}", t("failed"), e));
            }
            Phase::Finished | Phase::Cancelled => {
                if let Some(o) = self.state.outcome.clone() {
                    let title = if self.state.phase == Phase::Cancelled {
                        t("cancelled")
                    } else {
                        t("done")
                    };
                    ui.label(egui::RichText::new(title).color(CYAN).strong());
                    ui.label(format!(
                        "{} {} · {} {} · {}: {} / {} / {} / {}",
                        o.items,
                        t("files"),
                        o.errors,
                        t("errors"),
                        t("findings"),
                        o.high,
                        o.medium,
                        o.low,
                        o.info
                    ));
                    let lines = self.state.evidence_lines();
                    if !lines.is_empty() {
                        egui::CollapsingHeader::new(format!(
                            "{} ({})",
                            t("evidence_ids"),
                            lines.len()
                        ))
                        .show(ui, |ui| {
                            for l in &lines {
                                ui.monospace(l);
                            }
                        });
                    }
                    ui.horizontal(|ui| {
                        if ui.button(t("open_report")).clicked() {
                            open_path(&o.report);
                        }
                        if ui.button(t("open_logs")).clicked() {
                            open_path(&o.log_dir);
                        }
                    });
                }
            }
            _ => {}
        }
        if !self.state.warnings.is_empty() {
            egui::CollapsingHeader::new(format!(
                "{} ({})",
                t("warnings"),
                self.state.warnings.len()
            ))
            .show(ui, |ui| {
                for w in &self.state.warnings {
                    ui.label(w);
                }
            });
        }
    }

    fn results_table(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        section_title(ui, format!("{} ({})", t("results"), self.state.rows.len()));
        if self.state.rows.is_empty() {
            ui.weak(t("results_empty"));
            return;
        }
        let selected = self.state.item.as_ref().map(|v| v.row);
        let mut clicked = None;
        egui::ScrollArea::vertical()
            .max_height(230.0)
            .id_salt("results")
            .show(ui, |ui| {
                egui::Grid::new("results-grid")
                    .striped(true)
                    .num_columns(5)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        for h in [
                            "col_index",
                            "col_item",
                            "col_kind",
                            "col_status",
                            "col_findings",
                        ] {
                            ui.label(egui::RichText::new(t(h)).strong().color(CYAN));
                        }
                        ui.end_row();
                        for (i, r) in self.state.rows.iter().enumerate() {
                            ui.monospace(format!("{:05}", r.index));
                            if ui.selectable_label(selected == Some(i), &r.name).clicked() {
                                clicked = Some(i);
                            }
                            ui.label(&r.kind);
                            badge(
                                ui,
                                &t(&format!("status_{}", r.status)),
                                status_color(&r.status),
                            );
                            ui.label(egui::RichText::new(r.findings.join(", ")).size(11.5));
                            ui.end_row();
                        }
                    });
            });
        if let Some(i) = clicked {
            self.state.select_row(i);
        }
    }

    fn chain_view(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        let Some(view) = self.state.item.clone() else {
            if !self.state.rows.is_empty() {
                ui.add_space(6.0);
                ui.weak(t("select_item"));
            }
            return;
        };
        let name = self
            .state
            .rows
            .get(view.row)
            .map(|r| r.name.clone())
            .unwrap_or_default();
        section_title(ui, format!("{} — {}", t("chain_view"), name));
        if view.trees.is_empty() {
            ui.weak(t("no_chain"));
        }
        let mut pick = None;
        ui.columns(2, |cols| {
            let ui = &mut cols[0];
            egui::ScrollArea::vertical()
                .id_salt("trees")
                .max_height(ui.available_height())
                .show(ui, |ui| {
                    for (ti, tree) in view.trees.iter().enumerate() {
                        let col = match tree.status_key {
                            "chain_valid" => GREEN,
                            "chain_untrusted" => AMBER,
                            _ => RED,
                        };
                        ui.horizontal_wrapped(|ui| {
                            badge(ui, &t(tree.status_key), col);
                            ui.weak(format!(
                                "{} {} ({}) · {} {}",
                                t("at"),
                                tree.at,
                                tree.at_source,
                                t("purpose"),
                                tree.purpose
                            ));
                        });
                        for (ni, n) in tree.nodes.iter().enumerate() {
                            ui.horizontal(|ui| {
                                let indent = 18.0 * ni as f32;
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(indent + 14.0, 18.0),
                                    egui::Sense::hover(),
                                );
                                if ni > 0 {
                                    let x = rect.min.x + indent - 9.0;
                                    let p = ui.painter();
                                    let s = egui::Stroke::new(1.5, egui::Color32::from_gray(110));
                                    p.line_segment(
                                        [
                                            egui::pos2(x, rect.min.y - 8.0),
                                            egui::pos2(x, rect.center().y),
                                        ],
                                        s,
                                    );
                                    p.line_segment(
                                        [
                                            egui::pos2(x, rect.center().y),
                                            egui::pos2(rect.max.x - 2.0, rect.center().y),
                                        ],
                                        s,
                                    );
                                }
                                let (bt, bc) = match n.badge {
                                    Badge::Ok => (t(n.badge.key()), GREEN),
                                    Badge::Error => (t(n.badge.key()), RED),
                                    Badge::Incomplete => (t(n.badge.key()), AMBER),
                                };
                                badge(ui, &bt, bc);
                                if n.anchor.is_some() {
                                    badge(ui, &t("badge_anchor"), CYAN);
                                }
                                let sel = view.selected == Some((ti, ni));
                                if ui
                                    .selectable_label(sel, egui::RichText::new(&n.subject).strong())
                                    .clicked()
                                {
                                    pick = Some((ti, ni));
                                }
                            });
                            ui.horizontal(|ui| {
                                ui.add_space(18.0 * ni as f32 + 18.0);
                                ui.vertical(|ui| {
                                    let reason =
                                        format!("OpenSSL {}: {}", n.openssl_code, n.reason);
                                    ui.label(
                                        egui::RichText::new(reason)
                                            .size(11.5)
                                            .color(if n.openssl_code == 0 { MIST } else { RED }),
                                    );
                                    if let Some(r) = &n.revocation {
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{}: {}",
                                                t("revocation"),
                                                r
                                            ))
                                            .size(11.0)
                                            .weak(),
                                        );
                                    }
                                    if let Some(a) = &n.anchor {
                                        ui.label(
                                            egui::RichText::new(format!("{}: {}", t("anchor"), a))
                                                .size(11.0)
                                                .color(CYAN),
                                        );
                                    }
                                    if let Some(l) = &n.trust_list {
                                        ui.label(egui::RichText::new(l).size(11.0).weak());
                                    }
                                });
                            });
                        }
                        for e in tree.errors.iter().chain(&tree.notes) {
                            ui.label(egui::RichText::new(e).size(11.0).weak());
                        }
                        ui.separator();
                    }
                    for e in &view.errors {
                        ui.colored_label(AMBER, e);
                    }
                });
            let ui = &mut cols[1];
            egui::ScrollArea::vertical()
                .id_salt("fields")
                .max_height(ui.available_height())
                .show(ui, |ui| {
                    if let Some(n) = view.selected_node() {
                        ui.label(egui::RichText::new(t("fields")).strong().color(CYAN));
                        let value_w = (ui.available_width() - 150.0).max(120.0);
                        egui::Grid::new("fields-grid")
                            .num_columns(2)
                            .striped(true)
                            .spacing([10.0, 3.0])
                            .max_col_width(value_w)
                            .show(ui, |ui| {
                                for (k, v) in cert_fields(&n.cert) {
                                    ui.label(egui::RichText::new(t(k)).size(11.5).weak());
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(v).size(11.5).monospace(),
                                        )
                                        .wrap_mode(egui::TextWrapMode::Wrap),
                                    );
                                    ui.end_row();
                                }
                            });
                    }
                    if !view.certificate_text.is_empty() {
                        egui::CollapsingHeader::new("certificate.txt")
                            .default_open(true)
                            .show(ui, |ui| {
                                let mut txt = view.certificate_text.clone();
                                ui.add(
                                    egui::TextEdit::multiline(&mut txt)
                                        .code_editor()
                                        .interactive(false)
                                        .desired_width(f32::INFINITY),
                                );
                            });
                    }
                });
        });
        if let Some((a, b)) = pick {
            self.state.select_node(a, b);
        }
    }

    fn analyze_tab(&mut self, ui: &mut egui::Ui) {
        let running = self.state.is_running();
        egui::Panel::left("analyze-options")
            .default_size(520.0)
            .resizable(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("analyze-left")
                    .show(ui, |ui| {
                        ui.add_enabled_ui(!running, |ui| {
                            self.evidence_section(ui);
                            self.options_section(ui);
                            self.hashing_section(ui);
                            self.report_section(ui);
                            self.trust_section(ui);
                        });
                        self.run_section(ui);
                    });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            self.results_table(ui);
            self.chain_view(ui);
        });
    }

    // ---------------------------------------------------------------------------------------------------------
    // Create tab
    // ---------------------------------------------------------------------------------------------------------

    fn ca_section(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        let ctx = ui.ctx().clone();
        let busy = self.state.create.busy;
        section_title(ui, t("ca_folder"));
        ui.horizontal(|ui| {
            entry(
                ui,
                &mut self.state.create.ca_entry,
                &t("ca_folder_hint"),
                400.0,
            );
            if let Some(d) = browse(ui, &t("browse"), true) {
                self.state.create.ca_entry = d.display().to_string();
            }
        });
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new(t("open_ca")))
                .clicked()
            {
                let op = self.state.create_open_ca();
                self.spawn_op(&ctx, op, false);
            }
            if ui
                .add_enabled(!busy, egui::Button::new(t("verify_ca")))
                .clicked()
            {
                let op = self.state.create_verify_ca();
                self.spawn_op(&ctx, op, false);
            }
        });
        if let Some(e) = &self.state.create.ca_error {
            ui.colored_label(RED, e);
        }
        match &self.state.create.verify {
            Some(Ok(n)) => {
                ui.colored_label(
                    GREEN,
                    format!("{} ({} {})", t("verify_ok"), n, t("records")),
                );
            }
            Some(Err(e)) => {
                ui.colored_label(RED, format!("{}: {}", t("verify_failed"), e));
            }
            None => {}
        }
        if let Some(v) = &self.state.create.ca {
            let f = &v.folder;
            egui::Grid::new("ca-grid")
                .num_columns(2)
                .spacing([10.0, 3.0])
                .show(ui, |ui| {
                    let rows = [
                        ("ca_id", format!("{} ({:?})", f.ca_id, f.kind)),
                        ("f_subject", f.subject.clone()),
                        ("f_serial", f.serial_hex.clone()),
                        ("validity", format!("{} → {}", f.not_before, f.not_after)),
                        (
                            "key_location",
                            match &f.key {
                                rv_certcheck_core::certs::KeyLocation::EncryptedFile {
                                    path,
                                    ..
                                } => path.clone(),
                                rv_certcheck_core::certs::KeyLocation::Pkcs11 {
                                    token_serial,
                                    key_id_hex,
                                    ..
                                } => {
                                    format!("token {token_serial} · key {key_id_hex}")
                                }
                            },
                        ),
                        (
                            "profiles",
                            f.allowed_profiles
                                .iter()
                                .map(|p| p.name())
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                        ("ca_records", v.records.to_string()),
                        ("f_sha256", f.certificate_sha256.clone()),
                    ];
                    for (k, val) in rows {
                        ui.label(egui::RichText::new(t(k)).weak());
                        ui.label(egui::RichText::new(val).monospace().size(11.5));
                        ui.end_row();
                    }
                });
            ui.label(egui::RichText::new(format!("{} ({})", t("issued"), v.issued.len())).strong());
            egui::ScrollArea::vertical()
                .max_height(180.0)
                .id_salt("issued")
                .show(ui, |ui| {
                    egui::Grid::new("issued-grid")
                        .striped(true)
                        .num_columns(4)
                        .spacing([8.0, 3.0])
                        .show(ui, |ui| {
                            for r in &v.issued {
                                ui.monospace(&r.serial[..r.serial.len().min(12)])
                                    .on_hover_text(&r.serial);
                                ui.label(&r.profile);
                                ui.label(egui::RichText::new(&r.subject).size(11.5));
                                match &r.revoked {
                                    Some(why) => {
                                        badge(ui, &format!("{} · {}", t("revoked"), why), RED)
                                    }
                                    None => badge(
                                        ui,
                                        &format!("{} {}", t("valid_until"), r.not_after),
                                        GREEN,
                                    ),
                                }
                                ui.end_row();
                            }
                        });
                });
        }
        section_title(ui, t("runs_folder"));
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.state.create.out_dir).desired_width(280.0));
            if let Some(d) = browse(ui, &t("browse"), true) {
                self.state.create.out_dir = d.display().to_string();
            }
        });
        ui.weak(t("runs_folder_note"));
        section_title(ui, t("tokens"));
        ui.horizontal(|ui| {
            entry(
                ui,
                &mut self.state.create.token_module,
                &t("module_hint"),
                280.0,
            );
            if ui
                .add_enabled(!busy, egui::Button::new(t("list_tokens")))
                .clicked()
            {
                let op = self.state.create_list_tokens();
                self.spawn_op(&ctx, op, false);
            }
        });
        for tk in &self.state.create.tokens {
            ui.label(
                egui::RichText::new(format!(
                    "slot {} · {} · {}",
                    tk.slot_id,
                    tk.slot_description,
                    if tk.token_present {
                        format!(
                            "{} ({})",
                            tk.label.clone().unwrap_or_default(),
                            tk.serial.clone().unwrap_or_default()
                        )
                    } else {
                        t("no_token")
                    }
                ))
                .size(11.5),
            );
        }
    }

    /// The key part of a wizard: encrypted file or token (with the token list), and the secret.
    fn key_form(&mut self, ui: &mut egui::Ui, w: Wizard, new_key: bool, file_only: bool) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        let mode = match w {
            Wizard::NewRoot => self.state.create.root.key.mode,
            Wizard::Import => self.state.create.import.key.mode,
            Wizard::Issue => self.state.create.issue.key.mode,
            _ => self.state.create.csr.key.mode,
        };
        if !file_only {
            ui.horizontal(|ui| {
                ui.label(t("key_location"));
                let mut m = mode;
                ui.radio_value(&mut m, KeyMode::File, t("key_file_mode"));
                ui.radio_value(&mut m, KeyMode::Token, t("key_token_mode"));
                if m != mode {
                    self.state.create_set_key_mode(w, m);
                }
            });
        }
        let serials: Vec<String> = self
            .state
            .create
            .tokens
            .iter()
            .filter(|x| x.token_present)
            .filter_map(|x| x.serial.clone())
            .collect();
        let mut use_serial = None;
        let f: &mut KeyForm = match w {
            Wizard::NewRoot => &mut self.state.create.root.key,
            Wizard::Import => &mut self.state.create.import.key,
            Wizard::Issue => &mut self.state.create.issue.key,
            _ => &mut self.state.create.csr.key,
        };
        egui::Grid::new(("key-grid", w.name()))
            .num_columns(2)
            .spacing([10.0, 5.0])
            .show(ui, |ui| match f.mode {
                KeyMode::File => {
                    ui.label(t("key_file"));
                    entry(
                        ui,
                        &mut f.key_file,
                        &t(if new_key {
                            "key_file_default"
                        } else {
                            "key_file_existing"
                        }),
                        300.0,
                    );
                    ui.end_row();
                    ui.label(t("key_password"));
                    masked(ui, &mut f.password, 200.0);
                    ui.end_row();
                    if new_key {
                        ui.label(t("password_again"));
                        masked(ui, &mut f.password_again, 200.0);
                        ui.end_row();
                    }
                }
                KeyMode::Token => {
                    ui.label(t("module"));
                    entry(ui, &mut f.module, &t("module_hint"), 300.0);
                    ui.end_row();
                    ui.label(t("token_serial"));
                    ui.horizontal(|ui| {
                        entry(ui, &mut f.token_serial, "", 160.0);
                        if !serials.is_empty() {
                            egui::ComboBox::from_id_salt(("tok", w.name()))
                                .selected_text(t("pick_token"))
                                .show_ui(ui, |ui| {
                                    for s in &serials {
                                        if ui.selectable_label(f.token_serial == *s, s).clicked() {
                                            use_serial = Some(s.clone());
                                        }
                                    }
                                });
                        } else {
                            ui.weak(t("list_tokens_first"));
                        }
                    });
                    ui.end_row();
                    ui.label(t("key_label"));
                    entry(ui, &mut f.key_label, &t("key_label_hint"), 200.0);
                    ui.end_row();
                    if !new_key {
                        ui.label(t("key_id"));
                        entry(ui, &mut f.key_id, "3f9a0c…", 200.0);
                        ui.end_row();
                    }
                    ui.label(t("pin"));
                    masked(ui, &mut f.pin, 160.0);
                    ui.end_row();
                }
            });
        if let Some(s) = use_serial {
            self.state.create_use_token(w, &s);
        }
    }

    fn wizard_form(&mut self, ui: &mut egui::Ui, w: Wizard) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        ui.weak(t(&format!("{}_help", w.key())));
        ui.add_space(4.0);
        match w {
            Wizard::NewRoot => {
                let f = &mut self.state.create.root;
                egui::Grid::new("root-grid")
                    .num_columns(2)
                    .spacing([10.0, 5.0])
                    .show(ui, |ui| {
                        ui.label(t("new_ca_folder"));
                        entry(ui, &mut f.ca_dir, &t("new_ca_folder_hint"), 300.0);
                        ui.end_row();
                        ui.label(t("ca_id"));
                        entry(ui, &mut f.ca_id, "rakvor-root-2026", 200.0);
                        ui.end_row();
                        ui.label(t("subject"));
                        entry(
                            ui,
                            &mut f.subject,
                            "C=CO,O=Rakvor SAS,CN=Rakvor Root CA 2026",
                            320.0,
                        );
                        ui.end_row();
                        ui.label(t("key_type"));
                        key_type_combo(ui, "root-kt", &mut f.key_type);
                        ui.end_row();
                        ui.label(t("validity_days"));
                        entry(ui, &mut f.validity_days, "7300", 80.0);
                        ui.end_row();
                    });
                self.key_form(ui, w, true, false);
                if self.state.create.root.key.mode == KeyMode::Token {
                    let mut on = self.state.create.root.confirm_root;
                    if ui
                        .checkbox(
                            &mut on,
                            egui::RichText::new(t("confirm_root")).color(AMBER).strong(),
                        )
                        .changed()
                    {
                        self.state.create_set_confirm_root(on);
                    }
                    ui.weak(t("confirm_root_note"));
                }
            }
            Wizard::Import => {
                let f = &mut self.state.create.import;
                egui::Grid::new("import-grid")
                    .num_columns(2)
                    .spacing([10.0, 5.0])
                    .show(ui, |ui| {
                        ui.label(t("new_ca_folder"));
                        entry(ui, &mut f.ca_dir, &t("new_ca_folder_hint"), 300.0);
                        ui.end_row();
                        ui.label(t("ca_id"));
                        entry(ui, &mut f.ca_id, "rakvor-issuing-2026", 200.0);
                        ui.end_row();
                        ui.label(t("ca_cert_file"));
                        entry(ui, &mut f.cert_file, "certs/<SERIAL>.crt", 300.0);
                        ui.end_row();
                    });
                self.key_form(ui, w, false, false);
            }
            Wizard::Issue => {
                let profile = self.state.create.issue.profile;
                let mut chosen = None;
                ui.horizontal(|ui| {
                    ui.label(t("profile"));
                    egui::ComboBox::from_id_salt("profile")
                        .selected_text(profile.name())
                        .show_ui(ui, |ui| {
                            for (p, enabled, why) in profile_choices() {
                                let r = ui.add_enabled(
                                    enabled,
                                    egui::Button::selectable(profile == p, p.name()),
                                );
                                let r = match why {
                                    Some(k) => r.on_disabled_hover_text(t(k)),
                                    None => r,
                                };
                                if r.clicked() {
                                    chosen = Some(p);
                                }
                            }
                        });
                    ui.weak(t(&format!(
                        "profile_{}_help",
                        profile.name().replace('-', "_")
                    )));
                });
                ui.weak(format!(
                    "client-internal: {}",
                    t("profile_client_internal_reason")
                ));
                if let Some(p) = chosen
                    && let Err(e) = self.state.create_set_profile(p)
                {
                    self.create_notice = Some(e);
                }
                let examiner = profile == IssueProfile::Examiner;
                let f = &mut self.state.create.issue;
                egui::Grid::new("issue-grid")
                    .num_columns(2)
                    .spacing([10.0, 5.0])
                    .show(ui, |ui| {
                        ui.label(t("subject"));
                        entry(ui, &mut f.subject, "C=CO,O=Rakvor SAS,CN=Ana Ruiz", 320.0);
                        ui.end_row();
                        ui.label(t("sans"));
                        entry(
                            ui,
                            &mut f.sans,
                            "dns:hub.rakvor.local email:ana.ruiz@rakvor.co",
                            320.0,
                        );
                        ui.end_row();
                        ui.label(t("validity_days"));
                        entry(ui, &mut f.validity_days, "825", 80.0);
                        ui.end_row();
                        if !examiner {
                            ui.label(t("from_csr"));
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut f.use_csr, "");
                                ui.add_enabled(
                                    f.use_csr,
                                    egui::TextEdit::singleline(&mut f.csr_file)
                                        .hint_text("request.csr")
                                        .desired_width(260.0),
                                );
                            });
                            ui.end_row();
                        }
                        if !f.use_csr || examiner {
                            ui.label(t("key_type"));
                            key_type_combo(ui, "issue-kt", &mut f.key_type);
                            ui.end_row();
                        }
                        ui.label(t("ca_secret"));
                        masked(ui, &mut f.ca_secret, 200.0);
                        ui.end_row();
                        if examiner {
                            ui.label(t("p12_new_password"));
                            masked(ui, &mut f.p12_password, 200.0);
                            ui.end_row();
                            ui.label(t("password_again"));
                            masked(ui, &mut f.p12_again, 200.0);
                            ui.end_row();
                        }
                    });
                if !self.state.create.issue.use_csr || examiner {
                    self.key_form(ui, w, true, examiner);
                }
            }
            Wizard::Revoke => {
                let serials: Vec<(String, String)> = self
                    .state
                    .create
                    .ca
                    .as_ref()
                    .map(|v| {
                        v.issued
                            .iter()
                            .filter(|r| r.revoked.is_none())
                            .map(|r| (r.serial.clone(), r.subject.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                let f = &mut self.state.create.revoke;
                egui::Grid::new("revoke-grid")
                    .num_columns(2)
                    .spacing([10.0, 5.0])
                    .show(ui, |ui| {
                        ui.label(t("serial"));
                        egui::ComboBox::from_id_salt("serial")
                            .selected_text(if f.serial.is_empty() {
                                t("pick_certificate")
                            } else {
                                f.serial.clone()
                            })
                            .width(320.0)
                            .show_ui(ui, |ui| {
                                for (s, subj) in &serials {
                                    ui.selectable_value(
                                        &mut f.serial,
                                        s.clone(),
                                        format!("{} · {}", &s[..s.len().min(12)], subj),
                                    );
                                }
                            });
                        ui.end_row();
                        ui.label(t("reason"));
                        egui::ComboBox::from_id_salt("reason")
                            .selected_text(f.reason.clone())
                            .show_ui(ui, |ui| {
                                for r in REVOCATION_REASONS {
                                    ui.selectable_value(&mut f.reason, r.to_string(), r);
                                }
                            });
                        ui.end_row();
                        ui.label(t("revoked_at"));
                        entry(ui, &mut f.at, &t("now_hint"), 200.0);
                        ui.end_row();
                    });
            }
            Wizard::Crl => {
                let f = &mut self.state.create.crl;
                egui::Grid::new("crl-grid")
                    .num_columns(2)
                    .spacing([10.0, 5.0])
                    .show(ui, |ui| {
                        ui.label(t("next_update_days"));
                        entry(ui, &mut f.next_update_days, "30", 80.0);
                        ui.end_row();
                        ui.label(t("ca_secret"));
                        masked(ui, &mut f.ca_secret, 200.0);
                        ui.end_row();
                    });
            }
            Wizard::Csr => {
                let f = &mut self.state.create.csr;
                egui::Grid::new("csr-grid")
                    .num_columns(2)
                    .spacing([10.0, 5.0])
                    .show(ui, |ui| {
                        ui.label(t("subject"));
                        entry(
                            ui,
                            &mut f.subject,
                            "C=CO,O=Rakvor SAS,CN=www.rakvor.co",
                            320.0,
                        );
                        ui.end_row();
                        ui.label(t("sans"));
                        entry(ui, &mut f.sans, "dns:www.rakvor.co", 320.0);
                        ui.end_row();
                        ui.label(t("key_type"));
                        key_type_combo(ui, "csr-kt", &mut f.key_type);
                        ui.end_row();
                        ui.label(t("csr_out"));
                        entry(ui, &mut f.csr_out, "www.csr", 300.0);
                        ui.end_row();
                    });
                self.key_form(ui, w, true, false);
            }
            Wizard::Lab => {
                let f = &mut self.state.create.lab;
                egui::Grid::new("lab-grid")
                    .num_columns(2)
                    .spacing([10.0, 5.0])
                    .show(ui, |ui| {
                        ui.label(t("lab_set"));
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut f.set, "full".to_string(), "full");
                            ui.radio_value(&mut f.set, "minimal".to_string(), "minimal");
                        });
                        ui.end_row();
                        ui.label(t("seed"));
                        entry(ui, &mut f.seed, "1", 80.0);
                        ui.end_row();
                        ui.label(t("base_time"));
                        entry(ui, &mut f.base_time, "2026-01-01T00:00:00Z", 200.0);
                        ui.end_row();
                        ui.label(t("lab_out"));
                        entry(ui, &mut f.out_dir, "lab-full-1", 300.0);
                        ui.end_row();
                    });
                ui.weak(rv_certcheck_core::creation::LAB_NOTICE);
            }
        }
    }

    fn create_result(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        let Some(o) = self.state.create.last.clone() else {
            return;
        };
        ui.separator();
        let (title, col) = if o.ok {
            (t("op_done"), GREEN)
        } else {
            (t("op_failed"), RED)
        };
        ui.horizontal(|ui| {
            badge(ui, &title, col);
            ui.label(egui::RichText::new(&o.command).strong());
            ui.weak(&o.run_id);
        });
        if let Some(e) = &o.error {
            ui.colored_label(RED, e);
        }
        for l in &o.summary {
            ui.monospace(l);
        }
        if !o.files.is_empty() {
            ui.label(egui::RichText::new(t("files_written")).strong());
            egui::Grid::new("files-grid")
                .striped(true)
                .num_columns(3)
                .spacing([8.0, 2.0])
                .show(ui, |ui| {
                    for (role, path, sha) in &o.files {
                        ui.label(role);
                        ui.monospace(path.display().to_string());
                        ui.monospace(&sha[..sha.len().min(16)]).on_hover_text(sha);
                        ui.end_row();
                    }
                });
        }
        ui.horizontal(|ui| {
            if let Some(f) = self.state.create.last_folder.clone()
                && ui.button(t("open_folder")).clicked()
            {
                open_path(&f);
            }
            if !o.report_dir.as_os_str().is_empty() && ui.button(t("open_report")).clicked() {
                open_path(&o.report_dir.join("report.txt"));
            }
            if !o.log_dir.as_os_str().is_empty() && ui.button(t("open_logs")).clicked() {
                open_path(&o.log_dir);
            }
        });
    }

    fn create_tab(&mut self, ui: &mut egui::Ui) {
        let c = self.state.catalog();
        let t = |k: &str| c.ui(k);
        let busy = self.state.create.busy;
        egui::Panel::left("create-ca")
            .default_size(520.0)
            .resizable(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("create-left")
                    .show(ui, |ui| {
                        ui.add_enabled_ui(!busy, |ui| self.ca_section(ui));
                    });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("create-main")
                .show(ui, |ui| {
                    section_title(ui, t("wizards"));
                    ui.horizontal_wrapped(|ui| {
                        for w in Wizard::ALL {
                            let on = self.state.create.wizard == Some(w);
                            if ui
                                .add_enabled(!busy, egui::Button::selectable(on, t(&w.key())))
                                .clicked()
                            {
                                self.create_notice = None;
                                self.state
                                    .create_set_wizard(if on { None } else { Some(w) });
                            }
                        }
                    });
                    ui.colored_label(AMBER, t("internal_notice"));
                    if let Some(w) = self.state.create.wizard {
                        ui.separator();
                        ui.label(egui::RichText::new(t(&w.key())).strong().size(15.0));
                        if w.needs_ca() && self.state.create.ca.is_none() {
                            ui.colored_label(AMBER, t("err_open_ca_first"));
                        }
                        ui.add_enabled_ui(!busy, |ui| self.wizard_form(ui, w));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            let run = egui::Button::new(
                                egui::RichText::new(t("run_wizard"))
                                    .strong()
                                    .color(egui::Color32::WHITE),
                            )
                            .fill(BLUE);
                            if ui.add_enabled(!busy, run).clicked() {
                                let ctx = ui.ctx().clone();
                                let op = self.state.create_prepare();
                                self.spawn_op(&ctx, op, false);
                            }
                            if busy {
                                ui.spinner();
                                ui.weak(t("working"));
                            }
                            if let Some(n) = &self.create_notice {
                                ui.colored_label(AMBER, n);
                            }
                        });
                    }
                    self.create_result(ui);
                });
        });
    }

    // ---------------------------------------------------------------------------------------------------------
    // Trust lists tab
    // ---------------------------------------------------------------------------------------------------------

    fn trust_tab(&mut self, ui: &mut egui::Ui) {
        let c: &'static Catalog = self.state.catalog();
        let t = |k: &str| c.ui(k);
        let busy = self.state.create.busy;
        let ctx = ui.ctx().clone();
        egui::Panel::left("trust-left")
            .default_size(620.0)
            .resizable(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("trust-left-s")
                    .show(ui, |ui| {
                        section_title(ui, t("tl_store"));
                        ui.horizontal(|ui| {
                            let r = ui.add(
                                egui::TextEdit::singleline(&mut self.state.trust.store_dir)
                                    .desired_width(360.0),
                            );
                            if r.lost_focus() || ui.button(t("refresh")).clicked() {
                                self.state.trust.refresh();
                            }
                        });
                        section_title(ui, t("tl_import"));
                        ui.horizontal(|ui| {
                            let mut k = self.state.trust.import_list;
                            ui.radio_value(&mut k, TrustListKind::Eu, t("tl_eu"));
                            ui.radio_value(&mut k, TrustListKind::Co, t("tl_co"));
                            if k != self.state.trust.import_list {
                                self.state.trust_set_import_list(k);
                            }
                        });
                        ui.horizontal(|ui| {
                            entry(
                                ui,
                                &mut self.state.trust.import_file,
                                &t("tl_file_hint"),
                                320.0,
                            );
                            if let Some(f) = browse(ui, &t("browse"), false) {
                                self.state.trust.import_file = f.display().to_string();
                            }
                            if ui
                                .add_enabled(!busy, egui::Button::new(t("tl_import_button")))
                                .clicked()
                            {
                                let op = self.state.trust_import();
                                self.spawn_op(&ctx, op, true);
                            }
                        });
                        ui.weak(t("tl_signature_note"));
                        if let Some(n) = &self.trust_notice {
                            ui.colored_label(AMBER, n);
                        }
                        if let Some(o) = &self.state.create.last
                            && o.command == "trust-list import"
                        {
                            let col = if o.ok { GREEN } else { RED };
                            ui.colored_label(
                                col,
                                o.summary
                                    .first()
                                    .cloned()
                                    .or(o.error.clone())
                                    .unwrap_or_default(),
                            );
                        }
                        if let Some(e) = &self.state.trust.error {
                            ui.colored_label(RED, e);
                        }
                        section_title(
                            ui,
                            format!(
                                "{} ({})",
                                t("tl_snapshots"),
                                self.state.trust.snapshots.len()
                            ),
                        );
                        let mut inspect = None;
                        let mut anchor = None;
                        let used = self.state.analysis.anchor_lists.clone();
                        egui::Grid::new("snap-grid")
                            .striped(true)
                            .num_columns(5)
                            .spacing([8.0, 3.0])
                            .show(ui, |ui| {
                                for h in ["tl_fetched", "tl_id", "f_sha256", "tl_services", ""] {
                                    ui.label(
                                        egui::RichText::new(if h.is_empty() {
                                            String::new()
                                        } else {
                                            t(h)
                                        })
                                        .strong()
                                        .color(CYAN),
                                    );
                                }
                                ui.end_row();
                                for (i, s) in self.state.trust.snapshots.iter().enumerate() {
                                    ui.label(&s.fetched_utc);
                                    let sel = self
                                        .state
                                        .trust
                                        .selected
                                        .as_ref()
                                        .is_some_and(|x| x.id == s.id);
                                    if ui.selectable_label(sel, &s.id).clicked() {
                                        inspect = Some(i);
                                    }
                                    ui.monospace(&s.sha256[..s.sha256.len().min(16)])
                                        .on_hover_text(&s.sha256);
                                    ui.label(format!("{} / {}", s.services, s.entries));
                                    let spec = anchor_spec(s);
                                    let mut on = used.contains(&spec);
                                    if ui.checkbox(&mut on, t("tl_use_anchor")).changed() {
                                        anchor = Some((spec, on));
                                    }
                                    ui.end_row();
                                }
                            });
                        if let Some(i) = inspect {
                            self.state.trust_inspect(i);
                        }
                        if let Some((s, on)) = anchor {
                            self.state.set_anchor_list(&s, on);
                        }
                    });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            let Some(s) = self.state.trust.selected.clone() else {
                ui.weak(t("tl_pick"));
                return;
            };
            section_title(ui, s.id.clone());
            egui::Grid::new("snap-meta")
                .num_columns(2)
                .spacing([10.0, 3.0])
                .show(ui, |ui| {
                    for (k, v) in [
                        ("tl_source", s.source.clone()),
                        ("tl_fetched", s.fetched_utc.clone()),
                        ("f_sha256", s.sha256.clone()),
                        ("tl_issue_date", s.issue_date.clone().unwrap_or_default()),
                        ("tl_next_update", s.next_update.clone().unwrap_or_default()),
                        ("tl_territory", s.territory.clone().unwrap_or_default()),
                        (
                            "tl_signature",
                            if s.signature_verified {
                                t("yes")
                            } else {
                                t("tl_not_verified")
                            },
                        ),
                    ] {
                        ui.label(egui::RichText::new(t(k)).weak());
                        ui.label(egui::RichText::new(v).monospace().size(11.5));
                        ui.end_row();
                    }
                });
            ui.horizontal(|ui| {
                ui.label(t("filter"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.state.trust.filter).desired_width(240.0),
                );
            });
            let services = self.state.trust.services();
            egui::ScrollArea::vertical()
                .id_salt("services")
                .show(ui, |ui| {
                    egui::Grid::new("svc-grid")
                        .striped(true)
                        .num_columns(5)
                        .spacing([8.0, 3.0])
                        .show(ui, |ui| {
                            for h in ["tl_country", "tl_tsp", "tl_service", "tl_type", "tl_status"]
                            {
                                ui.label(egui::RichText::new(t(h)).strong().color(CYAN));
                            }
                            ui.end_row();
                            for (x, n) in services {
                                ui.label(&x.country);
                                ui.label(egui::RichText::new(&x.tsp_name).size(11.5));
                                ui.label(
                                    egui::RichText::new(format!("{} ({n})", x.service_name))
                                        .size(11.5),
                                );
                                ui.label(
                                    egui::RichText::new(
                                        x.service_type.rsplit('/').next().unwrap_or(""),
                                    )
                                    .size(11.5),
                                )
                                .on_hover_text(&x.service_type);
                                let st = x
                                    .current_status
                                    .rsplit('/')
                                    .next()
                                    .unwrap_or("")
                                    .to_string();
                                let col = if st.contains("granted") || st.contains("accredited") {
                                    GREEN
                                } else {
                                    AMBER
                                };
                                badge(ui, &st, col);
                                ui.end_row();
                            }
                        });
                });
        });
    }

    /// Draws one frame (the eframe entry point and the headless screenshot both call it).
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        if !self.themed {
            apply_theme(ui.ctx());
            self.themed = true;
        }
        self.drain();
        if self.state.is_running() || self.state.create.busy {
            // Keep the elapsed timer moving even when no event arrives (large files).
            ui.ctx().request_repaint_after(Duration::from_millis(200));
        }
        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(4.0);
            self.header(ui);
        });
        match self.state.tab {
            Tab::Analyze => self.analyze_tab(ui),
            Tab::Create => self.create_tab(ui),
            Tab::TrustLists => self.trust_tab(ui),
        }
    }
}

impl Default for HashInvApp {
    fn default() -> Self {
        Self::new()
    }
}

impl eframe::App for HashInvApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

#[cfg(test)]
mod launch_tests {
    use super::*;
    use crate::launch::parse_launch_args;

    fn launch(args: &[&str]) -> HashInvApp {
        HashInvApp::from_launch(parse_launch_args(args.iter().map(std::ffi::OsString::from)))
    }

    fn actions(app: &HashInvApp) -> Vec<&str> {
        app.state
            .ui
            .actions
            .iter()
            .map(|(a, _)| a.as_str())
            .collect()
    }

    #[test]
    fn launcher_case_dir_is_preset_and_audited() {
        let app = launch(&["--case-dir", "X", "a.crt"]);
        assert_eq!(app.state.case_dir, "X");
        assert_eq!(app.case_entry, "X");
        assert!(app.state.out_locked());
        let a = actions(&app);
        assert!(
            a.ends_with(&["ui_case_dir_from_launcher", "ui_case_dir_changed"]),
            "{a:?}"
        );
        assert!(app.notice.is_none());
    }

    #[test]
    fn case_dir_without_a_value_is_noted_and_ignored() {
        let app = launch(&["a.crt", "--case-dir"]);
        assert!(app.state.case_dir.is_empty());
        assert!(actions(&app).contains(&"ui_launch_argument_ignored"));
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.contains("--case-dir"))
        );
    }
}
