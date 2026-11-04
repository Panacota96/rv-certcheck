//! Renders the window headless (no display, no GPU) to a PNG, for the documentation:
//!
//!     cargo run -p rv-certcheck-gui --example gui_screenshot -- docs/images/gui-analyze.png analyze [en|es|fr]
//!     cargo run -p rv-certcheck-gui --example gui_screenshot -- docs/images/gui-create.png create [en|es|fr]
//!
//! `analyze` runs the sample (`examples/sample/evidence`, anchor `anchors/rakvor-lab-root.crt`, judged at
//! 2026-06-01) in process and opens the chain view of `leaf-revoked.crt`. `create` builds a throw-away PKI
//! (root, intermediate imported as the issuing CA, one examiner certificate, one revocation) through `state`,
//! opens the issuing CA and the Issue wizard. Then a few egui frames run and egui's tessellated meshes are
//! rasterised on the CPU (textured triangles, premultiplied alpha), so the picture is what the window draws,
//! minus the GPU. Same approach as rv-imgauth's viewer_screenshot. No password typed here is ever drawn: masked
//! fields render as dots and are empty after each operation.
#![forbid(unsafe_code)]

use eframe::egui;
use egui::epaint::{ClippedPrimitive, Color32, ImageData, Primitive, TextureId};
use rv_certcheck_core::certs::{IssueProfile, KeySpec};
use rv_certcheck_gui::app::HashInvApp;
use rv_certcheck_gui::state::create::{Wizard, execute};
use rv_certcheck_gui::state::{AtChoice, GuiState, Tab};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const W: usize = 1600;
const H: usize = 1000;

struct Tex {
    w: usize,
    h: usize,
    px: Vec<Color32>,
}

impl Tex {
    /// Bilinear sample of premultiplied texels, clamped at the edges.
    fn sample(&self, u: f32, v: f32) -> [f32; 4] {
        let x = (u * self.w as f32 - 0.5).clamp(0.0, (self.w - 1) as f32);
        let y = (v * self.h as f32 - 0.5).clamp(0.0, (self.h - 1) as f32);
        let (x0, y0) = (x.floor() as usize, y.floor() as usize);
        let (x1, y1) = ((x0 + 1).min(self.w - 1), (y0 + 1).min(self.h - 1));
        let (fx, fy) = (x - x0 as f32, y - y0 as f32);
        let at = |x: usize, y: usize| {
            let c = self.px[y * self.w + x];
            [c.r() as f32, c.g() as f32, c.b() as f32, c.a() as f32]
        };
        let (a, b, c, d) = (at(x0, y0), at(x1, y0), at(x0, y1), at(x1, y1));
        let mut o = [0.0; 4];
        for i in 0..4 {
            let top = a[i] + (b[i] - a[i]) * fx;
            let bot = c[i] + (d[i] - c[i]) * fx;
            o[i] = (top + (bot - top) * fy) / 255.0;
        }
        o
    }
}

fn rasterise(
    prims: &[ClippedPrimitive],
    textures: &HashMap<TextureId, Tex>,
    ppp: f32,
) -> Vec<[f32; 4]> {
    let mut canvas = vec![[0.0f32, 0.0, 0.0, 1.0]; W * H];
    for p in prims {
        let Primitive::Mesh(mesh) = &p.primitive else {
            continue;
        };
        let Some(tex) = textures.get(&mesh.texture_id) else {
            continue;
        };
        let cx0 = (p.clip_rect.min.x * ppp).max(0.0).floor() as i64;
        let cy0 = (p.clip_rect.min.y * ppp).max(0.0).floor() as i64;
        let cx1 = ((p.clip_rect.max.x * ppp).ceil() as i64).min(W as i64);
        let cy1 = ((p.clip_rect.max.y * ppp).ceil() as i64).min(H as i64);
        for t in mesh.indices.chunks_exact(3) {
            let v = [
                &mesh.vertices[t[0] as usize],
                &mesh.vertices[t[1] as usize],
                &mesh.vertices[t[2] as usize],
            ];
            let pt: Vec<[f32; 2]> = v.iter().map(|v| [v.pos.x * ppp, v.pos.y * ppp]).collect();
            let area = (pt[1][0] - pt[0][0]) * (pt[2][1] - pt[0][1])
                - (pt[2][0] - pt[0][0]) * (pt[1][1] - pt[0][1]);
            if area.abs() < 1e-9 {
                continue;
            }
            let minx = pt.iter().map(|p| p[0]).fold(f32::MAX, f32::min).floor() as i64;
            let maxx = pt.iter().map(|p| p[0]).fold(f32::MIN, f32::max).ceil() as i64;
            let miny = pt.iter().map(|p| p[1]).fold(f32::MAX, f32::min).floor() as i64;
            let maxy = pt.iter().map(|p| p[1]).fold(f32::MIN, f32::max).ceil() as i64;
            for y in miny.max(cy0)..maxy.min(cy1) {
                for x in minx.max(cx0)..maxx.min(cx1) {
                    let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
                    let e = |a: [f32; 2], b: [f32; 2]| {
                        (b[0] - a[0]) * (py - a[1]) - (b[1] - a[1]) * (px - a[0])
                    };
                    let w0 = e(pt[1], pt[2]) / area;
                    let w1 = e(pt[2], pt[0]) / area;
                    let w2 = e(pt[0], pt[1]) / area;
                    if w0 < 0.0 || w1 < 0.0 || w2 < 0.0 {
                        continue;
                    }
                    let u = w0 * v[0].uv.x + w1 * v[1].uv.x + w2 * v[2].uv.x;
                    let vv = w0 * v[0].uv.y + w1 * v[1].uv.y + w2 * v[2].uv.y;
                    let s = tex.sample(u, vv);
                    let col = |i: usize| {
                        let c = |v: &egui::epaint::Vertex| v.color.to_array()[i] as f32 / 255.0;
                        w0 * c(v[0]) + w1 * c(v[1]) + w2 * c(v[2])
                    };
                    let src = [s[0] * col(0), s[1] * col(1), s[2] * col(2), s[3] * col(3)];
                    let d = &mut canvas[y as usize * W + x as usize];
                    for i in 0..4 {
                        d[i] = src[i] + d[i] * (1.0 - src[3]);
                    }
                }
            }
        }
    }
    canvas
}

fn analyze_state(root: &Path, out: &Path) -> GuiState {
    let sample = root.join("examples/sample");
    let mut s = GuiState {
        timestamp: false,
        ..Default::default()
    };
    s.add_input(sample.join("evidence"));
    s.add_anchor_file(Some(sample.join("anchors/rakvor-lab-root.crt")));
    s.set_at(AtChoice::Date, "2026-06-01T00:00:00Z");
    s.actor = "Sample".into();
    s.out_dir = out.display().to_string();
    let cfg = s.to_config().expect("config");
    s.start();
    let cancel = std::sync::atomic::AtomicBool::new(false);
    rv_certcheck_core::run(&cfg, &mut |e| s.apply(e), &cancel).expect("run");
    let i = s
        .rows
        .iter()
        .position(|r| r.name == "leaf-revoked.crt")
        .expect("sample row");
    s.select_row(i);
    s
}

fn create_state(out: &Path) -> GuiState {
    let mut s = GuiState {
        actor: "Ana Ruiz".into(),
        ..Default::default()
    };
    s.create.out_dir = out.join("runs").display().to_string();
    let go = |s: &mut GuiState| {
        let op = s.create_prepare().expect("valid form");
        let r = execute(op);
        assert!(r.outcome.ok, "{:?}", r.outcome.error);
        s.create_finish(r);
    };
    let pw = |f: &mut rv_certcheck_gui::state::MaskedField, v: &str| f.buffer().push_str(v);
    s.set_tab(Tab::Create);
    s.create_set_wizard(Some(Wizard::NewRoot));
    s.create.root.ca_dir = out.join("pki/root-2026").display().to_string();
    s.create.root.ca_id = "rakvor-root-2026".into();
    s.create.root.subject = "C=CO,O=Rakvor SAS,CN=Rakvor Root CA 2026".into();
    s.create.root.key_type = KeySpec::P384;
    pw(&mut s.create.root.key.password, "screenshot-root");
    pw(&mut s.create.root.key.password_again, "screenshot-root");
    go(&mut s);
    s.create_set_wizard(Some(Wizard::Issue));
    s.create_set_profile(IssueProfile::Intermediate).unwrap();
    s.create.issue.subject = "C=CO,O=Rakvor SAS,CN=Rakvor Issuing CA 2026".into();
    s.create.issue.key_type = KeySpec::P384;
    s.create.issue.validity_days = "1825".into();
    s.create.issue.key.key_file = out.join("pki/issuing-2026.key.p8").display().to_string();
    pw(&mut s.create.issue.key.password, "screenshot-int");
    pw(&mut s.create.issue.key.password_again, "screenshot-int");
    pw(&mut s.create.issue.ca_secret, "screenshot-root");
    go(&mut s);
    s.create_set_wizard(Some(Wizard::Import));
    s.create.import.ca_dir = out.join("pki/issuing-2026").display().to_string();
    s.create.import.ca_id = "rakvor-issuing-2026".into();
    pw(&mut s.create.import.key.password, "screenshot-int");
    go(&mut s);
    for (cn, mail, prof) in [
        (
            "Ana Ruiz",
            "email:ana.ruiz@rakvor.co",
            IssueProfile::Examiner,
        ),
        (
            "Luis Gómez",
            "email:luis.gomez@rakvor.co",
            IssueProfile::Examiner,
        ),
        (
            "hub.rakvor.local",
            "dns:hub.rakvor.local",
            IssueProfile::TlsServer,
        ),
    ] {
        s.create_set_wizard(Some(Wizard::Issue));
        s.create_set_profile(prof).unwrap();
        s.create.issue.subject = format!("C=CO,O=Rakvor SAS,CN={cn}");
        s.create.issue.sans = mail.into();
        s.create.issue.key_type = KeySpec::P256;
        s.create.issue.validity_days = "825".into();
        pw(&mut s.create.issue.key.password, "screenshot-key");
        pw(&mut s.create.issue.key.password_again, "screenshot-key");
        pw(&mut s.create.issue.ca_secret, "screenshot-int");
        if prof == IssueProfile::Examiner {
            pw(&mut s.create.issue.p12_password, "screenshot-p12");
            pw(&mut s.create.issue.p12_again, "screenshot-p12");
        }
        go(&mut s);
    }
    let serial = s.create.ca.as_ref().unwrap().issued[1].serial.clone();
    s.create_set_wizard(Some(Wizard::Revoke));
    s.create.revoke.serial = serial;
    s.create.revoke.reason = "keyCompromise".into();
    go(&mut s);
    let op = s.create_verify_ca().expect("verify");
    s.create_finish(execute(op));
    // The examiner issue of Ana's successor, filled in but not run: the last outcome stays the verify run.
    s.create_set_wizard(Some(Wizard::Issue));
    s.create_set_profile(IssueProfile::Examiner).unwrap();
    s.create.issue.subject = "C=CO,O=Rakvor SAS,CN=Marta Díaz".into();
    s.create.issue.sans = "email:marta.diaz@rakvor.co".into();
    s.create.issue.validity_days = "825".into();
    pw(&mut s.create.issue.ca_secret, "dots-only");
    let op = s.create_list_tokens();
    assert!(op.is_err(), "no module typed: refused before any run");
    s.create.token_module = "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll".into();
    s
}

fn main() {
    let mut args = std::env::args().skip(1);
    let target = PathBuf::from(args.next().unwrap_or_else(|| "gui.png".into()));
    let mode = args.next().unwrap_or_else(|| "analyze".into());
    let ui_lang = args.next().unwrap_or_else(|| "en".into());
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root");
    let out = std::env::temp_dir().join(format!("rv-certcheck-gui-shot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let mut s = match mode.as_str() {
        "create" => create_state(&out),
        _ => analyze_state(&root, &out),
    };
    s.set_ui_lang(&ui_lang);
    let mut app = HashInvApp::from_state(s);

    let ctx = egui::Context::default();
    let mut textures: HashMap<TextureId, Tex> = HashMap::new();
    let mut last = None;
    for frame in 0..5 {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(W as f32, H as f32),
            )),
            time: Some(frame as f64 * 0.1),
            ..Default::default()
        };
        let mut output = ctx.run_ui(raw, |ui| app.draw(ui));
        for (id, deltas) in &output.textures_delta.set {
            for d in deltas {
                let ImageData::Color(img) = &d.image;
                match d.pos {
                    None => {
                        textures.insert(
                            *id,
                            Tex {
                                w: img.size[0],
                                h: img.size[1],
                                px: img.pixels.clone(),
                            },
                        );
                    }
                    Some([x0, y0]) => {
                        let t = textures.get_mut(id).expect("patch of a known texture");
                        for y in 0..img.size[1] {
                            for x in 0..img.size[0] {
                                t.px[(y0 + y) * t.w + x0 + x] = img.pixels[y * img.size[0] + x];
                            }
                        }
                    }
                }
            }
        }
        output.textures_delta.clear();
        last = Some(output);
    }
    let output = last.expect("frames ran");
    let ppp = output.pixels_per_point;
    let prims = ctx.tessellate(output.shapes, ppp);
    let canvas = rasterise(&prims, &textures, ppp);
    let rgba: Vec<u8> = canvas
        .iter()
        .flat_map(|p| {
            let a = p[3].clamp(1e-6, 1.0);
            [p[0] / a, p[1] / a, p[2] / a, 1.0].map(|c| (c.clamp(0.0, 1.0) * 255.0).round() as u8)
        })
        .collect();
    if let Some(dir) = target.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).expect("output folder");
    }
    let file = std::fs::File::create(&target).expect("create png");
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), W as u32, H as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()
        .expect("png")
        .write_image_data(&rgba)
        .expect("png data");
    println!(
        "wrote {} ({W}x{H}, {} meshes, {} ui_* actions pending)",
        target.display(),
        prims.len(),
        app.state().ui.actions.len()
    );
    let _ = std::fs::remove_dir_all(&out);
}
