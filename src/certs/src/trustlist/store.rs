//! OWNER: A. Snapshot storage (`<store>/<list>/<id>.json`), listing and lookup.
//!
//! Each snapshot is written as pretty JSON (`<id>.json`) next to `<id>.json.sha256` (`sha256sum` format). `load`
//! recomputes the digest of the JSON file and refuses a snapshot whose file no longer matches, so an anchor
//! taken from a trust list is exactly the one imported (the import itself records the SHA-256 of the source XML
//! or CSV in the snapshot).
use crate::analysis::util::*;
use crate::model::*;
use std::path::{Path, PathBuf};

fn io(what: &str, p: &Path, e: impl std::fmt::Display) -> CertError {
    CertError::new(ErrorKind::Io, format!("{what} {}: {e}", p.display()))
}

/// `<list>-<YYYYMMDDTHHMMSSZ>-<first 8 hex of sha256>`.
pub(crate) fn snapshot_id(
    list: TrustListKind,
    fetched_utc: &str,
    sha256: &str,
) -> CertResult<String> {
    let t = epoch_to_rfc3339(rfc3339_to_epoch(fetched_utc)?);
    let compact: String = t.chars().filter(|c| *c != '-' && *c != ':').collect();
    Ok(format!(
        "{}-{}-{}",
        list.name(),
        compact,
        &sha256[..8.min(sha256.len())]
    ))
}

fn safe_id(id: &str) -> CertResult<()> {
    if id.is_empty()
        || id.contains("..")
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            format!("invalid trust-list snapshot id '{id}'"),
        ));
    }
    Ok(())
}

/// Writes the snapshot and its digest file; returns the JSON path.
pub(crate) fn save(store_dir: &Path, snap: &TrustListSnapshot) -> CertResult<PathBuf> {
    safe_id(&snap.id)?;
    let dir = store_dir.join(&snap.list);
    std::fs::create_dir_all(&dir).map_err(|e| io("cannot create", &dir, e))?;
    let path = dir.join(format!("{}.json", snap.id));
    let mut text = serde_json::to_string_pretty(snap)
        .map_err(|e| CertError::new(ErrorKind::Crypto, format!("snapshot JSON: {e}")))?;
    text.push('\n');
    std::fs::write(&path, &text).map_err(|e| io("cannot write", &path, e))?;
    let side = dir.join(format!("{}.json.sha256", snap.id));
    std::fs::write(
        &side,
        format!("{}  {}.json\n", sha256_hex(text.as_bytes()), snap.id),
    )
    .map_err(|e| io("cannot write", &side, e))?;
    Ok(path)
}

fn read_snapshot(path: &Path) -> CertResult<(TrustListSnapshot, String)> {
    let data = std::fs::read(path).map_err(|e| io("cannot read", path, e))?;
    let got = sha256_hex(&data);
    let side = PathBuf::from(format!("{}.sha256", path.display()));
    let rec =
        std::fs::read_to_string(&side).map_err(|e| io("cannot read the digest file", &side, e))?;
    let want = rec.split_whitespace().next().unwrap_or_default();
    if want != got {
        return Err(CertError::new(
            ErrorKind::Parse,
            format!(
                "trust-list snapshot {} was altered: SHA-256 {got}, recorded {want}",
                path.display()
            ),
        ));
    }
    let snap: TrustListSnapshot = serde_json::from_slice(&data)
        .map_err(|e| parse_err(&format!("trust-list snapshot {}", path.display()), e))?;
    Ok((snap, got))
}

/// The snapshot and the SHA-256 of its JSON file.
pub(crate) fn load_with_digest(
    store_dir: &Path,
    list: TrustListKind,
    id: &str,
) -> CertResult<(TrustListSnapshot, String)> {
    let dir = store_dir.join(list.name());
    let id = if id == "latest" {
        let mut all = summaries(&dir)?;
        all.sort_by(|a, b| (&b.fetched_utc, &b.id).cmp(&(&a.fetched_utc, &a.id)));
        all.first().map(|s| s.id.clone()).ok_or_else(|| {
            CertError::new(
                ErrorKind::Io,
                format!(
                    "no {} trust-list snapshot in {} (import one with trust-list import)",
                    list.name(),
                    dir.display()
                ),
            )
        })?
    } else {
        safe_id(id)?;
        id.to_string()
    };
    read_snapshot(&dir.join(format!("{id}.json")))
}

pub fn load(store_dir: &Path, list: TrustListKind, id: &str) -> CertResult<TrustListSnapshot> {
    load_with_digest(store_dir, list, id).map(|(s, _)| s)
}

fn summaries(dir: &Path) -> CertResult<Vec<TrustListSummary>> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(out);
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let (s, _) = read_snapshot(&p)?;
        out.push(TrustListSummary {
            id: s.id,
            list: s.list,
            source: s.source,
            fetched_utc: s.fetched_utc,
            sha256: s.sha256,
            services: s.services.len() as u32,
            entries: s.entries.len() as u32,
            path: p,
        });
    }
    Ok(out)
}

pub fn list(store_dir: &Path) -> CertResult<Vec<TrustListSummary>> {
    let mut all = vec![];
    for l in [TrustListKind::Eu, TrustListKind::Co] {
        all.extend(summaries(&store_dir.join(l.name()))?);
    }
    all.sort_by(|a, b| (&b.fetched_utc, &b.id).cmp(&(&a.fetched_utc, &a.id)));
    Ok(all)
}

/// Status of `svc` at `at`: the history period that contains it.
pub(crate) fn status_at(svc: &TrustService, at: &str) -> String {
    let Ok(t) = rfc3339_to_epoch(at) else {
        return svc.current_status.clone();
    };
    for p in &svc.history {
        let from = rfc3339_to_epoch(&p.from).unwrap_or(i64::MIN);
        let until = p
            .until
            .as_deref()
            .and_then(|u| rfc3339_to_epoch(u).ok())
            .unwrap_or(i64::MAX);
        if from <= t && t < until {
            return p.status.clone();
        }
    }
    match svc.history.first() {
        Some(p) => format!(
            "not listed at that date (first status {} from {})",
            p.status, p.from
        ),
        None => svc.current_status.clone(),
    }
}

pub fn lookup(snapshot: &TrustListSnapshot, cert: &CertInfo, at: &str) -> Option<TrustListMatch> {
    let entry = snapshot
        .entries
        .iter()
        .find(|e| !cert.sha256.is_empty() && e.cert_sha256 == cert.sha256)
        .or_else(|| {
            snapshot.entries.iter().find(|e| {
                e.subject == cert.subject && e.ski_hex.is_some() && e.ski_hex == cert.ski_hex
            })
        })?;
    let svc = snapshot.services.get(entry.service_index as usize)?;
    Some(TrustListMatch {
        list: snapshot.list.clone(),
        snapshot_id: snapshot.id.clone(),
        snapshot_sha256: snapshot.sha256.clone(),
        tsp_name: svc.tsp_name.clone(),
        service_name: svc.service_name.clone(),
        service_type: svc.service_type.clone(),
        status_at: status_at(svc, at),
        at: at.to_string(),
    })
}

/// Builds the history periods (sorted, each `until` = the next `from`) and the current status.
pub(crate) fn close_history(
    mut periods: Vec<ServiceStatusPeriod>,
) -> (Vec<ServiceStatusPeriod>, String) {
    periods.sort_by_key(|p| rfc3339_to_epoch(&p.from).unwrap_or(i64::MIN));
    let n = periods.len();
    for i in 0..n {
        if i + 1 < n {
            let next = periods[i + 1].from.clone();
            let keep = periods[i]
                .until
                .as_deref()
                .and_then(|u| rfc3339_to_epoch(u).ok())
                .zip(rfc3339_to_epoch(&next).ok())
                .is_some_and(|(u, nx)| u < nx);
            if !keep {
                periods[i].until = Some(next);
            }
        }
    }
    let current = periods.last().map(|p| p.status.clone()).unwrap_or_default();
    (periods, current)
}

/// One trust-list entry from a certificate.
pub(crate) fn entry(service_index: u32, der: &[u8]) -> CertResult<TrustListEntry> {
    let c = crate::analysis::parse::cert_info(der)?;
    Ok(TrustListEntry {
        service_index,
        cert_sha256: c.sha256,
        subject: c.subject,
        ski_hex: c.ski_hex,
        not_after: c.not_after,
        cert_b64: openssl::base64::encode_block(&c.der),
    })
}

/// A time from a list (RFC 3339 with any offset, or a date) in the model's format; unchanged when unparsable.
pub(crate) fn norm_time(s: &str) -> String {
    match AtTime::parse(s) {
        Ok(AtTime::Fixed(t)) => t,
        _ => s.trim().to_string(),
    }
}

/// ETSI TS 119 612 service statuses under which a listed certificate is used as a trust anchor: `granted` and
/// `recognisedatnationallevel` (TS 119 612 v2, `…/TrustedList/Svcstatus/…`), `accredited` (v1 `…/Svcstatus/…`)
/// and the Colombian CSV's `accredited`. Every other status (withdrawn, deprecatedatnationallevel, suspended,
/// undersupervision, supervisionincessation, …) and "not listed at that date" withholds the certificate.
pub(crate) fn status_trusted(status: &str) -> bool {
    let last = status
        .trim()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        last.as_str(),
        "granted" | "recognisedatnationallevel" | "accredited"
    )
}

/// Kind of a service type: ETSI `…/Svctype/CA/QC` or `CA/PKC` (certificate issuance) and `…/Svctype/TSA`,
/// `TSA/QTST`, `TSA/TSS-QC`, `TSA/TSS-AdESQCandQES` (timestamping), or the CSV's `CA/QC` / `TSA`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceKind {
    Ca,
    Tsa,
}

pub(crate) fn service_kind(service_type: &str) -> Option<ServiceKind> {
    let t = service_type.trim();
    let t = t.rsplit_once("Svctype/").map(|(_, s)| s).unwrap_or(t);
    let up = t.to_ascii_uppercase();
    match up.as_str() {
        "CA/QC" | "CA/PKC" => Some(ServiceKind::Ca),
        "TSA" => Some(ServiceKind::Tsa),
        _ if up.starts_with("TSA/") => Some(ServiceKind::Tsa),
        _ => None,
    }
}

/// Why a trust-list certificate is not used as an anchor at a date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Withheld {
    pub service: String,
    pub service_type: String,
    pub status: String,
}

/// Ok when at least one service listing the certificate (`cert_sha256`) is of a kind accepted for `purpose`
/// (CA types always; TSA types only for `timestamping`) and has a trusted status at `at`
/// ([`status_trusted`], status history included). Otherwise the service that best explains the refusal.
pub(crate) fn anchor_standing(
    snapshot: &TrustListSnapshot,
    cert_sha256: &str,
    at: &str,
    purpose: Purpose,
) -> Result<(), Withheld> {
    let mut first: Option<Withheld> = None;
    for e in snapshot
        .entries
        .iter()
        .filter(|e| e.cert_sha256 == cert_sha256)
    {
        let Some(svc) = snapshot.services.get(e.service_index as usize) else {
            continue;
        };
        let status = status_at(svc, at);
        let kind_ok = match service_kind(&svc.service_type) {
            Some(ServiceKind::Ca) => true,
            Some(ServiceKind::Tsa) => purpose == Purpose::Timestamping,
            None => false,
        };
        if kind_ok && status_trusted(&status) {
            return Ok(());
        }
        let w = Withheld {
            service: svc.service_name.clone(),
            service_type: if kind_ok {
                svc.service_type.clone()
            } else {
                format!(
                    "{} (a type not accepted as an anchor for the purpose {})",
                    svc.service_type,
                    purpose.name()
                )
            },
            status,
        };
        // Prefer explaining by the status of an accepted type over a type mismatch.
        if first.is_none() || (kind_ok && first.as_ref().is_some_and(|f| f.service_type.contains("not accepted"))) {
            first = Some(w);
        }
    }
    Err(first.unwrap_or(Withheld {
        service: "none".into(),
        service_type: String::new(),
        status: "not listed".into(),
    }))
}
