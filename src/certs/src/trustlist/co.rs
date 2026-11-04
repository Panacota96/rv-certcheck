//! OWNER: A. Curated Colombian CSV of ONAC-accredited ECDs.
//!
//! ONAC publishes no machine-readable list of accredited *entidades de certificación digital* (ECD), so Rakvor
//! keeps a curated CSV, checked by hand against ONAC's published accreditations. Its SHA-256, source and import
//! time are recorded in the snapshot (limitation TRUST_LIST_SNAPSHOT_DATED); there is no signature to verify.
//!
//! # Format (RFC 4180 CSV, UTF-8, optional BOM; JSON Schema of one row: `schemas/trustlist-co.schema.json`)
//!
//! First line: the header, exactly these nine columns (any order):
//!
//! | column                   | content                                                                       |
//! |--------------------------|-------------------------------------------------------------------------------|
//! | `ecd_name`               | the ECD (trust service provider), e.g. `Ejemplo ECD S.A.S.`                    |
//! | `service_name`           | the service, e.g. `Ejemplo CA Firma Digital`                                  |
//! | `service_type`           | `CA/QC` (issues certificates for firma digital), `TSA` (estampado cronológico), or another short type |
//! | `status`                 | `accredited` \| `suspended` \| `withdrawn`                                    |
//! | `status_from`            | start of that status, RFC 3339 (`2025-01-01T00:00:00Z`) or `YYYY-MM-DD`        |
//! | `status_until`           | end of that status, same format, empty = still current                        |
//! | `certificate_pem_or_b64` | one CA certificate: a quoted PEM block or base64 DER on one line; may be empty |
//! | `source_url`             | where the accreditation was checked (ONAC page)                               |
//! | `checked_utc`            | when the row was checked by the curator (RFC 3339)                            |
//!
//! One row = one status period of one service (`ecd_name` + `service_name` + `service_type`); a service with a
//! history has one row per period, and a service with several CA certificates one row per certificate (same
//! status columns). The snapshot's `issue_date` is the latest `checked_utc`.
use super::store::{close_history, entry, norm_time, save, snapshot_id};
use crate::analysis::util::*;
use crate::model::*;
use std::path::Path;

pub const COLUMNS: [&str; 9] = [
    "ecd_name",
    "service_name",
    "service_type",
    "status",
    "status_from",
    "status_until",
    "certificate_pem_or_b64",
    "source_url",
    "checked_utc",
];

pub const STATUSES: [&str; 3] = ["accredited", "suspended", "withdrawn"];

fn bad(line: usize, msg: impl std::fmt::Display) -> CertError {
    CertError::new(
        ErrorKind::InvalidInput,
        format!("Colombian trust-list CSV, line {line}: {msg}"),
    )
}

/// RFC 4180: fields separated by commas, quoted with `"` (`""` inside), CRLF or LF, newlines allowed inside
/// quotes. Returns (first line number, fields) per record.
pub(crate) fn parse_csv(text: &str) -> CertResult<Vec<(usize, Vec<String>)>> {
    let mut rows = vec![];
    let mut field = String::new();
    let mut row: Vec<String> = vec![];
    let mut in_q = false;
    let mut line = 1usize;
    let mut row_line = 1usize;
    let mut chars = text.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        any = true;
        if in_q {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => in_q = false,
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => in_q = true,
            '"' => return Err(bad(line, "quote inside an unquoted field")),
            ',' => row.push(std::mem::take(&mut field)),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                row.push(std::mem::take(&mut field));
                if !(row.len() == 1 && row[0].is_empty()) {
                    rows.push((row_line, std::mem::take(&mut row)));
                }
                row.clear();
                line += 1;
                row_line = line;
            }
            _ => field.push(c),
        }
    }
    if in_q {
        return Err(bad(line, "unterminated quoted field"));
    }
    if any && (!field.is_empty() || !row.is_empty()) {
        row.push(field);
        rows.push((row_line, row));
    }
    Ok(rows)
}

fn cert_der(cell: &str, line: usize) -> CertResult<Option<Vec<u8>>> {
    let t = cell.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if t.contains("-----BEGIN") {
        let p = pem::parse(t).map_err(|e| bad(line, format!("certificate PEM: {e}")))?;
        return Ok(Some(p.contents().to_vec()));
    }
    let clean: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    openssl::base64::decode_block(&clean)
        .map(Some)
        .map_err(|e| bad(line, format!("certificate base64: {e}")))
}

fn time_cell(v: &str, line: usize, col: &str) -> CertResult<String> {
    match AtTime::parse(v) {
        Ok(AtTime::Fixed(t)) => Ok(t),
        _ => Err(bad(
            line,
            format!("{col} '{v}' is not RFC 3339 or YYYY-MM-DD"),
        )),
    }
}

pub fn import_co_csv(
    csv: &[u8],
    source: &str,
    fetched_utc: &str,
    store_dir: &Path,
) -> CertResult<TrustListSnapshot> {
    let text = std::str::from_utf8(csv.strip_prefix(b"\xef\xbb\xbf").unwrap_or(csv))
        .map_err(|e| parse_err("Colombian trust-list CSV (UTF-8 expected)", e))?;
    let rows = parse_csv(text)?;
    let Some((_, header)) = rows.first() else {
        return Err(bad(1, "empty file"));
    };
    let mut idx = [0usize; 9];
    for (i, col) in COLUMNS.iter().enumerate() {
        idx[i] = header
            .iter()
            .position(|h| h.trim() == *col)
            .ok_or_else(|| {
                bad(
                    1,
                    format!("missing column {col} (header: {})", COLUMNS.join(",")),
                )
            })?;
    }
    let sha256 = sha256_hex(csv);
    let fetched = norm_time(fetched_utc);
    let mut snap = TrustListSnapshot {
        schema: TRUST_LIST_SCHEMA.into(),
        id: snapshot_id(TrustListKind::Co, &fetched, &sha256)?,
        list: "co".into(),
        source: source.into(),
        fetched_utc: fetched,
        sha256,
        territory: Some("CO".into()),
        signature_verified: false,
        ..Default::default()
    };
    // (key, periods, certificates, source_url)
    type Group = (
        (String, String, String),
        Vec<ServiceStatusPeriod>,
        Vec<Vec<u8>>,
        String,
    );
    let mut groups: Vec<Group> = vec![];
    let mut latest_check: Option<String> = None;
    for (line, r) in rows.iter().skip(1) {
        let line = *line;
        if r.len() != header.len() {
            return Err(bad(
                line,
                format!("{} fields, the header has {}", r.len(), header.len()),
            ));
        }
        let get = |i: usize| r[idx[i]].trim().to_string();
        let key = (get(0), get(1), get(2));
        if key.0.is_empty() || key.1.is_empty() || key.2.is_empty() {
            return Err(bad(
                line,
                "ecd_name, service_name and service_type are required",
            ));
        }
        let status = get(3);
        if !STATUSES.contains(&status.as_str()) {
            return Err(bad(
                line,
                format!("status '{status}': use accredited, suspended or withdrawn"),
            ));
        }
        let from = time_cell(&get(4), line, "status_from")?;
        let until = match get(5) {
            u if u.is_empty() => None,
            u => Some(time_cell(&u, line, "status_until")?),
        };
        let checked = time_cell(&get(8), line, "checked_utc")?;
        if latest_check.as_ref().is_none_or(|l| checked > *l) {
            latest_check = Some(checked);
        }
        let der = cert_der(&r[idx[6]], line)?;
        let src = get(7);
        let g = match groups.iter_mut().position(|g| g.0 == key) {
            Some(p) => &mut groups[p],
            None => {
                groups.push((key, vec![], vec![], src.clone()));
                groups.last_mut().expect("just pushed")
            }
        };
        let period = ServiceStatusPeriod {
            status,
            from,
            until,
        };
        if !g.1.contains(&period) {
            g.1.push(period);
        }
        if let Some(d) = der {
            if !g.2.contains(&d) {
                g.2.push(d);
            }
        }
        if g.3.is_empty() {
            g.3 = src;
        }
    }
    for ((ecd, name, typ), periods, certs, src) in groups {
        let index = snap.services.len() as u32;
        let (history, current) = close_history(periods);
        for d in certs {
            snap.entries.push(
                entry(index, &d).map_err(|e| {
                    CertError::new(e.kind, format!("service '{name}': {}", e.message))
                })?,
            );
        }
        snap.services.push(TrustService {
            index,
            country: "CO".into(),
            tsp_name: ecd,
            service_name: name,
            service_type: typ,
            current_status: current,
            history,
            source_url: src,
        });
    }
    snap.issue_date = latest_check;
    save(store_dir, &snap)?;
    Ok(snap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_and_newlines() {
        let r = parse_csv("a,b\r\n\"x,1\",\"line1\nline2 \"\"q\"\"\"\n\n").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(
            r[1].1,
            vec!["x,1".to_string(), "line1\nline2 \"q\"".to_string()]
        );
        assert!(parse_csv("a,\"b\n").is_err());
        assert!(parse_csv("a,b\"c\n").is_err());
    }
}
