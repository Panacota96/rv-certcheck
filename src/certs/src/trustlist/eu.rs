//! OWNER: A. ETSI TS 119 612 LOTL/TL XML (quick-xml).
//!
//! Read (namespace prefixes ignored, local names only): SchemeInformation (TSLSequenceNumber, SchemeTerritory,
//! ListIssueDateTime, NextUpdate/dateTime); per TrustServiceProvider its TSPName; per TSPService the
//! ServiceTypeIdentifier, ServiceName, every DigitalId/X509Certificate, ServiceStatus and StatusStartingTime,
//! plus every ServiceHistoryInstance (status, start, certificates). Names prefer `xml:lang="en"`.
//! A LOTL holds pointers to national TLs, not services: its snapshot has no services (v0.1 does not follow the
//! pointers; import each national TL). The XAdES signature of the list is NOT verified in v0.1
//! (`signature_verified = false`, limitation TRUST_LIST_SIGNATURE_NOT_VERIFIED_V01). No DTD or external entity
//! is ever resolved.
use super::store::{close_history, entry, norm_time, save, snapshot_id};
use crate::analysis::util::*;
use crate::model::*;
use quick_xml::events::Event;
use std::path::Path;

#[derive(Default)]
struct Svc {
    service_type: String,
    name: Option<String>,
    status: String,
    from: String,
    certs: Vec<String>,
    history: Vec<ServiceStatusPeriod>,
}

#[derive(Default)]
struct Hist {
    status: String,
    from: String,
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

pub fn import_eu(
    xml: &[u8],
    source: &str,
    fetched_utc: &str,
    store_dir: &Path,
) -> CertResult<TrustListSnapshot> {
    let text = std::str::from_utf8(xml.strip_prefix(b"\xef\xbb\xbf").unwrap_or(xml))
        .map_err(|e| parse_err("trust list (UTF-8 expected)", e))?;
    let mut r = quick_xml::Reader::from_str(text);
    let sha256 = sha256_hex(xml);
    let fetched = norm_time(fetched_utc);
    let mut snap = TrustListSnapshot {
        schema: TRUST_LIST_SCHEMA.into(),
        id: snapshot_id(TrustListKind::Eu, &fetched, &sha256)?,
        list: "eu".into(),
        source: source.into(),
        fetched_utc: fetched,
        sha256,
        signature_verified: false,
        ..Default::default()
    };
    let mut path: Vec<String> = vec![];
    let mut buf = String::new();
    let mut lang_en = false;
    let mut tsp_name: Option<String> = None;
    let mut svc: Option<Svc> = None;
    let mut hist: Option<Hist> = None;
    let mut saw_root = false;
    loop {
        let ev = r.read_event().map_err(|e| parse_err("trust list XML", e))?;
        match ev {
            Event::Start(e) => {
                let n = local(e.local_name().as_ref());
                if path.is_empty() {
                    if n != "TrustServiceStatusList" {
                        return Err(parse_err(
                            "trust list",
                            format!(
                                "root element is {n}, not TrustServiceStatusList (ETSI TS 119 612)"
                            ),
                        ));
                    }
                    saw_root = true;
                }
                lang_en = e.attributes().flatten().any(|a| {
                    local(a.key.as_ref()) == "lang"
                        && a.normalized_value(quick_xml::XmlVersion::default())
                            .is_ok_and(|v| v.eq_ignore_ascii_case("en"))
                });
                match n.as_str() {
                    "TrustServiceProvider" => tsp_name = None,
                    "TSPService" => svc = Some(Svc::default()),
                    "ServiceHistoryInstance" => hist = Some(Hist::default()),
                    _ => {}
                }
                path.push(n);
                buf.clear();
            }
            Event::Text(t) => buf.push_str(&t.xml10_content()),
            Event::CData(t) => buf.push_str(&t.xml10_content()),
            Event::GeneralRef(g) => {
                if let Ok(Some(c)) = g.resolve_char_ref() {
                    buf.push(c);
                } else {
                    match &*g {
                        "amp" => buf.push('&'),
                        "lt" => buf.push('<'),
                        "gt" => buf.push('>'),
                        "quot" => buf.push('"'),
                        "apos" => buf.push('\''),
                        other => {
                            return Err(parse_err(
                                "trust list XML",
                                format!(
                                    "undefined entity &{other}; (DTD entities are not resolved)"
                                ),
                            ));
                        }
                    }
                }
            }
            Event::End(_) => {
                let Some(n) = path.pop() else {
                    return Err(parse_err("trust list XML", "unbalanced end tag"));
                };
                let parent = path.last().map(String::as_str).unwrap_or("");
                let in_hist = path.iter().any(|p| p == "ServiceHistoryInstance");
                let in_scheme = path.iter().any(|p| p == "SchemeInformation");
                let v = buf.trim().to_string();
                match (n.as_str(), parent) {
                    ("TSLSequenceNumber", _) if in_scheme => snap.sequence_number = Some(v),
                    ("SchemeTerritory", _) if in_scheme => snap.territory = Some(v),
                    ("ListIssueDateTime", _) if in_scheme => snap.issue_date = Some(norm_time(&v)),
                    ("dateTime", "NextUpdate") if in_scheme => {
                        snap.next_update = Some(norm_time(&v))
                    }
                    ("Name", "TSPName") => {
                        if tsp_name.is_none() || lang_en {
                            tsp_name = Some(v);
                        }
                    }
                    ("Name", "ServiceName") if !in_hist => {
                        if let Some(s) = svc.as_mut()
                            && (s.name.is_none() || lang_en)
                        {
                            s.name = Some(v);
                        }
                    }
                    ("ServiceTypeIdentifier", _) if !in_hist => {
                        if let Some(s) = svc.as_mut() {
                            s.service_type = v;
                        }
                    }
                    ("X509Certificate", _) => {
                        if let Some(s) = svc.as_mut() {
                            s.certs.push(v);
                        }
                    }
                    ("ServiceStatus", _) => match (in_hist, hist.as_mut(), svc.as_mut()) {
                        (true, Some(h), _) => h.status = v,
                        (false, _, Some(s)) => s.status = v,
                        _ => {}
                    },
                    ("StatusStartingTime", _) => match (in_hist, hist.as_mut(), svc.as_mut()) {
                        (true, Some(h), _) => h.from = norm_time(&v),
                        (false, _, Some(s)) => s.from = norm_time(&v),
                        _ => {}
                    },
                    ("ServiceHistoryInstance", _) => {
                        if let (Some(h), Some(s)) = (hist.take(), svc.as_mut()) {
                            s.history.push(ServiceStatusPeriod {
                                status: h.status,
                                from: h.from,
                                until: None,
                            });
                        }
                    }
                    ("TSPService", _) => {
                        if let Some(s) = svc.take() {
                            add_service(
                                &mut snap,
                                tsp_name.clone().unwrap_or_default(),
                                s,
                                source,
                            )?;
                        }
                    }
                    _ => {}
                }
                buf.clear();
            }
            Event::Empty(_) | Event::Comment(_) | Event::Decl(_) | Event::PI(_) => {}
            Event::DocType(_) => {
                return Err(parse_err(
                    "trust list XML",
                    "a DOCTYPE is not allowed in a trust list",
                ));
            }
            Event::Eof => break,
        }
    }
    if !saw_root || !path.is_empty() {
        return Err(parse_err("trust list XML", "truncated document"));
    }
    save(store_dir, &snap)?;
    Ok(snap)
}

fn add_service(snap: &mut TrustListSnapshot, tsp: String, s: Svc, source: &str) -> CertResult<()> {
    let index = snap.services.len() as u32;
    let mut periods = s.history;
    periods.push(ServiceStatusPeriod {
        status: s.status.clone(),
        from: s.from.clone(),
        until: None,
    });
    let (history, _) = close_history(periods);
    let service_name = s.name.unwrap_or_default();
    for b64 in s.certs {
        let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let der = openssl::base64::decode_block(&clean)
            .map_err(|e| parse_err(&format!("service '{service_name}': X509Certificate"), e))?;
        let e = entry(index, &der).map_err(|e| {
            CertError::new(e.kind, format!("service '{service_name}': {}", e.message))
        })?;
        if !snap
            .entries
            .iter()
            .any(|x| x.service_index == index && x.cert_sha256 == e.cert_sha256)
        {
            snap.entries.push(e);
        }
    }
    snap.services.push(TrustService {
        index,
        country: snap.territory.clone().unwrap_or_default(),
        tsp_name: tsp,
        service_name,
        service_type: s.service_type,
        current_status: s.status,
        history,
        source_url: source.to_string(),
    });
    Ok(())
}
