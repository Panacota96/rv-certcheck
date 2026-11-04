//! OWNER: A. `--online`: CRLs from the CRL distribution points and OCSP answers from the AIA responders of every
//! certificate of the built path. HTTP(S) only, 15 s timeout per request, 20 MiB per response, no cache
//! (`Cache-Control: no-cache`), every URL recorded with the response SHA-256 and the time
//! ([`OnlineFetch`], audited by core). Loopback addresses bypass the proxy.
use super::parse::cert_info;
use super::util::*;
use crate::model::*;
use openssl::x509::X509;
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BYTES: u64 = 20 * 1024 * 1024;

fn agent_for(url: &str) -> ureq::Agent {
    let host = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    let bare = if host.starts_with('[') {
        host.split(']').next().unwrap_or("").trim_start_matches('[')
    } else {
        host.split(':').next().unwrap_or("")
    };
    let loopback = bare == "localhost"
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let mut cfg = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .http_status_as_error(false);
    if loopback {
        cfg = cfg.proxy(None);
    }
    cfg.build().into()
}

/// GET (body None) or POST an OCSP request. Returns (status, body).
pub(crate) fn http(url: &str, body: Option<&[u8]>) -> Result<(u16, Vec<u8>), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!(
            "unsupported URL scheme (only http and https are fetched): {url}"
        ));
    }
    let agent = agent_for(url);
    let resp = match body {
        None => agent
            .get(url)
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
            .call(),
        Some(b) => agent
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .header("Cache-Control", "no-cache")
            .send(b),
    };
    let mut resp = resp.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let data = resp
        .body_mut()
        .with_config()
        .limit(MAX_BYTES)
        .read_to_vec()
        .map_err(|e| e.to_string())?;
    Ok((status, data))
}

fn record(
    kind: &str,
    url: &str,
    subject: &str,
    r: &Result<(u16, Vec<u8>), String>,
    t: String,
) -> OnlineFetch {
    match r {
        Ok((status, data)) => OnlineFetch {
            kind: kind.into(),
            url: url.into(),
            for_subject: subject.into(),
            fetched_utc: t,
            http_status: Some(*status),
            bytes: data.len() as u64,
            sha256: Some(sha256_hex(data)),
            error: (*status != 200).then(|| format!("HTTP status {status}")),
        },
        Err(e) => OnlineFetch {
            kind: kind.into(),
            url: url.into(),
            for_subject: subject.into(),
            fetched_utc: t,
            error: Some(e.clone()),
            ..Default::default()
        },
    }
}

/// Fetches revocation data for every certificate of `chain` that has an issuer in it.
pub(crate) fn fetch_for_chain(
    chain: &[X509],
) -> (Vec<LabeledDer>, Vec<LabeledDer>, Vec<OnlineFetch>) {
    let mut crls = vec![];
    let mut ocsp = vec![];
    let mut log = vec![];
    let mut done: Vec<String> = vec![];
    for (i, x) in chain.iter().enumerate() {
        let Some(issuer) = chain.get(i + 1) else {
            break;
        };
        let Ok(der) = x.to_der() else { continue };
        let Ok(info) = cert_info(&der) else { continue };
        for url in &info.crl_dps {
            if done.contains(url) {
                continue;
            }
            done.push(url.clone());
            let t = now_rfc3339();
            let r = http(url, None);
            log.push(record("crl", url, &info.subject, &r, t));
            if let Ok((200, data)) = r {
                crls.push(LabeledDer::new(format!("url:{url}"), data));
            }
        }
        for url in &info.aia_ocsp {
            let req = (|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
                let id = openssl::ocsp::OcspCertId::from_cert(
                    openssl::hash::MessageDigest::sha1(),
                    x,
                    issuer,
                )?;
                let mut r = openssl::ocsp::OcspRequest::new()?;
                r.add_id(id)?;
                r.to_der()
            })();
            let t = now_rfc3339();
            let r = match req {
                Ok(body) => http(url, Some(&body)),
                Err(e) => Err(format!("cannot build the OCSP request: {e}")),
            };
            log.push(record("ocsp", url, &info.subject, &r, t));
            if let Ok((200, data)) = r {
                ocsp.push(LabeledDer::new(format!("url:{url}"), data));
            }
        }
    }
    (crls, ocsp, log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// One-shot HTTP server on 127.0.0.1 answering `body` with `status`; returns its base URL.
    fn serve(status: u16, body: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut req = vec![0u8; 4096];
            let n = s.read(&mut req).unwrap_or(0);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
            String::from_utf8_lossy(&req[..n]).into_owned()
        });
        (url, h)
    }

    #[test]
    fn fetches_are_recorded_with_digest_and_time_and_never_cached() {
        let crl = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/openssl/intermediate.crl"
        ))
        .unwrap();
        let (url, h) = serve(200, crl.clone());
        let u = format!("{url}/intermediate.crl");
        let r = http(&u, None);
        let req = h.join().unwrap();
        assert!(
            req.to_ascii_lowercase().contains("cache-control: no-cache"),
            "{req}"
        );
        let rec = record("crl", &u, "CN=x", &r, "2026-11-03T10:00:00Z".into());
        assert_eq!(rec.http_status, Some(200));
        assert_eq!(rec.sha256.as_deref(), Some(sha256_hex(&crl).as_str()));
        assert_eq!(rec.bytes, crl.len() as u64);
        assert!(rec.error.is_none());
        let (url, h) = serve(404, b"no".to_vec());
        let r = http(&format!("{url}/x"), None);
        h.join().unwrap();
        assert_eq!(
            record("crl", &url, "CN=x", &r, "t".into()).error.as_deref(),
            Some("HTTP status 404")
        );
        assert!(
            http("ldap://ldap.example/cn=crl", None)
                .unwrap_err()
                .contains("only http and https")
        );
        let dead = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let r = http(&format!("http://{dead}/x"), None);
        assert!(record("ocsp", "u", "CN=x", &r, "t".into()).error.is_some());
    }
}
