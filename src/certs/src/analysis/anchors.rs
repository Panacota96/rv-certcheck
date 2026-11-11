//! OWNER: A. `--anchor` resolution (file, bundled Rakvor root, system store, trust-list snapshot).
//!
//! `system`: on Unix the CA bundle of the operating system is read from `SSL_CERT_FILE` / `SSL_CERT_DIR` or the
//! usual distribution paths (the vendored OpenSSL's compiled-in default paths point to its build prefix, not
//! to the system). On Windows the ROOT store is not read in v0.1 (no Windows API binding in this crate): the
//! anchor is refused with "system store not available on this platform", so the examiner supplies the root
//! as `--anchor FILE`.
use super::parse::pkcs7_contents;
use super::util::*;
use crate::model::*;
use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;

pub fn resolve_anchors(
    specs: &[AnchorSpec],
    trust_list_dir: Option<&Path>,
) -> CertResult<Vec<ResolvedAnchor>> {
    specs
        .iter()
        .map(|s| resolve_one(s, trust_list_dir))
        .collect()
}

fn resolve_one(spec: &AnchorSpec, trust_list_dir: Option<&Path>) -> CertResult<ResolvedAnchor> {
    let name = spec.describe();
    let labeled = |ders: Vec<Vec<u8>>| -> Vec<LabeledDer> {
        ders.into_iter()
            .map(|d| LabeledDer::new(name.clone(), d))
            .collect()
    };
    match spec {
        AnchorSpec::File { path } => {
            let data = std::fs::read(path).map_err(|e| {
                CertError::new(
                    ErrorKind::Io,
                    format!("cannot read anchor {}: {e}", path.display()),
                )
            })?;
            let ders = certificates_in(&data).map_err(|e| {
                CertError::new(e.kind, format!("anchor {}: {}", path.display(), e.message))
            })?;
            Ok(ResolvedAnchor {
                spec: name.clone(),
                source_sha256: Some(sha256_hex(&data)),
                certificates: labeled(ders),
                snapshot: None,
            })
        }
        AnchorSpec::Rakvor => Ok(ResolvedAnchor {
            spec: name.clone(),
            source_sha256: Some(sha256_hex(crate::RAKVOR_ROOT_DER)),
            certificates: labeled(vec![crate::RAKVOR_ROOT_DER.to_vec()]),
            snapshot: None,
        }),
        AnchorSpec::System => Ok(ResolvedAnchor {
            spec: name.clone(),
            source_sha256: None,
            certificates: labeled(system_roots()?),
            snapshot: None,
        }),
        AnchorSpec::TrustList { list, snapshot } => {
            let dir = trust_list_dir
                .map(Path::to_path_buf)
                .unwrap_or_else(crate::trust_list::default_store_dir);
            let (snap, file_sha) =
                crate::trustlist::store::load_with_digest(&dir, *list, snapshot)?;
            let mut ders = vec![];
            for e in &snap.entries {
                let d = openssl::base64::decode_block(&e.cert_b64)
                    .map_err(|err| parse_err("trust-list certificate", err))?;
                if !ders.contains(&d) {
                    ders.push(d);
                }
            }
            Ok(ResolvedAnchor {
                spec: format!("tl:{}@{}", list.name(), snap.id),
                source_sha256: Some(file_sha),
                certificates: ders
                    .into_iter()
                    .map(|d| LabeledDer::new(format!("tl:{}@{}", list.name(), snap.id), d))
                    .collect(),
                snapshot: Some(snap),
            })
        }
    }
}

/// Every certificate in PEM (any number of CERTIFICATE blocks), DER or PKCS#7 bytes.
pub(crate) fn certificates_in(data: &[u8]) -> CertResult<Vec<Vec<u8>>> {
    let mut out = vec![];
    if super::sniff::looks_pem(data) {
        let blocks = pem::parse_many(data).map_err(|e| parse_err("PEM", e))?;
        for b in blocks {
            match b.tag() {
                "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
                    let x = openssl::x509::X509::from_der(b.contents())
                        .map_err(|e| parse_err("certificate", e))?;
                    out.push(x.to_der().map_err(|e| parse_err("certificate", e))?);
                }
                "PKCS7" | "CMS" => out.extend(pkcs7_contents(b.contents())?.0),
                _ => {}
            }
        }
    } else if let Ok(x) = openssl::x509::X509::from_der(data) {
        out.push(x.to_der().map_err(|e| parse_err("certificate", e))?);
    } else if openssl::pkcs7::Pkcs7::from_der(data).is_ok() {
        out.extend(pkcs7_contents(data)?.0);
    }
    if out.is_empty() {
        return Err(CertError::new(
            ErrorKind::Parse,
            "no certificate found (PEM, DER or PKCS#7 expected)",
        ));
    }
    Ok(out)
}

#[cfg(windows)]
fn system_roots() -> CertResult<Vec<Vec<u8>>> {
    Err(CertError::new(
        ErrorKind::Unsupported,
        "system store not available on this platform in v0.1 (the Windows ROOT store is not read): export the root and use --anchor FILE",
    ))
}

#[cfg(not(windows))]
fn system_roots() -> CertResult<Vec<Vec<u8>>> {
    let mut files: Vec<PathBuf> = vec![];
    if let Some(f) = std::env::var_os("SSL_CERT_FILE").filter(|v| !v.is_empty()) {
        files.push(PathBuf::from(f));
    }
    for f in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/ssl/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
        "/opt/homebrew/etc/openssl@3/cert.pem",
    ] {
        files.push(PathBuf::from(f));
    }
    let mut out = vec![];
    for f in files {
        if let Ok(data) = std::fs::read(&f)
            && let Ok(c) = certificates_in(&data)
        {
            out = c;
            break;
        }
    }
    if out.is_empty()
        && let Some(d) = std::env::var_os("SSL_CERT_DIR").filter(|v| !v.is_empty())
    {
        for e in std::fs::read_dir(PathBuf::from(d))
            .into_iter()
            .flatten()
            .flatten()
        {
            if let Ok(data) = std::fs::read(e.path())
                && let Ok(c) = certificates_in(&data)
            {
                for d in c {
                    if !out.contains(&d) {
                        out.push(d);
                    }
                }
            }
        }
    }
    if out.is_empty() {
        return Err(CertError::new(
            ErrorKind::Unsupported,
            "system store not available on this platform: no CA bundle found (set SSL_CERT_FILE or use --anchor FILE)",
        ));
    }
    Ok(out)
}
