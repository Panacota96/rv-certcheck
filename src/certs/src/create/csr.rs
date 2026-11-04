//! OWNER: B. PKCS#10 creation and display.

use super::build;
use super::derw;
use super::keys::{self, crypto};
use super::pki::{name_rdns, name_string, sha256_hex};
use super::rng::Rand;
use super::signer::Signer;
use super::tokens;
use crate::model::*;
use x509_parser::prelude::FromDer;

pub fn new(req: &CsrRequest) -> CertResult<CsrResult> {
    let subject = derw::name(&req.subject.rdns)?;
    for g in &req.subject.sans {
        derw::general_name(g)?;
    }
    if req.out.exists() {
        return Err(CertError::new(
            ErrorKind::Policy,
            format!(
                "{} already exists: files are never overwritten",
                req.out.display()
            ),
        ));
    }
    let (loc, signer) = match &req.key_target {
        KeyTarget::EncryptedFile { path, password } => {
            let k = keys::generate(req.key_spec)?;
            let pem = keys::encrypted_pkcs8_pem(&k, password, &mut Rand::Os)?;
            keys::write_new(path, pem.as_bytes(), true)?;
            let abs = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir().unwrap_or_default().join(path)
            };
            (
                KeyLocation::EncryptedFile {
                    path: abs.display().to_string(),
                    format: "pkcs8-encrypted".into(),
                },
                Signer::Soft(k),
            )
        }
        KeyTarget::Pkcs11 {
            module,
            token_serial,
            pin,
            key_label,
        } => {
            let s = tokens::open(module, token_serial, pin)?;
            let loc = s.generate(req.key_spec, key_label, false)?;
            let KeyLocation::Pkcs11 { key_id_hex, .. } = &loc else {
                unreachable!()
            };
            let id = key_id_hex.clone();
            (loc, Signer::token(s, &id)?)
        }
    };
    let der = build::csr(
        &subject,
        &signer.spki()?,
        &req.subject.sans,
        signer.default_alg()?,
        &signer,
    )?;
    keys::write_new(
        &req.out,
        keys::pem_encode("CERTIFICATE REQUEST", &der).as_bytes(),
        false,
    )?;
    Ok(CsrResult {
        csr_path: req.out.clone(),
        key: loc,
        csr: show(&der)?,
    })
}

/// SAN entries of a CSR's extensionRequest.
pub(crate) fn sans_of(der: &[u8]) -> CertResult<Vec<GeneralName>> {
    let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(der)
        .map_err(|e| CertError::new(ErrorKind::Parse, format!("CSR: {e}")))?;
    let mut out = vec![];
    if let Some(exts) = csr.requested_extensions() {
        for e in exts {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = e {
                for g in &san.general_names {
                    out.push(general_name_of(g));
                }
            }
        }
    }
    Ok(out)
}

fn general_name_of(g: &x509_parser::extensions::GeneralName) -> GeneralName {
    use x509_parser::extensions::GeneralName as G;
    let (kind, value) = match g {
        G::DNSName(s) => ("dns", s.to_string()),
        G::RFC822Name(s) => ("email", s.to_string()),
        G::URI(s) => ("uri", s.to_string()),
        G::IPAddress(b) => (
            "ip",
            match b.len() {
                4 => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
                16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(b);
                    std::net::Ipv6Addr::from(a).to_string()
                }
                _ => hex(b),
            },
        ),
        G::DirectoryName(n) => ("dir", n.to_string()),
        other => ("other", format!("{other:?}")),
    };
    GeneralName {
        kind: kind.into(),
        value,
    }
}

fn oid_name(oid: &str) -> String {
    openssl::asn1::Asn1Object::from_str(oid)
        .ok()
        .and_then(|o| o.nid().long_name().ok().map(str::to_string))
        .filter(|n| !n.is_empty() && n != "undefined")
        .unwrap_or_else(|| oid.to_string())
}

fn oid_short_name(oid: &str) -> String {
    openssl::asn1::Asn1Object::from_str(oid)
        .ok()
        .and_then(|o| o.nid().short_name().ok().map(str::to_string))
        .filter(|n| !n.is_empty() && n != "UNDEF")
        .unwrap_or_else(|| oid.to_string())
}

pub fn show(data: &[u8]) -> CertResult<CsrInfo> {
    let der = keys::der_from_pem_or_der(data, &["CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"])?;
    let req = openssl::x509::X509Req::from_der(&der)
        .map_err(|e| CertError::new(ErrorKind::Parse, format!("not a PKCS#10 request: {e}")))?;
    let pk = req.public_key().map_err(crypto("CSR key"))?;
    let signature_valid = req.verify(&pk).unwrap_or(false);
    let (_, parsed) = x509_parser::certification_request::X509CertificationRequest::from_der(&der)
        .map_err(|e| CertError::new(ErrorKind::Parse, format!("CSR: {e}")))?;
    let mut requested_extensions = vec![];
    for a in parsed.certification_request_info.iter_attributes() {
        if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(er) =
            a.parsed_attribute()
        {
            for e in &er.extensions {
                let o = e.oid.to_id_string();
                requested_extensions.push(ExtensionInfo {
                    name: oid_short_name(&o),
                    oid: o,
                    critical: e.critical,
                });
            }
        }
    }
    Ok(CsrInfo {
        subject: name_string(req.subject_name()),
        subject_rdns: name_rdns(req.subject_name()),
        sans: sans_of(&der)?,
        key: keys::key_info_of(&pk)?,
        signature_algorithm: oid_name(&parsed.signature_algorithm.algorithm.to_id_string()),
        signature_valid,
        requested_extensions,
        sha256: sha256_hex(&der),
    })
}
