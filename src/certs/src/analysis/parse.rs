//! OWNER: A. Field extraction into CertInfo / CrlInfo / OcspInfo / TimestampInfo / KeyInfo / CsrInfo.
//!
//! OpenSSL decides whether an object is well formed (d2i_*) and supplies names, times, fingerprints and the
//! self-signature check; x509-parser decodes the extensions into fields; x509-ocsp and cms decode the OCSP and
//! PKCS#7 structures the `openssl` crate does not expose. Private keys are opened only to read their public
//! facts (algorithm, size, curve, SPKI digest): no private byte reaches any output type.
use super::keymatch::{key_facts, load_private_key};
use super::sniff::{base64_body, label_kind, sniff_inner};
use super::util::*;
use crate::model::*;
use openssl::pkey::{HasPublic, Id, PKeyRef};
use openssl::x509::{X509, X509Crl, X509Req};
use x509_parser::extensions::{GeneralName as XGn, ParsedExtension};
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

pub fn parse_any(data: &[u8], password: Option<&Secret>) -> CertResult<ParsedInput> {
    let s = sniff_inner(data);
    let mut p = ParsedInput {
        kind: s.kind,
        encoding: s.encoding,
        ..Default::default()
    };
    match s.encoding {
        Encoding::Pem => parse_pem(data, password, &mut p)?,
        Encoding::Base64 => {
            let der = Zeroizing::new(
                base64_body(data).ok_or_else(|| parse_err("base64", "not decodable"))?,
            );
            parse_der(&der, s.kind.0, password, &mut p)?;
        }
        Encoding::Der => parse_der(data, s.kind.0, password, &mut p)?,
    }
    if p.kind.0 == InputKind::Unknown {
        return Err(CertError::new(
            ErrorKind::Parse,
            "not a recognised cryptographic object (certificate, CRL, OCSP, PKCS#7, PKCS#12, RFC 3161 token, key or CSR)",
        ));
    }
    let mut signals = std::mem::take(&mut p.signals);
    for c in &p.certificates {
        cert_signals(c, &mut signals);
    }
    dedup(&mut signals);
    p.signals = signals;
    Ok(p)
}

fn dedup(v: &mut Vec<Signal>) {
    let mut seen: Vec<Signal> = vec![];
    v.retain(|s| {
        if seen.contains(s) {
            false
        } else {
            seen.push(s.clone());
            true
        }
    });
}

fn parse_pem(data: &[u8], password: Option<&Secret>, p: &mut ParsedInput) -> CertResult<()> {
    let blocks = pem::parse_many(data).map_err(|e| parse_err("PEM", e))?;
    let mut any = false;
    for b in &blocks {
        let Some(kind) = label_kind(b.tag(), b.contents()) else {
            continue;
        };
        any = true;
        if kind == InputKind::PrivateKey {
            if p.private_key.is_none() {
                // Re-armoured so OpenSSL also sees legacy `Proc-Type: 4,ENCRYPTED` headers.
                let text = Zeroizing::new(pem::encode(b));
                match load_private_key(text.as_bytes(), password) {
                    Ok((key, encrypted)) => p.private_key = Some(key_facts(&key, encrypted)?),
                    // A key that cannot be opened beside certificates: keep the certificates. A key-only item
                    // reports the error (core: ANALYSIS_STEP_FAILED with the reason, never the password).
                    Err(e) if p.kind.0 == InputKind::PrivateKey => return Err(e),
                    Err(_) => {}
                }
            }
            continue;
        }
        parse_der(b.contents(), kind, password, p)?;
    }
    if !any {
        return Err(parse_err("PEM", "no supported PEM block"));
    }
    Ok(())
}

fn parse_der(
    der: &[u8],
    kind: InputKind,
    password: Option<&Secret>,
    p: &mut ParsedInput,
) -> CertResult<()> {
    match kind {
        InputKind::Certificate | InputKind::CertBundle => p.certificates.push(cert_info(der)?),
        InputKind::Crl => p.crls.push(crl_info(der)?),
        InputKind::Csr => p.csr = Some(csr_info(der)?),
        InputKind::OcspResponse => p.ocsp = Some(ocsp_info(der)?),
        InputKind::TimestampToken => {
            let (info, _) = super::timestamp::parse_token(der)?;
            p.timestamp = Some(info);
        }
        InputKind::Pkcs7 => {
            let (certs, crls) = pkcs7_contents(der)?;
            for c in certs {
                p.certificates.push(cert_info(&c)?);
            }
            for c in crls {
                p.crls.push(crl_info(&c)?);
            }
        }
        InputKind::Pkcs12 => parse_p12(der, password, p)?,
        InputKind::PrivateKey => {
            let (key, encrypted) = load_private_key(der, password)?;
            p.private_key = Some(key_facts(&key, encrypted)?);
        }
        InputKind::Unknown => {}
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ PKCS#7

/// Certificates and CRLs of a PKCS#7 / CMS SignedData, in file order (DER).
/// (certificates, CRLs), DER each.
pub(crate) type DerLists = (Vec<Vec<u8>>, Vec<Vec<u8>>);

pub(crate) fn pkcs7_contents(der: &[u8]) -> CertResult<DerLists> {
    use der::{Decode, Encode};
    let mut certs = vec![];
    let mut crls = vec![];
    let decoded = cms::content_info::ContentInfo::from_der(der)
        .ok()
        .and_then(|ci| ci.content.decode_as::<cms::signed_data::SignedData>().ok());
    if let Some(sd) = decoded {
        for c in sd.certificates.iter().flat_map(|s| s.0.iter()) {
            if let cms::cert::CertificateChoices::Certificate(c) = c {
                if let Ok(d) = c.to_der() {
                    certs.push(d);
                }
            }
        }
        for r in sd.crls.iter().flat_map(|s| s.0.iter()) {
            if let cms::revocation::RevocationInfoChoice::Crl(c) = r {
                if let Ok(d) = c.to_der() {
                    crls.push(d);
                }
            }
        }
        return Ok((certs, crls));
    }
    // Not strict DER (BER from some exporters): OpenSSL still reads the certificates.
    let p7 = openssl::pkcs7::Pkcs7::from_der(der).map_err(|e| parse_err("PKCS#7", e))?;
    if let Some(stack) = p7.signed().and_then(|s| s.certificates()) {
        for c in stack {
            certs.push(c.to_der().map_err(|e| parse_err("PKCS#7 certificate", e))?);
        }
    }
    Ok((certs, crls))
}

// ------------------------------------------------------------------------------------------------ PKCS#12

fn parse_p12(der: &[u8], password: Option<&Secret>, p: &mut ParsedInput) -> CertResult<()> {
    let p12 = openssl::pkcs12::Pkcs12::from_der(der).map_err(|e| parse_err("PKCS#12", e))?;
    let pw = password.map(|s| s.expose()).unwrap_or("");
    match p12.parse2(pw) {
        Ok(parsed) => {
            if let Some(c) = &parsed.cert {
                p.certificates.push(cert_info(
                    &c.to_der().map_err(|e| parse_err("PKCS#12", e))?,
                )?);
            }
            if let Some(ca) = &parsed.ca {
                for c in ca {
                    p.certificates.push(cert_info(
                        &c.to_der().map_err(|e| parse_err("PKCS#12", e))?,
                    )?);
                }
            }
            if let Some(k) = &parsed.pkey {
                p.private_key = Some(key_facts(k, !pw.is_empty())?);
            }
            return Ok(());
        }
        Err(_) => {
            // Legacy encryptions (RC2-40, 3DES) need OpenSSL's legacy provider, absent from the vendored build:
            // p12-keystore reads them.
            if let Ok(ks) = p12_keystore::KeyStore::from_pkcs12(
                der,
                pw,
                p12_keystore::Pkcs12ImportPolicy::Relaxed,
            ) {
                let mut found = false;
                if let Some((_, chain)) = ks.private_key_chain() {
                    let kder = Zeroizing::new(chain.key().as_der().to_vec());
                    if let Ok(k) = openssl::pkey::PKey::private_key_from_der(&kder) {
                        p.private_key = Some(key_facts(&k, !pw.is_empty())?);
                    }
                    for c in chain.certs() {
                        p.certificates.push(cert_info(c.as_der())?);
                    }
                    found = true;
                }
                for (_, e) in ks.entries() {
                    if let p12_keystore::KeyStoreEntry::Certificate(c) = e {
                        p.certificates.push(cert_info(c.as_der())?);
                        found = true;
                    }
                }
                if found {
                    return Ok(());
                }
            }
        }
    }
    let reason = if password.is_none() {
        "a password is needed to open it and none was supplied"
    } else {
        "wrong password, or an encryption this build cannot open"
    };
    p.signals
        .push(Signal::of(codes::PKCS12_UNREADABLE).with("reason", reason));
    Ok(())
}

// ------------------------------------------------------------------------------------------------ certificates

/// Public facts of a public key (from a certificate, CSR or the public half of a private key).
pub(crate) fn pubkey_facts<T: HasPublic>(k: &PKeyRef<T>) -> KeyInfo {
    let spki = k.public_key_to_der().unwrap_or_default();
    let bits = Some(k.bits());
    let (algorithm, bits, curve) = match k.id() {
        Id::RSA => ("rsa".to_string(), bits, None),
        Id::DSA => ("dsa".to_string(), bits, None),
        Id::ED25519 => ("ed25519".to_string(), Some(256), None),
        Id::ED448 => ("ed448".to_string(), Some(456), None),
        Id::EC => {
            let curve = k
                .ec_key()
                .ok()
                .and_then(|e| e.group().curve_name())
                .map(curve_name);
            ("ec".to_string(), bits, curve)
        }
        other => (format!("nid:{}", other.as_raw()), bits, None),
    };
    KeyInfo {
        algorithm,
        bits,
        curve,
        spki_sha256: sha256_hex(&spki),
        encrypted: false,
    }
}

fn curve_name(n: openssl::nid::Nid) -> String {
    use openssl::nid::Nid;
    match n {
        Nid::X9_62_PRIME256V1 => "P-256".into(),
        Nid::SECP384R1 => "P-384".into(),
        Nid::SECP521R1 => "P-521".into(),
        Nid::SECP224R1 => "P-224".into(),
        Nid::X9_62_PRIME192V1 => "P-192".into(),
        other => other
            .short_name()
            .map(str::to_string)
            .unwrap_or_else(|_| format!("nid:{}", other.as_raw())),
    }
}

/// SubjectPublicKeyInfo DER → key facts (falls back to the algorithm OID when OpenSSL cannot load the key).
fn spki_facts(spki_der: &[u8], alg_oid: &str) -> KeyInfo {
    match openssl::pkey::PKey::public_key_from_der(spki_der) {
        Ok(k) => KeyInfo {
            spki_sha256: sha256_hex(spki_der),
            ..pubkey_facts(&k)
        },
        Err(_) => KeyInfo {
            algorithm: alg_oid.to_string(),
            spki_sha256: sha256_hex(spki_der),
            ..Default::default()
        },
    }
}

pub(crate) fn gn(g: &XGn<'_>) -> GeneralName {
    let (kind, value) = match g {
        XGn::DNSName(s) => ("dns", s.to_string()),
        XGn::RFC822Name(s) => ("email", s.to_string()),
        XGn::URI(s) => ("uri", s.to_string()),
        XGn::IPAddress(b) => ("ip", ip_text(b)),
        XGn::DirectoryName(n) => ("dir", name_der_string(n.as_raw())),
        XGn::OtherName(oid, _) => ("other", format!("otherName:{}", oid.to_id_string())),
        XGn::RegisteredID(oid) => ("other", format!("registeredID:{}", oid.to_id_string())),
        XGn::X400Address(_) => ("other", "x400Address".into()),
        XGn::EDIPartyName(_) => ("other", "ediPartyName".into()),
        XGn::Invalid(_, b) => ("other", format!("invalid:{}", hex(b))),
    };
    GeneralName {
        kind: kind.into(),
        value,
    }
}

/// 4/16 bytes → address; 8/32 bytes (name constraints) → address/prefix.
fn ip_text(b: &[u8]) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let prefix = |m: &[u8]| m.iter().map(|x| x.count_ones()).sum::<u32>();
    match b.len() {
        4 => Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Ipv6Addr::from(a).to_string()
        }
        8 => format!(
            "{}/{}",
            Ipv4Addr::new(b[0], b[1], b[2], b[3]),
            prefix(&b[4..])
        ),
        32 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[..16]);
            format!("{}/{}", Ipv6Addr::from(a), prefix(&b[16..]))
        }
        _ => format!("#{}", hex(b)),
    }
}

const KU_NAMES: [&str; 9] = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];

pub const OID_DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";

fn eku_names(e: &x509_parser::extensions::ExtendedKeyUsage<'_>) -> Vec<String> {
    let mut v = vec![];
    for (on, name) in [
        (e.server_auth, "serverAuth"),
        (e.client_auth, "clientAuth"),
        (e.code_signing, "codeSigning"),
        (e.email_protection, "emailProtection"),
        (e.time_stamping, "timeStamping"),
        (e.ocsp_signing, "OCSPSigning"),
        (e.any, "anyExtendedKeyUsage"),
    ] {
        if on {
            v.push(name.to_string());
        }
    }
    for o in &e.other {
        let id = o.to_id_string();
        v.push(if id == OID_DOCUMENT_SIGNING {
            "documentSigning".into()
        } else {
            oid_short_name(&id)
        });
    }
    v
}

/// Every field of one certificate. Fails only when OpenSSL cannot decode it.
pub fn cert_info(der: &[u8]) -> CertResult<CertInfo> {
    let x = X509::from_der(der).map_err(|e| parse_err("certificate", e))?;
    let der = x.to_der().map_err(|e| parse_err("certificate", e))?;
    let subject_rdns = name_rdns(x.subject_name());
    let issuer_rdns = name_rdns(x.issuer_name());
    let serial_hex = x
        .serial_number()
        .to_bn()
        .and_then(|b| b.to_hex_str().map(|s| s.to_ascii_lowercase()))
        .map_err(|e| parse_err("serial number", e))?;
    let pubkey = x.public_key().ok();
    let self_issued =
        x.subject_name().try_cmp(x.issuer_name()).ok() == Some(std::cmp::Ordering::Equal);
    let self_signed = self_issued
        && pubkey
            .as_ref()
            .is_some_and(|k| x.verify(k).unwrap_or(false));
    let sig_long = x
        .signature_algorithm()
        .object()
        .nid()
        .long_name()
        .map(str::to_string)
        .unwrap_or_else(|_| x.signature_algorithm().object().to_string());
    let mut c = CertInfo {
        version: (x.version() + 1).max(1) as u32,
        subject: rdns_string(&subject_rdns),
        subject_rdns,
        issuer: rdns_string(&issuer_rdns),
        issuer_rdns,
        serial_hex,
        not_before: asn1_rfc3339(x.not_before())?,
        not_after: asn1_rfc3339(x.not_after())?,
        signature_algorithm: sig_long,
        sha256: sha256_hex(&der),
        sha1: sha1_hex(&der),
        self_signed,
        ..Default::default()
    };
    if let Ok((_, xp)) = x509_parser::certificate::X509Certificate::from_der(&der) {
        c.signature_algorithm_oid = xp.signature_algorithm.algorithm.to_id_string();
        c.key = spki_facts(
            xp.tbs_certificate.subject_pki.raw,
            &xp.tbs_certificate
                .subject_pki
                .algorithm
                .algorithm
                .to_id_string(),
        );
        for ext in xp.extensions() {
            let oid = ext.oid.to_id_string();
            c.extensions.push(ExtensionInfo {
                name: oid_short_name(&oid),
                oid,
                critical: ext.critical,
            });
            match ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(s) => {
                    c.sans.extend(s.general_names.iter().map(gn))
                }
                ParsedExtension::KeyUsage(k) => {
                    c.key_usage = KU_NAMES
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| k.flags & (1 << i) != 0)
                        .map(|(_, n)| n.to_string())
                        .collect();
                    c.key_usage_critical = ext.critical;
                }
                ParsedExtension::ExtendedKeyUsage(e) => {
                    c.eku = eku_names(e);
                    c.eku_critical = ext.critical;
                }
                ParsedExtension::BasicConstraints(b) => {
                    c.basic_constraints = Some(BasicConstraints {
                        ca: b.ca,
                        path_len: b.path_len_constraint,
                        critical: ext.critical,
                    })
                }
                ParsedExtension::NameConstraints(n) => {
                    let conv = |v: &Option<Vec<x509_parser::extensions::GeneralSubtree<'_>>>| {
                        v.iter().flatten().map(|s| gn(&s.base)).collect::<Vec<_>>()
                    };
                    c.name_constraints = Some(NameConstraints {
                        permitted: conv(&n.permitted_subtrees),
                        excluded: conv(&n.excluded_subtrees),
                        critical: ext.critical,
                    });
                }
                ParsedExtension::CertificatePolicies(ps) => {
                    c.policy_oids = ps.iter().map(|p| p.policy_id.to_id_string()).collect()
                }
                ParsedExtension::AuthorityInfoAccess(a) => {
                    for d in a.iter() {
                        let XGn::URI(u) = &d.access_location else {
                            continue;
                        };
                        match d.access_method.to_id_string().as_str() {
                            "1.3.6.1.5.5.7.48.1" => c.aia_ocsp.push(u.to_string()),
                            "1.3.6.1.5.5.7.48.2" => c.aia_ca_issuers.push(u.to_string()),
                            _ => {}
                        }
                    }
                }
                ParsedExtension::CRLDistributionPoints(d) => {
                    for p in d.iter() {
                        if let Some(x509_parser::extensions::DistributionPointName::FullName(
                            names,
                        )) = &p.distribution_point
                        {
                            for n in names {
                                if let XGn::URI(u) = n {
                                    c.crl_dps.push(u.to_string());
                                }
                            }
                        }
                    }
                }
                ParsedExtension::SubjectKeyIdentifier(k) => c.ski_hex = Some(hex(k.0)),
                ParsedExtension::AuthorityKeyIdentifier(a) => {
                    c.aki_hex = a.key_identifier.as_ref().map(|k| hex(k.0))
                }
                _ => {}
            }
        }
    } else if let Some(k) = &pubkey {
        c.key = pubkey_facts(k);
    }
    c.der = der;
    Ok(c)
}

/// Weak keys and signature algorithms are this tool's policy (not OpenSSL's): RSA < 2048 bits, any DSA key,
/// curves below 256 bits; MD2/MD4/MD5/SHA-1 signatures.
pub(crate) fn weak_key(k: &KeyInfo) -> Option<(String, String)> {
    let bits = k.bits.unwrap_or(0);
    match k.algorithm.as_str() {
        "rsa" if bits < 2048 => Some(("RSA".into(), format!("{bits} bits"))),
        "dsa" => Some(("DSA".into(), format!("{bits} bits"))),
        "ec" if bits < 256 => Some((
            format!("EC ({})", k.curve.as_deref().unwrap_or("unknown curve")),
            format!("{bits} bits"),
        )),
        _ => None,
    }
}

const WEAK_SIG_OIDS: [&str; 7] = [
    "1.2.840.113549.1.1.2", // md2WithRSAEncryption
    "1.2.840.113549.1.1.3", // md4WithRSAEncryption
    "1.2.840.113549.1.1.4", // md5WithRSAEncryption
    "1.2.840.113549.1.1.5", // sha1WithRSAEncryption
    "1.3.14.3.2.29",        // sha1WithRSA (OIW)
    "1.2.840.10040.4.3",    // dsa-with-SHA1
    "1.2.840.10045.4.1",    // ecdsa-with-SHA1
];

/// RSASSA-PSS with a SHA-1 hash is not detected from the OID (the hash is in the parameters): see limitations.
pub(crate) fn weak_signature(c: &CertInfo) -> bool {
    let oid = c.signature_algorithm_oid.as_str();
    if WEAK_SIG_OIDS.contains(&oid) {
        return true;
    }
    let n = c.signature_algorithm.to_ascii_lowercase();
    ["md2", "md4", "md5", "sha1"].iter().any(|w| {
        n.starts_with(w) || n.ends_with(&format!("-{w}")) || n.contains(&format!("with{w}"))
    })
}

pub(crate) fn rakvor_policy(c: &CertInfo) -> Option<&str> {
    let arc = format!("{RAKVOR_OID_ARC}.");
    c.policy_oids
        .iter()
        .find(|p| p.starts_with(&arc) || p.as_str() == RAKVOR_OID_ARC)
        .map(String::as_str)
}

/// Parse-time signals of one certificate.
pub(crate) fn cert_signals(c: &CertInfo, out: &mut Vec<Signal>) {
    if let Some((alg, size)) = weak_key(&c.key) {
        out.push(
            Signal::of(codes::CERT_WEAK_KEY)
                .with("subject", &c.subject)
                .with("algorithm", alg)
                .with("size", size),
        );
    }
    if weak_signature(c) {
        out.push(
            Signal::of(codes::CERT_WEAK_SIGNATURE_ALGORITHM)
                .with("subject", &c.subject)
                .with("algorithm", &c.signature_algorithm),
        );
    }
    if c.self_signed {
        out.push(Signal::of(codes::CERT_SELF_SIGNED).with("subject", &c.subject));
    }
    if let Some(p) = rakvor_policy(c) {
        out.push(
            Signal::of(codes::CERT_ISSUED_BY_RAKVOR_INTERNAL)
                .with("subject", &c.subject)
                .with("policy", p),
        );
    }
}

// ------------------------------------------------------------------------------------------------ CRL, CSR, OCSP

pub(crate) fn reason_name(code: u8) -> String {
    match code {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "cACompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aACompromise",
        _ => return format!("reason-{code}"),
    }
    .into()
}

pub fn crl_info(der: &[u8]) -> CertResult<CrlInfo> {
    let crl = X509Crl::from_der(der).map_err(|e| parse_err("CRL", e))?;
    let der = crl.to_der().map_err(|e| parse_err("CRL", e))?;
    let mut info = CrlInfo {
        issuer: name_string(crl.issuer_name()),
        this_update: asn1_rfc3339(crl.last_update())?,
        next_update: match crl.next_update() {
            Some(t) => Some(asn1_rfc3339(t)?),
            None => None,
        },
        sha256: sha256_hex(&der),
        ..Default::default()
    };
    let (_, xp) = x509_parser::revocation_list::CertificateRevocationList::from_der(&der)
        .map_err(|e| parse_err("CRL", e))?;
    info.signature_algorithm = oid_long_name(&xp.signature_algorithm.algorithm.to_id_string());
    info.crl_number = xp.crl_number().map(|n| n.to_string());
    for ext in xp.extensions() {
        if let ParsedExtension::AuthorityKeyIdentifier(a) = ext.parsed_extension() {
            info.aki_hex = a.key_identifier.as_ref().map(|k| hex(k.0));
        }
    }
    for r in xp.iter_revoked_certificates() {
        info.revoked.push(RevokedEntry {
            serial_hex: int_hex(r.raw_serial()),
            revoked_at: epoch_to_rfc3339(r.revocation_date.timestamp()),
            reason: r
                .reason_code()
                .map(|(_, c)| reason_name(c.0))
                .unwrap_or_else(|| "unspecified".into()),
        });
    }
    info.der = der;
    Ok(info)
}

pub fn csr_info(der: &[u8]) -> CertResult<CsrInfo> {
    let req = X509Req::from_der(der).map_err(|e| parse_err("CSR", e))?;
    let der = req.to_der().map_err(|e| parse_err("CSR", e))?;
    let subject_rdns = name_rdns(req.subject_name());
    let signature_valid = req
        .public_key()
        .ok()
        .is_some_and(|k| req.verify(&k).unwrap_or(false));
    let mut info = CsrInfo {
        subject: rdns_string(&subject_rdns),
        subject_rdns,
        signature_valid,
        sha256: sha256_hex(&der),
        ..Default::default()
    };
    if let Ok((_, xp)) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&der)
    {
        let cri = &xp.certification_request_info;
        info.key = spki_facts(
            cri.subject_pki.raw,
            &cri.subject_pki.algorithm.algorithm.to_id_string(),
        );
        info.signature_algorithm = oid_long_name(&xp.signature_algorithm.algorithm.to_id_string());
        for attr in cri.attributes() {
            if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(er) =
                attr.parsed_attribute()
            {
                for ext in &er.extensions {
                    let oid = ext.oid.to_id_string();
                    info.requested_extensions.push(ExtensionInfo {
                        name: oid_short_name(&oid),
                        oid,
                        critical: ext.critical,
                    });
                    if let ParsedExtension::SubjectAlternativeName(s) = ext.parsed_extension() {
                        info.sans.extend(s.general_names.iter().map(gn));
                    }
                }
            }
        }
    } else if let Ok(k) = req.public_key() {
        info.key = pubkey_facts(&k);
    }
    Ok(info)
}

fn gt_epoch(t: &x509_ocsp::OcspGeneralizedTime) -> i64 {
    t.0.to_unix_duration().as_secs() as i64
}

pub fn ocsp_info(der: &[u8]) -> CertResult<OcspInfo> {
    use der::{Decode, Encode};
    let o =
        openssl::ocsp::OcspResponse::from_der(der).map_err(|e| parse_err("OCSP response", e))?;
    let der = o.to_der().map_err(|e| parse_err("OCSP response", e))?;
    let mut info = OcspInfo {
        response_status: ocsp_status_name(o.status().as_raw()).into(),
        sha256: sha256_hex(&der),
        ..Default::default()
    };
    let basic = x509_ocsp::OcspResponse::from_der(&der)
        .ok()
        .and_then(|r| r.response_bytes)
        .filter(|rb| rb.response_type.to_string() == "1.3.6.1.5.5.7.48.1.1")
        .and_then(|rb| x509_ocsp::BasicOcspResponse::from_der(rb.response.as_bytes()).ok());
    if let Some(b) = basic {
        let rd = &b.tbs_response_data;
        info.produced_at = Some(epoch_to_rfc3339(gt_epoch(&rd.produced_at)));
        info.responder = Some(match &rd.responder_id {
            x509_ocsp::ResponderId::ByName(n) => {
                n.to_der().map(|d| name_der_string(&d)).unwrap_or_default()
            }
            x509_ocsp::ResponderId::ByKey(k) => format!("key:{}", hex(k.as_bytes())),
        });
        for s in &rd.responses {
            let (status, revoked_at, reason) = match &s.cert_status {
                x509_ocsp::CertStatus::Good(_) => ("good", None, None),
                x509_ocsp::CertStatus::Revoked(r) => (
                    "revoked",
                    Some(epoch_to_rfc3339(gt_epoch(&r.revocation_time))),
                    Some(
                        r.revocation_reason
                            .map(|c| reason_name(c as u8))
                            .unwrap_or_else(|| "unspecified".into()),
                    ),
                ),
                x509_ocsp::CertStatus::Unknown(_) => ("unknown", None, None),
            };
            info.responses.push(OcspSingle {
                serial_hex: int_hex(s.cert_id.serial_number.as_bytes()),
                issuer_key_hash_hex: hex(s.cert_id.issuer_key_hash.as_bytes()),
                status: status.into(),
                revoked_at,
                reason,
                this_update: epoch_to_rfc3339(gt_epoch(&s.this_update)),
                next_update: s
                    .next_update
                    .as_ref()
                    .map(|t| epoch_to_rfc3339(gt_epoch(t))),
            });
        }
        for c in b.certs.iter().flatten() {
            if let Ok(d) = c.to_der() {
                info.certificates.push(cert_info(&d)?);
            }
        }
    }
    info.der = der;
    Ok(info)
}

pub(crate) fn ocsp_status_name(raw: i32) -> &'static str {
    match raw {
        0 => "successful",
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => "unknown",
    }
}
