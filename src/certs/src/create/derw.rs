//! OWNER: B. A small DER writer (X.690) for everything the creation side signs: certificates, CRLs, CSRs, OCSP
//! responses, PKCS#8 and PKCS#12 containers. Hand-written on purpose: every byte that gets signed is decided here,
//! so lab sets can carry deliberately weak or broken structures (MD5/SHA-1 signatures, critical EKUs, exact issuer
//! names copied from an imported CA) that the certificate libraries refuse to build.
//!
//! Every function returns a complete TLV. `SET OF` contents are sorted (DER rule 11.6).

use crate::model::*;
use chrono::{DateTime, Datelike, Utc};

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// SET OF: elements sorted by their encodings (DER).
pub fn set_of(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut v = parts.to_vec();
    v.sort();
    tlv(0x31, &v.concat())
}

/// OBJECT IDENTIFIER from dotted text. Arcs up to 128 bits (UUID arcs under 2.25).
pub fn oid(dotted: &str) -> Vec<u8> {
    tlv(0x06, &oid_content(dotted).expect("static OID"))
}

pub fn oid_content(dotted: &str) -> CertResult<Vec<u8>> {
    let bad = || CertError::new(ErrorKind::InvalidInput, format!("invalid OID '{dotted}'"));
    let arcs: Vec<u128> = dotted
        .split('.')
        .map(|a| a.parse::<u128>().map_err(|_| bad()))
        .collect::<CertResult<_>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
        return Err(bad());
    }
    let mut out = vec![];
    let first = arcs[0]
        .checked_mul(40)
        .and_then(|v| v.checked_add(arcs[1]))
        .ok_or_else(bad)?;
    for a in std::iter::once(first).chain(arcs[2..].iter().copied()) {
        let mut groups = vec![(a & 0x7f) as u8];
        let mut v = a >> 7;
        while v > 0 {
            groups.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        groups.reverse();
        out.extend(groups);
    }
    Ok(out)
}

/// INTEGER from an unsigned big-endian magnitude (leading zeros stripped, 0x00 added when the top bit is set).
pub fn uint(bytes: &[u8]) -> Vec<u8> {
    let mut b: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    if b.is_empty() {
        b.push(0);
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

pub fn int(n: u64) -> Vec<u8> {
    uint(&n.to_be_bytes())
}

pub fn boolean(b: bool) -> Vec<u8> {
    tlv(0x01, &[if b { 0xff } else { 0 }])
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

/// BIT STRING of whole bytes (0 unused bits): signatures, public keys.
pub fn bits(b: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(b.len() + 1);
    c.push(0);
    c.extend_from_slice(b);
    tlv(0x03, &c)
}

/// BIT STRING of named bits (bit 0 = most significant bit of the first byte), trailing zero bits removed (DER).
pub fn named_bits(set: &[usize]) -> Vec<u8> {
    let max = set.iter().copied().max().unwrap_or(0);
    let mut bytes = vec![0u8; max / 8 + 1];
    for &i in set {
        bytes[i / 8] |= 0x80 >> (i % 8);
    }
    while bytes.len() > 1 && *bytes.last().unwrap() == 0 {
        bytes.pop();
    }
    let last = *bytes.last().unwrap();
    let unused = if last == 0 {
        0
    } else {
        last.trailing_zeros() as u8
    };
    let mut c = vec![unused];
    c.extend(bytes);
    tlv(0x03, &c)
}

pub fn enumerated(n: u8) -> Vec<u8> {
    tlv(0x0a, &[n])
}

pub fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}

pub fn printable(s: &str) -> Vec<u8> {
    tlv(0x13, s.as_bytes())
}

pub fn ia5(s: &str) -> Vec<u8> {
    tlv(0x16, s.as_bytes())
}

/// BMPString (UCS-2 big endian), for PKCS#12 friendlyName.
pub fn bmp(s: &str) -> Vec<u8> {
    let b: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    tlv(0x1e, &b)
}

/// `[n] EXPLICIT` (constructed context tag around a complete TLV).
pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

/// `[n] IMPLICIT` primitive (replaces the tag of a primitive type).
pub fn implicit_prim(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, content)
}

/// `[n] IMPLICIT` constructed (replaces the tag of a SEQUENCE / SET).
pub fn implicit_cons(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, content)
}

/// The content octets of a complete TLV (no validation beyond the length header).
pub fn content_of(der: &[u8]) -> &[u8] {
    if der.len() < 2 {
        return &[];
    }
    let l = der[1] as usize;
    if l < 0x80 {
        &der[2..(2 + l).min(der.len())]
    } else {
        let n = l & 0x7f;
        let mut len = 0usize;
        for b in &der[2..2 + n] {
            len = (len << 8) | *b as usize;
        }
        &der[2 + n..(2 + n + len).min(der.len())]
    }
}

/// X.509 Time: UTCTime for 1950–2049, GeneralizedTime otherwise (RFC 5280 4.1.2.5).
pub fn time(t: DateTime<Utc>) -> Vec<u8> {
    if (1950..2050).contains(&t.year()) {
        tlv(0x17, t.format("%y%m%d%H%M%SZ").to_string().as_bytes())
    } else {
        gentime(t)
    }
}

pub fn gentime(t: DateTime<Utc>) -> Vec<u8> {
    tlv(0x18, t.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
}

/// AlgorithmIdentifier with NULL parameters (RSA family, digests).
pub fn alg_null(o: &str) -> Vec<u8> {
    seq(&[oid(o), null()])
}

/// AlgorithmIdentifier with absent parameters (ECDSA, EdDSA).
pub fn alg_absent(o: &str) -> Vec<u8> {
    seq(&[oid(o)])
}

/// One Extension.
pub fn extension(o: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(o)];
    if critical {
        parts.push(boolean(true));
    }
    parts.push(octet(value));
    seq(&parts)
}

// ------------------------------------------------------------------------------------------------------------
// Names
// ------------------------------------------------------------------------------------------------------------

/// (short name, OID, string type) of the attributes a subject may use. `p` PrintableString, `i` IA5String,
/// `u` UTF8String.
const ATTRS: &[(&str, &str, char)] = &[
    ("C", "2.5.4.6", 'p'),
    ("ST", "2.5.4.8", 'u'),
    ("L", "2.5.4.7", 'u'),
    ("O", "2.5.4.10", 'u'),
    ("OU", "2.5.4.11", 'u'),
    ("CN", "2.5.4.3", 'u'),
    ("SN", "2.5.4.4", 'u'),
    ("GN", "2.5.4.42", 'u'),
    ("title", "2.5.4.12", 'u'),
    ("serialNumber", "2.5.4.5", 'p'),
    ("organizationIdentifier", "2.5.4.97", 'u'),
    ("street", "2.5.4.9", 'u'),
    ("postalCode", "2.5.4.17", 'u'),
    ("emailAddress", "1.2.840.113549.1.9.1", 'i'),
    ("DC", "0.9.2342.19200300.100.1.25", 'i'),
    ("UID", "0.9.2342.19200300.100.1.1", 'u'),
];

/// DER Name (RDNSequence, one attribute per RDN, in the given order).
pub fn name(rdns: &[(String, String)]) -> CertResult<Vec<u8>> {
    if rdns.is_empty() {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            "empty subject: give at least CN=...",
        ));
    }
    let mut out = vec![];
    for (k, v) in rdns {
        let key = k.trim();
        let (o, ty) = match ATTRS.iter().find(|(n, _, _)| n.eq_ignore_ascii_case(key)) {
            Some((_, o, t)) => (o.to_string(), *t),
            None if key.contains('.') && oid_content(key).is_ok() => (key.to_string(), 'u'),
            None => {
                return Err(CertError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "unknown subject attribute '{key}': use C, ST, L, O, OU, CN, SN, GN, title, serialNumber, organizationIdentifier, emailAddress, DC, UID or a dotted OID"
                    ),
                ));
            }
        };
        if v.is_empty() {
            return Err(CertError::new(
                ErrorKind::InvalidInput,
                format!("empty value for subject attribute {key}"),
            ));
        }
        let value = match ty {
            'p' => {
                if !v
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || " '()+,-./:=?".contains(c))
                {
                    return Err(CertError::new(
                        ErrorKind::InvalidInput,
                        format!("{key}={v}: only PrintableString characters are allowed"),
                    ));
                }
                if key.eq_ignore_ascii_case("C") && v.len() != 2 {
                    return Err(CertError::new(
                        ErrorKind::InvalidInput,
                        format!("C={v}: the country is a two-letter ISO 3166 code (CO, FR)"),
                    ));
                }
                printable(v)
            }
            'i' => {
                if !v.is_ascii() {
                    return Err(CertError::new(
                        ErrorKind::InvalidInput,
                        format!("{key}={v}: only ASCII is allowed"),
                    ));
                }
                ia5(v)
            }
            _ => utf8(v),
        };
        out.push(set_of(&[seq(&[tlv(0x06, &oid_content(&o)?), value])]));
    }
    Ok(seq(&out))
}

/// One GeneralName (SAN entry or name-constraint base). `ip` values are addresses (SAN) or `addr/prefix`
/// (name constraints).
pub fn general_name(g: &GeneralName) -> CertResult<Vec<u8>> {
    let v = g.value.trim();
    let bad = |m: &str| {
        CertError::new(
            ErrorKind::InvalidInput,
            format!("{}:{}: {m}", g.kind, g.value),
        )
    };
    match g.kind.as_str() {
        "dns" => {
            if v.is_empty() || !v.is_ascii() || v.contains(' ') {
                return Err(bad("not an ASCII DNS name (use punycode for IDNs)"));
            }
            Ok(implicit_prim(2, v.as_bytes()))
        }
        "email" => {
            if !v.is_ascii() || v.is_empty() || v.contains(' ') {
                return Err(bad("not an ASCII e-mail address or domain"));
            }
            Ok(implicit_prim(1, v.as_bytes()))
        }
        "uri" => {
            if !v.is_ascii() || v.is_empty() {
                return Err(bad("not an ASCII URI"));
            }
            Ok(implicit_prim(6, v.as_bytes()))
        }
        "ip" => {
            let (addr, prefix) = match v.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (v, None),
            };
            let ip: std::net::IpAddr = addr.parse().map_err(|_| bad("not an IP address"))?;
            let mut b = match ip {
                std::net::IpAddr::V4(a) => a.octets().to_vec(),
                std::net::IpAddr::V6(a) => a.octets().to_vec(),
            };
            if let Some(p) = prefix {
                let p: usize = p.parse().map_err(|_| bad("bad prefix length"))?;
                let total = b.len() * 8;
                if p > total {
                    return Err(bad("prefix longer than the address"));
                }
                let mask: Vec<u8> = (0..b.len())
                    .map(|i| {
                        let bitsset = p.saturating_sub(i * 8).min(8);
                        (0xffu16 << (8 - bitsset)) as u8
                    })
                    .collect();
                for (x, m) in b.iter_mut().zip(&mask) {
                    *x &= m;
                }
                b.extend(mask);
            }
            Ok(implicit_prim(7, &b))
        }
        _ => Err(bad("SAN type must be dns, ip, email or uri")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_and_integers_encode_like_openssl() {
        assert_eq!(oid("1.2.840.113549.1.1.11"), {
            let mut v = vec![0x06, 0x09];
            v.extend([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
            v
        });
        // The Rakvor UUID arc round-trips through OpenSSL's OID parser.
        let o = openssl::asn1::Asn1Object::from_str(RAKVOR_POLICY_INTERNAL).unwrap();
        assert_eq!(
            o.as_slice(),
            &oid_content(RAKVOR_POLICY_INTERNAL).unwrap()[..]
        );
        assert_eq!(uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[0, 0, 1]), vec![0x02, 0x01, 0x01]);
        assert_eq!(int(0), vec![0x02, 0x01, 0x00]);
        // keyCertSign + cRLSign = bits 5 and 6 -> 03 02 01 06
        assert_eq!(named_bits(&[5, 6]), vec![0x03, 0x02, 0x01, 0x06]);
        // digitalSignature only -> 03 02 07 80
        assert_eq!(named_bits(&[0]), vec![0x03, 0x02, 0x07, 0x80]);
        let long = vec![0u8; 300];
        assert_eq!(&octet(&long)[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(content_of(&octet(&long)).len(), 300);
    }

    #[test]
    fn names_and_general_names() {
        let n = name(&[("C".into(), "CO".into()), ("CN".into(), "Ana Ruiz".into())]).unwrap();
        let parsed = openssl::x509::X509Name::from_der(&n).unwrap();
        assert_eq!(parsed.entries().count(), 2);
        assert!(name(&[]).is_err());
        assert!(name(&[("C".into(), "Colombia".into())]).is_err());
        assert!(name(&[("XX".into(), "v".into())]).is_err());
        let ip = general_name(&GeneralName {
            kind: "ip".into(),
            value: "192.0.2.7/24".into(),
        })
        .unwrap();
        assert_eq!(ip, vec![0x87, 8, 192, 0, 2, 0, 255, 255, 255, 0]);
    }
}
