//! OWNER: A. Small helpers shared by the analysis modules: errors, times, OpenSSL-style names, a bounds-checked
//! DER walker (never panics on hostile input) and digests.
use crate::model::*;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::x509::X509NameRef;
use sha2::Digest;

pub fn parse_err(what: &str, e: impl std::fmt::Display) -> CertError {
    CertError::new(ErrorKind::Parse, format!("{what}: {e}"))
}

pub fn crypto_err(what: &str, e: impl std::fmt::Display) -> CertError {
    CertError::new(ErrorKind::Crypto, format!("{what}: {e}"))
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&sha2::Sha256::digest(b))
}

pub fn sha1_hex(b: &[u8]) -> String {
    hex(&sha1::Sha1::digest(b))
}

/// Seconds since the Unix epoch → the model's RFC 3339 format.
pub fn epoch_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(rfc3339)
        .unwrap_or_else(|| format!("@{secs}"))
}

/// RFC 3339 (any offset) → seconds since the Unix epoch.
pub fn rfc3339_to_epoch(s: &str) -> CertResult<i64> {
    if let Ok(AtTime::Fixed(t)) = AtTime::parse(s)
        && let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&t)
    {
        return Ok(dt.timestamp());
    }
    Err(CertError::new(
        ErrorKind::InvalidInput,
        format!("invalid time '{s}': expected RFC 3339 such as 2026-06-01T00:00:00Z"),
    ))
}

pub fn now_rfc3339() -> String {
    rfc3339(chrono::Utc::now())
}

/// OpenSSL ASN1_TIME → seconds since the epoch.
pub fn asn1_epoch(t: &Asn1TimeRef) -> CertResult<i64> {
    let epoch = Asn1Time::from_unix(0).map_err(|e| crypto_err("time", e))?;
    let d = epoch.diff(t).map_err(|e| parse_err("time", e))?;
    Ok(d.days as i64 * 86_400 + d.secs as i64)
}

pub fn asn1_rfc3339(t: &Asn1TimeRef) -> CertResult<String> {
    asn1_epoch(t).map(epoch_to_rfc3339)
}

/// OpenSSL's printed time (`Feb  1 00:00:00 2026 GMT`, the only accessor of an ASN1_GENERALIZEDTIME in the
/// `openssl` crate) → RFC 3339.
pub fn printed_time_to_rfc3339(s: &str) -> Option<String> {
    let norm = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let norm = norm.trim_end_matches(" GMT");
    // Fractional seconds (`00:00:00.123`) are dropped: the model has second precision.
    let mut parts: Vec<String> = norm.split(' ').map(str::to_string).collect();
    if let Some(p) = parts.get_mut(2)
        && let Some((hms, _)) = p.split_once('.')
    {
        *p = hms.to_string();
    }
    let norm = parts.join(" ");
    chrono::NaiveDateTime::parse_from_str(&norm, "%b %d %H:%M:%S %Y")
        .ok()
        .map(|t| rfc3339(t.and_utc()))
}

/// (short name, value) pairs in certificate order. Unknown attributes keep their OID.
pub fn name_rdns(n: &X509NameRef) -> Vec<(String, String)> {
    n.entries()
        .map(|e| {
            let obj = e.object();
            let key = obj
                .nid()
                .short_name()
                .map(str::to_string)
                .unwrap_or_else(|_| obj.to_string());
            let val = e
                .data()
                .to_string()
                .unwrap_or_else(|_| format!("#{}", hex(e.data().as_slice())));
            (key, val)
        })
        .collect()
}

/// `C=CO, O=Rakvor, CN=Rakvor Lab Root` (certificate order, OpenSSL short names).
pub fn rdns_string(r: &[(String, String)]) -> String {
    r.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn name_string(n: &X509NameRef) -> String {
    rdns_string(&name_rdns(n))
}

/// A Name given as DER (x509-parser / RustCrypto structures) rendered the OpenSSL way.
pub fn name_der_string(der: &[u8]) -> String {
    openssl::x509::X509Name::from_der(der)
        .map(|n| name_string(&n))
        .unwrap_or_else(|_| format!("#{}", hex(der)))
}

/// OpenSSL long name of an OID (`sha256WithRSAEncryption`), else the OID itself.
pub fn oid_long_name(oid: &str) -> String {
    openssl::asn1::Asn1Object::from_str(oid)
        .ok()
        .and_then(|o| o.nid().long_name().ok().map(str::to_string))
        .unwrap_or_else(|| oid.to_string())
}

/// OpenSSL short name of an OID (`basicConstraints`), else the OID itself.
pub fn oid_short_name(oid: &str) -> String {
    openssl::asn1::Asn1Object::from_str(oid)
        .ok()
        .and_then(|o| o.nid().short_name().ok().map(str::to_string))
        .unwrap_or_else(|| oid.to_string())
}

/// Lowercase hex of a big-endian unsigned integer without leading zero bytes (the model's serial format).
pub fn int_hex(bytes: &[u8]) -> String {
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    let h = hex(b);
    let t = h.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

// ------------------------------------------------------------------------------------------------ DER walker

/// One DER TLV: `tag` is the identifier octet (low-tag-number form only), `content` its value.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// The whole TLV (header + content).
    pub raw: &'a [u8],
}

/// Reads one TLV from the front of `b`; returns it and the rest. None on anything malformed (indefinite or
/// over-long lengths, truncation, high tag numbers). Never panics.
pub fn tlv(b: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *b.first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *b.get(1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2usize)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut l = 0usize;
        for i in 0..n {
            l = (l << 8) | *b.get(2 + i)? as usize;
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some((
        Tlv {
            tag,
            content: &b[hdr..end],
            raw: &b[..end],
        },
        &b[end..],
    ))
}

/// All TLVs inside a constructed value, in order (stops at the first malformed one).
pub fn children(content: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = vec![];
    let mut rest = content;
    while !rest.is_empty() {
        match tlv(rest) {
            Some((t, r)) => {
                out.push(t);
                rest = r;
            }
            None => break,
        }
    }
    out
}

/// Dotted text of an OBJECT IDENTIFIER's content octets.
pub fn oid_text(content: &[u8]) -> Option<String> {
    if content.is_empty() || content.len() > 64 {
        return None;
    }
    let mut arcs: Vec<u128> = vec![];
    let mut v: u128 = 0;
    for (i, &b) in content.iter().enumerate() {
        v = v.checked_mul(128)?.checked_add((b & 0x7f) as u128)?;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let (a, b2) = if v < 40 {
                    (0, v)
                } else if v < 80 {
                    (1, v - 40)
                } else {
                    (2, v - 80)
                };
                arcs.push(a);
                arcs.push(b2);
            } else {
                arcs.push(v);
            }
            v = 0;
        } else if i == content.len() - 1 {
            return None;
        }
    }
    Some(
        arcs.iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// DER content octets of a dotted OID (arcs up to 128 bits). None for malformed text.
pub fn oid_encode(text: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u128> = text
        .split('.')
        .map(|a| a.parse::<u128>().ok())
        .collect::<Option<_>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return None;
    }
    let mut out = vec![];
    let first = arcs[0].checked_mul(40)?.checked_add(arcs[1])?;
    for v in std::iter::once(first).chain(arcs[2..].iter().copied()) {
        let mut groups = vec![(v & 0x7f) as u8];
        let mut x = v >> 7;
        while x > 0 {
            groups.push(((x & 0x7f) as u8) | 0x80);
            x >>= 7;
        }
        out.extend(groups.iter().rev());
    }
    Some(out)
}

/// `20261103101500Z` / `20261103101500.123Z` (GeneralizedTime content) → RFC 3339, fractions dropped. Lenient on
/// purpose (as the template's TSTInfo parser in core/trust.rs): many TSAs send fractional seconds.
pub fn generalized_time(content: &[u8]) -> Option<String> {
    let raw = std::str::from_utf8(content).ok()?;
    if raw.len() < 14 || !raw.as_bytes()[..14].iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let s = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &raw[0..4],
        &raw[4..6],
        &raw[6..8],
        &raw[8..10],
        &raw[10..12],
        &raw[12..14]
    );
    // Offsets other than Z are not DER; accept only Z or no zone (treated as UTC).
    let tail = &raw[14..];
    let tail = tail.split_once('.').map(|(_, f)| f).unwrap_or(tail);
    let zone = tail.trim_start_matches(|c: char| c.is_ascii_digit());
    if !(zone.is_empty() || zone == "Z") {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(&s).ok()?;
    Some(s)
}

pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// For a CMS ContentInfo with SignedData: the eContentType OID. None if the bytes are not that.
pub fn signed_data_econtent_type(der: &[u8]) -> Option<String> {
    let (ci, _) = tlv(der)?;
    if ci.tag != 0x30 {
        return None;
    }
    let f = children(ci.content);
    if f.len() < 2
        || f[0].tag != 0x06
        || oid_text(f[0].content)? != OID_SIGNED_DATA
        || f[1].tag != 0xa0
    {
        return None;
    }
    let (sd, _) = tlv(f[1].content)?;
    let sdf = children(sd.content);
    // version INTEGER, digestAlgorithms SET, encapContentInfo SEQUENCE { eContentType OID, ... }
    let eci = sdf.get(2)?;
    if sdf.first()?.tag != 0x02 || eci.tag != 0x30 {
        return None;
    }
    let (oid, _) = tlv(eci.content)?;
    if oid.tag != 0x06 {
        return None;
    }
    oid_text(oid.content)
}

/// The TimeStampToken inside a TimeStampResp (`SEQUENCE { PKIStatusInfo, ContentInfo OPTIONAL }`), with the PKI
/// status number. None if the bytes are not a TimeStampResp.
pub fn tsr_parts(der: &[u8]) -> Option<(i64, Option<&[u8]>)> {
    let (resp, _) = tlv(der)?;
    if resp.tag != 0x30 {
        return None;
    }
    let f = children(resp.content);
    let st = f.first()?;
    if st.tag != 0x30 {
        return None;
    }
    let (status, _) = tlv(st.content)?;
    if status.tag != 0x02 || status.content.is_empty() || status.content.len() > 2 {
        return None;
    }
    let n = status
        .content
        .iter()
        .fold(0i64, |a, &b| (a << 8) | b as i64);
    match f.get(1) {
        Some(tok) if signed_data_econtent_type(tok.raw).as_deref() == Some(OID_TST_INFO) => {
            Some((n, Some(tok.raw)))
        }
        Some(_) => None,
        None => Some((n, None)),
    }
}

/// `encapContentInfo.eContent` (the OCTET STRING content) of a SignedData ContentInfo.
pub fn signed_data_econtent(der: &[u8]) -> Option<&[u8]> {
    let (ci, _) = tlv(der)?;
    let f = children(ci.content);
    let (sd, _) = tlv(f.get(1)?.content)?;
    let sdf = children(sd.content);
    let eci = children(sdf.get(2)?.content);
    let explicit = eci.get(1)?;
    if explicit.tag != 0xa0 {
        return None;
    }
    let (oct, _) = tlv(explicit.content)?;
    if oct.tag != 0x04 {
        return None;
    }
    Some(oct.content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walker_is_bounds_checked() {
        assert!(tlv(b"").is_none());
        assert!(tlv(b"\x30").is_none());
        assert!(tlv(b"\x30\x82\xff\xff").is_none());
        assert!(tlv(b"\x30\x85\x01\x01\x01\x01\x01").is_none());
        assert!(tlv(b"\x30\x80\x00\x00").is_none());
        let (t, rest) = tlv(b"\x02\x01\x05\xff").unwrap();
        assert_eq!((t.tag, t.content, rest), (2, &b"\x05"[..], &b"\xff"[..]));
        assert_eq!(
            oid_text(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]).unwrap(),
            "1.2.840.113549"
        );
        assert!(oid_text(&[0x86]).is_none());
        let arc = oid_encode(RAKVOR_OID_ARC).unwrap();
        assert_eq!(oid_text(&arc).unwrap(), RAKVOR_OID_ARC);
        assert_eq!(
            oid_encode("1.2.840.113549").unwrap(),
            [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]
        );
        assert_eq!(
            generalized_time(b"20261020182422.123Z").unwrap(),
            "2026-10-20T18:24:22Z"
        );
        assert!(generalized_time(b"2026").is_none());
        assert!(generalized_time(b"20261340182422Z").is_none());
        assert_eq!(int_hex(&[0, 0x20, 0x01]), "2001");
        assert_eq!(int_hex(&[0]), "0");
        assert_eq!(
            printed_time_to_rfc3339("Feb  1 00:00:00 2026 GMT").unwrap(),
            "2026-02-01T00:00:00Z"
        );
    }
}
