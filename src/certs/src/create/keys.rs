//! OWNER: B. Key generation, key protection and key files.
//!
//! KEY PROTECTION (production keys: CA keys, CSR keys, examiner keys):
//! - Encrypted PKCS#8 (`-----BEGIN ENCRYPTED PRIVATE KEY-----`, RFC 5958 EncryptedPrivateKeyInfo) with PBES2
//!   (RFC 8018): key derivation PBKDF2-HMAC-SHA256, [`PBKDF2_ITERATIONS`] = 600 000 iterations (OWASP 2023 for
//!   PBKDF2-SHA256), 16-byte random salt; cipher AES-256-CBC with a 16-byte random IV. Readable by
//!   `openssl pkey -in key.p8` and by every PKCS#8 reader. scrypt was not chosen: OpenSSL's PKCS#8 reader caps
//!   scrypt memory at 32 MiB, which forbids strong scrypt parameters for files other tools must open.
//! - PKCS#12 (examiner `.p12`): the key in a pkcs8ShroudedKeyBag with the same PBES2 parameters, certificates in
//!   a plain SafeContents (public data), integrity by HMAC-SHA256 with the RFC 7292 appendix B key derivation,
//!   600 000 iterations, 16-byte salt. Loads with OpenSSL 3, p12-keystore (rv-hashinv `--sign-cert`) and
//!   Windows 10 1709+.
//! - Files are created with `create_new` (never overwritten). On Unix they are written 0600 (directories 0700).
//!   On Windows, files under the user's profile inherit an ACL granting access to the user, SYSTEM and
//!   Administrators only, which is what "owner-only" means there; keep CA folders inside the profile (or on an
//!   offline medium) and not in shared folders.
//! - Plaintext key material lives in `Zeroizing` buffers and OpenSSL objects (freed with `BN_clear_free` /
//!   `OPENSSL_clear_free`); passwords only in [`Secret`].
//!
//! LAB SETS ONLY: [`seeded_rsa`] derives keys from a seeded ChaCha20 stream, and the lab
//! PKCS#12 uses a seeded salt and IV, so a set is byte-identical for a seed. Those keys are public by construction.

use super::derw::*;
use super::rng::Rand;
use crate::model::*;
use openssl::bn::{BigNum, BigNumContext};
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Rsa;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

/// PBKDF2-HMAC-SHA256 iterations for every encrypted key and PKCS#12 MAC.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

const OID_PBES2: &str = "1.2.840.113549.1.5.13";
const OID_PBKDF2: &str = "1.2.840.113549.1.5.12";
const OID_HMAC_SHA256: &str = "1.2.840.113549.2.9";
const OID_AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";

pub fn crypto(what: &str) -> impl Fn(openssl::error::ErrorStack) -> CertError + '_ {
    move |e| CertError::new(ErrorKind::Crypto, format!("{what}: {e}"))
}

pub fn io_err(path: &Path) -> impl Fn(std::io::Error) -> CertError + '_ {
    move |e| CertError::new(ErrorKind::Io, format!("{}: {e}", path.display()))
}

// ------------------------------------------------------------------------------------------------------------
// Generation
// ------------------------------------------------------------------------------------------------------------

/// A new key from the OS CSPRNG (OpenSSL).
pub fn generate(spec: KeySpec) -> CertResult<PKey<Private>> {
    let c = crypto("key generation");
    let ec = |nid| -> CertResult<PKey<Private>> {
        let g = openssl::ec::EcGroup::from_curve_name(nid).map_err(&c)?;
        let k = openssl::ec::EcKey::generate(&g).map_err(&c)?;
        PKey::from_ec_key(k).map_err(&c)
    };
    match spec {
        KeySpec::Rsa2048 => PKey::from_rsa(Rsa::generate(2048).map_err(&c)?).map_err(&c),
        KeySpec::Rsa3072 => PKey::from_rsa(Rsa::generate(3072).map_err(&c)?).map_err(&c),
        KeySpec::Rsa4096 => PKey::from_rsa(Rsa::generate(4096).map_err(&c)?).map_err(&c),
        KeySpec::P256 => ec(openssl::nid::Nid::X9_62_PRIME256V1),
        KeySpec::P384 => ec(openssl::nid::Nid::SECP384R1),
        KeySpec::Ed25519 => PKey::generate_ed25519().map_err(&c),
    }
}

/// LAB ONLY. An RSA key whose primes come from the seeded stream: random odd candidates with the two top bits
/// set (so n has exactly `bits` bits), a small-prime sieve, gcd(e, p-1) = 1, then OpenSSL's Miller-Rabin test
/// (whose own random witnesses only affect the error probability, not which candidate is accepted).
pub fn seeded_rsa(rand: &mut Rand, bits: u32) -> CertResult<PKey<Private>> {
    let c = crypto("lab RSA key");
    let mut ctx = BigNumContext::new().map_err(&c)?;
    let e = BigNum::from_u32(65537).map_err(&c)?;
    let one = BigNum::from_u32(1).map_err(&c)?;
    loop {
        let mut p = seeded_prime(rand, bits / 2, &mut ctx)?;
        let mut q = seeded_prime(rand, bits - bits / 2, &mut ctx)?;
        if p == q {
            continue;
        }
        if p < q {
            std::mem::swap(&mut p, &mut q);
        }
        let mut n = BigNum::new().map_err(&c)?;
        n.checked_mul(&p, &q, &mut ctx).map_err(&c)?;
        if n.num_bits() != bits as i32 {
            continue;
        }
        let (mut p1, mut q1) = (BigNum::new().map_err(&c)?, BigNum::new().map_err(&c)?);
        p1.checked_sub(&p, &one).map_err(&c)?;
        q1.checked_sub(&q, &one).map_err(&c)?;
        let mut g = BigNum::new().map_err(&c)?;
        g.gcd(&p1, &q1, &mut ctx).map_err(&c)?;
        let mut phi = BigNum::new().map_err(&c)?;
        phi.checked_mul(&p1, &q1, &mut ctx).map_err(&c)?;
        let mut lambda = BigNum::new().map_err(&c)?;
        lambda.checked_div(&phi, &g, &mut ctx).map_err(&c)?;
        let mut d = BigNum::new().map_err(&c)?;
        d.mod_inverse(&e, &lambda, &mut ctx).map_err(&c)?;
        let (mut dmp1, mut dmq1, mut iqmp) = (
            BigNum::new().map_err(&c)?,
            BigNum::new().map_err(&c)?,
            BigNum::new().map_err(&c)?,
        );
        dmp1.nnmod(&d, &p1, &mut ctx).map_err(&c)?;
        dmq1.nnmod(&d, &q1, &mut ctx).map_err(&c)?;
        iqmp.mod_inverse(&q, &p, &mut ctx).map_err(&c)?;
        let rsa = Rsa::from_private_components(
            n,
            BigNum::from_u32(65537).map_err(&c)?,
            d,
            p,
            q,
            dmp1,
            dmq1,
            iqmp,
        )
        .map_err(&c)?;
        if !rsa.check_key().map_err(&c)? {
            continue;
        }
        return PKey::from_rsa(rsa).map_err(&c);
    }
}

const SMALL_PRIMES: [u32; 53] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

fn seeded_prime(rand: &mut Rand, bits: u32, ctx: &mut BigNumContext) -> CertResult<BigNum> {
    let c = crypto("lab RSA prime");
    let nbytes = bits.div_ceil(8) as usize;
    let excess = (nbytes * 8) as u32 - bits;
    loop {
        let mut b = Zeroizing::new(rand.bytes(nbytes)?);
        b[0] &= 0xffu8 >> excess;
        // Two top bits set: the product of two such primes has exactly 2*bits bits.
        b[0] |= 0xc0u8 >> excess;
        if excess == 7 {
            b[1] |= 0x80;
        }
        let last = b.len() - 1;
        b[last] |= 1;
        let cand = BigNum::from_slice(&b).map_err(&c)?;
        if SMALL_PRIMES
            .iter()
            .any(|sp| cand.mod_word(*sp).map(|r| r == 0).unwrap_or(true))
        {
            continue;
        }
        if cand.mod_word(65537).map_err(&c)? == 1 {
            continue;
        }
        if cand.is_prime(64, ctx).map_err(&c)? {
            return Ok(cand);
        }
    }
}

/// The KeySpec a key corresponds to, if it is one of the supported ones.
pub fn spec_of<T: openssl::pkey::HasPublic>(k: &openssl::pkey::PKeyRef<T>) -> Option<KeySpec> {
    match k.id() {
        Id::RSA => match k.bits() {
            2048 => Some(KeySpec::Rsa2048),
            3072 => Some(KeySpec::Rsa3072),
            4096 => Some(KeySpec::Rsa4096),
            _ => None,
        },
        Id::EC => match k.ec_key().ok()?.group().curve_name()? {
            openssl::nid::Nid::X9_62_PRIME256V1 => Some(KeySpec::P256),
            openssl::nid::Nid::SECP384R1 => Some(KeySpec::P384),
            _ => None,
        },
        Id::ED25519 => Some(KeySpec::Ed25519),
        _ => None,
    }
}

// ------------------------------------------------------------------------------------------------------------
// Public facts
// ------------------------------------------------------------------------------------------------------------

/// Canonical DER SubjectPublicKeyInfo (OpenSSL re-encoding), so keys from files, certificates and tokens compare.
pub fn canonical_spki(spki: &[u8]) -> CertResult<Vec<u8>> {
    let k = PKey::public_key_from_der(spki).map_err(|e| {
        CertError::new(ErrorKind::Parse, format!("not a SubjectPublicKeyInfo: {e}"))
    })?;
    k.public_key_to_der().map_err(crypto("public key"))
}

/// The subjectPublicKey BIT STRING contents of an SPKI (what SKI / OCSP key hashes are computed over).
pub fn spki_key_bits(spki: &[u8]) -> CertResult<Vec<u8>> {
    let parts = children(content_of(spki));
    match parts.get(1) {
        Some(b) if b.first() == Some(&0x03) => {
            let c = content_of(b);
            Ok(c.get(1..).unwrap_or_default().to_vec())
        }
        _ => Err(CertError::new(
            ErrorKind::Parse,
            "SubjectPublicKeyInfo without a BIT STRING",
        )),
    }
}

/// RFC 5280 4.2.1.2 method 1: SHA-1 of the subjectPublicKey bits.
pub fn key_id(spki: &[u8]) -> CertResult<Vec<u8>> {
    Ok(openssl::sha::sha1(&spki_key_bits(spki)?).to_vec())
}

/// The complete TLVs inside a constructed value's content octets.
pub fn children(mut content: &[u8]) -> Vec<&[u8]> {
    let mut out = vec![];
    while content.len() >= 2 {
        let l = content[1] as usize;
        let (hdr, len) = if l < 0x80 {
            (2, l)
        } else {
            let n = l & 0x7f;
            if content.len() < 2 + n {
                break;
            }
            let mut len = 0usize;
            for b in &content[2..2 + n] {
                len = (len << 8) | *b as usize;
            }
            (2 + n, len)
        };
        if content.len() < hdr + len {
            break;
        }
        out.push(&content[..hdr + len]);
        content = &content[hdr + len..];
    }
    out
}

pub fn key_info(spki: &[u8]) -> CertResult<KeyInfo> {
    let k = PKey::public_key_from_der(spki)
        .map_err(|e| CertError::new(ErrorKind::Parse, format!("public key: {e}")))?;
    key_info_of(&k)
}

pub fn key_info_of<T: openssl::pkey::HasPublic>(
    k: &openssl::pkey::PKeyRef<T>,
) -> CertResult<KeyInfo> {
    let der = k.public_key_to_der().map_err(crypto("public key"))?;
    let (algorithm, bits, curve) = match k.id() {
        Id::RSA => ("rsa".to_string(), Some(k.bits()), None),
        Id::DSA => ("dsa".to_string(), Some(k.bits()), None),
        Id::EC => {
            let curve = k
                .ec_key()
                .ok()
                .and_then(|e| e.group().curve_name())
                .map(|n| match n {
                    openssl::nid::Nid::X9_62_PRIME256V1 => "P-256".to_string(),
                    openssl::nid::Nid::SECP384R1 => "P-384".to_string(),
                    openssl::nid::Nid::SECP521R1 => "P-521".to_string(),
                    other => other.short_name().unwrap_or("unknown").to_string(),
                });
            ("ec".to_string(), Some(k.bits()), curve)
        }
        Id::ED25519 => ("ed25519".to_string(), Some(256), None),
        Id::ED448 => ("ed448".to_string(), Some(456), None),
        other => (format!("id-{}", other.as_raw()), Some(k.bits()), None),
    };
    Ok(KeyInfo {
        algorithm,
        bits,
        curve,
        spki_sha256: hex(&openssl::sha::sha256(&der)),
        encrypted: false,
    })
}

// ------------------------------------------------------------------------------------------------------------
// Encrypted PKCS#8 and PKCS#12
// ------------------------------------------------------------------------------------------------------------

fn password_bytes(p: &Secret) -> CertResult<&[u8]> {
    if p.expose().contains('\0') {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            "a password must not contain a NUL character",
        ));
    }
    Ok(p.expose().as_bytes())
}

/// PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC) EncryptedPrivateKeyInfo of a plaintext PKCS#8 DER.
fn pbes2_encrypt(
    plain: &[u8],
    password: &Secret,
    rand: &mut Rand,
    iterations: u32,
) -> CertResult<Vec<u8>> {
    let pw = password_bytes(password)?;
    if pw.is_empty() {
        return Err(CertError::new(
            ErrorKind::Password,
            "an empty password cannot protect a private key: give one (env variable or prompt)",
        ));
    }
    let salt = rand.bytes(16)?;
    let iv = rand.bytes(16)?;
    let mut key = Zeroizing::new([0u8; 32]);
    openssl::pkcs5::pbkdf2_hmac(
        pw,
        &salt,
        iterations as usize,
        MessageDigest::sha256(),
        &mut key[..],
    )
    .map_err(crypto("PBKDF2"))?;
    let ct = openssl::symm::encrypt(
        openssl::symm::Cipher::aes_256_cbc(),
        &key[..],
        Some(&iv),
        plain,
    )
    .map_err(crypto("AES-256-CBC"))?;
    let kdf = seq(&[
        oid(OID_PBKDF2),
        seq(&[
            octet(&salt),
            int(iterations as u64),
            alg_null(OID_HMAC_SHA256),
        ]),
    ]);
    let enc = seq(&[oid(OID_AES256_CBC), octet(&iv)]);
    Ok(seq(&[seq(&[oid(OID_PBES2), seq(&[kdf, enc])]), octet(&ct)]))
}

/// `-----BEGIN ENCRYPTED PRIVATE KEY-----` of a key.
pub fn encrypted_pkcs8_pem(
    key: &PKey<Private>,
    password: &Secret,
    rand: &mut Rand,
) -> CertResult<Zeroizing<String>> {
    let plain = Zeroizing::new(key.private_key_to_pkcs8().map_err(crypto("PKCS#8"))?);
    let der = pbes2_encrypt(&plain, password, rand, PBKDF2_ITERATIONS)?;
    Ok(Zeroizing::new(pem_encode("ENCRYPTED PRIVATE KEY", &der)))
}

/// LAB ONLY: an unencrypted PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) for deliberately public test keys.
pub fn plain_pkcs8_pem(key: &PKey<Private>) -> CertResult<Zeroizing<String>> {
    let plain = Zeroizing::new(key.private_key_to_pkcs8().map_err(crypto("PKCS#8"))?);
    Ok(Zeroizing::new(pem_encode("PRIVATE KEY", &plain)))
}

pub fn pem_encode(label: &str, der: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new(label, der.to_vec()),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

/// DER from PEM (first block with one of `labels`) or the bytes themselves when they are DER.
pub fn der_from_pem_or_der(data: &[u8], labels: &[&str]) -> CertResult<Vec<u8>> {
    if data.first() == Some(&0x30) {
        return Ok(data.to_vec());
    }
    let blocks = pem::parse_many(data)
        .map_err(|e| CertError::new(ErrorKind::Parse, format!("not PEM or DER: {e}")))?;
    blocks
        .into_iter()
        .find(|b| labels.contains(&b.tag()))
        .map(|b| b.into_contents())
        .ok_or_else(|| {
            CertError::new(
                ErrorKind::Parse,
                format!("no {} block found", labels.join(" / ")),
            )
        })
}

/// Opens a private key file: encrypted PKCS#8 (PEM or DER) or PKCS#12. Returns the key and the format
/// (`pkcs8-encrypted` | `pkcs12`). Plaintext keys are refused: a managed key must be protected at rest.
pub fn open_key_file(data: &[u8], password: &Secret) -> CertResult<(PKey<Private>, String)> {
    let pw = password_bytes(password)?;
    let text = String::from_utf8_lossy(data);
    if text.contains("-----BEGIN PRIVATE KEY-----")
        || text.contains("-----BEGIN RSA PRIVATE KEY-----") && !text.contains("ENCRYPTED")
        || text.contains("-----BEGIN EC PRIVATE KEY-----") && !text.contains("ENCRYPTED")
    {
        return Err(CertError::new(
            ErrorKind::Policy,
            "the key file is not encrypted: protect it first (openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000)",
        ));
    }
    let der = if data.first() == Some(&0x30) {
        Zeroizing::new(data.to_vec())
    } else {
        Zeroizing::new(der_from_pem_or_der(data, &["ENCRYPTED PRIVATE KEY"])?)
    };
    if let Ok(p12) = openssl::pkcs12::Pkcs12::from_der(&der) {
        let parsed = p12.parse2(password.expose()).map_err(|_| {
            CertError::new(
                ErrorKind::Password,
                "cannot open the PKCS#12 file: wrong password or unsupported (legacy RC2) encryption",
            )
        })?;
        let key = parsed.pkey.ok_or_else(|| {
            CertError::new(
                ErrorKind::InvalidInput,
                "the PKCS#12 file holds no private key",
            )
        })?;
        return Ok((key, "pkcs12".into()));
    }
    if pw.is_empty() {
        return Err(CertError::new(
            ErrorKind::Password,
            "the key password is missing (env variable or prompt)",
        ));
    }
    let key = PKey::private_key_from_pkcs8_passphrase(&der, pw).map_err(|_| {
        CertError::new(
            ErrorKind::Password,
            "cannot decrypt the key file: wrong password or not an encrypted PKCS#8 key",
        )
    })?;
    Ok((key, "pkcs8-encrypted".into()))
}

/// PKCS#12 (RFC 7292) with the key in a PBES2 pkcs8ShroudedKeyBag, `certs[0]` = the key's certificate (with
/// localKeyId + friendlyName, so p12-keystore and Windows pair them), the rest = its chain, and an HMAC-SHA256
/// MAC. `rand` gives salts and IVs (seeded for lab sets only).
pub fn pkcs12(
    key: &PKey<Private>,
    certs: &[Vec<u8>],
    friendly_name: &str,
    password: &Secret,
    rand: &mut Rand,
) -> CertResult<Vec<u8>> {
    const DATA: &str = "1.2.840.113549.1.7.1";
    let local_key_id = {
        let first = certs.first().ok_or_else(|| {
            CertError::new(ErrorKind::InvalidInput, "PKCS#12 without certificate")
        })?;
        openssl::sha::sha1(first).to_vec()
    };
    let attrs = set_of(&[
        seq(&[
            oid("1.2.840.113549.1.9.21"),
            set_of(&[octet(&local_key_id)]),
        ]),
        seq(&[oid("1.2.840.113549.1.9.20"), set_of(&[bmp(friendly_name)])]),
    ]);
    let mut cert_bags = vec![];
    for (i, c) in certs.iter().enumerate() {
        let cert_bag = seq(&[oid("1.2.840.113549.1.9.22.1"), explicit(0, &octet(c))]);
        let mut bag = vec![oid("1.2.840.113549.1.12.10.1.3"), explicit(0, &cert_bag)];
        if i == 0 {
            bag.push(attrs.clone());
        }
        cert_bags.push(seq(&bag));
    }
    let plain = Zeroizing::new(key.private_key_to_pkcs8().map_err(crypto("PKCS#8"))?);
    let epki = pbes2_encrypt(&plain, password, rand, PBKDF2_ITERATIONS)?;
    let key_bag = seq(&[oid("1.2.840.113549.1.12.10.1.2"), explicit(0, &epki), attrs]);
    let content_info =
        |safe_contents: Vec<u8>| seq(&[oid(DATA), explicit(0, &octet(&safe_contents))]);
    let auth_safe = seq(&[content_info(seq(&cert_bags)), content_info(seq(&[key_bag]))]);
    // MAC: HMAC-SHA256 keyed by the RFC 7292 B.2 KDF (ID 3) over the AuthenticatedSafe octets.
    let mac_salt = rand.bytes(16)?;
    let mac_key = p12_kdf_sha256(password, &mac_salt, 3, PBKDF2_ITERATIONS, 32)?;
    let hkey = PKey::hmac(&mac_key).map_err(crypto("HMAC"))?;
    let mut signer =
        openssl::sign::Signer::new(MessageDigest::sha256(), &hkey).map_err(crypto("HMAC"))?;
    signer.update(&auth_safe).map_err(crypto("HMAC"))?;
    let mac = signer.sign_to_vec().map_err(crypto("HMAC"))?;
    let mac_data = seq(&[
        seq(&[alg_null("2.16.840.1.101.3.4.2.1"), octet(&mac)]),
        octet(&mac_salt),
        int(PBKDF2_ITERATIONS as u64),
    ]);
    Ok(seq(&[int(3), content_info(auth_safe), mac_data]))
}

/// RFC 7292 appendix B.2 key derivation with SHA-256 (u = 32, v = 64). The password is BMPString + 2 NULs.
fn p12_kdf_sha256(
    password: &Secret,
    salt: &[u8],
    id: u8,
    iterations: u32,
    n: usize,
) -> CertResult<Zeroizing<Vec<u8>>> {
    const U: usize = 32;
    const V: usize = 64;
    let pw = password_bytes(password)?;
    let mut bmp_pw: Zeroizing<Vec<u8>> = Zeroizing::new(
        std::str::from_utf8(pw)
            .unwrap_or_default()
            .encode_utf16()
            .flat_map(|u| u.to_be_bytes())
            .collect(),
    );
    bmp_pw.extend([0, 0]);
    // I = S || P, built in one zeroized buffer (no un-wiped temporaries holding the password).
    let fill = |out: &mut Vec<u8>, src: &[u8]| {
        if !src.is_empty() {
            let len = V * src.len().div_ceil(V);
            out.extend((0..len).map(|i| src[i % src.len()]));
        }
    };
    let d = vec![id; V];
    let mut i_buf = Zeroizing::new(Vec::with_capacity(
        V * (salt.len() + bmp_pw.len()).div_ceil(V) + 2 * V,
    ));
    fill(&mut i_buf, salt);
    fill(&mut i_buf, &bmp_pw);
    let c = n.div_ceil(U);
    let mut out = Zeroizing::new(Vec::with_capacity(c * U));
    for round in 0..c {
        let mut h = openssl::sha::Sha256::new();
        h.update(&d);
        h.update(&i_buf);
        let mut a = Zeroizing::new(h.finish());
        for _ in 1..iterations {
            *a = openssl::sha::sha256(&a[..]);
        }
        out.extend_from_slice(&a[..]);
        if round + 1 < c {
            let b: Vec<u8> = (0..V).map(|k| a[k % U]).collect();
            for chunk in i_buf.chunks_mut(V) {
                let mut carry = 1u16;
                for k in (0..V).rev() {
                    let s = chunk[k] as u16 + b[k] as u16 + carry;
                    chunk[k] = s as u8;
                    carry = s >> 8;
                }
            }
        }
    }
    out.truncate(n);
    Ok(out)
}

// ------------------------------------------------------------------------------------------------------------
// Files
// ------------------------------------------------------------------------------------------------------------

/// Creates `path` with `bytes`; never overwrites. `secret` files are 0600 on Unix (see the module doc for Windows).
pub fn write_new(path: &Path, bytes: &[u8], secret: bool) -> CertResult<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(io_err(parent))?;
    }
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = o.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            CertError::new(
                ErrorKind::Policy,
                format!(
                    "{} already exists: files are never overwritten",
                    path.display()
                ),
            )
        } else {
            CertError::new(ErrorKind::Io, format!("{}: {e}", path.display()))
        }
    })?;
    f.write_all(bytes).map_err(io_err(path))?;
    f.sync_all().map_err(io_err(path))?;
    Ok(())
}

/// Replaces `path` atomically (write a temporary file, then rename): ca.json, crl/latest.crl.
pub fn replace(path: &Path, bytes: &[u8]) -> CertResult<()> {
    let tmp = path.with_extension("tmp-write");
    let _ = std::fs::remove_file(&tmp);
    write_new(&tmp, bytes, false)?;
    std::fs::rename(&tmp, path).map_err(io_err(path))
}

/// A directory for keys: created 0700 on Unix.
pub fn key_dir(path: &Path) -> CertResult<()> {
    std::fs::create_dir_all(path).map_err(io_err(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(io_err(path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_pkcs8_opens_with_openssl_and_refuses_bad_passwords() {
        let k = generate(KeySpec::P256).unwrap();
        let pem = encrypted_pkcs8_pem(&k, &Secret::new("pw-1"), &mut Rand::Os).unwrap();
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
        let (back, fmt) = open_key_file(pem.as_bytes(), &Secret::new("pw-1")).unwrap();
        assert_eq!(fmt, "pkcs8-encrypted");
        assert!(back.public_eq(&k));
        assert_eq!(
            open_key_file(pem.as_bytes(), &Secret::new("wrong"))
                .unwrap_err()
                .kind,
            ErrorKind::Password
        );
        let plain = plain_pkcs8_pem(&k).unwrap();
        assert_eq!(
            open_key_file(plain.as_bytes(), &Secret::new("x"))
                .unwrap_err()
                .kind,
            ErrorKind::Policy
        );
        assert!(encrypted_pkcs8_pem(&k, &Secret::new(""), &mut Rand::Os).is_err());
    }

    #[test]
    fn seeded_rsa_is_deterministic_and_valid() {
        let a = seeded_rsa(&mut Rand::lab(7, "k"), 1024).unwrap();
        let b = seeded_rsa(&mut Rand::lab(7, "k"), 1024).unwrap();
        assert_eq!(
            a.private_key_to_pkcs8().unwrap(),
            b.private_key_to_pkcs8().unwrap()
        );
        assert_eq!(a.bits(), 1024);
        assert!(a.rsa().unwrap().check_key().unwrap());
        let c = seeded_rsa(&mut Rand::lab(8, "k"), 1024).unwrap();
        assert!(!a.public_eq(&c));
    }

    #[test]
    fn pkcs12_kdf_matches_the_rfc_7292_reference_shape() {
        // Cross-check: a PKCS#12 written here opens with OpenSSL and with p12-keystore (rv-hashinv's reader).
        let k = seeded_rsa(&mut Rand::lab(1, "p12"), 2048).unwrap();
        let mut b = openssl::x509::X509Builder::new().unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "p12 test").unwrap();
        let name = name.build();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&k).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&k, MessageDigest::sha256()).unwrap();
        let cert = b.build().to_der().unwrap();
        let pw = Secret::new("pässword");
        let p12 = pkcs12(
            &k,
            std::slice::from_ref(&cert),
            "p12 test",
            &pw,
            &mut Rand::lab(1, "s"),
        )
        .unwrap();
        let again = pkcs12(
            &k,
            std::slice::from_ref(&cert),
            "p12 test",
            &pw,
            &mut Rand::lab(1, "s"),
        )
        .unwrap();
        assert_eq!(p12, again, "seeded PKCS#12 must be byte-identical");
        let parsed = openssl::pkcs12::Pkcs12::from_der(&p12)
            .unwrap()
            .parse2("pässword")
            .unwrap();
        assert!(parsed.pkey.unwrap().public_eq(&k));
        assert_eq!(parsed.cert.unwrap().to_der().unwrap(), cert);
        assert!(
            openssl::pkcs12::Pkcs12::from_der(&p12)
                .unwrap()
                .parse2("bad")
                .is_err()
        );
        let ks = p12_keystore::KeyStore::from_pkcs12(
            &p12,
            "pässword",
            p12_keystore::Pkcs12ImportPolicy::Relaxed,
        )
        .unwrap();
        let (_, chain) = ks
            .private_key_chain()
            .expect("key paired with its certificate");
        assert_eq!(chain.certs()[0].as_der(), &cert[..]);
        assert_eq!(chain.key().as_der(), &k.private_key_to_pkcs8().unwrap()[..]);
    }
}
