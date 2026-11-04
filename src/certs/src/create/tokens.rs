//! OWNER: B. PKCS#11 through cryptoki (SoftHSM2 in CI, YubiKey ykcs11 manually).
//!
//! - One `Pkcs11` context per module path for the life of the process (C_Initialize once; never C_Finalize while
//!   another session may use the module).
//! - Keys are generated on the token with CKA_TOKEN, CKA_PRIVATE, CKA_SENSITIVE and CKA_EXTRACTABLE = false, so
//!   the private key never leaves it. Signing uses mechanisms every vendor offers: CKM_RSA_PKCS over a DigestInfo
//!   computed here, CKM_ECDSA over a digest computed here (r||s converted to DER), CKM_EDDSA.
//! - The PIN only travels in [`Secret`] / cryptoki's `AuthPin` (zeroized), and is never stored or logged.

use super::derw::*;
use super::keys::{crypto, key_info};
use super::signer::{SigAlg, digest_info_prefix};
use crate::model::*;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// A logged-in session on one token. Internals are agent B's; the methods below are the frozen surface pki uses.
pub struct TokenSession {
    session: Session,
    pub(crate) module: String,
    pub(crate) token_serial: String,
    pub(crate) token_label: Option<String>,
}

impl std::fmt::Debug for TokenSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TokenSession {{ module: {:?}, token_serial: {:?} }}",
            self.module, self.token_serial
        )
    }
}

fn tok(what: &str) -> impl Fn(cryptoki::error::Error) -> CertError + '_ {
    move |e| {
        use cryptoki::error::{Error, RvError};
        let kind = match &e {
            Error::Pkcs11(
                RvError::PinIncorrect
                | RvError::PinInvalid
                | RvError::PinLenRange
                | RvError::PinLocked
                | RvError::PinExpired,
                _,
            ) => ErrorKind::Password,
            _ => ErrorKind::Token,
        };
        CertError::new(kind, format!("PKCS#11 {what}: {e}"))
    }
}

fn context(module: &Path) -> CertResult<Pkcs11> {
    static CTX: OnceLock<Mutex<HashMap<PathBuf, Pkcs11>>> = OnceLock::new();
    let map = CTX.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(p) = map.get(module) {
        return Ok(p.clone());
    }
    let p = Pkcs11::new(module).map_err(|e| {
        CertError::new(
            ErrorKind::Token,
            format!("cannot load PKCS#11 module {}: {e}", module.display()),
        )
    })?;
    match p.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => {}
        Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::CryptokiAlreadyInitialized,
            _,
        )) => {}
        Err(e) => return Err(tok("C_Initialize")(e)),
    }
    map.insert(module.to_path_buf(), p.clone());
    Ok(p)
}

fn find_slot(p: &Pkcs11, token_serial: &str) -> CertResult<(Slot, cryptoki::slot::TokenInfo)> {
    for s in p.get_slots_with_token().map_err(tok("C_GetSlotList"))? {
        if let Ok(ti) = p.get_token_info(s) {
            if ti.serial_number().trim() == token_serial.trim() {
                return Ok((s, ti));
            }
        }
    }
    Err(CertError::new(
        ErrorKind::Token,
        format!("no token with serial '{token_serial}' (tokens list shows the serials)"),
    ))
}

fn label_opt(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

pub fn list(module: &Path) -> CertResult<Vec<TokenInfo>> {
    let p = context(module)?;
    let mut out = vec![];
    for s in p.get_all_slots().map_err(tok("C_GetSlotList"))? {
        let si = p.get_slot_info(s).map_err(tok("C_GetSlotInfo"))?;
        let mut t = TokenInfo {
            slot_id: s.id(),
            slot_description: si.slot_description().trim().to_string(),
            token_present: si.token_present(),
            ..Default::default()
        };
        if si.token_present() {
            if let Ok(ti) = p.get_token_info(s) {
                t.label = label_opt(ti.label());
                t.manufacturer = label_opt(ti.manufacturer_id());
                t.model = label_opt(ti.model());
                t.serial = label_opt(ti.serial_number());
                t.login_required = ti.login_required();
            }
        }
        out.push(t);
    }
    Ok(out)
}

pub fn open(module: &Path, token_serial: &str, pin: &Secret) -> CertResult<TokenSession> {
    let p = context(module)?;
    let (slot, ti) = find_slot(&p, token_serial)?;
    let session = p.open_rw_session(slot).map_err(tok("C_OpenSession"))?;
    let auth = AuthPin::from(pin.expose().to_string());
    match session.login(UserType::User, Some(&auth)) {
        Ok(()) => {}
        Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => return Err(tok("C_Login")(e)),
    }
    Ok(TokenSession {
        session,
        module: module.display().to_string(),
        token_serial: ti.serial_number().trim().to_string(),
        token_label: label_opt(ti.label()),
    })
}

fn hex_decode(s: &str) -> CertResult<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            format!("key id '{s}' is not hex"),
        ));
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect())
}

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_ED25519: &str = "1.3.101.112";

impl TokenSession {
    fn find_one(&self, class: ObjectClass, id: &[u8]) -> CertResult<ObjectHandle> {
        let found = self
            .session
            .find_objects(&[Attribute::Class(class), Attribute::Id(id.to_vec())])
            .map_err(tok("C_FindObjects"))?;
        found.into_iter().next().ok_or_else(|| {
            CertError::new(
                ErrorKind::Token,
                format!("no {class} object with key id {} on the token", hex(id)),
            )
        })
    }

    fn spki_of(&self, pubkey: ObjectHandle) -> CertResult<Vec<u8>> {
        let attrs = self
            .session
            .get_attributes(
                pubkey,
                &[
                    AttributeType::KeyType,
                    AttributeType::Modulus,
                    AttributeType::PublicExponent,
                    AttributeType::EcParams,
                    AttributeType::EcPoint,
                ],
            )
            .map_err(tok("C_GetAttributeValue"))?;
        let (mut kt, mut n, mut e, mut params, mut point) = (None, None, None, None, None);
        for a in attrs {
            match a {
                Attribute::KeyType(k) => kt = Some(k),
                Attribute::Modulus(v) => n = Some(v),
                Attribute::PublicExponent(v) => e = Some(v),
                Attribute::EcParams(v) => params = Some(v),
                Attribute::EcPoint(v) => point = Some(v),
                _ => {}
            }
        }
        let c = crypto("token public key");
        match kt {
            Some(KeyType::RSA) => {
                let (n, e) = (n.unwrap_or_default(), e.unwrap_or_default());
                let rsa = openssl::rsa::Rsa::from_public_components(
                    openssl::bn::BigNum::from_slice(&n).map_err(&c)?,
                    openssl::bn::BigNum::from_slice(&e).map_err(&c)?,
                )
                .map_err(&c)?;
                openssl::pkey::PKey::from_rsa(rsa)
                    .map_err(&c)?
                    .public_key_to_der()
                    .map_err(&c)
            }
            Some(KeyType::EC) => {
                let params = params.unwrap_or_default();
                let alg = seq(&[oid(OID_EC_PUBLIC_KEY), params]);
                first_valid_spki(&alg, &point.unwrap_or_default())
            }
            Some(KeyType::EC_EDWARDS) => {
                first_valid_spki(&alg_absent(OID_ED25519), &point.unwrap_or_default())
            }
            other => Err(CertError::new(
                ErrorKind::Unsupported,
                format!("token key type {other:?} is not supported"),
            )),
        }
    }

    /// Key pairs on the token (public facts only).
    pub fn keys(&self) -> CertResult<Vec<TokenKeyInfo>> {
        let pubs = self
            .session
            .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)])
            .map_err(tok("C_FindObjects"))?;
        let mut out = vec![];
        for h in pubs {
            let attrs = self
                .session
                .get_attributes(h, &[AttributeType::Id, AttributeType::Label])
                .map_err(tok("C_GetAttributeValue"))?;
            let (mut id, mut label) = (vec![], None);
            for a in attrs {
                match a {
                    Attribute::Id(v) => id = v,
                    Attribute::Label(v) => label = label_opt(&String::from_utf8_lossy(&v)),
                    _ => {}
                }
            }
            let Ok(spki) = self.spki_of(h) else { continue };
            let certificate_subject = self
                .find_one(ObjectClass::CERTIFICATE, &id)
                .ok()
                .and_then(|c| self.session.get_attributes(c, &[AttributeType::Value]).ok())
                .and_then(|a| {
                    a.into_iter().find_map(|x| match x {
                        Attribute::Value(v) => Some(v),
                        _ => None,
                    })
                })
                .and_then(|der| openssl::x509::X509::from_der(&der).ok())
                .map(|x| super::pki::name_string(x.subject_name()));
            out.push(TokenKeyInfo {
                key_id_hex: hex(&id),
                label,
                key: key_info(&spki)?,
                certificate_subject,
            });
        }
        out.sort_by(|a, b| a.key_id_hex.cmp(&b.key_id_hex));
        Ok(out)
    }

    /// DER SubjectPublicKeyInfo of the key with this CKA_ID.
    pub fn public_key_der(&self, key_id_hex: &str) -> CertResult<Vec<u8>> {
        let id = hex_decode(key_id_hex)?;
        let h = self.find_one(ObjectClass::PUBLIC_KEY, &id)?;
        self.spki_of(h)
    }

    /// Signs `data` with the key (`scheme`: `rsa-pkcs1-sha256`, `rsa-pkcs1-sha384`, `ecdsa-sha256`,
    /// `ecdsa-sha384`, `ed25519`); returns the signature as X.509 expects it (ECDSA DER-encoded).
    pub fn sign(&self, key_id_hex: &str, scheme: &str, data: &[u8]) -> CertResult<Vec<u8>> {
        let id = hex_decode(key_id_hex)?;
        let key = self.find_one(ObjectClass::PRIVATE_KEY, &id)?;
        let c = crypto("digest");
        match scheme {
            "rsa-pkcs1-sha256" | "rsa-pkcs1-sha384" => {
                let (alg, md) = if scheme.ends_with("256") {
                    (SigAlg::RsaSha256, openssl::hash::MessageDigest::sha256())
                } else {
                    (SigAlg::RsaSha384, openssl::hash::MessageDigest::sha384())
                };
                let mut di = digest_info_prefix(alg).to_vec();
                di.extend_from_slice(&openssl::hash::hash(md, data).map_err(&c)?);
                self.session
                    .sign(&Mechanism::RsaPkcs, key, &di)
                    .map_err(tok("C_Sign"))
            }
            "ecdsa-sha256" | "ecdsa-sha384" => {
                let md = if scheme.ends_with("256") {
                    openssl::hash::MessageDigest::sha256()
                } else {
                    openssl::hash::MessageDigest::sha384()
                };
                let h = openssl::hash::hash(md, data).map_err(&c)?;
                let raw = self
                    .session
                    .sign(&Mechanism::Ecdsa, key, &h)
                    .map_err(tok("C_Sign"))?;
                let half = raw.len() / 2;
                let sig = openssl::ecdsa::EcdsaSig::from_private_components(
                    openssl::bn::BigNum::from_slice(&raw[..half]).map_err(&c)?,
                    openssl::bn::BigNum::from_slice(&raw[half..]).map_err(&c)?,
                )
                .map_err(&c)?;
                sig.to_der().map_err(&c)
            }
            "ed25519" => self
                .session
                .sign(
                    &Mechanism::Eddsa(cryptoki::mechanism::eddsa::EddsaParams::new(
                        cryptoki::mechanism::eddsa::EddsaSignatureScheme::Pure,
                    )),
                    key,
                    data,
                )
                .map_err(tok("C_Sign")),
            other => Err(CertError::new(
                ErrorKind::InvalidInput,
                format!(
                    "unknown signing scheme '{other}': use rsa-pkcs1-sha256, rsa-pkcs1-sha384, ecdsa-sha256, ecdsa-sha384 or ed25519"
                ),
            )),
        }
    }

    /// Generates a key pair on this token (see [`generate_key`]).
    pub(crate) fn generate(
        &self,
        spec: KeySpec,
        label: &str,
        confirm_root: bool,
    ) -> CertResult<KeyLocation> {
        let mut id = [0u8; 16];
        openssl::rand::rand_bytes(&mut id).map_err(crypto("random key id"))?;
        let label = if confirm_root {
            format!("{label} [root, --confirm-root]")
        } else {
            label.to_string()
        };
        let common_pub = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let common_priv = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let (mech, mut pub_t) = match spec {
            KeySpec::Rsa2048 | KeySpec::Rsa3072 | KeySpec::Rsa4096 => {
                // CK_ULONG is 32 bits on Windows and 64 on Linux: Ulong only converts from the platform's own
                // CK_ULONG or, portably, through TryFrom<usize> (2048..4096 always fits).
                let bits: usize = match spec {
                    KeySpec::Rsa2048 => 2048,
                    KeySpec::Rsa3072 => 3072,
                    _ => 4096,
                };
                (
                    Mechanism::RsaPkcsKeyPairGen,
                    vec![
                        Attribute::ModulusBits(
                            cryptoki::types::Ulong::try_from(bits).expect("RSA size fits CK_ULONG"),
                        ),
                        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
                    ],
                )
            }
            KeySpec::P256 => (
                Mechanism::EccKeyPairGen,
                vec![Attribute::EcParams(oid(OID_P256))],
            ),
            KeySpec::P384 => (
                Mechanism::EccKeyPairGen,
                vec![Attribute::EcParams(oid(OID_P384))],
            ),
            KeySpec::Ed25519 => (
                Mechanism::EccEdwardsKeyPairGen,
                vec![Attribute::EcParams(oid(OID_ED25519))],
            ),
        };
        pub_t.extend(common_pub);
        self.session
            .generate_key_pair(&mech, &pub_t, &common_priv)
            .map_err(tok("C_GenerateKeyPair"))?;
        Ok(KeyLocation::Pkcs11 {
            module: self.module.clone(),
            token_serial: self.token_serial.clone(),
            token_label: self.token_label.clone(),
            key_id_hex: hex(&id),
            key_label: Some(label),
        })
    }
}

/// CKA_EC_POINT is a DER OCTET STRING holding the point, but some modules return the raw point. Both readings are
/// tried and the one OpenSSL accepts as a public key wins (a raw point can look like a DER header by chance).
fn first_valid_spki(alg: &[u8], point: &[u8]) -> CertResult<Vec<u8>> {
    let unwrapped = unwrap_octet(point);
    for candidate in [&unwrapped[..], point] {
        let spki = seq(&[alg.to_vec(), bits(candidate)]);
        if openssl::pkey::PKey::public_key_from_der(&spki).is_ok() {
            return Ok(spki);
        }
    }
    Err(CertError::new(
        ErrorKind::Token,
        "the token's CKA_EC_POINT is not a valid public key",
    ))
}

/// CKA_EC_POINT is a DER OCTET STRING holding the point (some modules return the raw point).
fn unwrap_octet(v: &[u8]) -> Vec<u8> {
    if v.first() == Some(&0x04) && v.len() >= 2 {
        let inner = content_of(v);
        let hdr = v.len() - inner.len();
        if hdr >= 2 && inner.len() + hdr == v.len() && !inner.is_empty() {
            // An uncompressed point also starts with 0x04: only unwrap when the length header matches exactly.
            return inner.to_vec();
        }
    }
    v.to_vec()
}

pub fn generate_key(
    module: &Path,
    token_serial: &str,
    pin: &Secret,
    spec: KeySpec,
    label: &str,
    confirm_root: bool,
) -> CertResult<KeyLocation> {
    if label.trim().is_empty() {
        return Err(CertError::new(
            ErrorKind::InvalidInput,
            "a token key needs a label",
        ));
    }
    open(module, token_serial, pin)?.generate(spec, label, confirm_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_points_raw_or_wrapped() {
        let k = openssl::ec::EcKey::generate(
            &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let raw = k
            .public_key()
            .to_bytes(
                k.group(),
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();
        let alg = seq(&[oid(OID_EC_PUBLIC_KEY), oid(OID_P256)]);
        let want = openssl::pkey::PKey::from_ec_key(k)
            .unwrap()
            .public_key_to_der()
            .unwrap();
        assert_eq!(first_valid_spki(&alg, &octet(&raw)).unwrap(), want);
        assert_eq!(first_valid_spki(&alg, &raw).unwrap(), want);
    }

    /// Regression: a raw point (0x04 || X || Y) read as a TLV has a random "length" byte; when it looked like a
    /// long-form header the reader indexed past the end and panicked (seen with ~1 key in 3).
    #[test]
    fn ec_points_never_panic_for_many_random_keys() {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let alg = seq(&[oid(OID_EC_PUBLIC_KEY), oid(OID_P256)]);
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        for _ in 0..200 {
            let k = openssl::ec::EcKey::generate(&group).unwrap();
            let raw = k
                .public_key()
                .to_bytes(
                    &group,
                    openssl::ec::PointConversionForm::UNCOMPRESSED,
                    &mut ctx,
                )
                .unwrap();
            let want = openssl::pkey::PKey::from_ec_key(k)
                .unwrap()
                .public_key_to_der()
                .unwrap();
            assert_eq!(first_valid_spki(&alg, &raw).unwrap(), want);
            assert_eq!(first_valid_spki(&alg, &octet(&raw)).unwrap(), want);
        }
        assert!(super::super::derw::content_of(&[0x04, 0x85, 0x01]).is_empty());
        assert!(super::super::derw::content_of(&[0x30, 0x80]).is_empty());
    }
}
