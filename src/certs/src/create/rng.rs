//! OWNER: B. Randomness: the OS CSPRNG through OpenSSL for real CAs, or a seeded ChaCha20 stream for lab sets.
//!
//! LAB ONLY: [`Rand::lab`] derives every stream from `(seed, label)` with SHA-256, so a lab set is reproducible
//! byte for byte. Seeded salts, IVs, serials and keys are public by construction; never use them for a real key.

use crate::model::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

pub enum Rand {
    /// OpenSSL `RAND_bytes` (the operating system's CSPRNG behind OpenSSL's DRBG).
    Os,
    /// ChaCha20 seeded from SHA-256("rakvor.lab-set/1|<seed>|<label>"). Lab sets only.
    Seeded(Box<ChaCha20Rng>),
}

impl Rand {
    /// The seeded stream for one labelled object of a lab set (each key / serial / salt has its own label, so adding a
    /// case never changes the bytes of the other cases).
    pub fn lab(seed: u64, label: &str) -> Rand {
        let h = openssl::sha::sha256(format!("rakvor.lab-set/1|{seed}|{label}").as_bytes());
        Rand::Seeded(Box::new(ChaCha20Rng::from_seed(h)))
    }

    pub fn fill(&mut self, buf: &mut [u8]) -> CertResult<()> {
        match self {
            Rand::Os => openssl::rand::rand_bytes(buf)
                .map_err(|e| CertError::new(ErrorKind::Crypto, format!("random generator: {e}"))),
            Rand::Seeded(r) => {
                r.fill_bytes(buf);
                Ok(())
            }
        }
    }

    pub fn bytes(&mut self, n: usize) -> CertResult<Vec<u8>> {
        let mut v = vec![0u8; n];
        self.fill(&mut v)?;
        Ok(v)
    }

    /// A positive 128-bit serial (16 octets, top bit clear, first octet non-zero): 127 random bits.
    pub fn serial(&mut self) -> CertResult<Vec<u8>> {
        let mut s = self.bytes(16)?;
        s[0] &= 0x7f;
        if s[0] == 0 {
            s[0] = 0x01;
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_streams_are_reproducible_and_independent() {
        let a = Rand::lab(1, "root").bytes(32).unwrap();
        assert_eq!(a, Rand::lab(1, "root").bytes(32).unwrap());
        assert_ne!(a, Rand::lab(2, "root").bytes(32).unwrap());
        assert_ne!(a, Rand::lab(1, "leaf").bytes(32).unwrap());
        for _ in 0..64 {
            let s = Rand::Os.serial().unwrap();
            assert_eq!(s.len(), 16);
            assert!(s[0] != 0 && s[0] < 0x80);
        }
    }
}
