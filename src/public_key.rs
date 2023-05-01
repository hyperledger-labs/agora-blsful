use crate::*;
use bls12_381_plus::{group::Curve, G1Projective, G2Affine, G2Projective};
use subtle::{Choice, CtOption};

/// A BLS public key
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicKey(pub G2Projective);

display_one_impl!(PublicKey);

impl From<&SecretKey> for PublicKey {
    fn from(s: &SecretKey) -> Self {
        Self(G2Projective::GENERATOR * s.0)
    }
}

impl From<PublicKey> for [u8; PublicKey::BYTES] {
    fn from(pk: PublicKey) -> Self {
        pk.to_bytes()
    }
}

impl<'a> From<&'a PublicKey> for [u8; PublicKey::BYTES] {
    fn from(pk: &'a PublicKey) -> [u8; PublicKey::BYTES] {
        pk.to_bytes()
    }
}

serde_impl!(PublicKey, G2Projective);

cond_select_impl!(PublicKey, G2Projective);

impl PublicKey {
    /// Number of bytes needed to represent the public key
    pub const BYTES: usize = G2Projective::COMPRESSED_BYTES;

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);

    #[cfg(any(features = "alloc", feature = "std"))]
    /// Signcryption as described in
    /// <https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf>
    pub fn sign_crypt<B: AsRef<[u8]>>(&self, msg: B) -> Ciphertext<G2Projective, G1Projective> {
        let (u, v, w) = SignCryptorG2::seal(self.0, msg.as_ref());
        Ciphertext { u, v, w }
    }
}
