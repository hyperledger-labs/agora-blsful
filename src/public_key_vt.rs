use crate::*;
use bls12_381_plus::{group::Curve, G1Affine, G1Projective, G2Projective};
use subtle::{Choice, CtOption};

/// A BLS public key
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicKeyVt(pub G1Projective);

display_one_impl!(PublicKeyVt);

impl From<&SecretKey> for PublicKeyVt {
    fn from(s: &SecretKey) -> Self {
        Self(G1Projective::GENERATOR * s.0)
    }
}

impl From<PublicKeyVt> for [u8; PublicKeyVt::BYTES] {
    fn from(pk: PublicKeyVt) -> Self {
        pk.to_bytes()
    }
}

impl<'a> From<&'a PublicKeyVt> for [u8; PublicKeyVt::BYTES] {
    fn from(pk: &'a PublicKeyVt) -> [u8; PublicKeyVt::BYTES] {
        pk.to_bytes()
    }
}

serde_impl!(PublicKeyVt, G1Projective);

cond_select_impl!(PublicKeyVt, G1Projective);

impl PublicKeyVt {
    /// Number of bytes needed to represent the public key
    pub const BYTES: usize = G1Projective::COMPRESSED_BYTES;

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);

    #[cfg(any(features = "alloc", feature = "std"))]
    /// Signcryption as described in
    /// <https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf>
    pub fn sign_crypt<B: AsRef<[u8]>>(&self, msg: B) -> Ciphertext<G1Projective, G2Projective> {
        let (u, v, w) = SignCryptorG1::seal(self.0, msg.as_ref());
        Ciphertext { u, v, w }
    }
}
