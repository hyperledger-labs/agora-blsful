use super::SecretKey;
use bls12_381_plus::{G1Affine, G1Projective, group::Curve};
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
    pub const BYTES: usize = 48;

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);
}
