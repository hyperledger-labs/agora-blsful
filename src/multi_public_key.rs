use crate::PublicKey;
use bls12_381_plus::{group::Curve, G2Affine, G2Projective};
use subtle::{Choice, CtOption};

/// Represents multiple public keys into one that can be used to verify multisignatures
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MultiPublicKey(pub G2Projective);

impl From<&[PublicKey]> for MultiPublicKey {
    fn from(keys: &[PublicKey]) -> Self {
        let mut g = G2Projective::IDENTITY;
        for k in keys {
            g += k.0;
        }
        Self(g)
    }
}

display_one_impl!(MultiPublicKey);

serde_impl!(MultiPublicKey, G2Projective);

cond_select_impl!(MultiPublicKey, G2Projective);

impl MultiPublicKey {
    /// Number of bytes needed to represent the multi public key
    pub const BYTES: usize = G2Projective::COMPRESSED_BYTES;

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);
}
