use crate::PublicKeyVt;
use bls12_381_plus::{G1Affine, G1Projective, group::Curve};
use subtle::{Choice, CtOption};

/// Represents multiple public keys into one that can be used to verify multisignatures
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MultiPublicKeyVt(pub G1Projective);

impl From<&[PublicKeyVt]> for MultiPublicKeyVt {
    fn from(keys: &[PublicKeyVt]) -> Self {
        let mut g = G1Projective::IDENTITY;
        for k in keys {
            g += k.0;
        }
        Self(g)
    }
}

display_one_impl!(MultiPublicKeyVt);

serde_impl!(MultiPublicKeyVt, G1Projective);

cond_select_impl!(MultiPublicKeyVt, G1Projective);

impl MultiPublicKeyVt {
    /// Number of bytes needed to represent the multi public key
    pub const BYTES: usize = 48;

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);
}
