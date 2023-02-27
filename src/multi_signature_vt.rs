use crate::{MultiPublicKeyVt, PublicKeyVt, SignatureVt};
use bls12_381_plus::{G2Affine, G2Projective};
use group::Curve;
use subtle::{Choice, CtOption};

/// Represents a BLS SignatureVt in G1 for multiple SignatureVts that signed the same message
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MultiSignatureVt(pub G2Projective);

display_one_impl!(MultiSignatureVt);

impl From<&[SignatureVt]> for MultiSignatureVt {
    fn from(sigs: &[SignatureVt]) -> Self {
        let mut g = G2Projective::IDENTITY;
        for s in sigs {
            g += s.0;
        }
        Self(g)
    }
}

serde_impl!(MultiSignatureVt, G2Projective);

cond_select_impl!(MultiSignatureVt, G2Projective);

impl MultiSignatureVt {
    /// Number of bytes needed to represent the SignatureVt
    pub const BYTES: usize = 96;

    validity_checks!();

    bytes_impl!(G2Affine, G2Projective);

    /// Verify this multi SignatureVt is over `msg` with the multi public key
    pub fn verify<B: AsRef<[u8]>>(&self, public_key: MultiPublicKeyVt, msg: B) -> Choice {
        SignatureVt(self.0).verify(PublicKeyVt(public_key.0), msg)
    }
}
