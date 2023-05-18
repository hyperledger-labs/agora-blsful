use crate::*;
use bls12_381_plus::elliptic_curve::Group;

/// A trait that defines the BLS schemes that support multi-signatures
pub trait BlsMultiSignature: BlsSignatureCore {
    /// Merges multiple signatures into one
    fn from_signatures<I: Iterator<Item = Self::Signature>>(signatures: I) -> Self::Signature {
        let mut g = Self::Signature::identity();
        for sig in signatures {
            g += sig;
        }
        g
    }
}
