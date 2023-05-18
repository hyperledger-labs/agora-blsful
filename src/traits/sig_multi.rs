use bls12_381_plus::elliptic_curve::Group;
use crate::*;

/// A trait that defines the BLS schemes that support multi-signatures
pub trait BlsMultiSignature: BlsSignatureCore {
    /// Merges multiple signatures into one
    fn from_signatures<B: AsRef<[Self::Signature]>>(signatures: B) -> Self::Signature {
        let mut g = Self::Signature::identity();
        for sig in signatures.as_ref() {
            g += sig;
        }
        g
    }
}