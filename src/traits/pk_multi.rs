use bls12_381_plus::elliptic_curve::Group;
use crate::*;

/// A trait that defines the BLS schemes that support multi-signatures
pub trait BlsMultiKey: BlsSignatureCore {
    /// Merges multiple public keys into one
    fn from_public_keys<B: AsRef<[Self::PublicKey]>>(keys: B) -> Self::PublicKey {
        let mut g = Self::PublicKey::identity();
        for key in keys.as_ref() {
            g += key;
        }
        g
    }
}