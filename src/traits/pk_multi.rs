use crate::*;
use crate::impls::inner_types::*;

/// A trait that defines the BLS schemes that support multi-signatures
pub trait BlsMultiKey: BlsSignatureCore {
    /// Merges multiple public keys into one
    fn from_public_keys<I: Iterator<Item = Self::PublicKey>>(keys: I) -> Self::PublicKey {
        let mut g = Self::PublicKey::identity();
        for key in keys {
            g += key;
        }
        g
    }
}
