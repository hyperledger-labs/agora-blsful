use bls12_381_plus::elliptic_curve::group::{Group, GroupEncoding};
use core::fmt::Display;
use serde::de::DeserializeOwned;
use serde::Serialize;
use subtle::ConditionallySelectable;
use vsss_rs::Share;

/// Operations that support pairing trait
pub trait Pairing {
    /// The secret key share
    type SecretKeyShare: Share<Identifier = u8> + core::fmt::Debug;
    /// The public key group
    type PublicKey: Group + GroupEncoding + Default + Display + ConditionallySelectable;
    /// The public key share
    type PublicKeyShare: Share<Identifier = u8>
        + Copy
        + Display
        + core::fmt::Debug
        + ConditionallySelectable
        + Serialize
        + DeserializeOwned;
    /// The signature group
    type Signature: Group<Scalar = <Self::PublicKey as Group>::Scalar>
        + GroupEncoding
        + Default
        + Display
        + ConditionallySelectable;
    /// The signature share
    type SignatureShare: Share<Identifier = u8>
        + Copy
        + Display
        + core::fmt::Debug
        + ConditionallySelectable
        + Serialize
        + DeserializeOwned;
    /// The target group from a pairing computation
    type PairingResult: Group + GroupEncoding + Default + Display + ConditionallySelectable;
    /// Compute the pairing based on supplied points
    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult;
}
