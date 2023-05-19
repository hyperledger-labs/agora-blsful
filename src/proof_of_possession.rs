use crate::*;
use subtle::{Choice, ConditionallySelectable};

/// A proof of possession of the secret key
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofOfPossession<C: BlsSignatureImpl>(
    /// The BLS proof of possession raw value
    #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
    pub <C as Pairing>::Signature,
);

impl<C: BlsSignatureImpl> Default for ProofOfPossession<C> {
    fn default() -> Self {
        Self(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureImpl> core::fmt::Display for ProofOfPossession<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<C: BlsSignatureImpl> core::fmt::Debug for ProofOfPossession<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProofOfPossession{{ {:?} }}", self.0)
    }
}

impl<C: BlsSignatureImpl> Copy for ProofOfPossession<C> {}

impl<C: BlsSignatureImpl> Clone for ProofOfPossession<C> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<C: BlsSignatureImpl> ConditionallySelectable for ProofOfPossession<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::Signature::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<C: BlsSignatureImpl> ProofOfPossession<C> {
    /// Verify this proof of possession
    pub fn verify(&self, pk: PublicKey<C>) -> BlsResult<()> {
        <C as BlsSignaturePop>::pop_verify(pk.0, self.0)
    }
}
