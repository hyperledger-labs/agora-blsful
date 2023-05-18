use crate::*;
use subtle::{Choice, ConditionallySelectable};

/// A proof of possession of the secret key
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofOfPossession<
    C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop,
>(
    /// The BLS proof of possession raw value
    #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
    pub <C as Pairing>::Signature,
);

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Default
    for ProofOfPossession<C>
{
    fn default() -> Self {
        Self(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> core::fmt::Display
    for ProofOfPossession<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> core::fmt::Debug
    for ProofOfPossession<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProofOfPossession{{ {:?} }}", self.0)
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Copy
    for ProofOfPossession<C>
{
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Clone
    for ProofOfPossession<C>
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    ConditionallySelectable for ProofOfPossession<C>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::Signature::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    ProofOfPossession<C>
{
    /// Verify this proof of possession
    pub fn verify(&self, pk: PublicKey<C>) -> BlsResult<()> {
        <C as BlsSignaturePop>::pop_verify(pk.0, self.0)
    }
}
