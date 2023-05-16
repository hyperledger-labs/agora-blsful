use crate::*;

/// Represents a BLS signature for multiple signatures that signed different messages
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AggregateSignature<
    C: BlsSignatureBasic
        + BlsSignatureMessageAugmentation
        + BlsSignaturePop
        + BlsSignCrypt
        + BlsTimeCrypt
        + BlsSignatureProof
        + BlsSerde,
> {
    /// The basic signature scheme
    Basic(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The message augmentation signature scheme
    MessageAugmentation(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The proof of possession scheme
    ProofOfPossession(
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Default for AggregateSignature<C>
{
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > core::fmt::Display for AggregateSignature<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
        }
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > core::fmt::Debug for AggregateSignature<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({:?})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
        }
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Copy for AggregateSignature<C>
{
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Clone for AggregateSignature<C>
{
    fn clone(&self) -> Self {
        match self {
            Self::Basic(s) => Self::Basic(*s),
            Self::MessageAugmentation(s) => Self::MessageAugmentation(*s),
            Self::ProofOfPossession(s) => Self::ProofOfPossession(*s),
        }
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > subtle::ConditionallySelectable for AggregateSignature<C>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        match (a, b) {
            (Self::Basic(a), Self::Basic(b)) => {
                Self::Basic(<C as Pairing>::Signature::conditional_select(a, b, choice))
            }
            (Self::MessageAugmentation(a), Self::MessageAugmentation(b)) => {
                Self::MessageAugmentation(<C as Pairing>::Signature::conditional_select(
                    a, b, choice,
                ))
            }
            (Self::ProofOfPossession(a), Self::ProofOfPossession(b)) => {
                Self::ProofOfPossession(<C as Pairing>::Signature::conditional_select(a, b, choice))
            }
            _ => panic!("Signature::conditional_select: mismatched variants"),
        }
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > AggregateSignature<C>
{
    /// Verify the aggregated signature using the public keys
    pub fn verify<B: AsRef<[u8]>>(&self, data: &[(PublicKey<C>, B)]) -> BlsResult<()> {
        let ii = data.iter().map(|(pk, m)| (pk.0, m));
        match self {
            Self::Basic(sig) => <C as BlsSignatureBasic>::aggregate_verify(ii, *sig),
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::aggregate_verify(ii, *sig)
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::aggregate_verify(ii, *sig),
        }
    }
}
