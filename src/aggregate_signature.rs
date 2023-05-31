use crate::impls::inner_types::*;
use crate::*;

/// Represents a BLS signature for multiple signatures that signed different messages
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AggregateSignature<C: BlsSignatureImpl> {
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

impl<C: BlsSignatureImpl> Default for AggregateSignature<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureImpl> core::fmt::Display for AggregateSignature<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
        }
    }
}

impl<C: BlsSignatureImpl> core::fmt::Debug for AggregateSignature<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({:?})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
        }
    }
}

impl<C: BlsSignatureImpl> Copy for AggregateSignature<C> {}

impl<C: BlsSignatureImpl> Clone for AggregateSignature<C> {
    fn clone(&self) -> Self {
        match self {
            Self::Basic(s) => Self::Basic(*s),
            Self::MessageAugmentation(s) => Self::MessageAugmentation(*s),
            Self::ProofOfPossession(s) => Self::ProofOfPossession(*s),
        }
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for AggregateSignature<C> {
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

impl<C: BlsSignatureImpl> TryFrom<&[Signature<C>]> for AggregateSignature<C> {
    type Error = BlsError;

    fn try_from(sigs: &[Signature<C>]) -> Result<Self, Self::Error> {
        let mut g = <C as Pairing>::Signature::identity();
        for s in &sigs[1..] {
            if !s.same_scheme(&sigs[0]) {
                return Err(BlsError::InvalidSignatureScheme);
            }
            let ss = match s {
                Signature::Basic(sig) => sig,
                Signature::MessageAugmentation(sig) => sig,
                Signature::ProofOfPossession(sig) => sig,
            };
            g += ss;
        }
        match sigs[0] {
            Signature::Basic(s) => Ok(Self::Basic(g + s)),
            Signature::MessageAugmentation(s) => Ok(Self::MessageAugmentation(g + s)),
            Signature::ProofOfPossession(s) => Ok(Self::ProofOfPossession(g + s)),
        }
    }
}

impl<C: BlsSignatureImpl> AggregateSignature<C> {
    /// Accumulate multiple signatures into a single signature
    /// Verify fails if any signed message is a duplicate
    pub fn from_signatures<B: AsRef<[Signature<C>]>>(signatures: B) -> BlsResult<Self> {
        Self::try_from(signatures.as_ref())
    }

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
