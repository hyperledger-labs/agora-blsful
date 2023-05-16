use crate::*;
use bls12_381_plus::elliptic_curve::Group;

/// Represents a BLS signature for multiple signatures that signed different messages
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MultiSignature<
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
    > Default for MultiSignature<C>
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
    > core::fmt::Display for MultiSignature<C>
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
    > core::fmt::Debug for MultiSignature<C>
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
    > Copy for MultiSignature<C>
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
    > Clone for MultiSignature<C>
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
    > subtle::ConditionallySelectable for MultiSignature<C>
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
    > TryFrom<&[Signature<C>]> for MultiSignature<C>
{
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

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > MultiSignature<C>
{
    /// Verify the multi-signature using the multi-public key
    pub fn verify<B: AsRef<[u8]>>(&self, pk: MultiPublicKey<C>, msg: B) -> BlsResult<()> {
        match self {
            Self::Basic(sig) => <C as BlsSignatureBasic>::verify(pk.0, *sig, msg),
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::verify(pk.0, *sig, msg)
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::verify(pk.0, *sig, msg),
        }
    }

    /// Extract the inner raw representation
    pub fn as_raw_value(&self) -> &<C as Pairing>::Signature {
        match self {
            Self::Basic(s) => s,
            Self::MessageAugmentation(s) => s,
            Self::ProofOfPossession(s) => s,
        }
    }
}
