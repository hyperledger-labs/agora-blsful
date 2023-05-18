use crate::*;
use subtle::ConditionallySelectable;

/// A BLS signature wrapped in the appropriate scheme used to generate it
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Signature<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> {
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

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Default
    for Signature<C>
{
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> core::fmt::Display
    for Signature<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
        }
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> core::fmt::Debug
    for Signature<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({:?})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
        }
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Copy
    for Signature<C>
{
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Clone
    for Signature<C>
{
    fn clone(&self) -> Self {
        match self {
            Self::Basic(s) => Self::Basic(*s),
            Self::MessageAugmentation(s) => Self::MessageAugmentation(*s),
            Self::ProofOfPossession(s) => Self::ProofOfPossession(*s),
        }
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    ConditionallySelectable for Signature<C>
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

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Signature<C> {
    /// Verify the signature using the public key
    pub fn verify<B: AsRef<[u8]>>(&self, pk: &PublicKey<C>, msg: B) -> BlsResult<()> {
        match self {
            Self::Basic(sig) => <C as BlsSignatureBasic>::verify(pk.0, *sig, msg),
            Self::MessageAugmentation(sig) => {
                <C as BlsSignatureMessageAugmentation>::verify(pk.0, *sig, msg)
            }
            Self::ProofOfPossession(sig) => <C as BlsSignaturePop>::verify(pk.0, *sig, msg),
        }
    }

    /// Determine if two signature were signed using the same scheme
    pub fn same_scheme(&self, &other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::Basic(_), Self::Basic(_))
                | (Self::MessageAugmentation(_), Self::MessageAugmentation(_))
                | (Self::ProofOfPossession(_), Self::ProofOfPossession(_))
        )
    }

    /// Create a signature from shares
    pub fn from_shares(shares: &[SignatureShare<C>]) -> BlsResult<Self> {
        if !shares.iter().skip(1).all(|s| s.same_scheme(&shares[0])) {
            return Err(BlsError::InvalidSignatureScheme);
        }
        let points = shares
            .iter()
            .map(|s| *s.as_raw_value())
            .collect::<Vec<<C as Pairing>::SignatureShare>>();
        let sig = <C as BlsSignatureCore>::core_combine_signature_shares(&points)?;
        match shares[0] {
            SignatureShare::Basic(_) => Ok(Self::Basic(sig)),
            SignatureShare::MessageAugmentation(_) => Ok(Self::MessageAugmentation(sig)),
            SignatureShare::ProofOfPossession(_) => Ok(Self::ProofOfPossession(sig)),
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
