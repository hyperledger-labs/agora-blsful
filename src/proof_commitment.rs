use crate::*;
use bls12_381_plus::elliptic_curve::{Group, PrimeField};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use subtle::CtOption;

/// The commitment portion of the signature proof of knowledge
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProofCommitment<C: BlsSignatureImpl> {
    /// The basic signature scheme
    Basic(
        /// The commitment
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The message augmentation signature scheme
    MessageAugmentation(
        /// The commitment
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
    /// The proof of possession signature scheme
    ProofOfPossession(
        /// The commitment
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        <C as Pairing>::Signature,
    ),
}

impl<C: BlsSignatureImpl> Default for ProofCommitment<C> {
    fn default() -> Self {
        Self::ProofOfPossession(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureImpl> core::fmt::Display for ProofCommitment<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({})", s),
        }
    }
}

impl<C: BlsSignatureImpl> core::fmt::Debug for ProofCommitment<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Basic(s) => write!(f, "Basic({:?})", s),
            Self::MessageAugmentation(s) => write!(f, "MessageAugmentation({:?})", s),
            Self::ProofOfPossession(s) => write!(f, "ProofOfPossession({:?})", s),
        }
    }
}

impl<C: BlsSignatureImpl> Copy for ProofCommitment<C> {}

impl<C: BlsSignatureImpl> Clone for ProofCommitment<C> {
    fn clone(&self) -> Self {
        match self {
            Self::Basic(s) => Self::Basic(*s),
            Self::MessageAugmentation(s) => Self::MessageAugmentation(*s),
            Self::ProofOfPossession(s) => Self::ProofOfPossession(*s),
        }
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for ProofCommitment<C> {
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
            _ => panic!("Cannot conditional select between different proof commitments"),
        }
    }
}

impl<C: BlsSignatureImpl> ProofCommitment<C> {
    /// Generate a new proof of knowledge commitment
    /// This is step 1 in the 3 step process
    pub fn generate<B: AsRef<[u8]>>(
        msg: B,
        signature: Signature<C>,
    ) -> BlsResult<(Self, ProofCommitmentSecret<C>)> {
        match signature {
            Signature::Basic(_) => {
                let (u, x) = <C as BlsSignatureProof>::generate_commitment(
                    msg,
                    <C as BlsSignatureBasic>::DST,
                )?;
                Ok((Self::Basic(u), ProofCommitmentSecret(x)))
            }
            Signature::MessageAugmentation(_) => {
                let (u, x) = <C as BlsSignatureProof>::generate_commitment(
                    msg,
                    <C as BlsSignatureMessageAugmentation>::DST,
                )?;
                Ok((Self::MessageAugmentation(u), ProofCommitmentSecret(x)))
            }
            Signature::ProofOfPossession(_) => {
                let (u, x) = <C as BlsSignatureProof>::generate_commitment(
                    msg,
                    <C as BlsSignaturePop>::SIG_DST,
                )?;
                Ok((Self::ProofOfPossession(u), ProofCommitmentSecret(x)))
            }
        }
    }

    /// Finish the commitment value by converting it into a proof of knowledge
    /// Step 3 in the 3 step process
    pub fn finalize(
        self,
        x: ProofCommitmentSecret<C>,
        y: ProofCommitmentChallenge<C>,
        sig: Signature<C>,
    ) -> BlsResult<ProofOfKnowledge<C>> {
        match (self, sig) {
            (Self::Basic(u), Signature::Basic(s)) => {
                let (u, v) = <C as BlsSignatureProof>::generate_proof(u, x.0, y.0, s)?;
                Ok(ProofOfKnowledge::Basic { u, v })
            }
            (Self::MessageAugmentation(u), Signature::MessageAugmentation(s)) => {
                let (u, v) = <C as BlsSignatureProof>::generate_proof(u, x.0, y.0, s)?;
                Ok(ProofOfKnowledge::MessageAugmentation { u, v })
            }
            (Self::ProofOfPossession(u), Signature::ProofOfPossession(s)) => {
                let (u, v) = <C as BlsSignatureProof>::generate_proof(u, x.0, y.0, s)?;
                Ok(ProofOfKnowledge::ProofOfPossession { u, v })
            }
            (_, _) => Err(BlsError::InvalidProof),
        }
    }
}

/// A commitment secret used to create the proof of knowledge
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ProofCommitmentSecret<C: BlsSignatureImpl>(
    /// The commitment secret raw value
    #[serde(serialize_with = "traits::scalar::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::scalar::deserialize::<C, _>")]
    pub <<C as Pairing>::PublicKey as Group>::Scalar,
);

impl<C: BlsSignatureImpl> ProofCommitmentSecret<C> {
    /// Get the byte representation of this key
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        let mut bytes = self.0.to_repr();
        let ptr = bytes.as_mut();
        // Make big endian
        ptr.reverse();
        <[u8; SECRET_KEY_BYTES]>::try_from(ptr).unwrap()
    }

    /// Convert a big-endian representation of the secret key.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        let mut repr =
            <<<C as Pairing>::PublicKey as Group>::Scalar as PrimeField>::Repr::default();
        let t = repr.as_mut();
        t.copy_from_slice(bytes);
        t.reverse();
        <<C as Pairing>::PublicKey as Group>::Scalar::from_repr(repr).map(Self)
    }
}

/// The proof of knowledge challenge value generated by the server in
/// step 2 of the proof generation process
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct ProofCommitmentChallenge<C: BlsSignatureImpl>(
    /// The commitment challenge raw value
    #[serde(serialize_with = "traits::scalar::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::scalar::deserialize::<C, _>")]
    pub <<C as Pairing>::PublicKey as Group>::Scalar,
);

impl<C: BlsSignatureImpl> ProofCommitmentChallenge<C> {
    /// Create a new random secret key
    pub fn new() -> Self {
        Self::random(get_crypto_rng())
    }

    /// Compute a secret key from a hash
    pub fn from_hash<B: AsRef<[u8]>>(data: B) -> Self {
        Self(<C as HashToScalar>::hash_to_scalar(
            data.as_ref(),
            KEYGEN_SALT,
        ))
    }

    /// Compute a random challenge from a CS-PRNG
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Self(<C as HashToScalar>::hash_to_scalar(
            rng.gen::<[u8; SECRET_KEY_BYTES]>(),
            KEYGEN_SALT,
        ))
    }

    /// Get the byte representation of this key
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        let mut bytes = self.0.to_repr();
        let ptr = bytes.as_mut();
        // Make big endian
        ptr.reverse();
        <[u8; SECRET_KEY_BYTES]>::try_from(ptr).unwrap()
    }

    /// Convert a big-endian representation of the secret key.
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        let mut repr =
            <<<C as Pairing>::PublicKey as Group>::Scalar as PrimeField>::Repr::default();
        let t = repr.as_mut();
        t.copy_from_slice(bytes);
        t.reverse();
        <<C as Pairing>::PublicKey as Group>::Scalar::from_repr(repr).map(Self)
    }
}
