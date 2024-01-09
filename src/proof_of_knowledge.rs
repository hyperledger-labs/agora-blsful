use crate::*;
use subtle::Choice;

/// A signature proof of knowledge
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProofOfKnowledge<C: BlsSignatureImpl> {
    /// The basic signature scheme
    Basic {
        /// The commitment value
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        u: <C as Pairing>::Signature,
        /// The proof
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        v: <C as Pairing>::Signature,
    },
    /// The message augmentation signature scheme
    MessageAugmentation {
        /// The commitment value
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        u: <C as Pairing>::Signature,
        /// The proof
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        v: <C as Pairing>::Signature,
    },
    /// The proof of possession signature scheme
    ProofOfPossession {
        /// The commitment value
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        u: <C as Pairing>::Signature,
        /// The proof
        #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
        #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
        v: <C as Pairing>::Signature,
    },
}

impl<C: BlsSignatureImpl> Default for ProofOfKnowledge<C> {
    fn default() -> Self {
        Self::ProofOfPossession {
            u: <C as Pairing>::Signature::default(),
            v: <C as Pairing>::Signature::default(),
        }
    }
}

impl<C: BlsSignatureImpl> core::fmt::Display for ProofOfKnowledge<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Basic { u, v } => write!(f, "Basic{{ u: {}, v: {} }}", u, v),
            Self::MessageAugmentation { u, v } => {
                write!(f, "MessageAugmentation{{ u: {}, v: {} }}", u, v)
            }
            Self::ProofOfPossession { u, v } => {
                write!(f, "ProofOfPossession{{ u: {}, v: {} }}", u, v)
            }
        }
    }
}

impl<C: BlsSignatureImpl> core::fmt::Debug for ProofOfKnowledge<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Basic { u, v } => write!(f, "Basic{{ u: {:?}, v: {:?} }}", u, v),
            Self::MessageAugmentation { u, v } => {
                write!(f, "MessageAugmentation{{ u: {:?}, v: {:?} }}", u, v)
            }
            Self::ProofOfPossession { u, v } => {
                write!(f, "ProofOfPossession{{ u: {:?}, v: {:?} }}", u, v)
            }
        }
    }
}

impl<C: BlsSignatureImpl> Copy for ProofOfKnowledge<C> {}

impl<C: BlsSignatureImpl> Clone for ProofOfKnowledge<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for ProofOfKnowledge<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        match (a, b) {
            (Self::Basic { u: u1, v: v1 }, Self::Basic { u: u2, v: v2 }) => Self::Basic {
                u: <C as Pairing>::Signature::conditional_select(u1, u2, choice),
                v: <C as Pairing>::Signature::conditional_select(v1, v2, choice),
            },
            (
                Self::MessageAugmentation { u: u1, v: v1 },
                Self::MessageAugmentation { u: u2, v: v2 },
            ) => Self::MessageAugmentation {
                u: <C as Pairing>::Signature::conditional_select(u1, u2, choice),
                v: <C as Pairing>::Signature::conditional_select(v1, v2, choice),
            },
            (
                Self::ProofOfPossession { u: u1, v: v1 },
                Self::ProofOfPossession { u: u2, v: v2 },
            ) => Self::ProofOfPossession {
                u: <C as Pairing>::Signature::conditional_select(u1, u2, choice),
                v: <C as Pairing>::Signature::conditional_select(v1, v2, choice),
            },
            _ => panic!("Signature::conditional_select: mismatched variants"),
        }
    }
}

impl<C: BlsSignatureImpl> From<&ProofOfKnowledge<C>> for Vec<u8> {
    fn from(value: &ProofOfKnowledge<C>) -> Self {
        serde_bare::to_vec(value).expect("Failed to serialize ProofOfKnowledge")
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for ProofOfKnowledge<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> BlsResult<Self> {
        let output = serde_bare::from_slice(value)?;
        Ok(output)
    }
}

impl_from_derivatives!(ProofOfKnowledge);

impl<C: BlsSignatureImpl> ProofOfKnowledge<C> {
    /// Verify the proof of knowledge
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        pk: PublicKey<C>,
        msg: B,
        y: ProofCommitmentChallenge<C>,
    ) -> BlsResult<()> {
        match self {
            ProofOfKnowledge::Basic { u, v } => <C as BlsSignatureProof>::verify(
                *u,
                *v,
                pk.0,
                y.0,
                msg,
                <C as BlsSignatureBasic>::DST,
            ),
            ProofOfKnowledge::MessageAugmentation { u, v } => <C as BlsSignatureProof>::verify(
                *u,
                *v,
                pk.0,
                y.0,
                msg,
                <C as BlsSignatureMessageAugmentation>::DST,
            ),
            ProofOfKnowledge::ProofOfPossession { u, v } => <C as BlsSignatureProof>::verify(
                *u,
                *v,
                pk.0,
                y.0,
                msg,
                <C as BlsSignaturePop>::SIG_DST,
            ),
        }
    }
}

/// A signature proof of knowledge based on a timestamp
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofOfKnowledgeTimestamp<C: BlsSignatureImpl> {
    /// The inner proof of knowledge
    #[serde(bound(
        serialize = "ProofOfKnowledge<C>: serde::Serialize",
        deserialize = "ProofOfKnowledge<C>: serde::Deserialize<'de>"
    ))]
    pub proof: ProofOfKnowledge<C>,
    /// The timestamp associated with the proof
    pub timestamp: u64,
}

impl<C: BlsSignatureImpl> Default for ProofOfKnowledgeTimestamp<C> {
    fn default() -> Self {
        Self {
            proof: ProofOfKnowledge::ProofOfPossession {
                u: <C as Pairing>::Signature::default(),
                v: <C as Pairing>::Signature::default(),
            },
            timestamp: 0,
        }
    }
}

impl<C: BlsSignatureImpl> core::fmt::Display for ProofOfKnowledgeTimestamp<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{{ proof: {}, timestamp: {} }}",
            self.proof, self.timestamp
        )
    }
}

impl<C: BlsSignatureImpl> core::fmt::Debug for ProofOfKnowledgeTimestamp<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{{ proof: {:?}, timestamp: {:?} }}",
            self.proof, self.timestamp
        )
    }
}

impl<C: BlsSignatureImpl> Copy for ProofOfKnowledgeTimestamp<C> {}

impl<C: BlsSignatureImpl> Clone for ProofOfKnowledgeTimestamp<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for ProofOfKnowledgeTimestamp<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            proof: ProofOfKnowledge::conditional_select(&a.proof, &b.proof, choice),
            timestamp: u64::conditional_select(&a.timestamp, &b.timestamp, choice),
        }
    }
}

impl<C: BlsSignatureImpl> From<&ProofOfKnowledgeTimestamp<C>> for Vec<u8> {
    fn from(value: &ProofOfKnowledgeTimestamp<C>) -> Self {
        serde_bare::to_vec(value).expect("Failed to serialize ProofOfKnowledgeTimestamp")
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for ProofOfKnowledgeTimestamp<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> BlsResult<Self> {
        let output = serde_bare::from_slice(value)?;
        Ok(output)
    }
}

impl_from_derivatives!(ProofOfKnowledgeTimestamp);

impl<C: BlsSignatureImpl> ProofOfKnowledgeTimestamp<C> {
    /// Create a new signature proof of knowledge using a timestamp
    pub fn generate<B: AsRef<[u8]>>(msg: B, signature: Signature<C>) -> BlsResult<Self> {
        match signature {
            Signature::Basic(s) => {
                let (u, v, timestamp) = <C as BlsSignatureProof>::generate_timestamp_proof(
                    msg,
                    <C as BlsSignatureBasic>::DST,
                    s,
                )?;
                Ok(Self {
                    proof: ProofOfKnowledge::Basic { u, v },
                    timestamp,
                })
            }
            Signature::MessageAugmentation(s) => {
                let (u, v, timestamp) = <C as BlsSignatureProof>::generate_timestamp_proof(
                    msg,
                    <C as BlsSignatureMessageAugmentation>::DST,
                    s,
                )?;
                Ok(Self {
                    proof: ProofOfKnowledge::MessageAugmentation { u, v },
                    timestamp,
                })
            }
            Signature::ProofOfPossession(s) => {
                let (u, v, timestamp) = <C as BlsSignatureProof>::generate_timestamp_proof(
                    msg,
                    <C as BlsSignaturePop>::SIG_DST,
                    s,
                )?;
                Ok(Self {
                    proof: ProofOfKnowledge::ProofOfPossession { u, v },
                    timestamp,
                })
            }
        }
    }

    /// Verify this proof of knowledge
    pub fn verify<B: AsRef<[u8]>>(
        &self,
        pk: PublicKey<C>,
        msg: B,
        timeout_ms: Option<u64>,
    ) -> BlsResult<()> {
        match self.proof {
            ProofOfKnowledge::Basic { u, v } => <C as BlsSignatureProof>::verify_timestamp_proof(
                u,
                v,
                pk.0,
                self.timestamp,
                timeout_ms,
                msg,
                <C as BlsSignatureBasic>::DST,
            ),
            ProofOfKnowledge::MessageAugmentation { u, v } => {
                <C as BlsSignatureProof>::verify_timestamp_proof(
                    u,
                    v,
                    pk.0,
                    self.timestamp,
                    timeout_ms,
                    msg,
                    <C as BlsSignatureMessageAugmentation>::DST,
                )
            }
            ProofOfKnowledge::ProofOfPossession { u, v } => {
                <C as BlsSignatureProof>::verify_timestamp_proof(
                    u,
                    v,
                    pk.0,
                    self.timestamp,
                    timeout_ms,
                    msg,
                    <C as BlsSignaturePop>::SIG_DST,
                )
            }
        }
    }
}
