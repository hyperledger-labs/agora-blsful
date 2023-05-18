use crate::*;
use bls12_381_plus::{
    elliptic_curve::{group::Group, hash2curve::ExpandMsgXmd},
    G1Projective, G2Projective, Gt, Scalar,
};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

/// Represents BLS signatures on the BLS12-381 curve where
/// Signatures are in G2 and Public Keys are in G1 or
/// i.e. signatures are large and public keys are small
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Bls12381G2;

impl HashToPoint for Bls12381G2 {
    type Output = G2Projective;

    fn hash_to_point<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        Self::Output::hash::<ExpandMsgXmd<sha2::Sha256>>(m.as_ref(), dst.as_ref())
    }
}

impl HashToScalar for Bls12381G2 {
    type Output = Scalar;

    fn hash_to_scalar<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        scalar_from_hkdf_bytes(Some(dst.as_ref()), m.as_ref())
    }
}

impl Pairing for Bls12381G2 {
    type SecretKeyShare = [u8; 33];
    type PublicKey = G1Projective;
    type PublicKeyShare = InnerPointShareG1;
    type Signature = G2Projective;
    type SignatureShare = InnerPointShareG2;
    type PairingResult = Gt;

    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult {
        pairing_g2_g1(points)
    }
}

impl BlsSerde for Bls12381G2 {
    fn serialize_scalar<S: Serializer>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error> {
        scalar.serialize(serializer)
    }

    fn serialize_scalar_share<S: Serializer>(
        share: &Self::SecretKeyShare,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        fixed_arr::BigArray::serialize(share, serializer)
    }

    fn serialize_signature<S: Serializer>(
        signature: &Self::Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        signature.serialize(serializer)
    }

    fn serialize_public_key<S: Serializer>(
        public_key: &Self::PublicKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        public_key.serialize(serializer)
    }

    fn deserialize_scalar<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<<Self::PublicKey as Group>::Scalar, D::Error> {
        Scalar::deserialize(deserializer)
    }

    fn deserialize_scalar_share<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::SecretKeyShare, D::Error> {
        fixed_arr::BigArray::deserialize(deserializer)
    }

    fn deserialize_signature<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::Signature, D::Error> {
        Self::Signature::deserialize(deserializer)
    }

    fn deserialize_public_key<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::PublicKey, D::Error> {
        Self::PublicKey::deserialize(deserializer)
    }
}

impl BlsSignatureCore for Bls12381G2 {}

impl BlsSignatureBasic for Bls12381G2 {
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
}

impl BlsSignatureMessageAugmentation for Bls12381G2 {
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
}

impl BlsSignaturePop for Bls12381G2 {
    const SIG_DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const POP_DST: &'static [u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
}

impl BlsSignatureProof for Bls12381G2 {}

impl BlsSignCrypt for Bls12381G2 {}

impl BlsTimeCrypt for Bls12381G2 {}

impl BlsElGamal for Bls12381G2 {
    const ENC_DST: &'static [u8] = b"BLS_ELGAMAL_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    type PublicKeyHasher = Bls12381G2Hasher;

    fn scalar_from_bytes_wide(bytes: &[u8; 64]) -> <Self::PublicKey as Group>::Scalar {
        Scalar::from_bytes_wide(bytes)
    }
}

impl BlsMultiKey for Bls12381G2 {}

impl BlsMultiSignature for Bls12381G2 {}

impl Bls12381G2 {
    /// Create a new random secret key
    pub fn new_secret_key() -> SecretKey<Self> {
        SecretKey::random(get_crypto_rng())
    }

    /// Compute a secret key from a hash
    pub fn secret_key_from_hash<B: AsRef<[u8]>>(data: B) -> SecretKey<Self> {
        SecretKey(<Self as HashToScalar>::hash_to_scalar(
            data.as_ref(),
            KEYGEN_SALT,
        ))
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random_secret_key(mut rng: impl RngCore + CryptoRng) -> SecretKey<Self> {
        SecretKey(<Self as HashToScalar>::hash_to_scalar(
            rng.gen::<[u8; SECRET_KEY_BYTES]>(),
            KEYGEN_SALT,
        ))
    }

    /// Create a new random commitment challenge for signature proofs of knowledge
    /// as step 2
    pub fn new_proof_challenge() -> ProofCommitmentChallenge<Self> {
        ProofCommitmentChallenge::new()
    }

    /// Compute a commitment challenge for signature proofs of knowledge from a hash
    /// as step 2
    pub fn proof_challenge_from_hash<B: AsRef<[u8]>>(data: B) -> ProofCommitmentChallenge<Self> {
        ProofCommitmentChallenge::from_hash(data)
    }

    /// Compute a commitment challenge for signature proofs of knowledge from a CS-PRNG
    /// as step 2
    pub fn random_proof_challenge(
        mut rng: impl RngCore + CryptoRng,
    ) -> ProofCommitmentChallenge<Self> {
        ProofCommitmentChallenge::random(&mut rng)
    }
}

/// The BLS12381 G1 hash to public key group
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Bls12381G2Hasher;

impl HashToPoint for Bls12381G2Hasher {
    type Output = G1Projective;

    fn hash_to_point<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        Self::Output::hash::<ExpandMsgXmd<sha2::Sha256>>(m.as_ref(), dst.as_ref())
    }
}
