use crate::*;
use bls12_381_plus::{
    elliptic_curve::{group::Group, hash2curve::ExpandMsgXmd},
    G1Projective, G2Projective, Gt, Scalar,
};
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Represents BLS signatures on the BLS12-381 curve where
/// Signatures are in G1 and Public Keys are in G2 or
/// i.e. signatures are small and public keys are large
#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct Bls12381G1;

impl HashToPoint for Bls12381G1 {
    type Output = G1Projective;

    fn hash_to_point<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        Self::Output::hash::<ExpandMsgXmd<sha2::Sha256>>(m.as_ref(), dst.as_ref())
    }
}

impl HashToScalar for Bls12381G1 {
    type Output = Scalar;

    fn hash_to_scalar<B: AsRef<[u8]>, C: AsRef<[u8]>>(m: B, dst: C) -> Self::Output {
        scalar_from_hkdf_bytes(Some(dst.as_ref()), m.as_ref())
    }
}

impl Pairing for Bls12381G1 {
    type SecretKeyShare = [u8; 33];
    type PublicKey = G2Projective;
    type PublicKeyShare = InnerPointShareG2;
    type Signature = G1Projective;
    type SignatureShare = InnerPointShareG1;
    type PairingResult = Gt;

    fn pairing(points: &[(Self::Signature, Self::PublicKey)]) -> Self::PairingResult {
        pairing_g1_g2(points)
    }
}

impl BlsSerde for Bls12381G1 {
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

impl BlsSignatureCore for Bls12381G1 {}

impl BlsSignatureBasic for Bls12381G1 {
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
}

impl BlsSignatureMessageAugmentation for Bls12381G1 {
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";
}

impl BlsSignaturePop for Bls12381G1 {
    const SIG_DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    const POP_DST: &'static [u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
}

impl BlsSignatureProof for Bls12381G1 {
    const DST: &'static [u8] = b"BLS_POK_BLS12381G1_XMD:SHA-256_RO_POK_";
}

impl BlsSignCrypt for Bls12381G1 {}

impl BlsTimeCrypt for Bls12381G1 {}

impl Bls12381G1 {
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
}
