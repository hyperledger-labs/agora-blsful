//! The implementations of the BLS signature scheme
//! and all supporting types and algorithms

mod g1;
mod g2;

pub use g1::*;
pub use g2::*;

use crate::*;
use core::marker::PhantomData;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};

/// Types that implement BLS signatures
pub trait BlsSignatureImpl:
    BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop
{
}

/// A BLS signature implementation
pub struct BlsSignature<T: BlsSignatureImpl>(PhantomData<T>);

impl<T: BlsSignatureImpl> BlsSignature<T> {
    /// Create a new random secret key
    pub fn new_secret_key() -> SecretKey<T> {
        SecretKey::random(get_crypto_rng())
    }

    /// Compute a secret key from a hash
    pub fn secret_key_from_hash<B: AsRef<[u8]>>(data: B) -> SecretKey<T> {
        SecretKey(<T as HashToScalar>::hash_to_scalar(
            data.as_ref(),
            KEYGEN_SALT,
        ))
    }

    /// Compute a secret key from a CS-PRNG
    pub fn random_secret_key(mut rng: impl RngCore + CryptoRng) -> SecretKey<T> {
        SecretKey(<T as HashToScalar>::hash_to_scalar(
            rng.gen::<[u8; SECRET_KEY_BYTES]>(),
            KEYGEN_SALT,
        ))
    }

    /// Create a new random commitment challenge for signature proofs of knowledge
    /// as step 2
    pub fn new_proof_challenge() -> ProofCommitmentChallenge<T> {
        ProofCommitmentChallenge::new()
    }

    /// Compute a commitment challenge for signature proofs of knowledge from a hash
    /// as step 2
    pub fn proof_challenge_from_hash<B: AsRef<[u8]>>(data: B) -> ProofCommitmentChallenge<T> {
        ProofCommitmentChallenge::from_hash(data)
    }

    /// Compute a commitment challenge for signature proofs of knowledge from a CS-PRNG
    /// as step 2
    pub fn random_proof_challenge(
        mut rng: impl RngCore + CryptoRng,
    ) -> ProofCommitmentChallenge<T> {
        ProofCommitmentChallenge::random(&mut rng)
    }
}

/// A BLS signature implementation using G1 for signatures and G2 for public keys
pub type Bls12381G1 = BlsSignature<Bls12381G1Impl>;

/// A BLS signature implementation using G2 for signatures and G1 for public keys
pub type Bls12381G2 = BlsSignature<Bls12381G2Impl>;


pub(crate) mod inner_types {
    #[cfg(feature = "blst")]
    pub use blstrs::{*, group::{Curve, Group, GroupEncoding}, ff::{Field, PrimeField}};
    #[cfg(all(feature = "rust", not(feature = "blst")))]
    pub use bls12_381_plus::{*, ff::{Field, PrimeField}, group::{Group, GroupEncoding, Curve}, elliptic_curve::hash2curve::ExpandMsgXmd};
}
