//! This crate implements BLS signatures according to the IETF draft v4
//!
//! for the Proof of Possession Cipher Suite
//!
//! Since BLS signatures can use either G1 or G2 fields, there are two types of
//! public keys and signatures. Normal and Variant (suffix'd with Vt).
//!
//! Normal puts signatures in G1 and pubic keys in G2.
//! Variant is the reverse.
//!
//! This crate has been designed to be compliant with no-std by avoiding allocations
//!
//! but provides some optimizations when an allocator exists for verifying
//! aggregated signatures.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

pub(crate) mod libs {
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::vec;
    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::vec::Vec;

    #[cfg(feature = "std")]
    pub use std::vec;
    #[cfg(feature = "std")]
    pub use std::vec::Vec;

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    pub fn byte_xor(arr1: &[u8], arr2: &[u8]) -> Vec<u8> {
        debug_assert_eq!(arr1.len(), arr2.len());
        let mut o = Vec::with_capacity(arr1.len());
        for (a, b) in arr1.iter().zip(arr2.iter()) {
            o.push(*a ^ *b)
        }
        o
    }

    pub fn get_crypto_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_entropy()
    }
}

#[macro_use]
mod macros;

mod aggregate_signature;
mod aggregate_signature_vt;
mod multi_public_key;
mod multi_public_key_vt;
mod multi_signature;
mod multi_signature_vt;
mod partial_signature;
mod partial_signature_vt;
mod proof_commitment;
mod proof_commitment_vt;
mod proof_of_knowledge;
mod proof_of_knowledge_vt;
mod proof_of_possession;
mod proof_of_possession_vt;
mod public_key;
mod public_key_vt;
mod secret_key;
mod secret_key_share;
#[cfg(any(feature = "alloc", feature = "std"))]
mod sign_crypt_ciphertext;
mod signature;
mod signature_vt;

pub use aggregate_signature::*;
pub use aggregate_signature_vt::*;
pub use multi_public_key::*;
pub use multi_public_key_vt::*;
pub use multi_signature::*;
pub use multi_signature_vt::*;
pub use partial_signature::*;
pub use partial_signature_vt::*;
pub use proof_commitment::*;
pub use proof_commitment_vt::*;
pub use proof_of_knowledge::*;
pub use proof_of_knowledge_vt::*;
pub use proof_of_possession::*;
pub use proof_of_possession_vt::*;
pub use public_key::*;
pub use public_key_vt::*;
pub use secret_key::*;
pub use secret_key_share::*;
#[cfg(any(feature = "alloc", feature = "std"))]
pub use sign_crypt_ciphertext::*;
pub use signature::*;
pub use signature_vt::*;

pub use bls12_381_plus;
pub use vsss_rs;

use bls12_381_plus::Scalar;
use rand_core::{CryptoRng, RngCore};

pub(crate) fn hash_fr(salt: Option<&[u8]>, ikm: &[u8]) -> Scalar {
    const INFO: [u8; 2] = [0u8, 48u8];

    let mut extractor = hkdf::HkdfExtract::<sha2::Sha256>::new(salt);
    extractor.input_ikm(ikm);
    extractor.input_ikm(&[0u8]);
    let (_, h) = extractor.finalize();

    let mut output = [0u8; 48];
    let mut s = Scalar::ZERO;
    // Odds of this happening are extremely low but check anyway
    while s == Scalar::ZERO {
        // Unwrap allowed since 48 is a valid length
        h.expand(&INFO, &mut output).unwrap();
        s = Scalar::from_okm(&output);
    }
    s
}

pub(crate) fn random_nz_fr(salt: Option<&[u8]>, mut rng: impl RngCore + CryptoRng) -> Scalar {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    hash_fr(salt, &ikm)
}

#[cfg(test)]
pub struct MockRng(rand_xorshift::XorShiftRng);

#[cfg(test)]
impl rand_core::SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

#[cfg(test)]
impl CryptoRng for MockRng {}

#[cfg(test)]
impl RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
