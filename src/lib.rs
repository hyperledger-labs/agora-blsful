//! This crate implements BLS signatures according to the IETF draft v4
//!
//! for the Proof of Possession Cipher Suite
//!
//! Since BLS signatures can use either G1 or G2 fields, there are two types of
//! public keys and signatures. Normal and Variant (suffix'd with Vt).
//!
//! Normal puts signatures in G1 and pubic keys in G2.
//! Variant is the reverse.
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

mod helpers;

use helpers::*;

mod aggregate_signature;
mod elgamal_ciphertext;
mod elgamal_decryption_share;
mod elgamal_proof;
mod error;
mod impls;
mod multi_public_key;
mod multi_signature;
mod proof_commitment;
mod proof_of_knowledge;
mod proof_of_possession;
mod public_key;
mod public_key_share;
mod secret_key;
mod secret_key_share;
mod sig_types;
mod sign_crypt_ciphertext;
mod sign_decryption_share;
mod signature;
mod signature_share;
mod time_crypt_ciphertext;
mod traits;

pub use error::*;
pub use impls::*;

pub use aggregate_signature::*;
pub use elgamal_ciphertext::*;
pub use elgamal_decryption_share::*;
pub use elgamal_proof::*;
pub use multi_public_key::*;
pub use multi_signature::*;
pub use proof_commitment::*;
pub use proof_of_knowledge::*;
pub use proof_of_possession::*;
pub use public_key::*;
pub use public_key_share::*;
pub use secret_key::*;
pub use secret_key_share::*;
pub use sig_types::*;
pub use sign_crypt_ciphertext::*;
pub use sign_decryption_share::*;
pub use signature::*;
pub use signature_share::*;
pub use time_crypt_ciphertext::*;
pub use traits::*;

pub use bls12_381_plus;
pub use vsss_rs;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::Choice;
use vsss_rs::Share;
use zeroize::Zeroize;

/// The share type for points in G1
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Zeroize, Serialize, Deserialize,
)]
pub struct InnerPointShareG1(
    /// The inner share representation
    #[serde(with = "fixed_arr::BigArray")]
    pub [u8; 49],
);

impl subtle::ConditionallySelectable for InnerPointShareG1 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0u8; 49];
        for (i, r) in result.iter_mut().enumerate() {
            *r = u8::conditional_select(&a.0[i], &b.0[i], choice);
        }
        InnerPointShareG1(result)
    }
}

impl Default for InnerPointShareG1 {
    fn default() -> Self {
        Self([0u8; 49])
    }
}

impl core::fmt::Display for InnerPointShareG1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Share for InnerPointShareG1 {
    type Identifier = u8;

    fn empty_share_with_capacity(_size_hint: usize) -> Self {
        Self([0u8; 49])
    }

    fn identifier(&self) -> Self::Identifier {
        self.0[0]
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0[0]
    }

    fn value(&self) -> &[u8] {
        &self.0[1..]
    }

    fn value_mut(&mut self) -> &mut [u8] {
        &mut self.0[1..]
    }
}

/// The share type for points in G2
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Zeroize, Serialize, Deserialize,
)]
pub struct InnerPointShareG2(
    /// The inner share representation
    #[serde(with = "fixed_arr::BigArray")]
    pub [u8; 97],
);

impl subtle::ConditionallySelectable for InnerPointShareG2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut result = [0u8; 97];
        for (i, r) in result.iter_mut().enumerate() {
            *r = u8::conditional_select(&a.0[i], &b.0[i], choice);
        }
        InnerPointShareG2(result)
    }
}

impl Default for InnerPointShareG2 {
    fn default() -> Self {
        Self([0u8; 97])
    }
}

impl core::fmt::Display for InnerPointShareG2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Share for InnerPointShareG2 {
    type Identifier = u8;

    fn empty_share_with_capacity(_size_hint: usize) -> Self {
        Self([0u8; 97])
    }

    fn identifier(&self) -> Self::Identifier {
        self.0[0]
    }

    fn identifier_mut(&mut self) -> &mut Self::Identifier {
        &mut self.0[0]
    }

    fn value(&self) -> &[u8] {
        &self.0[1..]
    }

    fn value_mut(&mut self) -> &mut [u8] {
        &mut self.0[1..]
    }
}
