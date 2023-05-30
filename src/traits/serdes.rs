use crate::traits::Pairing;
use crate::impls::inner_types::*;
use serde::{Deserializer, Serializer};

/// Serialization trait for inner types
pub trait BlsSerde: Pairing {
    /// Serialize a scalar
    fn serialize_scalar<S: Serializer>(
        scalar: &<Self::PublicKey as Group>::Scalar,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;
    /// Serialize a scalar share
    fn serialize_scalar_share<S: Serializer>(
        share: &Self::SecretKeyShare,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;
    /// Serialize a signature
    fn serialize_signature<S: Serializer>(
        signature: &Self::Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;
    /// Serialize a public key
    fn serialize_public_key<S: Serializer>(
        public_key: &Self::PublicKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;

    /// Deserialize a scalar
    fn deserialize_scalar<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<<Self::PublicKey as Group>::Scalar, D::Error>;
    /// Deserialize a scalar share
    fn deserialize_scalar_share<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::SecretKeyShare, D::Error>;
    /// Deserialize a signature
    fn deserialize_signature<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::Signature, D::Error>;
    /// Deserialize a public key
    fn deserialize_public_key<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::PublicKey, D::Error>;
}

pub(crate) mod secret_key_share {
    use super::*;

    pub fn serialize<B: BlsSerde, S: Serializer>(
        sks: &B::SecretKeyShare,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        B::serialize_scalar_share(sks, s)
    }

    pub fn deserialize<'de, B: BlsSerde, D: Deserializer<'de>>(
        d: D,
    ) -> Result<B::SecretKeyShare, D::Error> {
        B::deserialize_scalar_share(d)
    }
}

pub(crate) mod public_key {
    use super::*;

    pub fn serialize<B: BlsSerde, S: Serializer>(
        pk: &B::PublicKey,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        B::serialize_public_key(pk, s)
    }

    pub fn deserialize<'de, B: BlsSerde, D: Deserializer<'de>>(
        d: D,
    ) -> Result<B::PublicKey, D::Error> {
        B::deserialize_public_key(d)
    }
}

pub(crate) mod signature {
    use super::*;

    pub fn serialize<B: BlsSerde, S: Serializer>(
        sig: &B::Signature,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        B::serialize_signature(sig, s)
    }

    pub fn deserialize<'de, B: BlsSerde, D: Deserializer<'de>>(
        d: D,
    ) -> Result<B::Signature, D::Error> {
        B::deserialize_signature(d)
    }
}

pub(crate) mod scalar {
    use super::*;

    pub fn serialize<B: BlsSerde, S: Serializer>(
        sig: &<B::PublicKey as Group>::Scalar,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        B::serialize_scalar(sig, s)
    }

    pub fn deserialize<'de, B: BlsSerde, D: Deserializer<'de>>(
        d: D,
    ) -> Result<<B::PublicKey as Group>::Scalar, D::Error> {
        B::deserialize_scalar(d)
    }
}
