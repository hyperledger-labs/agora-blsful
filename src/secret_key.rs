use crate::helpers::{get_crypto_rng, KEYGEN_SALT};
use crate::impls::inner_types::*;
use crate::*;
use rand::Rng;
use rand_core::{CryptoRng, RngCore};
use subtle::CtOption;
use vsss_rs::{combine_shares, shamir};

/// Number of bytes needed to represent the secret key
pub const SECRET_KEY_BYTES: usize = 32;

/// The secret key is field element 0 < `x` < `r`
/// where `r` is the curve order. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKey<C: BlsSignatureImpl>(
    /// The secret key raw value
    #[serde(serialize_with = "traits::scalar::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::scalar::deserialize::<C, _>")]
    pub <<C as Pairing>::PublicKey as Group>::Scalar,
);

impl<C: BlsSignatureImpl> From<SecretKey<C>> for [u8; SECRET_KEY_BYTES] {
    fn from(sk: SecretKey<C>) -> [u8; SECRET_KEY_BYTES] {
        sk.to_be_bytes()
    }
}

impl<'a, C: BlsSignatureImpl> From<&'a SecretKey<C>> for [u8; SECRET_KEY_BYTES] {
    fn from(sk: &'a SecretKey<C>) -> [u8; SECRET_KEY_BYTES] {
        sk.to_be_bytes()
    }
}

impl<C: BlsSignatureImpl> From<SecretKey<C>> for Vec<u8> {
    fn from(value: SecretKey<C>) -> Self {
        Self::from(&value)
    }
}

impl<C: BlsSignatureImpl> From<&SecretKey<C>> for Vec<u8> {
    fn from(value: &SecretKey<C>) -> Self {
        value.to_be_bytes().to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<Vec<u8>> for SecretKey<C> {
    type Error = BlsError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<C: BlsSignatureImpl> TryFrom<&Vec<u8>> for SecretKey<C> {
    type Error = BlsError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SecretKey<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 32]>::try_from(value)
            .map_err(|_| BlsError::InvalidInputs("Invalid secret key bytes".to_string()))?;
        Option::from(Self::from_be_bytes(&bytes))
            .ok_or_else(|| BlsError::InvalidInputs("Invalid secret key bytes".to_string()))
    }
}

impl<C: BlsSignatureImpl> TryFrom<Box<[u8]>> for SecretKey<C> {
    type Error = BlsError;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl<C: BlsSignatureImpl> SecretKey<C> {
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

    /// Compute a secret key from a CS-PRNG
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Self(<C as HashToScalar>::hash_to_scalar(
            rng.gen::<[u8; SECRET_KEY_BYTES]>(),
            KEYGEN_SALT,
        ))
    }

    /// Get the big-endian byte representation of this key
    pub fn to_be_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        scalar_to_be_bytes::<C, SECRET_KEY_BYTES>(self.0)
    }

    /// Get the little-endian byte representation of this key
    pub fn to_le_bytes(&self) -> [u8; SECRET_KEY_BYTES] {
        scalar_to_le_bytes::<C, SECRET_KEY_BYTES>(self.0)
    }

    /// Convert a big-endian representation of the secret key.
    pub fn from_be_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        scalar_from_be_bytes::<C, SECRET_KEY_BYTES>(bytes).map(Self)
    }

    /// Convert a little-endian representation of the secret key.
    pub fn from_le_bytes(bytes: &[u8; SECRET_KEY_BYTES]) -> CtOption<Self> {
        scalar_from_le_bytes::<C, SECRET_KEY_BYTES>(bytes).map(Self)
    }

    /// Secret share this key by creating `limit` shares where `threshold` are required
    /// to combine back into this secret
    pub fn split(&self, threshold: usize, limit: usize) -> BlsResult<Vec<SecretKeyShare<C>>> {
        self.split_with_rng(threshold, limit, get_crypto_rng())
    }

    /// Secret share this key by creating `limit` shares where `threshold` are required
    /// to combine back into this secret using a specified RNG
    pub fn split_with_rng(
        &self,
        threshold: usize,
        limit: usize,
        rng: impl RngCore + CryptoRng,
    ) -> BlsResult<Vec<SecretKeyShare<C>>> {
        let shares = shamir::split_secret(threshold, limit, self.0, rng)?
            .into_iter()
            .map(SecretKeyShare)
            .collect::<Vec<_>>();
        Ok(shares)
    }

    /// Reconstruct a secret from shares created from `split`
    pub fn combine(shares: &[SecretKeyShare<C>]) -> BlsResult<Self> {
        let ss = shares.iter().map(|s| s.0.clone()).collect::<Vec<_>>();
        let secret = combine_shares(&ss)?;
        Ok(Self(secret))
    }

    /// Compute the public key
    pub fn public_key(&self) -> PublicKey<C> {
        PublicKey(<C as BlsSignatureCore>::public_key(&self.0))
    }

    /// Create a proof of possession
    pub fn proof_of_possession(&self) -> BlsResult<ProofOfPossession<C>> {
        Ok(ProofOfPossession(<C as BlsSignaturePop>::pop_prove(
            &self.0,
        )?))
    }

    /// Sign a message with this secret key using the specified scheme
    pub fn sign(&self, scheme: SignatureSchemes, msg: &[u8]) -> BlsResult<Signature<C>> {
        match scheme {
            SignatureSchemes::Basic => {
                let inner = <C as BlsSignatureBasic>::sign(&self.0, msg)?;
                Ok(Signature::Basic(inner))
            }
            SignatureSchemes::MessageAugmentation => {
                let inner = <C as BlsSignatureMessageAugmentation>::sign(&self.0, msg)?;
                Ok(Signature::MessageAugmentation(inner))
            }
            SignatureSchemes::ProofOfPossession => {
                let inner = <C as BlsSignaturePop>::sign(&self.0, msg)?;
                Ok(Signature::ProofOfPossession(inner))
            }
        }
    }

    /// Create a Signcrypt decryption key where the secret key is hidden
    /// that can decrypt ciphertext
    pub fn sign_decryption_key<B: AsRef<[u8]>>(
        &self,
        ciphertext: &SignCryptCiphertext<C>,
    ) -> SignCryptDecryptionKey<C> {
        SignCryptDecryptionKey(ciphertext.u * self.0)
    }
}
