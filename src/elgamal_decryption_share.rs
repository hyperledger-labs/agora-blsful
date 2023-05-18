use crate::*;

/// A public key share is a point on the curve
/// Must be combined with other public key shares
/// in order to decrypt a ciphertext
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalDecryptionShare<
    C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop,
>(pub <C as Pairing>::PublicKeyShare);

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Clone
    for ElGamalDecryptionShare<C>
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> core::fmt::Debug
    for ElGamalDecryptionShare<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    ElGamalDecryptionShare<C>
{
}

/// An ElGamal decryption key where the secret key is hidden or combined from shares
/// that can decrypt ciphertext
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElGamalDecryptionKey<
    C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop,
>(
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop> Clone
    for ElGamalDecryptionKey<C>
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<C: BlsSignatureBasic + BlsSignatureMessageAugmentation + BlsSignaturePop>
    ElGamalDecryptionKey<C>
{
    /// Decrypt signcrypt ciphertext
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext<C>) -> <C as Pairing>::PublicKey {
        ciphertext.c2 - self.0
    }

    /// Combine decryption shares into a signcrypt decryption key
    pub fn from_shares(shares: &[ElGamalDecryptionShare<C>]) -> BlsResult<Self> {
        let points = shares
            .iter()
            .map(|s| s.0)
            .collect::<Vec<<C as Pairing>::PublicKeyShare>>();
        <C as BlsSignatureCore>::core_combine_public_key_shares(&points).map(Self)
    }
}
