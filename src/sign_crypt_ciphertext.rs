use crate::*;
use subtle::CtOption;

/// The ciphertext output from sign crypt encryption
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignCryptCiphertext<C: BlsSignatureImpl> {
    /// The `u` component
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub u: <C as Pairing>::PublicKey,
    /// The `v` component
    pub v: Vec<u8>,
    /// The `w` component
    #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
    pub w: <C as Pairing>::Signature,
    /// The signature scheme used to generate this ciphertext
    pub scheme: SignatureSchemes,
}

impl<C: BlsSignatureImpl> Display for SignCryptCiphertext<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ u: {}, v: {:?}, w: {}, scheme: {:?} }}",
            self.u, self.v, self.w, self.scheme
        )
    }
}

impl<C: BlsSignatureImpl> From<&SignCryptCiphertext<C>> for Vec<u8> {
    fn from(value: &SignCryptCiphertext<C>) -> Self {
        serde_bare::to_vec(value).expect("failed to serialize SignCryptCiphertext")
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SignCryptCiphertext<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> BlsResult<Self> {
        let output = serde_bare::from_slice(value)?;
        Ok(output)
    }
}

impl_from_derivatives_generic!(SignCryptCiphertext);

impl<C: BlsSignatureImpl> SignCryptCiphertext<C> {
    /// Create a decryption share from a secret key share
    pub fn create_decryption_share(
        &self,
        sks: &SecretKeyShare<C>,
    ) -> BlsResult<SignDecryptionShare<C>> {
        Ok(SignDecryptionShare(
            <C as BlsSignatureCore>::public_key_share_with_generator(&sks.0, self.u)?,
        ))
    }

    /// Open the ciphertext given the decryption shares.
    pub fn decrypt_with_shares<B: AsRef<[SignDecryptionShare<C>]>>(
        &self,
        shares: B,
    ) -> CtOption<Vec<u8>> {
        let dst = match self.scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };

        let shares = shares.as_ref().iter().map(|s| s.0).collect::<Vec<_>>();
        <C as BlsSignCrypt>::unseal_with_shares(self.u, &self.v, self.w, shares.as_slice(), dst)
    }

    /// Decrypt the signcrypt ciphertext
    pub fn decrypt(&self, sk: &SecretKey<C>) -> CtOption<Vec<u8>> {
        let dst = match self.scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };

        <C as BlsSignCrypt>::unseal(self.u, &self.v, self.w, &sk.0, dst)
    }

    /// Check if the ciphertext is valid
    pub fn is_valid(&self) -> Choice {
        match self.scheme {
            SignatureSchemes::Basic => {
                <C as BlsSignCrypt>::valid(self.u, &self.v, self.w, <C as BlsSignatureBasic>::DST)
            }
            SignatureSchemes::MessageAugmentation => <C as BlsSignCrypt>::valid(
                self.u,
                &self.v,
                self.w,
                <C as BlsSignatureMessageAugmentation>::DST,
            ),
            SignatureSchemes::ProofOfPossession => {
                <C as BlsSignCrypt>::valid(self.u, &self.v, self.w, <C as BlsSignaturePop>::SIG_DST)
            }
        }
    }
}

/// A Signcrypt decryption key where the secret key is hidden or combined from shares
/// that can decrypt ciphertext
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignCryptDecryptionKey<C: BlsSignatureImpl>(
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<C: BlsSignatureImpl> fmt::Debug for SignCryptDecryptionKey<C> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureImpl> Clone for SignCryptDecryptionKey<C> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<C: BlsSignatureImpl> From<&SignCryptDecryptionKey<C>> for Vec<u8> {
    fn from(value: &SignCryptDecryptionKey<C>) -> Self {
        serde_bare::to_vec(value).expect("failed to serialize SignCryptDecryptionKey")
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for SignCryptDecryptionKey<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> BlsResult<Self> {
        let output = serde_bare::from_slice(value)?;
        Ok(output)
    }
}

impl_from_derivatives_generic!(SignCryptDecryptionKey);

impl<C: BlsSignatureImpl> SignCryptDecryptionKey<C> {
    /// Decrypt signcrypt ciphertext
    pub fn decrypt(&self, ciphertext: &SignCryptCiphertext<C>) -> CtOption<Vec<u8>> {
        let dst = match ciphertext.scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };

        let choice = <C as BlsSignCrypt>::valid(ciphertext.u, &ciphertext.v, ciphertext.w, dst);
        <C as BlsSignCrypt>::decrypt(&ciphertext.v, self.0, choice)
    }

    /// Combine decryption shares into a signcrypt decryption key
    pub fn from_shares(shares: &[SignDecryptionShare<C>]) -> BlsResult<Self> {
        let points = shares
            .iter()
            .map(|s| s.0)
            .collect::<Vec<<C as Pairing>::PublicKeyShare>>();
        <C as BlsSignatureCore>::core_combine_public_key_shares(&points).map(Self)
    }
}
