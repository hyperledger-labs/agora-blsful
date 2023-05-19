use crate::*;
use bls12_381_plus::elliptic_curve::Group;

/// A BLS public key
#[derive(Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublicKey<C: BlsSignatureImpl>(
    /// The BLS public key raw value
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<C: BlsSignatureImpl> From<&SecretKey<C>> for PublicKey<C> {
    fn from(s: &SecretKey<C>) -> Self {
        Self(<C as Pairing>::PublicKey::generator() * s.0)
    }
}

impl<C: BlsSignatureImpl> core::fmt::Display for PublicKey<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<C: BlsSignatureImpl> core::fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureImpl> Copy for PublicKey<C> {}

impl<C: BlsSignatureImpl> Clone for PublicKey<C> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for PublicKey<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::PublicKey::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<C: BlsSignatureImpl> PublicKey<C> {
    /// Encrypt a message using signcryption
    pub fn sign_crypt<B: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
    ) -> SignCryptCiphertext<C> {
        let dst = match scheme {
            SignatureSchemes::Basic => <C as BlsSignatureBasic>::DST,
            SignatureSchemes::MessageAugmentation => <C as BlsSignatureMessageAugmentation>::DST,
            SignatureSchemes::ProofOfPossession => <C as BlsSignaturePop>::SIG_DST,
        };
        let (u, v, w) = <C as BlsSignCrypt>::seal(self.0, msg.as_ref(), dst);
        SignCryptCiphertext { u, v, w, scheme }
    }

    /// Encrypt a message using time lock encryption
    pub fn encrypt_time_lock<B: AsRef<[u8]>, D: AsRef<[u8]>>(
        &self,
        scheme: SignatureSchemes,
        msg: B,
        id: D,
    ) -> BlsResult<TimeCryptCiphertext<C>> {
        let (u, v, w) = <C as BlsTimeCrypt>::seal(
            self.0,
            msg.as_ref(),
            id.as_ref(),
            <C as BlsSignatureBasic>::DST,
        )?;
        Ok(TimeCryptCiphertext { u, v, w, scheme })
    }

    /// Encrypt a message using ElGamal
    pub fn encrypt_key_el_gamal(&self, sk: &SecretKey<C>) -> BlsResult<ElGamalCiphertext<C>> {
        let (c1, c2) = <C as BlsElGamal>::seal_scalar(self.0, sk.0, None, None, get_crypto_rng())?;
        Ok(ElGamalCiphertext { c1, c2 })
    }

    /// Encrypt a message using ElGamal and generate a proof
    pub fn encrypt_key_el_gamal_with_proof(&self, sk: &SecretKey<C>) -> BlsResult<ElGamalProof<C>> {
        let (c1, c2, message_proof, blinder_proof, challenge) =
            <C as BlsElGamal>::seal_scalar_with_proof(self.0, sk.0, None, None, get_crypto_rng())?;
        Ok(ElGamalProof {
            ciphertext: ElGamalCiphertext { c1, c2 },
            message_proof,
            blinder_proof,
            challenge,
        })
    }

    /// Create a public key from secret shares
    pub fn from_shares(shares: &[PublicKeyShare<C>]) -> BlsResult<Self> {
        let points = shares
            .iter()
            .map(|s| s.0)
            .collect::<Vec<<C as Pairing>::PublicKeyShare>>();
        <C as BlsSignatureCore>::core_combine_public_key_shares(&points).map(Self)
    }
}
