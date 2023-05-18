use crate::*;
use bls12_381_plus::elliptic_curve::Group;

/// A BLS public key
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey<
    C: BlsSignatureBasic
        + BlsSignatureMessageAugmentation
        + BlsSignaturePop
>(
    /// The BLS public key raw value
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
    > From<&SecretKey<C>> for PublicKey<C>
{
    fn from(s: &SecretKey<C>) -> Self {
        Self(<C as Pairing>::PublicKey::generator() * s.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
    > core::fmt::Display for PublicKey<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
    > core::fmt::Debug for PublicKey<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
    > Copy for PublicKey<C>
{
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
    > Clone for PublicKey<C>
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
    > subtle::ConditionallySelectable for PublicKey<C>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::PublicKey::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
    > PublicKey<C>
{
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
    pub fn time_lock_encrypt<B: AsRef<[u8]>, D: AsRef<[u8]>>(
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

    /// Create a public key from secret shares
    pub fn from_shares(shares: &[PublicKeyShare<C>]) -> BlsResult<Self> {
        let points = shares
            .iter()
            .map(|s| s.0)
            .collect::<Vec<<C as Pairing>::PublicKeyShare>>();
        <C as BlsSignatureCore>::core_combine_public_key_shares(&points).map(Self)
    }
}
