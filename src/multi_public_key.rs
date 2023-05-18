use crate::*;
use bls12_381_plus::elliptic_curve::Group;

/// An accumulated public key
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiPublicKey<
    C: BlsSignatureBasic
        + BlsSignatureMessageAugmentation
        + BlsSignaturePop
        + BlsSignCrypt
        + BlsTimeCrypt
        + BlsSignatureProof
        + BlsSerde,
>(
    /// The inner raw value
    #[serde(serialize_with = "traits::public_key::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::public_key::deserialize::<C, _>")]
    pub <C as Pairing>::PublicKey,
);

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > core::fmt::Display for MultiPublicKey<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > core::fmt::Debug for MultiPublicKey<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Copy for MultiPublicKey<C>
{
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Clone for MultiPublicKey<C>
{
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > subtle::ConditionallySelectable for MultiPublicKey<C>
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
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > From<&[PublicKey<C>]> for MultiPublicKey<C>
{
    fn from(keys: &[PublicKey<C>]) -> Self {
        let mut g = <C as Pairing>::PublicKey::identity();
        for k in keys {
            g += k.0;
        }
        Self(g)
    }
}

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > MultiPublicKey<C>
{
    /// Accumulate multiple public keys into a single public key
    pub fn from_public_keys<B: AsRef<[PublicKey<C>]>>(keys: B) -> Self {
        Self::from(keys.as_ref())
    }
}
