use crate::*;
use subtle::Choice;

/// A public key share is point on the curve. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
/// Must be combined with other public key shares
/// to produce the completed key, or used for
/// creating partial signatures which can be
/// combined into a complete signature
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyShare<
    C: BlsSignatureBasic
        + BlsSignatureMessageAugmentation
        + BlsSignaturePop
        + BlsSignCrypt
        + BlsTimeCrypt
        + BlsSignatureProof
        + BlsSerde,
>(pub <C as Pairing>::PublicKeyShare);

impl<
        C: BlsSignatureBasic
            + BlsSignatureMessageAugmentation
            + BlsSignaturePop
            + BlsSignCrypt
            + BlsTimeCrypt
            + BlsSignatureProof
            + BlsSerde,
    > Copy for PublicKeyShare<C>
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
    > Clone for PublicKeyShare<C>
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
    > subtle::ConditionallySelectable for PublicKeyShare<C>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::PublicKeyShare::conditional_select(
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
    > core::fmt::Display for PublicKeyShare<C>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
    > PublicKeyShare<C>
{
    /// Verify the signature share with the public key share
    pub fn verify<B: AsRef<[u8]>>(&self, sig: &SignatureShare<C>, msg: B) -> BlsResult<()> {
        let pk = self.0.as_group_element::<<C as Pairing>::PublicKey>()?;
        match sig {
            SignatureShare::Basic(sig) => {
                let sig = sig.as_group_element::<<C as Pairing>::Signature>()?;
                <C as BlsSignatureBasic>::verify(pk, sig, msg)
            }
            SignatureShare::MessageAugmentation(sig) => {
                let sig = sig.as_group_element::<<C as Pairing>::Signature>()?;
                <C as BlsSignatureMessageAugmentation>::verify(pk, sig, msg)
            }
            SignatureShare::ProofOfPossession(sig) => {
                let sig = sig.as_group_element::<<C as Pairing>::Signature>()?;
                <C as BlsSignaturePop>::verify(pk, sig, msg)
            }
        }
    }
}
