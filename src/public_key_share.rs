use crate::*;
use subtle::Choice;

/// A public key share is point on the curve. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
/// Must be combined with other public key shares
/// to produce the completed key, or used for
/// creating partial signatures which can be
/// combined into a complete signature
#[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PublicKeyShare<C: BlsSignatureImpl>(pub <C as Pairing>::PublicKeyShare);

impl<C: BlsSignatureImpl> Copy for PublicKeyShare<C> {}

impl<C: BlsSignatureImpl> Clone for PublicKeyShare<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> subtle::ConditionallySelectable for PublicKeyShare<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::PublicKeyShare::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl<C: BlsSignatureImpl> core::fmt::Display for PublicKeyShare<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl_from_derivatives_generic!(PublicKeyShare);

impl<C: BlsSignatureImpl> From<&PublicKeyShare<C>> for Vec<u8> {
    fn from(pk: &PublicKeyShare<C>) -> Vec<u8> {
        serde_bare::to_vec(&pk.0).unwrap()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for PublicKeyShare<C> {
    type Error = BlsError;
    fn try_from(bytes: &[u8]) -> BlsResult<Self> {
        serde_bare::from_slice(bytes)
            .map(Self)
            .map_err(|e| BlsError::InvalidInputs(e.to_string()))
    }
}

impl<C: BlsSignatureImpl> PublicKeyShare<C> {
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
