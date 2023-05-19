use crate::*;

/// A public key share is point on the curve. See Section 4.3 in
/// <https://eprint.iacr.org/2016/663.pdf>
/// Must be combined with other public key shares
/// to produce the completed key, or used for
/// creating partial signatures which can be
/// combined into a complete signature
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct SignDecryptionShare<C: BlsSignatureImpl>(pub <C as Pairing>::PublicKeyShare);

impl<C: BlsSignatureImpl> Clone for SignDecryptionShare<C> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<C: BlsSignatureImpl> core::fmt::Debug for SignDecryptionShare<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: BlsSignatureImpl> SignDecryptionShare<C> {
    /// Verify the signcrypt decryption share with the corresponding public key and ciphertext
    pub fn verify(&self, pks: &PublicKeyShare<C>, sig: &SignCryptCiphertext<C>) -> BlsResult<()> {
        let share = self.0.as_group_element::<<C as Pairing>::PublicKey>()?;
        let pk = pks.0.as_group_element::<<C as Pairing>::PublicKey>()?;
        if <C as BlsSignCrypt>::verify_share(
            share,
            pk,
            sig.u,
            &sig.v,
            sig.w,
            <C as BlsSignatureBasic>::DST,
        )
        .into()
        {
            Ok(())
        } else {
            Err(BlsError::InvalidDecryptionShare)
        }
    }
}
