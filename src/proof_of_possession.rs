use crate::*;
use subtle::{Choice, ConditionallySelectable};

/// A proof of possession of the secret key
#[derive(PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofOfPossession<C: BlsSignatureImpl>(
    /// The BLS proof of possession raw value
    #[serde(serialize_with = "traits::signature::serialize::<C, _>")]
    #[serde(deserialize_with = "traits::signature::deserialize::<C, _>")]
    pub <C as Pairing>::Signature,
);

impl<C: BlsSignatureImpl> Default for ProofOfPossession<C> {
    fn default() -> Self {
        Self(<C as Pairing>::Signature::default())
    }
}

impl<C: BlsSignatureImpl> Display for ProofOfPossession<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<C: BlsSignatureImpl> fmt::Debug for ProofOfPossession<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ProofOfPossession{{ {:?} }}", self.0)
    }
}

impl<C: BlsSignatureImpl> Copy for ProofOfPossession<C> {}

impl<C: BlsSignatureImpl> Clone for ProofOfPossession<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: BlsSignatureImpl> ConditionallySelectable for ProofOfPossession<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<C as Pairing>::Signature::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

impl_from_derivatives_generic!(ProofOfPossession);

impl<C: BlsSignatureImpl> From<&ProofOfPossession<C>> for Vec<u8> {
    fn from(value: &ProofOfPossession<C>) -> Self {
        value.0.to_bytes().as_ref().to_vec()
    }
}

impl<C: BlsSignatureImpl> TryFrom<&[u8]> for ProofOfPossession<C> {
    type Error = BlsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut repr = C::Signature::default().to_bytes();
        let len = repr.as_ref().len();

        if len != value.len() {
            return Err(BlsError::InvalidInputs(format!(
                "Invalid length, expected {}, got {}",
                len,
                value.len()
            )));
        }

        repr.as_mut().copy_from_slice(value);
        let key: Option<C::Signature> = C::Signature::from_bytes(&repr).into();
        key.map(Self)
            .ok_or_else(|| BlsError::InvalidInputs("Invalid byte sequence".to_string()))
    }
}

impl<C: BlsSignatureImpl> ProofOfPossession<C> {
    /// Verify this proof of possession
    pub fn verify(&self, pk: PublicKey<C>) -> BlsResult<()> {
        <C as BlsSignaturePop>::pop_verify(pk.0, self.0)
    }
}
