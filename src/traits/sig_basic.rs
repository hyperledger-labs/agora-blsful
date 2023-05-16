use crate::*;
use bls12_381_plus::elliptic_curve::group::Group;
use std::collections::HashMap;

pub trait BlsSignatureBasic: BlsSignatureCore {
    const DST: &'static [u8];

    fn partial_sign<B: AsRef<[u8]>>(
        sks: &Self::SecretKeyShare,
        msg: B,
    ) -> BlsResult<Self::SignatureShare> {
        <Self as BlsSignatureCore>::core_partial_sign(sks, msg, Self::DST)
    }

    fn partial_verify<B: AsRef<[u8]>>(
        pks: Self::PublicKeyShare,
        sig: Self::SignatureShare,
        msg: B,
    ) -> BlsResult<()> {
        <Self as BlsSignatureCore>::core_signature_share_verify(pks, sig, msg, Self::DST)
    }

    fn sign<B: AsRef<[u8]>>(
        sk: &<Self::PublicKey as Group>::Scalar,
        msg: B,
    ) -> BlsResult<Self::Signature> {
        <Self as BlsSignatureCore>::core_sign(sk, msg, Self::DST)
    }

    fn verify<B: AsRef<[u8]>>(pk: Self::PublicKey, sig: Self::Signature, msg: B) -> BlsResult<()> {
        <Self as BlsSignatureCore>::core_verify(pk, sig, msg, Self::DST)
    }

    fn aggregate_verify<P, B>(pks: P, sig: Self::Signature) -> BlsResult<()>
    where
        P: Iterator<Item = (Self::PublicKey, B)>,
        B: AsRef<[u8]>,
    {
        // check uniqueness
        let mut set = HashMap::new();
        let mut inputs = Vec::new();
        for (i, (pk, m)) in pks.enumerate() {
            let item = m.as_ref().to_vec();
            if let Some(old) = set.insert(item.clone(), i) {
                return Err(BlsError::InvalidInputs(format!(
                    "duplicate messages detected at {} and {}",
                    old, i
                )));
            }
            inputs.push((pk, item));
        }
        <Self as BlsSignatureCore>::core_aggregate_verify(
            inputs.iter().map(|(pk, b)| (*pk, b.as_slice())),
            sig,
            Self::DST,
        )
    }
}
