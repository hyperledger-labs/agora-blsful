use crate::*;
use bls12_381_plus::elliptic_curve::{group::GroupEncoding, Group};

pub trait BlsSignatureMessageAugmentation: BlsSignatureCore {
    const DST: &'static [u8];

    fn sign<B: AsRef<[u8]>>(
        sk: &<Self::PublicKey as Group>::Scalar,
        msg: B,
    ) -> BlsResult<Self::Signature> {
        let mut overhead = Self::pk_bytes(Self::public_key(sk), msg.as_ref().len());
        overhead.extend_from_slice(msg.as_ref());
        <Self as BlsSignatureCore>::core_sign(sk, overhead.as_slice(), Self::DST)
    }

    fn verify<B: AsRef<[u8]>>(pk: Self::PublicKey, sig: Self::Signature, msg: B) -> BlsResult<()> {
        let mut overhead = Self::pk_bytes(pk, msg.as_ref().len());
        overhead.extend_from_slice(msg.as_ref());
        <Self as BlsSignatureCore>::core_verify(pk, sig, overhead.as_slice(), Self::DST)
    }

    fn aggregate_verify<P, B>(pks: P, sig: Self::Signature) -> BlsResult<()>
    where
        P: Iterator<Item = (Self::PublicKey, B)>,
        B: AsRef<[u8]>,
    {
        let new_pks = pks.map(|(pk, m)| {
            let mut overhead = Self::pk_bytes(pk, m.as_ref().len());
            overhead.extend_from_slice(m.as_ref());
            (pk, overhead)
        });
        <Self as BlsSignatureCore>::core_aggregate_verify(new_pks, sig, Self::DST)
    }

    fn pk_bytes(pk: Self::PublicKey, size_hint: usize) -> Vec<u8> {
        let pk_bytes = pk.to_bytes();
        let pk_bytes_ref = pk_bytes.as_ref();
        let mut overhead = Vec::with_capacity(pk_bytes_ref.len() + size_hint);
        overhead.extend_from_slice(pk_bytes_ref);
        overhead
    }
}
