use crate::*;
use bls12_381_plus::elliptic_curve::{group::GroupEncoding, Group};

pub trait BlsSignaturePop: BlsSignatureCore {
    const SIG_DST: &'static [u8];
    const POP_DST: &'static [u8];

    fn partial_sign<B: AsRef<[u8]>>(
        sks: &Self::SecretKeyShare,
        msg: B,
    ) -> BlsResult<Self::SignatureShare> {
        <Self as BlsSignatureCore>::core_partial_sign(sks, msg, Self::SIG_DST)
    }

    fn partial_verify<B: AsRef<[u8]>>(
        pks: Self::PublicKeyShare,
        sig: Self::SignatureShare,
        msg: B,
    ) -> BlsResult<()> {
        <Self as BlsSignatureCore>::core_signature_share_verify(pks, sig, msg, Self::SIG_DST)
    }

    fn sign<B: AsRef<[u8]>>(
        sk: &<Self::PublicKey as Group>::Scalar,
        msg: B,
    ) -> BlsResult<Self::Signature> {
        <Self as BlsSignatureCore>::core_sign(sk, msg, Self::SIG_DST)
    }

    fn verify<B: AsRef<[u8]>>(pk: Self::PublicKey, sig: Self::Signature, msg: B) -> BlsResult<()> {
        <Self as BlsSignatureCore>::core_verify(pk, sig, msg, Self::SIG_DST)
    }

    fn multi_sig_verify<P: Iterator<Item = Self::PublicKey>, B: AsRef<[u8]>>(
        pks: P,
        sig: Self::Signature,
        msg: B,
    ) -> BlsResult<()> {
        let apk = <Self as BlsSignatureCore>::aggregate_public_keys(pks);
        <Self as BlsSignatureCore>::core_verify(apk, sig, msg, Self::SIG_DST)
    }

    fn aggregate_verify<P, B>(pks: P, sig: Self::Signature) -> BlsResult<()>
    where
        P: Iterator<Item = (Self::PublicKey, B)>,
        B: AsRef<[u8]>,
    {
        <Self as BlsSignatureCore>::core_aggregate_verify(pks, sig, Self::SIG_DST)
    }

    fn pop_prove(sk: &<Self::PublicKey as Group>::Scalar) -> BlsResult<Self::Signature> {
        let pk_bytes = Self::public_key(sk).to_bytes();
        <Self as BlsSignatureCore>::core_sign(sk, pk_bytes, Self::POP_DST)
    }

    fn pop_verify(pk: Self::PublicKey, sig: Self::Signature) -> BlsResult<()> {
        let pk_bytes = pk.to_bytes();
        <Self as BlsSignatureCore>::core_verify(pk, sig, pk_bytes, Self::POP_DST)
    }
}
