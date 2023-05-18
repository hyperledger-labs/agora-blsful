use crate::*;
use bls12_381_plus::elliptic_curve::{group::GroupEncoding, Field, Group};
use vsss_rs::{combine_shares_group, Share};

/// The core methods used by BLS signatures
pub trait BlsSignatureCore: Pairing + HashToPoint<Output = Self::Signature> + BlsSerde + BlsSignatureProof + BlsSignCrypt + BlsTimeCrypt + BlsElGamal {
    /// Get the public key corresponding to the secret key
    fn public_key(sk: &<Self::PublicKey as Group>::Scalar) -> Self::PublicKey {
        <Self::PublicKey as Group>::generator() * sk
    }

    /// Get the public key share corresponding to the secret key share
    fn public_key_share(sks: &Self::SecretKeyShare) -> BlsResult<Self::PublicKeyShare> {
        Self::public_key_share_with_generator(sks, <Self::PublicKey as Group>::generator())
    }

    /// Get the public key share corresponding to the secret key share and a generator
    fn public_key_share_with_generator(sks: &Self::SecretKeyShare, generator: Self::PublicKey) -> BlsResult<Self::PublicKeyShare> {
        let sk = sks.as_field_element::<<Self::PublicKey as Group>::Scalar>()?;
        let pk: Self::PublicKey = generator * sk;
        let pk_bytes = pk.to_bytes();
        let mut pk_share = Self::PublicKeyShare::empty_share_with_capacity(pk_bytes.as_ref().len());
        *pk_share.identifier_mut() = sks.identifier();
        pk_share.value_mut().copy_from_slice(pk_bytes.as_ref());
        Ok(pk_share)
    }

    /// Aggregate signatures
    fn aggregate_signatures<S>(sigs: S) -> Self::Signature
    where
        S: Iterator<Item = Self::Signature>,
    {
        let mut r = <Self::Signature as Group>::identity();
        for s in sigs {
            r += s;
        }
        r
    }

    /// Aggregate public keys
    fn aggregate_public_keys<P>(pks: P) -> Self::PublicKey
    where
        P: Iterator<Item = Self::PublicKey>,
    {
        let mut r = <Self::PublicKey as Group>::identity();
        for p in pks {
            r += p;
        }
        r
    }

    /// Compute a signature share
    fn core_partial_sign<B: AsRef<[u8]>, C: AsRef<[u8]>>(
        sks: &Self::SecretKeyShare,
        msg: B,
        dst: C,
    ) -> BlsResult<Self::SignatureShare> {
        let sk = sks.as_field_element()?;
        let sig = <Self as BlsSignatureCore>::core_sign(&sk, msg, dst.as_ref())?;
        let sig_bytes = sig.to_bytes();
        let mut sig_share =
            <Self as Pairing>::SignatureShare::empty_share_with_capacity(sig_bytes.as_ref().len());
        *sig_share.identifier_mut() = sks.identifier();
        sig_share.value_mut().copy_from_slice(sig_bytes.as_ref());
        Ok(sig_share)
    }

    /// Verify a signature share
    fn core_signature_share_verify<B: AsRef<[u8]>, C: AsRef<[u8]>>(
        pks: Self::PublicKeyShare,
        sig: Self::SignatureShare,
        msg: B,
        dst: C,
    ) -> BlsResult<()> {
        if pks.identifier() != sig.identifier() {
            return Err(BlsError::InvalidInputs(
                "signature and public shares do not correspond".to_string(),
            ));
        }
        let pk = pks.as_group_element()?;
        let sig = sig.as_group_element()?;
        Self::core_verify(pk, sig, msg, dst)
    }

    /// Combine signature shares to form a signature
    fn core_combine_signature_shares(
        shares: &[Self::SignatureShare],
    ) -> BlsResult<Self::Signature> {
        let sig = combine_shares_group(shares)?;
        Ok(sig)
    }

    /// Combine public key shares to form a public key
    fn core_combine_public_key_shares(
        shares: &[Self::PublicKeyShare],
    ) -> BlsResult<Self::PublicKey> {
        let pk = combine_shares_group(shares)?;
        Ok(pk)
    }

    /// Compute a signature
    fn core_sign<B: AsRef<[u8]>, C: AsRef<[u8]>>(
        sk: &<Self::PublicKey as Group>::Scalar,
        msg: B,
        dst: C,
    ) -> BlsResult<Self::Signature> {
        if sk.is_zero().into() {
            return Err(BlsError::SigningError("signing key is zero".to_string()));
        }
        Ok(Self::hash_to_point(msg, dst) * sk)
    }

    /// Verify a signature and message
    fn core_verify<B: AsRef<[u8]>, C: AsRef<[u8]>>(
        pk: Self::PublicKey,
        sig: Self::Signature,
        msg: B,
        dst: C,
    ) -> BlsResult<()> {
        if sig.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "signature is the identity point".to_string(),
            ));
        }
        if pk.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "public key is the identity point".to_string(),
            ));
        }
        let a = Self::hash_to_point::<B, C>(msg, dst);
        let generator = -Self::PublicKey::generator();
        if Self::pairing(&[(a, pk), (sig, generator)])
            .is_identity()
            .into()
        {
            Ok(())
        } else {
            Err(BlsError::InvalidSignature)
        }
    }

    /// Verify an aggregate signature and messages
    fn core_aggregate_verify<P, B, C>(pks: P, sig: Self::Signature, dst: C) -> BlsResult<()>
    where
        P: Iterator<Item = (Self::PublicKey, B)>,
        B: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        if sig.is_identity().into() {
            return Err(BlsError::InvalidInputs(
                "signature is the identity point".to_string(),
            ));
        }
        let mut pairs = Vec::with_capacity(1);
        for (i, (pk, msg)) in pks.enumerate() {
            if pk.is_identity().into() {
                return Err(BlsError::InvalidInputs(format!(
                    "public key at {} is the identity point",
                    i + 1
                )));
            }
            let a = Self::hash_to_point::<_, _>(msg.as_ref(), dst.as_ref());
            pairs.push((a, pk));
        }
        pairs.push((sig, -<Self::PublicKey as Group>::generator()));
        if Self::pairing(pairs.as_slice()).is_identity().into() {
            Ok(())
        } else {
            Err(BlsError::InvalidSignature)
        }
    }
}
