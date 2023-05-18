use bls12_381_plus::elliptic_curve::{Field, Group};
use bls12_381_plus::group::GroupEncoding;
use rand_core::{CryptoRng, RngCore};
use crate::{BlsError, BlsResult};
use super::*;

const SALT: &'static [u8] = b"ELGAMAL_BLS12381_XOF:HKDF-SHA2-256_";

/// The methods for implementing ElGamal encryption
/// and derived ZKPs
pub trait BlsElGamal:
    Pairing
    + HashToScalar<Output = <Self::PublicKey as Group>::Scalar>
{
    /// Create a scalar from 64 bytes
    fn scalar_from_bytes_wide(bytes: &[u8; 64]) -> <Self::PublicKey as Group>::Scalar;

    /// Encrypt a byte sequence. To decrypt call `decrypt_scalar`
    fn seal_slice<B: AsRef<[u8]>>(
        pk: Self::PublicKey,
        message: B,
        generator: Option<Self::PublicKey>,
        blinder: Option<<Self::PublicKey as Group>::Scalar>,
        rng: impl CryptoRng + RngCore,
    ) -> BlsResult<(Self::PublicKey, Self::PublicKey)> {
        let msg = Self::hash_to_scalar(message.as_ref(), SALT);
        Self::seal_scalar(pk, msg, generator, blinder, rng)
    }

    /// Encrypt a scalar
    fn seal_scalar(
        pk: Self::PublicKey,
        message: <Self::PublicKey as Group>::Scalar,
        generator: Option<Self::PublicKey>,
        blinder: Option<<Self::PublicKey as Group>::Scalar>,
        rng: impl CryptoRng + RngCore,
    ) -> BlsResult<(Self::PublicKey, Self::PublicKey)> {
        let generator = generator.unwrap_or_else(|| Self::PublicKey::generator());

        if (generator.is_identity() | pk.is_identity()).into() {
            return Err(BlsError::InvalidInputs("Generator or public key is identity point".to_string()));
        }

        // odds of this being zero are 2^-256 so we can ignore checking for zero
        let blinder = blinder.unwrap_or_else(|| <Self::PublicKey as Group>::Scalar::random(rng));

        let ek = generator * message;
        let c1 = Self::PublicKey::generator() * blinder;
        let c2 = pk * blinder + ek;

        Ok((c1, c2))
    }

    /// Encrypt a point
    fn seal_point(
        pk: Self::PublicKey,
        message: Self::PublicKey,
        blinder: Option<<Self::PublicKey as Group>::Scalar>,
        rng: impl CryptoRng + RngCore,
    ) -> BlsResult<(Self::PublicKey, Self::PublicKey)> {
        if pk.is_identity().into() {
            return Err(BlsError::InvalidInputs("Generator or public key is identity point".to_string()));
        }
        let blinder = blinder.unwrap_or_else(|| <Self::PublicKey as Group>::Scalar::random(rng));
        let c1 = Self::PublicKey::generator() * blinder;
        let c2 = pk * blinder + message;
        Ok((c1, c2))
    }

    /// Encrypt a slice and generate a ZKP
    fn seal_slice_with_proof<B: AsRef<[u8]>>(
        pk: Self::PublicKey,
        message: B,
        generator: Option<Self::PublicKey>,
        blinder: Option<<Self::PublicKey as Group>::Scalar>,
        rng: impl CryptoRng + RngCore,
    ) -> BlsResult<(Self::PublicKey, Self::PublicKey, Self::PublicKey, Self::PublicKey, <Self::PublicKey as Group>::Scalar, <Self::PublicKey as Group>::Scalar, <Self::PublicKey as Group>::Scalar)> {
        let message = Self::hash_to_scalar(message.as_ref(), SALT);
        Self::seal_scalar_with_proof(pk, message, generator, blinder, rng)
    }

    /// Encrypt a scalar and generate a ZKP
    fn seal_scalar_with_proof(
        pk: Self::PublicKey,
        message: <Self::PublicKey as Group>::Scalar,
        generator: Option<Self::PublicKey>,
        blinder: Option<<Self::PublicKey as Group>::Scalar>,
        mut rng: impl CryptoRng + RngCore,
    ) -> BlsResult<(Self::PublicKey, Self::PublicKey, Self::PublicKey, Self::PublicKey, <Self::PublicKey as Group>::Scalar, <Self::PublicKey as Group>::Scalar, <Self::PublicKey as Group>::Scalar)> {
        let generator = generator.unwrap_or_else(|| Self::PublicKey::generator());
        let b = blinder.unwrap_or_else(|| <Self::PublicKey as Group>::Scalar::random(&mut rng));
        let r = <Self::PublicKey as Group>::Scalar::random(&mut rng);
        // c1 = P^b
        // c2 = H^m * P^ab
        let (c1, c2) = Self::seal_scalar(pk, message, Some(generator), Some(b), &mut rng)?;
        // r1 = P^r
        // r2 = H^b * P^ar
        let (r1, r2) = Self::seal_scalar(pk, b, Some(generator), Some(r), &mut rng)?;

        let mut transcript = merlin::Transcript::new(b"ElGamalProof");
        transcript.append_message(b"dst", SALT);
        transcript.append_message(b"base point", Self::PublicKey::generator().to_bytes().as_ref());
        transcript.append_message(b"pk", pk.to_bytes().as_ref());
        transcript.append_message(b"generator", generator.to_bytes().as_ref());
        transcript.append_message(b"c1", c1.to_bytes().as_ref());
        transcript.append_message(b"c2", c2.to_bytes().as_ref());
        transcript.append_message(b"r1", r1.to_bytes().as_ref());
        transcript.append_message(b"r2", r2.to_bytes().as_ref());
        let mut challenge = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge);
        let challenge = Self::scalar_from_bytes_wide(&challenge);

        let message_proof = b + challenge * message;
        let blinder_proof = r + challenge * b;
        Ok((c1, c2, r1, r2, message_proof, blinder_proof, challenge))
    }

    /// Decrypt an ElGamal ciphertext and return the resulting point
    ///
    /// If a message or scalar was encrypted, the value is in the exponent
    /// If a point was encrypted, the actual value is the result
    fn decrypt(
        sk: <Self::PublicKey as Group>::Scalar,
        c1: Self::PublicKey,
        c2: Self::PublicKey,
    ) -> Self::PublicKey {
        c2 - c1 * sk
    }

    /// Verify an elgamal proof and decrypt the resulting point if the proof is valid
    fn verify_and_decrypt(
        sk: <Self::PublicKey as Group>::Scalar,
        generator: Self::PublicKey,
        c1: Self::PublicKey,
        c2: Self::PublicKey,
        message_proof: <Self::PublicKey as Group>::Scalar,
        blinder_proof: <Self::PublicKey as Group>::Scalar,
        challenge: <Self::PublicKey as Group>::Scalar,
    ) -> BlsResult<Self::PublicKey> {
        let pk = Self::PublicKey::generator() * sk;
        Self::verify_proof(pk, generator, c1, c2, message_proof, blinder_proof, challenge)?;
        Ok(Self::decrypt(sk, c1, c2))
    }

    /// Verify an elgamal proof
    fn verify_proof(
        pk: Self::PublicKey,
        generator: Self::PublicKey,
        c1: Self::PublicKey,
        c2: Self::PublicKey,
        message_proof: <Self::PublicKey as Group>::Scalar,
        blinder_proof: <Self::PublicKey as Group>::Scalar,
        challenge: <Self::PublicKey as Group>::Scalar,
    ) -> BlsResult<()> {
        if (pk.is_identity() | generator.is_identity() | c1.is_identity() | c2.is_identity()).into() {
            return Err(BlsError::InvalidInputs("Parameters or ciphertext values are identity point".to_string()));
        }
        if (message_proof.is_zero() | blinder_proof.is_zero() | challenge.is_zero()).into() {
            return Err(BlsError::InvalidInputs("Proof values are zero".to_string()));
        }

        let neg_challenge = -challenge;
        // r1 = P^-bc P^(r + b * c)
        let r1 = c1 * neg_challenge + Self::PublicKey::generator() * blinder_proof;
        // r1 = H^-mc P^-abc H^(b + m * c) P^a(r + b * c)
        let r2 = c2 * neg_challenge + generator * message_proof + pk * blinder_proof;

        let mut transcript = merlin::Transcript::new(b"ElGamalProof");
        transcript.append_message(b"dst", SALT);
        transcript.append_message(b"base point", Self::PublicKey::generator().to_bytes().as_ref());
        transcript.append_message(b"pk", pk.to_bytes().as_ref());
        transcript.append_message(b"generator", generator.to_bytes().as_ref());
        transcript.append_message(b"c1", c1.to_bytes().as_ref());
        transcript.append_message(b"c2", c2.to_bytes().as_ref());
        transcript.append_message(b"r1", r1.to_bytes().as_ref());
        transcript.append_message(b"r2", r2.to_bytes().as_ref());
        let mut challenge_bytes = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let challenge_verifier = Self::scalar_from_bytes_wide(&challenge_bytes);

        if challenge != challenge_verifier {
            return Err(BlsError::InvalidInputs("Challenge values do not match".to_string()));
        } else {
            Ok(())
        }
    }
}