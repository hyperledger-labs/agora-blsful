use crate::{ProofOfKnowledge, Signature};
use bls12_381_plus::{G1Affine, G1Projective, Scalar};
use ff::Field;
use group::Curve;
use subtle::{Choice, CtOption};

/// The first step in proof of knowledge protocol
/// where the client sends this commitment first
/// then the verifier sends the challenge
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProofCommitment(pub G1Projective);

display_one_impl!(ProofCommitment);

serde_impl!(ProofCommitment, G1Projective);

cond_select_impl!(ProofCommitment, G1Projective);

impl ProofCommitment {
    /// Number of bytes needed to represent this commitment
    pub const BYTES: usize = 48;

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);

    /// Complete the proof of knowledge once the challenge is received from the verifier
    /// after the commitment was sent
    pub fn complete(self, x: Scalar, y: Scalar, sig: Signature) -> Option<ProofOfKnowledge> {
        if (self.is_invalid() | sig.is_invalid() | x.is_zero() | y.is_zero()).unwrap_u8() == 1u8 {
            return None;
        }

        let v = sig.0 * (x + y);
        if v.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        Some(ProofOfKnowledge { u: self.0, v: -v })
    }
}
