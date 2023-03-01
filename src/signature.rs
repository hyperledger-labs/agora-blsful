use crate::partial_signature::PARTIAL_SIGNATURE_BYTES;
use crate::{PartialSignature, ProofCommitment, PublicKey, SecretKey};
use bls12_381_plus::{
    multi_miller_loop, ExpandMsgXmd, G1Affine, G1Projective, G2Affine, G2Prepared, Scalar,
};
use ff::Field;
use group::{Curve, Group};
use subtle::{Choice, CtOption};
use vsss_rs::{Error, Shamir, Share};

/// Represents a BLS signature in G1 using the proof of possession scheme
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Signature(pub G1Projective);

display_one_impl!(Signature);

serde_impl!(Signature, G1Projective);

cond_select_impl!(Signature, G1Projective);

impl Signature {
    /// Number of bytes needed to represent the signature
    pub const BYTES: usize = 48;
    /// The domain separation tag
    const DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    /// Create a new bls
    pub fn new<B: AsRef<[u8]>>(sk: &SecretKey, msg: B) -> Option<Self> {
        if sk.0.is_zero().unwrap_u8() == 1u8 {
            return None;
        }
        let a = Self::hash_msg(msg.as_ref());
        Some(Self(a * sk.0))
    }

    pub(crate) fn hash_msg(msg: &[u8]) -> G1Projective {
        G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, Self::DST)
    }

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);

    /// Verify if the bls is over `msg` with `pk`
    pub fn verify<B: AsRef<[u8]>>(&self, pk: PublicKey, msg: B) -> Choice {
        if (pk.0.is_identity() | self.is_invalid()).unwrap_u8() == 1 {
            return 0u8.into();
        }
        let a = Self::hash_msg(msg.as_ref());
        let g2 = -G2Affine::generator();

        multi_miller_loop(&[
            (&a.to_affine(), &G2Prepared::from(pk.0.to_affine())),
            (&self.0.to_affine(), &G2Prepared::from(g2)),
        ])
        .final_exponentiation()
        .is_identity()
    }

    /// Combine partial signatures into a completed signature
    pub fn from_partials<const T: usize, const N: usize>(
        partials: &[PartialSignature],
    ) -> Result<Self, Error> {
        if T > partials.len() {
            return Err(Error::SharingLimitLessThanThreshold);
        }
        let mut pp = [Share::<PARTIAL_SIGNATURE_BYTES>::default(); T];
        for i in 0..T {
            pp[i] = partials[i].0;
        }
        let point =
            Shamir::<T, N>::combine_shares_group::<Scalar, G1Projective, PARTIAL_SIGNATURE_BYTES>(
                &pp,
            )?;
        Ok(Self(point))
    }

    #[cfg(feature = "std")]
    /// Create a zero-knowledge proof of a valid signature
    /// `x` is a random Scalar and should be kept private
    /// The commitment is then sent to the verifier to receive
    /// a challenge
    pub fn proof_of_knowledge_commitment<B: AsRef<[u8]>>(
        &self,
        msg: B,
    ) -> Option<(ProofCommitment, Scalar)> {
        let x = Scalar::random(rand_core::OsRng);
        let pok = self.proof_of_knowledge_commitment_with_x(msg, x)?;
        Some((pok, x))
    }

    /// Create a zero-knowledge proof of a valid signature
    /// `x` should be a random Scalar and kept private
    /// The commitment is then sent to the verifier to receive
    /// a challenge
    pub fn proof_of_knowledge_commitment_with_x<B: AsRef<[u8]>>(
        &self,
        msg: B,
        x: Scalar,
    ) -> Option<ProofCommitment> {
        if (self.is_invalid() | x.is_zero()).unwrap_u8() == 1u8 {
            return None;
        }
        let a = Self::hash_msg(msg.as_ref());
        if a.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        let u = a * x;
        if u.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        Some(ProofCommitment(u))
    }

    /// Create a proof of knowledge based ona timestamp instead of a
    /// server challenge
    /// `x` should be a random Scalar and kept private
    #[cfg(feature = "iso8601-timestamp")]
    pub fn proof_of_knowledge_with_timestamp<B: AsRef<[u8]>>(
        &self,
        msg: B,
        x: Scalar,
    ) -> Option<crate::ProofOfKnowledgeTimestamp> {
        use crate::ProofOfKnowledge;

        if self.is_invalid().unwrap_u8() == 1u8 {
            return None;
        }
        if x.is_zero().unwrap_u8() == 1u8 {
            return None;
        }
        let a = Self::hash_msg(msg.as_ref());
        if a.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        let u = a * x;
        if u.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        let (y, t) = ProofOfKnowledge::generate_timestamp_based_y(u);
        if y.is_zero().unwrap_u8() == 1u8 {
            return None;
        }

        let v = self.0 * (x + y);
        if v.is_identity().unwrap_u8() == 1u8 {
            return None;
        }
        Some(crate::ProofOfKnowledgeTimestamp {
            pok: ProofOfKnowledge { u, v: -v },
            t,
        })
    }
}

#[test]
fn signature_works() {
    use crate::MockRng;
    use rand_core::{RngCore, SeedableRng};

    let seed = [2u8; 16];
    let mut rng = MockRng::from_seed(seed);
    let sk = SecretKey::random(&mut rng).unwrap();
    let mut msg = [0u8; 12];
    rng.fill_bytes(&mut msg);
    let sig = Signature::new(&sk, msg).unwrap();
    let pk = PublicKey::from(&sk);
    assert_eq!(sig.verify(pk, msg).unwrap_u8(), 1);
}

#[test]
fn threshold_works() {
    use crate::MockRng;
    use rand_core::{RngCore, SeedableRng};

    let seed = [3u8; 16];
    let mut rng = MockRng::from_seed(seed);
    let sk = SecretKey::random(&mut rng).unwrap();
    let pk = PublicKey::from(&sk);

    let res_shares = sk.split::<MockRng, 2, 3>(&mut rng);
    assert!(res_shares.is_ok());
    let shares = res_shares.unwrap();
    let mut msg = [0u8; 12];
    rng.fill_bytes(&mut msg);

    let mut sigs = [PartialSignature::default(); 3];
    for (i, share) in shares.iter().enumerate() {
        let opt = PartialSignature::new(share, &msg);
        assert!(opt.is_some());
        sigs[i] = opt.unwrap();
    }

    // Try all combinations to make sure they verify
    for i in 0..3 {
        for j in 0..3 {
            if i == j {
                continue;
            }
            let res = Signature::from_partials::<2, 3>(&[sigs[i], sigs[j]]);
            assert!(res.is_ok());
            let sig = res.unwrap();
            assert_eq!(sig.verify(pk, msg).unwrap_u8(), 1);
        }
    }
}
