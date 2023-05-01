use crate::{PublicKey, SecretKey};
use bls12_381_plus::{
    elliptic_curve::hash2curve::ExpandMsgXmd,
    ff::Field,
    group::{Curve, Group},
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared,
};
use subtle::{Choice, CtOption};

/// A proof of possession of the secret key
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProofOfPossession(pub G1Projective);

display_one_impl!(ProofOfPossession);

serde_impl!(ProofOfPossession, G1Projective);

cond_select_impl!(ProofOfPossession, G1Projective);

impl ProofOfPossession {
    /// Number of bytes needed to represent the proof
    pub const BYTES: usize = G1Projective::COMPRESSED_BYTES;
    /// The domain separation tag
    const DST: &'static [u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    /// Create a new proof of possession
    pub fn new(sk: &SecretKey) -> Option<Self> {
        if sk.0.is_zero().unwrap_u8() == 1u8 {
            return None;
        }
        let pk = PublicKey::from(sk);
        let a = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&pk.to_bytes(), Self::DST);
        Some(Self(a * sk.0))
    }

    validity_checks!();

    bytes_impl!(G1Affine, G1Projective);

    /// Verify if the proof is over `pk`
    pub fn verify(&self, pk: PublicKey) -> Choice {
        if (self.is_invalid() | pk.is_invalid()).unwrap_u8() == 1 {
            return Choice::from(0);
        }
        let a = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&pk.to_bytes(), Self::DST);
        let g2 = -G2Affine::generator();

        multi_miller_loop(&[
            (&a.to_affine(), &G2Prepared::from(pk.0.to_affine())),
            (&self.0.to_affine(), &G2Prepared::from(g2)),
        ])
        .final_exponentiation()
        .is_identity()
    }
}

#[test]
fn pop_works() {
    use crate::MockRng;
    use rand_core::SeedableRng;

    let seed = [2u8; 16];
    let mut rng = MockRng::from_seed(seed);
    let sk = SecretKey::random(&mut rng);
    let pop = ProofOfPossession::new(&sk).unwrap();
    let pk = PublicKey::from(&sk);
    assert_eq!(pop.verify(pk).unwrap_u8(), 1);
}
